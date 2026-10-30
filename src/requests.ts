import type { Database } from "bun:sqlite";
import type { ApprovalRow, RequestRow, UseTokenRow } from "./db.ts";
import {
  hashToken,
  newFillKeypair,
  open,
  openFillEnvelope,
  openJson,
  randomId,
  randomToken,
  seal,
  sealJson,
  type FillEnvelope,
} from "./crypto.ts";
import {
  FIELD_TYPES,
  RETENTIONS,
  type ApprovePageData,
  type AutofillPayload,
  type Field,
  type FieldType,
  type FillPageData,
  type FillPost,
  type Level,
  type Retention,
  type Status,
  type Via,
} from "./model.ts";
import { notify } from "./server/waiters.ts";

export type Ctx = {
  db: Database;
  key: CryptoKey;
  /** Changes while running when the tunnel assigns a new address. */
  publicUrl: string;
  /** Header the tunnel sets to the real client address, if it's one a client can't forge. */
  clientIpHeader?: string;
  now?: () => number;
};

export class LockedError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

const MIN = 60_000;
export const DEFAULT_LINK_TTL = 15 * MIN;
export const MAX_LINK_TTL = 24 * 60 * MIN;
export const USE_TOKEN_TTL = MIN;
export const APPROVAL_TTL = 10 * MIN;
/** "Delete after first use" keeps the secret this long after the first use, so a two-page login still works. */
export const ONCE_GRACE = 5 * MIN;
const ONCE_CAP = 24 * 60 * MIN;
const RETENTION_MS: Record<Retention, number | null> = { once: ONCE_CAP, "1h": 60 * MIN, "24h": 24 * 60 * MIN, forever: null };
const MAX_VALUE = 16 * 1024;

const now = (ctx: Ctx) => (ctx.now ? ctx.now() : Date.now());

export type RequestSummary = {
  id: string;
  label: string;
  reason: string;
  site: string | null;
  level: Level;
  status: Status;
  fields: Field[];
  retention: Retention;
  useCount: number;
  createdAt: number;
  linkExpiresAt: number;
  openedAt: number | null;
  filledAt: number | null;
  secretExpiresAt: number | null;
  declineNote: string | null;
};

export type UseResult =
  | { kind: "token"; token: string; origin: string; fields: string[]; expiresAt: number }
  | { kind: "values"; values: Record<string, string>; fields: string[] }
  | { kind: "approval"; approvalId: string; approvalUrl: string; expiresAt: number };

export type ApprovalSummary = {
  id: string;
  requestId: string;
  status: "pending" | "approved" | "denied" | "expired" | "redeemed";
  via: Via;
  purpose: string;
  origin: string | null;
  fields: string[];
  createdAt: number;
  expiresAt: number;
};

// ---------------------------------------------------------------------------
// Input validation

/** "github.com" → "https://github.com". Only http(s) origins. */
export function normalizeSite(site: string): string {
  const raw = site.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new LockedError("bad_site", `not a site: ${site}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new LockedError("bad_site", `site must be http(s): ${site}`);
  return url.origin;
}

const FIELD_NAME = /^[a-zA-Z][a-zA-Z0-9_-]{0,39}$/;

function titleCase(name: string) {
  const words: Record<string, string> = { otp: "One-time code", apikey: "API key", "new-password": "New password" };
  return words[name] ?? name.replace(/[-_]+/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function normalizeFields(fields: Array<Partial<Field> & { name: string }>): Field[] {
  if (!Array.isArray(fields) || fields.length === 0) throw new LockedError("bad_fields", "ask for at least one field");
  if (fields.length > 12) throw new LockedError("bad_fields", "at most 12 fields");
  const seen = new Set<string>();
  return fields.map((f) => {
    if (!FIELD_NAME.test(f.name ?? "")) throw new LockedError("bad_fields", `bad field name: ${f.name}`);
    if (seen.has(f.name)) throw new LockedError("bad_fields", `duplicate field: ${f.name}`);
    seen.add(f.name);
    const type = (f.type ?? (FIELD_TYPES.includes(f.name as FieldType) ? f.name : "text")) as FieldType;
    if (!FIELD_TYPES.includes(type)) throw new LockedError("bad_fields", `unknown field type: ${type}`);
    const label = (f.label ?? "").trim().slice(0, 80) || titleCase(f.name);
    return { name: f.name, type, label, required: f.required ?? true };
  });
}

// ---------------------------------------------------------------------------
// Helpers

function audit(ctx: Ctx, requestId: string | null, event: string, detail?: Record<string, unknown>) {
  ctx.db
    .query("INSERT INTO audit (ts, request_id, event, detail) VALUES (?, ?, ?, ?)")
    .run(now(ctx), requestId, event, detail ? JSON.stringify(detail) : null);
}

function rowById(ctx: Ctx, id: string): RequestRow {
  const row = ctx.db.query("SELECT * FROM requests WHERE id = ?").get(id) as RequestRow | null;
  if (!row) throw new LockedError("not_found", `no request ${id}`, 404);
  return row;
}

function rowByFillToken(ctx: Ctx, token: string): RequestRow | null {
  return ctx.db.query("SELECT * FROM requests WHERE fill_token_hash = ?").get(hashToken(token)) as RequestRow | null;
}

function effectiveStatus(ctx: Ctx, row: RequestRow): Status {
  const t = now(ctx);
  if (row.status === "pending" && row.link_expires_at <= t) return "expired";
  if (row.status === "filled" && (row.secret == null || (row.secret_expires_at != null && row.secret_expires_at <= t))) return "expired";
  return row.status as Status;
}

function summarize(ctx: Ctx, row: RequestRow): RequestSummary {
  return {
    id: row.id,
    label: row.label,
    reason: row.reason,
    site: row.site,
    level: row.level as Level,
    status: effectiveStatus(ctx, row),
    fields: JSON.parse(row.fields),
    retention: row.retention as Retention,
    useCount: row.use_count,
    createdAt: row.created_at,
    linkExpiresAt: row.link_expires_at,
    openedAt: row.opened_at,
    filledAt: row.filled_at,
    secretExpiresAt: row.secret_expires_at,
    declineNote: row.decline_note,
  };
}

function pickFields(row: RequestRow, only?: string[]): Field[] {
  const all = JSON.parse(row.fields) as Field[];
  if (!only || only.length === 0) return all;
  return only.map((name) => {
    const f = all.find((x) => x.name === name);
    if (!f) throw new LockedError("bad_fields", `request ${row.id} has no field "${name}" (has: ${all.map((x) => x.name).join(", ")})`);
    return f;
  });
}

async function loadValues(ctx: Ctx, row: RequestRow): Promise<Record<string, string>> {
  const status = effectiveStatus(ctx, row);
  if (status !== "filled" || !row.secret) {
    throw new LockedError(`not_${status}`, `request ${row.id} is ${status === "pending" ? "still waiting for the user" : status}`, 409);
  }
  return openJson<Record<string, string>>(ctx.key, row.secret, `secret:${row.id}`);
}

function markUsed(ctx: Ctx, row: RequestRow, via: Via) {
  const t = now(ctx);
  let expires = row.secret_expires_at;
  if (row.retention === "once") expires = Math.min(expires ?? Infinity, t + ONCE_GRACE);
  ctx.db
    .query("UPDATE requests SET use_count = use_count + 1, first_used_at = COALESCE(first_used_at, ?), secret_expires_at = ? WHERE id = ?")
    .run(t, expires, row.id);
  audit(ctx, row.id, "used", { via });
}

function subset(values: Record<string, string>, fields: Field[]) {
  const out: Record<string, string> = {};
  for (const f of fields) if (values[f.name] != null && values[f.name] !== "") out[f.name] = values[f.name]!;
  return out;
}

// ---------------------------------------------------------------------------
// Creating requests and filling them

export type CreateInput = {
  label: string;
  reason?: string;
  site?: string | null;
  fields: Array<Partial<Field> & { name: string }>;
  level?: Level;
  ttlMs?: number;
  retention?: Retention;
};

export async function createRequest(ctx: Ctx, input: CreateInput) {
  const label = String(input.label ?? "").trim().slice(0, 80);
  if (!label) throw new LockedError("bad_label", "a label is required, e.g. \"GitHub login\"");
  const level: Level = input.level === "sealed" ? "sealed" : "normal";
  if (input.level && input.level !== "normal" && input.level !== "sealed") throw new LockedError("bad_level", "level is normal or sealed");
  const retention: Retention = input.retention ?? "1h";
  if (!RETENTIONS.includes(retention)) throw new LockedError("bad_retention", `keep is one of ${RETENTIONS.join(", ")}`);
  const ttl = Math.min(Math.max(input.ttlMs ?? DEFAULT_LINK_TTL, MIN), MAX_LINK_TTL);
  const fields = normalizeFields(input.fields);
  const site = input.site ? normalizeSite(input.site) : null;

  const id = randomId("lk");
  const token = randomToken();
  const pair = await newFillKeypair();
  const t = now(ctx);
  ctx.db
    .query(
      `INSERT INTO requests (id, fill_token_hash, label, reason, site, fields, level, retention, status,
         fill_public_key, fill_private_key, created_at, link_expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`,
    )
    .run(
      id,
      hashToken(token),
      label,
      String(input.reason ?? "").trim().slice(0, 500),
      site,
      JSON.stringify(fields),
      level,
      retention,
      pair.publicKey,
      await seal(ctx.key, pair.privateJwk, `fill:${id}`),
      t,
      t + ttl,
    );
  audit(ctx, id, "created", { level, site, fields: fields.map((f) => f.name) });
  return { id, url: `${ctx.publicUrl}/r/${token}`, expiresAt: t + ttl, level, site, fields };
}

export function fillPageData(ctx: Ctx, token: string): FillPageData {
  const row = rowByFillToken(ctx, token);
  if (!row) return { state: "missing" };
  const status = effectiveStatus(ctx, row);
  if (status !== "pending") return { state: status === "filled" ? "filled" : status, label: row.label };
  if (row.opened_at == null) {
    ctx.db.query("UPDATE requests SET opened_at = ? WHERE id = ?").run(now(ctx), row.id);
    audit(ctx, row.id, "opened");
  }
  const seen = row.site ? ctx.db.query("SELECT 1 FROM origins_seen WHERE origin = ?").get(row.site) : true;
  return {
    state: "open",
    id: row.id,
    label: row.label,
    reason: row.reason,
    site: row.site,
    level: row.level as Level,
    fields: JSON.parse(row.fields),
    retention: row.retention as Retention,
    publicKey: row.fill_public_key,
    createdAt: row.created_at,
    expiresAt: row.link_expires_at,
    firstTimeSite: !seen,
  };
}

export async function submitFill(ctx: Ctx, token: string, post: FillPost): Promise<{ state: "filled" | "declined" }> {
  const row = rowByFillToken(ctx, token);
  if (!row) throw new LockedError("missing", "this link doesn't exist", 404);
  const status = effectiveStatus(ctx, row);
  if (status !== "pending") throw new LockedError(status, `this link is ${status === "filled" ? "already used" : status}`, 409);

  if (post?.action === "decline") {
    ctx.db
      .query("UPDATE requests SET status = 'declined', decline_note = ?, fill_private_key = NULL WHERE id = ?")
      .run(String(post.note ?? "").slice(0, 500) || null, row.id);
    audit(ctx, row.id, "declined");
    notify(row.id);
    return { state: "declined" };
  }
  if (post?.action !== "submit") throw new LockedError("bad_post", "unknown action");

  const retention = post.retention ?? (row.retention as Retention);
  if (!RETENTIONS.includes(retention)) throw new LockedError("bad_retention", "bad retention");
  if (!row.fill_private_key) throw new LockedError("missing", "this link can no longer be filled", 409);

  const privateJwk = new TextDecoder().decode(await open(ctx.key, row.fill_private_key, `fill:${row.id}`));
  let plain: { values?: Record<string, unknown> };
  try {
    plain = await openFillEnvelope(privateJwk, post.envelope as FillEnvelope, row.id);
  } catch {
    throw new LockedError("bad_envelope", "couldn't decrypt the form; reload the page and try again");
  }
  const fields = JSON.parse(row.fields) as Field[];
  const values: Record<string, string> = {};
  for (const f of fields) {
    const v = plain.values?.[f.name];
    if (v != null && typeof v !== "string") throw new LockedError("bad_value", `${f.label} must be text`);
    if (typeof v === "string" && v.length > MAX_VALUE) throw new LockedError("bad_value", `${f.label} is too long`);
    if (f.required && !v) throw new LockedError("bad_value", `${f.label} is required`);
    if (v) values[f.name] = v;
  }

  const t = now(ctx);
  const keep = RETENTION_MS[retention];
  ctx.db
    .query(
      `UPDATE requests SET status = 'filled', filled_at = ?, retention = ?, secret = ?, secret_expires_at = ?,
         fill_private_key = NULL WHERE id = ? AND status = 'pending'`,
    )
    .run(t, retention, await sealJson(ctx.key, values, `secret:${row.id}`), keep == null ? null : t + keep, row.id);
  if (row.site) {
    ctx.db
      .query("INSERT INTO origins_seen (origin, first_seen, fills) VALUES (?, ?, 1) ON CONFLICT(origin) DO UPDATE SET fills = fills + 1")
      .run(row.site, t);
  }
  audit(ctx, row.id, "filled", { retention, fields: Object.keys(values) });
  notify(row.id);
  return { state: "filled" };
}

// ---------------------------------------------------------------------------
// Reading status

export function getRequest(ctx: Ctx, id: string): RequestSummary {
  return summarize(ctx, rowById(ctx, id));
}

/** `stored`: only secrets that are filled and still kept, i.e. the ones you can use. */
export function listRequests(ctx: Ctx, limit = 50, opts: { stored?: boolean } = {}): RequestSummary[] {
  const where = opts.stored ? "WHERE status = 'filled' AND secret IS NOT NULL" : "";
  const rows = ctx.db.query(`SELECT * FROM requests ${where} ORDER BY created_at DESC LIMIT ?`).all(limit) as RequestRow[];
  const all = rows.map((r) => summarize(ctx, r));
  return opts.stored ? all.filter((r) => r.status === "filled") : all;
}

// ---------------------------------------------------------------------------
// Using secrets

/**
 * Plaintext for `locked get`. Sealed requests only after the owner confirmed on the Mac itself
 * (Touch ID, checked by the server, not the caller): `deviceConfirmed` is set by the agent API.
 */
export async function reveal(ctx: Ctx, id: string, only?: string[], opts: { deviceConfirmed?: boolean; dryRun?: boolean } = {}) {
  const row = rowById(ctx, id);
  if (row.level === "sealed" && !opts.deviceConfirmed) {
    throw new LockedError("sealed", `${id} is sealed: it can't be printed without Touch ID on the Mac. Use inject, exec, copy or panel.`, 403);
  }
  const fields = pickFields(row, only);
  const loaded = await loadValues(ctx, row);
  if (opts.dryRun) return { values: {}, fields: [] };
  const values = subset(loaded, fields);
  markUsed(ctx, row, "get");
  if (opts.deviceConfirmed) audit(ctx, row.id, "device_confirmed", { via: "get" });
  return { values, fields: Object.keys(values) };
}

/** What the native panel shows before any value leaves the database. */
/** What a panel or phone share will show: throws unless the secret is filled and unexpired. */
export async function releaseTarget(ctx: Ctx, id: string, only?: string[]) {
  const row = rowById(ctx, id);
  await loadValues(ctx, row); // throws unless filled and unexpired
  return { request: summarize(ctx, row), fields: pickFields(row, only) };
}

/** The panel's values, on its first Type or Copy. For a sealed request the caller has already run Touch ID. */
/** Values for the Mac panel or the phone. Sealed ones need the device's own check (Touch ID, Face ID) first. */
export async function releaseValues(ctx: Ctx, id: string, fields: string[], opts: { via: "panel" | "phone"; deviceConfirmed?: boolean }) {
  const row = rowById(ctx, id);
  if (row.level === "sealed" && !opts.deviceConfirmed) throw new LockedError("sealed", `${id} is sealed: Touch ID first`, 403);
  const values = subset(await loadValues(ctx, row), pickFields(row, fields));
  markUsed(ctx, row, opts.via);
  if (opts.deviceConfirmed) audit(ctx, row.id, "device_confirmed", { via: opts.via });
  return values;
}

/** Audit entries for things that happen outside this module (panel clicks). Names and field names only. */
export function recordEvent(ctx: Ctx, requestId: string | null, event: string, detail?: Record<string, unknown>) {
  audit(ctx, requestId, event, detail);
}

export type UseInput = { via: Exclude<Via, "get">; purpose?: string; origin?: string; only?: string[] };

export async function requestUse(ctx: Ctx, id: string, input: UseInput): Promise<UseResult> {
  const row = rowById(ctx, id);
  if (!["inject", "exec", "copy"].includes(input.via)) throw new LockedError("bad_via", "via is inject, exec or copy");
  await loadValues(ctx, row); // throws unless filled and unexpired
  const fields = pickFields(row, input.only);
  let origin: string | null = null;
  if (input.via === "inject") {
    origin = input.origin ? normalizeSite(input.origin) : row.site;
    if (!origin) throw new LockedError("no_origin", `${id} isn't tied to a site; pass --origin with the page's origin`);
    if (row.site && origin !== row.site) {
      throw new LockedError("origin_mismatch", `${id} is bound to ${row.site} and can't be filled into ${origin}`, 403);
    }
  }
  if (row.level === "sealed") {
    const approvalId = randomId("ap");
    const token = randomToken();
    const t = now(ctx);
    ctx.db
      .query(
        `INSERT INTO approvals (id, token_hash, request_id, via, purpose, origin, fields, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      )
      .run(
        approvalId,
        hashToken(token),
        row.id,
        input.via,
        String(input.purpose ?? "").slice(0, 200),
        origin,
        JSON.stringify(fields.map((f) => f.name)),
        t,
        t + APPROVAL_TTL,
      );
    audit(ctx, row.id, "approval_requested", { approvalId, via: input.via, origin });
    return { kind: "approval", approvalId, approvalUrl: `${ctx.publicUrl}/a/${token}`, expiresAt: t + APPROVAL_TTL };
  }
  return grant(ctx, row, input.via, origin, fields);
}

async function grant(ctx: Ctx, row: RequestRow, via: Exclude<Via, "get">, origin: string | null, fields: Field[]): Promise<UseResult> {
  if (via === "inject") {
    const token = randomToken();
    const t = now(ctx);
    ctx.db
      .query("INSERT INTO use_tokens (token_hash, request_id, fields, origin, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(hashToken(token), row.id, JSON.stringify(fields.map((f) => f.name)), origin!, t, t + USE_TOKEN_TTL);
    audit(ctx, row.id, "use_token_minted", { origin, fields: fields.map((f) => f.name) });
    return { kind: "token", token, origin: origin!, fields: fields.map((f) => f.name), expiresAt: t + USE_TOKEN_TTL };
  }
  const values = subset(await loadValues(ctx, row), fields);
  markUsed(ctx, row, via);
  return { kind: "values", values, fields: Object.keys(values) };
}

/**
 * The autofill snippet's fetch. Burns the token on first sight, whatever happens next.
 * `requestOrigin` is the page's Origin header; for the CSP hop it's the origin of the URL the
 * hop page will return to (with the values encrypted under a key only that page holds).
 */
export async function redeemUseToken(ctx: Ctx, token: string, requestOrigin: string | null): Promise<{ status: number; body: AutofillPayload }> {
  const use = ctx.db.query("SELECT * FROM use_tokens WHERE token_hash = ?").get(hashToken(token)) as UseTokenRow | null;
  if (!use) return { status: 404, body: { ok: false, error: "missing" } };
  if (use.used_at != null) return { status: 410, body: { ok: false, error: "used" } };
  const t = now(ctx);
  ctx.db.query("UPDATE use_tokens SET used_at = ? WHERE token_hash = ?").run(t, use.token_hash);
  if (use.expires_at <= t) return { status: 410, body: { ok: false, error: "expired" } };
  if (requestOrigin !== use.origin) {
    audit(ctx, use.request_id, "use_origin_mismatch", { expected: use.origin, got: requestOrigin });
    return { status: 403, body: { ok: false, error: "origin" } };
  }
  const row = rowById(ctx, use.request_id);
  let values: Record<string, string>;
  try {
    values = await loadValues(ctx, row);
  } catch {
    return { status: 410, body: { ok: false, error: "expired" } };
  }
  const fields = pickFields(row, JSON.parse(use.fields));
  markUsed(ctx, row, "inject");
  audit(ctx, row.id, "autofill_delivered", { origin: use.origin, fields: fields.map((f) => f.name) });
  return {
    status: 200,
    body: { ok: true, origin: use.origin, fields: fields.filter((f) => values[f.name]).map((f) => ({ ...f, value: values[f.name]! })) },
  };
}

// ---------------------------------------------------------------------------
// Approvals for sealed secrets

function approvalStatusOf(ctx: Ctx, a: ApprovalRow): ApprovalSummary["status"] {
  if (a.redeemed_at != null) return "redeemed";
  if (a.status === "pending" && a.expires_at <= now(ctx)) return "expired";
  if (a.status === "approved" && a.expires_at <= now(ctx)) return "expired";
  return a.status as ApprovalSummary["status"];
}

function approvalById(ctx: Ctx, id: string): ApprovalRow {
  const a = ctx.db.query("SELECT * FROM approvals WHERE id = ?").get(id) as ApprovalRow | null;
  if (!a) throw new LockedError("not_found", `no approval ${id}`, 404);
  return a;
}

export function getApproval(ctx: Ctx, id: string): ApprovalSummary {
  const a = approvalById(ctx, id);
  return {
    id: a.id,
    requestId: a.request_id,
    status: approvalStatusOf(ctx, a),
    via: a.via as Via,
    purpose: a.purpose,
    origin: a.origin,
    fields: JSON.parse(a.fields),
    createdAt: a.created_at,
    expiresAt: a.expires_at,
  };
}

export function approvePageData(ctx: Ctx, token: string): ApprovePageData {
  const a = ctx.db.query("SELECT * FROM approvals WHERE token_hash = ?").get(hashToken(token)) as ApprovalRow | null;
  if (!a) return { state: "missing" };
  const row = rowById(ctx, a.request_id);
  const status = approvalStatusOf(ctx, a);
  const state = status === "pending" ? "open" : status === "redeemed" ? "used" : status;
  return {
    state,
    id: a.id,
    requestId: a.request_id,
    label: row.label,
    site: a.origin ?? row.site,
    via: a.via as Via,
    purpose: a.purpose,
    fields: JSON.parse(a.fields),
    createdAt: a.created_at,
    expiresAt: a.expires_at,
  };
}

export function decideApproval(ctx: Ctx, token: string, decision: "approve" | "deny") {
  const a = ctx.db.query("SELECT * FROM approvals WHERE token_hash = ?").get(hashToken(token)) as ApprovalRow | null;
  if (!a) throw new LockedError("missing", "this approval link doesn't exist", 404);
  const status = approvalStatusOf(ctx, a);
  if (status !== "pending") throw new LockedError(status, `this approval is already ${status}`, 409);
  if (decision !== "approve" && decision !== "deny") throw new LockedError("bad_post", "decision is approve or deny");
  const next = decision === "approve" ? "approved" : "denied";
  ctx.db.query("UPDATE approvals SET status = ?, decided_at = ? WHERE id = ?").run(next, now(ctx), a.id);
  audit(ctx, a.request_id, next, { approvalId: a.id, via: a.via });
  notify(a.id);
  return { state: next };
}

/** After the user approves: hand out the token (inject) or values (exec/copy). One redemption per approval. */
export async function redeemApproval(ctx: Ctx, approvalId: string, via?: Via): Promise<UseResult> {
  const a = approvalById(ctx, approvalId);
  const status = approvalStatusOf(ctx, a);
  if (status !== "approved") {
    throw new LockedError(`approval_${status}`, `approval ${approvalId} is ${status === "pending" ? "still waiting for the user" : status}`, 409);
  }
  if (via && via !== a.via) throw new LockedError("bad_via", `approval ${approvalId} was for ${a.via}, not ${via}`, 409);
  ctx.db.query("UPDATE approvals SET redeemed_at = ? WHERE id = ?").run(now(ctx), a.id);
  const row = rowById(ctx, a.request_id);
  return grant(ctx, row, a.via as Exclude<Via, "get">, a.origin, pickFields(row, JSON.parse(a.fields)));
}

// ---------------------------------------------------------------------------
// Ending things

export function revoke(ctx: Ctx, id: string) {
  const row = rowById(ctx, id);
  ctx.db.transaction(() => {
    ctx.db.query("UPDATE requests SET status = 'revoked', secret = NULL, fill_private_key = NULL, secret_expires_at = NULL WHERE id = ?").run(row.id);
    ctx.db.query("DELETE FROM use_tokens WHERE request_id = ?").run(row.id);
    ctx.db.query("UPDATE approvals SET status = 'denied' WHERE request_id = ? AND status = 'pending'").run(row.id);
  })();
  audit(ctx, row.id, "revoked");
  notify(row.id);
  return getRequest(ctx, id);
}

/** Expire links, wipe secrets past their retention, drop dead tokens. Runs every 30 s. */
export function sweep(ctx: Ctx) {
  const t = now(ctx);
  const expiredLinks = ctx.db
    .query("SELECT id FROM requests WHERE status = 'pending' AND link_expires_at <= ?")
    .all(t) as Array<{ id: string }>;
  const expiredSecrets = ctx.db
    .query("SELECT id FROM requests WHERE status = 'filled' AND secret_expires_at IS NOT NULL AND secret_expires_at <= ?")
    .all(t) as Array<{ id: string }>;
  const expiredApprovals = ctx.db
    .query("SELECT id FROM approvals WHERE status = 'pending' AND expires_at <= ?")
    .all(t) as Array<{ id: string }>;
  ctx.db.transaction(() => {
    ctx.db.query("UPDATE requests SET status = 'expired', fill_private_key = NULL WHERE status = 'pending' AND link_expires_at <= ?").run(t);
    ctx.db
      .query("UPDATE requests SET status = 'expired', secret = NULL WHERE status = 'filled' AND secret_expires_at IS NOT NULL AND secret_expires_at <= ?")
      .run(t);
    ctx.db.query("UPDATE approvals SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?").run(t);
    ctx.db.query("DELETE FROM use_tokens WHERE expires_at <= ?").run(t - 10 * MIN);
  })();
  for (const { id } of expiredLinks) {
    audit(ctx, id, "link_expired");
    notify(id);
  }
  for (const { id } of expiredSecrets) audit(ctx, id, "secret_wiped");
  for (const { id } of expiredApprovals) notify(id);
}
