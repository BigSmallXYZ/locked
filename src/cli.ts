import { existsSync, lstatSync, mkdirSync, readlinkSync, statSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { AGENT_PORT, agentToken, ensureHome, HOME, LOCAL_URL, paths, PUBLIC_PORT, TUNNEL_NAME } from "./config.ts";
import { api, CliError, startInBackground, stopServer } from "./client.ts";
import type { RequestSummary, UseResult, ApprovalSummary } from "./requests.ts";
import { matchRequest } from "./resolve.ts";
import type { PanelEvent, PanelSummary } from "./server/panels.ts";
import type { DeviceSummary, PairingSummary, ShareEvent, ShareSummary } from "./server/phone.ts";
import type { Provider, TunnelConfig } from "./tunnel.ts";

const EXIT = { ok: 0, failed: 1, pending: 2, needsApproval: 3 } as const;
const WAIT_DEFAULT_S = 110; // the Bash tool gives up at 120 s
const WAIT_MAX_S = 115;

const out = (s = ""): void => void process.stdout.write(s + "\n");
const err = (s = ""): void => void process.stderr.write(s + "\n");

// ---------------------------------------------------------------------------
// Small helpers

function duration(text: string): number {
  const m = /^(\d+(?:\.\d+)?)(s|m|h|d)?$/.exec(text.trim());
  if (!m) throw new CliError(`bad duration "${text}" (use e.g. 90s, 15m, 2h)`);
  return Number(m[1]) * { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[(m[2] ?? "m") as "s"];
}

function relative(ts: number | null | undefined): string {
  if (!ts) return "never";
  const d = ts - Date.now();
  const abs = Math.abs(d);
  const text = abs < 90_000 ? `${Math.round(abs / 1000)} s` : abs < 5_400_000 ? `${Math.round(abs / 60_000)} min` : abs < 172_800_000 ? `${Math.round(abs / 3_600_000)} h` : `${Math.round(abs / 86_400_000)} d`;
  return d >= 0 ? `in ${text}` : `${text} ago`;
}

/** "password", "password:password", "otp:otp?", "recovery_code?" */
function parseField(spec: string) {
  const m = /^([a-zA-Z][a-zA-Z0-9_-]*)(?::([a-z-]+))?(\?)?$/.exec(spec.trim());
  if (!m) throw new CliError(`bad --field "${spec}" (use name[:type][?], e.g. password, otp:otp?, key:apikey)`);
  return { name: m[1]!, ...(m[2] ? { type: m[2] } : {}), required: !m[3] };
}

function quote(arg: string) {
  return /^[A-Za-z0-9_\/.:=@%+,-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** The current command line with `--approval <id>` added, for "run this next". */
function rerunWith(approvalId: string) {
  const args = process.argv.slice(2);
  const dash = args.indexOf("--");
  const head = dash === -1 ? args : args.slice(0, dash);
  const tail = dash === -1 ? [] : args.slice(dash);
  return ["locked", ...head, "--approval", approvalId, ...tail].map(quote).join(" ");
}

function envName(field: string) {
  return "LOCKED_" + field.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

function list(v: string | string[] | undefined): string[] | undefined {
  if (v == null) return undefined;
  return (Array.isArray(v) ? v : [v]).flatMap((x) => x.split(",")).map((x) => x.trim()).filter(Boolean);
}

type Options = Record<string, { type: "string" | "boolean"; multiple?: boolean }>;

function args(argv: string[], options: Options): { values: Record<string, any>; positionals: string[] } {
  try {
    return parseArgs({ args: argv, options: { json: { type: "boolean" }, ...options }, allowPositionals: true, strict: true });
  } catch (e) {
    throw new CliError((e as Error).message);
  }
}

// ---------------------------------------------------------------------------
// Waiting

async function waitRequest(id: string, timeoutS: number): Promise<RequestSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  let r: { done: boolean; request: RequestSummary };
  do {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    r = await api("GET", `/api/requests/${id}/wait?timeout=${left}`);
  } while (!r.done && Date.now() < deadline - 500);
  return r.request;
}

async function waitApproval(id: string, timeoutS: number): Promise<ApprovalSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  let r: { done: boolean; approval: ApprovalSummary };
  do {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    r = await api("GET", `/api/approvals/${id}/wait?timeout=${left}`);
  } while (!r.done && Date.now() < deadline - 500);
  return r.approval;
}

const usedEvent = (e: PanelEvent) => e.event === "typed" || e.event === "copied";

/** Follows a panel's clicks until every field was typed or copied, it closes, or the time runs out. */
async function followPanel(id: string, timeoutS: number, onEvent: (e: PanelEvent) => void): Promise<PanelSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  let seen = 0;
  for (;;) {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    const { panel: p } = await api<{ panel: PanelSummary }>("GET", `/api/panels/${id}/wait?timeout=${left}&after=${seen}`);
    for (const e of p.events.slice(seen)) onEvent(e);
    seen = p.events.length;
    const allUsed = p.fields.every((f) => p.events.some((e) => e.field === f && usedEvent(e)));
    if (p.status === "closed" || p.status === "failed" || allUsed || Date.now() >= deadline - 500) return p;
  }
}

function printPanelEvent(e: PanelEvent) {
  if (e.event === "needs_accessibility") {
    out("The user clicked Type, but Locked isn't allowed to type yet: they need to turn on Locked in System Settings → Privacy & Security → Accessibility (macOS just asked them). Copy works meanwhile.");
  } else if (usedEvent(e)) out(`The user ${e.event} ${e.field}.`);
}

function describePanel(p: PanelSummary): { line: string; code: number } {
  const used = [...new Set(p.events.filter(usedEvent).map((e) => `${e.event} ${e.field}`))];
  const allUsed = p.fields.every((f) => p.events.some((e) => e.field === f && usedEvent(e)));
  if (p.status === "failed") return { line: `${p.id} failed: ${p.error ?? "unknown error"}`, code: EXIT.failed };
  if (used.length && (allUsed || p.status === "closed")) {
    return { line: `${p.id}: the user ${used.join(", ")}. ${p.status === "closed" ? "The panel is closed." : "The panel closes on its own."}`, code: EXIT.ok };
  }
  if (p.status === "closed") return { line: `${p.id} was closed without being used.`, code: EXIT.failed };
  const sofar = used.length ? `so far the user ${used.join(", ")}` : "nothing typed or copied yet";
  return { line: `${p.id} still open (it closes ${relative(p.expiresAt)}); ${sofar}. Run \`locked wait ${p.id}\` to keep waiting.`, code: EXIT.pending };
}

const shareUsed = (e: ShareEvent) => e.event === "copied" || e.event === "shown";

/** Follows a phone share until every field was copied or shown, it closes, or the time runs out. */
async function followShare(id: string, timeoutS: number, onEvent: (e: ShareEvent) => void): Promise<ShareSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  let seen = 0;
  for (;;) {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    const { share: s } = await api<{ share: ShareSummary }>("GET", `/api/shares/${id}/wait?timeout=${left}&after=${seen}`);
    for (const e of s.events.slice(seen)) onEvent(e);
    seen = s.events.length;
    const allUsed = s.fields.every((f) => s.events.some((e) => e.field === f && shareUsed(e)));
    if (s.status === "closed" || s.status === "failed" || allUsed || Date.now() >= deadline - 500) return s;
  }
}

function printShareEvent(e: ShareEvent) {
  if (e.event === "delivered") out("The notification reached the phone.");
  else if (e.event === "opened") out("The user opened it on the phone.");
  else if (e.event === "unlocked") out("The user unlocked it on the phone.");
  else if (shareUsed(e)) out(`The user ${e.event === "shown" ? "showed" : "copied"} ${e.field} on the phone.`);
}

function describeShare(s: ShareSummary): { line: string; code: number } {
  const used = [...new Set(s.events.filter(shareUsed).map((e) => `${e.event === "shown" ? "showed" : "copied"} ${e.field}`))];
  const allUsed = s.fields.every((f) => s.events.some((e) => e.field === f && shareUsed(e)));
  const has = (event: string) => s.events.some((e) => e.event === event);
  if (s.status === "failed") return { line: `${s.id} failed: ${s.error ?? "unknown error"}`, code: EXIT.failed };
  if (used.length && (allUsed || s.status === "closed")) {
    return { line: `${s.id}: on the phone, the user ${used.join(", ")}. ${s.status === "closed" ? "It's closed now." : `It closes on its own ${relative(s.expiresAt)}.`}`, code: EXIT.ok };
  }
  if (s.status === "closed") {
    return { line: `${s.id} closed ${has("unlocked") ? "after the user unlocked it, without copying or showing anything" : "without being unlocked"}.`, code: EXIT.failed };
  }
  const sofar = used.length
    ? `so far the user ${used.join(", ")}`
    : has("unlocked")
      ? "unlocked, nothing copied yet"
      : has("opened")
        ? "opened, not unlocked yet"
        : has("delivered")
          ? "the notification arrived, not opened yet"
          : "not opened yet";
  return { line: `${s.id} is on the phone (it closes ${relative(s.expiresAt)}); ${sofar}. Run \`locked wait ${s.id}\` to keep waiting.`, code: EXIT.pending };
}

async function waitPairing(id: string, timeoutS: number): Promise<PairingSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  for (;;) {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    const { pairing } = await api<{ pairing: PairingSummary }>("GET", `/api/pairings/${id}/wait?timeout=${left}`);
    if (pairing.status !== "pending" || Date.now() >= deadline - 500) return pairing;
  }
}

function describePairing(p: PairingSummary): { line: string; code: number } {
  if (p.status === "paired") {
    const push = p.pushOk
      ? "A first notification went to it."
      : "But the first notification didn't go through: check that notifications for Locked are allowed on the phone, then run `locked phone test`.";
    return { line: `Paired “${p.name}” (${p.deviceId}). ${push}`, code: p.pushOk ? EXIT.ok : EXIT.failed };
  }
  if (p.status === "expired") return { line: `${p.id} expired before the phone finished. Run \`locked phone pair\` again.`, code: EXIT.failed };
  return { line: `${p.id} is waiting for the phone (expires ${relative(p.expiresAt)}). Run \`locked wait ${p.id}\` to keep waiting.`, code: EXIT.pending };
}

/** Seconds: a bare number, or a duration like 90s, 10m, 1h. */
const seconds = (v: unknown) => (v === undefined ? undefined : /^\d+$/.test(String(v)) ? Number(v) : duration(String(v)) / 1000);

/** `lk_…` ids pass through; anything else is looked up by label or site among stored secrets. */
async function resolveId(query: string | undefined, usage: string): Promise<string> {
  if (!query) throw new CliError(usage);
  if (/^lk_[a-z0-9]+$/i.test(query)) return query;
  return (await resolveRequest(query)).id;
}

async function resolveRequest(query: string): Promise<RequestSummary> {
  if (/^lk_[a-z0-9]+$/i.test(query)) return (await api<{ request: RequestSummary }>("GET", `/api/requests/${query}`)).request;
  const { requests } = await api<{ requests: RequestSummary[] }>("GET", "/api/requests?stored=1&limit=1000");
  const m = matchRequest(requests, query);
  if (m.ok) return m.request;
  if (m.reason === "none") throw new CliError(`no stored secret matches "${query}" (see: locked creds)`);
  const lines = m.candidates.map((r) => `  ${r.id}  ${r.label}${r.site ? `  (${r.site})` : ""}`);
  throw new CliError(`"${query}" matches ${m.candidates.length} stored secrets; use one of these ids:\n${lines.join("\n")}`);
}

function describeRequest(r: RequestSummary): { line: string; code: number } {
  const fields = r.fields.map((f) => f.name).join(", ");
  switch (r.status) {
    case "filled": {
      const use =
        r.level === "sealed"
          ? `Sealed: use it with locked inject|exec|copy|panel ${r.id} (each use asks the user).`
          : `Use it: locked inject ${r.id} · locked exec ${r.id} -- <cmd> · locked panel ${r.id} · locked copy ${r.id} <field>`;
      return { line: `${r.id} filled (${fields}). ${use}`, code: EXIT.ok };
    }
    case "pending": {
      const opened = r.openedAt ? `the user opened the link ${relative(r.openedAt)}` : "the link hasn't been opened yet";
      return { line: `${r.id} still waiting: ${opened}; it expires ${relative(r.linkExpiresAt)}. Run \`locked wait ${r.id}\` again.`, code: EXIT.pending };
    }
    case "declined":
      return { line: `${r.id} declined by the user${r.declineNote ? `: "${r.declineNote}"` : "."}`, code: EXIT.failed };
    case "expired":
      return { line: `${r.id} expired. Create a new request if you still need it.`, code: EXIT.failed };
    case "revoked":
      return { line: `${r.id} was revoked.`, code: EXIT.failed };
  }
}

function describeApproval(a: ApprovalSummary): { line: string; code: number } {
  switch (a.status) {
    case "approved":
      return { line: `${a.id} approved. Run the same command again with --approval ${a.id}.`, code: EXIT.ok };
    case "pending":
      return { line: `${a.id} still waiting for the user to approve (expires ${relative(a.expiresAt)}). Run \`locked wait ${a.id}\` again.`, code: EXIT.pending };
    case "denied":
      return { line: `${a.id} denied by the user.`, code: EXIT.failed };
    case "expired":
      return { line: `${a.id} expired before it was used.`, code: EXIT.failed };
    case "redeemed":
      return { line: `${a.id} was already used. Each approval covers one use.`, code: EXIT.failed };
  }
}

/**
 * Gets a use grant for inject/exec/copy. Sealed requests first need the user's approval:
 * without --approval this prints the approval link and exits 3; with it, waits and redeems.
 */
async function obtain(
  id: string,
  via: "inject" | "exec" | "copy",
  opts: { only?: string[]; origin?: string; purpose?: string; approval?: string },
): Promise<Exclude<UseResult, { kind: "approval" }>> {
  if (opts.approval) {
    const a = await waitApproval(opts.approval, WAIT_DEFAULT_S);
    if (a.requestId !== id) throw new CliError(`${opts.approval} belongs to ${a.requestId}, not ${id}`);
    if (a.status !== "approved") {
      const d = describeApproval(a);
      throw new CliError(a.status === "pending" ? `${a.id} still waiting for the user. Run the same command again.` : d.line, d.code);
    }
    return api("POST", `/api/approvals/${opts.approval}/redeem`, { via });
  }
  const r = await api<UseResult & { ok: true }>("POST", `/api/requests/${id}/use`, { via, only: opts.only, origin: opts.origin, purpose: opts.purpose });
  if (r.kind === "approval") {
    out(`${id} is sealed, so this use needs the user's OK.`);
    out(`Send the user this link (valid ${relative(r.expiresAt).replace("in ", "")}):`);
    out(`  ${r.approvalUrl}`);
    out(`Then run: ${rerunWith(r.approvalId)}`);
    throw new CliError("", EXIT.needsApproval);
  }
  return r;
}

// ---------------------------------------------------------------------------
// Commands

const commands: Record<string, (argv: string[]) => Promise<number | void>> = {
  async request(argv) {
    const { values: o } = args(argv, {
      label: { type: "string" },
      site: { type: "string" },
      reason: { type: "string" },
      field: { type: "string", multiple: true },
      login: { type: "boolean" },
      level: { type: "string" },
      ttl: { type: "string" },
      keep: { type: "string" },
      wait: { type: "boolean" },
      timeout: { type: "string" },
    });
    const fields = [
      ...(o.login ? [{ name: "username", required: true }, { name: "password", required: true }] : []),
      ...((o.field as string[] | undefined) ?? []).map(parseField),
    ];
    if (!o.label) throw new CliError('--label is required, e.g. --label "GitHub login"');
    if (fields.length === 0) throw new CliError("ask for something: --login, or --field name[:type] (repeatable)");
    const r = await api("POST", "/api/requests", {
      label: o.label,
      site: o.site,
      reason: o.reason,
      fields,
      level: o.level,
      ttlMs: o.ttl ? duration(o.ttl as string) : undefined,
      retention: o.keep,
    });
    if (o.json) out(JSON.stringify({ id: r.id, url: r.url, expiresAt: r.expiresAt, level: r.level, site: r.site, fields: r.fields }));
    else {
      out(`Created ${r.id} (${r.level}${r.site ? `, for ${r.site}` : ""}); the link expires ${relative(r.expiresAt)}.`);
      out(`Send the user this link:`);
      out(`  ${r.url}`);
      out(`Then run: locked wait ${r.id}`);
    }
    if (o.wait) {
      const d = describeRequest(await waitRequest(r.id, Number(o.timeout ?? WAIT_DEFAULT_S)));
      out(d.line);
      return d.code;
    }
  },

  async wait(argv) {
    const { values: o, positionals: [id] } = args(argv, { timeout: { type: "string" } });
    if (!id) throw new CliError("usage: locked wait <lk_…|ap_…|pn_…|ps_…|pr_…>");
    const timeout = Number(o.timeout ?? WAIT_DEFAULT_S);
    if (id.startsWith("ps_")) {
      const s = await followShare(id, timeout, o.json ? () => {} : printShareEvent);
      const d = describeShare(s);
      out(o.json ? JSON.stringify(s) : d.line);
      return d.code;
    }
    if (id.startsWith("pr_")) {
      const p = await waitPairing(id, timeout);
      const d = describePairing(p);
      out(o.json ? JSON.stringify(p) : d.line);
      return d.code;
    }
    if (id.startsWith("pn_")) {
      const p = await followPanel(id, timeout, o.json ? () => {} : printPanelEvent);
      const d = describePanel(p);
      out(o.json ? JSON.stringify(p) : d.line);
      return d.code;
    }
    if (id.startsWith("ap_")) {
      const a = await waitApproval(id, timeout);
      const d = describeApproval(a);
      out(o.json ? JSON.stringify({ id: a.id, status: a.status, requestId: a.requestId }) : d.line);
      return d.code;
    }
    const r = await waitRequest(id, timeout);
    const d = describeRequest(r);
    out(o.json ? JSON.stringify({ id: r.id, status: r.status, opened: !!r.openedAt, fields: r.fields.map((f) => f.name), declineNote: r.declineNote }) : d.line);
    return d.code;
  },

  async status(argv) {
    const { values: o, positionals: [id] } = args(argv, {});
    if (!id) return commands.list!(argv);
    if (id.startsWith("pn_")) {
      const { panel } = await api<{ panel: PanelSummary }>("GET", `/api/panels/${id}`);
      out(o.json ? JSON.stringify(panel) : describePanel(panel).line);
      return;
    }
    if (id.startsWith("ps_")) {
      const { share } = await api<{ share: ShareSummary }>("GET", `/api/shares/${id}`);
      out(o.json ? JSON.stringify(share) : describeShare(share).line);
      return;
    }
    if (id.startsWith("pr_")) {
      const { pairing } = await api<{ pairing: PairingSummary }>("GET", `/api/pairings/${id}`);
      out(o.json ? JSON.stringify(pairing) : describePairing(pairing).line);
      return;
    }
    if (id.startsWith("ap_")) {
      const { approval } = await api("GET", `/api/approvals/${id}`);
      out(o.json ? JSON.stringify(approval) : describeApproval(approval).line);
      return;
    }
    const { request: r } = (await api("GET", `/api/requests/${id}`)) as { request: RequestSummary };
    if (o.json) return out(JSON.stringify(r));
    out(`${r.id}  ${r.label}`);
    out(`  status    ${r.status}${r.status === "pending" ? ` (link expires ${relative(r.linkExpiresAt)}, ${r.openedAt ? "opened" : "not opened"})` : ""}`);
    out(`  level     ${r.level}`);
    out(`  site      ${r.site ?? "any (not bound)"}`);
    out(`  fields    ${r.fields.map((f) => `${f.name}:${f.type}${f.required ? "" : "?"}`).join(", ")}`);
    if (r.reason) out(`  reason    ${r.reason}`);
    if (r.filledAt) out(`  filled    ${relative(r.filledAt)}, keep ${r.retention}${r.secretExpiresAt ? `, wiped ${relative(r.secretExpiresAt)}` : ""}`);
    out(`  used      ${r.useCount}×`);
  },

  async list(argv) {
    const { values: o } = args(argv, { limit: { type: "string" }, stored: { type: "boolean" } });
    if (o.stored) return commands.creds!(argv.filter((a) => a !== "--stored"));
    const { requests } = (await api("GET", `/api/requests?limit=${Number(o.limit ?? 20)}`)) as { requests: RequestSummary[] };
    if (o.json) return out(JSON.stringify(requests));
    if (requests.length === 0) return out("No requests yet. Create one with: locked request --label … --login");
    for (const r of requests) {
      out(`${r.id}  ${r.status.padEnd(8)} ${r.level.padEnd(6)} ${r.label}${r.site ? `  (${r.site})` : ""}  · ${relative(r.createdAt)}`);
    }
  },

  /** The secrets you can use right now. */
  async creds(argv) {
    const { values: o } = args(argv, { limit: { type: "string" } });
    const { requests } = (await api("GET", `/api/requests?stored=1&limit=${Number(o.limit ?? 200)}`)) as { requests: RequestSummary[] };
    if (o.json) return out(JSON.stringify(requests));
    if (requests.length === 0) return out("Nothing stored. Secrets show up here once someone fills a request.");
    for (const r of requests) {
      const kept = r.secretExpiresAt ? `wiped ${relative(r.secretExpiresAt)}` : "kept until revoked";
      out(`${r.id}  ${r.level.padEnd(6)} ${r.label}${r.site ? `  (${r.site})` : ""}  [${r.fields.map((f) => f.name).join(", ")}]  · ${kept} · used ${r.useCount}×`);
    }
  },

  async get(argv) {
    const { values: o, positionals: [query] } = args(argv, { field: { type: "string", multiple: true }, copy: { type: "boolean" }, clear: { type: "string" } });
    if (!query) throw new CliError("usage: locked get <id|name> [--field name] [--copy [--clear 30]]");
    const req = await resolveRequest(query);
    const sealed = req.level === "sealed";
    let only = list(o.field as string[] | undefined);
    if (o.copy) {
      const { clipboardSupported, copySecret } = await import("./clipboard.ts");
      if (!clipboardSupported()) throw new CliError("clipboard copy only works on macOS");
      const field = only?.[0] ?? (req.fields.find((f) => /password|apikey|otp/.test(f.type)) ?? req.fields[0])?.name;
      if (!field) throw new CliError(`${req.id} has no fields`);
      if (sealed) err(`${req.id} is sealed: confirm with Touch ID on the Mac…`);
      const r = await api<{ values: Record<string, string> }>("POST", `/api/requests/${req.id}/reveal`, { only: [field], deviceAuth: sealed });
      const value = r.values[field];
      if (!value) throw new CliError(`${req.id} has no value for ${field}`);
      const clearAfterSec = Number(o.clear ?? 30);
      await copySecret(value, { clearAfterSec });
      return out(`Copied ${field} of ${req.label} (${req.id}); the clipboard clears in ${clearAfterSec} s.`);
    }
    // A sealed value only prints into a real terminal, never into a pipe or an agent's tool output.
    if (sealed && !process.stdout.isTTY) {
      throw new CliError(`${req.id} is sealed: it only prints in your own terminal, after Touch ID. Use --copy, or locked panel, inject or exec.`, 1, "sealed");
    }
    if (sealed) err(`${req.id} is sealed: confirm with Touch ID on the Mac…`);
    const r = await api<{ values: Record<string, string> }>("POST", `/api/requests/${req.id}/reveal`, { only, deviceAuth: sealed });
    if (o.json) out(JSON.stringify(r.values));
    else if (only?.length === 1) out(r.values[only[0]!] ?? "");
    else for (const [k, v] of Object.entries(r.values)) out(`${k}: ${v}`);
    if (!process.stdout.isTTY) err("(printed secret values: don't repeat them in chat)");
  },

  async panel(argv) {
    const { values: o, positionals: [query] } = args(argv, {
      only: { type: "string", multiple: true },
      purpose: { type: "string" },
      timeout: { type: "string" },
      "no-wait": { type: "boolean" },
    });
    const id = await resolveId(query, "usage: locked panel <id|name> [--only a,b] [--purpose …] [--timeout 120] [--no-wait]");
    const { panel } = await api<{ panel: PanelSummary }>("POST", `/api/requests/${id}/panel`, {
      only: list(o.only as string[] | undefined),
      purpose: o.purpose,
      timeoutSec: o.timeout ? Number(o.timeout) : undefined,
    });
    if (o.json && o["no-wait"]) return out(JSON.stringify(panel));
    out(`Showing a Locked panel (${panel.id}) on the Mac, top right, for ${panel.fields.join(", ")} of ${id}.`);
    out(`Tell the user: click the input on the page, then click Type in the panel (or Copy, then paste).`);
    if (o["no-wait"]) return out(`Follow it with: locked wait ${panel.id}`);
    const p = await followPanel(panel.id, WAIT_DEFAULT_S, o.json ? () => {} : printPanelEvent);
    const d = describePanel(p);
    out(o.json ? JSON.stringify(p) : d.line);
    return d.code;
  },

  async phone(argv) {
    const [sub, ...rest] = argv;
    const usage = "usage: locked phone pair [--name …] | send <id> [--only a,b] [--purpose …] [--timeout 10m] | list | test [<dv_…>] | remove <dv_…>";
    if (sub === "pair") {
      const { values: o } = args(rest, { name: { type: "string" }, "no-wait": { type: "boolean" } });
      const t = await import("./tunnel.ts");
      const tunnel = t.loadTunnelConfig();
      if (tunnel.provider === "none") throw new CliError("a phone needs a fixed https address; set up a tunnel first (locked tunnel use ngrok --domain <reserved>, or cloudflare for your own domain)");
      if (t.urlChanges(tunnel)) err("Warning: this tunnel gets a new address on restart, and that unpairs the phone. For a phone, use a fixed address: locked tunnel use ngrok --domain <reserved>, or cloudflare for your own domain.");
      const r = await api<{ pairing: PairingSummary; code: string; url: string }>("POST", "/api/pairings", { name: o.name });
      if (o.json && o["no-wait"]) return out(JSON.stringify(r));
      out(`Open this on the phone (it works once, for 10 minutes):`);
      out(`  ${r.url}`);
      out(`  code ${r.code}`);
      out(`iPhone: open it in Safari, tap Share → Add to Home Screen, open Locked from the Home Screen, enter the code, then allow notifications and create the passkey.`);
      out(`Android: open it in Chrome, allow notifications, create the passkey.`);
      if (o["no-wait"]) return out(`Then: locked wait ${r.pairing.id}`);
      const d = describePairing(await waitPairing(r.pairing.id, WAIT_DEFAULT_S));
      out(d.line);
      return d.code;
    }
    if (sub === "list" || sub === "devices") {
      const { values: o } = args(rest, {});
      const { devices } = await api<{ devices: DeviceSummary[] }>("GET", "/api/devices");
      if (o.json) return out(JSON.stringify(devices));
      if (devices.length === 0) return out("No phone is paired. Run `locked phone pair`.");
      for (const d of devices) {
        out(`${d.id}  ${d.name}  · paired ${relative(d.createdAt)} · last unlock ${relative(d.lastSeenAt)} · ${d.push ? "notifications on" : "notifications off (pair it again)"}`);
      }
      return;
    }
    if (sub === "remove") {
      const { positionals: [id] } = args(rest, {});
      if (!id) throw new CliError("usage: locked phone remove <dv_…>");
      const { device } = await api<{ device: DeviceSummary }>("DELETE", `/api/devices/${id}`);
      return out(`Removed ${device.name} (${device.id}). Its passkey no longer unlocks anything; delete it on the phone too (Settings → Passwords).`);
    }
    if (sub === "test") {
      const { positionals: [id] } = args(rest, {});
      const { results } = await api<{ results: Array<{ id: string; name: string; ok: boolean; error?: string }> }>("POST", "/api/devices/test", { deviceId: id });
      for (const r of results) out(`${r.id}  ${r.name}  ${r.ok ? "sent" : `failed: ${r.error}`}`);
      return results.every((r) => r.ok) ? EXIT.ok : EXIT.failed;
    }
    if (sub === "send") {
      const { values: o, positionals: [query] } = args(rest, {
        only: { type: "string", multiple: true },
        purpose: { type: "string" },
        timeout: { type: "string" },
        device: { type: "string" },
        "no-wait": { type: "boolean" },
      });
      const id = await resolveId(query, "usage: locked phone send <id|name> [--only a,b] [--purpose …] [--timeout 10m] [--device dv_…] [--no-wait]");
      const { share } = await api<{ share: ShareSummary }>("POST", `/api/requests/${id}/phone`, {
        only: list(o.only as string[] | undefined),
        purpose: o.purpose,
        timeoutSec: seconds(o.timeout),
        device: o.device,
      });
      if (o.json && o["no-wait"]) return out(JSON.stringify(share));
      const to = share.devices.filter((d) => d.ok).map((d) => d.name).join(", ");
      out(`Sent ${share.fields.join(", ")} of ${id} to ${to} (${share.id}); it closes ${relative(share.expiresAt)}.`);
      for (const d of share.devices.filter((x) => !x.ok)) err(`Not sent to ${d.name}: ${d.error}`);
      out(`Tell the user: tap the Locked notification on your phone, unlock it, then Copy (or Show).`);
      if (o["no-wait"]) return out(`Follow it with: locked wait ${share.id}`);
      const s = await followShare(share.id, WAIT_DEFAULT_S, o.json ? () => {} : printShareEvent);
      const d = describeShare(s);
      out(o.json ? JSON.stringify(s) : d.line);
      return d.code;
    }
    throw new CliError(usage);
  },

  async inject(argv) {
    const { values: o, positionals: [query] } = args(argv, {
      origin: { type: "string" },
      only: { type: "string", multiple: true },
      map: { type: "string", multiple: true },
      submit: { type: "boolean" },
      approval: { type: "string" },
      purpose: { type: "string" },
      base: { type: "string" },
    });
    const id = await resolveId(query, "usage: locked inject <id|name> [--origin …] [--only a,b] [--map field=css] [--submit]");
    const map: Record<string, string> = {};
    for (const m of (o.map as string[] | undefined) ?? []) {
      const i = m.indexOf("=");
      if (i < 1) throw new CliError(`bad --map "${m}" (use field=css-selector)`);
      map[m.slice(0, i)] = m.slice(i + 1);
    }
    const grant = await obtain(id, "inject", { only: list(o.only as string[] | undefined), origin: o.origin as string | undefined, purpose: (o.purpose as string) ?? "sign in", approval: o.approval as string | undefined });
    if (grant.kind !== "token") throw new CliError("unexpected grant");
    const base = (o.base as string | undefined) ?? (await api("GET", "/api/health")).publicUrl;
    const { buildSnippet } = await import("./inject.ts");
    const snippet = buildSnippet({ base, token: grant.token, map: Object.keys(map).length ? map : undefined, submit: !!o.submit });
    if (o.json) return out(JSON.stringify({ snippet, origin: grant.origin, fields: grant.fields, expiresAt: grant.expiresAt }));
    err(`One-time autofill of ${grant.fields.join(", ")} into ${grant.origin}. Works once, for 60 s.`);
    err(`Run this in that page with your browser's JavaScript tool. It returns {ok, filled, missing}; never the values.`);
    err(`If it returns reason "hop", the page is reloading through Locked to get past its CSP: run the same snippet again once it has loaded.`);
    err(`Last resort (form in a cross-origin iframe): locked copy ${id} <field>, focus the input, press cmd+V.`);
    out(snippet);
  },

  async exec(argv) {
    const dash = argv.indexOf("--");
    if (dash === -1 || dash === argv.length - 1) throw new CliError("usage: locked exec <id> [--env VAR=field]... -- <command> [args…]");
    const cmd = argv.slice(dash + 1);
    const { values: o, positionals: [query] } = args(argv.slice(0, dash), {
      env: { type: "string", multiple: true },
      approval: { type: "string" },
      purpose: { type: "string" },
    });
    const id = await resolveId(query, "usage: locked exec <id|name> [--env VAR=field]... -- <command> [args…]");
    const mapping: Array<[string, string]> = ((o.env as string[] | undefined) ?? []).map((m) => {
      const i = m.indexOf("=");
      if (i < 1) throw new CliError(`bad --env "${m}" (use VAR=field)`);
      return [m.slice(0, i), m.slice(i + 1)];
    });
    const only = mapping.length ? [...new Set(mapping.map(([, f]) => f))] : undefined;
    const grant = await obtain(id, "exec", { only, purpose: (o.purpose as string) ?? `run ${cmd[0]}`, approval: o.approval as string | undefined });
    if (grant.kind !== "values") throw new CliError("unexpected grant");
    const env: Record<string, string> = {};
    if (mapping.length) for (const [name, field] of mapping) env[name] = grant.values[field] ?? "";
    else for (const [field, value] of Object.entries(grant.values)) env[envName(field)] = value;
    const { execWithSecrets } = await import("./exec.ts");
    return execWithSecrets(cmd, { env, secrets: Object.entries(grant.values).map(([name, value]) => ({ name, value })) });
  },

  async copy(argv) {
    const { values: o, positionals: [query, field] } = args(argv, { clear: { type: "string" }, approval: { type: "string" }, purpose: { type: "string" } });
    if (!query || !field) throw new CliError("usage: locked copy <id|name> <field> [--clear 30]");
    const id = await resolveId(query, "");
    const { clipboardSupported, copySecret } = await import("./clipboard.ts");
    if (!clipboardSupported()) throw new CliError("clipboard copy only works on macOS");
    const grant = await obtain(id, "copy", { only: [field], purpose: (o.purpose as string) ?? "paste into a form", approval: o.approval as string | undefined });
    if (grant.kind !== "values") throw new CliError("unexpected grant");
    const value = grant.values[field];
    if (!value) throw new CliError(`${id} has no value for ${field}`);
    const clearAfterSec = Number(o.clear ?? 30);
    await copySecret(value, { clearAfterSec });
    out(`Copied ${field} of ${id} to the clipboard; it clears in ${clearAfterSec} s. Focus the input and press cmd+V.`);
  },

  async revoke(argv) {
    const { positionals: [id] } = args(argv, {});
    if (!id) throw new CliError("usage: locked revoke <id>");
    await api("DELETE", `/api/requests/${id}`);
    out(`${id} revoked; its secret is wiped.`);
  },

  async audit(argv) {
    const { values: o, positionals: [id] } = args(argv, {});
    const { events } = await api("GET", `/api/audit${id ? `?request=${encodeURIComponent(id)}` : ""}`);
    if (o.json) return out(JSON.stringify(events));
    for (const e of events.reverse()) out(`${new Date(e.ts).toISOString()}  ${(e.request_id ?? "").padEnd(13)} ${e.event}${e.detail ? `  ${e.detail}` : ""}`);
  },

  async serve(argv) {
    const { values: o } = args(argv, { "no-tunnel": { type: "boolean" } });
    const { startServers } = await import("./server/index.ts");
    const t = await import("./tunnel.ts");
    const config: TunnelConfig = o["no-tunnel"] ? { provider: "none" } : t.loadTunnelConfig();
    if (config.provider === "cloudflare" && !existsSync(paths.tunnelConfig)) throw new CliError(`no ${paths.tunnelConfig}; run: locked tunnel use cloudflare --hostname <host>`);
    const s = await startServers({ publicUrl: t.staticUrl(config) ?? LOCAL_URL });
    s.ctx.clientIpHeader = t.clientIpHeader(config);
    out(`Locked is running.`);
    out(`  public  http://127.0.0.1:${s.publicServer.port}`);
    out(`  agent   http://127.0.0.1:${s.agentServer.port}  (localhost only)`);
    out(`  key     ${s.keySource === "keychain" ? "macOS Keychain" : paths.masterKey}`);
    out(`  url     ${t.staticUrl(config) ?? `waiting for ${config.provider}…`}`);
    if (config.provider === "none") out(`  note    no tunnel: links only open on this machine. Add one with: locked tunnel use quick`);
    const tunnel = t.startTunnel(config, {
      onUrl(url) {
        if (url === s.ctx.publicUrl) return;
        s.ctx.publicUrl = url;
        out(`  url     ${url}`);
        if (t.urlChanges(config)) out(`  note    this address changes when the tunnel restarts; earlier links stop working`);
      },
      onLine: (text) => err(`[tunnel] ${text}`),
    });
    const stop = () => {
      tunnel.stop();
      s.stop();
      process.exit(0);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    await new Promise(() => {});
  },

  /** Everything at once: safe to run again, and an agent can run it for you. */
  async setup(argv) {
    const { values: o } = args(argv, { tunnel: { type: "string" }, "no-start": { type: "boolean" }, "no-install": { type: "boolean" }, ...TUNNEL_OPTIONS });
    ensureHome();
    agentToken();
    const { openContext } = await import("./server/index.ts");
    const { ctx, keySource, keyCreated } = await openContext();
    ctx.db.close();
    out(`~/.locked ready (${HOME})`);
    out(`  master key  ${keySource === "keychain" ? "macOS Keychain (service \"locked\")" : paths.masterKey}${keyCreated ? " (new)" : ""}`);
    out(`  agent token ${paths.agentToken}`);

    const t = await import("./tunnel.ts");
    if (o.tunnel) await useTunnel(o.tunnel as string, undefined, o);
    else if (existsSync(paths.tunnel)) out(`  tunnel      ${describeTunnel(t.loadTunnelConfig())}`);
    else {
      if (!t.detectProvider() && !o["no-install"] && Bun.which("brew")) {
        out(`No tunnel found; installing cloudflared with Homebrew…`);
        Bun.spawnSync(["brew", "install", "cloudflared"], { stdout: "inherit", stderr: "inherit" });
      }
      const provider = t.detectProvider();
      if (provider) await useTunnel(provider, undefined, o);
      else out(`  tunnel      none, so links only open on this machine. Install cloudflared, then: locked tunnel use quick`);
    }

    for (const line of installSkills(detectedAgents())) out(`  ${line}`);

    if (o["no-start"]) return out(`Start it with: locked serve`);
    const publicUrl = await restartServer();
    out(`Locked is running at ${publicUrl}. Your agent can now use it; check everything with: locked doctor`);
    if (t.urlChanges(t.loadTunnelConfig())) out(`This address changes when the tunnel restarts. For a phone or a lasting address, see docs/tunnels.md.`);
  },

  async restart() {
    out(`Locked is running at ${await restartServer()}.`);
  },

  async stop() {
    out((await stopServer()) ? "Locked stopped. It starts again the next time the CLI needs it." : "Locked wasn't running.");
  },

  async tunnel(argv) {
    const [sub = "status", ...rest] = argv;
    if (sub === "use") {
      const { values: o, positionals: [provider, target] } = args(rest, TUNNEL_OPTIONS);
      if (!provider) throw new CliError(TUNNEL_USAGE);
      return useTunnel(provider, target, o);
    }
    if (sub === "status") {
      const t = await import("./tunnel.ts");
      const config = t.loadTunnelConfig();
      out(`tunnel       ${describeTunnel(config)}`);
      out(`cloudflared  ${t.cloudflaredPath() ?? "not installed"}`);
      out(`ngrok        ${t.ngrokPath() ?? "not installed"}`);
      out(`tunnelmole   ${t.tunnelmolePath() ?? "not installed"}`);
      const health = await api<{ publicUrl: string }>("GET", "/api/health", undefined, { autostart: false }).catch(() => null);
      out(`public URL   ${health?.publicUrl ?? "Locked isn't running"}`);
      return;
    }
    throw new CliError(TUNNEL_USAGE);
  },

  async doctor() {
    let bad = 0;
    const check = (ok: boolean, label: string, detail: string) => {
      if (!ok) bad++;
      out(`${ok ? "✓" : "✗"} ${label.padEnd(14)} ${detail}`);
    };
    check(existsSync(HOME) && (statSync(HOME).mode & 0o077) === 0, "home", `${HOME}${existsSync(HOME) ? "" : " (missing: locked setup)"}`);
    check(existsSync(paths.agentToken) && (statSync(paths.agentToken).mode & 0o077) === 0, "agent token", paths.agentToken);
    const health = await api("GET", "/api/health", undefined, { autostart: false }).catch((e) => e as CliError);
    check(!(health instanceof CliError), "agent API", health instanceof CliError ? health.message : `127.0.0.1:${AGENT_PORT}, key in ${health.keySource}`);
    const local = await fetch(`http://127.0.0.1:${PUBLIC_PORT}/healthz`).then((r) => r.ok).catch(() => false);
    check(local, "public server", `127.0.0.1:${PUBLIC_PORT}`);
    const exposed = await fetch(`http://127.0.0.1:${PUBLIC_PORT}/api/health`).then((r) => r.status).catch(() => 0);
    check(exposed === 404 || exposed === 0, "api not public", exposed === 404 || exposed === 0 ? "the public listener has no /api" : `public listener answered /api with ${exposed}!`);
    const t = await import("./tunnel.ts");
    const tunnel = t.loadTunnelConfig();
    out(`– ${"tunnel".padEnd(14)} ${describeTunnel(tunnel)}`);
    if (tunnel.provider === "quick" || tunnel.provider === "cloudflare") check(!!t.cloudflaredPath(), "cloudflared", t.cloudflaredPath() ?? "not installed (brew install cloudflared)");
    if (tunnel.provider === "ngrok") check(!!t.ngrokPath(), "ngrok", t.ngrokPath() ?? "not installed (brew install ngrok)");
    if (tunnel.provider === "tunnelmole") check(!!t.tunnelmolePath(), "tunnelmole", t.tunnelmolePath() ?? "not installed (npm install -g tunnelmole)");
    if (tunnel.provider === "cloudflare") check(existsSync(paths.tunnelConfig), "tunnel config", existsSync(paths.tunnelConfig) ? paths.tunnelConfig : `missing (locked tunnel use cloudflare --hostname ${tunnel.host})`);
    const publicUrl = health instanceof CliError ? t.staticUrl(tunnel) : (health.publicUrl as string);
    if (tunnel.provider !== "none" && publicUrl) {
      const remote = await fetch(`${publicUrl}/healthz`, { signal: AbortSignal.timeout(8_000) }).then((r) => r.ok).catch(() => false);
      check(remote, "public URL", `${publicUrl}/healthz ${remote ? "reachable" : "unreachable (is the tunnel running? a new one can take a few seconds)"}`);
      const remoteApi = await fetch(`${publicUrl}/api/health`, { signal: AbortSignal.timeout(8_000) }).then((r) => r.status).catch(() => 0);
      if (remote) check(remoteApi === 404, "api via tunnel", remoteApi === 404 ? "not exposed (404)" : `answered ${remoteApi}!`);
    }
    if (process.platform === "darwin") {
      const { APP, panelAppState } = await import("./native.ts");
      const state = panelAppState();
      // Not a failure: the server builds the app at startup and before each panel.
      if (state === "ready") check(true, "native panel", APP);
      else out(`– ${"native panel".padEnd(14)} ${state === "missing" ? "not built yet" : "out of date"}; Locked builds it on start and before a panel (needs the Xcode Command Line Tools)`);
    }
    const skills = Object.values(SKILL_DIRS).map((dir) => join(dir(), "locked")).filter((p) => existsSync(join(p, "SKILL.md")));
    check(skills.length > 0, "agent skill", skills.join(", ") || "not installed (locked install-skill)");
    return bad ? EXIT.failed : EXIT.ok;
  },

  async "install-skill"(argv) {
    const { values: o } = args(argv, { agent: { type: "string" }, dir: { type: "string" } });
    if (o.dir) return void installSkills([o.dir as string]).forEach((line) => out(line));
    const agent = o.agent as string | undefined;
    if (agent && !(agent in AGENTS) && agent !== "all") throw new CliError(`usage: locked install-skill [--agent ${Object.keys(AGENTS).join("|")}|all] [--dir <skills folder>]`);
    const dirs = agent === "all" ? Object.values(SKILL_DIRS).map((d) => d()) : agent ? [SKILL_DIRS[AGENTS[agent]!]!()] : detectedAgents();
    for (const line of installSkills(dirs)) out(line);
  },

  /** The skill as text, for agents with their own instruction files. */
  async skill() {
    out(await Bun.file(SKILL_SOURCE).text());
  },

  async help() {
    out(HELP);
  },
};

const TUNNEL_OPTIONS: Options = {
  hostname: { type: "string" },
  domain: { type: "string" },
  url: { type: "string" },
  "client-ip-header": { type: "string" },
};
const TUNNEL_USAGE = "usage: locked tunnel [status] | use quick | use ngrok [--domain <reserved>] | use tunnelmole [--domain <reserved>] | use cloudflare --hostname <host> | use url <https://…> [--client-ip-header <header>] | use none";

function describeTunnel(c: TunnelConfig) {
  switch (c.provider) {
    case "quick":
      return "quick (cloudflared, no account; a new address on each restart)";
    case "ngrok":
      return `ngrok${c.host ? ` (${c.host})` : " (a new address on each restart)"}`;
    case "tunnelmole":
      return `tunnelmole${c.host ? ` (${c.host})` : " (a new address on each restart)"}`;
    case "cloudflare":
      return `cloudflare (${c.host})`;
    case "url":
      return `your own (${c.url})`;
    case "none":
      return "none (links only open on this machine)";
  }
}

async function useTunnel(provider: string, target: string | undefined, o: Record<string, any>) {
  const t = await import("./tunnel.ts");
  if (!t.PROVIDERS.includes(provider as Provider)) throw new CliError(TUNNEL_USAGE);
  let config: TunnelConfig = { provider: provider as Provider };
  if (provider === "quick" && !t.cloudflaredPath()) throw new CliError("cloudflared isn't installed (brew install cloudflared)");
  if (provider === "ngrok") {
    if (!t.ngrokPath()) throw new CliError("ngrok isn't installed (brew install ngrok, then ngrok config add-authtoken <token>)");
    if (o.domain) config.host = (o.domain as string).replace(/^https:\/\//, "").replace(/\/$/, "");
  }
  if (provider === "tunnelmole") {
    if (!t.tunnelmolePath()) throw new CliError("tunnelmole isn't installed (npm install -g tunnelmole)");
    if (o.domain) config.host = (o.domain as string).replace(/^https:\/\//, "").replace(/\/$/, "");
  }
  if (provider === "cloudflare") {
    if (!o.hostname) throw new CliError("cloudflare needs a hostname on a zone you own: locked tunnel use cloudflare --hostname locked.example.com");
    config.host = o.hostname as string;
    const r = t.setupNamedTunnel(config.host, out);
    out(`Tunnel "${TUNNEL_NAME}" ${r.created ? "created" : "already existed"} (${r.id}).`);
    out(`  dns     ${r.dns}`);
    out(`  config  ${r.configPath}`);
  }
  if (provider === "url") {
    const url = target ?? (o.url as string | undefined);
    if (!url || !/^https:\/\/[^/]+\/?$/.test(url)) throw new CliError("url needs the https address of your tunnel, with no path: locked tunnel use url https://locked.example.com");
    config = { provider: "url", url, ...(o["client-ip-header"] ? { clientIpHeader: o["client-ip-header"] as string } : {}) };
  }
  t.saveTunnelConfig(config);
  out(`Tunnel: ${describeTunnel(config)}.`);
  if (provider === "url") out(`Point it at http://127.0.0.1:${PUBLIC_PORT}, and only that port.`);
  out(`To apply it now: locked restart`);
}

async function restartServer() {
  if (await stopServer()) await Bun.sleep(2_500); // if pm2 is in charge, it brings the server back itself
  const running = await api<{ publicUrl: string }>("GET", "/api/health", undefined, { autostart: false }).catch(() => null);
  return (running ?? (await startInBackground())).publicUrl;
}

function lstatExists(p: string) {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

const SKILL_SOURCE = join(import.meta.dir, "..", "skill", "SKILL.md");

// User-level skill folders. ~/.agents/skills is the open Agent Skills location Codex reads.
const SKILL_DIRS: Record<string, () => string> = {
  claude: () => join(process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude"), "skills"),
  agents: () => join(homedir(), ".agents", "skills"),
};
const AGENTS: Record<string, string> = { claude: "claude", codex: "agents", agents: "agents" };

/** Skill folders for the agents on this machine; the shared one if none is recognized. */
function detectedAgents(): string[] {
  const found: string[] = [];
  if (existsSync(dirname(SKILL_DIRS.claude!())) || Bun.which("claude")) found.push(SKILL_DIRS.claude!());
  if (existsSync(join(homedir(), ".agents")) || existsSync(join(homedir(), ".codex")) || Bun.which("codex")) found.push(SKILL_DIRS.agents!());
  return found.length ? found : [SKILL_DIRS.agents!()];
}

/** Links the skill into each folder. Anything already there that isn't ours is left alone. */
function installSkills(dirs: string[]): string[] {
  const source = dirname(SKILL_SOURCE);
  return dirs.map((dir) => {
    const target = join(dir, "locked");
    mkdirSync(dir, { recursive: true });
    if (lstatExists(target)) {
      if (lstatSync(target).isSymbolicLink() && readlinkSync(target) === source) return `skill       ${target} (already installed)`;
      return `skill       skipped ${target}: something else is there`;
    }
    symlinkSync(source, target);
    return `skill       ${target}`;
  });
}

const HELP = `locked: hand secrets to your AI agent through a link instead of the chat.

Ask
  locked request --label "GitHub login" --site github.com --login [--reason …]
                 [--field name[:type][?]]… [--level sealed] [--ttl 15m] [--keep once|1h|24h|forever] [--wait]
  locked wait <lk_…|ap_…|pn_…|ps_…|pr_…> [--timeout 110]   exit 0 done · 2 still waiting (run again) · 1 declined/expired
  locked status [<id>] · locked list [--stored] · locked creds · locked audit [<id>]

Use (<id> is an lk_… id, or a name: a label or site of a stored secret, like "github")
  locked inject <id> [--origin …] [--only a,b] [--map field=css]… [--submit]   prints a one-time autofill snippet
  locked panel <id> [--only a,b] [--purpose …] [--timeout 120] [--no-wait]    Mac panel: the user clicks Type or Copy
  locked exec <id> [--env VAR=field]… -- <command…>                           env LOCKED_<FIELD>, output redacted
  locked copy <id> <field> [--clear 30]                                       clipboard, then cmd+V
  locked get <id> [--field f] [--copy [--clear 30]]                           prints values; sealed: Touch ID, your terminal only
  locked revoke <id>
  locked phone send <id> [--only a,b] [--purpose …] [--timeout 10m]          notification on the user's phone: unlock, then Copy or Show
  Sealed requests: inject/exec/copy exit 3 with an approval link; then add --approval ap_…
  panel and get ask for Touch ID on the Mac instead; phone send asks for Face ID on the phone.

Phone
  locked phone pair [--name "iPhone"]   once: a link and code to open on the phone (passkey + notifications)
  locked phone list · locked phone test [<dv_…>] · locked phone remove <dv_…>

Run
  locked setup [--tunnel <provider>] [--no-start] [--no-install]   tunnel, agent skills and server, all at once
  locked restart · locked stop · locked serve [--no-tunnel]        the CLI starts the server by itself when it's needed
  locked tunnel [status] · locked tunnel use quick | ngrok [--domain …] | tunnelmole [--domain …] | cloudflare --hostname … | url <https://…> | none
  locked doctor · locked install-skill [--agent claude|codex|all] [--dir <folder>] · locked skill

Field types: username email password new-password otp apikey text textarea url number
`;

// ---------------------------------------------------------------------------

async function main() {
  const [name = "help", ...rest] = process.argv.slice(2);
  const cmd = commands[name === "--help" || name === "-h" ? "help" : name];
  if (!cmd) {
    err(`unknown command "${name}"\n`);
    err(HELP);
    return EXIT.failed;
  }
  return (await cmd(rest)) ?? EXIT.ok;
}

main().then(
  (code) => process.exit(typeof code === "number" ? code : 0),
  (e) => {
    if (e instanceof CliError) {
      if (e.message) err(`locked: ${e.message}`);
      process.exit(e.exitCode);
    }
    err(`locked: ${(e as Error)?.stack ?? e}`);
    process.exit(1);
  },
);
