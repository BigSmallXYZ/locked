// Native panel sessions. `locked panel` asks for one; the server launches the macOS helper on a
// one-time handle (/api/panel/<token> on the agent listener) and the helper reports clicks back.
// Values leave the database only when the user first clicks Type or Copy, and only to the helper:
// the CLI that asked for the panel never sees them. Sessions live in memory; a restart ends them.

import { hashToken, randomId, randomToken } from "../crypto.ts";
import type { Field } from "../model.ts";
import type { Native } from "../native.ts";
import { LockedError, recordEvent, releaseTarget, releaseValues, type Ctx } from "../requests.ts";
import { notify } from "./waiters.ts";

export const PANEL_DEFAULT_SEC = 120;
export const PANEL_MAX_SEC = 600;
/** How long the helper has to call back after `open` before the panel counts as failed. */
const LAUNCH_GRACE_MS = 20_000;
/** Closed sessions stay readable (for `locked panel`'s last wait) this long. */
const KEEP_CLOSED_MS = 10 * 60_000;

export type PanelEvent = { at: number; event: string; field?: string };
export type PanelStatus = "launching" | "open" | "closed" | "failed";
export type PanelSummary = {
  id: string;
  requestId: string;
  status: PanelStatus;
  fields: string[];
  events: PanelEvent[];
  error?: string;
  expiresAt: number;
};

type Session = PanelSummary & {
  tokenHash: string;
  label: string;
  site: string | null;
  level: string;
  purpose: string;
  fieldInfo: Field[];
  timeoutSec: number;
  valuesTaken: boolean;
  closedAt?: number;
};

const sessions = new Map<string, Session>();
const byToken = new Map<string, string>();

const HELPER_EVENTS = new Set(["typed", "copied", "closed", "expired", "needs_accessibility"]);

function summary(s: Session): PanelSummary {
  const { id, requestId, status, fields, events, error, expiresAt } = s;
  return { id, requestId, status, fields, events: [...events], ...(error ? { error } : {}), expiresAt };
}

function end(ctx: Ctx, s: Session, status: "closed" | "failed", why: string, error?: string) {
  if (s.status === "closed" || s.status === "failed") return;
  s.status = status;
  s.closedAt = Date.now();
  if (error) s.error = error;
  byToken.delete(s.tokenHash);
  recordEvent(ctx, s.requestId, status === "failed" ? "panel_failed" : "panel_closed", { panelId: s.id, why });
  notify(s.id);
}

export function sweepPanels(ctx: Ctx) {
  const t = Date.now();
  for (const s of sessions.values()) {
    if ((s.status === "launching" || s.status === "open") && t > s.expiresAt + 30_000) end(ctx, s, "closed", "expired");
    if (s.closedAt && t - s.closedAt > KEEP_CLOSED_MS) sessions.delete(s.id);
  }
}

export async function openPanel(
  ctx: Ctx,
  native: Native,
  agentBase: string,
  requestId: string,
  opts: { only?: string[]; purpose?: string; timeoutSec?: number },
): Promise<PanelSummary> {
  sweepPanels(ctx);
  const { request, fields } = await releaseTarget(ctx, requestId, opts.only);
  const timeoutSec = Math.round(Math.min(Math.max(Number(opts.timeoutSec) || PANEL_DEFAULT_SEC, 10), PANEL_MAX_SEC));
  const token = randomToken();
  const s: Session = {
    id: randomId("pn"),
    requestId: request.id,
    status: "launching",
    fields: fields.map((f) => f.name),
    events: [],
    expiresAt: Date.now() + timeoutSec * 1000 + LAUNCH_GRACE_MS,
    tokenHash: hashToken(token),
    label: request.label,
    site: request.site,
    level: request.level,
    purpose: String(opts.purpose ?? "").slice(0, 200),
    fieldInfo: fields,
    timeoutSec,
    valuesTaken: false,
  };
  sessions.set(s.id, s);
  byToken.set(s.tokenHash, s.id);
  recordEvent(ctx, s.requestId, "panel_shown", { panelId: s.id, fields: s.fields });
  try {
    await native.showPanel(`${agentBase}/api/panel/${token}`);
  } catch (err) {
    end(ctx, s, "failed", "launch", String((err as Error)?.message ?? err));
    throw new LockedError("panel_failed", s.error!, 500);
  }
  setTimeout(() => {
    if (s.status === "launching") end(ctx, s, "failed", "no_callback", "the panel didn't open (is the Mac awake and logged in?)");
  }, LAUNCH_GRACE_MS).unref();
  return summary(s);
}

export function getPanel(ctx: Ctx, id: string): PanelSummary {
  sweepPanels(ctx);
  const s = sessions.get(id);
  if (!s) throw new LockedError("not_found", `no panel ${id} (panels are forgotten 10 minutes after they close, or when Locked restarts)`, 404);
  return summary(s);
}

function byHandle(ctx: Ctx, token: string): Session {
  sweepPanels(ctx);
  const id = byToken.get(hashToken(token));
  const s = id ? sessions.get(id) : undefined;
  if (!s) throw new LockedError("not_found", "this panel is closed", 404);
  return s;
}

/** The helper's first call: what to show. No values. */
export function panelHandleInfo(ctx: Ctx, token: string) {
  const s = byHandle(ctx, token);
  if (s.status === "launching") {
    s.status = "open";
    s.expiresAt = Date.now() + s.timeoutSec * 1000;
    notify(s.id);
  }
  return {
    label: s.label,
    site: s.site,
    purpose: s.purpose,
    level: s.level,
    fields: s.fieldInfo.map((f) => ({ name: f.name, label: f.label, type: f.type })),
    timeoutSec: Math.max(1, Math.round((s.expiresAt - Date.now()) / 1000)),
  };
}

/** The values, once per panel, on the first Type or Copy. Sealed: Touch ID here, run by the server. */
export async function panelHandleValues(ctx: Ctx, native: Native, token: string) {
  const s = byHandle(ctx, token);
  if (s.valuesTaken) throw new LockedError("already", "this panel already has its values", 409);
  s.valuesTaken = true;
  let deviceConfirmed = false;
  if (s.level === "sealed") {
    deviceConfirmed = await native.deviceAuth(`type or copy “${s.label}”`);
    if (!deviceConfirmed) {
      s.valuesTaken = false; // let them try again
      recordEvent(ctx, s.requestId, "device_denied", { via: "panel", panelId: s.id });
      throw new LockedError("not_confirmed", "Touch ID wasn't confirmed.", 403);
    }
  }
  return releaseValues(ctx, s.requestId, s.fields, { via: "panel", deviceConfirmed });
}

export function panelHandleEvent(ctx: Ctx, token: string, input: { event?: string; field?: string }) {
  const s = byHandle(ctx, token);
  const event = String(input.event ?? "");
  if (!HELPER_EVENTS.has(event)) throw new LockedError("bad_event", `unknown panel event "${event}"`);
  const field = input.field != null ? String(input.field) : undefined;
  if (field !== undefined && !s.fields.includes(field)) throw new LockedError("bad_fields", `this panel has no field "${field}"`);
  if (event === "closed" || event === "expired") {
    end(ctx, s, "closed", event);
    return summary(s);
  }
  s.events.push({ at: Date.now(), event, ...(field ? { field } : {}) });
  recordEvent(ctx, s.requestId, `panel_${event}`, { panelId: s.id, ...(field ? { field } : {}) });
  notify(s.id);
  return summary(s);
}
