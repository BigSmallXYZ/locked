// The phone. `locked phone pair` prints a code; the phone opens /phone/ on the public listener,
// allows notifications and creates a passkey, and becomes a device (a Web Push subscription plus a
// passkey public key, in the DB). `locked phone send` then pushes a notification to it. Tapping it
// opens the share page, and a user-verified passkey assertion (Face ID, fingerprint) releases the
// values, sealed to a key the page made for that unlock, so the tunnel and Cloudflare only ever
// carry ciphertext. The push itself holds no secret: a share token, the label and Claude's purpose.
// Pairings and shares live in memory, like panels; a restart ends them.

import { b64u, hashToken, openJson, PHONE_INFO, randomId, randomToken, sealFillEnvelope, sealJson } from "../crypto.ts";
import type { DeviceRow } from "../db.ts";
import type { Field } from "../model.ts";
import { LockedError, recordEvent, releaseTarget, releaseValues, type Ctx } from "../requests.ts";
import { generateVapidKeys, sendPush, type PushResult, type PushSubscriptionJSON, type VapidKeys } from "../webpush.ts";
import { newChallenge, verifyAssertion, verifyRegistration, WebAuthnError, type AssertionInput, type RegistrationInput } from "../webauthn.ts";
import { notify } from "./waiters.ts";

export const SHARE_DEFAULT_SEC = 600;
export const SHARE_MAX_SEC = 3600;
const PAIR_TTL_MS = 10 * 60_000;
const CHALLENGE_TTL_MS = 2 * 60_000;
/** Ended pairings and shares stay readable (for the CLI's last wait) this long. */
const KEEP_ENDED_MS = 10 * 60_000;
/** Each unlock is a fresh Face ID; this caps how often one share can be reopened. */
const MAX_UNLOCKS = 10;
/** Wrong pairing codes (from anyone) before every open pairing is cancelled. */
const MAX_CODE_FAILURES = 10;

/** Sends one push. The real one signs with Locked's VAPID key; tests pass a fake. */
export type Pusher = (sub: PushSubscriptionJSON, payload: unknown, opts: { ttlSec: number }) => Promise<PushResult>;

export type PushPayload =
  | { t: "share"; s: string; title: string; body: string; exp: number }
  | { t: "info"; title: string; body: string };

const now = (ctx: Ctx) => (ctx.now ? ctx.now() : Date.now());

function rp(ctx: Ctx) {
  const u = new URL(ctx.publicUrl);
  return { id: u.hostname, origin: u.origin };
}

function webauthn<T>(p: Promise<T>): Promise<T> {
  return p.catch((err) => {
    if (err instanceof WebAuthnError) throw new LockedError(`passkey_${err.code}`, `The passkey check failed: ${err.message}`, 403);
    throw err;
  });
}

// --- VAPID key: made once, sealed under the master key ---

const vapidCache = new WeakMap<Ctx, Promise<VapidKeys>>();

export function vapidKeys(ctx: Ctx): Promise<VapidKeys> {
  let p = vapidCache.get(ctx);
  if (!p) {
    p = (async () => {
      const row = ctx.db.query("SELECT value FROM settings WHERE key = 'vapid'").get() as { value: Uint8Array } | null;
      if (row) return openJson<VapidKeys>(ctx.key, row.value, "settings:vapid");
      const keys = await generateVapidKeys();
      ctx.db.query("INSERT INTO settings (key, value) VALUES ('vapid', ?)").run(await sealJson(ctx.key, keys, "settings:vapid"));
      return keys;
    })();
    p.catch(() => vapidCache.delete(ctx));
    vapidCache.set(ctx, p);
  }
  return p;
}

export function webPusher(ctx: Ctx): Pusher {
  // RFC 8292 wants a contact; Locked's own https origin is one, and keeps the user's email out of it.
  return async (sub, payload, { ttlSec }) => sendPush(sub, payload, await vapidKeys(ctx), { subject: rp(ctx).origin, ttlSec, urgency: "high" });
}

// --- devices ---

export type DeviceSummary = { id: string; name: string; createdAt: number; lastSeenAt: number | null; push: boolean; userAgent: string };

function deviceSummary(r: DeviceRow): DeviceSummary {
  return { id: r.id, name: r.name, createdAt: r.created_at, lastSeenAt: r.last_seen_at, push: !!r.push, userAgent: r.user_agent };
}

function activeDevices(ctx: Ctx): DeviceRow[] {
  return ctx.db.query("SELECT * FROM devices WHERE revoked_at IS NULL ORDER BY created_at").all() as DeviceRow[];
}

export function listDevices(ctx: Ctx): DeviceSummary[] {
  return activeDevices(ctx).map(deviceSummary);
}

export function removeDevice(ctx: Ctx, id: string): DeviceSummary {
  const row = ctx.db.query("SELECT * FROM devices WHERE id = ? AND revoked_at IS NULL").get(id) as DeviceRow | null;
  if (!row) throw new LockedError("not_found", `no paired phone ${id} (see: locked phone list)`, 404);
  ctx.db.query("UPDATE devices SET revoked_at = ?, push = NULL WHERE id = ?").run(now(ctx), id);
  recordEvent(ctx, null, "phone_removed", { deviceId: id, name: row.name });
  return deviceSummary({ ...row, push: null });
}

/** Pushes to each device (or the one named); a subscription the push service calls gone is dropped. */
async function pushTo(ctx: Ctx, pusher: Pusher, devices: DeviceRow[], payload: PushPayload, ttlSec: number) {
  const results: Array<{ id: string; name: string; ok: boolean; status: number; error?: string }> = [];
  for (const d of devices) {
    if (!d.push) {
      results.push({ id: d.id, name: d.name, ok: false, status: 0, error: "no push subscription (pair it again)" });
      continue;
    }
    const sub = await openJson<PushSubscriptionJSON>(ctx.key, d.push, `device:${d.id}`);
    const r = await pusher(sub, payload, { ttlSec }).catch((err): PushResult => ({ ok: false, status: 0, gone: false, error: String(err?.message ?? err) }));
    if (r.gone) {
      ctx.db.query("UPDATE devices SET push = NULL WHERE id = ?").run(d.id);
      recordEvent(ctx, null, "phone_push_gone", { deviceId: d.id, status: r.status });
    }
    results.push({ id: d.id, name: d.name, ok: r.ok, status: r.status, ...(r.ok ? {} : { error: r.error ?? (r.gone ? "the phone's subscription is gone (pair it again)" : `push service answered ${r.status}`) }) });
  }
  return results;
}

export async function testPush(ctx: Ctx, pusher: Pusher, deviceId?: string) {
  const devices = activeDevices(ctx).filter((d) => !deviceId || d.id === deviceId);
  if (devices.length === 0) throw new LockedError("no_phone", deviceId ? `no paired phone ${deviceId}` : "No phone is paired yet. Run `locked phone pair`.", 409);
  return pushTo(ctx, pusher, devices, { t: "info", title: "Locked test", body: "This is how Claude's credential banners will arrive." }, 300);
}

// --- pairing ---

type Pairing = {
  id: string;
  codeHash: string;
  name: string;
  status: "pending" | "paired" | "expired";
  expiresAt: number;
  userHandle: string;
  challenge?: { value: string; expiresAt: number };
  deviceId?: string;
  pushOk?: boolean;
  endedAt?: number;
};
export type PairingSummary = Pick<Pairing, "id" | "status" | "expiresAt" | "deviceId" | "pushOk"> & { name: string };

const pairings = new Map<string, Pairing>();
let codeFailures = { n: 0, since: 0 };

const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no I, L, O, 0, 1
function newCode(): string {
  let out = "";
  while (out.length < 8) {
    const b = crypto.getRandomValues(new Uint8Array(16));
    for (const x of b) if (x < 248 && out.length < 8) out += CODE_ALPHABET[x % 31]; // 248 = 8·31, no modulo bias
  }
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}
const normalizeCode = (code: unknown) => String(code ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");

function pairingSummary(p: Pairing): PairingSummary {
  return { id: p.id, status: p.status, expiresAt: p.expiresAt, name: p.name, ...(p.deviceId ? { deviceId: p.deviceId } : {}), ...(p.pushOk !== undefined ? { pushOk: p.pushOk } : {}) };
}

const cleanName = (name: unknown, fallback: string) => String(name ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, 60) || fallback;

export function startPairing(ctx: Ctx, input: { name?: string } = {}) {
  sweepPhone(ctx);
  const code = newCode();
  const p: Pairing = {
    id: randomId("pr"),
    codeHash: hashToken(normalizeCode(code)),
    name: cleanName(input.name, "Phone"),
    status: "pending",
    expiresAt: now(ctx) + PAIR_TTL_MS,
    userHandle: b64u.encode(crypto.getRandomValues(new Uint8Array(16))),
  };
  pairings.set(p.id, p);
  recordEvent(ctx, null, "phone_pairing_started", { pairingId: p.id });
  return { pairing: pairingSummary(p), code, url: `${ctx.publicUrl}/phone/#pair=${code}` };
}

export function getPairing(ctx: Ctx, id: string): PairingSummary {
  sweepPhone(ctx);
  const p = pairings.get(id);
  if (!p) throw new LockedError("not_found", `no pairing ${id} (pairings are forgotten 10 minutes after they end, or when Locked restarts)`, 404);
  return pairingSummary(p);
}

/** Public, step 1: the code from `locked phone pair` buys a WebAuthn registration challenge. */
export async function pairBegin(ctx: Ctx, input: { code?: string }) {
  sweepPhone(ctx);
  const t = now(ctx);
  const hash = hashToken(normalizeCode(input.code));
  const p = [...pairings.values()].find((x) => x.status === "pending" && x.codeHash === hash);
  if (!p) {
    if (t - codeFailures.since > PAIR_TTL_MS) codeFailures = { n: 0, since: t };
    if (++codeFailures.n >= MAX_CODE_FAILURES) {
      for (const x of pairings.values()) if (x.status === "pending") endPairing(ctx, x, "expired");
      recordEvent(ctx, null, "phone_pairing_locked_out", { failures: codeFailures.n });
    }
    throw new LockedError("bad_code", "That code doesn't match an open pairing. Run `locked phone pair` on the Mac for a new one.", 404);
  }
  p.challenge = { value: newChallenge(), expiresAt: t + CHALLENGE_TTL_MS };
  const { id: rpId } = rp(ctx);
  const exclude = activeDevices(ctx).map((d) => ({ type: "public-key", id: d.credential_id }));
  return {
    pairingId: p.id,
    name: p.name,
    vapidPublicKey: (await vapidKeys(ctx)).publicKey,
    publicKey: {
      challenge: p.challenge.value,
      rp: { id: rpId, name: "Locked" },
      user: { id: p.userHandle, name: `Locked · ${p.name}`, displayName: `Locked · ${p.name}` },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
      timeout: CHALLENGE_TTL_MS,
      excludeCredentials: exclude,
    },
  };
}

function checkSubscription(sub: unknown): PushSubscriptionJSON {
  const s = sub as PushSubscriptionJSON;
  let ok = false;
  try {
    ok = new URL(s.endpoint).protocol === "https:" && typeof s.keys?.p256dh === "string" && typeof s.keys?.auth === "string";
  } catch {}
  if (!ok) throw new LockedError("bad_subscription", "The phone didn't send a usable push subscription. Allow notifications and try again.");
  return { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } };
}

/** Public, step 2: the new passkey and push subscription become a device. */
export async function pairFinish(
  ctx: Ctx,
  pusher: Pusher,
  input: { pairingId?: string; credential?: RegistrationInput; subscription?: unknown; name?: string; userAgent?: string },
) {
  sweepPhone(ctx);
  const p = pairings.get(String(input.pairingId ?? ""));
  if (!p || p.status !== "pending") throw new LockedError("expired", "This pairing has ended. Run `locked phone pair` on the Mac for a new one.", 410);
  const challenge = p.challenge;
  if (!challenge || challenge.expiresAt < now(ctx)) throw new LockedError("expired", "That took too long. Enter the code again.", 410);
  p.challenge = undefined; // one registration per challenge, pass or fail
  const sub = checkSubscription(input.subscription);
  const { id: rpId, origin } = rp(ctx);
  const reg = await webauthn(verifyRegistration(input.credential ?? ({} as RegistrationInput), { challenge: challenge.value, origin, rpId }));

  const id = randomId("dv");
  const name = cleanName(input.name, p.name);
  const t = now(ctx);
  const others = activeDevices(ctx);
  ctx.db
    .query(
      `INSERT INTO devices (id, name, credential_id, public_key, sign_count, push, user_agent, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(id, name, reg.credentialId, JSON.stringify(reg.publicKeyJwk), reg.signCount, await sealJson(ctx.key, sub, `device:${id}`), String(input.userAgent ?? "").slice(0, 200), t, t);
  p.status = "paired";
  p.deviceId = id;
  p.name = name;
  p.endedAt = t;
  recordEvent(ctx, null, "phone_paired", { pairingId: p.id, deviceId: id, name, backedUp: reg.backedUp });

  const [welcome] = await pushTo(ctx, pusher, [activeDevices(ctx).find((d) => d.id === id)!], { t: "info", title: "Locked is paired", body: "Credentials Claude shares with this phone will arrive like this." }, 300);
  p.pushOk = !!welcome?.ok;
  // Anyone else's phones hear about it, in case the code leaked.
  if (others.length) await pushTo(ctx, pusher, others, { t: "info", title: "New phone paired with Locked", body: `“${name}”. Not you? On the Mac: locked phone remove ${id}` }, 3600);
  notify(p.id);
  return { deviceId: id, name, pushOk: p.pushOk };
}

function endPairing(ctx: Ctx, p: Pairing, status: "expired") {
  if (p.status !== "pending") return;
  p.status = status;
  p.endedAt = now(ctx);
  notify(p.id);
}

// --- shares ---

export type ShareEvent = { at: number; event: string; field?: string; device?: string };
export type ShareStatus = "sent" | "open" | "closed" | "failed";
export type ShareSummary = {
  id: string;
  requestId: string;
  status: ShareStatus;
  fields: string[];
  events: ShareEvent[];
  devices: Array<{ id: string; name: string; ok: boolean; error?: string }>;
  error?: string;
  expiresAt: number;
};

type Share = ShareSummary & {
  tokenHash: string;
  label: string;
  site: string | null;
  level: string;
  purpose: string;
  fieldInfo: Field[];
  challenges: Map<string, number>;
  sessions: Map<string, string>;
  unlocks: number;
  endedAt?: number;
};

const shares = new Map<string, Share>();
const sharesByToken = new Map<string, string>();

const SHARE_EVENTS = new Set(["copied", "shown", "closed"]);

function shareSummary(s: Share): ShareSummary {
  const { id, requestId, status, fields, events, devices, error, expiresAt } = s;
  return { id, requestId, status, fields, events: [...events], devices, ...(error ? { error } : {}), expiresAt };
}

function endShare(ctx: Ctx, s: Share, status: "closed" | "failed", why: string, error?: string) {
  if (s.status === "closed" || s.status === "failed") return;
  s.status = status;
  s.endedAt = now(ctx);
  if (error) s.error = error;
  sharesByToken.delete(s.tokenHash);
  s.sessions.clear();
  s.challenges.clear();
  recordEvent(ctx, s.requestId, status === "failed" ? "phone_failed" : "phone_closed", { shareId: s.id, why });
  notify(s.id);
}

export function sweepPhone(ctx: Ctx) {
  const t = now(ctx);
  for (const p of pairings.values()) {
    if (p.status === "pending" && t > p.expiresAt) endPairing(ctx, p, "expired");
    if (p.endedAt && t - p.endedAt > KEEP_ENDED_MS) pairings.delete(p.id);
  }
  for (const s of shares.values()) {
    if ((s.status === "sent" || s.status === "open") && t > s.expiresAt) endShare(ctx, s, "closed", "expired");
    if (s.endedAt && t - s.endedAt > KEEP_ENDED_MS) shares.delete(s.id);
  }
}

const fieldList = (names: string[]) => (names.length <= 1 ? names.join("") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`);

export async function sendShare(ctx: Ctx, pusher: Pusher, requestId: string, opts: { only?: string[]; purpose?: string; timeoutSec?: number; device?: string }) {
  sweepPhone(ctx);
  const { request, fields } = await releaseTarget(ctx, requestId, opts.only);
  const devices = activeDevices(ctx).filter((d) => !opts.device || d.id === opts.device);
  if (devices.length === 0) {
    throw new LockedError("no_phone", opts.device ? `no paired phone ${opts.device} (see: locked phone list)` : "No phone is paired yet. Run `locked phone pair` first.", 409);
  }
  const timeoutSec = Math.round(Math.min(Math.max(Number(opts.timeoutSec) || SHARE_DEFAULT_SEC, 60), SHARE_MAX_SEC));
  const token = randomToken();
  const purpose = String(opts.purpose ?? "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, 160);
  const s: Share = {
    id: randomId("ps"),
    requestId: request.id,
    status: "sent",
    fields: fields.map((f) => f.name),
    events: [],
    devices: [],
    expiresAt: now(ctx) + timeoutSec * 1000,
    tokenHash: hashToken(token),
    label: request.label,
    site: request.site,
    level: request.level,
    purpose,
    fieldInfo: fields,
    challenges: new Map(),
    sessions: new Map(),
    unlocks: 0,
  };
  shares.set(s.id, s);
  sharesByToken.set(s.tokenHash, s.id);
  const what = fieldList(fields.map((f) => f.label.toLowerCase()));
  const payload: PushPayload = {
    t: "share",
    s: token,
    title: request.label,
    body: `${purpose ? `Claude: ${purpose}. ` : ""}Tap to unlock the ${what}.`,
    exp: s.expiresAt,
  };
  const results = await pushTo(ctx, pusher, devices, payload, timeoutSec);
  s.devices = results.map(({ id, name, ok, error }) => ({ id, name, ok, ...(error ? { error } : {}) }));
  recordEvent(ctx, s.requestId, "phone_sent", { shareId: s.id, fields: s.fields, devices: s.devices.filter((d) => d.ok).map((d) => d.id) });
  if (!results.some((r) => r.ok)) {
    endShare(ctx, s, "failed", "push", results.map((r) => `${r.name}: ${r.error}`).join("; "));
    throw new LockedError("push_failed", `Couldn't reach the phone: ${s.error}`, 502);
  }
  return shareSummary(s);
}

export function getShare(ctx: Ctx, id: string): ShareSummary {
  sweepPhone(ctx);
  const s = shares.get(id);
  if (!s) throw new LockedError("not_found", `no phone share ${id} (shares are forgotten 10 minutes after they end, or when Locked restarts)`, 404);
  return shareSummary(s);
}

function byToken(ctx: Ctx, token: string): Share {
  sweepPhone(ctx);
  const id = sharesByToken.get(hashToken(token));
  const s = id ? shares.get(id) : undefined;
  if (!s) throw new LockedError("expired", "This share has ended. Ask Claude to send it again.", 410);
  return s;
}

function addEvent(ctx: Ctx, s: Share, event: string, extra: { field?: string; device?: string } = {}) {
  s.events.push({ at: now(ctx), event, ...extra });
  recordEvent(ctx, s.requestId, `phone_${event}`, { shareId: s.id, ...extra });
  notify(s.id);
}

/** Public: the service worker saw the push arrive. Harmless without auth: it only adds an event. */
export function shareDelivered(ctx: Ctx, token: string) {
  const s = byToken(ctx, token);
  if (!s.events.some((e) => e.event === "delivered")) addEvent(ctx, s, "delivered");
  return {};
}

/** Public: what the share page shows before unlocking. No values. */
export function shareInfo(ctx: Ctx, token: string) {
  const s = byToken(ctx, token);
  if (s.status === "sent") {
    s.status = "open";
    addEvent(ctx, s, "opened");
  }
  return {
    id: s.id,
    label: s.label,
    site: s.site,
    purpose: s.purpose,
    level: s.level,
    fields: s.fieldInfo.map((f) => ({ name: f.name, label: f.label, type: f.type })),
    expiresAt: s.expiresAt,
    credentialIds: activeDevices(ctx).map((d) => d.credential_id),
  };
}

export function shareChallenge(ctx: Ctx, token: string) {
  const s = byToken(ctx, token);
  const t = now(ctx);
  for (const [c, exp] of s.challenges) if (exp < t) s.challenges.delete(c);
  if (s.challenges.size >= 20) throw new LockedError("rate", "Too many unlock attempts on this share.", 429);
  const challenge = newChallenge();
  s.challenges.set(challenge, t + CHALLENGE_TTL_MS);
  return { challenge, rpId: rp(ctx).id, timeoutMs: CHALLENGE_TTL_MS };
}

/** Public: a fresh user-verified passkey assertion from a paired phone releases the values, sealed to `epk`. */
export async function shareUnlock(ctx: Ctx, token: string, input: { assertion?: AssertionInput; epk?: string }) {
  const s = byToken(ctx, token);
  if (s.unlocks >= MAX_UNLOCKS) throw new LockedError("rate", "This share has been unlocked too many times. Ask Claude to send it again.", 429);
  const assertion = input.assertion ?? ({} as AssertionInput);
  let challenge = "";
  try {
    challenge = JSON.parse(new TextDecoder().decode(b64u.decode(String(assertion.clientDataJSON)))).challenge;
  } catch {}
  const exp = s.challenges.get(challenge);
  s.challenges.delete(challenge);
  if (!exp || exp < now(ctx)) throw new LockedError("expired_challenge", "That took too long. Tap Unlock again.", 403);
  const device = ctx.db.query("SELECT * FROM devices WHERE credential_id = ? AND revoked_at IS NULL").get(String(assertion.credentialId)) as DeviceRow | null;
  if (!device) throw new LockedError("not_paired", "This passkey isn't paired with Locked any more. Pair the phone again.", 403);
  const { id: rpId, origin } = rp(ctx);
  const { signCount } = await webauthn(
    verifyAssertion(assertion, { publicKeyJwk: JSON.parse(device.public_key), signCount: device.sign_count }, { challenge, origin, rpId }),
  );
  // Keep the highest count seen, so one 0 from the authenticator doesn't switch clone detection off.
  ctx.db.query("UPDATE devices SET sign_count = ?, last_seen_at = ? WHERE id = ?").run(Math.max(device.sign_count, signCount), now(ctx), device.id);

  // Seal before releasing, so a bad key costs nothing and isn't counted as a use.
  if (typeof input.epk !== "string") throw new LockedError("bad_key", "missing page key");
  await sealFillEnvelope(input.epk, {}, s.id, PHONE_INFO).catch(() => {
    throw new LockedError("bad_key", "The page sent a bad key.");
  });
  const values = await releaseValues(ctx, s.requestId, s.fields, { via: "phone", deviceConfirmed: true });
  const envelope = await sealFillEnvelope(input.epk, { values }, s.id, PHONE_INFO);
  const session = randomToken();
  s.sessions.set(hashToken(session), device.id);
  s.unlocks++;
  addEvent(ctx, s, "unlocked", { device: device.id });
  return { envelope, session };
}

/** Public: what the user did after unlocking (Copy, Show, Done). Needs the session from the unlock. */
export function shareEvent(ctx: Ctx, token: string, input: { session?: string; event?: string; field?: string }) {
  const s = byToken(ctx, token);
  const device = s.sessions.get(hashToken(String(input.session ?? "")));
  if (!device) throw new LockedError("forbidden", "unlock first", 403);
  const event = String(input.event ?? "");
  if (!SHARE_EVENTS.has(event)) throw new LockedError("bad_event", `unknown event "${event}"`);
  const field = input.field != null ? String(input.field) : undefined;
  if (field !== undefined && !s.fields.includes(field)) throw new LockedError("bad_fields", `this share has no field "${field}"`);
  if (event === "closed") {
    endShare(ctx, s, "closed", "done");
    return {};
  }
  addEvent(ctx, s, event, { ...(field ? { field } : {}), device });
  return {};
}
