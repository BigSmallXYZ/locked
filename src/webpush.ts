// Web Push sender: VAPID (RFC 8292) plus message encryption (RFC 8291, the
// aes128gcm content coding of RFC 8188). WebCrypto and fetch only, no libraries.
// Works with any push service a browser hands out: web.push.apple.com, FCM, Mozilla.
//
//   ecdh_secret = ECDH(as_private, ua_public)
//   IKM         = HKDF(salt = auth, ikm = ecdh_secret, info = "WebPush: info" 0 ua_public as_public, 32)
//   CEK         = HKDF(salt, IKM, "Content-Encoding: aes128gcm" 0, 16)
//   NONCE       = HKDF(salt, IKM, "Content-Encoding: nonce" 0, 12)
//   body        = salt(16) rs(4) idlen(1) as_public(65) AES-128-GCM(CEK, NONCE, plaintext 0x02)

import { b64u } from "./crypto.ts";

const subtle = crypto.subtle;
const enc = new TextEncoder();

/** WebCrypto wants bytes backed by a plain ArrayBuffer. */
type Bytes = Uint8Array<ArrayBuffer>;

/** As produced by PushSubscription.toJSON() in the browser; keys are base64url. */
export type PushSubscriptionJSON = { endpoint: string; keys: { p256dh: string; auth: string } };

/** publicKey: base64url of the raw uncompressed P-256 point (65 bytes), what the browser takes as applicationServerKey. */
export type VapidKeys = { publicKey: string; privateJwk: JsonWebKey };

export type PushResult = { ok: boolean; status: number; gone: boolean; error?: string };

/** Push services only promise to accept 4096 bytes of body (RFC 8291 §4). */
export const MAX_BODY = 4096;
const RECORD_SIZE = 4096;
const HEADER_LEN = 16 + 4 + 1 + 65;
const TAG_LEN = 16;
/** 3993 bytes: what fits once the header, the padding delimiter and the GCM tag are taken out. */
export const MAX_PLAINTEXT = MAX_BODY - HEADER_LEN - 1 - TAG_LEN;

const MAX_VAPID_EXP_SEC = 24 * 60 * 60;
const DEFAULT_VAPID_EXP_SEC = 12 * 60 * 60;
const FETCH_TIMEOUT_MS = 30_000;

function concat(...parts: ArrayLike<number>[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function isUncompressedPoint(bytes: Uint8Array): boolean {
  return bytes.length === 65 && bytes[0] === 0x04;
}

/** Raw uncompressed point from a P-256 JWK's x and y. */
function jwkPublicRaw(jwk: JsonWebKey): Bytes {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) throw new Error("expected a P-256 JWK");
  const x = b64u.decode(jwk.x);
  const y = b64u.decode(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error("P-256 JWK has malformed x/y");
  return concat([0x04], x, y);
}

/** Only the key material. key_ops/alg left over from an export would block importing for another algorithm. */
function bareJwk(jwk: JsonWebKey): JsonWebKey {
  if (!jwk.d) throw new Error("expected a private JWK (no d)");
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
}

function parseSubscription(sub: PushSubscriptionJSON): { endpoint: URL; uaPublic: Bytes; authSecret: Bytes } {
  let endpoint: URL;
  try {
    endpoint = new URL(sub?.endpoint);
  } catch {
    throw new Error("push subscription: endpoint is not a valid URL");
  }
  if (endpoint.protocol !== "https:") throw new Error("push subscription: endpoint must be https");
  const { p256dh, auth } = sub.keys ?? {};
  if (typeof p256dh !== "string" || typeof auth !== "string") throw new Error("push subscription: keys.p256dh and keys.auth are required");
  const uaPublic = b64u.decode(p256dh);
  if (!isUncompressedPoint(uaPublic)) throw new Error("push subscription: keys.p256dh must decode to a 65-byte uncompressed P-256 point");
  const authSecret = b64u.decode(auth);
  if (authSecret.length !== 16) throw new Error("push subscription: keys.auth must decode to 16 bytes");
  return { endpoint, uaPublic, authSecret };
}

async function hkdf(salt: Bytes, ikm: Bytes, info: Bytes, bytes: number): Promise<Bytes> {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, bytes * 8));
}

// ---------------------------------------------------------------------------
// VAPID

export async function generateVapidKeys(): Promise<VapidKeys> {
  const pair = (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return {
    publicKey: b64u.encode(await subtle.exportKey("raw", pair.publicKey)),
    privateJwk: await subtle.exportKey("jwk", pair.privateKey),
  };
}

/**
 * The Authorization header value: `vapid t=<JWT>, k=<publicKey>`.
 * aud = origin of the endpoint. expSec is the JWT's exp claim (Unix seconds), default now+12h;
 * push services reject anything more than 24h out.
 */
export async function vapidAuthorization(endpoint: string, vapid: VapidKeys, subject: string, expSec?: number): Promise<string> {
  const url = new URL(endpoint);
  if (url.protocol !== "https:") throw new Error("VAPID: endpoint must be https");
  // Apple rejects the token (BadJwtToken) unless sub is a mailto: or https: URL.
  if (!/^(mailto:[^\s@]+@[^\s@]+|https:\/\/\S+)$/.test(subject)) throw new Error("VAPID: subject must be a mailto: or https: URL");
  const now = Math.floor(Date.now() / 1000);
  const exp = expSec ?? now + DEFAULT_VAPID_EXP_SEC;
  if (!Number.isInteger(exp) || exp <= now || exp > now + MAX_VAPID_EXP_SEC) {
    throw new Error("VAPID: expSec is the exp claim in Unix seconds and must be in the future, at most 24h from now");
  }
  const publicRaw = b64u.decode(vapid.publicKey);
  if (!isUncompressedPoint(publicRaw)) throw new Error("VAPID: publicKey must be a 65-byte uncompressed P-256 point");
  if (b64u.encode(jwkPublicRaw(vapid.privateJwk)) !== b64u.encode(publicRaw)) throw new Error("VAPID: publicKey does not match privateJwk");

  const key = await subtle.importKey("jwk", bareJwk(vapid.privateJwk), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const header = b64u.encode(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u.encode(enc.encode(JSON.stringify({ aud: url.origin, exp, sub: subject })));
  const input = `${header}.${claims}`;
  // WebCrypto's ECDSA signature is already the raw r||s that JWS ES256 wants.
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(input));
  return `vapid t=${input}.${b64u.encode(sig)}, k=${vapid.publicKey}`;
}

// ---------------------------------------------------------------------------
// Message encryption

/** RFC 8291 §3.4 key schedule. Exported so tests can check the intermediate values. */
export async function deriveContentKeys(p: {
  ecdhSecret: Bytes;
  authSecret: Bytes;
  uaPublic: Bytes;
  asPublic: Bytes;
  salt: Bytes;
}): Promise<{ ikm: Bytes; cek: Bytes; nonce: Bytes }> {
  const keyInfo = concat(enc.encode("WebPush: info"), [0], p.uaPublic, p.asPublic);
  const ikm = await hkdf(p.authSecret, p.ecdhSecret, keyInfo, 32);
  const cek = await hkdf(p.salt, ikm, concat(enc.encode("Content-Encoding: aes128gcm"), [0]), 16);
  const nonce = await hkdf(p.salt, ikm, concat(enc.encode("Content-Encoding: nonce"), [0]), 12);
  return { ikm, cek, nonce };
}

async function encryptWithKey(
  sub: PushSubscriptionJSON,
  plaintext: Uint8Array,
  salt: Bytes,
  asPrivate: CryptoKey,
  asPublic: Bytes,
): Promise<Bytes> {
  const { uaPublic, authSecret } = parseSubscription(sub);
  if (salt.length !== 16) throw new Error("web push: salt must be 16 bytes");
  if (!isUncompressedPoint(asPublic)) throw new Error("web push: sender public key must be a 65-byte uncompressed P-256 point");
  if (plaintext.length > MAX_PLAINTEXT) {
    throw new Error(
      `web push: payload is ${plaintext.length} bytes, which encrypts to ${HEADER_LEN + plaintext.length + 1 + TAG_LEN} bytes; ` +
        `push services only accept ${MAX_BODY} (at most ${MAX_PLAINTEXT} bytes of payload)`,
    );
  }

  const peer = await subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: peer }, asPrivate, 256));
  const { cek, nonce } = await deriveContentKeys({ ecdhSecret, authSecret, uaPublic, asPublic, salt });

  const aes = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  // One record, sequence number 0, so the nonce is used as is. 0x02 marks the last (only) record.
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(plaintext, [0x02])));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, RECORD_SIZE);
  return concat(salt, rs, [asPublic.length], asPublic, ct);
}

/** encryptPayload with a fixed salt and sender key pair, for test vectors. Use encryptPayload otherwise. */
export async function encryptPayloadWith(
  sub: PushSubscriptionJSON,
  plaintext: Uint8Array,
  opts: { salt: Bytes; senderPrivateJwk: JsonWebKey; senderPublicRaw: Bytes },
): Promise<Uint8Array> {
  if (b64u.encode(jwkPublicRaw(opts.senderPrivateJwk)) !== b64u.encode(opts.senderPublicRaw)) {
    throw new Error("web push: senderPublicRaw does not match senderPrivateJwk");
  }
  const asPrivate = await subtle.importKey("jwk", bareJwk(opts.senderPrivateJwk), { name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  return encryptWithKey(sub, plaintext, opts.salt, asPrivate, opts.senderPublicRaw);
}

/** RFC 8291 body: salt(16) || rs(uint32 BE = 4096) || idlen(1)=65 || as_public(65) || AES-128-GCM ciphertext of (plaintext || 0x02). */
export async function encryptPayload(sub: PushSubscriptionJSON, plaintext: Uint8Array): Promise<Uint8Array> {
  // A fresh sender key and salt per message, as the RFC requires.
  const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const asPublic = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  return encryptWithKey(sub, plaintext, crypto.getRandomValues(new Uint8Array(16)), pair.privateKey, asPublic);
}

// ---------------------------------------------------------------------------
// Sending

/**
 * JSON.stringify(payload), encrypt, POST to sub.endpoint. gone = 404 or 410 (subscription dead,
 * caller deletes it). Throws only on bad input (subscription, VAPID, options, oversized payload);
 * HTTP errors come back as ok:false, network errors as ok:false, status:0.
 */
export async function sendPush(
  sub: PushSubscriptionJSON,
  payload: unknown,
  vapid: VapidKeys,
  opts: { subject: string; ttlSec?: number; urgency?: "very-low" | "low" | "normal" | "high"; topic?: string; fetch?: typeof fetch },
): Promise<PushResult> {
  const ttl = opts.ttlSec ?? 60;
  if (!Number.isInteger(ttl) || ttl < 0) throw new Error("web push: ttlSec must be a non-negative integer");
  const urgency = opts.urgency ?? "high";
  if (!["very-low", "low", "normal", "high"].includes(urgency)) throw new Error(`web push: unknown urgency ${urgency}`);
  // RFC 8030 §5.4: at most 32 characters from the base64url alphabet.
  if (opts.topic !== undefined && !/^[A-Za-z0-9_-]{1,32}$/.test(opts.topic)) {
    throw new Error("web push: topic must be 1-32 characters of [A-Za-z0-9_-]");
  }
  const json = JSON.stringify(payload);
  if (json === undefined) throw new Error("web push: payload is not JSON-serializable");

  const body = (await encryptPayload(sub, enc.encode(json))) as Bytes;
  const headers: Record<string, string> = {
    Authorization: await vapidAuthorization(sub.endpoint, vapid, opts.subject),
    TTL: String(ttl),
    Urgency: urgency,
    "Content-Type": "application/octet-stream",
    "Content-Encoding": "aes128gcm",
  };
  if (opts.topic !== undefined) headers.Topic = opts.topic;

  let res: Response;
  try {
    res = await (opts.fetch ?? fetch)(sub.endpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    return { ok: false, status: 0, gone: false, error: err instanceof Error ? err.message : String(err) };
  }
  const text = await res.text().catch(() => "");
  const gone = res.status === 404 || res.status === 410;
  if (res.ok) return { ok: true, status: res.status, gone };
  // Push services explain rejections in the body, e.g. Apple's {"reason":"BadJwtToken"}.
  const detail = text.trim().slice(0, 500);
  const status = [String(res.status), res.statusText].filter(Boolean).join(" ");
  return { ok: false, status: res.status, gone, error: detail ? `${status}: ${detail}` : status };
}
