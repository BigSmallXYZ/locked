// Browser half of Locked's fill-page encryption. Must stay in step with
// sealFillEnvelope / openFillEnvelope in src/crypto.ts ("Fill-page encryption"):
//
//   shared = ECDH(ephemeral P-256 key, request public key)    256 bits
//   key    = HKDF-SHA256(shared, salt(16), info = FILL_INFO)  AES-256-GCM
//   ct     = AES-GCM(key, iv(12), JSON(data), aad = requestId)
//
// There is no fallback: without WebCrypto this throws, and the page sends nothing.

export const FILL_INFO = "locked/fill/v1";

const enc = new TextEncoder();

function webCrypto() {
  const c = globalThis.crypto;
  if (globalThis.isSecureContext === false || !c || !c.subtle || typeof c.getRandomValues !== "function") {
    throw new Error("This browser can't encrypt on this page (it needs a secure https connection), so nothing was sent.");
  }
  return c;
}

/** True when sealFillEnvelope can run here. */
export function cryptoAvailable() {
  try {
    webCrypto();
    return true;
  } catch {
    return false;
  }
}

export function b64uEncode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new Error("invalid base64url");
  }
  let b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Encrypt `data` to the request's public key (raw uncompressed P-256 point, base64url).
 * Returns { v: 1, epk, salt, iv, ct }, all base64url.
 */
export async function sealFillEnvelope(publicKeyB64u, data, requestId) {
  const c = webCrypto();
  const subtle = c.subtle;
  if (typeof requestId !== "string" || requestId === "") throw new Error("missing request id");
  const peerRaw = b64uDecode(publicKeyB64u);
  if (peerRaw.length !== 65 || peerRaw[0] !== 4) throw new Error("invalid request public key");
  const json = JSON.stringify(data);
  if (typeof json !== "string") throw new Error("nothing to encrypt");

  const peer = await subtle.importKey("raw", peerRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  // The private half never leaves WebCrypto; the public half of a pair is always exportable.
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const shared = await subtle.deriveBits({ name: "ECDH", public: peer }, eph.privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = c.getRandomValues(new Uint8Array(16));
  const iv = c.getRandomValues(new Uint8Array(12));
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(FILL_INFO) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const plaintext = enc.encode(json);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(requestId) }, key, plaintext);
  plaintext.fill(0);
  return {
    v: 1,
    epk: b64uEncode(await subtle.exportKey("raw", eph.publicKey)),
    salt: b64uEncode(salt),
    iv: b64uEncode(iv),
    ct: b64uEncode(ct),
  };
}

/** The exact FillPost body the fill page sends for a submit. */
export async function buildSubmitPost(publicKeyB64u, values, requestId, retention) {
  const envelope = await sealFillEnvelope(publicKeyB64u, { values }, requestId);
  return { action: "submit", envelope, retention };
}
