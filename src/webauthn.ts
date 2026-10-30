// WebAuthn passkeys for the paired phone, verified server-side with WebCrypto
// alone. The phone registers a passkey once when it pairs; after that it has to
// produce a user-verified assertion (Face ID / fingerprint) before a secret is
// released to it.
//
// Deliberately narrow: ES256 (COSE alg -7, P-256) is the only algorithm, and
// attestation is "none". The attestationObject is parsed, but attStmt is never
// verified, whatever its fmt, so nothing here proves which authenticator made
// the key, only that the same key signs later.

import { timingSafeEqual } from "node:crypto";
import { b64u, randomToken } from "./crypto.ts";

const subtle = crypto.subtle;
const enc = new TextEncoder();
const utf8 = new TextDecoder("utf-8", { fatal: true });

/** WebCrypto wants bytes backed by a plain ArrayBuffer. */
type Bytes = Uint8Array<ArrayBuffer>;

export class WebAuthnError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "WebAuthnError";
  }
}

function fail(code: string, message: string): never {
  throw new WebAuthnError(code, message);
}

function malformed(message: string): never {
  return fail("malformed", message);
}

/** All binary fields are base64url (no padding), as the browser code sends them. */
export type RegistrationInput = { clientDataJSON: string; attestationObject: string };

export type Expect = {
  /** base64url, as issued by newChallenge(). */
  challenge: string;
  origin: string;
  rpId: string;
};

export type Registration = {
  /** base64url */
  credentialId: string;
  /** P-256 public key, for storage. */
  publicKeyJwk: JsonWebKey;
  signCount: number;
  /** UUID form; all zeros for most "none" attestations. Informational only. */
  aaguid: string;
  /** The BS flag: the passkey is synced (iCloud Keychain, Google Password Manager). */
  backedUp: boolean;
};

export type AssertionInput = {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  /** ASN.1 DER ECDSA, as browsers return it. */
  signature: string;
  userHandle?: string | null;
};

/** Random 32-byte challenge, base64url. */
export function newChallenge(): string {
  return randomToken(32);
}

export async function verifyRegistration(input: RegistrationInput, expect: Expect): Promise<Registration> {
  const { clientDataJSON, attestationObject } = (input ?? {}) as Partial<RegistrationInput>;
  checkClientData(field(clientDataJSON, "clientDataJSON"), "webauthn.create", expect);

  const att = field(attestationObject, "attestationObject");
  const { value, end } = decodeCbor(att);
  if (end !== att.length) malformed("trailing bytes after attestationObject");
  if (!(value instanceof Map)) malformed("attestationObject is not a CBOR map");
  const fmt = value.get("fmt");
  const attStmt = value.get("attStmt");
  const rawAuthData = value.get("authData");
  if (typeof fmt !== "string" || !(attStmt instanceof Map) || !(rawAuthData instanceof Uint8Array)) {
    malformed("attestationObject needs fmt, attStmt and authData");
  }

  const authData = parseAuthData(rawAuthData);
  await checkAuthData(authData, expect);
  if (!authData.attested) fail("no_credential", "authenticatorData carries no attested credential (AT flag unset)");
  const { aaguid, credentialId, publicKey } = authData.attested;
  const publicKeyJwk = coseToJwk(publicKey);
  await importKey(publicKeyJwk); // rejects points that aren't on the curve

  return {
    credentialId: b64u.encode(credentialId),
    publicKeyJwk,
    signCount: authData.signCount,
    aaguid: uuid(aaguid),
    backedUp: (authData.flags & BS) !== 0,
  };
}

export async function verifyAssertion(
  input: AssertionInput,
  credential: { publicKeyJwk: JsonWebKey; signCount: number },
  expect: Expect,
): Promise<{ signCount: number }> {
  const { credentialId, clientDataJSON, authenticatorData, signature } = (input ?? {}) as Partial<AssertionInput>;
  field(credentialId, "credentialId");
  const clientData = field(clientDataJSON, "clientDataJSON");
  checkClientData(clientData, "webauthn.get", expect);

  const rawAuthData = field(authenticatorData, "authenticatorData");
  const authData = parseAuthData(rawAuthData);
  await checkAuthData(authData, expect);

  const sig = derToRaw(field(signature, "signature"));
  const key = await importKey(credential?.publicKeyJwk);
  const signed = concat(rawAuthData, await sha256(clientData));
  const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, signed).catch(() => false);
  if (!ok) fail("bad_signature", "assertion signature does not verify");

  // Synced passkeys (iCloud Keychain) always report 0, so only a counter that
  // is running and fails to move forward looks like a cloned authenticator.
  const stored = credential.signCount;
  const count = authData.signCount;
  if (stored > 0 && count > 0 && count <= stored) fail("cloned", `sign count went from ${stored} to ${count}`);
  return { signCount: count };
}

// ---------------------------------------------------------------------------
// clientDataJSON and authenticatorData

const B64U = /^[A-Za-z0-9_-]*$/;
const MAX_FIELD = 64 * 1024;

function field(value: unknown, name: string): Bytes {
  if (typeof value !== "string" || value.length > MAX_FIELD || value.length % 4 === 1 || !B64U.test(value)) {
    malformed(`${name} is not base64url`);
  }
  return b64u.decode(value);
}

function checkClientData(raw: Bytes, type: string, expect: Expect) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8.decode(raw));
  } catch {
    malformed("clientDataJSON is not JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) malformed("clientDataJSON is not an object");
  const data = parsed as Record<string, unknown>;
  if (data.type !== type) fail("bad_type", `clientData type is ${show(data.type)}, expected ${type}`);
  if (typeof data.challenge !== "string" || !sameBytes(enc.encode(data.challenge), enc.encode(expect.challenge))) {
    fail("bad_challenge", "challenge does not match");
  }
  if (data.origin !== expect.origin) fail("bad_origin", `origin is ${show(data.origin)}, expected ${expect.origin}`);
  if (data.crossOrigin !== undefined && data.crossOrigin !== false) fail("cross_origin", "ceremony ran in a cross-origin iframe");
}

/** For error messages; the value came from the client. */
function show(value: unknown): string {
  return (JSON.stringify(value) ?? "undefined").slice(0, 100);
}

// authenticatorData flags: user present, user verified, backup eligible,
// backed up, attested credential data included, extension data included.
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
const ED = 0x80;

type AuthData = {
  rpIdHash: Bytes;
  flags: number;
  signCount: number;
  attested?: { aaguid: Bytes; credentialId: Bytes; publicKey: CborMap };
};

/** rpIdHash(32) || flags(1) || signCount(4, BE) || [attested credential data] || [extensions] */
function parseAuthData(data: Bytes): AuthData {
  if (data.length < 37) malformed("authenticatorData is too short");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const flags = data[32]!;
  if ((flags & BS) && !(flags & BE)) malformed("BS flag set without BE");
  const out: AuthData = { rpIdHash: data.slice(0, 32), flags, signCount: view.getUint32(33) };
  let pos = 37;
  if (flags & AT) {
    // aaguid(16) || credentialIdLength(2, BE) || credentialId || COSE_Key
    if (data.length < pos + 18) malformed("attested credential data is truncated");
    const idLength = view.getUint16(pos + 16);
    const idStart = pos + 18;
    if (idLength < 1 || idLength > 1023 || idStart + idLength > data.length) malformed("bad credential id length");
    const key = decodeCbor(data, idStart + idLength);
    if (!(key.value instanceof Map)) malformed("credential public key is not a COSE_Key map");
    out.attested = {
      aaguid: data.slice(pos, pos + 16),
      credentialId: data.slice(idStart, idStart + idLength),
      publicKey: key.value,
    };
    pos = key.end;
  }
  if (flags & ED) {
    const ext = decodeCbor(data, pos);
    if (!(ext.value instanceof Map)) malformed("extension data is not a CBOR map");
    pos = ext.end;
  }
  if (pos !== data.length) malformed("trailing bytes in authenticatorData");
  return out;
}

async function checkAuthData(authData: AuthData, expect: Expect) {
  if (!sameBytes(authData.rpIdHash, await sha256(enc.encode(expect.rpId)))) fail("bad_rp", `rpIdHash is not SHA-256(${expect.rpId})`);
  if (!(authData.flags & UP)) fail("no_user_presence", "UP flag not set");
  if (!(authData.flags & UV)) fail("no_user_verification", "UV flag not set");
}

// ---------------------------------------------------------------------------
// Keys and signatures

// COSE_Key labels. The only key accepted is EC2 / ES256 / P-256.
const KTY = 1;
const ALG = 3;
const CRV = -1;
const X = -2;
const Y = -3;

function coseToJwk(key: CborMap): JsonWebKey {
  if (key.get(KTY) !== 2 || key.get(ALG) !== -7 || key.get(CRV) !== 1) {
    fail("bad_alg", `credential key is not ES256 (kty ${show(key.get(KTY))}, alg ${show(key.get(ALG))}, crv ${show(key.get(CRV))})`);
  }
  const x = key.get(X);
  const y = key.get(Y);
  if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) {
    fail("bad_key", "P-256 coordinates must be 32 bytes each");
  }
  return { kty: "EC", crv: "P-256", x: b64u.encode(x), y: b64u.encode(y) };
}

async function importKey(jwk: JsonWebKey | undefined): Promise<CryptoKey> {
  if (jwk?.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    fail("bad_key", "stored key is not a P-256 JWK");
  }
  const clean = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
  return subtle
    .importKey("jwk", clean, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
    .catch(() => fail("bad_key", "not a valid P-256 public key"));
}

/**
 * ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }) to the raw r || s that
 * WebCrypto verifies. DER integers drop leading zeros and gain a 0x00 when the
 * top bit is set, so each one is 1..33 bytes and gets left-padded to 32.
 */
function derToRaw(der: Bytes): Bytes {
  const bad = () => fail("bad_signature", "signature is not a DER-encoded ECDSA signature");
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) bad();
  const raw = new Uint8Array(64);
  let pos = 2;
  for (const offset of [0, 32]) {
    if (der[pos] !== 0x02) bad();
    const length = der[pos + 1] ?? 0;
    pos += 2;
    if (length < 1 || length > 33 || pos + length > der.length) bad();
    let int = der.subarray(pos, pos + length);
    pos += length;
    if (int[0]! & 0x80) bad(); // negative
    if (int.length === 33 && int[0] === 0) int = int.subarray(1);
    if (int.length > 32) bad();
    raw.set(int, offset + 32 - int.length);
  }
  if (pos !== der.length) bad();
  return raw;
}

async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function concat(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function uuid(bytes: Bytes): string {
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ---------------------------------------------------------------------------
// CBOR, just enough for attestationObject and COSE_Key: major types 0-5 with
// definite lengths, plus false/true/null. Tags, floats and indefinite lengths
// are rejected. Every declared length is checked against the bytes left before
// anything is read or allocated, and nesting is capped, so hostile input costs
// at most linear time.

type CborMap = Map<number | string, Cbor>;
type Cbor = number | string | boolean | null | Bytes | Cbor[] | CborMap;

const MAX_DEPTH = 16;

/** Decodes the one item starting at `start`. `end` is where it stops, so the caller can read what follows. */
function decodeCbor(buf: Bytes, start = 0): { value: Cbor; end: number } {
  let pos = start;

  const length = (info: number): number => {
    if (info < 24) return info;
    if (info > 27) malformed(info === 31 ? "CBOR indefinite lengths are not supported" : "reserved CBOR additional info");
    const size = 1 << (info - 24);
    if (size > buf.length - pos) malformed("CBOR is truncated");
    let n = 0;
    for (let i = 0; i < size; i++) n = n * 256 + buf[pos++]!;
    if (!Number.isSafeInteger(n)) malformed("CBOR integer is too large");
    return n;
  };

  const item = (depth: number): Cbor => {
    if (depth > MAX_DEPTH) malformed("CBOR is nested too deeply");
    if (pos >= buf.length) malformed("CBOR is truncated");
    const head = buf[pos++]!;
    const major = head >> 5;
    const info = head & 0x1f;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      malformed("unsupported CBOR simple value or float");
    }
    if (major === 6) malformed("CBOR tags are not supported");
    const n = length(info);
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2 || major === 3) {
      if (n > buf.length - pos) malformed("CBOR is truncated");
      const bytes = buf.slice(pos, pos + n);
      pos += n;
      if (major === 2) return bytes;
      try {
        return utf8.decode(bytes);
      } catch {
        malformed("CBOR text is not UTF-8");
      }
    }
    if (major === 4) {
      if (n > buf.length - pos) malformed("CBOR is truncated");
      const array: Cbor[] = [];
      for (let i = 0; i < n; i++) array.push(item(depth + 1));
      return array;
    }
    // major 5: map
    if (n * 2 > buf.length - pos) malformed("CBOR is truncated");
    const map: CborMap = new Map();
    for (let i = 0; i < n; i++) {
      const key = item(depth + 1);
      if (typeof key !== "number" && typeof key !== "string") malformed("CBOR map keys must be integers or text");
      if (map.has(key)) malformed("duplicate CBOR map key");
      map.set(key, item(depth + 1));
    }
    return map;
  };

  const value = item(0);
  return { value, end: pos };
}
