import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

/** WebCrypto wants bytes backed by a plain ArrayBuffer. */
type Bytes = Uint8Array<ArrayBuffer>;

export const b64u = {
  encode: (bytes: Uint8Array | ArrayBuffer) => Buffer.from(bytes as Uint8Array).toString("base64url"),
  decode: (text: string): Bytes => new Uint8Array(Buffer.from(text, "base64url")),
};

/** URL-safe random token. 32 bytes = 256 bits. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

const BASE32 = "abcdefghijkmnpqrstuvwxyz23456789";
/** Short readable ids like `lk_7f3kq2m9xa`. Not secret; tokens are. */
export function randomId(prefix: string, length = 10): string {
  const bytes = randomBytes(length);
  let out = "";
  for (const b of bytes) out += BASE32[b % BASE32.length];
  return `${prefix}_${out}`;
}

/** Tokens are 256-bit random, so a plain SHA-256 is enough to store them. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

// ---------------------------------------------------------------------------
// Master key: AES-256-GCM, sealing every stored secret.

export async function importMasterKey(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error("master key must be 32 bytes");
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Returns iv(12) || ciphertext+tag. `aad` binds the blob to its row so blobs can't be swapped. */
export async function seal(key: CryptoKey, plaintext: string | Bytes, aad: string): Promise<Uint8Array> {
  const iv = new Uint8Array(randomBytes(12));
  const data = typeof plaintext === "string" ? enc.encode(plaintext) : plaintext;
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, data));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

export async function open(key: CryptoKey, blob: Uint8Array, aad: string): Promise<Uint8Array> {
  const iv = new Uint8Array(blob.subarray(0, 12));
  const ct = new Uint8Array(blob.subarray(12));
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, ct));
}

export async function sealJson(key: CryptoKey, value: unknown, aad: string) {
  return seal(key, JSON.stringify(value), aad);
}

export async function openJson<T>(key: CryptoKey, blob: Uint8Array, aad: string): Promise<T> {
  return JSON.parse(dec.decode(await open(key, blob, aad))) as T;
}

// ---------------------------------------------------------------------------
// Fill-page encryption. Cloudflare terminates TLS, so the browser encrypts the
// form to a per-request P-256 key before posting. web/fill-crypto.js is the
// browser half and must stay in step with this file.
//
//   shared = ECDH(browser ephemeral, request key)            256 bits
//   key    = HKDF-SHA256(shared, salt, info = FILL_INFO)     AES-256-GCM
//   ct     = AES-GCM(key, iv, JSON(values), aad = requestId)

export const FILL_INFO = "locked/fill/v1";

export type FillEnvelope = {
  v: 1;
  /** Browser's ephemeral public key, raw uncompressed P-256 point, base64url. */
  epk: string;
  salt: string;
  iv: string;
  ct: string;
};

export async function newFillKeypair(): Promise<{ publicKey: string; privateJwk: string }> {
  const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKey = b64u.encode(await subtle.exportKey("raw", pair.publicKey));
  const privateJwk = JSON.stringify(await subtle.exportKey("jwk", pair.privateKey));
  return { publicKey, privateJwk };
}

async function fillAesKey(privateKey: CryptoKey, peerPublicRaw: Bytes, salt: Bytes) {
  const peer = await subtle.importKey("raw", peerPublicRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(FILL_INFO) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function openFillEnvelope<T = unknown>(privateJwk: string, envelope: FillEnvelope, requestId: string): Promise<T> {
  if (envelope?.v !== 1) throw new Error("unsupported envelope");
  const privateKey = await subtle.importKey(
    "jwk",
    JSON.parse(privateJwk),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const key = await fillAesKey(privateKey, b64u.decode(envelope.epk), b64u.decode(envelope.salt));
  const plain = await subtle.decrypt(
    { name: "AES-GCM", iv: b64u.decode(envelope.iv), additionalData: enc.encode(requestId) },
    key,
    b64u.decode(envelope.ct),
  );
  return JSON.parse(dec.decode(plain)) as T;
}

/** What the browser does. Used by tests; the page uses web/fill-crypto.js. */
export async function sealFillEnvelope(publicKey: string, data: unknown, requestId: string): Promise<FillEnvelope> {
  const eph = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const salt = new Uint8Array(randomBytes(16));
  const iv = new Uint8Array(randomBytes(12));
  const key = await fillAesKey(eph.privateKey, b64u.decode(publicKey), salt);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(requestId) }, key, enc.encode(JSON.stringify(data)));
  return {
    v: 1,
    epk: b64u.encode(await subtle.exportKey("raw", eph.publicKey)),
    salt: b64u.encode(salt),
    iv: b64u.encode(iv),
    ct: b64u.encode(ct),
  };
}

// ---------------------------------------------------------------------------
// Where the master key lives: macOS Keychain, or a 0600 file.

const KEYCHAIN_SERVICE = process.env.LOCKED_KEYCHAIN_SERVICE ?? "locked";
const KEYCHAIN_ACCOUNT = "master-key";

function keychainRead(): Bytes | null {
  const r = Bun.spawnSync(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"]);
  if (r.exitCode !== 0) return null;
  const hex = r.stdout.toString().trim();
  return /^[0-9a-f]{64}$/.test(hex) ? new Uint8Array(Buffer.from(hex, "hex")) : null;
}

function keychainWrite(raw: Bytes) {
  // `security -i` reads the command from stdin, which keeps the key out of argv (and `ps`).
  const line = `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${KEYCHAIN_ACCOUNT} -l "Locked master key" -w ${Buffer.from(raw).toString("hex")}\n`;
  const r = Bun.spawnSync(["security", "-i"], { stdin: Buffer.from(line) });
  if (r.exitCode !== 0 || !keychainRead()) throw new Error("could not save the master key to the Keychain: " + r.stderr.toString());
}

export type KeySource = "keychain" | "file";

export async function loadMasterKey(opts: {
  keystore: string;
  filePath: string;
  /** Only allowed when nothing is encrypted yet. A new key would orphan every stored secret. */
  create: boolean;
  writeFile: (path: string, data: string) => void;
}): Promise<{ key: CryptoKey; source: KeySource; created: boolean }> {
  const source: KeySource = opts.keystore === "keychain" ? "keychain" : "file";
  let raw = source === "keychain" ? keychainRead() : null;
  if (!raw && existsSync(opts.filePath)) {
    const hex = readFileSync(opts.filePath, "utf8").trim();
    if (/^[0-9a-f]{64}$/.test(hex)) raw = new Uint8Array(Buffer.from(hex, "hex"));
    if (raw) return { key: await importMasterKey(raw), source: "file", created: false };
  }
  if (raw) return { key: await importMasterKey(raw), source, created: false };
  if (!opts.create) {
    throw new Error(
      "Locked's master key is missing but the database already holds encrypted data. " +
        "Refusing to create a new key, because that would make every stored secret unreadable. " +
        "Restore the key (Keychain item 'locked' or ~/.locked/master.key) or delete ~/.locked/locked.db to start over.",
    );
  }
  const fresh = new Uint8Array(randomBytes(32));
  if (source === "keychain") keychainWrite(fresh);
  else opts.writeFile(opts.filePath, Buffer.from(fresh).toString("hex") + "\n");
  return { key: await importMasterKey(fresh), source, created: true };
}
