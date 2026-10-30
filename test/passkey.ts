// A software passkey for tests: what Safari + Face ID would hand the phone page, built with
// WebCrypto and a few lines of CBOR. "none" attestation, ES256, like a real phone.

import { createHash } from "node:crypto";
import { b64u } from "../src/crypto.ts";

const enc = new TextEncoder();
const sha256 = (data: Uint8Array) => new Uint8Array(createHash("sha256").update(data).digest());

function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function head(major: number, n: number) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  return new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
}

type Cbor = number | string | Uint8Array | Map<Cbor, Cbor> | { [k: string]: Cbor };
export function cbor(v: Cbor): Uint8Array {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") return concat(head(3, enc.encode(v).length), enc.encode(v));
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  const entries = v instanceof Map ? [...v.entries()] : Object.entries(v);
  return concat(head(5, entries.length), ...entries.flatMap(([k, x]) => [cbor(k), cbor(x)]));
}

/** WebCrypto signs as raw r||s; browsers hand the page ASN.1 DER. */
function der(raw: Uint8Array) {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    return concat(new Uint8Array([0x02, v.length + (v[0]! & 0x80 ? 1 : 0)]), v[0]! & 0x80 ? new Uint8Array([0]) : new Uint8Array(), v);
  };
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

export async function softPasskey(rpId: string) {
  const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const rawId = crypto.getRandomValues(new Uint8Array(16));
  const rpIdHash = sha256(enc.encode(rpId));
  const counter = new Uint8Array(4); // iCloud Keychain passkeys always say 0
  return {
    credentialId: b64u.encode(rawId),

    /** navigator.credentials.create(), reduced to what the page posts to pair/finish. */
    create(challenge: string, origin: string) {
      const clientDataJSON = enc.encode(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }));
      const cose = cbor(new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, b64u.decode(jwk.x!)], [-3, b64u.decode(jwk.y!)]]));
      const authData = concat(rpIdHash, new Uint8Array([0x45]), counter, new Uint8Array(16), new Uint8Array([0, rawId.length]), rawId, cose);
      const attestationObject = cbor({ fmt: "none", attStmt: new Map(), authData });
      return { clientDataJSON: b64u.encode(clientDataJSON), attestationObject: b64u.encode(attestationObject) };
    },

    /** navigator.credentials.get(), as the page posts it to unlock. `uv: false` = no Face ID. */
    async get(challenge: string, origin: string, opts: { uv?: boolean } = {}) {
      const clientDataJSON = enc.encode(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
      const authenticatorData = concat(rpIdHash, new Uint8Array([opts.uv === false ? 0x01 : 0x05]), counter);
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, concat(authenticatorData, sha256(clientDataJSON))));
      return {
        credentialId: b64u.encode(rawId),
        clientDataJSON: b64u.encode(clientDataJSON),
        authenticatorData: b64u.encode(authenticatorData),
        signature: b64u.encode(der(raw)),
        userHandle: null,
      };
    },
  };
}
