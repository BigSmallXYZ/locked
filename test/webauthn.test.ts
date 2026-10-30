import { describe, expect, test } from "bun:test";
import { b64u } from "../src/crypto.ts";
import {
  newChallenge,
  verifyAssertion,
  verifyRegistration,
  WebAuthnError,
  type AssertionInput,
  type Expect,
  type RegistrationInput,
} from "../src/webauthn.ts";

type Bytes = Uint8Array<ArrayBuffer>;
const subtle = crypto.subtle;
const enc = new TextEncoder();

const RP_ID = "locked.example.com";
const ORIGIN = "https://locked.example.com";
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
const ED = 0x80;

// ---------------------------------------------------------------------------
// A tiny CBOR encoder, enough to play authenticator.

/** Spliced into the output as-is, for building broken CBOR. */
class Raw {
  constructor(readonly bytes: Uint8Array) {}
}
type CborIn = number | string | boolean | null | Uint8Array | Raw | CborIn[] | Map<number | string, CborIn> | { [key: string]: CborIn };

function head(major: number, n: number): number[] {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  return [m | 26, n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function cbor(value: CborIn): Bytes {
  const out: number[] = [];
  const put = (v: CborIn): void => {
    if (v instanceof Raw) for (const b of v.bytes) out.push(b);
    else if (v === false) out.push(0xf4);
    else if (v === true) out.push(0xf5);
    else if (v === null) out.push(0xf6);
    else if (typeof v === "number") out.push(...(v >= 0 ? head(0, v) : head(1, -1 - v)));
    else if (typeof v === "string") out.push(...head(3, enc.encode(v).length), ...enc.encode(v));
    else if (v instanceof Uint8Array) out.push(...head(2, v.length), ...v);
    else if (Array.isArray(v)) {
      out.push(...head(4, v.length));
      for (const x of v) put(x);
    } else {
      const entries: [number | string, CborIn][] = v instanceof Map ? [...v] : Object.entries(v);
      out.push(...head(5, entries.length));
      for (const [k, x] of entries) {
        put(k);
        put(x);
      }
    }
  };
  put(value);
  return new Uint8Array(out);
}

function concat(...parts: ArrayLike<number>[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const sha256 = async (data: Bytes) => new Uint8Array(await subtle.digest("SHA-256", data));

function derInteger(bytes: Uint8Array): number[] {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const v = [...bytes.subarray(i)];
  if (v[0]! & 0x80) v.unshift(0);
  return [0x02, v.length, ...v];
}

/** WebCrypto signs as raw r || s; browsers hand the server DER, so the test does too. */
function rawToDer(raw: Uint8Array): Bytes {
  const r = derInteger(raw.subarray(0, 32));
  const s = derInteger(raw.subarray(32));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

// ---------------------------------------------------------------------------
// A software authenticator.

type ClientOpts = { type?: string; challenge?: string; origin?: string; crossOrigin?: unknown };
type AuthOpts = { rpId?: string; flags?: number; signCount?: number };
type RegisterOpts = ClientOpts &
  AuthOpts & { coseKey?: Uint8Array; extensions?: Uint8Array; aaguid?: Uint8Array; fmt?: string; attStmt?: CborIn };
type AssertOpts = ClientOpts & AuthOpts & { signWith?: CryptoKey; until?: (raw: Bytes) => boolean };

function clientDataJSON(type: string, expect: Expect, o: ClientOpts): Bytes {
  return enc.encode(
    JSON.stringify({
      type: "type" in o ? o.type : type,
      challenge: "challenge" in o ? o.challenge : expect.challenge,
      origin: "origin" in o ? o.origin : expect.origin,
      crossOrigin: "crossOrigin" in o ? o.crossOrigin : false,
    }),
  );
}

async function authData(o: AuthOpts & { flags: number }, ...rest: ArrayLike<number>[]): Promise<Bytes> {
  const n = o.signCount ?? 0;
  const counter = [n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  return concat(await sha256(enc.encode(o.rpId ?? RP_ID)), [o.flags], counter, ...rest);
}

class SoftAuthenticator {
  readonly credentialId = crypto.getRandomValues(new Uint8Array(16));
  private constructor(readonly keys: CryptoKeyPair) {}

  static async create() {
    const keys = (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
    return new SoftAuthenticator(keys);
  }

  async coseKey(alg = -7): Promise<Bytes> {
    const point = new Uint8Array(await subtle.exportKey("raw", this.keys.publicKey)); // 0x04 || x || y
    return cbor(new Map<number, CborIn>([[1, 2], [3, alg], [-1, 1], [-2, point.slice(1, 33)], [-3, point.slice(33)]]));
  }

  /** Also returns the authData it built, for tests that rebuild the attestationObject around it. */
  async register(expect: Expect, o: RegisterOpts = {}): Promise<RegistrationInput & { authData: Bytes }> {
    const flags = o.flags ?? UP | UV | AT;
    const id = this.credentialId;
    const attested = flags & AT ? concat(o.aaguid ?? new Uint8Array(16), [id.length >> 8, id.length & 0xff], id, o.coseKey ?? (await this.coseKey())) : [];
    const data = await authData({ ...o, flags }, attested, o.extensions ?? []);
    return {
      clientDataJSON: b64u.encode(clientDataJSON("webauthn.create", expect, o)),
      attestationObject: b64u.encode(cbor({ fmt: o.fmt ?? "none", attStmt: o.attStmt ?? {}, authData: data })),
      authData: data,
    };
  }

  async assert(expect: Expect, o: AssertOpts = {}): Promise<AssertionInput> {
    const data = await authData({ ...o, flags: o.flags ?? UP | UV });
    const client = clientDataJSON("webauthn.get", expect, o);
    const signed = concat(data, await sha256(client));
    const sign = async () => new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, o.signWith ?? this.keys.privateKey, signed));
    let raw = await sign();
    for (let tries = 0; o.until && !o.until(raw); tries++) {
      if (tries === 20_000) throw new Error("no signature matched the predicate");
      raw = await sign();
    }
    return {
      credentialId: b64u.encode(this.credentialId),
      clientDataJSON: b64u.encode(client),
      authenticatorData: b64u.encode(data),
      signature: b64u.encode(rawToDer(raw)),
      userHandle: null,
    };
  }
}

const freshExpect = (): Expect => ({ challenge: newChallenge(), origin: ORIGIN, rpId: RP_ID });

async function paired() {
  const auth = await SoftAuthenticator.create();
  const expect = freshExpect();
  const reg = await verifyRegistration(await auth.register(expect), expect);
  return { auth, credential: { publicKeyJwk: reg.publicKeyJwk, signCount: reg.signCount } };
}

async function rejects(promise: Promise<unknown>, code: string) {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(WebAuthnError);
  expect((error as WebAuthnError).code).toBe(code);
}

/** Swap the authData inside an attestationObject, keeping the outer CBOR valid. */
function withAuthData(reg: RegistrationInput, data: Uint8Array | Raw, extra: Record<string, CborIn> = {}): RegistrationInput {
  return { ...reg, attestationObject: b64u.encode(cbor({ fmt: "none", attStmt: {}, authData: data, ...extra })) };
}

// ---------------------------------------------------------------------------

describe("registration", () => {
  test("a valid registration yields the credential", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    const reg = await verifyRegistration(await auth.register(e), e);
    const jwk = await subtle.exportKey("jwk", auth.keys.publicKey);
    expect(reg).toEqual({
      credentialId: b64u.encode(auth.credentialId),
      publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! },
      signCount: 0,
      aaguid: "00000000-0000-0000-0000-000000000000",
      backedUp: false,
    });
  });

  test("reports the BS flag and the aaguid", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    const aaguid = new Uint8Array(Buffer.from("fbfc3007154e4ecc8c0b6e020557d7bd", "hex"));
    const reg = await verifyRegistration(await auth.register(e, { flags: UP | UV | AT | BE | BS, aaguid }), e);
    expect(reg.backedUp).toBe(true);
    expect(reg.aaguid).toBe("fbfc3007-154e-4ecc-8c0b-6e020557d7bd");
  });

  test("accepts any attestation format without verifying attStmt", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    const attStmt = { alg: -7, sig: new Uint8Array(70), x5c: [new Uint8Array(300)] };
    const reg = await verifyRegistration(await auth.register(e, { fmt: "packed", attStmt }), e);
    expect(reg.credentialId).toBe(b64u.encode(auth.credentialId));
  });

  test("extension data after the COSE key (ED flag) parses", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    const extensions = cbor({ credProtect: 2, hmacSecret: true });
    const reg = await verifyRegistration(await auth.register(e, { flags: UP | UV | AT | ED, extensions }), e);
    expect(reg.credentialId).toBe(b64u.encode(auth.credentialId));
  });

  test("crossOrigin may be absent", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    await verifyRegistration(await auth.register(e, { crossOrigin: undefined }), e);
  });

  const failures: [string, string, RegisterOpts][] = [
    ["a wrong challenge", "bad_challenge", { challenge: newChallenge() }],
    ["a missing challenge", "bad_challenge", { challenge: undefined as unknown as string }],
    ["a wrong origin", "bad_origin", { origin: "https://evil.example.com" }],
    ["an origin with a trailing slash", "bad_origin", { origin: ORIGIN + "/" }],
    ["an http origin", "bad_origin", { origin: "http://locked.example.com" }],
    ["the assertion type", "bad_type", { type: "webauthn.get" }],
    ["crossOrigin true", "cross_origin", { crossOrigin: true }],
    ["a wrong rpId", "bad_rp", { rpId: "evil.example.com" }],
    ["missing UV", "no_user_verification", { flags: UP | AT }],
    ["missing UP", "no_user_presence", { flags: UV | AT }],
    ["missing AT", "no_credential", { flags: UP | UV }],
    ["BS without BE", "malformed", { flags: UP | UV | AT | BS }],
  ];
  for (const [name, code, opts] of failures) {
    test(`rejects ${name} (${code})`, async () => {
      const auth = await SoftAuthenticator.create();
      const e = freshExpect();
      await rejects(verifyRegistration(await auth.register(e, opts), e), code);
    });
  }

  test("rejects keys that aren't ES256", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    const xy = new Uint8Array(32);
    const keys: [string, Bytes][] = [
      ["RS256", await auth.coseKey(-257)],
      ["ES384 alg", await auth.coseKey(-35)],
      ["Ed25519", cbor(new Map<number, CborIn>([[1, 1], [3, -8], [-1, 6], [-2, xy]]))],
      ["P-384 curve", cbor(new Map<number, CborIn>([[1, 2], [3, -7], [-1, 2], [-2, xy], [-3, xy]]))],
      ["no alg", cbor(new Map<number, CborIn>([[1, 2], [-1, 1], [-2, xy], [-3, xy]]))],
    ];
    for (const [, coseKey] of keys) await rejects(verifyRegistration(await auth.register(e, { coseKey }), e), "bad_alg");
  });

  test("rejects bad coordinates", async () => {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    const ec2 = (x: Uint8Array, y: Uint8Array) => cbor(new Map<number, CborIn>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
    const rand = () => crypto.getRandomValues(new Uint8Array(32));
    await rejects(verifyRegistration(await auth.register(e, { coseKey: ec2(new Uint8Array(31), rand()) }), e), "bad_key");
    await rejects(verifyRegistration(await auth.register(e, { coseKey: ec2(rand(), "y" as unknown as Uint8Array) }), e), "bad_key");
    await rejects(verifyRegistration(await auth.register(e, { coseKey: ec2(rand(), rand()) }), e), "bad_key"); // not on the curve
  });
});

describe("assertion", () => {
  test("a valid assertion verifies", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    expect(await verifyAssertion(await auth.assert(e), credential, e)).toEqual({ signCount: 0 });
    const withHandle = { ...(await auth.assert(e)), userHandle: b64u.encode(new Uint8Array(16)) };
    expect(await verifyAssertion(withHandle, credential, e)).toEqual({ signCount: 0 });
  });

  const failures: [string, string, AssertOpts][] = [
    ["a wrong challenge", "bad_challenge", { challenge: newChallenge() }],
    ["a wrong origin", "bad_origin", { origin: "https://evil.example.com" }],
    ["the registration type", "bad_type", { type: "webauthn.create" }],
    ["crossOrigin true", "cross_origin", { crossOrigin: true }],
    ["crossOrigin that isn't a boolean", "cross_origin", { crossOrigin: "yes" }],
    ["a wrong rpId", "bad_rp", { rpId: "locked.example.org" }],
    ["missing UV", "no_user_verification", { flags: UP }],
    ["missing UP", "no_user_presence", { flags: UV }],
  ];
  for (const [name, code, opts] of failures) {
    test(`rejects ${name} (${code})`, async () => {
      const { auth, credential } = await paired();
      const e = freshExpect();
      await rejects(verifyAssertion(await auth.assert(e, opts), credential, e), code);
    });
  }

  test("rejects a replayed assertion against a new challenge", async () => {
    const { auth, credential } = await paired();
    const first = freshExpect();
    const assertion = await auth.assert(first);
    await verifyAssertion(assertion, credential, first);
    await rejects(verifyAssertion(assertion, credential, freshExpect()), "bad_challenge");
  });

  test("rejects tampered authenticatorData", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    const assertion = await auth.assert(e, { signCount: 4 });
    const data = b64u.decode(assertion.authenticatorData);
    data[36]! ^= 0x01; // the counter, so only the signature can notice
    await rejects(verifyAssertion({ ...assertion, authenticatorData: b64u.encode(data) }, credential, e), "bad_signature");
  });

  test("rejects tampered clientDataJSON", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    const assertion = await auth.assert(e);
    const client = JSON.parse(Buffer.from(b64u.decode(assertion.clientDataJSON)).toString("utf8"));
    const tampered = b64u.encode(enc.encode(JSON.stringify({ ...client, other_keys_can_be_added_here: "x" })));
    await rejects(verifyAssertion({ ...assertion, clientDataJSON: tampered }, credential, e), "bad_signature");
  });

  test("rejects a signature from a different key", async () => {
    const { auth, credential } = await paired();
    const other = await SoftAuthenticator.create();
    const e = freshExpect();
    await rejects(verifyAssertion(await auth.assert(e, { signWith: other.keys.privateKey }), credential, e), "bad_signature");
    await rejects(verifyAssertion(await other.assert(e), credential, e), "bad_signature");
  });

  test("rejects a stored key that isn't a usable P-256 JWK", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    const assertion = await auth.assert(e);
    for (const publicKeyJwk of [{}, { ...credential.publicKeyJwk, crv: "P-384" }, { ...credential.publicKeyJwk, x: b64u.encode(new Uint8Array(32)) }]) {
      await rejects(verifyAssertion(assertion, { publicKeyJwk, signCount: 0 }, e), "bad_key");
    }
  });

  test("rejects attested credential data that doesn't parse", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    const assertion = await auth.assert(e, { flags: UP | UV | AT });
    await rejects(verifyAssertion(assertion, credential, e), "malformed");
  });
});

describe("sign counter", () => {
  async function counted(stored: number, next: number) {
    const { auth, credential } = await paired();
    const e = freshExpect();
    return verifyAssertion(await auth.assert(e, { signCount: next }), { ...credential, signCount: stored }, e);
  }

  test("0 staying 0 is fine (iCloud Keychain)", async () => {
    expect(await counted(0, 0)).toEqual({ signCount: 0 });
  });

  test("a counter that starts or moves forward is returned", async () => {
    expect(await counted(0, 7)).toEqual({ signCount: 7 });
    expect(await counted(7, 8)).toEqual({ signCount: 8 });
    expect(await counted(7, 0xffffffff)).toEqual({ signCount: 0xffffffff });
  });

  test("a non-zero counter that doesn't move forward means a clone", async () => {
    await rejects(counted(8, 8), "cloned");
    await rejects(counted(8, 3), "cloned");
  });

  test("a counter dropping to 0 is not called a clone", async () => {
    expect(await counted(8, 0)).toEqual({ signCount: 0 });
  });
});

describe("DER signatures", () => {
  /** Length byte of r (which: 0) or s (which: 1) inside a DER signature. */
  function intLength(der: Bytes, which: 0 | 1): number {
    return which === 0 ? der[3]! : der[5 + der[3]!]!;
  }

  for (const [which, name] of [
    [0, "r"],
    [1, "s"],
  ] as const) {
    const at = which * 32;

    test(`${name} with its top bit set (DER adds a leading 0x00)`, async () => {
      const { auth, credential } = await paired();
      const e = freshExpect();
      const assertion = await auth.assert(e, { until: (raw) => raw[at]! >= 0x80 });
      const der = b64u.decode(assertion.signature);
      expect(intLength(der, which)).toBe(33);
      expect(await verifyAssertion(assertion, credential, e)).toEqual({ signCount: 0 });
    });

    test(`${name} shorter than 32 bytes`, async () => {
      const { auth, credential } = await paired();
      const e = freshExpect();
      const assertion = await auth.assert(e, { until: (raw) => raw[at] === 0 && raw[at + 1]! < 0x80 });
      const der = b64u.decode(assertion.signature);
      expect(intLength(der, which)).toBeLessThan(32);
      expect(await verifyAssertion(assertion, credential, e)).toEqual({ signCount: 0 });
    });
  }

  test("signatures that aren't DER are bad_signature", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    const assertion = await auth.assert(e, { until: (raw) => raw[0]! < 0x80 && raw[0] !== 0 });
    const der = b64u.decode(assertion.signature);
    const rLength = der[3]!;
    const variants: Uint8Array[] = [
      new Uint8Array(0),
      new Uint8Array(64), // raw r || s, not DER
      concat([0x31], der.subarray(1)), // SET, not SEQUENCE
      concat([0x30, der[1]! + 1], der.subarray(2)), // length disagrees
      concat(der, [0x00]), // trailing byte
      concat([0x30, der[1]! + 1], der.subarray(2), [0x00]), // trailing byte inside the SEQUENCE
      concat([0x30, der[1]!, 0x03], der.subarray(3)), // r isn't an INTEGER
      concat(der.subarray(0, 4), [der[4]! | 0x80], der.subarray(5)), // r is negative
      concat([0x30, der[1]! + 2, 0x02, rLength + 2, 0x01, 0x00], der.subarray(4)), // r is 33+ bytes of magnitude
      der.subarray(0, der.length - 1),
    ];
    for (const v of variants) await rejects(verifyAssertion({ ...assertion, signature: b64u.encode(v) }, credential, e), "bad_signature");
  });
});

describe("malformed input", () => {
  async function registration() {
    const auth = await SoftAuthenticator.create();
    const e = freshExpect();
    return { auth, e, reg: await auth.register(e) };
  }

  test("every truncation of the attestationObject is malformed", async () => {
    const { e, reg } = await registration();
    const att = b64u.decode(reg.attestationObject);
    for (let n = 0; n < att.length; n++) {
      await rejects(verifyRegistration({ ...reg, attestationObject: b64u.encode(att.subarray(0, n)) }, e), "malformed");
    }
  });

  test("every truncation of authData is malformed", async () => {
    const { e, reg } = await registration();
    const data = reg.authData;
    expect(data.length).toBe(37 + 16 + 2 + 16 + 77);
    await verifyRegistration(withAuthData(reg, data), e);
    for (let n = 0; n < data.length; n++) await rejects(verifyRegistration(withAuthData(reg, data.subarray(0, n)), e), "malformed");
  });

  test("every truncation of an assertion's authenticatorData is malformed", async () => {
    const { auth, credential } = await paired();
    const e = freshExpect();
    const assertion = await auth.assert(e);
    const data = b64u.decode(assertion.authenticatorData);
    for (let n = 0; n < data.length; n++) {
      await rejects(verifyAssertion({ ...assertion, authenticatorData: b64u.encode(data.subarray(0, n)) }, credential, e), "malformed");
    }
  });

  test("trailing bytes are malformed", async () => {
    const { e, reg } = await registration();
    const att = b64u.decode(reg.attestationObject);
    await rejects(verifyRegistration({ ...reg, attestationObject: b64u.encode(concat(att, [0x00])) }, e), "malformed");
    const data = reg.authData;
    await rejects(verifyRegistration(withAuthData(reg, concat(data, [0xa0])), e), "malformed"); // no ED flag
    data[32]! |= ED;
    await rejects(verifyRegistration(withAuthData(reg, concat(data, [0xa0, 0x00])), e), "malformed");
    await rejects(verifyRegistration(withAuthData(reg, concat(data, [0x80])), e), "malformed"); // extensions not a map
  });

  test("indefinite lengths are malformed", async () => {
    const { e, reg } = await registration();
    const data = reg.authData;
    const indefiniteMap = concat([0xbf], cbor("fmt"), cbor("none"), cbor("attStmt"), [0xa0], cbor("authData"), cbor(data), [0xff]);
    await rejects(verifyRegistration({ ...reg, attestationObject: b64u.encode(indefiniteMap) }, e), "malformed");
    const chunked = new Raw(concat([0x5f], cbor(data.subarray(0, 40)), cbor(data.subarray(40)), [0xff]));
    await rejects(verifyRegistration(withAuthData(reg, chunked), e), "malformed");
    await rejects(verifyRegistration(withAuthData(reg, data, { attStmt: new Raw(new Uint8Array([0x9f, 0xff])) }), e), "malformed");
    await rejects(verifyRegistration(withAuthData(reg, data, { attStmt: new Raw(new Uint8Array([0x7f, 0x61, 0x61, 0xff])) }), e), "malformed");
  });

  test("deep nesting is malformed, not a stack overflow", async () => {
    const { auth, e, reg } = await registration();
    const nested = concat(new Uint8Array(100_000).fill(0x81), [0x00]);
    await rejects(verifyRegistration(withAuthData(reg, reg.authData, { attStmt: new Raw(nested) }), e), "malformed");
    await rejects(verifyRegistration({ ...reg, attestationObject: b64u.encode(nested.subarray(0, 40_000)) }, e), "malformed");
    await rejects(verifyRegistration(await auth.register(e, { coseKey: concat(new Uint8Array(1000).fill(0xa1), [0x01]) }), e), "malformed");
  });

  test("huge declared lengths and counts are malformed", async () => {
    const { e, reg } = await registration();
    const data = reg.authData;
    const lies = [
      [0x5a, 0xff, 0xff, 0xff, 0xff], // byte string of 4 GiB
      [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // past 2^53
      [0x9a, 0xff, 0xff, 0xff, 0xff], // array of 4 billion items
      [0xba, 0x7f, 0xff, 0xff, 0xff], // map of 2 billion pairs
    ];
    for (const lie of lies) {
      await rejects(verifyRegistration(withAuthData(reg, data, { attStmt: new Raw(new Uint8Array(lie)) }), e), "malformed");
    }
  });

  test("unsupported CBOR is malformed", async () => {
    const { e, reg } = await registration();
    const data = reg.authData;
    const unsupported = [
      [0xc0, 0x61, 0x61], // tag 0
      [0xf9, 0x3c, 0x00], // half float 1.0
      [0xf7], // undefined
      [0xff], // stray break
      [0x1c], // reserved additional info
      [0xa1, 0x61, 0x61, 0x61, 0xff], // { "a": text that isn't UTF-8 }
      [0xa1, 0x40, 0x00], // byte-string map key
      [0xa2, 0x01, 0x00, 0x01, 0x00], // duplicate key
    ];
    for (const bytes of unsupported) {
      await rejects(verifyRegistration(withAuthData(reg, data, { attStmt: new Raw(new Uint8Array(bytes)) }), e), "malformed");
    }
  });

  test("an attestationObject of the wrong shape is malformed", async () => {
    const { e, reg } = await registration();
    const data = reg.authData;
    const shapes: CborIn[] = [
      [data],
      { fmt: "none", authData: data },
      { fmt: 1, attStmt: {}, authData: data },
      { fmt: "none", attStmt: [], authData: data },
      { fmt: "none", attStmt: {}, authData: b64u.encode(data) },
    ];
    for (const shape of shapes) await rejects(verifyRegistration({ ...reg, attestationObject: b64u.encode(cbor(shape)) }, e), "malformed");
  });

  test("fields that aren't base64url JSON are malformed", async () => {
    const { e, reg } = await registration();
    // The real clientData plus one more field whose value isn't UTF-8.
    const json = b64u.decode(reg.clientDataJSON);
    const notUtf8 = concat(json.subarray(0, -1), enc.encode(',"x":"'), [0xff], enc.encode('"}'));
    const bad: unknown[] = [
      null,
      42,
      { ...reg, clientDataJSON: undefined },
      { ...reg, clientDataJSON: 42 },
      { ...reg, clientDataJSON: reg.clientDataJSON + "+" },
      { ...reg, clientDataJSON: reg.clientDataJSON + "=" },
      { ...reg, clientDataJSON: b64u.encode(enc.encode("not json")) },
      { ...reg, clientDataJSON: b64u.encode(enc.encode("[]")) },
      { ...reg, clientDataJSON: b64u.encode(enc.encode("null")) },
      { ...reg, clientDataJSON: b64u.encode(notUtf8) },
      { ...reg, attestationObject: "%%%" },
      { ...reg, attestationObject: "A".repeat(100_000) },
    ];
    for (const input of bad) await rejects(verifyRegistration(input as RegistrationInput, e), "malformed");
  });

  test("random corruption only ever produces WebAuthnError", async () => {
    let seed = 0x5eed;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t ^= t + Math.imul(t ^ (t >>> 7), 61 | t);
      return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
    };
    const mutate = (bytes: Uint8Array): Bytes => {
      const out = [...bytes];
      for (let edits = 1 + Math.floor(random() * 3); edits > 0; edits--) {
        const at = Math.floor(random() * (out.length + 1));
        const op = random();
        if (op < 0.5) out[Math.min(at, out.length - 1)] = Math.floor(random() * 256);
        else if (op < 0.7) out.splice(at, 0, Math.floor(random() * 256));
        else if (op < 0.85) out.splice(at, 1 + Math.floor(random() * 8));
        else out.length = at;
      }
      return new Uint8Array(out);
    };
    const others: unknown[] = [];
    const attempt = (p: Promise<unknown>) => p.catch((err: unknown) => void (err instanceof WebAuthnError || others.push(err)));

    const { e, reg } = await registration();
    const att = b64u.decode(reg.attestationObject);
    for (let i = 0; i < 500; i++) await attempt(verifyRegistration({ ...reg, attestationObject: b64u.encode(mutate(att)) }, e));

    const { auth, credential } = await paired();
    const assertion = await auth.assert(e);
    const data = b64u.decode(assertion.authenticatorData);
    const sig = b64u.decode(assertion.signature);
    for (let i = 0; i < 300; i++) {
      await attempt(verifyAssertion({ ...assertion, authenticatorData: b64u.encode(mutate(data)) }, credential, e));
      await attempt(verifyAssertion({ ...assertion, signature: b64u.encode(mutate(sig)) }, credential, e));
    }
    expect(others).toEqual([]);
  });
});

test("newChallenge is 32 random bytes, base64url", () => {
  const a = newChallenge();
  expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(b64u.decode(a).length).toBe(32);
  expect(newChallenge()).not.toBe(a);
});
