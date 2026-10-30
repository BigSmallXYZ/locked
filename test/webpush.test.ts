import { describe, expect, test } from "bun:test";
import { b64u } from "../src/crypto.ts";
import {
  deriveContentKeys,
  encryptPayload,
  encryptPayloadWith,
  generateVapidKeys,
  MAX_PLAINTEXT,
  sendPush,
  vapidAuthorization,
  type PushSubscriptionJSON,
} from "../src/webpush.ts";

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();
type Bytes = Uint8Array<ArrayBuffer>;

const concat = (...parts: ArrayLike<number>[]): Bytes => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
/** The RFC prints base64url wrapped with spaces; strip them. */
const u = (text: string) => b64u.decode(text.replace(/\s+/g, ""));
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

// ---------------------------------------------------------------------------
// The browser's half, written from RFC 8291 §3.4's HMAC pseudocode rather than
// with the module's HKDF calls, so a shared mistake can't cancel out.

async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

async function newBrowserSubscription(endpoint = "https://web.push.apple.com/QGuQyavXutnMH3ZIMZnwcA") {
  const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const uaPublic = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const auth = crypto.getRandomValues(new Uint8Array(16));
  const sub: PushSubscriptionJSON = { endpoint, keys: { p256dh: b64u.encode(uaPublic), auth: b64u.encode(auth) } };
  return { sub, uaPrivate: pair.privateKey, uaPublic, auth };
}

async function browserDecrypt(uaPrivate: CryptoKey, uaPublic: Bytes, authSecret: Bytes, body: Uint8Array): Promise<Uint8Array> {
  const salt = body.slice(0, 16);
  const rs = new DataView(body.buffer, body.byteOffset).getUint32(16);
  const idlen = body[20]!;
  const asPublic = body.slice(21, 21 + idlen);
  const ct = body.slice(21 + idlen);
  expect(rs).toBe(4096);
  expect(idlen).toBe(65);
  expect(ct.length).toBeLessThan(rs);

  const peer = await subtle.importKey("raw", asPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: peer }, uaPrivate, 256));
  const prkKey = await hmac(authSecret, ecdhSecret);
  const keyInfo = concat(enc.encode("WebPush: info"), [0], uaPublic, asPublic);
  const ikm = await hmac(prkKey, concat(keyInfo, [1]));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode("Content-Encoding: aes128gcm"), [0, 1]))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode("Content-Encoding: nonce"), [0, 1]))).slice(0, 12);

  const aes = await subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  const padded = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, aes, ct));
  // Last record: plaintext, then 0x02, then optional zero padding.
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end--;
  if (padded[end] !== 0x02) throw new Error("bad padding delimiter");
  return padded.slice(0, end);
}

// ---------------------------------------------------------------------------
// RFC 8291 §5 and Appendix A, copied from https://www.rfc-editor.org/rfc/rfc8291.txt.

const RFC = {
  plaintext: "When I grow up, I want to be a watermelon",
  plaintextB64: "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24",
  endpoint: "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV",
  asPublic: "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
  asPrivate: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
  uaPublic: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV- JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
  uaPrivate: "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
  salt: "DGv6ra1nlYgDCS1FRnbzlw",
  auth: "BTBZMqHH6r4Tts7J_aSIgg",
  ecdhSecret: "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs",
  ikm: "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg",
  cek: "oIhVW04MRdy2XN9CiKLxTg",
  nonce: "4h_95klXJ5E_qnoN",
  header: `DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
           mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8`,
  ciphertext: `8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs
               bI_0LpXMuGvnzQ`,
  body: `DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
         mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT
         pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN`,
};

describe("RFC 8291 Appendix A test vector", () => {
  const asPublic = u(RFC.asPublic);
  const sub: PushSubscriptionJSON = {
    endpoint: RFC.endpoint,
    keys: { p256dh: RFC.uaPublic.replace(/\s+/g, ""), auth: RFC.auth },
  };
  const senderPrivateJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: RFC.asPrivate,
    x: b64u.encode(asPublic.subarray(1, 33)),
    y: b64u.encode(asPublic.subarray(33)),
  };

  test("encryptPayloadWith reproduces the §5 message exactly", async () => {
    expect(b64u.encode(enc.encode(RFC.plaintext))).toBe(RFC.plaintextB64);
    const body = await encryptPayloadWith(sub, enc.encode(RFC.plaintext), { salt: u(RFC.salt), senderPrivateJwk, senderPublicRaw: asPublic });
    expect(hex(body)).toBe(hex(u(RFC.body)));
    expect(hex(body.subarray(0, 86))).toBe(hex(u(RFC.header)));
    expect(hex(body.subarray(86))).toBe(hex(u(RFC.ciphertext)));
    // 86 + 41 + 1 + 16. (The RFC's example request says Content-Length: 145, but its own body is 144 bytes.)
    expect(body.length).toBe(144);
  });

  test("intermediate values: ecdh_secret, IKM, CEK, NONCE", async () => {
    const uaPublic = u(RFC.uaPublic);
    const ecdhSecret = u(RFC.ecdhSecret);
    // The shared secret from both sides matches the RFC's.
    const asKey = await subtle.importKey("jwk", senderPrivateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const uaPeer = await subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
    expect(hex(new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: uaPeer }, asKey, 256)))).toBe(hex(ecdhSecret));

    const keys = await deriveContentKeys({ ecdhSecret, authSecret: u(RFC.auth), uaPublic, asPublic, salt: u(RFC.salt) });
    expect(b64u.encode(keys.ikm)).toBe(RFC.ikm);
    expect(b64u.encode(keys.cek)).toBe(RFC.cek);
    expect(b64u.encode(keys.nonce)).toBe(RFC.nonce);
  });

  test("the test-side browser decryptor opens the RFC message with ua_private", async () => {
    const uaPublic = u(RFC.uaPublic);
    const uaPrivate = await subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", d: RFC.uaPrivate, x: b64u.encode(uaPublic.subarray(1, 33)), y: b64u.encode(uaPublic.subarray(33)) },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    expect(dec.decode(await browserDecrypt(uaPrivate, uaPublic, u(RFC.auth), u(RFC.body)))).toBe(RFC.plaintext);
  });
});

// ---------------------------------------------------------------------------

describe("encryptPayload", () => {
  test("round trip through a simulated browser", async () => {
    const b = await newBrowserSubscription();
    const plaintext = enc.encode(JSON.stringify({ title: "Locked", body: "ünï 🔑 request lk_7f3kq2m9xa is waiting" }));
    const body = await encryptPayload(b.sub, plaintext);
    expect(body.length).toBe(86 + plaintext.length + 1 + 16);
    expect(hex(await browserDecrypt(b.uaPrivate, b.uaPublic, b.auth, body))).toBe(hex(plaintext));
  });

  test("fresh salt and sender key every message", async () => {
    const b = await newBrowserSubscription();
    const one = await encryptPayload(b.sub, enc.encode("same"));
    const two = await encryptPayload(b.sub, enc.encode("same"));
    expect(hex(one.subarray(0, 16))).not.toBe(hex(two.subarray(0, 16)));
    expect(hex(one.subarray(21, 86))).not.toBe(hex(two.subarray(21, 86)));
  });

  test("the largest payload fills exactly 4096 bytes; one more byte throws", async () => {
    const b = await newBrowserSubscription();
    expect(MAX_PLAINTEXT).toBe(3993);
    const max = new Uint8Array(MAX_PLAINTEXT).fill(0x61);
    const body = await encryptPayload(b.sub, max);
    expect(body.length).toBe(4096);
    expect(hex(await browserDecrypt(b.uaPrivate, b.uaPublic, b.auth, body))).toBe(hex(max));
    await expect(encryptPayload(b.sub, new Uint8Array(MAX_PLAINTEXT + 1))).rejects.toThrow(/4096/);
  });

  test("rejects malformed subscriptions", async () => {
    const { sub } = await newBrowserSubscription();
    const msg = enc.encode("hi");
    await expect(encryptPayload({ ...sub, endpoint: "http://push.example.net/x" }, msg)).rejects.toThrow(/https/);
    await expect(encryptPayload({ ...sub, endpoint: "not a url" }, msg)).rejects.toThrow(/valid URL/);
    await expect(encryptPayload({ ...sub, keys: { ...sub.keys, p256dh: sub.keys.p256dh.slice(0, 40) } }, msg)).rejects.toThrow(/p256dh/);
    const compressed = b64u.encode(concat([0x02], b64u.decode(sub.keys.p256dh).subarray(1, 33)));
    await expect(encryptPayload({ ...sub, keys: { ...sub.keys, p256dh: compressed } }, msg)).rejects.toThrow(/p256dh/);
    await expect(encryptPayload({ ...sub, keys: { ...sub.keys, auth: b64u.encode(new Uint8Array(12)) } }, msg)).rejects.toThrow(/auth/);
    await expect(encryptPayload({ endpoint: sub.endpoint } as PushSubscriptionJSON, msg)).rejects.toThrow(/keys/);
  });
});

// ---------------------------------------------------------------------------

function parseAuthorization(header: string) {
  const m = /^vapid t=([^,\s]+), k=([A-Za-z0-9_-]+)$/.exec(header);
  if (!m) throw new Error(`bad Authorization header: ${header}`);
  const jwt = m[1]!;
  const [h, c, s] = jwt.split(".") as [string, string, string];
  return {
    k: m[2]!,
    signingInput: `${h}.${c}`,
    header: JSON.parse(dec.decode(b64u.decode(h))) as Record<string, unknown>,
    claims: JSON.parse(dec.decode(b64u.decode(c))) as { aud: string; exp: number; sub: string },
    sig: b64u.decode(s),
    jwt,
  };
}

async function verifyEs256(publicKey: string, signingInput: string, sig: Bytes): Promise<boolean> {
  const key = await subtle.importKey("raw", b64u.decode(publicKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, enc.encode(signingInput));
}

describe("VAPID", () => {
  const endpoint = "https://web.push.apple.com/QGuQyavXutnMH3ZIMZnwcA";
  const subject = "mailto:ops@example.com";

  test("generateVapidKeys gives a 65-byte applicationServerKey and a private JWK", async () => {
    const keys = await generateVapidKeys();
    const raw = b64u.decode(keys.publicKey);
    expect(raw.length).toBe(65);
    expect(raw[0]).toBe(0x04);
    expect(keys.privateJwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(typeof keys.privateJwk.d).toBe("string");
  });

  test("the JWT verifies with the public key; aud, exp, sub and k are right", async () => {
    const keys = await generateVapidKeys();
    const now = Math.floor(Date.now() / 1000);
    const a = parseAuthorization(await vapidAuthorization(endpoint, keys, subject));
    expect(a.k).toBe(keys.publicKey);
    expect(a.header).toEqual({ typ: "JWT", alg: "ES256" });
    expect(a.claims.aud).toBe("https://web.push.apple.com");
    expect(a.claims.sub).toBe(subject);
    expect(a.claims.exp).toBeGreaterThan(now);
    expect(a.claims.exp).toBeLessThanOrEqual(now + 24 * 3600);
    expect(Math.abs(a.claims.exp - (now + 12 * 3600))).toBeLessThan(5);
    expect(a.jwt).not.toContain("=");
    expect(a.sig.length).toBe(64);
    expect(await verifyEs256(keys.publicKey, a.signingInput, a.sig)).toBe(true);

    // A different key, or altered claims, must not verify.
    const other = await generateVapidKeys();
    expect(await verifyEs256(other.publicKey, a.signingInput, a.sig)).toBe(false);
    const forged = `${a.signingInput.split(".")[0]}.${b64u.encode(enc.encode(JSON.stringify({ ...a.claims, aud: "https://evil.example" })))}`;
    expect(await verifyEs256(keys.publicKey, forged, a.sig)).toBe(false);
  });

  test("aud is the origin, keeping a non-default port and dropping the path", async () => {
    const keys = await generateVapidKeys();
    const a = parseAuthorization(await vapidAuthorization("https://push.example.net:8443/wpush/v2/abc?x=1", keys, subject));
    expect(a.claims.aud).toBe("https://push.example.net:8443");
  });

  test("expSec sets exp; more than 24h out, in the past, or a bad subject throws", async () => {
    const keys = await generateVapidKeys();
    const now = Math.floor(Date.now() / 1000);
    const a = parseAuthorization(await vapidAuthorization(endpoint, keys, "https://locked.example", now + 600));
    expect(a.claims.exp).toBe(now + 600);
    await expect(vapidAuthorization(endpoint, keys, subject, now + 25 * 3600)).rejects.toThrow(/24h/);
    await expect(vapidAuthorization(endpoint, keys, subject, now - 1)).rejects.toThrow(/24h/);
    await expect(vapidAuthorization(endpoint, keys, "ops@example.com")).rejects.toThrow(/subject/);
    await expect(vapidAuthorization("http://push.example.net/x", keys, subject)).rejects.toThrow(/https/);
  });

  test("a public key that doesn't match the private key throws", async () => {
    const keys = await generateVapidKeys();
    const other = await generateVapidKeys();
    await expect(vapidAuthorization(endpoint, { ...keys, publicKey: other.publicKey }, subject)).rejects.toThrow(/match/);
  });
});

// ---------------------------------------------------------------------------

type Call = { url: string; init: RequestInit };

function fakeFetch(respond: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const call = { url: String(input), init: init ?? {} };
    calls.push(call);
    return respond(call);
  }) as typeof fetch;
  return { fetch: fn, calls };
}

describe("sendPush", () => {
  const payload = { title: "Locked", body: "A secret is waiting", url: "/r/lk_7f3kq2m9xa" };

  test("POSTs the encrypted payload with the right headers; 201 is ok", async () => {
    const b = await newBrowserSubscription();
    const vapid = await generateVapidKeys();
    const f = fakeFetch(() => new Response(null, { status: 201 }));
    const result = await sendPush(b.sub, payload, vapid, { subject: "mailto:ops@example.com", fetch: f.fetch });
    expect(result).toEqual({ ok: true, status: 201, gone: false });

    expect(f.calls.length).toBe(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe(b.sub.endpoint);
    expect(init.method).toBe("POST");
    const h = new Headers(init.headers);
    expect(h.get("TTL")).toBe("60");
    expect(h.get("Urgency")).toBe("high");
    expect(h.get("Topic")).toBeNull();
    expect(h.get("Content-Type")).toBe("application/octet-stream");
    expect(h.get("Content-Encoding")).toBe("aes128gcm");

    const a = parseAuthorization(h.get("Authorization")!);
    expect(a.k).toBe(vapid.publicKey);
    expect(a.claims.aud).toBe("https://web.push.apple.com");
    expect(await verifyEs256(vapid.publicKey, a.signingInput, a.sig)).toBe(true);

    const body = init.body as Uint8Array;
    expect(body).toBeInstanceOf(Uint8Array);
    expect(dec.decode(await browserDecrypt(b.uaPrivate, b.uaPublic, b.auth, body))).toBe(JSON.stringify(payload));
  });

  test("ttlSec, urgency and topic become headers", async () => {
    const b = await newBrowserSubscription("https://fcm.googleapis.com/fcm/send/dQw4w9WgXcQ:APA91b");
    const f = fakeFetch(() => new Response(null, { status: 201 }));
    await sendPush(b.sub, payload, await generateVapidKeys(), {
      subject: "https://locked.example",
      ttlSec: 3600,
      urgency: "low",
      topic: "lk_7f3kq2m9xa",
      fetch: f.fetch,
    });
    const h = new Headers(f.calls[0]!.init.headers);
    expect(h.get("TTL")).toBe("3600");
    expect(h.get("Urgency")).toBe("low");
    expect(h.get("Topic")).toBe("lk_7f3kq2m9xa");
    expect(parseAuthorization(h.get("Authorization")!).claims.aud).toBe("https://fcm.googleapis.com");
  });

  test("410 and 404 mean the subscription is gone", async () => {
    const b = await newBrowserSubscription();
    const vapid = await generateVapidKeys();
    for (const status of [410, 404]) {
      const f = fakeFetch(() => new Response("", { status }));
      const r = await sendPush(b.sub, payload, vapid, { subject: "mailto:ops@example.com", fetch: f.fetch });
      expect(r).toMatchObject({ ok: false, status, gone: true });
      expect(r.error).toContain(String(status));
    }
  });

  test("other HTTP errors come back with the service's reason, not thrown", async () => {
    const b = await newBrowserSubscription();
    const f = fakeFetch(() => new Response(JSON.stringify({ reason: "BadJwtToken" }), { status: 403, statusText: "Forbidden" }));
    const r = await sendPush(b.sub, payload, await generateVapidKeys(), { subject: "mailto:ops@example.com", fetch: f.fetch });
    expect(r).toMatchObject({ ok: false, status: 403, gone: false });
    expect(r.error).toBe('403 Forbidden: {"reason":"BadJwtToken"}');
  });

  test("a network error is ok:false, status 0", async () => {
    const b = await newBrowserSubscription();
    const f = fakeFetch(() => {
      throw new TypeError("fetch failed");
    });
    const r = await sendPush(b.sub, payload, await generateVapidKeys(), { subject: "mailto:ops@example.com", fetch: f.fetch });
    expect(r).toEqual({ ok: false, status: 0, gone: false, error: "fetch failed" });
  });

  test("an oversized payload throws before anything is sent", async () => {
    const b = await newBrowserSubscription();
    const f = fakeFetch(() => new Response(null, { status: 201 }));
    const big = { blob: "x".repeat(MAX_PLAINTEXT) };
    await expect(sendPush(b.sub, big, await generateVapidKeys(), { subject: "mailto:ops@example.com", fetch: f.fetch })).rejects.toThrow(
      /4096/,
    );
    expect(f.calls.length).toBe(0);
  });

  test("bad options throw before anything is sent", async () => {
    const b = await newBrowserSubscription();
    const vapid = await generateVapidKeys();
    const f = fakeFetch(() => new Response(null, { status: 201 }));
    const base = { subject: "mailto:ops@example.com", fetch: f.fetch };
    await expect(sendPush(b.sub, payload, vapid, { ...base, topic: "has spaces" })).rejects.toThrow(/topic/);
    await expect(sendPush(b.sub, payload, vapid, { ...base, topic: "x".repeat(33) })).rejects.toThrow(/topic/);
    await expect(sendPush(b.sub, payload, vapid, { ...base, ttlSec: -1 })).rejects.toThrow(/ttlSec/);
    await expect(sendPush(b.sub, undefined, vapid, base)).rejects.toThrow(/JSON/);
    expect(f.calls.length).toBe(0);
  });
});
