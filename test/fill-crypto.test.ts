import { describe, expect, test } from "bun:test";
import { newFillKeypair, openFillEnvelope, sealFillEnvelope as serverSeal, type FillEnvelope } from "../src/crypto.ts";

type WebFillCrypto = {
  FILL_INFO: string;
  cryptoAvailable(): boolean;
  b64uEncode(bytes: Uint8Array | ArrayBuffer): string;
  b64uDecode(text: string): Uint8Array;
  sealFillEnvelope(publicKey: string, data: unknown, requestId: string): Promise<FillEnvelope>;
  buildSubmitPost(
    publicKey: string,
    values: Record<string, string>,
    requestId: string,
    retention: string,
  ): Promise<{ action: "submit"; envelope: FillEnvelope; retention: string }>;
};

// Loaded by URL so tsc (allowJs: false) doesn't need types for the browser module.
const web = (await import(new URL("../web/fill-crypto.js", import.meta.url).href)) as WebFillCrypto;

const REQUEST_ID = "lk_7f3kq2m9xa";
const values = {
  username: "octocat@example.com",
  password: "hunter2-Correct-Horse-Battery-Staple ünï 🔑",
  apikey: "fake_key_51HxQpLmNoPqRsTuVwXyZ0123456789",
  key: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
};
const B64U = /^[A-Za-z0-9_-]+$/;

describe("web/fill-crypto.js", () => {
  test("round trip: the browser seals, the server opens", async () => {
    const kp = await newFillKeypair();
    const envelope = await web.sealFillEnvelope(kp.publicKey, { values }, REQUEST_ID);
    expect(await openFillEnvelope(kp.privateJwk, envelope, REQUEST_ID)).toEqual({ values });
  });

  test("envelope has the server's shape and sizes", async () => {
    const kp = await newFillKeypair();
    const data = { values };
    const envelope = await web.sealFillEnvelope(kp.publicKey, data, REQUEST_ID);
    const server = await serverSeal(kp.publicKey, data, REQUEST_ID);
    expect(Object.keys(envelope).sort()).toEqual(Object.keys(server).sort());
    expect(envelope.v).toBe(1);
    for (const k of ["epk", "salt", "iv", "ct"] as const) expect(envelope[k]).toMatch(B64U);
    const epk = web.b64uDecode(envelope.epk);
    expect(epk.length).toBe(65);
    expect(epk[0]).toBe(4);
    expect(web.b64uDecode(envelope.salt).length).toBe(16);
    expect(web.b64uDecode(envelope.iv).length).toBe(12);
    expect(web.b64uDecode(envelope.ct).length).toBe(new TextEncoder().encode(JSON.stringify(data)).length + 16);
  });

  test("a different requestId fails to open", async () => {
    const kp = await newFillKeypair();
    const envelope = await web.sealFillEnvelope(kp.publicKey, { values }, REQUEST_ID);
    await expect(openFillEnvelope(kp.privateJwk, envelope, "lk_someoneelse")).rejects.toThrow();
  });

  test("another request's key or a tampered ciphertext fails to open", async () => {
    const kp = await newFillKeypair();
    const other = await newFillKeypair();
    const envelope = await web.sealFillEnvelope(kp.publicKey, { values }, REQUEST_ID);
    await expect(openFillEnvelope(other.privateJwk, envelope, REQUEST_ID)).rejects.toThrow();
    const ct = web.b64uDecode(envelope.ct);
    ct[0] = (ct[0] ?? 0) ^ 1;
    await expect(openFillEnvelope(kp.privateJwk, { ...envelope, ct: web.b64uEncode(ct) }, REQUEST_ID)).rejects.toThrow();
  });

  test("every seal uses a fresh ephemeral key, salt and iv", async () => {
    const kp = await newFillKeypair();
    const a = await web.sealFillEnvelope(kp.publicKey, { values }, REQUEST_ID);
    const b = await web.sealFillEnvelope(kp.publicKey, { values }, REQUEST_ID);
    expect(a.epk).not.toBe(b.epk);
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
  });

  test("the posted body never contains the plaintext", async () => {
    const kp = await newFillKeypair();
    const post = await web.buildSubmitPost(kp.publicKey, values, REQUEST_ID, "once");
    const body = JSON.stringify(post);
    expect(Object.keys(post).sort()).toEqual(["action", "envelope", "retention"]);
    expect(post.action).toBe("submit");
    expect(post.retention).toBe("once");
    for (const [name, value] of Object.entries(values)) {
      const bytes = new TextEncoder().encode(value);
      expect(body).not.toContain(value);
      expect(body).not.toContain(JSON.stringify(value).slice(1, -1));
      expect(body).not.toContain(Buffer.from(bytes).toString("base64").replace(/=+$/, ""));
      expect(body).not.toContain(web.b64uEncode(bytes));
      expect(body).not.toContain(`"${name}"`);
    }
    expect(body).not.toContain("values");
    // ...and it is still what the server needs.
    expect(await openFillEnvelope(kp.privateJwk, post.envelope, REQUEST_ID)).toEqual({ values });
  });

  test("base64url helpers match Buffer", () => {
    for (let n = 0; n <= 70; n++) {
      const bytes = crypto.getRandomValues(new Uint8Array(n));
      const text = web.b64uEncode(bytes);
      expect(text).toBe(Buffer.from(bytes).toString("base64url"));
      expect(Array.from(web.b64uDecode(text))).toEqual(Array.from(bytes));
    }
    expect(() => web.b64uDecode("abc+")).toThrow();
    expect(() => web.b64uDecode("abcde")).toThrow();
  });

  test("rejects a malformed public key or a missing request id", async () => {
    const kp = await newFillKeypair();
    await expect(web.sealFillEnvelope("not a key!", { values }, REQUEST_ID)).rejects.toThrow();
    await expect(web.sealFillEnvelope(web.b64uEncode(new Uint8Array(33)), { values }, REQUEST_ID)).rejects.toThrow();
    await expect(web.sealFillEnvelope(kp.publicKey, { values }, "")).rejects.toThrow();
  });

  test("refuses to run without WebCrypto or outside a secure context", async () => {
    const kp = await newFillKeypair();
    const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    expect(original?.configurable).toBe(true);
    Object.defineProperty(globalThis, "crypto", { value: { getRandomValues: () => undefined }, configurable: true, writable: true });
    try {
      expect(web.cryptoAvailable()).toBe(false);
      await expect(web.sealFillEnvelope(kp.publicKey, { values }, REQUEST_ID)).rejects.toThrow(/encrypt/);
    } finally {
      Object.defineProperty(globalThis, "crypto", original!);
    }
    Object.defineProperty(globalThis, "isSecureContext", { value: false, configurable: true });
    try {
      expect(web.cryptoAvailable()).toBe(false);
      await expect(web.buildSubmitPost(kp.publicKey, values, REQUEST_ID, "once")).rejects.toThrow(/encrypt/);
    } finally {
      delete (globalThis as { isSecureContext?: boolean }).isSecureContext;
    }
    expect(web.cryptoAvailable()).toBe(true);
  });
});
