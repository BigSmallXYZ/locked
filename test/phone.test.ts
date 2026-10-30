import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { b64u, openFillEnvelope, PHONE_INFO, sealFillEnvelope, type FillEnvelope } from "../src/crypto.ts";
import { startServers, type Running } from "../src/server/index.ts";
import type { PushPayload, Pusher } from "../src/server/phone.ts";
import type { PushResult, PushSubscriptionJSON } from "../src/webpush.ts";
import { softPasskey } from "./passkey.ts";

// Stands in for Web Push: records what would have been pushed, answers with `pushAnswer`.
const pushed: Array<{ sub: PushSubscriptionJSON; payload: PushPayload }> = [];
let pushAnswer: PushResult = { ok: true, status: 201, gone: false };
const fakePusher: Pusher = async (sub, payload) => {
  pushed.push({ sub, payload: payload as PushPayload });
  return pushAnswer;
};

let s: Running;
let pub: string;
let agent: string;
const token = "test-agent-token-0123456789";
const auth = { Authorization: `Bearer ${token}` };

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "locked-phone-"));
  s = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(dir, "t.db"), keyPath: join(dir, "k"), keystore: "file", token, native: null, pusher: fakePusher });
  pub = `http://127.0.0.1:${s.publicServer.port}`;
  agent = `http://127.0.0.1:${s.agentServer.port}`;
});
afterAll(() => s.stop());

async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(agent + path, { method, headers: { ...auth, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: (await res.json()) as any };
}

/** What the phone page does: same-origin JSON to /phone/api/… */
async function phone(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${pub}/phone/api/${path}`, { method, headers: { "Content-Type": "application/json", Origin: pub, ...headers }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: (await res.json()) as any };
}

async function filled(values: Record<string, string>, extra: Record<string, unknown> = {}) {
  const created = (await api("POST", "/api/requests", { label: "Phone login", site: "https://example.com", fields: [{ name: "username" }, { name: "password" }], ...extra })).body;
  const html = await (await fetch(created.url)).text();
  const data = JSON.parse(html.match(/<script type="application\/json" id="locked-data">(.*?)<\/script>/s)![1]!);
  const envelope = await sealFillEnvelope(data.publicKey, { values }, data.id);
  await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "submit", envelope, retention: "1h" }) });
  return created.id as string;
}

async function fakeSubscription(): Promise<PushSubscriptionJSON> {
  const ua = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  return {
    endpoint: `https://push.example/${crypto.randomUUID()}`,
    keys: { p256dh: b64u.encode(await crypto.subtle.exportKey("raw", ua.publicKey)), auth: b64u.encode(crypto.getRandomValues(new Uint8Array(16))) },
  };
}

/** The page's own key for one unlock; returns what to post and how to open the answer. */
async function pageKey() {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const privateJwk = JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey));
  return {
    epk: b64u.encode(await crypto.subtle.exportKey("raw", pair.publicKey)),
    open: (env: FillEnvelope, shareId: string) => openFillEnvelope<{ values: Record<string, string> }>(privateJwk, env, shareId, PHONE_INFO),
  };
}

async function pair(name: string) {
  const started = (await api("POST", "/api/pairings", { name })).body;
  const passkey = await softPasskey(new URL(pub).hostname);
  const begun = (await phone("POST", "pair/begin", { code: started.code })).body;
  const sub = await fakeSubscription();
  const finished = await phone("POST", "pair/finish", { pairingId: begun.pairingId, credential: passkey.create(begun.publicKey.challenge, pub), subscription: sub, name });
  return { started, begun, finished, passkey, sub };
}

async function unlock(shareToken: string, passkey: Awaited<ReturnType<typeof softPasskey>>, opts: { uv?: boolean } = {}) {
  const { challenge } = (await phone("POST", `s/${shareToken}/challenge`, {})).body;
  const key = await pageKey();
  const res = await phone("POST", `s/${shareToken}/unlock`, { assertion: await passkey.get(challenge, pub, opts), epk: key.epk });
  return { res, key, challenge };
}

let first: Awaited<ReturnType<typeof pair>>;

describe("phone", () => {
  test("the app shell: page, service worker and manifest", async () => {
    const page = await fetch(`${pub}/phone/`);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("manifest-src 'self'");
    expect(await page.text()).toContain("/assets/phone.js");
    expect((await fetch(`${pub}/phone`, { redirect: "manual" })).headers.get("location")).toBe("/phone/");
    const sw = await fetch(`${pub}/phone/sw.js`);
    expect(sw.headers.get("content-type")).toContain("javascript");
    expect(await sw.text()).toContain("showNotification");
    const manifest = await fetch(`${pub}/phone/manifest.webmanifest`);
    expect(manifest.headers.get("content-type")).toContain("manifest+json");
    expect((await manifest.json()).scope).toBe("/phone/");
    expect((await fetch(`${pub}/assets/phone-icon-180.png`)).headers.get("content-type")).toBe("image/png");
    expect((await phone("GET", "info")).body.vapidPublicKey).toMatch(/^[A-Za-z0-9_-]{87}$/);
  });

  test("pairing: the code buys a passkey challenge; the passkey and subscription become a device", async () => {
    const started = (await api("POST", "/api/pairings", { name: "Test iPhone" })).body;
    expect(started.code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(started.url).toBe(`${pub}/phone/#pair=${started.code}`);
    expect(started.pairing.status).toBe("pending");

    expect((await phone("POST", "pair/begin", { code: "AAAA-AAAA" })).status).toBe(404);
    // Codes are forgiving about case and dashes.
    const begun = (await phone("POST", "pair/begin", { code: started.code.toLowerCase().replace("-", " ") })).body;
    expect(begun.publicKey.rp.id).toBe("127.0.0.1");
    expect(begun.publicKey.authenticatorSelection.userVerification).toBe("required");
    expect(begun.vapidPublicKey).toBe((await phone("GET", "info")).body.vapidPublicKey);

    const passkey = await softPasskey("127.0.0.1");
    const sub = await fakeSubscription();
    // A browser elsewhere can't post to the phone API.
    const cross = await fetch(`${pub}/phone/api/pair/finish`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://evil.example" }, body: "{}" });
    expect(cross.status).toBe(403);
    // A registration for some other challenge fails, and spends this one.
    const wrong = await phone("POST", "pair/finish", { pairingId: begun.pairingId, credential: passkey.create(b64u.encode(new Uint8Array(32)), pub), subscription: sub });
    expect(wrong.status).toBe(403);
    expect((await phone("POST", "pair/finish", { pairingId: begun.pairingId, credential: passkey.create(begun.publicKey.challenge, pub), subscription: sub })).status).toBe(410);

    const again = (await phone("POST", "pair/begin", { code: started.code })).body;
    pushed.length = 0;
    const finished = await phone("POST", "pair/finish", { pairingId: again.pairingId, credential: passkey.create(again.publicKey.challenge, pub), subscription: sub, name: "Anderson's test phone" });
    expect(finished.status).toBe(200);
    expect(finished.body).toMatchObject({ name: "Anderson's test phone", pushOk: true });
    expect(pushed).toHaveLength(1);
    expect(pushed[0]!.sub).toEqual(sub);
    expect(pushed[0]!.payload).toMatchObject({ t: "info", title: "Locked is paired" });

    // The code works once.
    expect((await phone("POST", "pair/begin", { code: started.code })).status).toBe(404);
    expect((await api("GET", `/api/pairings/${started.pairing.id}/wait?timeout=1`)).body.pairing).toMatchObject({ status: "paired", deviceId: finished.body.deviceId, pushOk: true });
    const devices = (await api("GET", "/api/devices")).body.devices;
    expect(devices).toEqual([expect.objectContaining({ id: finished.body.deviceId, name: "Anderson's test phone", push: true })]);
    first = { started, begun: again, finished, passkey, sub };
  });

  test("send: a push without the secret; Face ID on the phone releases the values, sealed to the page", async () => {
    const id = await filled({ username: "octo", password: "phone-canary-pw" });
    pushed.length = 0;
    const sent = await api("POST", `/api/requests/${id}/phone`, { purpose: "sign in to the GitHub app", timeoutSec: 300 });
    expect(sent.status).toBe(200);
    const share = sent.body.share;
    expect(share).toMatchObject({ requestId: id, status: "sent", fields: ["username", "password"], devices: [{ id: first.finished.body.deviceId, ok: true }] });
    expect(pushed).toHaveLength(1);
    const payload = pushed[0]!.payload as Extract<PushPayload, { t: "share" }>;
    expect(payload).toMatchObject({ t: "share", title: "Phone login" });
    expect(payload.body).toContain("Claude: sign in to the GitHub app");
    expect(JSON.stringify(pushed)).not.toContain("phone-canary-pw");
    const t = payload.s;

    const waiting = api("GET", `/api/shares/${share.id}/wait?timeout=10&after=0`);
    expect((await phone("POST", `s/${t}/delivered`, {})).status).toBe(200);
    expect((await waiting).body.share.events.map((e: any) => e.event)).toEqual(["delivered"]);

    const info = (await phone("GET", `s/${t}`)).body;
    expect(info).toMatchObject({ id: share.id, label: "Phone login", site: "https://example.com", purpose: "sign in to the GitHub app", level: "normal" });
    expect(info.fields.map((f: any) => f.name)).toEqual(["username", "password"]);
    expect(info.credentialIds).toContain(first.passkey.credentialId);
    expect(JSON.stringify(info)).not.toContain("phone-canary-pw");
    expect((await phone("GET", "s/not-a-real-share-token-at-all")).status).toBe(410);

    // No Face ID (user verification), no values.
    expect((await unlock(t, first.passkey, { uv: false })).res.status).toBe(403);
    // Another passkey for the same site that was never paired.
    const stranger = await softPasskey("127.0.0.1");
    expect((await unlock(t, stranger)).res.body.code).toBe("not_paired");
    // A challenge works once.
    const { res, key, challenge } = await unlock(t, first.passkey);
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toContain("phone-canary-pw");
    expect((await key.open(res.body.envelope, share.id)).values).toEqual({ username: "octo", password: "phone-canary-pw" });
    const replay = await phone("POST", `s/${t}/unlock`, { assertion: await first.passkey.get(challenge, pub), epk: key.epk });
    expect(replay.body.code).toBe("expired_challenge");

    const session = res.body.session;
    expect((await phone("POST", `s/${t}/event`, { event: "copied", field: "password" })).status).toBe(403);
    expect((await phone("POST", `s/${t}/event`, { session, event: "copied", field: "nope" })).status).toBe(400);
    expect((await phone("POST", `s/${t}/event`, { session, event: "copied", field: "password" })).status).toBe(200);
    expect((await phone("POST", `s/${t}/event`, { session, event: "shown", field: "username" })).status).toBe(200);
    const events = (await api("GET", `/api/shares/${share.id}`)).body.share.events;
    expect(events.map((e: any) => [e.event, e.field ?? null])).toEqual([
      ["delivered", null],
      ["opened", null],
      ["unlocked", null],
      ["copied", "password"],
      ["shown", "username"],
    ]);

    expect((await phone("POST", `s/${t}/event`, { session, event: "closed" })).status).toBe(200);
    expect((await api("GET", `/api/shares/${share.id}`)).body.share.status).toBe("closed");
    expect((await phone("GET", `s/${t}`)).status).toBe(410); // the token dies with the share

    const audit = (await api("GET", `/api/audit?request=${id}`)).body.events;
    const names = audit.map((e: any) => e.event);
    for (const n of ["phone_sent", "phone_opened", "phone_unlocked", "phone_copied", "phone_closed", "used"]) expect(names).toContain(n);
    expect(JSON.stringify(audit)).not.toContain("phone-canary-pw");
  });

  test("sealed secrets go through the phone too: Face ID counts as the device check", async () => {
    const id = await filled({ username: "u", password: "sealed-phone-pw" }, { level: "sealed", label: "Bank login" });
    pushed.length = 0;
    const share = (await api("POST", `/api/requests/${id}/phone`, { only: ["password"] })).body.share;
    expect(share.fields).toEqual(["password"]);
    const t = (pushed[0]!.payload as Extract<PushPayload, { t: "share" }>).s;
    expect((await phone("GET", `s/${t}`)).body.level).toBe("sealed");
    const { res, key } = await unlock(t, first.passkey);
    expect((await key.open(res.body.envelope, share.id)).values).toEqual({ password: "sealed-phone-pw" });
    const audit = (await api("GET", `/api/audit?request=${id}`)).body.events.map((e: any) => e.event);
    expect(audit).toContain("device_confirmed");
  });

  test("a bad page key costs nothing; a second phone is announced to the first", async () => {
    const id = await filled({ username: "u", password: "p" });
    pushed.length = 0;
    const share = (await api("POST", `/api/requests/${id}/phone`, {})).body.share;
    const t = (pushed[0]!.payload as Extract<PushPayload, { t: "share" }>).s;
    const { challenge } = (await phone("POST", `s/${t}/challenge`, {})).body;
    const bad = await phone("POST", `s/${t}/unlock`, { assertion: await first.passkey.get(challenge, pub), epk: "AAAA" });
    expect(bad.body.code).toBe("bad_key");
    expect((await api("GET", `/api/requests/${id}`)).body.request.useCount).toBe(0);
    expect((await api("GET", `/api/shares/${share.id}`)).body.share.events.map((e: any) => e.event)).not.toContain("unlocked");

    pushed.length = 0;
    const second = await pair("Second phone");
    expect(second.finished.status).toBe(200);
    const announce = pushed.find((p) => p.sub.endpoint === first.sub.endpoint);
    expect(announce?.payload).toMatchObject({ t: "info", title: "New phone paired with Locked" });
    expect((await api("GET", "/api/devices")).body.devices).toHaveLength(2);

    // Removing a phone: its passkey stops working, and it gets no more shares.
    expect((await api("DELETE", `/api/devices/${second.finished.body.deviceId}`)).status).toBe(200);
    pushed.length = 0;
    const share2 = (await api("POST", `/api/requests/${id}/phone`, {})).body.share;
    expect(share2.devices.map((d: any) => d.id)).toEqual([first.finished.body.deviceId]);
    const t2 = (pushed[0]!.payload as Extract<PushPayload, { t: "share" }>).s;
    expect((await unlock(t2, second.passkey)).res.body.code).toBe("not_paired");
  });

  test("a subscription the push service calls gone is dropped, and sending says so", async () => {
    const id = await filled({ username: "u", password: "p" });
    pushAnswer = { ok: false, status: 410, gone: true };
    const res = await api("POST", `/api/requests/${id}/phone`, {});
    pushAnswer = { ok: true, status: 201, gone: false };
    expect(res.status).toBe(502);
    expect(res.body.code).toBe("push_failed");
    expect((await api("GET", "/api/devices")).body.devices[0].push).toBe(false);
    expect((await api("POST", "/api/devices/test", {})).body.results[0]).toMatchObject({ ok: false });
  });

  test("no phone, no share; too many wrong codes cancel every open pairing", async () => {
    expect((await api("DELETE", `/api/devices/${first.finished.body.deviceId}`)).status).toBe(200);
    const id = await filled({ username: "u", password: "p" });
    expect((await api("POST", `/api/requests/${id}/phone`, {})).body.code).toBe("no_phone");

    const open = (await api("POST", "/api/pairings", {})).body;
    // From many addresses, so the per-IP rate limit doesn't stop them first.
    for (let i = 0; i < 10; i++) {
      const r = await phone("POST", "pair/begin", { code: "ZZZZ-ZZZZ" }, { "CF-Connecting-IP": `203.0.113.${i + 1}` });
      expect(r.status).toBe(404);
    }
    expect((await api("GET", `/api/pairings/${open.pairing.id}`)).body.pairing.status).toBe("expired");
    expect((await phone("POST", "pair/begin", { code: open.code })).status).toBe(404);
  });
});
