import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sealFillEnvelope } from "../src/crypto.ts";
import { startServers, type Running } from "../src/server/index.ts";

let s: Running;
let pub: string;
let agent: string;
const token = "test-agent-token-0123456789";
const auth = { Authorization: `Bearer ${token}` };

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "locked-srv-"));
  s = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(dir, "t.db"), keyPath: join(dir, "k"), keystore: "file", token, native: null });
  pub = `http://127.0.0.1:${s.publicServer.port}`;
  agent = `http://127.0.0.1:${s.agentServer.port}`;
});
afterAll(() => s.stop());

async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(agent + path, { method, headers: { ...auth, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: (await res.json()) as any };
}

function dataFrom(html: string) {
  const m = html.match(/<script type="application\/json" id="locked-data">(.*?)<\/script>/s);
  return JSON.parse(m![1]!);
}

async function createAndFill(values: Record<string, string>, extra: Record<string, unknown> = {}) {
  const created = (await api("POST", "/api/requests", { label: "Test login", site: "http://127.0.0.1:7420", fields: [{ name: "username" }, { name: "password" }], ...extra })).body;
  const html = await (await fetch(created.url)).text();
  const data = dataFrom(html);
  const envelope = await sealFillEnvelope(data.publicKey, { values }, data.id);
  const res = await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "submit", envelope, retention: "1h" }) });
  return { created, res, body: (await res.json()) as any };
}

describe("public listener", () => {
  test("has no agent API", async () => {
    for (const path of ["/api/requests", "/api/health", "/", "/r/short", "/assets/../src/config.ts"]) {
      const res = await fetch(pub + path);
      expect(res.status).toBe(404);
    }
    expect(await (await fetch(pub + "/healthz")).text()).toBe("ok");
  });

  test("fill page: headers, data, single use, ciphertext only", async () => {
    const created = (await api("POST", "/api/requests", { label: "Test login", site: "http://127.0.0.1:7420", fields: [{ name: "username" }, { name: "password" }] })).body;
    expect(created.url).toStartWith(pub + "/r/");
    const res = await fetch(created.url);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(res.headers.get("cache-control")).toBe("no-store");
    const data = dataFrom(await res.text());
    expect(data).toMatchObject({ state: "open", label: "Test login", site: "http://127.0.0.1:7420" });

    const envelope = await sealFillEnvelope(data.publicKey, { values: { username: "u", password: "wire-canary-pw" } }, data.id);
    const payload = JSON.stringify({ action: "submit", envelope, retention: "1h" });
    expect(payload).not.toContain("wire-canary-pw");

    const cross = await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://evil.example" }, body: payload });
    expect(cross.status).toBe(403);
    const form = await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: payload });
    expect(form.status).toBe(403);

    const ok = await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: payload });
    expect(await ok.json()).toEqual({ ok: true, state: "filled" });
    const again = await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: payload });
    expect(again.status).toBe(409);
    expect(dataFrom(await (await fetch(created.url)).text()).state).toBe("filled");
  });

  test("autofill payload: CORS-bound, one use", async () => {
    const { created } = await createAndFill({ username: "octo", password: "pw-cors" });
    const use = (await api("POST", `/api/requests/${created.id}/use`, { via: "inject" })).body;
    expect(use.kind).toBe("token");
    const res = await fetch(`${pub}/u/${use.token}`, { headers: { Origin: "http://127.0.0.1:7420" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://127.0.0.1:7420");
    expect(((await res.json()) as any).fields.map((f: any) => f.value)).toEqual(["octo", "pw-cors"]);
    expect((await fetch(`${pub}/u/${use.token}`, { headers: { Origin: "http://127.0.0.1:7420" } })).status).toBe(410);

    const use2 = (await api("POST", `/api/requests/${created.id}/use`, { via: "inject" })).body;
    const evil = await fetch(`${pub}/u/${use2.token}`, { headers: { Origin: "https://evil.example" } });
    expect(evil.status).toBe(403);
    expect(await evil.json()).toEqual({ ok: false, error: "origin" });
  });

  test("CSP hop: page, same-site POST, bound to the return URL's origin", async () => {
    const hop = await fetch(`${pub}/hop`);
    expect(hop.status).toBe(200);
    expect(hop.headers.get("content-security-policy")).toContain("connect-src 'self'");
    expect(await hop.text()).toContain("/assets/hop.js");
    expect((await fetch(`${pub}/assets/hop.js`)).status).toBe(200);

    const { created } = await createAndFill({ username: "octo", password: "pw-hop" });
    const post = (token: string, back: string, extra: Record<string, string> = {}) =>
      fetch(`${pub}/u/${token}/hop`, { method: "POST", headers: { "Content-Type": "application/json", ...extra }, body: JSON.stringify({ return: back }) });

    const use = (await api("POST", `/api/requests/${created.id}/use`, { via: "inject" })).body;
    expect((await post(use.token, "http://127.0.0.1:7420/csp", { Origin: "https://evil.example" })).status).toBe(403);
    const ok = await post(use.token, "http://127.0.0.1:7420/csp?x=1#old");
    expect(ok.status).toBe(200);
    expect(ok.headers.get("access-control-allow-origin")).toBeNull();
    expect(((await ok.json()) as any).fields.map((f: any) => f.value)).toEqual(["octo", "pw-hop"]);
    expect((await post(use.token, "http://127.0.0.1:7420/csp")).status).toBe(410);

    for (const back of ["https://evil.example/login", "javascript:alert(1)", "not a url"]) {
      const t = (await api("POST", `/api/requests/${created.id}/use`, { via: "inject" })).body.token;
      const res = await post(t, back);
      expect(res.status).toBe(403);
      expect(await res.json()).toMatchObject({ ok: false, error: "origin" });
      expect((await post(t, "http://127.0.0.1:7420/csp")).status).toBe(410);
    }
  });
});

describe("agent listener", () => {
  test("needs the bearer token, rejects browsers", async () => {
    expect((await fetch(agent + "/api/requests")).status).toBe(401);
    expect((await fetch(agent + "/api/requests", { headers: { Authorization: "Bearer wrong-token-wrong-token" } })).status).toBe(401);
    expect((await fetch(agent + "/api/requests", { headers: { ...auth, Origin: "http://127.0.0.1:7420" } })).status).toBe(403);
    expect((await api("GET", "/api/health")).body).toMatchObject({ ok: true, publicUrl: pub });
  });

  test("wait wakes up as soon as the form is submitted", async () => {
    const created = (await api("POST", "/api/requests", { label: "Wait test", fields: [{ name: "password" }] })).body;
    const pending = await api("GET", `/api/requests/${created.id}/wait?timeout=0`);
    expect(pending.body).toMatchObject({ done: false, request: { status: "pending" } });

    const started = Date.now();
    const waiting = api("GET", `/api/requests/${created.id}/wait?timeout=20`);
    await Bun.sleep(150);
    const data = dataFrom(await (await fetch(created.url)).text());
    const envelope = await sealFillEnvelope(data.publicKey, { values: { password: "p" } }, data.id);
    await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "submit", envelope, retention: "1h" }) });
    const done = await waiting;
    expect(done.body).toMatchObject({ done: true, request: { status: "filled" } });
    expect(Date.now() - started).toBeLessThan(3000);
  });

  test("sealed: reveal refused, approval page works end to end", async () => {
    const { created } = await createAndFill({ username: "u", password: "sealed-http" }, { level: "sealed" });
    expect((await api("POST", `/api/requests/${created.id}/reveal`, {})).status).toBe(403);
    const use = (await api("POST", `/api/requests/${created.id}/use`, { via: "exec", purpose: "deploy" })).body;
    expect(use.kind).toBe("approval");
    expect(use.approvalUrl).toStartWith(pub + "/a/");
    const page = dataFrom(await (await fetch(use.approvalUrl)).text());
    expect(page).toMatchObject({ state: "open", via: "exec", purpose: "deploy" });
    const decided = await fetch(use.approvalUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision: "approve" }) });
    expect(await decided.json()).toEqual({ ok: true, state: "approved" });
    const waited = (await api("GET", `/api/approvals/${use.approvalId}/wait?timeout=1`)).body;
    expect(waited).toMatchObject({ done: true, approval: { status: "approved" } });
    const redeemed = (await api("POST", `/api/approvals/${use.approvalId}/redeem`, { via: "exec" })).body;
    expect(redeemed.values).toEqual({ username: "u", password: "sealed-http" });
  });

  test("audit trail never includes values", async () => {
    const { created } = await createAndFill({ username: "audit-user", password: "audit-canary-pw" });
    await api("POST", `/api/requests/${created.id}/reveal`, {});
    const events = (await api("GET", `/api/audit?request=${created.id}`)).body.events;
    expect(events.map((e: any) => e.event)).toEqual(["used", "filled", "opened", "created"]);
    expect(JSON.stringify(events)).not.toContain("audit-canary-pw");
  });
});
