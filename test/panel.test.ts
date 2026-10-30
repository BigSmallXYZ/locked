import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sealFillEnvelope } from "../src/crypto.ts";
import type { Native } from "../src/native.ts";
import { startServers, type Running } from "../src/server/index.ts";

// Stands in for native/LockedPanel.swift: records what the server asked it to show, and answers
// Touch ID with whatever the test sets.
const shown: string[] = [];
const authReasons: string[] = [];
let authAnswer = true;
const fakeNative: Native = {
  async showPanel(url) {
    shown.push(url);
  },
  async deviceAuth(reason) {
    authReasons.push(reason);
    return authAnswer;
  },
};

let s: Running;
let bare: Running;
let pub: string;
let agent: string;
const token = "test-agent-token-0123456789";
const auth = { Authorization: `Bearer ${token}` };

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "locked-panel-"));
  s = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(dir, "t.db"), keyPath: join(dir, "k"), keystore: "file", token, native: fakeNative });
  pub = `http://127.0.0.1:${s.publicServer.port}`;
  agent = `http://127.0.0.1:${s.agentServer.port}`;
  bare = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(dir, "b.db"), keyPath: join(dir, "kb"), keystore: "file", token, native: null });
});
afterAll(() => {
  s.stop();
  bare.stop();
});

async function api(method: string, path: string, body?: unknown, base = agent) {
  const res = await fetch(base + path, { method, headers: { ...auth, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: (await res.json()) as any };
}

/** What the helper app does: no bearer token, just the one-time handle. */
async function helper(method: string, url: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(url, { method, headers: { "Content-Type": "application/json", ...headers }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: (await res.json()) as any };
}

async function filled(values: Record<string, string>, extra: Record<string, unknown> = {}, base = agent) {
  const created = (await api("POST", "/api/requests", { label: "Panel login", site: "https://example.com", fields: [{ name: "username" }, { name: "password" }], ...extra }, base)).body;
  const html = await (await fetch(created.url)).text();
  const data = JSON.parse(html.match(/<script type="application\/json" id="locked-data">(.*?)<\/script>/s)![1]!);
  const envelope = await sealFillEnvelope(data.publicKey, { values }, data.id);
  await fetch(created.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "submit", envelope, retention: "1h" }) });
  return created.id as string;
}

describe("native panel", () => {
  test("shows, hands values to the helper once, reports clicks, then closes", async () => {
    const id = await filled({ username: "octo", password: "panel-canary-pw" });
    expect((await fetch(`${agent}/api/requests/${id}/panel`, { method: "POST" })).status).toBe(401);

    const opened = await api("POST", `/api/requests/${id}/panel`, { purpose: "sign in", timeoutSec: 60 });
    expect(opened.status).toBe(200);
    const panel = opened.body.panel;
    expect(panel).toMatchObject({ requestId: id, status: "launching", fields: ["username", "password"], events: [] });
    expect(JSON.stringify(opened.body)).not.toContain("panel-canary-pw");
    const url = shown.at(-1)!;
    expect(url).toStartWith(`${agent}/api/panel/`);

    // The helper's first call: what to show, never values.
    const info = await helper("GET", url);
    expect(info.body).toMatchObject({ ok: true, label: "Panel login", site: "https://example.com", purpose: "sign in", level: "normal" });
    expect(info.body.fields.map((f: any) => f.name)).toEqual(["username", "password"]);
    expect(info.body.timeoutSec).toBeGreaterThan(50);
    expect(JSON.stringify(info.body)).not.toContain("panel-canary-pw");
    expect((await api("GET", `/api/panels/${panel.id}`)).body.panel.status).toBe("open");

    // Browsers and wrong handles are out.
    expect((await helper("GET", url, undefined, { Origin: "https://evil.example" })).status).toBe(403);
    expect((await helper("GET", `${agent}/api/panel/not-a-real-handle-not-a-real-handle`)).status).toBe(404);

    const waiting = api("GET", `/api/panels/${panel.id}/wait?timeout=10&after=0`);
    const values = await helper("POST", url + "/values", {});
    expect(values.body.values).toEqual({ username: "octo", password: "panel-canary-pw" });
    expect((await helper("POST", url + "/values", {})).status).toBe(409);

    expect((await helper("POST", url + "/event", { event: "typed", field: "nope" })).status).toBe(400);
    expect((await helper("POST", url + "/event", { event: "launch-missiles" })).status).toBe(400);
    await helper("POST", url + "/event", { event: "typed", field: "password" });
    const woke = (await waiting).body.panel;
    expect(woke.events.map((e: any) => [e.event, e.field])).toEqual([["typed", "password"]]);

    const closed = await helper("POST", url + "/event", { event: "closed" });
    expect(closed.body.panel.status).toBe("closed");
    expect((await helper("GET", url)).status).toBe(404); // the handle dies with the panel

    const events = (await api("GET", `/api/audit?request=${id}`)).body.events;
    expect(events.map((e: any) => e.event).slice(0, 4)).toEqual(["panel_closed", "panel_typed", "used", "panel_shown"]);
    expect(JSON.stringify(events)).not.toContain("panel-canary-pw");
  });

  test("sealed: values only after Touch ID, checked by the server", async () => {
    const id = await filled({ username: "u", password: "sealed-panel-pw" }, { level: "sealed", label: "Bank login" });
    const panel = (await api("POST", `/api/requests/${id}/panel`, {})).body.panel;
    const url = shown.at(-1)!;
    expect((await helper("GET", url)).body.level).toBe("sealed");

    authAnswer = false;
    const denied = await helper("POST", url + "/values", {});
    expect(denied.status).toBe(403);
    expect(denied.body.error).toContain("Touch ID");
    authAnswer = true;
    const ok = await helper("POST", url + "/values", {});
    expect(ok.body.values).toEqual({ username: "u", password: "sealed-panel-pw" });
    expect(authReasons.at(-1)).toContain("Bank login");
    await helper("POST", url + "/event", { event: "closed" });
    expect((await api("GET", `/api/panels/${panel.id}`)).body.panel.status).toBe("closed");
  });

  test("sealed get: refused without Touch ID, printed after it", async () => {
    const id = await filled({ username: "u", password: "sealed-get-pw" }, { level: "sealed", label: "Mail login" });
    expect((await api("POST", `/api/requests/${id}/reveal`, {})).status).toBe(403);
    authAnswer = false;
    const denied = await api("POST", `/api/requests/${id}/reveal`, { deviceAuth: true });
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe("not_confirmed");
    authAnswer = true;
    const ok = await api("POST", `/api/requests/${id}/reveal`, { deviceAuth: true, only: ["password"] });
    expect(ok.body.values).toEqual({ password: "sealed-get-pw" });
    expect(authReasons.at(-1)).toContain("Mail login");
    const events = (await api("GET", `/api/audit?request=${id}`)).body.events.map((e: any) => e.event);
    expect(events).toContain("device_confirmed");
  });

  test("a helper that never calls back fails the panel; without macOS there's no panel", async () => {
    const id = await filled({ username: "u", password: "p" });
    const panel = (await api("POST", `/api/requests/${id}/panel`, { only: ["password"] })).body.panel;
    expect(panel.fields).toEqual(["password"]);
    expect((await api("GET", `/api/panels/${panel.id}/wait?timeout=0`)).body.panel.status).toBe("launching");

    const other = `http://127.0.0.1:${bare.agentServer.port}`;
    const id2 = await filled({ username: "u", password: "p" }, {}, other);
    const res = await api("POST", `/api/requests/${id2}/panel`, {}, other);
    expect(res.status).toBe(501);
    expect((await api("POST", `/api/requests/${id2}/reveal`, { deviceAuth: true }, other)).status).toBe(200); // normal: no Touch ID needed
  });

  test("stored list only has usable secrets", async () => {
    const pending = (await api("POST", "/api/requests", { label: "Not filled", fields: [{ name: "password" }] })).body.id;
    const stored = (await api("GET", "/api/requests?stored=1&limit=100")).body.requests;
    expect(stored.length).toBeGreaterThan(0);
    expect(stored.every((r: any) => r.status === "filled")).toBe(true);
    expect(stored.some((r: any) => r.id === pending)).toBe(false);
  });
});
