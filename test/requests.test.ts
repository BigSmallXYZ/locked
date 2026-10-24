import { beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sealFillEnvelope } from "../src/crypto.ts";
import { hasEncryptedData } from "../src/db.ts";
import {
  approvePageData,
  createRequest,
  decideApproval,
  fillPageData,
  getApproval,
  getRequest,
  LockedError,
  normalizeSite,
  redeemApproval,
  redeemUseToken,
  requestUse,
  reveal,
  revoke,
  submitFill,
  sweep,
  type Ctx,
} from "../src/requests.ts";
import { openContext } from "../src/server/index.ts";

let ctx: Ctx;
let clock = 1_700_000_000_000;

beforeEach(async () => {
  const dir = mkdtempSync(join(tmpdir(), "locked-req-"));
  ({ ctx } = await openContext({ dbPath: join(dir, "t.db"), keyPath: join(dir, "k"), keystore: "file", publicUrl: "https://locked.test" }));
  clock = 1_700_000_000_000;
  ctx.now = () => clock;
});

const tokenOf = (url: string) => url.split("/").pop()!;

async function fill(url: string, values: Record<string, string>, retention: "once" | "1h" | "24h" | "forever" = "1h") {
  const token = tokenOf(url);
  const data = fillPageData(ctx, token);
  const envelope = await sealFillEnvelope(data.publicKey!, { values }, data.id!);
  return submitFill(ctx, token, { action: "submit", envelope, retention });
}

async function rejects(p: Promise<unknown> | (() => unknown), code: string) {
  try {
    await (typeof p === "function" ? p() : p);
  } catch (e) {
    expect(e).toBeInstanceOf(LockedError);
    expect((e as LockedError).code).toBe(code);
    return;
  }
  throw new Error(`expected LockedError ${code}`);
}

const login = { label: "GitHub login", site: "github.com", fields: [{ name: "username" }, { name: "password" }] };

describe("requests", () => {
  test("site normalization", () => {
    expect(normalizeSite("github.com")).toBe("https://github.com");
    expect(normalizeSite("http://127.0.0.1:7420/login?x=1")).toBe("http://127.0.0.1:7420");
    expect(() => normalizeSite("javascript:alert(1)")).toThrow();
  });

  test("create → open → fill → reveal", async () => {
    const r = await createRequest(ctx, { ...login, reason: "push the repo" });
    expect(r.url).toStartWith("https://locked.test/r/");
    expect(r.site).toBe("https://github.com");
    expect(getRequest(ctx, r.id).status).toBe("pending");

    const page = fillPageData(ctx, tokenOf(r.url));
    expect(page.state).toBe("open");
    expect(page.firstTimeSite).toBe(true);
    expect(page.fields!.map((f) => f.type)).toEqual(["username", "password"]);
    expect(getRequest(ctx, r.id).openedAt).toBe(clock);

    const envelope = await sealFillEnvelope(page.publicKey!, { values: { username: "octo", password: "hunter2-test" } }, r.id);
    await submitFill(ctx, tokenOf(r.url), { action: "submit", envelope, retention: "1h" });
    expect(getRequest(ctx, r.id).status).toBe("filled");
    expect(hasEncryptedData(ctx.db)).toBe(true);
    expect((await reveal(ctx, r.id)).values).toEqual({ username: "octo", password: "hunter2-test" });
    expect((await reveal(ctx, r.id, ["password"])).values).toEqual({ password: "hunter2-test" });

    // single-use link, and the next request for this site is no longer "first time"
    expect(fillPageData(ctx, tokenOf(r.url)).state).toBe("filled");
    await rejects(submitFill(ctx, tokenOf(r.url), { action: "submit", envelope, retention: "1h" }), "filled"); // replay
    const r2 = await createRequest(ctx, login);
    expect(fillPageData(ctx, tokenOf(r2.url)).firstTimeSite).toBe(false);
  });

  test("the stored row never holds plaintext", async () => {
    const r = await createRequest(ctx, login);
    await fill(r.url, { username: "octo", password: "plaintext-canary-123" });
    const row = ctx.db.query("SELECT * FROM requests WHERE id = ?").get(r.id) as Record<string, unknown>;
    const dump = JSON.stringify(row, (_k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString("latin1") : v));
    expect(dump).not.toContain("plaintext-canary-123");
    expect(row.fill_private_key).toBeNull();
  });

  test("required fields and tampered envelopes are rejected", async () => {
    const r = await createRequest(ctx, login);
    await rejects(fill(r.url, { username: "octo" }), "bad_value");
    const token = tokenOf(r.url);
    const data = fillPageData(ctx, token);
    const envelope = await sealFillEnvelope(data.publicKey!, { values: { username: "a", password: "b" } }, "lk_other");
    await rejects(submitFill(ctx, token, { action: "submit", envelope, retention: "1h" }), "bad_envelope");
    expect(getRequest(ctx, r.id).status).toBe("pending");
  });

  test("decline", async () => {
    const r = await createRequest(ctx, login);
    await submitFill(ctx, tokenOf(r.url), { action: "decline", note: "not now" });
    const s = getRequest(ctx, r.id);
    expect(s.status).toBe("declined");
    expect(s.declineNote).toBe("not now");
  });

  test("links expire", async () => {
    const r = await createRequest(ctx, { ...login, ttlMs: 5 * 60_000 });
    clock += 5 * 60_000 + 1;
    expect(getRequest(ctx, r.id).status).toBe("expired");
    expect(fillPageData(ctx, tokenOf(r.url)).state).toBe("expired");
    sweep(ctx);
    const row = ctx.db.query("SELECT status, fill_private_key FROM requests WHERE id = ?").get(r.id) as any;
    expect(row.status).toBe("expired");
    expect(row.fill_private_key).toBeNull();
  });

  test("retention: 1h wipes after an hour, once wipes 5 min after first use", async () => {
    const a = await createRequest(ctx, login);
    await fill(a.url, { username: "u", password: "p" }, "1h");
    clock += 60 * 60_000 + 1;
    sweep(ctx);
    expect(getRequest(ctx, a.id).status).toBe("expired");
    await rejects(reveal(ctx, a.id), "not_expired");

    const b = await createRequest(ctx, login);
    await fill(b.url, { username: "u", password: "p" }, "once");
    await reveal(ctx, b.id, ["username"]);
    clock += 4 * 60_000;
    await reveal(ctx, b.id, ["password"]); // second step of a two-page login still works
    clock += 60_000 + 1;
    await rejects(reveal(ctx, b.id), "not_expired");
  });

  test("inject: one-time token bound to the site's origin", async () => {
    const r = await createRequest(ctx, login);
    await fill(r.url, { username: "octo", password: "pw-test" });
    await rejects(requestUse(ctx, r.id, { via: "inject", origin: "https://evil.example" }), "origin_mismatch");

    const use = await requestUse(ctx, r.id, { via: "inject" });
    expect(use.kind).toBe("token");
    if (use.kind !== "token") return;
    expect(use.origin).toBe("https://github.com");

    const ok = await redeemUseToken(ctx, use.token, "https://github.com");
    expect(ok.status).toBe(200);
    expect(ok.body.ok && ok.body.fields.map((f) => [f.name, f.value])).toEqual([
      ["username", "octo"],
      ["password", "pw-test"],
    ]);
    expect((await redeemUseToken(ctx, use.token, "https://github.com")).status).toBe(410);

    // wrong origin burns the token
    const bad = await requestUse(ctx, r.id, { via: "inject", only: ["password"] });
    if (bad.kind !== "token") throw new Error();
    expect((await redeemUseToken(ctx, bad.token, "https://evil.example")).status).toBe(403);
    expect((await redeemUseToken(ctx, bad.token, "https://github.com")).status).toBe(410);

    // tokens live 60 s
    const late = await requestUse(ctx, r.id, { via: "inject", only: ["password"] });
    if (late.kind !== "token") throw new Error();
    clock += 61_000;
    expect((await redeemUseToken(ctx, late.token, "https://github.com")).body).toEqual({ ok: false, error: "expired" });
    expect((await redeemUseToken(ctx, "nope-nope-nope-nope-nope", "https://github.com")).status).toBe(404);
  });

  test("inject without a site needs --origin", async () => {
    const r = await createRequest(ctx, { label: "API key", fields: [{ name: "key", type: "apikey" }] });
    await fill(r.url, { key: "sk-test" });
    await rejects(requestUse(ctx, r.id, { via: "inject" }), "no_origin");
    const use = await requestUse(ctx, r.id, { via: "inject", origin: "http://127.0.0.1:7420" });
    expect(use.kind === "token" && use.origin).toBe("http://127.0.0.1:7420");
  });

  test("sealed: no reveal, every use needs approval", async () => {
    const r = await createRequest(ctx, { ...login, level: "sealed" });
    await fill(r.url, { username: "octo", password: "sealed-pw" });
    await rejects(reveal(ctx, r.id), "sealed");

    const use = await requestUse(ctx, r.id, { via: "copy", only: ["password"], purpose: "sign in" });
    expect(use.kind).toBe("approval");
    if (use.kind !== "approval") return;
    expect(use.approvalUrl).toStartWith("https://locked.test/a/");
    await rejects(redeemApproval(ctx, use.approvalId), "approval_pending");

    const token = tokenOf(use.approvalUrl);
    const page = approvePageData(ctx, token);
    expect(page).toMatchObject({ state: "open", label: "GitHub login", via: "copy", fields: ["password"], purpose: "sign in" });
    decideApproval(ctx, token, "approve");
    expect(getApproval(ctx, use.approvalId).status).toBe("approved");
    await rejects(redeemApproval(ctx, use.approvalId, "exec"), "bad_via");
    const got = await redeemApproval(ctx, use.approvalId, "copy");
    expect(got).toEqual({ kind: "values", values: { password: "sealed-pw" }, fields: ["password"] });
    await rejects(redeemApproval(ctx, use.approvalId), "approval_redeemed");
    expect(approvePageData(ctx, token).state).toBe("used");

    // a second use asks again; deny sticks
    const again = await requestUse(ctx, r.id, { via: "inject" });
    if (again.kind !== "approval") throw new Error("expected approval");
    decideApproval(ctx, tokenOf(again.approvalUrl), "deny");
    await rejects(redeemApproval(ctx, again.approvalId), "approval_denied");
    expect(() => decideApproval(ctx, tokenOf(again.approvalUrl), "approve")).toThrow();

    // approved inject hands out a site-bound token
    const third = await requestUse(ctx, r.id, { via: "inject" });
    if (third.kind !== "approval") throw new Error();
    decideApproval(ctx, tokenOf(third.approvalUrl), "approve");
    const t = await redeemApproval(ctx, third.approvalId);
    expect(t.kind === "token" && t.origin).toBe("https://github.com");
  });

  test("approvals expire after 10 minutes", async () => {
    const r = await createRequest(ctx, { ...login, level: "sealed" });
    await fill(r.url, { username: "u", password: "p" });
    const use = await requestUse(ctx, r.id, { via: "exec" });
    if (use.kind !== "approval") throw new Error();
    clock += 10 * 60_000 + 1;
    expect(getApproval(ctx, use.approvalId).status).toBe("expired");
    expect(() => decideApproval(ctx, tokenOf(use.approvalUrl), "approve")).toThrow();
  });

  test("revoke wipes the secret and kills tokens", async () => {
    const r = await createRequest(ctx, login);
    await fill(r.url, { username: "u", password: "p" }, "forever");
    const use = await requestUse(ctx, r.id, { via: "inject" });
    if (use.kind !== "token") throw new Error();
    revoke(ctx, r.id);
    expect(getRequest(ctx, r.id).status).toBe("revoked");
    expect((await redeemUseToken(ctx, use.token, "https://github.com")).status).toBe(404);
    await rejects(reveal(ctx, r.id), "not_revoked");
  });

  test("validation", async () => {
    await rejects(createRequest(ctx, { label: "", fields: [{ name: "a" }] }), "bad_label");
    await rejects(createRequest(ctx, { label: "x", fields: [] }), "bad_fields");
    await rejects(createRequest(ctx, { label: "x", fields: [{ name: "a" }, { name: "a" }] }), "bad_fields");
    await rejects(createRequest(ctx, { label: "x", fields: [{ name: "a", type: "weird" as any }] }), "bad_fields");
    const r = await createRequest(ctx, { label: "x", fields: [{ name: "otp" }, { name: "recovery_code", required: false }] });
    expect(r.fields).toEqual([
      { name: "otp", type: "otp", label: "One-time code", required: true },
      { name: "recovery_code", type: "text", label: "Recovery code", required: false },
    ]);
  });
});
