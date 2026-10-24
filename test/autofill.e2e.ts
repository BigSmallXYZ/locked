// End-to-end: run the real snippet in Chromium against the fixture pages and a mock Locked,
// plus the real Locked servers (port 0) for the CSP hop through /hop.
//   bun test ./test/autofill.e2e.ts
// Needs Playwright plus a Chromium it can launch (its own, or an installed Google Chrome).
// Playwright is not a project dependency; this looks for, in order: `playwright`,
// `playwright-core`, $LOCKED_PLAYWRIGHT (path to either package), then a copy in Bun's
// install cache. Without one the suite is skipped with the reason.

import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { sealFillEnvelope } from "../src/crypto.ts";
import { buildSnippet } from "../src/inject.ts";
import type { AutofillResult, Field } from "../src/model.ts";
import { createRequest, fillPageData, requestUse, submitFill } from "../src/requests.ts";
import { startServers } from "../src/server/index.ts";
import { startFixtureServer } from "./fixtures/serve.ts";

setDefaultTimeout(30_000);

// Obviously fake values. None may ever show up in a result.
const FAKE = {
  username: "test-user", // 9
  password: "fake-pass-123", // 13
  email: "fake.user@example.test", // 22
  code: "246813",
  apikey: "lk_test_fake_0000000000000000000000", // 35
  webhook: "https://hooks.example.test/fake", // 31
};

function playwrightCandidates(): string[] {
  const out = ["playwright", "playwright-core"];
  if (process.env.LOCKED_PLAYWRIGHT) out.push(process.env.LOCKED_PLAYWRIGHT);
  const cache = join(homedir(), ".bun", "install", "cache");
  if (existsSync(cache))
    for (const dir of readdirSync(cache).filter((d) => d.startsWith("playwright-core@")).sort().reverse()) out.push(join(cache, dir, "index.js"));
  return out;
}

async function openBrowser(): Promise<{ browser?: any; why?: string }> {
  let chromium: any;
  for (const spec of playwrightCandidates()) {
    try {
      ({ chromium } = await import(spec));
      if (chromium) break;
    } catch {
      // next
    }
  }
  if (!chromium) return { why: "Playwright not found (bun add -d playwright, or set LOCKED_PLAYWRIGHT)" };
  const errors: string[] = [];
  for (const opts of [{}, { channel: "chrome" }]) {
    try {
      return { browser: await chromium.launch({ headless: true, ...opts }) };
    } catch (e) {
      errors.push(String((e as Error).message).split("\n")[0]!);
    }
  }
  return { why: `no Chromium Playwright can launch; run \`bunx playwright install chromium\` or install Google Chrome (${errors.join("; ")})` };
}

const { browser, why } = await openBrowser();

if (!browser) {
  console.warn(`autofill e2e skipped: ${why}`);
  test.skip(`autofill e2e (skipped: ${why})`, () => {});
} else {
  let fixtures: ReturnType<typeof startFixtureServer>;
  try {
    fixtures = startFixtureServer();
  } catch {
    fixtures = startFixtureServer(0); // the usual port is taken, e.g. by `bun run fixtures`
  }
  const SITE = `http://127.0.0.1:${fixtures.port}`;

  // Mock Locked: GET /u/:token is one use and CORS-bound to the token's origin.
  type Rec = { origin: string; fields: Array<Field & { value: string }>; used: boolean };
  const tokens = new Map<string, Rec>();
  let serial = 0;
  const autofillJs = readFileSync(join(import.meta.dir, "..", "web", "autofill.js"), "utf8");
  const locked = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(req) {
      const url = new URL(req.url);
      const from = req.headers.get("origin");
      if (url.pathname === "/inject.js") return new Response(autofillJs, { headers: { "content-type": "text/javascript" } });
      const reply = (status: number, body: unknown, allow = from) =>
        Response.json(body, { status, headers: { "cache-control": "no-store", ...(allow ? { "access-control-allow-origin": allow, vary: "Origin" } : {}) } });
      const m = url.pathname.match(/^\/u\/([^/]+)$/);
      const rec = m ? tokens.get(decodeURIComponent(m[1]!)) : undefined;
      if (!rec) return reply(404, { ok: false, error: "missing" });
      if (rec.used) return reply(410, { ok: false, error: "used" });
      rec.used = true; // burned whatever happens next
      if (from !== rec.origin) return reply(403, { ok: false, error: "origin" });
      return reply(200, { ok: true, origin: rec.origin, fields: rec.fields }, rec.origin);
    },
  });
  const LOCKED = `http://127.0.0.1:${locked.port}`;

  const issue = (fields: Array<[name: string, type: Field["type"], value: string, label?: string]>, origin = SITE) => {
    const token = `tok_${++serial}_${crypto.randomUUID().slice(0, 8)}`;
    tokens.set(token, { origin, used: false, fields: fields.map(([name, type, value, label]) => ({ name, type, value, label: label ?? name, required: true })) });
    return token;
  };
  const login = () => issue([["username", "username", FAKE.username, "Username"], ["password", "password", FAKE.password, "Password"]]);

  const context = await browser.newContext();
  const open = async (path: string) => {
    const page = await context.newPage();
    await page.goto(SITE + path);
    return page;
  };
  const clean = (result: unknown) => {
    const json = JSON.stringify(result);
    for (const value of Object.values(FAKE)) expect(json).not.toContain(value);
  };
  const run = async (page: any, snippet: string): Promise<AutofillResult> => {
    const result = await page.evaluate(snippet);
    clean(result);
    return result;
  };
  const fill = (page: any, token: string, extra: { map?: Record<string, string>; submit?: boolean } = {}) =>
    run(page, buildSnippet({ base: LOCKED, token, ...extra }));
  const text = (page: any, sel: string) => page.locator(sel).first().textContent();

  // The real Locked, for the CSP hop (its /hop page and POST /u/:token/hop).
  const realDir = mkdtempSync(join(tmpdir(), "locked-e2e-"));
  const real = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(realDir, "t.db"), keyPath: join(realDir, "k"), keystore: "file", token: "e2e-agent-token-0123456789" });
  const PUB = `http://127.0.0.1:${real.publicServer.port}`;
  const hasHopPage = existsSync(join(import.meta.dir, "..", "web", "hop.html"));
  /** A filled login request bound to the fixture site; returns its id. */
  const realLogin = async () => {
    const { id, url } = await createRequest(real.ctx, { label: "Fixture login", site: SITE, fields: [{ name: "username" }, { name: "password" }] });
    const fillToken = url.split("/").pop()!;
    const data = fillPageData(real.ctx, fillToken);
    const envelope = await sealFillEnvelope(data.publicKey!, { values: { username: FAKE.username, password: FAKE.password } }, data.id!);
    await submitFill(real.ctx, fillToken, { action: "submit", envelope, retention: "1h" });
    return id;
  };
  const mint = async (id: string) => {
    const use = await requestUse(real.ctx, id, { via: "inject", origin: SITE });
    if (use.kind !== "token") throw new Error(`expected an inject token, got ${use.kind}`);
    return use.token;
  };
  /** Run a snippet that hops, and wait until the page is back with `hash` (a prefix). */
  const hop = async (page: any, snippet: string, hash: string) => {
    const seen: string[] = [];
    const onNav = (frame: any) => frame === page.mainFrame() && seen.push(frame.url());
    page.on("framenavigated", onNav);
    // The navigation may swallow the return value; when it arrives it must say "hop".
    const first = await page.evaluate(snippet).catch(() => null);
    if (first) {
      clean(first);
      expect(first).toMatchObject({ ok: false, reason: "hop" });
    }
    await page.waitForURL((u: URL) => u.pathname === "/csp" && u.hash.startsWith(hash), { timeout: 15_000 });
    await page.waitForSelector("#pw");
    page.off("framenavigated", onNav);
    return seen;
  };
  const hopState = (page: any) => page.evaluate(`({ hash: location.hash, saved: sessionStorage.getItem("locked:hop") })`);

  afterAll(async () => {
    await browser.close();
    fixtures.stop(true);
    locked.stop(true);
    real.stop();
  });

  describe("autofill in Chromium", () => {
    test("/plain: fills username + password, submits, leaves decoys alone, adds no globals", async () => {
      const page = await open("/plain");
      const before: string[] = await page.evaluate("Object.getOwnPropertyNames(window)");
      const result = await fill(page, login(), { submit: true });
      expect(result).toEqual({ ok: true, filled: ["username", "password"], missing: [], origin: SITE, submitted: true });
      expect(await text(page, "#result")).toBe("username: 9 chars, password: 13 chars");
      const decoys = await page.evaluate(`[...document.querySelectorAll("input[name=website],input[name=q],input[name=newsletter]")].map(i => i.value.length)`);
      expect(decoys).toEqual([0, 0, 0]);
      const after: string[] = await page.evaluate("Object.getOwnPropertyNames(window)");
      expect(after.filter((k) => !before.includes(k))).toEqual([]);
    });

    test("one use: a second run with the same token gets reason 'used'", async () => {
      const page = await open("/plain");
      const token = login();
      expect((await fill(page, token)).ok).toBe(true);
      expect(await fill(page, token)).toMatchObject({ ok: false, reason: "used", filled: [] });
    });

    test("a token bound to another site gets reason 'origin' and fills nothing", async () => {
      const page = await open("/plain");
      const token = issue([["password", "password", FAKE.password]], "https://elsewhere.example.test");
      expect(await fill(page, token)).toMatchObject({ ok: false, reason: "origin", filled: [] });
      expect(await page.inputValue("#pw")).toBe("");
    });

    test("an unknown token gets reason 'missing'", async () => {
      const page = await open("/plain");
      expect(await fill(page, "tok_nope")).toMatchObject({ ok: false, reason: "missing" });
    });

    test("a page with nothing to fill does not spend the token", async () => {
      const page = await open("/");
      const token = login();
      expect(await fill(page, token)).toMatchObject({ ok: false, reason: "no-inputs" });
      expect(tokens.get(token)!.used).toBe(false);
    });


    test("/two-step: email with one token, password with a second", async () => {
      const page = await open("/two-step");
      const fields: Array<[string, Field["type"], string, string]> = [
        ["email", "email", FAKE.email, "Email"],
        ["password", "password", FAKE.password, "Password"],
      ];
      const one = await fill(page, issue(fields));
      expect(one).toMatchObject({ ok: true, filled: ["email"], missing: ["password"] });
      expect(one.message).toBeTruthy();
      await page.click("#next");
      await page.waitForSelector("input[type=password]");
      const two = await fill(page, issue(fields), { submit: true });
      expect(two).toMatchObject({ ok: true, filled: ["password"], missing: ["email"], submitted: true });
      expect(await text(page, "#result")).toBe("email: 22 chars, password: 13 chars");
    });

    test("/react: controlled inputs see the values and the submit button enables", async () => {
      const page = await open("/react");
      const ready = await page
        .waitForSelector("#root[data-ready='1']", { timeout: 15_000 })
        .then(() => true)
        .catch(() => false);
      if (!ready) {
        console.warn("skipping /react: React 18.3.1 did not load from unpkg (offline?)");
        return;
      }
      expect(await page.isDisabled("#submit")).toBe(true);
      const result = await fill(page, login());
      expect(result).toMatchObject({ ok: true, filled: ["username", "password"], missing: [] });
      expect(await text(page, "#state")).toBe("React state: username 9 chars, password 13 chars");
      expect(await page.isDisabled("#submit")).toBe(false);
      await page.click("#submit");
      expect(await text(page, "#result")).toBe("username: 9 chars, password: 13 chars");
    });

    test("/react with submit: waits for the re-render, then clicks the enabled button", async () => {
      const page = await open("/react");
      if (!(await page.waitForSelector("#root[data-ready='1']", { timeout: 15_000 }).then(() => true).catch(() => false))) return;
      expect(await fill(page, login(), { submit: true })).toMatchObject({ ok: true, submitted: true });
      expect(await text(page, "#result")).toBe("username: 9 chars, password: 13 chars");
    });

    test("/otp: six one-character boxes get one digit each", async () => {
      const page = await open("/otp");
      const result = await fill(page, issue([["code", "otp", FAKE.code, "Verification code"]]), { submit: true });
      expect(result).toMatchObject({ ok: true, filled: ["code"], missing: [], submitted: true });
      expect(await page.evaluate(`[...document.querySelectorAll(".otp input")].map(i => i.value).join("")`)).toBe(FAKE.code);
      expect(await text(page, "#result")).toBe("code: 6 chars");
    });

    test("/shadow: fills inside an open shadow root", async () => {
      const page = await open("/shadow");
      expect(await fill(page, login(), { submit: true })).toMatchObject({ ok: true, filled: ["username", "password"], submitted: true });
      expect(await text(page, "#result")).toBe("username: 9 chars, password: 13 chars");
    });

    test("/iframe: fills inside a same-origin iframe", async () => {
      const page = await open("/iframe");
      const frame = page.frameLocator("#frame");
      await frame.locator("#pw").waitFor();
      expect(await fill(page, login(), { submit: true })).toMatchObject({ ok: true, filled: ["username", "password"], submitted: true });
      expect(await frame.locator("#result").textContent()).toBe("username: 9 chars, password: 13 chars");
    });

    test("/apikey: matches other field types by name and label", async () => {
      const page = await open("/apikey");
      const token = issue([
        ["api_key", "apikey", FAKE.apikey, "API key"],
        ["webhook", "url", FAKE.webhook, "Webhook URL"],
      ]);
      expect(await fill(page, token, { submit: true })).toMatchObject({ ok: true, filled: ["api_key", "webhook"], missing: [], submitted: true });
      expect(await text(page, "#result")).toBe("api key: 35 chars, webhook: 31 chars");
      expect(await page.inputValue("#notes")).toBe("");
    });

    test("/signup: new-password fills the password and its confirm box", async () => {
      const page = await open("/signup");
      const token = issue([
        ["email", "email", FAKE.email, "Email"],
        ["password", "new-password", FAKE.password, "New password"],
      ]);
      expect(await fill(page, token, { submit: true })).toMatchObject({ ok: true, filled: ["email", "password"], missing: [], submitted: true });
      expect(await text(page, "#result")).toBe("email: 22 chars, password: 13 chars, confirm: 13 chars");
      expect(await page.inputValue("#full")).toBe("");
    });

    test("opts.map beats the heuristics", async () => {
      const page = await open("/plain");
      const result = await fill(page, login(), { map: { username: "input[name=newsletter]" } });
      expect(result).toMatchObject({ ok: true, filled: ["username", "password"] });
      expect(await page.evaluate(`document.querySelector("input[name=newsletter]").value.length`)).toBe(9);
      expect(await page.inputValue("#login-id")).toBe("");
    });

    test("script-tag mode fills and dispatches locked:autofill", async () => {
      const page = await open("/plain");
      const token = login();
      const result = await page.evaluate(
        `new Promise((resolve) => {
          document.addEventListener("locked:autofill", (e) => resolve({ detail: e.detail, api: typeof window.Locked?.fill }), { once: true });
          const s = document.createElement("script");
          s.src = ${JSON.stringify(LOCKED + "/inject.js")};
          s.dataset.token = ${JSON.stringify(token)};
          s.setAttribute("data-submit", "");
          document.head.append(s);
        })`,
      );
      expect(result.api).toBe("function");
      expect(result.detail).toMatchObject({ ok: true, filled: ["username", "password"], submitted: true });
      expect(JSON.stringify(result)).not.toContain(FAKE.password);
      expect(await text(page, "#result")).toBe("username: 9 chars, password: 13 chars");
    });

    test.skipIf(!hasHopPage)("/csp hop: through the real Locked's /hop and back, then fills on the next run", async () => {
      const page = await open("/csp");
      const token = await mint(await realLogin());
      const seen = await hop(page, buildSnippet({ base: PUB, token, submit: true }), "#locked=");
      expect(seen.some((u) => u.startsWith(`${PUB}/hop`))).toBe(true);
      const back = page.url();
      for (const value of Object.values(FAKE)) expect(decodeURIComponent(back)).not.toContain(value); // ciphertext only
      expect(JSON.parse((await hopState(page)).saved)).toMatchObject({ submit: true });

      // The same snippet again, minus submit: the saved submit still applies.
      const result = await run(page, buildSnippet({ base: PUB, token }));
      expect(result).toEqual({ ok: true, filled: ["username", "password"], missing: [], origin: SITE, submitted: true });
      expect(await hopState(page)).toEqual({ hash: "", saved: null });
      expect(new URL(page.url()).hash).toBe("");
      expect(await text(page, "#result")).toBe("username: 9 chars, password: 13 chars");
    });

    test.skipIf(!hasHopPage)("/csp hop: a second hop with the same token comes back used", async () => {
      const page = await open("/csp");
      const snippet = buildSnippet({ base: PUB, token: await mint(await realLogin()) });
      await hop(page, snippet, "#locked=");
      expect((await run(page, snippet)).ok).toBe(true);

      await hop(page, snippet, "#locked-error=used");
      expect(await run(page, snippet)).toMatchObject({ ok: false, reason: "used", filled: [] });
      expect(await hopState(page)).toEqual({ hash: "", saved: null });
    });

    test("/csp with hop: false just reports 'csp'", async () => {
      const page = await open("/csp");
      const token = login();
      expect(await run(page, buildSnippet({ base: LOCKED, token, hop: false }))).toMatchObject({ ok: false, reason: "csp" });
      expect(page.url()).toBe(SITE + "/csp");
      expect(tokens.get(token)!.used).toBe(false);
    });
  });
}
