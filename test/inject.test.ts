import { describe, expect, test } from "bun:test";
import { buildSnippet, fillSource, isSingleExpression } from "../src/inject.ts";

const BASE = "http://127.0.0.1:7410";
const BUDGET = 6500; // bytes
const FAKE_PASSWORD = "fake-pass-123";

// A tiny stand-in for the browser, enough to run the snippet end to end in Bun.
class FakeEvent {
  constructor(public type: string, public init?: unknown) {}
}
class FakeInput {
  tagName = "INPUT";
  localName = "input";
  disabled = false;
  readOnly = false;
  maxLength = -1;
  labels: unknown[] = [];
  form = null;
  events: string[] = [];
  protoSets = 0;
  declare value: string; // defined per instance in the constructor and on the prototype below
  ownerDocument: any;
  constructor(public type: string, public name: string, doc: any, public id = "") {
    this.ownerDocument = doc;
    // What React does: an own `value` property on the element that tracks writes.
    // Writing through it would hide the change from React, so the snippet must not.
    Object.defineProperty(this, "value", {
      configurable: true,
      get: () => (this as any).__v ?? "",
      set: () => {
        throw new Error("wrote through the instance property instead of the prototype setter");
      },
    });
  }
  getAttribute(n: string) {
    return n === "autocomplete" && this.type === "password" ? "current-password" : null;
  }
  getBoundingClientRect() {
    return { width: 200, height: 30, right: 210, bottom: 40 };
  }
  getRootNode() {
    return this.ownerDocument;
  }
  focus() {}
  blur() {}
  dispatchEvent(e: FakeEvent) {
    this.events.push(e.type);
    return true;
  }
}
Object.defineProperty(FakeInput.prototype, "value", {
  get() {
    return (this as any).__v ?? "";
  },
  set(v: string) {
    (this as any).__v = v;
    (this as any).protoSets++;
  },
});

type Reply = { status: number; body?: unknown } | "reject" | "csp";
type PageOpts = {
  inputs?: Array<[type: string, name: string, id?: string]>;
  /** sessionStorage contents. */
  storage?: Record<string, string>;
  hash?: string;
  /** Stand-in for window.crypto (default: Bun's WebCrypto). */
  crypto?: unknown;
};

function fakePage(reply: Reply, opts: PageOpts = {}) {
  const listeners = new Set<(e: { blockedURI: string }) => void>();
  const win = { scrollX: 0, scrollY: 0, Event: FakeEvent };
  const doc: any = {
    defaultView: win,
    addEventListener: (_: string, fn: any) => listeners.add(fn),
    removeEventListener: (_: string, fn: any) => listeners.delete(fn),
    querySelectorAll: (sel: string) => (sel === "*" ? els : els.filter((el) => "#" + el.id === sel)),
    getElementById: () => null,
  };
  const els = (opts.inputs ?? [["password", "pass"]]).map(([t, n, id]) => new FakeInput(t, n, doc, id));
  const stored = new Map(Object.entries(opts.storage ?? {}));
  const sessionStorage = {
    getItem: (k: string) => stored.get(k) ?? null,
    setItem: (k: string, v: string) => void stored.set(k, String(v)),
    removeItem: (k: string) => void stored.delete(k),
  };
  const assigned: string[] = [];
  const replaced: string[] = [];
  const location = {
    origin: "https://app.example.test",
    pathname: "/login",
    search: "?next=%2Fhome",
    hash: opts.hash ?? "",
    get href() {
      return this.origin + this.pathname + this.search + this.hash;
    },
    assign: (url: string) => void assigned.push(url),
  };
  const history = {
    replaceState: (_s: unknown, _t: string, url: string) => {
      replaced.push(url);
      location.hash = "";
    },
  };
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetch = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    if (reply === "reject") throw new TypeError("Failed to fetch");
    if (reply === "csp") {
      setTimeout(() => listeners.forEach((fn) => fn({ blockedURI: url })), 5);
      throw new TypeError("Failed to fetch");
    }
    return new Response(reply.body === undefined ? "<html>oops</html>" : JSON.stringify(reply.body), { status: reply.status, headers: { "content-type": "application/json" } });
  };
  const run = (snippet: string) =>
    new Function("fetch", "document", "location", "window", "setTimeout", "sessionStorage", "history", "crypto", `return ${snippet}`)(
      fetch,
      doc,
      location,
      win,
      setTimeout,
      sessionStorage,
      history,
      opts.crypto ?? crypto,
    );
  return { run, calls, els, listeners, stored, assigned, replaced, location };
}

const payload = (fields: Array<{ name: string; type: string; value: string }>) => ({
  ok: true,
  origin: "https://app.example.test",
  fields: fields.map((f) => ({ label: f.name, required: true, ...f })),
});

/** What Locked's hop page does: AES-GCM-256 under the page's key, iv || ciphertext, base64url. */
async function sealForHop(value: unknown) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(value))));
  return { k: Buffer.from(raw).toString("base64url"), blob: Buffer.concat([iv, ct]).toString("base64url") };
}

describe("buildSnippet", () => {
  const snippet = buildSnippet({ base: BASE, token: "tok_abc" });

  test("is one expression that parses", () => {
    expect(snippet.startsWith("(async()=>{")).toBe(true);
    expect(snippet.endsWith("})()")).toBe(true);
    expect(isSingleExpression(snippet)).toBe(true);
    expect(() => new Function("return " + snippet)).not.toThrow();
  });

  test(`stays under ${BUDGET} bytes`, () => {
    const bytes = Buffer.byteLength(snippet);
    console.log(`snippet: ${bytes} bytes (minified from ${Buffer.byteLength(fillSource())} bytes of source)`);
    expect(bytes).toBeLessThan(BUDGET);
  });

  test("embeds token, base and opts as JSON-safe literals", async () => {
    const token = `a"b'c\\d</script><!--  \${x}\`y`;
    const s = buildSnippet({ base: BASE + "/", token, submit: true, map: { password: 'input[name="pw"]' } });
    expect(isSingleExpression(s)).toBe(true);
    expect(s).not.toContain("</script>");
    expect(s).not.toContain(" ");
    expect(s).not.toContain(" ");
    expect(s).toContain(`"submit":true`);

    const page = fakePage({ status: 410, body: { ok: false, error: "used" } });
    const result = await page.run(s);
    expect(page.calls[0]!.url).toBe(`${BASE}/u/${encodeURIComponent(token)}`); // trailing slash dropped
    expect(result.reason).toBe("used");
  });

  test("asks for the payload without credentials or a referrer", async () => {
    const page = fakePage({ status: 404, body: { ok: false, error: "missing" } });
    await page.run(snippet);
    expect(page.calls[0]!.init).toMatchObject({ credentials: "omit", mode: "cors", cache: "no-store", referrerPolicy: "no-referrer" });
  });

  test("rejects bad arguments", () => {
    expect(() => buildSnippet({ base: "javascript:alert(1)", token: "t" })).toThrow();
    expect(() => buildSnippet({ base: "not a url", token: "t" })).toThrow();
    expect(() => buildSnippet({ base: BASE, token: "" })).toThrow();
    expect(() => buildSnippet({ base: BASE, token: "t", map: { password: 5 as any } })).toThrow();
  });

  test("passes hop: false through, and leaves it out by default", () => {
    expect(buildSnippet({ base: BASE, token: "t", hop: false })).toEndWith(`"t",{"hop":false})})()`);
    expect(buildSnippet({ base: BASE, token: "t", hop: true })).toEndWith(`"t",{})})()`);
  });

  test("caches the extracted source", () => {
    const a = buildSnippet({ base: BASE, token: "one" });
    const b = buildSnippet({ base: BASE, token: "two" });
    expect(a.replace('"one"', '"two"')).toBe(b);
  });
});

describe("snippet behaviour (fake DOM)", () => {
  const snippet = buildSnippet({ base: BASE, token: "tok_abc" });

  test("fills through the prototype setter, fires input+change, never returns the value", async () => {
    const body = {
      ok: true,
      origin: "https://app.example.test",
      fields: [{ name: "password", type: "password", label: "Password", required: true, value: FAKE_PASSWORD }],
    };
    const page = fakePage({ status: 200, body });
    const result = await page.run(snippet);
    expect(result).toEqual({ ok: true, filled: ["password"], missing: [], origin: "https://app.example.test" });
    expect(JSON.stringify(result)).not.toContain(FAKE_PASSWORD);
    const input = page.els[0]!;
    expect(input.value).toBe(FAKE_PASSWORD);
    expect(input.protoSets).toBe(1);
    expect(input.events).toEqual(["input", "change"]);
    expect(body.fields[0]!.value).toBe(FAKE_PASSWORD); // the server's copy; the snippet parsed its own
  });

  test("reports fields it could not place as missing", async () => {
    const page = fakePage({
      status: 200,
      body: {
        ok: true,
        origin: "https://app.example.test",
        fields: [
          { name: "password", type: "password", label: "Password", required: true, value: FAKE_PASSWORD },
          { name: "code", type: "otp", label: "Code", required: false, value: "123456" },
        ],
      },
    });
    const result = await page.run(snippet);
    expect(result.ok).toBe(true);
    expect(result.filled).toEqual(["password"]);
    expect(result.missing).toEqual(["code"]);
    expect(JSON.stringify(result)).not.toContain("123456");
  });

  test("refuses a payload bound to another origin", async () => {
    const page = fakePage({
      status: 200,
      body: { ok: true, origin: "https://other.example.test", fields: [{ name: "password", type: "password", label: "", required: true, value: FAKE_PASSWORD }] },
    });
    const result = await page.run(snippet);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("origin");
    expect(page.els[0]!.value).toBe("");
  });

  test.each([
    [403, "origin"],
    [404, "missing"],
    [410, "used"],
    [410, "expired"],
    [429, "rate"],
  ] as const)("maps HTTP %d {error:%s}", async (status, error) => {
    const page = fakePage({ status, body: { ok: false, error } });
    const result = await page.run(snippet);
    expect(result).toMatchObject({ ok: false, reason: error, filled: [], missing: [], origin: "https://app.example.test" });
  });

  test("falls back to the status code when the body is not JSON", async () => {
    const page = fakePage({ status: 429, body: undefined });
    const result = await page.run(snippet);
    expect(result.reason).toBe("rate");
  });

  test("tells a CSP block from a plain network failure", async () => {
    const csp = fakePage("csp");
    expect((await csp.run(buildSnippet({ base: BASE, token: "tok_abc", hop: false }))).reason).toBe("csp");
    expect(csp.listeners.size).toBe(0); // listener removed
    const net = fakePage("reject");
    expect((await net.run(snippet)).reason).toBe("network");
  });

  test("does not spend the token on a page with no inputs", async () => {
    const page = fakePage({ status: 200, body: { ok: true, fields: [] } }, { inputs: [] });
    const result = await page.run(snippet);
    expect(result.reason).toBe("no-inputs");
    expect(page.calls.length).toBe(0);
  }, 5000);

  test("leaves no globals behind", async () => {
    const before = new Set(Object.getOwnPropertyNames(globalThis));
    const page = fakePage({ status: 410, body: { ok: false, error: "used" } });
    await page.run(snippet);
    const added = Object.getOwnPropertyNames(globalThis).filter((k) => !before.has(k));
    expect(added).toEqual([]);
  });
});

describe("CSP hop", () => {
  const HOP = "locked:hop";
  const snippet = buildSnippet({ base: BASE, token: "tok_abc" });

  test("a CSP-blocked fetch stores a fresh key and navigates through {base}/hop", async () => {
    const page = fakePage("csp");
    const result = await page.run(buildSnippet({ base: BASE + "/", token: "tok_abc", map: { password: "#pw" }, submit: true }));
    expect(result).toMatchObject({ ok: false, reason: "hop", filled: [], missing: [], origin: "https://app.example.test" });
    expect(result.message).toContain("run the same snippet again");
    expect(page.assigned.length).toBe(1);
    const m = page.assigned[0]!.match(/^http:\/\/127\.0\.0\.1:7410\/hop#t=tok_abc&k=([\w-]{43})&r=(.+)$/);
    expect(m).not.toBeNull();
    expect(decodeURIComponent(m![2]!)).toBe("https://app.example.test/login?next=%2Fhome");
    const saved = JSON.parse(page.stored.get(HOP)!);
    expect(saved).toEqual({ k: m![1], at: expect.any(Number), map: { password: "#pw" }, submit: true });
    expect(Math.abs(Date.now() - saved.at)).toBeLessThan(5000);
    expect(Buffer.from(saved.k, "base64url").length).toBe(32);
    expect(page.listeners.size).toBe(0);
  });

  test("each hop gets a new key", async () => {
    const a = fakePage("csp"), b = fakePage("csp");
    await a.run(snippet);
    await b.run(snippet);
    expect(JSON.parse(a.stored.get(HOP)!).k).not.toBe(JSON.parse(b.stored.get(HOP)!).k);
  });

  test("hop: false keeps reason 'csp' and stays put", async () => {
    const page = fakePage("csp");
    expect((await page.run(buildSnippet({ base: BASE, token: "tok_abc", hop: false }))).reason).toBe("csp");
    expect(page.assigned).toEqual([]);
    expect(page.stored.size).toBe(0);
  });

  test("without WebCrypto (not a secure context) it stays 'csp'", async () => {
    const page = fakePage("csp", { crypto: { getRandomValues: (a: Uint8Array) => crypto.getRandomValues(a) } });
    expect((await page.run(snippet)).reason).toBe("csp");
    expect(page.assigned).toEqual([]);
  });

  test("a plain network failure never hops", async () => {
    const page = fakePage("reject");
    expect((await page.run(snippet)).reason).toBe("network");
    expect(page.assigned).toEqual([]);
  });

  test("coming back: decrypts #locked=, fills, strips hash and key, never touches the token", async () => {
    const { k, blob } = await sealForHop(payload([{ name: "password", type: "password", value: FAKE_PASSWORD }]));
    const page = fakePage({ status: 500 }, { storage: { [HOP]: JSON.stringify({ k, at: Date.now() - 2000, submit: false }) }, hash: `#locked=${blob}` });
    const result = await page.run(snippet);
    expect(result).toEqual({ ok: true, filled: ["password"], missing: [], origin: "https://app.example.test" });
    expect(JSON.stringify(result)).not.toContain(FAKE_PASSWORD);
    expect(page.els[0]!.value).toBe(FAKE_PASSWORD);
    expect(page.calls).toEqual([]);
    expect(page.stored.has(HOP)).toBe(false);
    expect(page.replaced).toEqual(["/login?next=%2Fhome"]);
    expect(page.location.hash).toBe("");
  });

  test("coming back uses the map saved before the hop", async () => {
    const { k, blob } = await sealForHop(payload([{ name: "password", type: "password", value: FAKE_PASSWORD }]));
    const page = fakePage(
      { status: 500 },
      {
        inputs: [["password", "a", "first"], ["password", "b", "second"]],
        storage: { [HOP]: JSON.stringify({ k, at: Date.now(), map: { password: "#second" }, submit: false }) },
        hash: `#locked=${blob}`,
      },
    );
    expect((await page.run(snippet)).filled).toEqual(["password"]);
    expect(page.els.map((el) => el.value)).toEqual(["", FAKE_PASSWORD]);
  });

  test("#locked-error=used comes back as reason 'used' and clears the hop", async () => {
    const page = fakePage({ status: 500 }, { storage: { [HOP]: JSON.stringify({ k: "x", at: Date.now() }) }, hash: "#locked-error=used" });
    expect(await page.run(snippet)).toMatchObject({ ok: false, reason: "used", filled: [] });
    expect(page.calls).toEqual([]);
    expect(page.stored.has(HOP)).toBe(false);
    expect(page.replaced).toEqual(["/login?next=%2Fhome"]);
  });

  test("an unknown #locked-error code is reason 'error'", async () => {
    const page = fakePage({ status: 500 }, { storage: { [HOP]: JSON.stringify({ k: "x", at: Date.now() }) }, hash: "#locked-error=weird" });
    expect((await page.run(snippet)).reason).toBe("error");
  });

  test("a tampered blob is reason 'error', fills nothing and clears the hop", async () => {
    const { k, blob } = await sealForHop(payload([{ name: "password", type: "password", value: FAKE_PASSWORD }]));
    const bad = (blob[20] === "A" ? "B" : "A") + "";
    const page = fakePage({ status: 500 }, { storage: { [HOP]: JSON.stringify({ k, at: Date.now() }) }, hash: `#locked=${blob.slice(0, 20)}${bad}${blob.slice(21)}` });
    expect(await page.run(snippet)).toMatchObject({ ok: false, reason: "error", filled: [] });
    expect(page.els[0]!.value).toBe("");
    expect(page.stored.has(HOP)).toBe(false);
    expect(page.location.hash).toBe("");
  });

  test("a hop older than 3 minutes with no answer is dropped and the token used normally", async () => {
    const page = fakePage({ status: 410, body: { ok: false, error: "used" } }, { storage: { [HOP]: JSON.stringify({ k: "x", at: Date.now() - 4 * 60_000 }) } });
    expect((await page.run(snippet)).reason).toBe("used");
    expect(page.calls.length).toBe(1);
    expect(page.stored.has(HOP)).toBe(false);
  });

  test("a recent hop with no answer is kept; the run goes ahead normally", async () => {
    const page = fakePage({ status: 410, body: { ok: false, error: "used" } }, { storage: { [HOP]: JSON.stringify({ k: "x", at: Date.now() }) } });
    await page.run(snippet);
    expect(page.calls.length).toBe(1);
    expect(page.stored.has(HOP)).toBe(true);
  });

  test("a #locked= hash with no stored key is ignored", async () => {
    const page = fakePage({ status: 404, body: { ok: false, error: "missing" } }, { hash: "#locked=AAAA" });
    expect((await page.run(snippet)).reason).toBe("missing");
    expect(page.calls.length).toBe(1);
    expect(page.replaced).toEqual([]);
  });

  test("coming back to a page that has not rendered its form yet keeps the hop for the next run", async () => {
    const { k, blob } = await sealForHop(payload([{ name: "password", type: "password", value: FAKE_PASSWORD }]));
    const page = fakePage({ status: 500 }, { inputs: [], storage: { [HOP]: JSON.stringify({ k, at: Date.now() }) }, hash: `#locked=${blob}` });
    expect(await page.run(snippet)).toMatchObject({ ok: false, reason: "no-inputs" });
    expect(page.stored.has(HOP)).toBe(true);
    expect(page.location.hash).toBe(`#locked=${blob}`);
  }, 5000);
});
