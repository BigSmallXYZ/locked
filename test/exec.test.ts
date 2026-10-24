import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { makeRedactor, redact, type Secret } from "../src/exec.ts";

const PW = "hunter2-Sup3rSecret!";
const pw: Secret[] = [{ name: "password", value: PW }];
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");

function streamed(secrets: Secret[], chunks: string[]): string {
  const r = makeRedactor(secrets);
  return chunks.map((c) => r.push(c)).join("") + r.flush();
}

describe("makeRedactor", () => {
  test("raw value", () => {
    expect(redact(`login ${PW} ok ${PW}`, pw)).toBe("login [locked:password] ok [locked:password]");
  });

  test("URL-encoded", () => {
    const v = "p@ss w/rd&x=1";
    expect(encodeURIComponent(v)).not.toBe(v);
    expect(redact(`https://x.test/?pw=${encodeURIComponent(v)}`, [{ name: "pw", value: v }])).toBe("https://x.test/?pw=[locked:pw]");
  });

  test("base64 with and without padding", () => {
    const v = "abcde12"; // 7 bytes -> one '=' of padding
    expect(b64(v).endsWith("=")).toBe(true);
    expect(redact(`a ${b64(v)} b`, [{ name: "k", value: v }])).toBe("a [locked:k] b");
    expect(redact(`a ${b64(v).replace(/=+$/, "")} b`, [{ name: "k", value: v }])).toBe("a [locked:k] b");
  });

  test("base64url", () => {
    const v = "ÿþý>>>???";
    expect(b64u(v)).not.toBe(b64(v).replace(/=+$/, ""));
    expect(redact(`token=${b64u(v)};`, [{ name: "k", value: v }])).toBe("token=[locked:k];");
  });

  test("JSON-escaped", () => {
    const v = 'quo"te\\back\nline';
    const json = JSON.stringify({ password: v });
    expect(redact(json, [{ name: "password", value: v }])).toBe('{"password":"[locked:password]"}');
  });

  test("unicode value", () => {
    const v = "pässwörd-🔑-日本";
    expect(redact(`[${v}] ${encodeURIComponent(v)} ${b64(v)}`, [{ name: "u", value: v }])).toBe("[[locked:u]] [locked:u] [locked:u]");
  });

  test("secret split across 2 chunks", () => {
    expect(streamed(pw, ["before hunter2-Su", "p3rSecret! after"])).toBe("before [locked:password] after");
  });

  test("secret split across 3 chunks", () => {
    expect(streamed(pw, ["x hun", "ter2-Sup3", "rSecret! y"])).toBe("x [locked:password] y");
  });

  test("one character per chunk", () => {
    const text = `a${PW}b${b64(PW)}c\n`;
    expect(streamed(pw, [...text])).toBe("a[locked:password]b[locked:password]c\n");
  });

  test("streaming output equals one-shot output for random chunkings", () => {
    const secrets: Secret[] = [
      { name: "a", value: "abcabc" },
      { name: "b", value: "cabx" },
      { name: "c", value: "zz🔑zz" },
    ];
    const alphabet = ["a", "b", "c", "x", "z", "🔑", " ", "\n", "=", "%"];
    let seed = 42;
    const rand = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n);
    for (let round = 0; round < 300; round++) {
      let text = "";
      const len = 20 + rand(80);
      while (text.length < len) {
        text += rand(4) === 0 ? secrets[rand(3)]!.value : alphabet[rand(alphabet.length)]!;
      }
      const chunks: string[] = [];
      for (let i = 0; i < text.length; ) {
        let j = Math.min(text.length, i + 1 + rand(7));
        if (j < text.length && /[\ud800-\udbff]/.test(text[j - 1]!)) j++; // the decoder never splits a pair
        chunks.push(text.slice(i, j));
        i = j;
      }
      const once = redact(text, secrets);
      expect(streamed(secrets, chunks)).toBe(once);
      for (const s of secrets) expect(once).not.toContain(s.value);
    }
  });

  test("overlapping secrets leave no fragment of either", () => {
    const secrets = [
      { name: "a", value: "abcdef" },
      { name: "b", value: "defghi" },
    ];
    expect(redact("<abcdefghi>", secrets)).toBe("<[locked:a][locked:b]>");
    expect(streamed(secrets, ["<abcd", "efg", "hi>"])).toBe("<[locked:a][locked:b]>");
  });

  test("a secret overlapping itself, and back-to-back copies", () => {
    expect(redact("xaaaaay", [{ name: "s", value: "aaa" }])).toBe("x[locked:s]y");
    expect(redact("xabcabcy", [{ name: "s", value: "abc" }])).toBe("x[locked:s][locked:s]y");
  });

  test("a value that looks like a label doesn't corrupt labels", () => {
    const secrets = [
      { name: "one", value: "hunter2" },
      { name: "two", value: "locked" },
    ];
    expect(redact("hunter2 locked", secrets)).toBe("[locked:one] [locked:two]");
  });

  test("longest pattern wins at the same position", () => {
    const secrets = [
      { name: "short", value: "secret" },
      { name: "long", value: "secret-and-more" },
    ];
    expect(redact("[secret-and-more] [secret]", secrets)).toBe("[[locked:long]] [[locked:short]]");
  });

  test("values shorter than 3 characters are skipped", () => {
    const secrets = [
      { name: "pin", value: "42" },
      { name: "x", value: "" },
    ];
    expect(redact("answer 42, total 420", secrets)).toBe("answer 42, total 420");
    expect(streamed(secrets, ["ab", "c"])).toBe("abc");
  });

  test("holds back at most longest-1 characters, and flush releases them", () => {
    const r = makeRedactor(pw);
    expect(r.push("Password: ")).toBe("");
    expect(r.flush()).toBe("Password: ");
    const long = "x".repeat(100);
    const out = r.push(long);
    expect(out.length).toBeGreaterThanOrEqual(100 - (b64(PW).length - 1));
    expect(out + r.flush()).toBe(long);
  });
});

// ---------------------------------------------------------------------------
// execWithSecrets, run in a child Bun so we can capture exactly what it prints.

const EXEC = join(import.meta.dir, "..", "src", "exec.ts");
const RUNNER = `
import { execWithSecrets } from ${JSON.stringify(EXEC)};
const cfg = JSON.parse(process.env.LOCKED_TEST_CFG);
delete process.env.LOCKED_TEST_CFG;
process.exit(await execWithSecrets(cfg.cmd, { env: cfg.env, secrets: cfg.secrets, idleFlushMs: cfg.idleFlushMs }));
`;

type Cfg = { cmd: string[]; env?: Record<string, string>; secrets?: Secret[]; idleFlushMs?: number };

function startRunner(cfg: Cfg) {
  return Bun.spawn(["bun", "-e", RUNNER], {
    env: { ...process.env, LOCKED_TEST_CFG: JSON.stringify({ env: {}, secrets: [], ...cfg }) },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function run(cfg: Cfg) {
  const p = startRunner(cfg);
  const [stdout, stderr, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { stdout, stderr, code };
}

describe("execWithSecrets", () => {
  const env = { LOCKED_PASSWORD: PW };

  test("redacts the raw and base64 value on stdout", async () => {
    const r = await run({
      cmd: ["sh", "-c", 'echo "$LOCKED_PASSWORD"; printf %s "$LOCKED_PASSWORD" | base64'],
      env,
      secrets: pw,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("[locked:password]\n[locked:password]\n");
    expect(r.stdout + r.stderr).not.toContain(PW);
    expect(r.stdout + r.stderr).not.toContain(b64(PW).replace(/=+$/, ""));
  });

  test("redacts stderr too, and a value written in two pieces", async () => {
    const r = await run({
      cmd: ["sh", "-c", 'echo "pw=$LOCKED_PASSWORD" >&2; printf %s "$A"; sleep 0.05; printf "%s\\n" "$B"'],
      env: { ...env, A: PW.slice(0, 9), B: PW.slice(9) },
      secrets: pw,
    });
    expect(r.code).toBe(0);
    expect(r.stderr).toBe("pw=[locked:password]\n");
    expect(r.stdout).toBe("[locked:password]\n");
  });

  test("secrets reach the child through env only, not argv", async () => {
    const r = await run({ cmd: ["sh", "-c", 'echo "$#:${LOCKED_PASSWORD:+set}"'], env, secrets: pw });
    expect(r.stdout).toBe("0:set\n");
  });

  test("exit codes pass through", async () => {
    expect((await run({ cmd: ["sh", "-c", "exit 7"] })).code).toBe(7);
    expect((await run({ cmd: ["true"] })).code).toBe(0);
  });

  test("a missing command returns 127 with a short error", async () => {
    const r = await run({ cmd: ["locked-no-such-command-xyz"], secrets: pw });
    expect(r.code).toBe(127);
    expect(r.stderr).toContain("locked-no-such-command-xyz");
    expect(r.stderr.split("\n").filter(Boolean).length).toBe(1);
  });

  test("idle output is flushed, and SIGTERM is forwarded to the child", async () => {
    const p = startRunner({
      cmd: ["sh", "-c", 'trap "echo got-term; exit 5" TERM; printf "ready> "; while :; do sleep 0.05; done'],
      env,
      secrets: pw,
      idleFlushMs: 100,
    });
    const reader = p.stdout.getReader();
    const dec = new TextDecoder();
    let out = "";
    const deadline = Date.now() + 4000;
    // "ready> " is shorter than the carry, so it only shows up thanks to the idle flush.
    while (!out.includes("ready> ") && Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      out += dec.decode(value, { stream: true });
    }
    expect(out).toBe("ready> ");
    p.kill("SIGTERM");
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      out += dec.decode(value, { stream: true });
    }
    expect(await p.exited).toBe(5);
    expect(out).toBe("ready> got-term\n");
  }, 10_000);
});
