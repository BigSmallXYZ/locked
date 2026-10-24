import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { clipboardHash, clipboardSupported, copySecret } from "../src/clipboard.ts";
import { sha256Hex } from "../src/crypto.ts";

const mac = process.platform === "darwin";
const UTF8 = { ...process.env, LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8" };

const paste = () => Bun.spawnSync(["pbpaste"], { env: UTF8 }).stdout.toString("utf8");
const setClipboard = (data: string | Uint8Array) =>
  Bun.spawnSync(["pbcopy"], { stdin: typeof data === "string" ? Buffer.from(data, "utf8") : data, env: UTF8 });
const fake = () => `locked-test-${randomBytes(8).toString("hex")}-ünï`;

function pasteboardTypes(): string[] {
  const r = Bun.spawnSync([
    "osascript",
    "-l",
    "JavaScript",
    "-e",
    `ObjC.import("AppKit"); $.NSPasteboard.generalPasteboard.types.js.map(t => t.js).join("\\n")`,
  ]);
  return r.stdout.toString().trim().split("\n");
}

describe.skipIf(!mac)("copySecret (macOS)", () => {
  // The person running the tests may have something on their clipboard. Put it back afterwards.
  let saved: Buffer | null = null;
  beforeAll(() => {
    saved = Bun.spawnSync(["pbpaste"], { env: UTF8 }).stdout;
  });
  afterAll(() => {
    if (saved) setClipboard(saved);
  });

  test("clipboardSupported", () => {
    expect(clipboardSupported()).toBe(true);
  });

  test("rejects a bad clear delay", async () => {
    await expect(copySecret("whatever", { clearAfterSec: 0 })).rejects.toThrow(RangeError);
    await expect(copySecret("whatever", { clearAfterSec: Number.NaN })).rejects.toThrow(RangeError);
  });

  test("copies, marks it concealed, and clears it after the CLI has exited", async () => {
    const value = fake();
    // Copy from a separate process that exits right away, like the CLI does.
    const runner = `
      import { copySecret } from ${JSON.stringify(join(import.meta.dir, "..", "src", "clipboard.ts"))};
      const v = process.env.LOCKED_TEST_VALUE; delete process.env.LOCKED_TEST_VALUE;
      console.log(JSON.stringify(await copySecret(v, { clearAfterSec: 2 })));
    `;
    const before = Date.now();
    const p = Bun.spawnSync(["bun", "-e", runner], { env: { ...process.env, LOCKED_TEST_VALUE: value } });
    expect(p.exitCode).toBe(0);
    const out = p.stdout.toString();
    expect(out).not.toContain(value);
    const { clearsAt } = JSON.parse(out);
    expect(clearsAt).toBeGreaterThanOrEqual(before + 2000);
    expect(clearsAt).toBeLessThan(Date.now() + 2500);

    expect(clipboardHash()).toBe(sha256Hex(value));
    const types = pasteboardTypes();
    expect(types).toContain("org.nspasteboard.ConcealedType");
    expect(types).toContain("org.nspasteboard.TransientType");

    await Bun.sleep(3200);
    expect(paste().length).toBe(0); // compare lengths so a failure never prints clipboard contents
  }, 10_000);

  test("leaves the clipboard alone if something else was copied in the meantime", async () => {
    const value = fake();
    await copySecret(value, { clearAfterSec: 2 });
    expect(clipboardHash()).toBe(sha256Hex(value));
    const other = `copied-by-the-user-${randomBytes(4).toString("hex")}`;
    setClipboard(other);
    await Bun.sleep(3200);
    expect(paste()).toBe(other);
  }, 10_000);
});

describe.skipIf(mac)("copySecret (other platforms)", () => {
  test("throws a clear error", async () => {
    expect(clipboardSupported()).toBe(false);
    await expect(copySecret("whatever")).rejects.toThrow(/macOS/);
  });
});
