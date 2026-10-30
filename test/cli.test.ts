import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The real CLI in a throwaway home, on its own ports.
const home = mkdtempSync(join(tmpdir(), "locked-cli-"));
const env = {
  ...process.env,
  HOME: home,
  PATH: "/usr/bin:/bin", // no real agents or tunnels on it
  CLAUDE_CONFIG_DIR: "",
  LOCKED_HOME: join(home, ".locked"),
  LOCKED_KEYSTORE: "file",
  LOCKED_PUBLIC_PORT: "7610",
  LOCKED_AGENT_PORT: "7611",
  LOCKED_PUBLIC_URL: "",
  LOCKED_NO_AUTOSTART: "",
};

async function locked(...args: string[]) {
  const p = Bun.spawn([process.execPath, join(import.meta.dir, "../src/cli.ts"), ...args], { env, stdout: "pipe", stderr: "pipe" });
  const [out, err] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text()]);
  return { code: await p.exited, out, err };
}

afterAll(() => locked("stop"), 20_000);

describe("cli", () => {
  test("setup installs for the agents it finds and leaves the rest alone", async () => {
    mkdirSync(join(home, ".codex"));
    const r = await locked("setup", "--tunnel", "none", "--no-start", "--no-install");
    expect(r.code).toBe(0);
    const link = join(home, ".agents/skills/locked");
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(existsSync(join(link, "SKILL.md"))).toBe(true);
    expect(readlinkSync(link)).toEndWith("skill");
    expect(existsSync(join(home, ".claude/skills/locked"))).toBe(false);
  });

  test("install-skill targets one agent, or any folder", async () => {
    expect((await locked("install-skill", "--agent", "claude")).code).toBe(0);
    expect(existsSync(join(home, ".claude/skills/locked/SKILL.md"))).toBe(true);
    expect((await locked("install-skill", "--dir", join(home, "elsewhere"))).code).toBe(0);
    expect(existsSync(join(home, "elsewhere/locked/SKILL.md"))).toBe(true);
    expect((await locked("install-skill", "--agent", "nope")).code).toBe(1);
  });

  test("the skill prints as text", async () => {
    expect((await locked("skill")).out).toContain("name: locked");
  });

  test("the server starts by itself, and stops", async () => {
    expect((await locked("doctor")).out).toContain("✗ agent API");
    const r = await locked("request", "--label", "Test", "--field", "password");
    expect(r.code).toBe(0);
    expect(r.out).toContain("http://127.0.0.1:7610/r/");
    expect((await locked("doctor")).out).toContain("✓ public server");
    expect((await locked("stop")).out).toContain("stopped");
    expect((await locked("doctor")).out).toContain("✗ agent API");
  }, 40_000);
});
