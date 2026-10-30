import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { paths } from "../src/config.ts";
import { clientIpHeader, loadTunnelConfig, parseTunnelLine, saveTunnelConfig, startTunnel, staticUrl, tunnelCommand, urlChanges } from "../src/tunnel.ts";
import { startServers } from "../src/server/index.ts";
import { resetRateLimits } from "../src/server/public.ts";

const dir = mkdtempSync(join(tmpdir(), "locked-tunnel-"));
afterAll(() => rmSync(paths.tunnel, { force: true }));

describe("config", () => {
  test("no config means local only", () => {
    rmSync(paths.tunnel, { force: true });
    expect(loadTunnelConfig()).toEqual({ provider: "none" });
    expect(staticUrl({ provider: "none" })).toBe("http://127.0.0.1:7410");
  });

  test("round trip, and which providers know their URL up front", () => {
    saveTunnelConfig({ provider: "ngrok", host: "calm-otter.ngrok-free.app" });
    expect(loadTunnelConfig()).toEqual({ provider: "ngrok", host: "calm-otter.ngrok-free.app" });
    expect(staticUrl(loadTunnelConfig())).toBe("https://calm-otter.ngrok-free.app");
    expect(staticUrl({ provider: "ngrok" })).toBeNull();
    expect(staticUrl({ provider: "quick" })).toBeNull();
    expect(staticUrl({ provider: "cloudflare", host: "locked.example.com" })).toBe("https://locked.example.com");
    expect(staticUrl({ provider: "url", url: "https://a.example.com/" })).toBe("https://a.example.com");
  });

  test("only free random addresses change", () => {
    expect(urlChanges({ provider: "quick" })).toBe(true);
    expect(urlChanges({ provider: "tunnelmole" })).toBe(true);
    expect(urlChanges({ provider: "tunnelmole", host: "mine.tunnelmole.net" })).toBe(false);
    expect(urlChanges({ provider: "ngrok" })).toBe(false);
  });

  test("client IP headers are only trusted where the edge overwrites them", () => {
    expect(clientIpHeader({ provider: "quick" })).toBe("cf-connecting-ip");
    expect(clientIpHeader({ provider: "cloudflare", host: "a.b" })).toBe("cf-connecting-ip");
    expect(clientIpHeader({ provider: "ngrok" })).toBeUndefined();
    expect(clientIpHeader({ provider: "url", url: "https://a.b" })).toBeUndefined();
    expect(clientIpHeader({ provider: "url", url: "https://a.b", clientIpHeader: "x-real-ip" })).toBe("x-real-ip");
  });
});

describe("commands", () => {
  test("only the public port is forwarded", () => {
    expect(tunnelCommand({ provider: "quick" }, 7410)).toContain("http://127.0.0.1:7410");
    expect(tunnelCommand({ provider: "ngrok" }, 7410)).toContain("7410");
  });

  test("ngrok keeps no local copy of traffic", () => {
    expect(tunnelCommand({ provider: "ngrok" })).toContain("--inspect=false");
  });

  test("ngrok uses the reserved domain", () => {
    const cmd = tunnelCommand({ provider: "ngrok", host: "calm-otter.ngrok-free.app" })!;
    expect(cmd.slice(cmd.indexOf("--url"))).toEqual(["--url", "https://calm-otter.ngrok-free.app"]);
  });

  test("tunnelmole forwards the public port, on a reserved domain if there is one", () => {
    expect(tunnelCommand({ provider: "tunnelmole" }, 7410)).toEqual(["tmole", "7410"]);
    expect(tunnelCommand({ provider: "tunnelmole", host: "mine.tunnelmole.net" }, 7410)).toEqual(["tmole", "7410", "as", "mine.tunnelmole.net"]);
  });

  test("nothing to run for your own tunnel", () => {
    expect(tunnelCommand({ provider: "url", url: "https://a.b" })).toBeNull();
    expect(tunnelCommand({ provider: "none" })).toBeNull();
  });
});

describe("parsing", () => {
  test("quick tunnel URL", () => {
    const line = "2026-10-30T17:11:59Z INF |  https://pottery-shelf-insulin-herald.trycloudflare.com  |";
    expect(parseTunnelLine("quick", line).url).toBe("https://pottery-shelf-insulin-herald.trycloudflare.com");
  });

  test("the quick tunnel API host isn't the URL", () => {
    expect(parseTunnelLine("quick", "ERR failed to request quick Tunnel: Post https://api.trycloudflare.com/tunnel").url).toBeUndefined();
  });

  test("tunnelmole URL, https only", () => {
    expect(parseTunnelLine("tunnelmole", "https://cqcu2t-ip-49-185-26-79.tunnelmole.net ⟶ http://localhost:7410").url).toBe("https://cqcu2t-ip-49-185-26-79.tunnelmole.net");
    expect(parseTunnelLine("tunnelmole", "http://cqcu2t-ip-49-185-26-79.tunnelmole.net ⟶ http://localhost:7410").url).toBeUndefined();
  });

  test("ngrok URL", () => {
    const line = JSON.stringify({ lvl: "info", msg: "started tunnel", obj: "tunnels", url: "https://calm-otter.ngrok-free.app" });
    expect(parseTunnelLine("ngrok", line)).toEqual({ url: "https://calm-otter.ngrok-free.app" });
  });

  test("ngrok failures are surfaced, and its noise isn't", () => {
    expect(parseTunnelLine("ngrok", JSON.stringify({ err: "authentication failed: ERR_NGROK_121\r\n", msg: "failed to reconnect session" })).error).toBe("authentication failed: ERR_NGROK_121");
    expect(parseTunnelLine("ngrok", JSON.stringify({ err: "<nil>", msg: "open config file" }))).toEqual({});
    expect(parseTunnelLine("ngrok", "not json")).toEqual({});
  });
});

function fakeTunnel(script: string) {
  const path = join(dir, `fake-${Math.random().toString(36).slice(2)}`);
  writeFileSync(path, `#!/bin/sh\n${script}\n`);
  chmodSync(path, 0o755);
  return [path];
}

describe("running", () => {
  test("the URL from a running tunnel reaches the links Locked hands out", async () => {
    const d = mkdtempSync(join(dir, "s-"));
    const s = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(d, "t.db"), keyPath: join(d, "k"), keystore: "file", token: "tunnel-test-token-0123456789", native: null });
    const line = JSON.stringify({ msg: "started tunnel", url: "https://calm-otter.ngrok-free.app" });
    const url = await new Promise<string>((resolve) => {
      const t = startTunnel({ provider: "ngrok" }, { onUrl: (u) => (t.stop(), resolve(u)), onLine() {} }, fakeTunnel(`echo '${line}'; sleep 5`));
    });
    s.ctx.publicUrl = url;
    const res = await fetch(`http://127.0.0.1:${s.agentServer.port}/api/requests`, {
      method: "POST",
      headers: { Authorization: "Bearer tunnel-test-token-0123456789", "Content-Type": "application/json" },
      body: JSON.stringify({ label: "Test", fields: [{ name: "password", required: true }] }),
    });
    expect(((await res.json()) as { url: string }).url).toStartWith("https://calm-otter.ngrok-free.app/r/");
    s.stop();
  });

  test("a forged client address doesn't dodge the rate limit", async () => {
    const d = mkdtempSync(join(dir, "s-"));
    const s = await startServers({ publicPort: 0, agentPort: 0, dbPath: join(d, "t.db"), keyPath: join(d, "k"), keystore: "file", token: "tunnel-test-token-0123456789", native: null });
    const pub = `http://127.0.0.1:${s.publicServer.port}`;
    const statuses: number[] = [];
    for (let i = 0; i < 32; i++) {
      const res = await fetch(`${pub}/u/not-a-real-token-0123456789`, { headers: { "CF-Connecting-IP": `203.0.113.${i + 1}` } });
      statuses.push(res.status);
    }
    resetRateLimits(); // shared with the other test files in this process
    expect(statuses).toContain(429);
    s.stop();
  });

  test("a tunnel that dies is reported", async () => {
    const text = await new Promise<string>((resolve) => {
      const t = startTunnel({ provider: "quick" }, { onUrl() {}, onLine: (l) => (t.stop(), resolve(l)) }, fakeTunnel("exit 3"));
    });
    expect(text).toContain("exited (3)");
  });
});
