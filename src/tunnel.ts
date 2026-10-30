// How people reach the public listener from outside this machine. `locked serve` starts the
// provider saved in ~/.locked/tunnel.json and keeps it running. Only the public listener is
// ever exposed; the agent API stays on localhost.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ensureHome, LOCAL_URL, paths, PUBLIC_PORT, PUBLIC_URL_OVERRIDE, TUNNEL_NAME, writePrivate } from "./config.ts";

export const PROVIDERS = ["quick", "ngrok", "tunnelmole", "cloudflare", "url", "none"] as const;
export type Provider = (typeof PROVIDERS)[number];

export type TunnelConfig = {
  provider: Provider;
  /** ngrok, tunnelmole: a reserved domain. cloudflare: the hostname routed to the named tunnel. */
  host?: string;
  /** url: the address of a tunnel or proxy Locked doesn't run itself. */
  url?: string;
  /** url: the header the proxy sets to the real client address, for rate limits. */
  clientIpHeader?: string;
};

function run(cmd: string[]) {
  const r = Bun.spawnSync(cmd, { stdout: "pipe", stderr: "pipe" });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
}

export function loadTunnelConfig(): TunnelConfig {
  if (PUBLIC_URL_OVERRIDE) return { provider: "url", url: PUBLIC_URL_OVERRIDE, clientIpHeader: process.env.LOCKED_CLIENT_IP_HEADER };
  if (!existsSync(paths.tunnel)) return { provider: "none" };
  return JSON.parse(readFileSync(paths.tunnel, "utf8")) as TunnelConfig;
}

export function saveTunnelConfig(config: TunnelConfig) {
  ensureHome();
  writePrivate(paths.tunnel, JSON.stringify(config, null, 2) + "\n");
}

/** The public URL when it's known before the tunnel starts; null when the provider assigns one. */
export function staticUrl(c: TunnelConfig): string | null {
  if (c.provider === "none") return LOCAL_URL;
  if (c.provider === "url") return c.url!.replace(/\/$/, "");
  return c.host ? `https://${c.host}` : null;
}

/** Passkeys and installed phone apps belong to one hostname, so a URL that changes unpairs them. */
export const urlChanges = (c: TunnelConfig) => c.provider === "quick" || ((c.provider === "ngrok" || c.provider === "tunnelmole") && !c.host);

/**
 * Which header holds the real client address. Only headers the edge overwrites qualify: anything
 * else a client could set itself to dodge rate limits, so it's left to the shared loopback bucket.
 */
export function clientIpHeader(c: TunnelConfig): string | undefined {
  if (c.provider === "quick" || c.provider === "cloudflare") return "cf-connecting-ip";
  return c.provider === "url" ? c.clientIpHeader : undefined;
}

export const cloudflaredPath = () => Bun.which("cloudflared");
export const ngrokPath = () => Bun.which("ngrok");
export const tunnelmolePath = () => Bun.which("tmole");

/** The provider a fresh install gets: no account needed if cloudflared is here, else ngrok. */
export function detectProvider(): Provider | null {
  if (cloudflaredPath()) return "quick";
  if (ngrokPath()) return "ngrok";
  if (tunnelmolePath()) return "tunnelmole";
  return null;
}

// --- named Cloudflare tunnel ---------------------------------------------------------------

export function findTunnel(name = TUNNEL_NAME): { id: string; name: string } | null {
  const r = run(["cloudflared", "tunnel", "list", "--output", "json", "--name", name]);
  if (r.code !== 0) throw new Error(`cloudflared tunnel list failed: ${r.err.trim()}`);
  const list = (JSON.parse(r.out || "[]") ?? []) as Array<{ id: string; name: string; deleted_at?: string }>;
  const live = list.find((t) => t.name === name && (!t.deleted_at || t.deleted_at.startsWith("0001")));
  return live ? { id: live.id, name: live.name } : null;
}

export function configYaml(id: string, host: string, port = PUBLIC_PORT) {
  return [
    `# Written by \`locked tunnel use cloudflare\`. Only the public listener is exposed; the agent API stays on localhost.`,
    `tunnel: ${id}`,
    `credentials-file: ${join(homedir(), ".cloudflared", `${id}.json`)}`,
    `ingress:`,
    `  - hostname: ${host}`,
    `    service: http://127.0.0.1:${port}`,
    `  - service: http_status:404`,
    ``,
  ].join("\n");
}

export type SetupResult = { id: string; created: boolean; dns: string; configPath: string };

export function setupNamedTunnel(host: string, log: (line: string) => void = console.log): SetupResult {
  if (!cloudflaredPath()) throw new Error("cloudflared isn't installed (brew install cloudflared)");
  if (!existsSync(join(homedir(), ".cloudflared", "cert.pem"))) throw new Error("no ~/.cloudflared/cert.pem; run `cloudflared tunnel login` first");

  let tunnel = findTunnel();
  let created = false;
  if (!tunnel) {
    log(`Creating tunnel "${TUNNEL_NAME}"…`);
    const r = run(["cloudflared", "tunnel", "create", TUNNEL_NAME]);
    if (r.code !== 0) throw new Error(`cloudflared tunnel create failed: ${(r.err || r.out).trim()}`);
    tunnel = findTunnel();
    if (!tunnel) throw new Error("tunnel was created but can't be found");
    created = true;
  }
  const creds = join(homedir(), ".cloudflared", `${tunnel.id}.json`);
  if (!existsSync(creds)) {
    throw new Error(`tunnel "${TUNNEL_NAME}" exists (${tunnel.id}) but its credentials file ${creds} is missing on this machine`);
  }

  log(`Routing ${host} to the tunnel…`);
  const route = run(["cloudflared", "tunnel", "route", "dns", TUNNEL_NAME, host]);
  const text = (route.err + route.out).trim();
  let dns: string;
  if (route.code === 0) {
    // cloudflared routes into the zone its cert.pem belongs to; a hostname from another zone
    // ends up as "<host>.<cert zone>". Catch that instead of reporting success.
    const added = text.match(/Added CNAME (\S+)/)?.[1];
    if (added && added !== host) throw new Error(`cloudflared created ${added} instead of ${host}; cert.pem is for another zone`);
    dns = added ? `added CNAME ${added}` : "route already set";
  } else if (/already exists/i.test(text)) {
    dns = `a DNS record for ${host} already exists; it must point at ${tunnel.id}.cfargotunnel.com`;
  } else {
    throw new Error(`cloudflared tunnel route dns failed: ${text}`);
  }

  const yaml = configYaml(tunnel.id, host);
  mkdirSync(dirname(paths.tunnelConfig), { recursive: true });
  if (!existsSync(paths.tunnelConfig) || readFileSync(paths.tunnelConfig, "utf8") !== yaml) writeFileSync(paths.tunnelConfig, yaml);
  return { id: tunnel.id, created, dns, configPath: paths.tunnelConfig };
}

// --- running it ----------------------------------------------------------------------------

/** The command for a provider Locked runs itself; null for `url` and `none`. */
export function tunnelCommand(c: TunnelConfig, port = PUBLIC_PORT): string[] | null {
  switch (c.provider) {
    case "quick":
      return ["cloudflared", "tunnel", "--no-autoupdate", "--url", `http://127.0.0.1:${port}`];
    case "ngrok":
      // No --inspect: the agent would otherwise keep request and response bodies for its local inspector.
      return ["ngrok", "http", String(port), "--log", "stdout", "--log-format", "json", "--inspect=false", ...(c.host ? ["--url", `https://${c.host}`] : [])];
    case "tunnelmole":
      return ["tmole", String(port), ...(c.host ? ["as", c.host] : [])];
    case "cloudflare":
      return ["cloudflared", "tunnel", "--no-autoupdate", "--config", paths.tunnelConfig, "run"];
    default:
      return null;
  }
}

export type TunnelLine = { url?: string; error?: string };

/** Picks the assigned URL, or a failure worth showing, out of one line of tunnel output. */
export function parseTunnelLine(provider: Provider, line: string): TunnelLine {
  if (provider === "quick") {
    const url = /https:\/\/(?!api\.)[a-z0-9-]+\.trycloudflare\.com/.exec(line)?.[0];
    if (url) return { url };
  }
  if (provider === "tunnelmole") {
    const url = /https:\/\/[a-z0-9.-]+\.tunnelmole\.net/.exec(line)?.[0];
    if (url) return { url };
  }
  if (provider === "ngrok") {
    let entry: { msg?: string; url?: string; err?: string };
    try {
      entry = JSON.parse(line);
    } catch {
      return {};
    }
    if (entry.msg === "started tunnel" && entry.url?.startsWith("https://")) return { url: entry.url };
    if (entry.err && entry.err !== "<nil>") return { error: entry.err.trim() };
    return {};
  }
  return /\bERR\b|failed to/i.test(line) ? { error: line.replace(/^\S+\s+/, "") } : {};
}

export type TunnelEvents = { onUrl(url: string): void; onLine(text: string): void };

/** Runs the tunnel and restarts it if it exits, backing off so a bad login doesn't spin. */
export function startTunnel(c: TunnelConfig, events: TunnelEvents, cmd = tunnelCommand(c)) {
  if (!cmd) return { stop() {} };
  let child: ReturnType<typeof Bun.spawn> | null = null;
  let stopping = false;
  let delay = 5_000;

  const follow = async (stream: ReadableStream<Uint8Array>) => {
    const decoder = new TextDecoder();
    let buf = "";
    for await (const chunk of stream) {
      buf += decoder.decode(chunk, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) !== -1) {
        const parsed = parseTunnelLine(c.provider, buf.slice(0, i));
        buf = buf.slice(i + 1);
        if (parsed.url) {
          delay = 5_000;
          events.onUrl(parsed.url);
        }
        if (parsed.error) events.onLine(parsed.error);
      }
    }
  };

  const start = () => {
    child = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe", env: { ...process.env, TUNNELMOLE_TELEMETRY: "0" } });
    void follow(child.stdout as ReadableStream<Uint8Array>);
    void follow(child.stderr as ReadableStream<Uint8Array>);
    child.exited.then((code) => {
      if (stopping) return;
      events.onLine(`${cmd[0]} exited (${code}); restarting in ${delay / 1000} s`);
      setTimeout(start, delay);
      delay = Math.min(delay * 2, 60_000);
    });
  };
  start();

  return {
    stop() {
      stopping = true;
      child?.kill();
    },
  };
}
