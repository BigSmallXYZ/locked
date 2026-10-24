// A named cloudflared tunnel of its own ("locked"), so other tunnels on this machine are never touched.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { paths, PUBLIC_PORT, PUBLIC_URL, TUNNEL_NAME } from "./config.ts";

export const TUNNEL_HOST = new URL(PUBLIC_URL).hostname;

function run(cmd: string[]) {
  const r = Bun.spawnSync(cmd, { stdout: "pipe", stderr: "pipe" });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
}

export function cloudflaredPath(): string | null {
  return Bun.which("cloudflared");
}

export function findTunnel(name = TUNNEL_NAME): { id: string; name: string } | null {
  const r = run(["cloudflared", "tunnel", "list", "--output", "json", "--name", name]);
  if (r.code !== 0) throw new Error(`cloudflared tunnel list failed: ${r.err.trim()}`);
  const list = (JSON.parse(r.out || "[]") ?? []) as Array<{ id: string; name: string; deleted_at?: string }>;
  const live = list.find((t) => t.name === name && (!t.deleted_at || t.deleted_at.startsWith("0001")));
  return live ? { id: live.id, name: live.name } : null;
}

export function configYaml(id: string, host = TUNNEL_HOST, port = PUBLIC_PORT) {
  return [
    `# Written by \`locked tunnel setup\`. Only the public listener is exposed; the agent API stays on localhost.`,
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

export function setupTunnel(log: (line: string) => void = console.log): SetupResult {
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

  log(`Routing ${TUNNEL_HOST} to the tunnel…`);
  const route = run(["cloudflared", "tunnel", "route", "dns", TUNNEL_NAME, TUNNEL_HOST]);
  const text = (route.err + route.out).trim();
  let dns: string;
  if (route.code === 0) {
    // cloudflared routes into the zone its cert.pem belongs to; a hostname from another zone
    // ends up as "<host>.<cert zone>". Catch that instead of reporting success.
    const added = text.match(/Added CNAME (\S+)/)?.[1];
    if (added && added !== TUNNEL_HOST) throw new Error(`cloudflared created ${added} instead of ${TUNNEL_HOST}; cert.pem is for another zone`);
    dns = added ? `added CNAME ${added}` : "route already set";
  } else if (/already exists/i.test(text)) {
    dns = `a DNS record for ${TUNNEL_HOST} already exists; it must point at ${tunnel.id}.cfargotunnel.com`;
  } else {
    throw new Error(`cloudflared tunnel route dns failed: ${text}`);
  }

  const yaml = configYaml(tunnel.id);
  mkdirSync(dirname(paths.tunnelConfig), { recursive: true });
  if (!existsSync(paths.tunnelConfig) || readFileSync(paths.tunnelConfig, "utf8") !== yaml) writeFileSync(paths.tunnelConfig, yaml);
  return { id: tunnel.id, created, dns, configPath: paths.tunnelConfig };
}

export function tunnelCommand(): string[] {
  return ["cloudflared", "tunnel", "--no-autoupdate", "--config", paths.tunnelConfig, "run"];
}
