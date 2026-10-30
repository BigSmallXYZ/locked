import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomToken } from "./crypto.ts";

const env = process.env;

export const HOME = env.LOCKED_HOME ?? join(homedir(), ".locked");
export const PUBLIC_PORT = Number(env.LOCKED_PUBLIC_PORT ?? 7410);
export const AGENT_PORT = Number(env.LOCKED_AGENT_PORT ?? 7411);
export const LOCAL_URL = `http://127.0.0.1:${PUBLIC_PORT}`;
/** Where people open fill links when you set it yourself; otherwise it comes from the tunnel. */
export const PUBLIC_URL_OVERRIDE = env.LOCKED_PUBLIC_URL?.replace(/\/$/, "") || undefined;
export const PUBLIC_URL = PUBLIC_URL_OVERRIDE ?? LOCAL_URL;
export const AGENT_URL = `http://127.0.0.1:${AGENT_PORT}`;
/** "keychain" (macOS default) or "file". Tests and Linux use "file". */
export const KEYSTORE = env.LOCKED_KEYSTORE ?? (process.platform === "darwin" ? "keychain" : "file");
export const TUNNEL_NAME = env.LOCKED_TUNNEL ?? "locked";

export const paths = {
  db: join(HOME, "locked.db"),
  agentToken: join(HOME, "agent.token"),
  masterKey: join(HOME, "master.key"),
  tunnel: join(HOME, "tunnel.json"),
  tunnelConfig: join(homedir(), ".cloudflared", `${TUNNEL_NAME}.yml`),
};

export function ensureHome() {
  if (!existsSync(HOME)) mkdirSync(HOME, { recursive: true, mode: 0o700 });
  chmodSync(HOME, 0o700);
}

export function writePrivate(path: string, data: string) {
  writeFileSync(path, data, { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** The bearer token the CLI and local scripts use for the agent API. Created on first use. */
export function agentToken(): string {
  ensureHome();
  if (existsSync(paths.agentToken)) return readFileSync(paths.agentToken, "utf8").trim();
  const token = randomToken(32);
  writePrivate(paths.agentToken, token + "\n");
  return token;
}
