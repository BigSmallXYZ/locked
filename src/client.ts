import { openSync } from "node:fs";
import { join } from "node:path";
import { AGENT_URL, agentToken, ensureHome, HOME, LOCAL_URL } from "./config.ts";

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode = 1,
    readonly code?: string,
  ) {
    super(message);
  }
}

/** Calls the local agent API. Throws CliError with the server's message on failure. */
export async function api<T = any>(method: string, path: string, body?: unknown, opts: { autostart?: boolean } = {}): Promise<T> {
  const call = () =>
    fetch(AGENT_URL + path, {
      method,
      headers: { Authorization: `Bearer ${agentToken()}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  let res: Response;
  try {
    res = await call();
  } catch {
    if (opts.autostart === false || process.env.LOCKED_NO_AUTOSTART) throw new CliError(`Locked isn't running on ${AGENT_URL}. Start it with: locked serve`, 1, "down");
    await startInBackground();
    res = await call();
  }
  const json = (await res.json().catch(() => ({}))) as any;
  if (!res.ok || json.ok === false) throw new CliError(json.error ?? `HTTP ${res.status}`, 1, json.code);
  return json as T;
}

const health = () => api<{ publicUrl: string }>("GET", "/api/health", undefined, { autostart: false }).catch(() => null);

/** Starts `locked serve` detached, and waits until it's up and any tunnel has its address. */
export async function startInBackground(): Promise<{ publicUrl: string }> {
  ensureHome();
  const log = openSync(join(HOME, "server.log"), "a", 0o600);
  const child = Bun.spawn([process.execPath, join(import.meta.dir, "cli.ts"), "serve"], { stdio: ["ignore", log, log], detached: true });
  child.unref();
  const { loadTunnelConfig, tunnelCommand } = await import("./tunnel.ts");
  const expectsTunnel = !!tunnelCommand(loadTunnelConfig());
  const deadline = Date.now() + 30_000;
  for (;;) {
    const h = await health();
    if (h && (!expectsTunnel || h.publicUrl !== LOCAL_URL)) return h;
    if (Date.now() >= deadline) {
      if (h) return h;
      throw new CliError(`Locked didn't start; see ${join(HOME, "server.log")}`, 1, "down");
    }
    await Bun.sleep(250);
  }
}

/** Asks a running server to exit. Under pm2 that's a restart. */
export async function stopServer(): Promise<boolean> {
  if (!(await health())) return false;
  await api("POST", "/api/shutdown", undefined, { autostart: false });
  while (await health()) await Bun.sleep(100);
  return true;
}
