import { AGENT_URL, agentToken } from "./config.ts";

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
export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(AGENT_URL + path, {
      method,
      headers: { Authorization: `Bearer ${agentToken()}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new CliError(`Locked isn't running on ${AGENT_URL}. Start it with: pm2 start locked locked-tunnel (or: locked serve --tunnel)`, 1, "down");
  }
  const json = (await res.json().catch(() => ({}))) as any;
  if (!res.ok || json.ok === false) throw new CliError(json.error ?? `HTTP ${res.status}`, 1, json.code);
  return json as T;
}
