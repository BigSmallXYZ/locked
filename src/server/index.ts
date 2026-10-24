import type { Server } from "bun";
import { AGENT_PORT, agentToken, ensureHome, KEYSTORE, paths, PUBLIC_PORT, PUBLIC_URL, writePrivate } from "../config.ts";
import { loadMasterKey } from "../crypto.ts";
import { hasEncryptedData, openDb } from "../db.ts";
import { sweep, type Ctx } from "../requests.ts";
import { agentHandler } from "./agent.ts";
import { publicHandler } from "./public.ts";

export const VERSION = "0.1.0";

export async function openContext(opts: { dbPath?: string; keystore?: string; keyPath?: string; publicUrl?: string } = {}) {
  ensureHome();
  const db = openDb(opts.dbPath ?? paths.db);
  const { key, source, created } = await loadMasterKey({
    keystore: opts.keystore ?? KEYSTORE,
    filePath: opts.keyPath ?? paths.masterKey,
    create: !hasEncryptedData(db),
    writeFile: writePrivate,
  });
  const ctx: Ctx = { db, key, publicUrl: opts.publicUrl ?? PUBLIC_URL };
  return { ctx, keySource: source, keyCreated: created };
}

export type Running = {
  ctx: Ctx;
  publicServer: Server<unknown>;
  agentServer: Server<unknown>;
  keySource: string;
  stop(): void;
};

export async function startServers(opts: {
  publicPort?: number;
  agentPort?: number;
  publicUrl?: string;
  dbPath?: string;
  keystore?: string;
  keyPath?: string;
  token?: string;
} = {}): Promise<Running> {
  const { ctx, keySource } = await openContext(opts);
  const token = opts.token ?? agentToken();

  const publicServer = Bun.serve({ hostname: "127.0.0.1", port: opts.publicPort ?? PUBLIC_PORT, fetch: publicHandler(ctx) });
  // With port 0 (tests) the public URL is only known after binding.
  if (!opts.publicUrl && opts.publicPort === 0) ctx.publicUrl = `http://127.0.0.1:${publicServer.port}`;

  let agentServer: Server<unknown>;
  const info = { get publicUrl() { return ctx.publicUrl; }, keySource, version: VERSION };
  agentServer = Bun.serve({
    hostname: "127.0.0.1",
    port: opts.agentPort ?? AGENT_PORT,
    idleTimeout: 60, // long-polls run up to 25 s
    fetch: agentHandler(ctx, token, info, () => agentServer.port!),
  });

  sweep(ctx);
  const sweeper = setInterval(() => sweep(ctx), 30_000);
  return {
    ctx,
    publicServer,
    agentServer,
    keySource,
    stop() {
      clearInterval(sweeper);
      publicServer.stop(true);
      agentServer.stop(true);
      ctx.db.close();
    },
  };
}
