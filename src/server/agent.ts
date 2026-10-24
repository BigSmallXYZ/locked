// Localhost-only API for the CLI and local scripts. Bound to 127.0.0.1 and never in the tunnel's ingress.

import { timingSafeEqual } from "node:crypto";
import {
  createRequest,
  getApproval,
  getRequest,
  listRequests,
  LockedError,
  redeemApproval,
  requestUse,
  reveal,
  revoke,
  type Ctx,
  type CreateInput,
  type UseInput,
} from "../requests.ts";
import type { Via } from "../model.ts";
import { waitFor } from "./waiters.ts";

/** Server-side cap for one long-poll. The CLI loops these to stay under the Bash tool's 2-minute limit. */
export const MAX_WAIT_MS = 25_000;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

function authorized(req: Request, token: string) {
  const header = req.headers.get("authorization") ?? "";
  const given = Buffer.from(header.startsWith("Bearer ") ? header.slice(7) : "");
  const want = Buffer.from(token);
  return given.length === want.length && timingSafeEqual(given, want);
}

async function body<T>(req: Request): Promise<T> {
  const text = await req.text();
  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new LockedError("bad_json", "bad JSON");
  }
}

function waitMs(url: URL) {
  const s = Number(url.searchParams.get("timeout") ?? 25);
  return Math.min(Math.max(Number.isFinite(s) ? s * 1000 : MAX_WAIT_MS, 0), MAX_WAIT_MS);
}

export type AgentInfo = { publicUrl: string; keySource: string; version: string };

export function agentHandler(ctx: Ctx, token: string, info: AgentInfo, port: () => number) {
  return async function fetch(req: Request): Promise<Response> {
    // Browsers always send Origin on cross-site requests; the CLI never does. This, the
    // Host check (DNS rebinding) and the bearer token keep web pages out.
    if (req.headers.get("origin")) return json({ ok: false, code: "forbidden", error: "browsers can't call the agent API" }, 403);
    const host = req.headers.get("host") ?? "";
    if (host !== `127.0.0.1:${port()}` && host !== `localhost:${port()}`) return json({ ok: false, code: "forbidden", error: "bad host" }, 403);
    if (!authorized(req, token)) return json({ ok: false, code: "unauthorized", error: "missing or wrong bearer token (~/.locked/agent.token)" }, 401);

    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["api", ...]
    if (parts[0] !== "api") return json({ ok: false, code: "not_found", error: "not found" }, 404);
    const [, kind, id, action] = parts;
    const m = req.method;

    try {
      if (kind === "health" && m === "GET") return json({ ok: true, ...info });

      if (kind === "requests") {
        if (!id && m === "POST") return json({ ok: true, ...(await createRequest(ctx, await body<CreateInput>(req))) });
        if (!id && m === "GET") return json({ ok: true, requests: listRequests(ctx, Number(url.searchParams.get("limit") ?? 50)) });
        if (id && !action && m === "GET") return json({ ok: true, request: getRequest(ctx, id) });
        if (id && !action && m === "DELETE") return json({ ok: true, request: revoke(ctx, id) });
        if (id && action === "wait" && m === "GET") {
          const deadline = Date.now() + waitMs(url);
          let request = getRequest(ctx, id);
          while (request.status === "pending" && Date.now() < deadline) {
            await waitFor(id, Math.min(deadline - Date.now(), 5_000));
            request = getRequest(ctx, id);
          }
          return json({ ok: true, done: request.status !== "pending", request });
        }
        if (id && action === "reveal" && m === "POST") {
          const { only } = await body<{ only?: string[] }>(req);
          return json({ ok: true, ...(await reveal(ctx, id, only)) });
        }
        if (id && action === "use" && m === "POST") return json({ ok: true, ...(await requestUse(ctx, id, await body<UseInput>(req))) });
      }

      if (kind === "approvals" && id) {
        if (!action && m === "GET") return json({ ok: true, approval: getApproval(ctx, id) });
        if (action === "wait" && m === "GET") {
          const deadline = Date.now() + waitMs(url);
          let approval = getApproval(ctx, id);
          while (approval.status === "pending" && Date.now() < deadline) {
            await waitFor(id, Math.min(deadline - Date.now(), 5_000));
            approval = getApproval(ctx, id);
          }
          return json({ ok: true, done: approval.status !== "pending", approval });
        }
        if (action === "redeem" && m === "POST") {
          const { via } = await body<{ via?: Via }>(req);
          return json({ ok: true, ...(await redeemApproval(ctx, id, via)) });
        }
      }

      if (kind === "audit" && m === "GET") {
        const request = url.searchParams.get("request");
        const rows = request
          ? ctx.db.query("SELECT ts, request_id, event, detail FROM audit WHERE request_id = ? ORDER BY id DESC LIMIT 200").all(request)
          : ctx.db.query("SELECT ts, request_id, event, detail FROM audit ORDER BY id DESC LIMIT 200").all();
        return json({ ok: true, events: rows });
      }

      return json({ ok: false, code: "not_found", error: "not found" }, 404);
    } catch (err) {
      if (err instanceof LockedError) return json({ ok: false, code: err.code, error: err.message }, err.status);
      console.error("[agent]", err);
      return json({ ok: false, code: "internal", error: String((err as Error)?.message ?? err) }, 500);
    }
  };
}
