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
import type { Native } from "../native.ts";
import { getPanel, openPanel, panelHandleEvent, panelHandleInfo, panelHandleValues } from "./panels.ts";
import { getPairing, getShare, listDevices, removeDevice, sendShare, startPairing, testPush, type Pusher } from "./phone.ts";
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

function noNative(): never {
  throw new LockedError("no_native", "the native panel and Touch ID only work on macOS", 501);
}

export function agentHandler(ctx: Ctx, token: string, info: AgentInfo, port: () => number, native: Native | null, pusher: Pusher) {
  return async function fetch(req: Request): Promise<Response> {
    // Browsers always send Origin on cross-site requests; the CLI never does. This, the
    // Host check (DNS rebinding) and the bearer token keep web pages out.
    if (req.headers.get("origin")) return json({ ok: false, code: "forbidden", error: "browsers can't call the agent API" }, 403);
    const host = req.headers.get("host") ?? "";
    if (host !== `127.0.0.1:${port()}` && host !== `localhost:${port()}`) return json({ ok: false, code: "forbidden", error: "bad host" }, 403);

    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["api", ...]
    const [, kind, id, action] = parts;
    const m = req.method;

    try {
      // The native panel's handle: the one-time token in the path stands in for the bearer token,
      // which the helper app never gets.
      if (parts[0] === "api" && kind === "panel" && id && parts.length <= 4) {
        if (!native) noNative();
        if (!action && m === "GET") return json({ ok: true, ...panelHandleInfo(ctx, id) });
        if (action === "values" && m === "POST") return json({ ok: true, values: await panelHandleValues(ctx, native, id) });
        if (action === "event" && m === "POST") return json({ ok: true, panel: panelHandleEvent(ctx, id, await body(req)) });
        return json({ ok: false, code: "not_found", error: "not found" }, 404);
      }

      if (!authorized(req, token)) return json({ ok: false, code: "unauthorized", error: "missing or wrong bearer token (~/.locked/agent.token)" }, 401);
      if (parts[0] !== "api") return json({ ok: false, code: "not_found", error: "not found" }, 404);

      if (kind === "health" && m === "GET") return json({ ok: true, ...info });

      if (kind === "requests") {
        if (!id && m === "POST") return json({ ok: true, ...(await createRequest(ctx, await body<CreateInput>(req))) });
        if (!id && m === "GET") {
          const limit = Number(url.searchParams.get("limit") ?? 50);
          return json({ ok: true, requests: listRequests(ctx, limit, { stored: url.searchParams.get("stored") === "1" }) });
        }
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
          const { only, deviceAuth } = await body<{ only?: string[]; deviceAuth?: boolean }>(req);
          const request = getRequest(ctx, id);
          if (!deviceAuth || request.level !== "sealed") return json({ ok: true, ...(await reveal(ctx, id, only)) });
          if (!native) noNative();
          await reveal(ctx, id, only, { deviceConfirmed: true, dryRun: true }); // fail fast before asking for a finger
          if (!(await native.deviceAuth(`show the sealed secret “${request.label}” in a terminal`))) {
            throw new LockedError("not_confirmed", "Touch ID wasn't confirmed, so nothing was revealed.", 403);
          }
          return json({ ok: true, ...(await reveal(ctx, id, only, { deviceConfirmed: true })) });
        }
        if (id && action === "use" && m === "POST") return json({ ok: true, ...(await requestUse(ctx, id, await body<UseInput>(req))) });
        if (id && action === "panel" && m === "POST") {
          if (!native) noNative();
          const input = await body<{ only?: string[]; purpose?: string; timeoutSec?: number }>(req);
          return json({ ok: true, panel: await openPanel(ctx, native, `http://127.0.0.1:${port()}`, id, input) });
        }
      }

      if (kind === "requests" && id && action === "phone" && m === "POST") {
        const input = await body<{ only?: string[]; purpose?: string; timeoutSec?: number; device?: string }>(req);
        return json({ ok: true, share: await sendShare(ctx, pusher, id, input) });
      }

      // Phone: pairing, paired devices, shares. See server/phone.ts.
      if (kind === "pairings") {
        if (!id && m === "POST") return json({ ok: true, ...startPairing(ctx, await body<{ name?: string }>(req)) });
        if (id && !action && m === "GET") return json({ ok: true, pairing: getPairing(ctx, id) });
        if (id && action === "wait" && m === "GET") {
          const deadline = Date.now() + waitMs(url);
          let pairing = getPairing(ctx, id);
          while (pairing.status === "pending" && Date.now() < deadline) {
            await waitFor(id, Math.min(deadline - Date.now(), 5_000));
            pairing = getPairing(ctx, id);
          }
          return json({ ok: true, pairing });
        }
      }
      if (kind === "devices") {
        if (!id && m === "GET") return json({ ok: true, devices: listDevices(ctx) });
        if (id === "test" && !action && m === "POST") {
          const { deviceId } = await body<{ deviceId?: string }>(req);
          return json({ ok: true, results: await testPush(ctx, pusher, deviceId) });
        }
        if (id && !action && m === "DELETE") return json({ ok: true, device: removeDevice(ctx, id) });
      }
      if (kind === "shares" && id) {
        if (!action && m === "GET") return json({ ok: true, share: getShare(ctx, id) });
        if (action === "wait" && m === "GET") {
          const after = Number(url.searchParams.get("after") ?? 0);
          const deadline = Date.now() + waitMs(url);
          let share = getShare(ctx, id);
          const settled = () => share.status === "closed" || share.status === "failed" || share.events.length > after;
          while (!settled() && Date.now() < deadline) {
            await waitFor(id, Math.min(deadline - Date.now(), 5_000));
            share = getShare(ctx, id);
          }
          return json({ ok: true, share });
        }
      }

      if (kind === "panels" && id) {
        if (!action && m === "GET") return json({ ok: true, panel: getPanel(ctx, id) });
        if (action === "wait" && m === "GET") {
          // Wakes on every click, not just when the panel closes: `after` is how many events the caller has seen.
          const after = Number(url.searchParams.get("after") ?? 0);
          const deadline = Date.now() + waitMs(url);
          let panel = getPanel(ctx, id);
          const settled = () => panel.status === "closed" || panel.status === "failed" || panel.events.length > after;
          while (!settled() && Date.now() < deadline) {
            await waitFor(id, Math.min(deadline - Date.now(), 5_000));
            panel = getPanel(ctx, id);
          }
          return json({ ok: true, panel });
        }
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
