// The only listener cloudflared reaches. It serves fill pages, approve pages and the
// one-time autofill payload. Nothing here can list requests or read a secret by id.

import type { Server } from "bun";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  approvePageData,
  decideApproval,
  fillPageData,
  LockedError,
  redeemUseToken,
  submitFill,
  type Ctx,
} from "../requests.ts";
import type { ApprovePost, FillPost } from "../model.ts";

export const WEB_DIR = join(import.meta.dir, "../../web");

const PAGE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

const BASE_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow",
  "Strict-Transport-Security": "max-age=31536000",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

const TOKEN = /^[A-Za-z0-9_-]{20,64}$/;
const ASSET = /^[a-z0-9][a-z0-9._-]*\.(js|css|svg|png|ico|webp|woff2)$/i;
const TYPES: Record<string, string> = {
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  ico: "image/x-icon",
  webp: "image/webp",
  woff2: "font/woff2",
};

function headers(extra: Record<string, string> = {}) {
  return { ...BASE_HEADERS, ...extra };
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: headers({ "Content-Type": "application/json", ...extra }) });
}

const LINE_SEPARATORS = new RegExp("[" + String.fromCharCode(0x2028, 0x2029) + "]", "g");

function dataScript(data: unknown) {
  const text = JSON.stringify(data).replace(/</g, "\\u003c").replace(LINE_SEPARATORS, (c) => "\\u" + c.charCodeAt(0).toString(16));
  return `<script type="application/json" id="locked-data">${text}</script>`;
}

async function page(name: string, data: unknown, status = 200) {
  const path = join(WEB_DIR, name);
  const template = existsSync(path) ? await Bun.file(path).text() : `<!doctype html><title>Locked</title><!--LOCKED_DATA--><p>Locked</p>`;
  const html = template.replace("<!--LOCKED_DATA-->", dataScript(data));
  return new Response(html, { status, headers: headers({ "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": PAGE_CSP }) });
}

async function notFound() {
  const path = join(WEB_DIR, "notfound.html");
  const html = existsSync(path) ? await Bun.file(path).text() : "<!doctype html><title>Not found</title><p>This Locked link doesn't exist.</p>";
  return new Response(html, { status: 404, headers: headers({ "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": PAGE_CSP }) });
}

// --- rate limiting (per client IP, fixed one-minute windows) ---

const hits = new Map<string, { n: number; reset: number }>();
function limited(key: string, max: number): boolean {
  const t = Date.now();
  const h = hits.get(key);
  if (!h || h.reset <= t) {
    hits.set(key, { n: 1, reset: t + 60_000 });
    return false;
  }
  return ++h.n > max;
}
setInterval(() => {
  const t = Date.now();
  for (const [k, h] of hits) if (h.reset <= t) hits.delete(k);
}, 60_000).unref();

function clientIp(req: Request, server: Server<unknown>) {
  // cloudflared connects from loopback; Cloudflare puts the real client in CF-Connecting-IP.
  return req.headers.get("cf-connecting-ip") ?? server.requestIP(req)?.address ?? "unknown";
}

/** POSTs must come from our own pages: JSON body, and an Origin (if any) on this host. */
function sameSitePost(req: Request) {
  if (!(req.headers.get("content-type") ?? "").includes("application/json")) return false;
  const origin = req.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.get("host");
  } catch {
    return false;
  }
}

async function readJson<T>(req: Request, max = 64 * 1024): Promise<T> {
  const text = await req.text();
  if (text.length > max) throw new LockedError("too_large", "request too large", 413);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new LockedError("bad_json", "bad JSON", 400);
  }
}

// Error codes the pages turn into their "this link is …" cards.
const TERMINAL: Record<string, string> = {
  filled: "filled",
  declined: "declined",
  expired: "expired",
  revoked: "revoked",
  missing: "missing",
  approved: "approved",
  denied: "denied",
  redeemed: "used",
};

function errorJson(err: unknown) {
  if (err instanceof LockedError) {
    const state = TERMINAL[err.code];
    return json({ ok: false, code: err.code, error: err.message, ...(state ? { state } : {}) }, err.status);
  }
  console.error("[public]", err);
  return json({ ok: false, code: "internal", error: "something went wrong" }, 500);
}

export function publicHandler(ctx: Ctx) {
  return async function fetch(req: Request, server: Server<unknown>): Promise<Response> {
    const url = new URL(req.url);
    const [, head, arg, ...rest] = url.pathname.split("/");
    const ip = clientIp(req, server);
    try {
      if (url.pathname === "/healthz") return new Response("ok", { headers: headers({ "Content-Type": "text/plain" }) });

      // Fill page
      if (head === "r" && arg && TOKEN.test(arg) && rest.length === 0) {
        if (req.method === "GET") {
          if (limited(`get:${ip}`, 120)) return json({ ok: false, error: "slow down" }, 429);
          const data = fillPageData(ctx, arg);
          return page("fill.html", data, data.state === "missing" ? 404 : 200);
        }
        if (req.method === "POST") {
          if (limited(`post:${ip}`, 30)) return json({ ok: false, code: "rate", error: "too many attempts, wait a minute" }, 429);
          if (!sameSitePost(req)) return json({ ok: false, code: "forbidden", error: "forbidden" }, 403);
          return json({ ok: true, ...(await submitFill(ctx, arg, await readJson<FillPost>(req))) });
        }
      }

      // Approve page (sealed secrets)
      if (head === "a" && arg && TOKEN.test(arg) && rest.length === 0) {
        if (req.method === "GET") {
          if (limited(`get:${ip}`, 120)) return json({ ok: false, error: "slow down" }, 429);
          const data = approvePageData(ctx, arg);
          return page("approve.html", data, data.state === "missing" ? 404 : 200);
        }
        if (req.method === "POST") {
          if (limited(`post:${ip}`, 30)) return json({ ok: false, code: "rate", error: "too many attempts, wait a minute" }, 429);
          if (!sameSitePost(req)) return json({ ok: false, code: "forbidden", error: "forbidden" }, 403);
          const body = await readJson<ApprovePost>(req);
          return json({ ok: true, ...decideApproval(ctx, arg, body.decision) });
        }
      }

      // One-time autofill payload, fetched by the snippet from inside the target page.
      if (head === "u" && arg && rest.length === 0) {
        const origin = req.headers.get("origin");
        // Error bodies hold no secrets, so any origin may read them; the values are gated server-side.
        const cors: Record<string, string> = origin ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {};
        if (req.method === "OPTIONS") {
          return new Response(null, { status: 204, headers: headers({ ...cors, "Access-Control-Allow-Methods": "GET", "Access-Control-Max-Age": "60" }) });
        }
        if (req.method === "GET") {
          if (limited(`use:${ip}`, 30)) return json({ ok: false, error: "rate" }, 429, cors);
          if (!TOKEN.test(arg)) return json({ ok: false, error: "missing" }, 404, cors);
          const { status, body } = await redeemUseToken(ctx, arg, origin);
          return json(body, status, cors);
        }
      }

      // CSP hop: pages whose CSP blocks the fetch above navigate here, and this page sends them
      // back with the values encrypted in the URL fragment. See web/hop.js.
      if (url.pathname === "/hop" && req.method === "GET") return page("hop.html", {});
      if (head === "u" && arg && TOKEN.test(arg) && rest.length === 1 && rest[0] === "hop" && req.method === "POST") {
        if (limited(`use:${ip}`, 30)) return json({ ok: false, error: "rate" }, 429);
        if (!sameSitePost(req)) return json({ ok: false, error: "forbidden" }, 403);
        const { return: back } = await readJson<{ return?: string }>(req, 8 * 1024);
        let returnOrigin: string | null = null;
        try {
          const u = new URL(String(back));
          if (u.protocol === "https:" || u.protocol === "http:") returnOrigin = u.origin;
        } catch {}
        const { status, body } = await redeemUseToken(ctx, arg, returnOrigin);
        return json(body, status);
      }

      // The autofill runtime as a plain script, for pages that can include a <script> tag.
      if (url.pathname === "/inject.js" && req.method === "GET") {
        const file = Bun.file(join(WEB_DIR, "autofill.js"));
        if (!(await file.exists())) return notFound();
        return new Response(file, {
          headers: headers({ "Content-Type": TYPES.js!, "Access-Control-Allow-Origin": "*", "Cross-Origin-Resource-Policy": "cross-origin" }),
        });
      }

      if (head === "assets" && arg && ASSET.test(arg) && rest.length === 0 && req.method === "GET") {
        const file = Bun.file(join(WEB_DIR, arg));
        if (await file.exists()) {
          const ext = arg.split(".").pop()!.toLowerCase();
          return new Response(file, { headers: headers({ "Content-Type": TYPES[ext] ?? "application/octet-stream" }) });
        }
      }

      return notFound();
    } catch (err) {
      return errorJson(err);
    }
  };
}
