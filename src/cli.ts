import { existsSync, lstatSync, mkdirSync, readlinkSync, statSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { AGENT_PORT, agentToken, ensureHome, HOME, paths, PUBLIC_PORT, PUBLIC_URL } from "./config.ts";
import { api, CliError } from "./client.ts";
import type { RequestSummary, UseResult, ApprovalSummary } from "./requests.ts";

const EXIT = { ok: 0, failed: 1, pending: 2, needsApproval: 3 } as const;
const WAIT_DEFAULT_S = 110; // the Bash tool gives up at 120 s
const WAIT_MAX_S = 115;

const out = (s = ""): void => void process.stdout.write(s + "\n");
const err = (s = ""): void => void process.stderr.write(s + "\n");

// ---------------------------------------------------------------------------
// Small helpers

function duration(text: string): number {
  const m = /^(\d+(?:\.\d+)?)(s|m|h|d)?$/.exec(text.trim());
  if (!m) throw new CliError(`bad duration "${text}" (use e.g. 90s, 15m, 2h)`);
  return Number(m[1]) * { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[(m[2] ?? "m") as "s"];
}

function relative(ts: number | null | undefined): string {
  if (!ts) return "never";
  const d = ts - Date.now();
  const abs = Math.abs(d);
  const text = abs < 90_000 ? `${Math.round(abs / 1000)} s` : abs < 5_400_000 ? `${Math.round(abs / 60_000)} min` : abs < 172_800_000 ? `${Math.round(abs / 3_600_000)} h` : `${Math.round(abs / 86_400_000)} d`;
  return d >= 0 ? `in ${text}` : `${text} ago`;
}

/** "password", "password:password", "otp:otp?", "recovery_code?" */
function parseField(spec: string) {
  const m = /^([a-zA-Z][a-zA-Z0-9_-]*)(?::([a-z-]+))?(\?)?$/.exec(spec.trim());
  if (!m) throw new CliError(`bad --field "${spec}" (use name[:type][?], e.g. password, otp:otp?, key:apikey)`);
  return { name: m[1]!, ...(m[2] ? { type: m[2] } : {}), required: !m[3] };
}

function quote(arg: string) {
  return /^[A-Za-z0-9_\/.:=@%+,-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** The current command line with `--approval <id>` added, for "run this next". */
function rerunWith(approvalId: string) {
  const args = process.argv.slice(2);
  const dash = args.indexOf("--");
  const head = dash === -1 ? args : args.slice(0, dash);
  const tail = dash === -1 ? [] : args.slice(dash);
  return ["locked", ...head, "--approval", approvalId, ...tail].map(quote).join(" ");
}

function envName(field: string) {
  return "LOCKED_" + field.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

function list(v: string | string[] | undefined): string[] | undefined {
  if (v == null) return undefined;
  return (Array.isArray(v) ? v : [v]).flatMap((x) => x.split(",")).map((x) => x.trim()).filter(Boolean);
}

type Options = Record<string, { type: "string" | "boolean"; multiple?: boolean }>;

function args(argv: string[], options: Options): { values: Record<string, any>; positionals: string[] } {
  try {
    return parseArgs({ args: argv, options: { json: { type: "boolean" }, ...options }, allowPositionals: true, strict: true });
  } catch (e) {
    throw new CliError((e as Error).message);
  }
}

// ---------------------------------------------------------------------------
// Waiting

async function waitRequest(id: string, timeoutS: number): Promise<RequestSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  let r: { done: boolean; request: RequestSummary };
  do {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    r = await api("GET", `/api/requests/${id}/wait?timeout=${left}`);
  } while (!r.done && Date.now() < deadline - 500);
  return r.request;
}

async function waitApproval(id: string, timeoutS: number): Promise<ApprovalSummary> {
  const deadline = Date.now() + Math.min(timeoutS, WAIT_MAX_S) * 1000;
  let r: { done: boolean; approval: ApprovalSummary };
  do {
    const left = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
    r = await api("GET", `/api/approvals/${id}/wait?timeout=${left}`);
  } while (!r.done && Date.now() < deadline - 500);
  return r.approval;
}

function describeRequest(r: RequestSummary): { line: string; code: number } {
  const fields = r.fields.map((f) => f.name).join(", ");
  switch (r.status) {
    case "filled": {
      const use =
        r.level === "sealed"
          ? `Sealed: use it with locked inject|exec|copy ${r.id} (each use asks the user).`
          : `Use it: locked inject ${r.id} · locked exec ${r.id} -- <cmd> · locked copy ${r.id} <field>`;
      return { line: `${r.id} filled (${fields}). ${use}`, code: EXIT.ok };
    }
    case "pending": {
      const opened = r.openedAt ? `the user opened the link ${relative(r.openedAt)}` : "the link hasn't been opened yet";
      return { line: `${r.id} still waiting: ${opened}; it expires ${relative(r.linkExpiresAt)}. Run \`locked wait ${r.id}\` again.`, code: EXIT.pending };
    }
    case "declined":
      return { line: `${r.id} declined by the user${r.declineNote ? `: "${r.declineNote}"` : "."}`, code: EXIT.failed };
    case "expired":
      return { line: `${r.id} expired. Create a new request if you still need it.`, code: EXIT.failed };
    case "revoked":
      return { line: `${r.id} was revoked.`, code: EXIT.failed };
  }
}

function describeApproval(a: ApprovalSummary): { line: string; code: number } {
  switch (a.status) {
    case "approved":
      return { line: `${a.id} approved. Run the same command again with --approval ${a.id}.`, code: EXIT.ok };
    case "pending":
      return { line: `${a.id} still waiting for the user to approve (expires ${relative(a.expiresAt)}). Run \`locked wait ${a.id}\` again.`, code: EXIT.pending };
    case "denied":
      return { line: `${a.id} denied by the user.`, code: EXIT.failed };
    case "expired":
      return { line: `${a.id} expired before it was used.`, code: EXIT.failed };
    case "redeemed":
      return { line: `${a.id} was already used. Each approval covers one use.`, code: EXIT.failed };
  }
}

/**
 * Gets a use grant for inject/exec/copy. Sealed requests first need the user's approval:
 * without --approval this prints the approval link and exits 3; with it, waits and redeems.
 */
async function obtain(
  id: string,
  via: "inject" | "exec" | "copy",
  opts: { only?: string[]; origin?: string; purpose?: string; approval?: string },
): Promise<Exclude<UseResult, { kind: "approval" }>> {
  if (opts.approval) {
    const a = await waitApproval(opts.approval, WAIT_DEFAULT_S);
    if (a.requestId !== id) throw new CliError(`${opts.approval} belongs to ${a.requestId}, not ${id}`);
    if (a.status !== "approved") {
      const d = describeApproval(a);
      throw new CliError(a.status === "pending" ? `${a.id} still waiting for the user. Run the same command again.` : d.line, d.code);
    }
    return api("POST", `/api/approvals/${opts.approval}/redeem`, { via });
  }
  const r = await api<UseResult & { ok: true }>("POST", `/api/requests/${id}/use`, { via, only: opts.only, origin: opts.origin, purpose: opts.purpose });
  if (r.kind === "approval") {
    out(`${id} is sealed, so this use needs the user's OK.`);
    out(`Send the user this link (valid ${relative(r.expiresAt).replace("in ", "")}):`);
    out(`  ${r.approvalUrl}`);
    out(`Then run: ${rerunWith(r.approvalId)}`);
    throw new CliError("", EXIT.needsApproval);
  }
  return r;
}

// ---------------------------------------------------------------------------
// Commands

const commands: Record<string, (argv: string[]) => Promise<number | void>> = {
  async request(argv) {
    const { values: o } = args(argv, {
      label: { type: "string" },
      site: { type: "string" },
      reason: { type: "string" },
      field: { type: "string", multiple: true },
      login: { type: "boolean" },
      level: { type: "string" },
      ttl: { type: "string" },
      keep: { type: "string" },
      wait: { type: "boolean" },
      timeout: { type: "string" },
    });
    const fields = [
      ...(o.login ? [{ name: "username", required: true }, { name: "password", required: true }] : []),
      ...((o.field as string[] | undefined) ?? []).map(parseField),
    ];
    if (!o.label) throw new CliError('--label is required, e.g. --label "GitHub login"');
    if (fields.length === 0) throw new CliError("ask for something: --login, or --field name[:type] (repeatable)");
    const r = await api("POST", "/api/requests", {
      label: o.label,
      site: o.site,
      reason: o.reason,
      fields,
      level: o.level,
      ttlMs: o.ttl ? duration(o.ttl as string) : undefined,
      retention: o.keep,
    });
    if (o.json) out(JSON.stringify({ id: r.id, url: r.url, expiresAt: r.expiresAt, level: r.level, site: r.site, fields: r.fields }));
    else {
      out(`Created ${r.id} (${r.level}${r.site ? `, for ${r.site}` : ""}); the link expires ${relative(r.expiresAt)}.`);
      out(`Send the user this link:`);
      out(`  ${r.url}`);
      out(`Then run: locked wait ${r.id}`);
    }
    if (o.wait) {
      const d = describeRequest(await waitRequest(r.id, Number(o.timeout ?? WAIT_DEFAULT_S)));
      out(d.line);
      return d.code;
    }
  },

  async wait(argv) {
    const { values: o, positionals: [id] } = args(argv, { timeout: { type: "string" } });
    if (!id) throw new CliError("usage: locked wait <lk_…|ap_…>");
    const timeout = Number(o.timeout ?? WAIT_DEFAULT_S);
    if (id.startsWith("ap_")) {
      const a = await waitApproval(id, timeout);
      const d = describeApproval(a);
      out(o.json ? JSON.stringify({ id: a.id, status: a.status, requestId: a.requestId }) : d.line);
      return d.code;
    }
    const r = await waitRequest(id, timeout);
    const d = describeRequest(r);
    out(o.json ? JSON.stringify({ id: r.id, status: r.status, opened: !!r.openedAt, fields: r.fields.map((f) => f.name), declineNote: r.declineNote }) : d.line);
    return d.code;
  },

  async status(argv) {
    const { values: o, positionals: [id] } = args(argv, {});
    if (!id) return commands.list!(argv);
    if (id.startsWith("ap_")) {
      const { approval } = await api("GET", `/api/approvals/${id}`);
      out(o.json ? JSON.stringify(approval) : describeApproval(approval).line);
      return;
    }
    const { request: r } = (await api("GET", `/api/requests/${id}`)) as { request: RequestSummary };
    if (o.json) return out(JSON.stringify(r));
    out(`${r.id}  ${r.label}`);
    out(`  status    ${r.status}${r.status === "pending" ? ` (link expires ${relative(r.linkExpiresAt)}, ${r.openedAt ? "opened" : "not opened"})` : ""}`);
    out(`  level     ${r.level}`);
    out(`  site      ${r.site ?? "any (not bound)"}`);
    out(`  fields    ${r.fields.map((f) => `${f.name}:${f.type}${f.required ? "" : "?"}`).join(", ")}`);
    if (r.reason) out(`  reason    ${r.reason}`);
    if (r.filledAt) out(`  filled    ${relative(r.filledAt)}, keep ${r.retention}${r.secretExpiresAt ? `, wiped ${relative(r.secretExpiresAt)}` : ""}`);
    out(`  used      ${r.useCount}×`);
  },

  async list(argv) {
    const { values: o } = args(argv, { limit: { type: "string" } });
    const { requests } = (await api("GET", `/api/requests?limit=${Number(o.limit ?? 20)}`)) as { requests: RequestSummary[] };
    if (o.json) return out(JSON.stringify(requests));
    if (requests.length === 0) return out("No requests yet. Create one with: locked request --label … --login");
    for (const r of requests) {
      out(`${r.id}  ${r.status.padEnd(8)} ${r.level.padEnd(6)} ${r.label}${r.site ? `  (${r.site})` : ""}  · ${relative(r.createdAt)}`);
    }
  },

  async get(argv) {
    const { values: o, positionals: [id] } = args(argv, { field: { type: "string", multiple: true } });
    if (!id) throw new CliError("usage: locked get <id> [--field name]");
    const only = list(o.field as string[] | undefined);
    const r = await api<{ values: Record<string, string> }>("POST", `/api/requests/${id}/reveal`, { only });
    if (o.json) out(JSON.stringify(r.values));
    else if (only?.length === 1) out(r.values[only[0]!] ?? "");
    else for (const [k, v] of Object.entries(r.values)) out(`${k}: ${v}`);
    err("(printed secret values: don't repeat them in chat)");
  },

  async inject(argv) {
    const { values: o, positionals: [id] } = args(argv, {
      origin: { type: "string" },
      only: { type: "string", multiple: true },
      map: { type: "string", multiple: true },
      submit: { type: "boolean" },
      approval: { type: "string" },
      purpose: { type: "string" },
      base: { type: "string" },
    });
    if (!id) throw new CliError("usage: locked inject <id> [--origin …] [--only a,b] [--map field=css] [--submit]");
    const map: Record<string, string> = {};
    for (const m of (o.map as string[] | undefined) ?? []) {
      const i = m.indexOf("=");
      if (i < 1) throw new CliError(`bad --map "${m}" (use field=css-selector)`);
      map[m.slice(0, i)] = m.slice(i + 1);
    }
    const grant = await obtain(id, "inject", { only: list(o.only as string[] | undefined), origin: o.origin as string | undefined, purpose: (o.purpose as string) ?? "sign in", approval: o.approval as string | undefined });
    if (grant.kind !== "token") throw new CliError("unexpected grant");
    const base = (o.base as string | undefined) ?? (await api("GET", "/api/health")).publicUrl;
    const { buildSnippet } = await import("./inject.ts");
    const snippet = buildSnippet({ base, token: grant.token, map: Object.keys(map).length ? map : undefined, submit: !!o.submit });
    if (o.json) return out(JSON.stringify({ snippet, origin: grant.origin, fields: grant.fields, expiresAt: grant.expiresAt }));
    err(`One-time autofill of ${grant.fields.join(", ")} into ${grant.origin}. Works once, for 60 s.`);
    err(`Run this in that page with your browser's JavaScript tool. It returns {ok, filled, missing}; never the values.`);
    err(`If it returns reason "hop", the page is reloading through Locked to get past its CSP: run the same snippet again once it has loaded.`);
    err(`Last resort (form in a cross-origin iframe): locked copy ${id} <field>, focus the input, press cmd+V.`);
    out(snippet);
  },

  async exec(argv) {
    const dash = argv.indexOf("--");
    if (dash === -1 || dash === argv.length - 1) throw new CliError("usage: locked exec <id> [--env VAR=field]... -- <command> [args…]");
    const cmd = argv.slice(dash + 1);
    const { values: o, positionals: [id] } = args(argv.slice(0, dash), {
      env: { type: "string", multiple: true },
      approval: { type: "string" },
      purpose: { type: "string" },
    });
    if (!id) throw new CliError("usage: locked exec <id> [--env VAR=field]... -- <command> [args…]");
    const mapping: Array<[string, string]> = ((o.env as string[] | undefined) ?? []).map((m) => {
      const i = m.indexOf("=");
      if (i < 1) throw new CliError(`bad --env "${m}" (use VAR=field)`);
      return [m.slice(0, i), m.slice(i + 1)];
    });
    const only = mapping.length ? [...new Set(mapping.map(([, f]) => f))] : undefined;
    const grant = await obtain(id, "exec", { only, purpose: (o.purpose as string) ?? `run ${cmd[0]}`, approval: o.approval as string | undefined });
    if (grant.kind !== "values") throw new CliError("unexpected grant");
    const env: Record<string, string> = {};
    if (mapping.length) for (const [name, field] of mapping) env[name] = grant.values[field] ?? "";
    else for (const [field, value] of Object.entries(grant.values)) env[envName(field)] = value;
    const { execWithSecrets } = await import("./exec.ts");
    return execWithSecrets(cmd, { env, secrets: Object.entries(grant.values).map(([name, value]) => ({ name, value })) });
  },

  async copy(argv) {
    const { values: o, positionals: [id, field] } = args(argv, { clear: { type: "string" }, approval: { type: "string" }, purpose: { type: "string" } });
    if (!id || !field) throw new CliError("usage: locked copy <id> <field> [--clear 30]");
    const { clipboardSupported, copySecret } = await import("./clipboard.ts");
    if (!clipboardSupported()) throw new CliError("clipboard copy only works on macOS");
    const grant = await obtain(id, "copy", { only: [field], purpose: (o.purpose as string) ?? "paste into a form", approval: o.approval as string | undefined });
    if (grant.kind !== "values") throw new CliError("unexpected grant");
    const value = grant.values[field];
    if (!value) throw new CliError(`${id} has no value for ${field}`);
    const clearAfterSec = Number(o.clear ?? 30);
    await copySecret(value, { clearAfterSec });
    out(`Copied ${field} of ${id} to the clipboard; it clears in ${clearAfterSec} s. Focus the input and press cmd+V.`);
  },

  async revoke(argv) {
    const { positionals: [id] } = args(argv, {});
    if (!id) throw new CliError("usage: locked revoke <id>");
    await api("DELETE", `/api/requests/${id}`);
    out(`${id} revoked; its secret is wiped.`);
  },

  async audit(argv) {
    const { values: o, positionals: [id] } = args(argv, {});
    const { events } = await api("GET", `/api/audit${id ? `?request=${encodeURIComponent(id)}` : ""}`);
    if (o.json) return out(JSON.stringify(events));
    for (const e of events.reverse()) out(`${new Date(e.ts).toISOString()}  ${(e.request_id ?? "").padEnd(13)} ${e.event}${e.detail ? `  ${e.detail}` : ""}`);
  },

  async serve(argv) {
    const { values: o } = args(argv, { tunnel: { type: "boolean" } });
    const { startServers } = await import("./server/index.ts");
    const { tunnelCommand } = await import("./tunnel.ts");
    if (o.tunnel && !existsSync(paths.tunnelConfig)) throw new CliError(`no ${paths.tunnelConfig}; run: locked tunnel setup`);
    const s = await startServers();
    out(`Locked is running.`);
    out(`  public  http://127.0.0.1:${s.publicServer.port}  →  ${PUBLIC_URL}`);
    out(`  agent   http://127.0.0.1:${s.agentServer.port}  (localhost only)`);
    out(`  key     ${s.keySource === "keychain" ? "macOS Keychain" : paths.masterKey}`);
    let tunnel: ReturnType<typeof Bun.spawn> | null = null;
    let stopping = false;
    if (o.tunnel) {
      const startTunnel = () => {
        tunnel = Bun.spawn(tunnelCommand(), { stdout: "ignore", stderr: "pipe" });
        (async () => {
          const reader = (tunnel!.stderr as ReadableStream<Uint8Array>).pipeThrough(new TextDecoderStream() as unknown as ReadableWritablePair<string, Uint8Array>).getReader();
          let buf = "";
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += value;
            let i;
            while ((i = buf.indexOf("\n")) !== -1) {
              const line = buf.slice(0, i);
              buf = buf.slice(i + 1);
              if (/Registered tunnel connection|ERR|error/i.test(line)) err(`[tunnel] ${line.replace(/^\S+\s+/, "")}`);
            }
          }
        })();
        tunnel.exited.then((code) => {
          if (stopping) return;
          err(`[tunnel] cloudflared exited (${code}); restarting in 5 s`);
          setTimeout(startTunnel, 5_000);
        });
      };
      startTunnel();
      out(`  tunnel  cloudflared → ${PUBLIC_URL}`);
    }
    const stop = () => {
      stopping = true;
      tunnel?.kill();
      s.stop();
      process.exit(0);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    await new Promise(() => {});
  },

  async setup(argv) {
    const { values: o } = args(argv, { tunnel: { type: "boolean" } });
    ensureHome();
    agentToken();
    const { openContext } = await import("./server/index.ts");
    const { ctx, keySource, keyCreated } = await openContext();
    ctx.db.close();
    out(`~/.locked ready (${HOME})`);
    out(`  master key  ${keySource === "keychain" ? "macOS Keychain (service \"locked\")" : paths.masterKey}${keyCreated ? " (new)" : ""}`);
    out(`  agent token ${paths.agentToken}`);
    if (o.tunnel) return commands.tunnel!(["setup"]);
  },

  async tunnel(argv) {
    const [sub = "status"] = argv;
    const t = await import("./tunnel.ts");
    if (sub === "setup") {
      const r = t.setupTunnel((line) => out(line));
      out(`Tunnel "${process.env.LOCKED_TUNNEL ?? "locked"}" ${r.created ? "created" : "already existed"} (${r.id}).`);
      out(`  dns     ${r.dns}`);
      out(`  config  ${r.configPath}`);
      out(`Start everything with: pm2 start ecosystem.config.cjs (or, in the foreground: locked serve --tunnel)`);
      return;
    }
    if (sub === "run") {
      if (!existsSync(paths.tunnelConfig)) throw new CliError(`no ${paths.tunnelConfig}; run: locked tunnel setup`);
      const p = Bun.spawn(t.tunnelCommand(), { stdout: "inherit", stderr: "inherit" });
      return p.exited;
    }
    if (sub === "status") {
      const found = t.cloudflaredPath() ? t.findTunnel() : null;
      out(`cloudflared  ${t.cloudflaredPath() ?? "not installed"}`);
      out(`tunnel       ${found ? `${found.name} (${found.id})` : "not created (locked tunnel setup)"}`);
      out(`config       ${existsSync(paths.tunnelConfig) ? paths.tunnelConfig : "missing"}`);
      out(`hostname     ${t.TUNNEL_HOST}`);
      return;
    }
    throw new CliError("usage: locked tunnel setup|run|status");
  },

  async doctor() {
    let bad = 0;
    const check = (ok: boolean, label: string, detail: string) => {
      if (!ok) bad++;
      out(`${ok ? "✓" : "✗"} ${label.padEnd(14)} ${detail}`);
    };
    check(existsSync(HOME) && (statSync(HOME).mode & 0o077) === 0, "home", `${HOME}${existsSync(HOME) ? "" : " (missing: locked setup)"}`);
    check(existsSync(paths.agentToken) && (statSync(paths.agentToken).mode & 0o077) === 0, "agent token", paths.agentToken);
    const health = await api("GET", "/api/health").catch((e) => e as CliError);
    check(!(health instanceof CliError), "agent API", health instanceof CliError ? health.message : `127.0.0.1:${AGENT_PORT}, key in ${health.keySource}`);
    const local = await fetch(`http://127.0.0.1:${PUBLIC_PORT}/healthz`).then((r) => r.ok).catch(() => false);
    check(local, "public server", `127.0.0.1:${PUBLIC_PORT}`);
    const exposed = await fetch(`http://127.0.0.1:${PUBLIC_PORT}/api/health`).then((r) => r.status).catch(() => 0);
    check(exposed === 404 || exposed === 0, "api not public", exposed === 404 || exposed === 0 ? "the public listener has no /api" : `public listener answered /api with ${exposed}!`);
    const t = await import("./tunnel.ts");
    check(!!t.cloudflaredPath(), "cloudflared", t.cloudflaredPath() ?? "not installed (brew install cloudflared)");
    check(existsSync(paths.tunnelConfig), "tunnel config", existsSync(paths.tunnelConfig) ? paths.tunnelConfig : "missing (locked tunnel setup)");
    const remote = await fetch(`${PUBLIC_URL}/healthz`, { signal: AbortSignal.timeout(8_000) }).then((r) => r.ok).catch(() => false);
    check(remote, "public URL", `${PUBLIC_URL}/healthz ${remote ? "reachable" : "unreachable (is the tunnel running? pm2 status locked-tunnel)"}`);
    const remoteApi = await fetch(`${PUBLIC_URL}/api/health`, { signal: AbortSignal.timeout(8_000) }).then((r) => r.status).catch(() => 0);
    if (remote) check(remoteApi === 404, "api via tunnel", remoteApi === 404 ? "not exposed (404)" : `answered ${remoteApi}!`);
    const skill = skillTarget();
    check(existsSync(join(skill, "SKILL.md")), "claude skill", existsSync(skill) ? skill : "not installed (locked install-skill)");
    return bad ? EXIT.failed : EXIT.ok;
  },

  async "install-skill"() {
    const source = join(import.meta.dir, "..", "skill");
    const target = skillTarget();
    mkdirSync(dirname(target), { recursive: true });
    if (existsSync(target) || lstatExists(target)) {
      if (lstatSync(target).isSymbolicLink() && readlinkSync(target) === source) return out(`Already installed: ${target} → ${source}`);
      throw new CliError(`${target} already exists and isn't Locked's symlink; move it away first`);
    }
    symlinkSync(source, target);
    out(`Installed: ${target} → ${source}`);
  },

  async help() {
    out(HELP);
  },
};

function lstatExists(p: string) {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

/** Where Claude Code looks for user skills: $CLAUDE_CONFIG_DIR/skills, else ~/.claude/skills. */
function skillTarget() {
  return join(process.env.CLAUDE_CONFIG_DIR || join(homedir(), ".claude"), "skills", "locked");
}

const HELP = `locked: hand secrets to Claude through a link instead of the chat.

Ask
  locked request --label "GitHub login" --site github.com --login [--reason …]
                 [--field name[:type][?]]… [--level sealed] [--ttl 15m] [--keep once|1h|24h|forever] [--wait]
  locked wait <lk_…|ap_…> [--timeout 110]   exit 0 done · 2 still waiting (run again) · 1 declined/expired
  locked status [<id>] · locked list · locked audit [<id>]

Use
  locked inject <id> [--origin …] [--only a,b] [--map field=css]… [--submit]   prints a one-time autofill snippet
  locked exec <id> [--env VAR=field]… -- <command…>                           env LOCKED_<FIELD>, output redacted
  locked copy <id> <field> [--clear 30]                                       clipboard, then cmd+V
  locked get <id> [--field f]                                                 prints values (normal level only)
  locked revoke <id>
  Sealed requests: inject/exec/copy exit 3 with an approval link; then add --approval ap_…

Run
  locked setup [--tunnel] · locked serve [--tunnel] · locked tunnel setup|run|status
  locked doctor · locked install-skill

Field types: username email password new-password otp apikey text textarea url number
`;

// ---------------------------------------------------------------------------

async function main() {
  const [name = "help", ...rest] = process.argv.slice(2);
  const cmd = commands[name === "--help" || name === "-h" ? "help" : name];
  if (!cmd) {
    err(`unknown command "${name}"\n`);
    err(HELP);
    return EXIT.failed;
  }
  return (await cmd(rest)) ?? EXIT.ok;
}

main().then(
  (code) => process.exit(typeof code === "number" ? code : 0),
  (e) => {
    if (e instanceof CliError) {
      if (e.message) err(`locked: ${e.message}`);
      process.exit(e.exitCode);
    }
    err(`locked: ${(e as Error)?.stack ?? e}`);
    process.exit(1);
  },
);
