// Run a command with secrets in its environment and redact them from its output.
//
// REDACTION IS BEST-EFFORT. It catches the value as-is and in a handful of common
// encodings (URL-encoded, base64, base64url, JSON-escaped). Any program that
// transforms the value before printing it (hashes it, reverses it, hex-encodes it,
// base64-encodes it together with other bytes, prints it one character per second)
// defeats it. It stops accidental leaks into Claude's transcript; it is not a sandbox.
// Secrets go into the child's environment only, never into argv.

export type Secret = { name: string; value: string };

export type Redactor = {
  /** Feed output; returns the redacted text that is safe to emit now. */
  push(chunk: string): string;
  /** Emit everything still held back. */
  flush(): string;
};

/** Values shorter than this are not redacted: replacing "ab" everywhere would mangle output. */
const MIN_SECRET_LENGTH = 3;

function patternsFor(value: string): string[] {
  const out = new Set<string>([value]);
  try {
    out.add(encodeURIComponent(value));
  } catch {
    // Lone surrogate: not URL-encodable, so it can't appear URL-encoded either.
  }
  const b64 = Buffer.from(value, "utf8").toString("base64");
  out.add(b64);
  out.add(b64.replace(/=+$/, ""));
  out.add(Buffer.from(value, "utf8").toString("base64url"));
  out.add(JSON.stringify(value).slice(1, -1));
  return [...out].filter((p) => p.length >= MIN_SECRET_LENGTH);
}

type Occurrence = { s: number; e: number; name: string };

/**
 * Replaces every occurrence of each secret (and its encodings) with `[locked:<name>]`.
 *
 * Overlapping occurrences (of one secret, or of two secrets sharing characters) are merged
 * into one run, so no fragment of either survives. A run is labelled by each distinct secret
 * that extends it; one found wholly inside an earlier, longer match adds no label. Patterns are
 * tried longest first, so at a given position the longest form wins.
 *
 * Streaming: let L be the longest pattern. After each push we search the whole buffer
 * (carry + chunk, length n) but only emit raw positions [0, c) with c = n - (L - 1), or one
 * less if that would split a surrogate pair; the raw tail [c, n) is kept as the carry.
 *   - An occurrence starting before c has length <= L, so it ends at <= c - 1 + L = n: it lies
 *     entirely inside the buffer and is found now.
 *   - An occurrence starting at or after c has not been emitted at all: its first character is
 *     still in the raw carry, so it will be found once the rest arrives.
 * So no occurrence is ever split across what was emitted and what is still to come. An
 * occurrence found now that starts before c but ends after it is emitted as its label, and the
 * part past c is remembered as `masked` so the next push suppresses it instead of printing it.
 * The output is identical to redacting the whole stream at once, however it is chunked
 * (except across an explicit flush(), which emits the carry and starts over).
 */
export function makeRedactor(secrets: Secret[]): Redactor {
  const byPattern = new Map<string, string>();
  for (const { name, value } of secrets) {
    if (typeof value !== "string" || value.length < MIN_SECRET_LENGTH) continue;
    for (const p of patternsFor(value)) if (!byPattern.has(p)) byPattern.set(p, name);
  }
  const patterns = [...byPattern.entries()].sort((a, b) => b[0].length - a[0].length);
  const longest = patterns[0]?.[0].length ?? 0;
  const keep = Math.max(0, longest - 1);
  const label = (name: string) => `[locked:${name}]`;

  let carry = "";
  /** How many leading chars of `carry` belong to a run that has already been labelled. */
  let masked = 0;
  /** Names already labelled in that open run. */
  let runNames = new Set<string>();

  function step(chunk: string, final: boolean): string {
    const buf = carry + chunk;
    const n = buf.length;
    if (patterns.length === 0) {
      carry = "";
      return buf;
    }
    let c = final ? n : Math.max(0, n - keep);
    // Never split a surrogate pair between what we emit and what we keep. Keeping more is safe.
    if (c > 0 && c < n && isHighSurrogate(buf.charCodeAt(c - 1))) c -= 1;

    // Every occurrence that starts before the cut (overlaps included).
    const occ: Occurrence[] = [];
    for (const [p, name] of patterns) {
      for (let i = buf.indexOf(p); i !== -1 && i < c; i = buf.indexOf(p, i + 1)) {
        occ.push({ s: i, e: i + p.length, name });
      }
    }
    occ.sort((a, b) => a.s - b.s || b.e - a.e);

    let out = "";
    let textFrom = masked; // raw text before this is already accounted for
    let runEnd = masked; // covered by the current run up to (exclusive)
    let names = masked > 0 ? runNames : new Set<string>();
    for (const o of occ) {
      if (o.s >= runEnd) {
        out += buf.slice(textFrom, o.s);
        names = new Set();
      } else if (o.e <= runEnd) {
        continue; // inside what is already covered (e.g. a shorter secret within a longer one)
      }
      runEnd = o.e;
      textFrom = runEnd;
      if (!names.has(o.name)) {
        names.add(o.name);
        out += label(o.name);
      }
    }
    if (textFrom < c) out += buf.slice(textFrom, c);

    carry = buf.slice(c);
    masked = Math.max(0, runEnd - c);
    runNames = masked > 0 ? names : new Set();
    return out;
  }

  return {
    push: (chunk) => step(chunk, false),
    flush: () => step("", true),
  };
}

function isHighSurrogate(code: number) {
  return code >= 0xd800 && code <= 0xdbff;
}

/** One-shot redaction of a complete string. */
export function redact(text: string, secrets: Secret[]): string {
  const r = makeRedactor(secrets);
  return r.push(text) + r.flush();
}

function write(stream: NodeJS.WriteStream, text: string): Promise<void> {
  if (!text) return Promise.resolve();
  return new Promise((resolve) => {
    stream.write(text, () => resolve());
  });
}

async function pump(
  source: ReadableStream<Uint8Array>,
  sink: NodeJS.WriteStream,
  redactor: Redactor,
  idleFlushMs: number,
): Promise<void> {
  const decoder = new TextDecoder("utf-8");
  let timer: ReturnType<typeof setTimeout> | undefined;
  for await (const bytes of source) {
    clearTimeout(timer);
    await write(sink, redactor.push(decoder.decode(bytes, { stream: true })));
    // A prompt like "Password: " sits in the carry until more output comes. Release it after
    // a short silence so interactive programs aren't stuck. (A secret printed slower than
    // this, character by character, gets through: best-effort.)
    timer = setTimeout(() => void write(sink, redactor.flush()), idleFlushMs);
  }
  clearTimeout(timer);
  await write(sink, redactor.push(decoder.decode()));
  await write(sink, redactor.flush());
}

const SIGNAL_NUMBERS: Record<string, number> = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15 };

/**
 * Runs `cmd` with `opts.env` added to the environment, stdin inherited, and stdout/stderr
 * redacted (each through its own redactor). Resolves to the child's exit code (128 + signal
 * when it was killed by one), or 127 when the command can't be started.
 */
export async function execWithSecrets(
  cmd: string[],
  opts: { env: Record<string, string>; secrets: Secret[]; idleFlushMs?: number },
): Promise<number> {
  const idleFlushMs = opts.idleFlushMs ?? 150;
  if (!Array.isArray(cmd) || cmd.length === 0) {
    await write(process.stderr, "locked: no command given\n");
    return 127;
  }

  let proc: Bun.Subprocess<"inherit", "pipe", "pipe">;
  try {
    proc = Bun.spawn(cmd, {
      env: { ...process.env, ...opts.env },
      stdin: "inherit",
      stdout: "pipe",
      stderr: "pipe",
    });
  } catch (err) {
    const why = (err as { code?: string })?.code === "ENOENT" ? "command not found" : String((err as Error)?.message ?? err);
    await write(process.stderr, redact(`locked: cannot run ${cmd[0]}: ${why}\n`, opts.secrets));
    return 127;
  }

  const forward = (signal: NodeJS.Signals) => () => {
    try {
      proc.kill(signal);
    } catch {
      // already gone
    }
  };
  const onInt = forward("SIGINT");
  const onTerm = forward("SIGTERM");
  process.on("SIGINT", onInt);
  process.on("SIGTERM", onTerm);
  try {
    const [, , exited] = await Promise.all([
      pump(proc.stdout, process.stdout, makeRedactor(opts.secrets), idleFlushMs),
      pump(proc.stderr, process.stderr, makeRedactor(opts.secrets), idleFlushMs),
      proc.exited,
    ]);
    if (proc.exitCode !== null) return proc.exitCode;
    if (proc.signalCode) return 128 + (SIGNAL_NUMBERS[proc.signalCode] ?? 0);
    return typeof exited === "number" ? exited : 1;
  } finally {
    process.off("SIGINT", onInt);
    process.off("SIGTERM", onTerm);
  }
}
