// Put a secret on the macOS clipboard so the user's browser can paste it (cmd+V), then clear it.
//
// The value only ever travels over stdin (to osascript or pbcopy). argv and env, which other
// processes can read with `ps`, only ever carry its SHA-256. The clipboard is marked concealed
// and transient (nspasteboard.org) so clipboard managers like Raycast, Maccy and Paste skip it.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { sha256Hex } from "./crypto.ts";

export const DEFAULT_CLEAR_AFTER_SEC = 30;

/** pbcopy/pbpaste pick the text encoding from the locale; pin it so hashes line up. */
const UTF8_ENV = { ...process.env, LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8", LC_CTYPE: "en_US.UTF-8" };

// JXA: read stdin as UTF-8, replace the clipboard with it, mark it concealed + transient.
const WRITE_JXA = `
ObjC.import('AppKit');
function run() {
  const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
  const text = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
  if (text.isNil()) return 'bad-utf8';
  const pb = $.NSPasteboard.generalPasteboard;
  pb.clearContents;
  const ok = pb.setStringForType(text, $.NSPasteboardTypeString);
  pb.setStringForType($(''), 'org.nspasteboard.ConcealedType');
  pb.setStringForType($(''), 'org.nspasteboard.TransientType');
  return ok ? 'ok' : 'failed';
}`;

/** Single-quoted into the sh script below, so it must not contain a single quote. */
const CLEAR_JXA = `ObjC.import("AppKit"); $.NSPasteboard.generalPasteboard.clearContents; ""`;

export function clipboardSupported(): boolean {
  return process.platform === "darwin";
}

function writeWithOsascript(value: string): boolean {
  const r = Bun.spawnSync(["osascript", "-l", "JavaScript", "-e", WRITE_JXA], {
    stdin: Buffer.from(value, "utf8"),
    stdout: "pipe",
    stderr: "pipe",
  });
  return r.exitCode === 0 && r.stdout.toString().trim() === "ok";
}

function writeWithPbcopy(value: string): boolean {
  const r = Bun.spawnSync(["pbcopy"], { stdin: Buffer.from(value, "utf8"), env: UTF8_ENV, stdout: "ignore", stderr: "pipe" });
  return r.exitCode === 0;
}

/** SHA-256 (hex) of what the clipboard currently holds as text, or null if it can't be read. */
export function clipboardHash(): string | null {
  const r = Bun.spawnSync(["pbpaste"], { env: UTF8_ENV, stdout: "pipe", stderr: "ignore" });
  if (r.exitCode !== 0) return null;
  return createHash("sha256").update(r.stdout).digest("hex");
}

/**
 * Copies `value` to the clipboard and schedules a clear `clearAfterSec` seconds later (default
 * 30). The clear runs in a detached process, so it still happens after the CLI exits, and it
 * only clears if the clipboard still holds this exact value (compared by hash), so anything the
 * user copied in the meantime is left alone. Never prints the value.
 */
export async function copySecret(value: string, opts?: { clearAfterSec?: number }): Promise<{ clearsAt: number }> {
  if (!clipboardSupported()) {
    throw new Error(`locked copy needs the macOS clipboard; it isn't available on ${process.platform}. Use locked inject or locked exec instead.`);
  }
  const clearAfterSec = opts?.clearAfterSec ?? DEFAULT_CLEAR_AFTER_SEC;
  if (!Number.isFinite(clearAfterSec) || clearAfterSec <= 0 || clearAfterSec > 86_400) {
    throw new RangeError("clearAfterSec must be a number of seconds between 1 and 86400");
  }
  const seconds = Math.ceil(clearAfterSec);
  const hash = sha256Hex(value);

  let written = writeWithOsascript(value) && clipboardHash() === hash;
  if (!written) written = writeWithPbcopy(value) && clipboardHash() === hash;
  if (!written) throw new Error("could not put the secret on the clipboard (the clipboard didn't hold it after writing)");

  scheduleClear(hash, seconds);
  return { clearsAt: Date.now() + seconds * 1000 };
}

/** Detached `sh` that sleeps, then clears the clipboard if it still hashes to `hash`. */
function scheduleClear(hash: string, seconds: number) {
  if (!/^[0-9a-f]{64}$/.test(hash) || !Number.isInteger(seconds)) throw new Error("bad clear schedule");
  const script = [
    `sleep ${seconds}`,
    `cur=$(pbpaste | shasum -a 256 | cut -d ' ' -f 1)`,
    `if [ "$cur" = "${hash}" ]; then`,
    `  osascript -l JavaScript -e '${CLEAR_JXA}' >/dev/null 2>&1 || printf '' | pbcopy`,
    `fi`,
  ].join("\n");
  const child = spawn("sh", ["-c", script], { detached: true, stdio: "ignore", env: UTF8_ENV });
  child.unref();
}
