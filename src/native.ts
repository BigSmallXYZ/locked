// The macOS helper (native/LockedPanel.swift): a floating panel that types or copies a secret into
// whatever input has focus, and Touch ID for sealed secrets.
//
// It's built on demand into ~/.locked/LockedPanel.app and launched with `open`, so macOS treats it
// as an app of its own: the Accessibility permission it needs for typing names "Locked", not bun or
// node. It's signed ad hoc, so a rebuild (only when the Swift source changes) asks for it again.

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "./config.ts";
import { sha256Hex } from "./crypto.ts";

export type Native = {
  /** Launches the panel on a one-time handle URL. Resolves once it's launched, not when it closes. */
  showPanel(url: string): Promise<void>;
  /** Touch ID (or the login password), with `reason` finishing "Locked is trying to …". */
  deviceAuth(reason: string): Promise<boolean>;
};

export const SOURCE = join(import.meta.dir, "../native/LockedPanel.swift");
export const APP = join(HOME, "LockedPanel.app");
const BIN = join(APP, "Contents/MacOS/LockedPanel");
const STAMP = join(APP, "Contents/Resources/source.sha256");

const INFO_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>dev.locked.panel</string>
  <key>CFBundleName</key><string>Locked</string>
  <key>CFBundleDisplayName</key><string>Locked</string>
  <key>CFBundleExecutable</key><string>LockedPanel</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHumanReadableCopyright</key><string>Types or copies the secrets you gave your agent through Locked.</string>
</dict>
</plist>
`;

export function nativeSupported() {
  return process.platform === "darwin";
}

export function panelAppState(): "missing" | "stale" | "ready" {
  if (!existsSync(BIN)) return "missing";
  const want = sha256Hex(readFileSync(SOURCE, "utf8"));
  return existsSync(STAMP) && readFileSync(STAMP, "utf8").trim() === want ? "ready" : "stale";
}

function run(cmd: string[]) {
  const r = Bun.spawnSync(cmd, { stdout: "pipe", stderr: "pipe" });
  if (r.exitCode !== 0) throw new Error(`${cmd[0]} failed: ${(r.stderr.toString() || r.stdout.toString()).trim().slice(0, 2000)}`);
}

let building: Promise<string> | null = null;

/** Builds the app when it's missing or its source changed. Needs Xcode or the Command Line Tools. */
export function ensurePanelApp(): Promise<string> {
  if (!nativeSupported()) return Promise.reject(new Error("the native panel only works on macOS"));
  if (panelAppState() === "ready") return Promise.resolve(APP);
  building ??= (async () => {
    try {
      const hash = sha256Hex(readFileSync(SOURCE, "utf8"));
      rmSync(APP, { recursive: true, force: true });
      mkdirSync(join(APP, "Contents/MacOS"), { recursive: true });
      mkdirSync(join(APP, "Contents/Resources"), { recursive: true });
      writeFileSync(join(APP, "Contents/Info.plist"), INFO_PLIST);
      run(["/usr/bin/xcrun", "swiftc", "-O", "-swift-version", "5", "-o", BIN, SOURCE, "-framework", "AppKit", "-framework", "LocalAuthentication"]);
      run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "dev.locked.panel", APP]);
      writeFileSync(STAMP, hash + "\n");
      return APP;
    } finally {
      building = null;
    }
  })();
  return building;
}

export const macNative: Native = {
  async showPanel(url) {
    const app = await ensurePanelApp();
    // -n: a new instance per panel; -g: don't bring it forward, so the page keeps focus.
    const p = Bun.spawn(["/usr/bin/open", "-n", "-g", "-a", app, "--args", "--panel", url], { stdout: "ignore", stderr: "pipe" });
    if ((await p.exited) !== 0) throw new Error(`couldn't open the panel: ${(await new Response(p.stderr).text()).trim()}`);
  },

  async deviceAuth(reason) {
    await ensurePanelApp();
    const p = Bun.spawn([BIN, "--auth", reason], { stdout: "ignore", stderr: "ignore" });
    const timer = setTimeout(() => p.kill(), 120_000);
    const code = await p.exited;
    clearTimeout(timer);
    return code === 0;
  },
};
