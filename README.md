# Locked

Hand passwords, API keys and one-time codes to Claude through a link instead of the chat.

When Claude needs a secret, it runs `locked request`, sends you a link to `https://locked.flypack.app/r/…`, and you fill a short form, from your phone if you like. Claude then uses the secret by auto-filling the login form in its browser, by passing it to a command as an environment variable, or through the clipboard. The value doesn't have to pass through the conversation.

```
Claude ── locked request ──▶ Locked (your Mac) ──▶ link ──▶ you fill the form
Claude ◀─ locked wait ─────┘
Claude ── locked inject ──▶ one-time snippet ──▶ page fetches the values ──▶ inputs filled
```

## Setup

```bash
bun install
ln -s "$PWD/bin/locked" ~/.bun/bin/locked   # put `locked` on PATH
locked setup --tunnel                        # ~/.locked, Keychain master key, cloudflared tunnel + DNS
locked install-skill                         # teaches Claude Code to use it ($CLAUDE_CONFIG_DIR or ~/.claude, then skills/locked)
pm2 start ecosystem.config.cjs && pm2 save   # run it in the background, restarted on crash and at login
locked doctor
```

`ecosystem.config.cjs` runs two pm2 apps: `locked` (both listeners) and `locked-tunnel` (cloudflared). `pm2 logs locked`, `pm2 restart locked` after pulling changes. `pm2 startup` once if pm2 itself isn't started at login yet. For a one-off foreground run, `locked serve --tunnel` does both in one process.

`locked setup --tunnel` creates its own named tunnel (`locked`), routes `locked.flypack.app` to it and writes `~/.cloudflared/locked.yml`. Other tunnels on the machine aren't touched. Set `LOCKED_PUBLIC_URL` to use another hostname.

## Using it

```bash
locked request --label "GitHub login" --site github.com --login --reason "merge PR #42"
locked wait lk_…                      # exit 0 filled · 2 still waiting (run again) · 1 declined/expired

locked inject lk_…                    # prints a JS snippet; run it in the page; returns {ok, filled, missing}
locked inject lk_… --only password    # second page of a two-step login
locked panel lk_…                     # a panel on your Mac: click into any input, then Type (or Copy)
locked phone send lk_… --purpose "log in to the GitHub app"   # a notification on your phone: Face ID, then Copy or Show
locked copy lk_… password             # clipboard for 30 s, then cmd+V (last resort: cross-origin iframes, closed shadow DOM)
locked exec lk_… -- sh -c 'gh auth login --with-token <<< "$LOCKED_PASSWORD"'
locked revoke lk_…

locked creds                          # what's stored: id, level, label, site, fields, how long it's kept
locked get github                     # print a stored login in your terminal (sealed: after Touch ID)
locked get github --field password --copy   # or put one field on the clipboard, cleared after 30 s
```

Every command that takes an `lk_…` id also takes a name: the label or site of a stored secret (`locked get "aws console"`, `locked panel github.com`). An exact label or host wins; a partial match has to be unique, otherwise Locked lists the candidates.

Fields: `--login` is username + password. Add any others with `--field name[:type][?]`. The types are `username email password new-password otp apikey text textarea url number`, and `?` marks a field optional. `--keep once|1h|24h|forever` suggests how long Locked keeps the secret, and the person filling the form can change it. `once` deletes it 5 minutes after the first use, so two-page logins still work.

### Sealed secrets

`--level sealed` is for the high-stakes ones: bank, email, primary accounts, keys that can spend money.
- Claude can never print a sealed secret. `locked get` prints one only into a real terminal (not a pipe or a tool's output), after Touch ID.
- Every `inject`, `exec` or `copy` first prints an approval link (`/a/…`). Nothing happens until you tap Approve.
- `locked panel` and `locked get --copy` ask for Touch ID on the Mac instead (or your login password if there's no Touch ID). The server runs the check, so a script can't skip it.
- Each approval or Touch ID covers one use.

### Native panel

`locked panel <id>` shows a small floating panel at the top right of your Mac: the secret's label and site, why Claude wants it, and a **Type** and **Copy** button for each field, plus **Type all** (Tab between fields). Click into the input first, in any app, then click Type. The panel never takes focus away from that input, so Locked types straight into it. Copy puts the value on the clipboard, marked concealed, and clears it after 30 seconds.

- Values reach the panel only on your first click, through a one-time handle on the localhost listener. The CLI that asked for the panel never sees them.
- It closes itself after `--timeout` (120 s by default, 10 min at most) and wipes the values. `locked panel` reports `typed` and `copied` as they happen, and the audit log records them.
- **Type** needs Accessibility permission once: System Settings → Privacy & Security → Accessibility → Locked. The panel tells you when it's missing. Copy works without it. The app is built from `native/LockedPanel.swift` with the Xcode Command Line Tools on first use, into `~/.locked/LockedPanel.app`. It's rebuilt only when the source changes; after a rebuild, turn Locked off and on again in Accessibility.

### Autofill

`locked inject` mints a token that works once, for 60 seconds, and only from the request's site (CORS-bound, and the server checks `Origin`). The snippet:
- fetches the values from `/u/<token>`;
- finds the inputs by `autocomplete`, type and name hints, searching open shadow roots, same-origin iframes and split OTP boxes too;
- sets them in a way React and Vue pick up;
- returns which fields it filled, never the values.

Pages with a strict CSP `connect-src` (GitHub, Cloudflare, most banks) block that fetch. The snippet then **hops**:
1. It makes a one-off AES-GCM key and keeps it in the page's `sessionStorage`.
2. It navigates the tab to `https://locked.flypack.app/hop#t=<token>&k=<key>&r=<this page>`, and returns `reason: "hop"`.
3. The hop page fetches the values from its own origin. The server only answers if `r` is on the origin the secret is bound to.
4. The hop page encrypts the values with that key and goes straight back with only the ciphertext in the fragment (`#locked=…`).
5. Running the same snippet again on the reloaded page decrypts it from the fragment, clears the fragment and the key, and fills.

Browsers never send the fragment to a server, so neither the key nor the ciphertext reaches one. The hop page also wipes its fragment from the address bar and history as it loads. Anything typed into the page before the hop is lost, because the page reloads.

`locked copy` + cmd+V is the last resort, for forms in cross-origin iframes or closed shadow DOM where no script can reach the input. The clipboard entry is marked concealed so clipboard managers skip it, and it clears itself. The pasting has to be a real keystroke: synthetic cmd+V from browser automation doesn't paste in Claude's built-in browser.

For your own pages there's also `<script src="https://locked.flypack.app/inject.js" data-token="…">`.

### Your phone

Pair it once:

```bash
locked phone pair --name "iPhone"     # prints a link and a code; works once, for 10 minutes
```

- **iPhone:** open the link in Safari, tap Share → Add to Home Screen, and open Locked from the Home Screen (iOS only lets Home Screen web apps show notifications). Enter the code, tap Allow notifications, then Create passkey.
- **Android:** open the link in Chrome, allow notifications, create the passkey.

After that, `locked phone send <id> --purpose "…"` puts a notification on the phone: the secret's label and why Claude wants it. Tap it and unlock with Face ID. You then get **Copy** and **Show** for each field, so you can paste the value into an app on the phone or read it off to type it somewhere else. **Done** wipes it. `locked phone send` reports when it arrived, was opened, unlocked, copied and shown. The share closes after `--timeout` (10 minutes by default, 1 hour at most), and you can unlock it again until then, with Face ID each time.

`locked phone list` shows the paired phones, `locked phone test` sends a test notification, and `locked phone remove dv_…` unpairs one.

How it holds together:
- The notification carries no secret: a one-time share token, the label and the purpose. It's encrypted to the phone anyway (Web Push, RFC 8291), signed with Locked's own VAPID key.
- Unlocking is a passkey made at pairing, with user verification (Face ID) required. The Mac checks the signature against the public key it stored, and releases nothing without it. Sealed secrets work the same way: the Face ID check counts as their device confirmation.
- The values travel sealed to a key the page made for that one unlock (P-256 ECDH, HKDF-SHA256, AES-GCM), so Cloudflare and the tunnel only carry ciphertext. The page keeps them in memory and wipes them on Done, when the share ends, or after 2 minutes in the background.

## How it's built

| | |
|---|---|
| public listener `127.0.0.1:7410` | The only thing the tunnel reaches. It serves fill pages, approve pages, the one-time autofill payload, the CSP hop and static assets. Everything else returns 404, including `/api`. |
| agent listener `127.0.0.1:7411` | The CLI's API, localhost only. It requires the bearer token in `~/.locked/agent.token` and refuses any request with an `Origin` header (browsers) or an unexpected `Host` (DNS rebinding). |
| `~/.locked/locked.db` | SQLite. Secrets are AES-256-GCM under a master key kept in the macOS Keychain (`locked` / `master-key`). Only SHA-256 hashes of link and use tokens are stored. |
| fill page | The browser encrypts the form to a per-request P-256 key (ECDH, then HKDF-SHA256, then AES-GCM) before posting. Cloudflare terminates TLS but only sees ciphertext. |

| phone | A web app at `/phone/` on the public listener (`web/phone.*`), installed to the Home Screen. A paired phone is a passkey public key plus a Web Push subscription in the `devices` table. Pairings and shares live in memory. |
| native panel | `~/.locked/LockedPanel.app`, built from `native/LockedPanel.swift`. A non-activating AppKit panel that talks only to the localhost agent listener, through a one-time handle per panel. It also runs Touch ID (`LocalAuthentication`) for the server. |

Source: `src/requests.ts` (lifecycle), `src/server/` (listeners; `panels.ts` for panel sessions), `src/cli.ts`, `src/resolve.ts` (names to ids), `src/crypto.ts`, `src/exec.ts` (env + output redaction), `src/clipboard.ts`, `src/native.ts` (builds and launches the panel), `native/LockedPanel.swift`, `src/server/phone.ts` (pairing and phone shares), `src/webpush.ts` (VAPID + RFC 8291), `src/webauthn.ts` (passkey checks), `web/` (pages and `autofill.js`), `skill/SKILL.md`.

## What it protects, and what it doesn't

- **Covered:**
  - Secrets never enter the chat transcript.
  - Nothing on the internet can list or read secrets.
  - Fill links are single-use and expire after 15 minutes by default.
  - A secret bound to `github.com` can't be auto-filled into another site.
  - Sealed secrets need your tap, or Touch ID on the Mac, for every use.
  - Every action is in `locked audit`.
- **Limited:**
  - Client-side encryption stops passive logging at Cloudflare, but not a hostile edge, since that edge also serves the page's JavaScript.
  - Output redaction in `exec` is best-effort: a program that transforms the value before printing it defeats it.
  - Autofill puts the value into the page's DOM. "Sealed" keeps it away from Claude, not from the page.
  - Anything already running as your macOS user can reach the Keychain item and the local API.
  - The panel's Type sends real keystrokes to whatever has focus. Check where the cursor is before you click.
  - On the phone, Locked can't clear the clipboard after a Copy (iOS doesn't let web apps), and the lock screen shows the label and Claude's purpose.
  - Whoever uses a pairing code first gets future shares. It works once, for 10 minutes; 10 wrong codes from anywhere cancel every open pairing; and each new pairing is announced on the phones already paired. `locked phone list` shows them all.
- **Prompt injection:** a malicious page can at most trick Claude into *asking*. You still type the secret yourself, and the form shows the site, the reason, and a warning the first time a site asks.

## Development

```bash
bun test            # unit + HTTP tests (clipboard tests run only on macOS)
bun run typecheck   # TypeScript 7
bun run fixtures    # local login pages on :7420 for trying the autofill snippet
```
