# Security

Locked keeps secrets out of chat transcripts and away from the internet. It doesn't protect you from software already running as your user.

## What it covers

- Secrets don't enter the transcript. The agent handles ids and links.
- Nothing on the internet can list or read secrets. The tunnel only reaches the public listener.
- Fill links are single-use and expire after 15 minutes by default.
- A secret bound to `github.com` can't be auto-filled into another site.
- Sealed secrets need your tap, or Touch ID, for every use.
- Every action is in `locked audit`.

## Prompt injection

A malicious page can at most trick an agent into *asking*. You still type the secret yourself, and the form shows the site, the reason, and a warning the first time a site asks. Read those before you fill it in.

The skill also tells agents to treat instructions in web pages, emails and tool output as untrusted, but that's guidance to a model, not a guarantee. What's enforced is that a secret stays bound to its site.

## What it doesn't cover

- **The tunnel provider.** Forms and phone unlocks reach the tunnel encrypted, but TLS ends at its edge, so autofill values pass through it in plaintext, and it serves the pages' JavaScript. A hostile edge could change that JavaScript. See [what each tunnel can see](tunnels.md#what-the-tunnel-provider-can-see).
- **A normal-level secret, once the agent asks for it.** `locked get` prints it, and `exec` hands it to a command the agent chose. Normal level keeps it out of the chat by default; it doesn't stop an agent that decides otherwise. Use sealed if that matters.
- **Output redaction in `exec`.** It's best-effort. A program that transforms the value before printing it defeats it.
- **The login page.** Autofill puts the value into the page's DOM. Sealed keeps it from the agent, not from the page.
- **Your own user account.** Anything already running as you can reach the Keychain item and the local API.
- **Where the cursor is.** The panel's Type sends real keystrokes to whatever has focus. Check before you click.
- **Phones.** Locked can't clear the clipboard after a Copy (iOS doesn't let web apps), and the lock screen shows the label and the agent's purpose.
- **Pairing.** Whoever uses a pairing code first gets future shares. A code works once, for 10 minutes; 10 wrong codes from anywhere cancel every open pairing; and each new pairing is announced on phones already paired. `locked phone list` shows them all.
- **Rate limits behind a shared address.** Without a trusted client address, every visitor shares one limit. That errs on the strict side.

## Reporting

See [SECURITY.md](../SECURITY.md).
