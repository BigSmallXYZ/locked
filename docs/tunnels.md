# Choosing a tunnel

Locked's form runs on `127.0.0.1:7410`. A tunnel gives that one port a public https address, so you can open links from your phone, and so paired phones can reach it. `locked serve` starts the tunnel you chose, keeps it running, and picks up the address it's given.

| | Account | Address | Phones | Install |
|---|---|---|---|---|
| `quick` (Cloudflare) | none | new on each restart | no | `brew install cloudflared` |
| `ngrok` | free | new on each restart; stable with a reserved domain | only with a reserved domain | `brew install ngrok`, then `ngrok config add-authtoken <token>` |
| `tunnelmole` | none | new on each restart; stable with a paid domain | only with a stable domain | `npm install -g tunnelmole` |
| `cloudflare` (named tunnel) | Cloudflare, with a domain on it | yours | yes | `brew install cloudflared`, then `cloudflared tunnel login` |
| `url` | whatever you run | yours | yes | nothing |
| `none` | none | this machine only | no | nothing |

Switching takes two commands:

```bash
locked tunnel use ngrok
locked restart
```

`locked tunnel` shows what's in use, and `locked doctor` checks that the address answers and that the agent API isn't exposed through it.

**Start with `quick`** if you just want to try Locked. **Move to a reserved ngrok domain or your own domain** if you'll pair a phone, or if you want links to survive a restart.

## Why a stable address matters

Three things are tied to the address:

- **Open links.** A link sent before a restart points at the old address and stops working. Ask the agent for a new one.
- **Paired phones.** The passkey belongs to one hostname, and so does the Home Screen app. If the address changes, pair the phone again.
- **Notifications.** Web Push subscriptions belong to the phone app, so they go with it.

`locked phone pair` warns you when the address will change, and refuses when there's no tunnel at all.

## What the tunnel provider can see

Every provider ends TLS at its edge, so its systems handle your traffic unencrypted at that layer. What's in that traffic depends on the flow:

- **Fill forms:** only ciphertext. The browser encrypts the values to a key on your machine before posting.
- **Phone unlocks:** only ciphertext, sealed to a key the page made for that unlock.
- **Autofill (`locked inject`):** the plaintext values, once. The page fetches them over the tunnel, so the edge could read them.
- **Page code:** the edge serves the JavaScript of the form, so a hostile edge could change it.

So you're trusting the provider for autofill, and against active attacks everywhere. If that's too much for a given secret, use `locked exec` or `locked panel`, which stay on your machine. The tunnel's own client runs locally too, and Locked starts `ngrok` with `--inspect=false` so it keeps no local copy of requests.

## ngrok

`locked tunnel use ngrok` takes whatever address ngrok assigns, and in our testing that changed on every start. Reserve a domain in the ngrok dashboard and pass it with `--domain` for one that stays. Locked needs an ngrok agent recent enough for your account; if `locked serve` logs `ERR_NGROK_121`, run `ngrok update`.

ngrok can show a warning page on a first visit from a browser on free accounts. If you see it, click Visit Site once. It didn't appear in our tests, and autofill worked through ngrok from a browser that had never visited the address.

## Your own domain on Cloudflare

```bash
cloudflared tunnel login
locked tunnel use cloudflare --hostname locked.example.com
locked restart
```

This creates a named tunnel called `locked`, adds the DNS record, and writes `~/.cloudflared/locked.yml`. Other tunnels on the machine aren't touched. Set `LOCKED_TUNNEL` to use another name.

## Bring your own

Anything that forwards https to `127.0.0.1:7410` works, for example Tailscale Funnel or a reverse proxy on a server:

```bash
locked tunnel use url https://locked.example.com
locked restart
```

Forward that port and nothing else. Port 7411 is the agent API.

Rate limits work per client address. If your proxy overwrites a header with the real client address, name it so clients don't all share one limit:

```bash
locked tunnel use url https://locked.example.com --client-ip-header cf-connecting-ip
```

Only name a header your proxy always overwrites. Otherwise a client could set it and get around the limits.

`LOCKED_PUBLIC_URL` does the same as `url` for one run and takes priority over the saved choice.
