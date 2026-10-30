# Setting up Locked (for agents)

You're an AI agent, and your user asked you to set up Locked. Follow these steps. Don't ask them to paste any secret into the chat at any point.

## 1. Install

Check for Bun with `bun --version`. If it's missing, ask the user before installing it, then:

```bash
curl -fsSL https://bun.sh/install | bash
```

Install Locked:

```bash
bun install -g github:BigSmallXYZ/locked
```

If `locked` isn't on PATH afterwards, Bun's global bin folder isn't either. It's `~/.bun/bin`.

## 2. Configure

```bash
locked setup
```

This creates `~/.locked`, chooses a tunnel, installs the skill for the agents it finds, and starts the server. Read its output. It can run `brew install cloudflared` if no tunnel tool is installed; pass `--no-install` if the user doesn't want that.

If the user asked for a particular tunnel, pass it, for example `locked setup --tunnel ngrok`. The choices are in [tunnels.md](tunnels.md). If they'll pair a phone, recommend `ngrok` or their own domain, because a quick tunnel's address changes on restart.

## 3. Teach yourself the skill

`locked setup` covers Claude Code (`~/.claude/skills`) and Codex and other agents that read `~/.agents/skills`. To target one:

```bash
locked install-skill --agent claude
locked install-skill --agent codex
locked install-skill --dir <your agent's skills folder>
```

If your agent has no skills folder, add the instructions to wherever it reads them. `locked skill` prints them, so for an `AGENTS.md`:

```bash
locked skill >> AGENTS.md
```

Ask the user before changing a file that's checked into a project.

## 4. Check it

```bash
locked doctor
```

Every line should start with `✓` or `–`. A public URL that's unreachable right after setup usually needs a few more seconds.

## 5. Show it works

Create a harmless request and give the user the link:

```bash
locked request --label "Test secret" --field note:text --reason "Check that Locked works" --keep once
locked wait <the lk_ id it printed>
```

When `locked wait` exits 0, tell the user it worked, and run `locked revoke <id>`.

## Later

The server starts by itself when the CLI needs it. After changing tunnels, run `locked restart`.
