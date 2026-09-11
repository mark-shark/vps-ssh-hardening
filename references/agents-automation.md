# Access for CI, automation, and AI agent sessions

Non-human clients fail differently from people. They cannot answer a passphrase prompt, they retry silently and fast, and when they break they usually break in a way that looks like a server problem.

## Give every automated client its own key

Same rule as machines, for the same reasons: revocation without collateral damage, and a log you can read.

```bash
ssh-keygen -t ed25519 -N "" -C "ci-deploy@gitlab" -f ~/.ssh/id_ed25519_ci
ssh-keygen -t ed25519 -N "" -C "agent-session@workstation" -f ~/.ssh/id_ed25519_agent
```

No passphrase, deliberately: an automated client cannot answer a prompt, and a key it can never unlock is not more secure, just broken. Compensate by narrowing what the key reaches and keeping the ability to revoke it alone.

Then give it a named host block, so the automation uses the intended identity rather than whatever the default files happen to be:

```
Host myserver-agent
  HostName 198.51.100.10
  User deploy
  IdentityFile ~/.ssh/id_ed25519_agent
  IdentitiesOnly yes
  PreferredAuthentications publickey
```

`IdentitiesOnly yes` stops ssh from offering every other key first — which matters because `MaxAuthTries` (often 3 on a hardened host) can be exhausted before the right key is tried.

## Prefer a less privileged account

An automated client rarely needs root. If it deploys, give it the deploy user. If it reads logs, an account with `sudo` limited to those commands.

When restoring access that previously ran as root, restoring root is defensible — you are returning to the prior state, not widening it. Expanding privilege while "fixing" something is how permissions creep. Say which of the two you are doing.

## Clients that address the host directly, not by alias

Some tools connect to `user@203.0.113.5` rather than an alias from your config. They then fall back to the **default identity files** (`~/.ssh/id_rsa`, `id_ecdsa`, `id_ed25519`, …). If you rotate away from one of those names, such a client stops working and cannot easily be reconfigured.

Fix it from the config side — no change needed in the tool:

```
Host 203.0.113.5
  User root
  IdentityFile ~/.ssh/id_ed25519_host
  IdentitiesOnly yes
```

Verify exactly the way the tool connects, bypassing your own conveniences:

```bash
ssh -o ControlPath=none -o IdentityAgent=none -o BatchMode=yes \
    root@203.0.113.5 'echo OK'
```

## Failure modes specific to automation

**Silent passphrase failure.** With `BatchMode=yes`, a passphrase-protected key produces `Server accepts key` and then denial. See `pitfalls.md`. Automation should use passphrase-less keys, or a key reliably loaded in an agent that survives reboots.

**Retry storms trigger bans.** An agent or IDE holding a stale key retries on its own schedule. Three attempts is enough to trip a default jail, and each retry after a ban expires can start a new one — so the outage never ends on its own. When a lockout will not clear, look for a client still retrying with an old key, and stop it before you unban.

**Non-interactive `PATH`.** `ssh host 'some-tool'` often fails where an interactive login works, because non-interactive SSH gets a minimal `PATH`. Use an absolute path or `zsh -lc "..."` — and do not conclude a tool is missing from one failed lookup.

**Credentials in a locked Keychain (macOS).** A tool that stores tokens in the login Keychain reports "not logged in" over SSH. The Keychain unlocks at GUI login, not for SSH sessions:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

State the cost: this exposes everything in that Keychain to the session. Better options where available are a long-lived token the tool can read from a file or environment variable, or running the tool in a graphical session (Screen Sharing).

## Long-running agent sessions over SSH

An interactive tool started over SSH dies with the connection. `tmux` (or `screen`) keeps it alive:

```bash
tmux new -A -s agent "some-interactive-tool"
```

`-A` attaches to the session if it already exists instead of creating a second one, so the same command both starts and resumes it. Detach with `Ctrl-B` then `D`.

Two things reliably go wrong on the first run, and both look like "it didn't start":

- **First-run prompts.** Interactive tools often ask a setup question on first launch and wait forever. From another session, `tmux capture-pane -p -t agent | tail -20` shows what it is waiting for. This is the fastest way to find out why something "isn't working" when it is simply blocked on a prompt.
- **Working directory.** A tool launched in `$HOME` may behave differently from one launched in the project. Pass the directory explicitly.

Wrap the whole thing in a small script on the remote machine rather than escaping quotes through several shell layers — it is readable, and the quoting is a genuine source of bugs:

```bash
#!/bin/bash
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "${2:-$HOME}" || exit 1
exec tmux new -A -s agent "some-tool ${1:-}"
```

## Handing context to another agent session

When several agents share infrastructure, tell the others what changed — a deleted key, a new port, a renamed account. Include what they can verify themselves (fingerprints, paths, exact commands) rather than conclusions, and name the traps that cost you time. An agent acting on a stale assumption produces exactly the retry storms described above.
