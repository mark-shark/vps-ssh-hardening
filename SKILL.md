---
name: vps-ssh-hardening
description: Harden SSH access to a remote Linux server (VPS, cloud instance, dedicated box) and keep it monitored, without locking yourself out. Use this skill whenever the user wants to secure SSH, disable password login, set up fail2ban or ufw, rotate or deploy SSH keys, fix "Permission denied (publickey)", recover from being locked out of a server, audit who can reach root, or set up health monitoring for a server they administer — even if they only say something like "my SSH stopped working", "make the server safe", "set up a key for my other machine", or "why can't I connect". Also use it before touching sshd_config, authorized_keys, or firewall rules on any machine reached over the network, because those edits can sever your only way in.
---

# Hardening remote SSH access without locking yourself out

Securing a server you can only reach over SSH has an unusual property: **the tool you use to fix mistakes is the same tool you might break.** A typo in `sshd_config`, an over-eager fail2ban rule, or a deleted key can leave you with a running server you cannot enter. Recovery then depends on a provider console that may be slow, unfamiliar, or broken exactly when you need it.

Everything here follows from that. The techniques are ordinary; the discipline around them is what matters.

## The two rules that prevent most disasters

**1. Never change remote access without a way back that does not depend on the change succeeding.**

Before editing `sshd_config`, `authorized_keys`, or firewall rules, arrange a safety net. On systemd hosts:

```bash
# Restores config and reloads in 10 minutes unless you cancel it
systemd-run --on-active=600 --unit=ssh-rollback /root/backup/rollback.sh
```

Do the work, verify it, then cancel the timer. If you lose the connection mid-change, the server repairs itself. Keep an already-open session as a second net — an existing connection survives changes that would block a new one.

**2. Verify with a connection that shares nothing with your current one.**

This is the rule people skip, and it produces false confidence. A live `ControlMaster` socket will happily serve new commands *after* the credentials that created it have stopped working. Existing sessions survive bans and config breakage. So the only meaningful test is a fresh connection:

```bash
ssh -o ControlPath=none -o BatchMode=yes -o IdentityAgent=none user@host 'echo OK'
```

`ControlPath=none` bypasses multiplexing, `IdentityAgent=none` ignores keys already loaded in the agent. If that succeeds, access genuinely works.

## Workflow

Work in this order. Each step is cheap; skipping one is how sessions turn into outages.

**Establish a baseline.** Confirm what works now, so you can tell later whether you broke it. Record which keys are authorized (`ssh-keygen -lf ~/.ssh/authorized_keys`), what `sshd -T` reports, and which users log in from where (`last`, `/var/log/auth.log`). Without this you cannot distinguish "my change broke it" from "it was already broken".

**Make key access work before removing password access.** Deploy and *verify* the key first. Disabling passwords while key auth is subtly broken is the classic lockout.

**Whitelist yourself in fail2ban before you test anything.** Verifying that a bad key is rejected means generating failed authentications — against your own jail. Add your network to `ignoreip` first. See `references/pitfalls.md`; this one bites hard.

**Harden, validating before applying.** `sshd -t` catches syntax errors before a reload can act on them. Prefer a drop-in under `/etc/ssh/sshd_config.d/` over editing the main file: it is self-contained, trivially reversible, and leaves the distribution config intact. Prefer `reload` over `restart` — existing sessions survive it.

**Verify freshly, then cancel the safety net.** Only after a fresh connection succeeds.

Detailed commands, config, and rationale: `references/hardening-steps.md`.

## Identity model: one key per machine

Give every machine and every automated agent its own key, with a comment naming it:

```bash
ssh-keygen -t ed25519 -C "vps-root@mac-mini" -f ~/.ssh/id_ed25519_vps_root
```

The comment lands in `authorized_keys` and in auth logs, so you can see who connected and revoke one machine without disturbing the others. A shared key gives you neither.

Generate each key **on the machine that will use it** so the private half never travels. Only the public key moves.

Keep one **rescue key** that is not tied to any machine, stored in a password manager, and deliberately exempt from any source restrictions you apply. It is what you reach for when the normal path fails — and if you never remove it from the machine that generated it, it is not a rescue key, just a second key in the same basket.

## Restricting *where* keys may be used

`from="10.0.0.0/24"` in `authorized_keys` and `Match Address` in `sshd_config` both limit source addresses. They are worth using **only when the user's addresses are predictable.**

Check before recommending them. Satellite links (Starlink), mobile tethering, CGNAT, and roaming between networks produce addresses that jump between unrelated blocks. Look at where the user has actually connected from:

```bash
last -100 -i | awk '{print $3}' | grep -E '^[0-9]' | sort -u
```

If those span multiple unrelated ranges, source restriction will lock them out during travel rather than protect them, and the key-per-machine model is the control that actually matches "only these machines". Say so plainly rather than implementing a rule that will fail later.

## When the user is already locked out

Resist the urge to guess. `Connection refused` has several causes that look identical from outside, and picking the wrong one sends the user chasing a console they do not need. Diagnose in this order:

1. Is the host reachable at all? (`ping`, and whether other ports like 80/443 respond)
2. Does port 22 refuse, or time out? Refusal means packets reach the host.
3. **Do not conclude "sshd is down" from a connect scan.** `nmap -sT` reports a fail2ban rejection and a dead service identically — see `references/pitfalls.md`.
4. Get inside by any route (provider console, another machine, an existing session) and check `systemctl show ssh -p ActiveEnterTimestamp` and `/var/log/fail2ban.log`. These settle it in seconds.

If you cannot get inside, say what you know and what you do not, rather than presenting a guess as a diagnosis. A confident wrong answer costs more than an honest "I can't tell from here".

## Pitfalls

`references/pitfalls.md` (English) and `references/pitfalls.cs.md` (Czech) collect failures that are hard to diagnose because the symptom points away from the cause — a passphrase-protected key that looks like a rejected key, `ssh-copy-id` that cannot fall back to a password, `authorized_keys` silently ignored because of directory ownership, a config block that overrides the ones below it.

**Read `references/pitfalls.md` before diagnosing any "Permission denied" or lockout.** Each entry names the symptom first, so you can match what you are seeing.

## Monitoring

Hardening is a state that decays: a package update re-enables a setting, a certificate expires, a service fails to come back after a reboot. `references/monitoring.md` covers a periodic health check (disk, memory, load, services, **whether the hardening is still in place**, certificate expiry, HTTPS reachability of the sites the server hosts) and a menu-bar indicator.

Two design points worth keeping if you adapt it: check that `PasswordAuthentication` is *still* `no`, because silent regression is the failure you would otherwise never notice; and report slow responses only after two consecutive readings, so a cold start does not cry wolf.

## Further references

Read the one that matches the task; they are written to be used on their own.

| File | Read it when |
|---|---|
| `references/pitfalls.md` | **Any** "Permission denied", lockout, or confusing auth failure. Start here. |
| `references/pitfalls.cs.md` | Same content in Czech, for humans who prefer it |
| `references/hardening-steps.md` | Applying sshd hardening, fail2ban, ufw |
| `references/recovery.md` | The user cannot get in by any normal route |
| `references/key-rotation.md` | Replacing, adding, or revoking a key |
| `references/agents-automation.md` | Giving CI or an AI agent session its own access |
| `references/macos-client.md` | The client side: `~/.ssh/config`, agent, Keychain, multiplexing |
| `references/monitoring.md` | Health checks and a status indicator |

## Bundled scripts

Adapt rather than run blind — hosts differ.

- `scripts/harden-ssh.sh` — hardening with rollback timer, validation, and fresh-connection verification
- `scripts/healthcheck.sh` — periodic check, human log plus JSON for other tools
- `scripts/swiftbar-plugin.sh` — macOS menu-bar indicator reading that JSON
- `scripts/email-digest.py` — daily HTML digest by mail, for when the workstation is off

## Reporting honestly

State what you verified and how. "Works" without saying which connection proved it is the claim that hides a `ControlMaster` artifact. If a step was skipped or a test was inconclusive, say so — on a machine whose only door is SSH, an unverified assumption is the thing that strands someone.
