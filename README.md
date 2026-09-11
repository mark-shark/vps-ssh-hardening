# vps-ssh-hardening

A [Claude Code](https://claude.com/claude-code) skill for hardening SSH access to a remote Linux server — and, more to the point, for not locking yourself out while doing it.

## Why this exists

Securing a machine you can only reach over SSH has an awkward property: the tool you would use to fix a mistake is the same tool you might break. A typo in `sshd_config`, an over-eager fail2ban rule, or a deleted key leaves you with a healthy server you cannot enter, and recovery then depends on a provider console that is often slow, unfamiliar, or broken exactly when you need it.

The techniques here are ordinary. The discipline around them is the point.

Most of the content came out of a single afternoon that went wrong: a two-hour lockout caused by fail2ban banning the operator's own address during verification testing, compounded by a misdiagnosis that sent everyone chasing a provider console they did not need. Each pitfall in `references/pitfalls.md` is written symptom-first, because the symptom is all you have when you start debugging.

## What is in it

```
SKILL.md                      workflow, and the two rules that prevent most disasters
references/
  pitfalls.md / pitfalls.cs.md  14 failure modes where the symptom points away from the cause
  hardening-steps.md            concrete config, in an order that cannot strand you
  recovery.md                   when you are already locked out
  key-rotation.md               adding, rotating and revoking keys safely
  agents-automation.md          access for CI and AI agent sessions
  macos-client.md               the client side: ssh_config, agent, Keychain, multiplexing
  monitoring.md                 health checks, and noticing silent regression
scripts/
  harden-ssh.sh                 hardening with a rollback timer and fresh-connection verification
  healthcheck.sh                periodic check, human log plus JSON
  swiftbar-plugin.sh            macOS menu-bar indicator reading that JSON
evals/evals.json                the test suite used to validate it
```

Pitfalls are available in English and Czech; everything else is English.

## The two rules

**Never change remote access without a way back that does not depend on the change succeeding.** Arm a rollback timer before editing, cancel it after verifying.

**Verify with a connection that shares nothing with your current one.** An open `ControlMaster` socket will happily keep serving commands after the credentials that created it have stopped working, so `ssh host` can succeed while real access is gone. Use `-o ControlPath=none`, and `-o IdentityAgent=none` when you want to prove a specific key file works on its own.

## Does it actually help?

It was measured against the same model without it, across four rounds of A/B tests with an independent grader. Final clean round: **26/26 with the skill, 13/26 without**, on three tasks (a diagnosis under a misleading premise, a hardening plan for live sites, and an auth failure that looks like the wrong thing).

Two findings worth stating plainly, because they cut both ways:

- On **writing hardening plans** the margin is narrow. A strong model already knows about rollback timers, `sshd -t`, `reload` over `restart`, and firewall ordering. The skill mostly adds polish there.
- On **diagnosis under a misleading signal** the margin is large, and it is not cosmetic. Without the skill, the model claimed three independent times — across two different scenarios — that a fail2ban ban would appear as `filtered` in the user's `nmap` scan. It does not: under a connect scan (`-sT`) the OS reports `ECONNREFUSED` for both a TCP RST and an ICMP port-unreachable, so a ban and a dead daemon are indistinguishable. Each time, that false premise demoted the ban hypothesis and produced a confident recommendation to go to the provider console for something a phone hotspot would have resolved in a minute.

The eval suite is included so you can check that rather than take my word for it.

## Installing

Copy the directory into your skills folder:

```bash
cp -R vps-ssh-hardening ~/.claude/skills/
```

Or package it as a `.skill` file and install it through the UI.

## Scope and caveats

Written against Debian/Ubuntu with systemd, and a macOS client. Service names, paths, and firewall tooling differ elsewhere — the reasoning transfers, the commands may not.

The bundled scripts are meant to be read and adapted, not run blind. `harden-ssh.sh` disables password authentication, which is exactly the change that locks people out; it refuses to proceed unless it can first prove key auth works on a fresh connection, but you should still read it before running it.

Source restrictions (`from=`, `Match Address`) are deliberately *not* recommended by default. They only make sense when the operator's addresses are predictable, and satellite links, mobile tethering, and roaming break that assumption in a way that locks you out while travelling.

## License

MIT
