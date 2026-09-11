# Monitoring a hardened server

Hardening is a state, not an event. A package update re-enables a setting, a certificate expires, a service fails to come back after a reboot, a disk fills. The point of monitoring here is not uptime graphs — it is noticing that the thing you configured has quietly stopped being true.

## What to check, and why each earns its place

| Check | Why |
|---|---|
| SSH reachable + key auth | Proves the whole access path, not just that a port is open |
| `PasswordAuthentication` still `no` | **Silent regression is the failure you would never notice.** A package update or a helpful script can undo it |
| Services active (sshd, firewall, fail2ban, web) | A service that failed to restart looks fine until you need it |
| TLS certificate expiry | Fails at a predictable moment, always inconvenient, always avoidable |
| HTTPS reachability of each hosted domain | Catches DNS, firewall, vhost, and certificate problems from the visitor's side |
| Disk, memory, load | The slow failures |
| Reboot required | Kernel updates that nobody applied |

Checking the hardening itself is the one people leave out, and it is the highest-value item. Everything else has other alarms; a silently re-enabled password login has none.

## Design choices worth keeping

**Check the domains from the client, not the server.** Running `curl` from the machine that hosts the sites only proves the web server is up. From outside you also exercise DNS, the firewall, the vhost mapping, and certificate validity — `curl` without `-k` fails on a bad certificate, which is exactly what you want.

**One SSH connection per run.** Gather all server-side values in a single session that emits `key=value` lines, then parse locally. Ten connections per run is ten times the auth load and ten times the chance of tripping a jail.

**Check domains in parallel.** Twelve domains with a ten-second timeout is two minutes if serial. In parallel it is one timeout.

**Report slow responses only after two consecutive readings.** A backend waking from idle produces one slow response and nothing is wrong. Requiring two in a row removes that noise while still catching real degradation, one interval later. Keep a small state file listing what was slow last run.

**Notify on state *change*, not on state.** Alerting every 15 minutes during a two-hour outage trains people to ignore the alert. Notify when the status changes, and again when it recovers.

**Write machine-readable output alongside the human log.** A JSON file lets a status indicator, a dashboard, or another tool consume the result without parsing prose:

```json
{
  "ts": "2026-09-11 22:20:55",
  "level": "OK",
  "disk_pct": 32,
  "cert_days": 50,
  "domains_total": 12,
  "domains_bad": 0,
  "problems": []
}
```

## Scheduling

On macOS, a launchd agent with `StartInterval` runs the check periodically and, unlike cron, fires after the machine wakes. On Linux, a systemd timer or cron.

Fifteen minutes is a reasonable default: fast enough to notice an outage, slow enough not to be noise. Certificate expiry does not need that cadence, but it costs nothing to fold in.

Use `StartInterval` rather than `KeepAlive` — the job should run and exit, not run forever.

## Status indicator

A menu-bar indicator answers "is everything fine?" without opening anything. On macOS, [SwiftBar](https://github.com/swiftbar/SwiftBar) or xbar runs a script and renders its output.

Have the indicator **read the JSON**, not perform its own checks. Two independent schedulers hitting the same server doubles the load and the auth attempts, and the menu bar should redraw instantly rather than waiting on a network round trip.

Treat stale data as its own alarm: if the JSON timestamp is older than roughly 1.5× the check interval, the monitoring itself has stopped — which is worth knowing and is invisible if you only render the last known status.

Useful states: OK, warning, failure, and *stale*. Rendering only the first three hides the case where nothing has run for a day.

## E-mail, for when the workstation is off

A menu-bar indicator only works while you are looking at that machine. A daily digest sent from the server covers the rest, and it is the only channel that survives you being on holiday.

`scripts/email-digest.py` renders the same data as an HTML mail. Three decisions in it are worth keeping if you write your own:

**One digest, not a mail per event.** A server on the open internet is banned dozens of times a day. Per-event mail stops being read within a week, and an alert nobody reads is worse than no alert, because it feels like coverage.

**Lead with the verdict, not the numbers.** Subject and headline say *all clear* / *needs attention* / *problem*; the counts are below. Accent colour carries the same signal, so the state is legible before a word is read.

**The section worth reading daily is successful logins** — who got in, from where, with which method. Ban counts are noise; an unexpected login is not.

### Getting mail out of a server

Most minimal VPS images have no MTA at all. Two routes:

- **A relay** (`msmtp` plus `msmtp-mta`) forwarding through an SMTP provider you already use. One small package, no listening daemon.
- **Direct sending** (postfix). Expect poor deliverability: hosting IP ranges are widely blocklisted and mail without SPF/DKIM alignment is junked. Not worth it for alerts you need to arrive.

If the machine already runs an application that sends mail, its configuration usually holds working credentials. Copying a secret **between files on the server** keeps it out of your terminal history and out of any transcript:

```bash
grep -m1 '^SMTP_PASSWORD=' /path/to/app/.env | cut -d= -f2- | tr -d '"' > /etc/msmtp-password
chmod 600 /etc/msmtp-password
```

Environment variable names differ between projects (`SMTP_PASSWORD` vs `SMTP_PASS`, `SMTP_USERNAME` vs `SMTP_USER`). Grepping for one spelling and finding nothing is not evidence that mail is unconfigured — list the keys before concluding anything.

### Two traps specific to msmtp

`/usr/bin/msmtp` is **setgid** to group `msmtp`, so it does not run as your user and cannot write a log owned `root:root` with mode `600`. And Ubuntu's AppArmor profile permits logs only under `@{HOME}/.msmtp*.log`, so fixing ownership alone changes nothing. Point the log at a permitted path rather than unloading the profile — `references/pitfalls.md` has the full shape, including the case where the profile is enforcing in the kernel while marked disabled on disk.

### HTML that survives real mail clients

Outlook on Windows renders through Word: no flex, no grid, no `<style>` rules beyond the basics. Everything structural has to be a `<table>` with inline styles. Send `multipart/alternative` so a text client and a watch notification still get something readable.

If you embed a header image, the structure matters:

```
multipart/related
├── multipart/alternative
│   ├── text/plain
│   └── text/html
└── image/png   <content-id>
```

The image must be a **sibling** of the alternative part, not inside it — some clients will not resolve the `cid:` reference otherwise and show a broken image. Mark it `Content-Disposition: inline` or it appears as an attachment. Keep a text-header fallback for when the asset is missing; an empty strip with a broken-image icon looks worse than plain text.

Set `Auto-Submitted: auto-generated` so out-of-office autoresponders do not reply to a robot.

## Notifications on macOS

`osascript -e 'display notification …'` is the obvious approach and frequently does nothing. Notifications are delivered under the identity of a registered application, and the interpreter may not be registered — the command exits 0 having shown nothing.

Check whether anything plausible is registered:

```bash
plutil -convert xml1 -o - ~/Library/Preferences/com.apple.ncprefs.plist \
  | grep -iE 'script|terminal'
```

If nothing matches, notifications from a script will not appear no matter how correct the code is. A menu-bar indicator sidesteps the problem entirely, which is one good reason to prefer it as the primary channel. A helper with its own bundle identifier (such as `terminal-notifier`) is the alternative.

**`exit 0` from `osascript` does not mean a notification appeared.** Verify by asking a human whether they saw it, and say plainly that the exit code proves only that the command ran.

## Ordering warning

Whatever you build, make sure the monitoring's own SSH access is whitelisted in fail2ban, and that its key is passphrase-less or reliably loaded in an agent. A health check failing on authentication produces alarming output that has nothing to do with the server.

See `scripts/healthcheck.sh` and `scripts/swiftbar-plugin.sh` for working implementations of all of the above.
