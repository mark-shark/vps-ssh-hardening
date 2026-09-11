# When you cannot get in

The goal here is to find the *actual* cause before spending an hour on the wrong remedy. A wrong diagnosis delivered confidently is worse than an honest "I can't tell from outside yet" — it sends someone chasing a provider console they never needed.

## Diagnose from outside, in this order

**Is the host alive at all?**

```bash
ping -c 3 <host>
curl -s -o /dev/null -w '%{http_code}\n' -k https://<host>    # if it serves web
```

If the web still answers, the machine is running and you are looking at something SSH-specific. That is good news and worth telling the user immediately — it removes the scariest possibility.

**Does port 22 refuse, or go silent?**

```bash
nc -z -G 6 <host> 22 && echo open || echo "refused or timed out"
```

Refusal means packets reach the host. Silence usually means a firewall dropping them, or a network problem in between.

**Do not stop here.** A connect scan (`nmap -sT`, or `nc`) cannot distinguish a fail2ban rejection from a dead sshd — the OS reports both as `ECONNREFUSED`. See `pitfalls.md`. If you have root locally you can use `nmap -sS` to tell RST from ICMP unreachable; otherwise this question is simply not answerable from outside, and saying so is the correct move.

**Stop retrying, and say so first.** This is the one instruction to give before any diagnosis, because the user is almost certainly still hammering the connection while they talk to you. If the cause is a ban, every further attempt can start a fresh `bantime` — so waiting it out never ends, and the outage looks permanent when it would have cleared on its own.

Also find and stop whatever else is retrying on a schedule: an IDE with a stale remote, a deploy job, a health check, a mounted SSHFS, another agent session using a key you rotated. These are invisible to the user and are the usual reason a ban appears never to expire. Tell them to stop those before testing anything.

**Do you still have any live session?** An existing SSH connection, a `ControlMaster` socket, another machine, a CI runner with its own key, a colleague. Existing connections survive bans and most config breakage:

```bash
ssh -O check <host>         # is a master still alive?
```

If one exists, use it immediately to diagnose — and do not close it.

## Settle it from inside

Two commands end the guessing:

```bash
systemctl show ssh -p ActiveEnterTimestamp -p ActiveState
grep <your-ip> /var/log/fail2ban.log | tail
```

`ActiveEnterTimestamp` tells you when sshd last started. If it predates the outage, sshd never went down and the cause is elsewhere. The fail2ban log shows `Ban` / `Unban` lines with exact timestamps.

Correlate with the last time access worked. If you have monitoring, its log gives you the minute the outage began — which, combined with the configured `bantime`, predicts when a ban will lift.

## Getting in when SSH is gone

**Another network.** If the cause is an IP ban, any other address works: phone tethering, VPN, a machine elsewhere. This is usually the fastest route and people forget it.

**A key that still works.** A rescue key stored in a password manager, or a CI key that authenticates from cloud addresses which are not banned.

**The provider console.** The universal fallback, and the one most likely to surprise you:

- Some providers offer an in-browser console (noVNC or similar). If it will not open, try another browser and allow pop-ups before concluding it is broken.
- Others expose a **real VNC server at the hypervisor level** with its own address, port, and separate VNC password set in the panel. That is not the same as your server's root password, and the VNC listener may only start once the password is set. You need a VNC client, not a browser.
- Most panels also offer **rescue mode** (boots a recovery system with your disk attached) and **password reset**. Rescue mode is the stronger tool when sshd itself is broken.

**Keyboard layout in consoles.** Browser and VNC consoles frequently assume a US layout. A password with special characters can be typed correctly and still be wrong. If a known-good password fails in a console, suspect this before suspecting the password.

## Once inside

```bash
fail2ban-client set sshd unbanip <ip>
systemctl stop fail2ban            # if you need room to work safely
```

Stopping fail2ban while you fix things is often better than unbanning: it guarantees you will not be ejected mid-repair. Re-enable it — with `ignoreip` corrected — before you leave.

If sshd genuinely failed to start:

```bash
journalctl -u ssh -n 50 --no-pager
sshd -t
```

`sshd -t` catches the typo that stopped it from coming back after a restart, which is the most common cause.

## Prevention, stated plainly

Every lockout in practice traces to one of these:

- A change applied without a rollback path
- Verification done over a connection that was already open
- Password auth disabled before key auth was proven
- Testing failure cases from an address the jail was watching
- A single key, on a single machine, with no independent backup

The rescue key is the cheapest insurance of the lot: one key, unrestricted, stored off the machine in a password manager, deliberately exempt from source restrictions. It costs one line in `authorized_keys` and it is what turns a two-hour outage into a two-minute one.
