# Pitfalls: when the symptom points away from the cause

Each entry starts with what you *see*, because that is what you have when you start debugging. These are ordered roughly by how often they waste time.

---

## "Server accepts key" — then Permission denied anyway

```
debug1: Server accepts key: /Users/x/.ssh/id_rsa RSA SHA256:qNak… explicit
debug1: Offering public key: /Users/x/.ssh/id_ed25519 …
user@host: Permission denied (publickey).
```

**The key is authorized.** The server confirmed it during the public-key probe. What failed is the *signature* step: the client could not use the private key.

Almost always a passphrase-protected key that is not loaded in the agent, combined with `BatchMode=yes` (or any non-interactive context), which forbids the prompt. The client silently gives up and moves to the next key.

Check:

```bash
ssh-keygen -y -P "" -f ~/.ssh/id_rsa >/dev/null 2>&1 \
  && echo "no passphrase" || echo "passphrase-protected"
ssh-add -l
```

Fix: load it (`ssh-add --apple-use-keychain ~/.ssh/id_rsa` on macOS), or use a passphrase-less key for automation.

**Why this misleads:** it is indistinguishable at a glance from "key not authorized", so people go and re-deploy a key that was already fine.

**Confirming it is the client, not the server.** `ssh -vvv` shows whether the client ever attempted a signature:

```
debug3: sign_and_send_pubkey: using ...        ← client tried to sign
```

If that line is absent after `Server accepts key`, the client never signed and the cause is local: no usable private key, a passphrase it cannot ask for, or an agent it cannot reach. If the line *is* present and the server still refuses, look server-side instead — account expiry, `AllowUsers`/`DenyUsers`, `AuthenticationMethods` requiring a second factor, or `from=`/`expiry-time` options on the key's line in `authorized_keys`.

A variant that specifically fits "works by hand, fails in my script": the key is in the agent, but cron, launchd, or systemd does not inherit `SSH_AUTH_SOCK`, so the scripted run has no agent to ask. Check `echo "$SSH_AUTH_SOCK"` *inside* the script, not in your shell.

---

## A connect scan cannot tell a ban from a dead service

`nmap -sT` (connect scan, the default without root) asks the OS to open a socket. The OS reports `ECONNREFUSED` for **both** a TCP RST *and* an ICMP port-unreachable. fail2ban's default `REJECT --reject-with icmp-port-unreachable` therefore looks exactly like "nothing is listening":

```
22/tcp closed ssh conn-refused      ← could be a ban, could be a dead sshd
```

The reasoning "it is `closed`, not `filtered`, so it is not the firewall" is invalid with `-sT`.

Distinguish with a SYN scan (`nmap -sS`, needs root), or settle it from inside:

```bash
systemctl show ssh -p ActiveEnterTimestamp   # has sshd actually restarted?
grep <your-ip> /var/log/fail2ban.log         # Ban / Unban lines with timestamps
```

Another trap in the same family: a port that the firewall *allows* while nothing listens also returns RST. So a second "closed" port is not corroboration — it may be closed for an entirely different reason.

---

## fail2ban bans you for testing your own hardening

Verifying that the old key no longer works, or that a passwordless attacker is refused, means generating failed authentications from your own address. With `maxretry = 3` that is three commands.

The ban then looks like a server outage, and waiting it out fails if anything keeps retrying — a stale key in an IDE, an agent session, a cron job — because each attempt can start a fresh ban.

**Add your network to `ignoreip` before testing:**

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24
```

Reload fail2ban and confirm with `fail2ban-client get sshd ignoreip`.

---

## `ssh-copy-id` fails without prompting for a password

```
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed …
user@host: Permission denied (publickey,password,keyboard-interactive).
```

No password prompt appeared. If the client config has `PreferredAuthentications publickey` — common in a hardened `Host *` block — ssh never attempts the password, so `ssh-copy-id` has no way to authenticate and install the key.

```bash
ssh-copy-id -o PreferredAuthentications=password,keyboard-interactive -i key.pub user@host
```

Worth remembering whenever bootstrapping access to a *new* machine: the hardening you applied for your servers also applies to hosts you have not set up yet.

---

## Wrong username looks exactly like wrong password

sshd deliberately treats a nonexistent user like a wrong password, so account names cannot be enumerated. "It won't take my password" often means "that account does not exist here".

Check the actual short name on the target — on macOS, *System Settings → General → Sharing → Remote Login* prints the exact `ssh user@host` command. Do not assume the username matches the one on the machine you are sitting at.

---

## authorized_keys silently ignored (StrictModes)

Auth fails, the key is definitely in the file, and the server log says nothing useful. With `StrictModes yes` (the default), sshd refuses to read `authorized_keys` when the ownership or permissions are too loose — and does not explain why.

```bash
stat -c "%a %U:%G %n" ~ ~/.ssh ~/.ssh/authorized_keys
```

Home must be owned by the user and not group/world-writable; `~/.ssh` should be `700`; `authorized_keys` `600`. A directory owned by a *different* user — easy to create by copying files around as root — disables the account's key auth entirely.

---

## You disabled password login and passwords still work

Your drop-in says `PasswordAuthentication no`, `sshd -t` passes, the service reloaded — and a password login still succeeds. Nothing is broken; your file simply lost.

`sshd_config` takes the **first** value for each option, and `Include /etc/ssh/sshd_config.d/*.conf` expands in lexical order. Ubuntu cloud images ship `/etc/ssh/sshd_config.d/50-cloud-init.conf` containing `PasswordAuthentication yes`. `50-` sorts before `99-`, so cloud-init wins and your hardening is inert.

```bash
grep -rn "PasswordAuthentication\|PermitRootLogin" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
sshd -T | grep -i passwordauthentication     # what is actually in force
```

Fix by editing or removing the lower-numbered file, or by naming your drop-in something that sorts earlier. Either way, trust `sshd -T` over the file you just wrote — and better still, prove it from outside:

```bash
ssh -v -o ControlPath=none -o PubkeyAuthentication=no user@host true 2>&1 | grep 'can continue'
# want: debug1: Authentications that can continue: publickey
```

The same ordering rule explains several silent failures: a directive in the main config below the `Include` line cannot override a drop-in, and two drop-ins setting the same option resolve by filename, not by intent.

---

## `Host *` overrides the blocks below it

`ssh_config` takes the **first** value found for each option, so a `Host *` block placed early wins over specific blocks that come later. `IdentityFile` is worse: it *accumulates*, in order of appearance, so a generic key listed early is offered **before** the host-specific one.

That can authenticate you as the wrong identity on services where both keys are registered.

```bash
ssh -G somehost | grep -E '^(user|identityfile|port) '
```

`ssh -G` prints what actually applies. Keep `Host *` last in the file.

---

## Multiplexing hides broken authentication

An open `ControlMaster` connection serves new commands without re-authenticating. After you rotate a key, revoke access, or get banned, `ssh host` can keep working from the shared socket — so tests pass while real access is gone.

Always verify with `-o ControlPath=none`, and add `-o IdentityAgent=none` when you want to prove a specific key file works on its own.

---

## A key's comment is published to every server it touches

The trailing comment in a public key (`user@corporate-domain.example`) is stored verbatim in `authorized_keys` and shows up in logs. It leaks where the key came from, and it is what people see when auditing access months later.

Use it deliberately: name the *machine or role* (`vps-root@mac-mini`, `ci-deploy@gitlab`). Changing it later with `ssh-keygen -c` requires the passphrase, which you may not have — so choose well at creation time.

---

## macOS Keychain is locked inside SSH sessions

A tool that stores credentials in the login Keychain reports "not logged in" when run over SSH, even though it works fine on the desktop:

```
security: SecKeychainCopySettings … User interaction is not allowed.
```

The login Keychain unlocks at GUI login, not for SSH sessions. Unlock it explicitly:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

Note the trade-off out loud: this exposes *everything* in that Keychain to processes in that session for its duration. A long-lived token, or running the tool in a graphical session (Screen Sharing), avoids it.

---

## `PATH` is minimal in non-interactive SSH

```bash
ssh host 'command -v some-tool'   # nothing
ssh host 'zsh -lc "command -v some-tool"'   # /opt/homebrew/bin/some-tool
```

Non-interactive SSH gets `/usr/bin:/bin:/usr/sbin:/sbin` — no Homebrew, no user-local bins. Concluding "it isn't installed" from the first result is wrong. Use a login shell or an absolute path.

---

## ControlPersist backgrounds the master, so supervisors see it exit

Running `ssh -M -N host` under a process supervisor (launchd, systemd) exits immediately with status 0 when `ControlPersist` is set, because the master forks into the background. The supervisor thinks the job crashed and restarts it forever.

Use `-o ControlPersist=no` for the supervised process so it stays in the foreground.

Related: a hard kill leaves a stale socket file that a new master cannot bind, and it then *silently* runs without multiplexing. A wrapper that checks `ssh -O check` and removes the dead socket first avoids a puzzling loss of performance.

---

## Enabling ufw can flush fail2ban's rules

`ufw enable` rewrites the firewall tables and can remove chains fail2ban installed. The jail still reports itself as active while no longer blocking anything.

After enabling or reloading ufw, restart fail2ban and confirm the rules exist:

```bash
systemctl restart fail2ban
iptables -S | grep f2b
```

---

## A mail relay that sends fine but cannot write its own log

`msmtp` (or a similar relay) delivers mail successfully — `smtpstatus=250` — while printing:

```
send-mail: cannot log to /var/log/msmtp.log: cannot open: Permission denied
```

Two causes stack here, and fixing only the obvious one leaves you puzzled.

**The binary is setgid.** `/usr/bin/msmtp` ships as `-rwxr-sr-x root msmtp`, so it runs with group `msmtp`, not as your user. A log file owned `root:root` with mode `600` is unreachable for it. `chown root:msmtp` plus `660` fixes that half.

**AppArmor confines it anyway.** Ubuntu ships a profile that permits logs only under `@{HOME}/.msmtp*.log`. Ownership changes do not help:

```bash
journalctl -k --since "5 min ago" | grep -i "apparmor.*DENIED"
```

A third wrinkle makes this genuinely confusing: the profile can be **loaded and enforcing in the kernel while marked disabled on disk** (a symlink in `/etc/apparmor.d/disable`). `apparmor_parser -r` then refuses with "Skipping profile in /etc/apparmor.d/disable" and your local override is never applied, while the running profile keeps denying.

Point the log at a path the profile already permits (`/root/.msmtp.log` when running as root) rather than unloading the profile. Weakening confinement of the program that talks to the outside world, for the sake of a log file, is a bad trade.

---

## Opening a second SSH port without extending the jail

Adding `Port 2222` for networks that block 22 also creates an unprotected brute-force surface, because the jail watches only the port it was configured with.

```ini
[sshd]
port = ssh,2222
```

Verify: `iptables -S | grep f2b-sshd` should show `--dports 22,2222`.
