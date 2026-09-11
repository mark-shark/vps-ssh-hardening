# Hardening steps

Concrete configuration for a Debian/Ubuntu host with systemd. Adapt paths and service names elsewhere (`sshd` instead of `ssh` on RHEL-family, no `ufw`, etc.).

## Order matters

1. Baseline — record current state
2. Deploy and **verify** key access
3. Whitelist yourself in fail2ban
4. Arrange a rollback net
5. Apply sshd hardening
6. Verify with a fresh connection
7. Firewall, then re-verify
8. Cancel the net

Doing 5 before 2 is the classic lockout. Doing 5 before 3 is how you ban yourself while testing.

---

## 1. Baseline

```bash
sshd -T | grep -iE '^(permitrootlogin|passwordauthentication|kbdinteractive|pubkeyauth|maxauthtries|port|x11forwarding) '
ssh-keygen -lf ~/.ssh/authorized_keys
stat -c "%a %U:%G %n" ~ ~/.ssh ~/.ssh/authorized_keys
last -20 -i
grep -c "Failed password" /var/log/auth.log
ss -tlnp | grep -v 127.0.0.1
```

The login history tells you which networks the user really comes from — needed before you consider any source restriction. The failed-password count tells you how much brute-force pressure the host is under, which is the honest argument for fail2ban.

## 2. Key access first

Deploy the public key, then verify with a connection that shares nothing:

```bash
ssh -o ControlPath=none -o BatchMode=yes -o IdentityAgent=none \
    -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_host user@host 'whoami'
```

If this does not print the username, **stop**. Everything below assumes key auth works.

## 3. fail2ban, with yourself whitelisted

```bash
apt-get install -y fail2ban
```

`/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
# Your own networks. Without this, your own verification tests will ban you.
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
# List every port sshd listens on, or the extra ones are unprotected
port     = ssh
filter   = sshd
maxretry = 3
bantime  = 2h
```

```bash
systemctl enable --now fail2ban
fail2ban-client status sshd
fail2ban-client get sshd ignoreip
```

A whitelisted range weakens the jail for attackers sharing it. With password authentication disabled that is a small price — the jail is then mostly noise reduction, not the thing holding the door. Say this out loud when recommending it rather than presenting the whitelist as free.

## 4. Rollback net

```bash
mkdir -p /root/ssh-backup
cp /etc/ssh/sshd_config /root/ssh-backup/sshd_config.orig

cat > /root/ssh-backup/rollback.sh <<'RB'
#!/bin/bash
rm -f /etc/ssh/sshd_config.d/99-hardening.conf
cp /root/ssh-backup/sshd_config.orig /etc/ssh/sshd_config
systemctl reload ssh 2>/dev/null || systemctl restart ssh
ufw --force disable 2>/dev/null
logger -t ssh-hardening "AUTOMATIC ROLLBACK EXECUTED"
RB
chmod +x /root/ssh-backup/rollback.sh

systemd-run --on-active=600 --unit=ssh-rollback /root/ssh-backup/rollback.sh
```

Cancel it only after verification succeeds:

```bash
systemctl stop ssh-rollback.timer
systemctl reset-failed ssh-rollback.timer
```

## 5. sshd hardening as a drop-in

Check that the main config includes drop-ins, and **where**:

```bash
grep -n '^Include' /etc/ssh/sshd_config
```

`sshd_config` takes the first value for each option, so an `Include` near the top means the drop-in wins over directives later in the file. If the `Include` is absent or at the bottom, edit the main file instead — otherwise your settings silently lose.

Check what is already in that directory before writing into it:

```bash
grep -rn "PasswordAuthentication\|PermitRootLogin" /etc/ssh/sshd_config.d/
```

Ubuntu cloud images ship `50-cloud-init.conf` with `PasswordAuthentication yes`, and `50-` sorts before `99-`. Drop-ins expand in lexical order and first value wins, so that file beats your hardening and passwords keep working. Edit or remove it rather than assuming a higher number means higher priority.

`/etc/ssh/sshd_config.d/99-hardening.conf`:

```
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
```

`KbdInteractiveAuthentication no` is not redundant. With `UsePAM yes`, leaving it enabled lets PAM accept passwords through keyboard-interactive even though `PasswordAuthentication` is off — a back door that looks closed in the config.

Validate, then reload:

```bash
sshd -t && systemctl reload ssh
sshd -T | grep -iE '^(permitrootlogin|passwordauthentication|kbdinteractive) '
```

`reload` re-reads the config and rebinds listeners without dropping existing sessions — keep them; they are your second safety net.

## 6. Verify from outside

```bash
# key auth still works, on a brand-new connection
ssh -o ControlPath=none -o BatchMode=yes user@host 'echo OK'

# password auth is genuinely gone — server should offer publickey only
ssh -v -o ControlPath=none -o PubkeyAuthentication=no user@host true 2>&1 \
  | grep 'can continue'
# expected: debug1: Authentications that can continue: publickey
```

The second check matters: `sshd -T` shows intent, this shows behaviour.

## 7. Firewall

Add the SSH rule **before** enabling, or you cut yourself off:

```bash
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
```

Then immediately verify a fresh SSH connection *and* that the services still answer.

`ufw enable` rewrites the firewall tables and can wipe fail2ban's chains. Restart fail2ban and confirm:

```bash
systemctl restart fail2ban
iptables -S | grep f2b
```

## A second SSH port

Restrictive networks (corporate guest wifi, some mobile carriers) allow only 80/443 outbound. A second port helps — if the firewall and jail both know about it:

```
Port 22
Port 2222
```

```ini
[sshd]
port = ssh,2222
```

```bash
ufw allow 2222/tcp
sshd -t && systemctl reload ssh
ss -tlnp | grep -E ':(22|2222)\b'
iptables -S | grep f2b-sshd     # expect --dports 22,2222
```

For networks that block everything but 443, `sslh` multiplexes SSH and HTTPS on one port. It sits in front of the web server, so treat it as a change to the site's traffic path and verify the site after every step.

## Persistence

```bash
systemctl is-enabled ssh fail2ban ufw
```

A hardening that does not survive a reboot is a hardening you will lose without noticing.
