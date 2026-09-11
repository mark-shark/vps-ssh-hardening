#!/bin/bash
#
# Harden SSH on a remote host, with a rollback timer so a mistake repairs itself.
#
#   ./harden-ssh.sh <ssh-target> <your-network-cidr> [extra-port]
#   ./harden-ssh.sh myserver 203.0.113.0/24 2222
#
# Read this before running it. It disables password authentication, which is
# exactly the change that locks people out when key auth is not actually working.
# The script refuses to proceed unless it can prove key auth first.
#
# Assumes Debian/Ubuntu with systemd. Elsewhere the service may be "sshd" and
# there may be no ufw.

set -u

TARGET="${1:?usage: $0 <ssh-target> <your-network-cidr> [extra-port]}"
MYNET="${2:?second argument: your network in CIDR form, e.g. 203.0.113.0/24}"
EXTRA_PORT="${3:-}"
ROLLBACK_MIN=10

say() { printf '\n=== %s ===\n' "$1"; }

# A connection that shares nothing with any existing one. ControlPath=none
# bypasses multiplexing (an open master would answer even if auth is broken)
# and IdentityAgent=none ignores keys already loaded in the agent.
fresh() {
    ssh -o ControlPath=none -o BatchMode=yes -o IdentityAgent=none \
        -o ConnectTimeout=20 "$TARGET" "$@"
}
remote() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$TARGET" "$@"; }

# ---------------------------------------------------------------------------
say "0. Preflight: does key authentication already work?"
if ! fresh 'echo ok' >/dev/null 2>&1; then
    echo "FAIL: cannot reach $TARGET with key auth on a fresh connection."
    echo "Fix that first — disabling passwords now would lock you out."
    exit 1
fi
echo "key auth OK as $(fresh 'whoami')"

say "1. Baseline"
remote 'sshd -T 2>/dev/null | grep -iE "^(permitrootlogin|passwordauthentication|kbdinteractive|maxauthtries|port) "'
remote 'echo "authorized keys:"; ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null | sed "s/^/  /"'

# fail2ban BEFORE hardening: verifying the hardening means producing failed
# logins from this address, which is exactly what the jail bans.
say "2. fail2ban, with this network whitelisted"
remote "export DEBIAN_FRONTEND=noninteractive
command -v fail2ban-client >/dev/null 2>&1 || apt-get install -y -qq fail2ban >/dev/null 2>&1
PORTS='ssh'; [ -n '${EXTRA_PORT}' ] && PORTS='ssh,${EXTRA_PORT}'
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 ${MYNET}
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = \$PORTS
filter   = sshd
maxretry = 3
bantime  = 2h
EOF
systemctl enable --now fail2ban >/dev/null 2>&1
sleep 3
fail2ban-client get sshd ignoreip 2>/dev/null | tail -4"

say "3. Rollback timer (${ROLLBACK_MIN} min) — cancelled only after verification"
remote "mkdir -p /root/ssh-backup
cp -n /etc/ssh/sshd_config /root/ssh-backup/sshd_config.orig 2>/dev/null
cp /etc/fail2ban/jail.local /root/ssh-backup/jail.local.bak 2>/dev/null
cat > /root/ssh-backup/rollback.sh <<'RB'
#!/bin/bash
rm -f /etc/ssh/sshd_config.d/99-hardening.conf
cp /root/ssh-backup/sshd_config.orig /etc/ssh/sshd_config
systemctl reload ssh 2>/dev/null || systemctl restart ssh
ufw --force disable 2>/dev/null
logger -t ssh-hardening 'AUTOMATIC ROLLBACK EXECUTED'
RB
chmod +x /root/ssh-backup/rollback.sh
systemctl stop ssh-rollback.timer 2>/dev/null
systemd-run --on-active=$((ROLLBACK_MIN*60)) --unit=ssh-rollback /root/ssh-backup/rollback.sh >/dev/null 2>&1
echo 'rollback armed'"

say "4. Hardening drop-in"
# sshd_config takes the FIRST value for each option, so a drop-in only wins if
# the Include sits above the directives it overrides.
remote 'grep -n "^Include" /etc/ssh/sshd_config || echo "WARNING: no Include — edit the main file instead"'
remote "cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
# Key-only access. Rollback: rm this file && systemctl reload ssh
PermitRootLogin prohibit-password
PasswordAuthentication no
# Without this, PAM can still accept passwords via keyboard-interactive
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
$([ -n "$EXTRA_PORT" ] && printf 'Port 22\nPort %s\n' "$EXTRA_PORT")
EOF
sshd -t && echo 'syntax OK' || { echo 'SYNTAX ERROR — reverting'; rm -f /etc/ssh/sshd_config.d/99-hardening.conf; exit 1; }"

# reload, not restart: existing sessions survive and remain a safety net
remote 'systemctl reload ssh && sleep 2 && systemctl is-active ssh'

say "5. Verify on a fresh connection"
if ! fresh 'echo ok' >/dev/null 2>&1; then
    echo "FAIL: key auth broken after hardening. Leaving the rollback timer armed."
    echo "It will restore the previous config within ${ROLLBACK_MIN} minutes."
    exit 1
fi
echo "key auth still works: $(fresh 'whoami')@$(fresh 'hostname -s')"

# sshd -T shows intent; this shows behaviour.
echo -n "password auth refused: "
ssh -o ControlPath=none -o BatchMode=yes -o PubkeyAuthentication=no \
    -o ConnectTimeout=15 "$TARGET" true 2>&1 | tail -1

if [ -n "$EXTRA_PORT" ]; then
    echo -n "port $EXTRA_PORT listening: "
    remote "ss -tlnp 2>/dev/null | grep -c ':${EXTRA_PORT}\b'"
fi

say "6. Firewall"
remote "if command -v ufw >/dev/null 2>&1; then
  ufw allow 22/tcp comment 'SSH' >/dev/null
  [ -n '${EXTRA_PORT}' ] && ufw allow ${EXTRA_PORT}/tcp comment 'SSH alt' >/dev/null
  for p in 80 443; do ss -tln | grep -q \":\$p\" && ufw allow \$p/tcp >/dev/null; done
  ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
  ufw --force enable >/dev/null
  # enabling ufw rewrites the tables and can wipe fail2ban's chains
  systemctl restart fail2ban; sleep 3
  ufw status | head -8
  echo \"fail2ban rules present: \$(iptables -S 2>/dev/null | grep -c f2b)\"
else echo 'ufw not installed — skipped'; fi"

say "7. Final verification"
fresh 'echo "OK: $(whoami)@$(hostname -s)"' || {
    echo "FAIL after firewall. Rollback timer still armed."; exit 1; }

say "8. Cancelling rollback timer"
remote 'systemctl stop ssh-rollback.timer 2>/dev/null
systemctl reset-failed ssh-rollback.timer 2>/dev/null
systemctl list-timers --all --no-pager 2>/dev/null | grep -c ssh-rollback || true'
echo "(0 = cancelled; the configuration is now permanent)"

say "Done"
remote 'echo "sshd:      $(systemctl is-active ssh)"
echo "fail2ban:  $(systemctl is-active fail2ban)"
echo "ufw:       $(ufw status 2>/dev/null | head -1)"
echo "hardening: PasswordAuthentication=$(sshd -T 2>/dev/null | awk "/^passwordauthentication /{print \$2}")"'

cat <<'NOTE'

Remaining, and worth doing:
  - Add a rescue key that lives only in a password manager, exempt from any
    source restriction. It turns a lockout from hours into minutes.
  - Give each machine and each automated client its own key, named in the
    comment, so access can be revoked one at a time.
NOTE
