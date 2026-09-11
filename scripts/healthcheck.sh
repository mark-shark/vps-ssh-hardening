#!/bin/bash
#
# Periodic health check for a hardened server.
#
# Writes a human-readable log and a JSON status file. Notifies only when the
# status *changes*, so a long outage produces one alert rather than one per run.
#
# Schedule it every ~15 min (launchd StartInterval on macOS, systemd timer or
# cron on Linux). Point HOST at an entry in ~/.ssh/config.
#
# Two things to get right before this is useful:
#   - the key it uses must be passphrase-less, or reliably loaded in an agent,
#     otherwise every run fails on authentication and alarms about nothing
#   - this machine's network must be in fail2ban's ignoreip, or repeated
#     failures during an outage can get you banned on top of it

set -u

# --- configuration ---------------------------------------------------------
HOST="${VPS_HOST:-myserver}"                       # ssh_config alias
DOMAINS_FILE="${VPS_DOMAINS:-$HOME/.ssh/vps-domains.txt}"   # one hostname per line, # comments ok
LOG="${VPS_LOG:-$HOME/Library/Logs/vps-healthcheck.log}"
STATE="$HOME/.vps-health-state"                    # last level, for change detection
SLOW_STATE="$HOME/.vps-slow-state"                 # domains slow in the PREVIOUS run
HEALTH_JSON="${VPS_JSON:-$HOME/.vps-health.json}"  # machine-readable status

DISK_WARN=85;  DISK_FAIL=95        # percent used
MEM_WARN=400                       # MB available
LOAD_WARN_PER_CORE=2               # load1 / cores
CERT_WARN=14;  CERT_FAIL=3         # days to expiry
HTTP_TIMEOUT=10                    # seconds per domain
HTTP_SLOW_WARN=3                   # seconds; reported only if two runs in a row
# ---------------------------------------------------------------------------

TS=$(date "+%Y-%m-%d %H:%M:%S")
problems=""
level="OK"

note() {   # note <LEVEL> <message>
    problems="${problems}  [$1] $2"$'\n'
    if [ "$1" = "FAIL" ]; then level="FAIL"
    elif [ "$level" != "FAIL" ]; then level="WARN"; fi
}

# --- server side, in ONE ssh connection ------------------------------------
# Ten separate connections per run would be ten times the auth load and ten
# times the chance of tripping a jail.
REMOTE='
echo "disk_pct=$(df --output=pcent / | tail -1 | tr -dc "0-9")"
echo "mem_avail=$(free -m | awk "/^Mem:/{print \$7}")"
echo "load1=$(cut -d" " -f1 /proc/loadavg)"
echo "cores=$(nproc)"
for s in nginx ssh fail2ban ufw; do
    systemctl list-unit-files "$s.service" >/dev/null 2>&1 && \
        echo "svc_$s=$(systemctl is-active $s 2>&1)"
done
# The check that matters most: has the hardening silently regressed?
echo "passauth=$(sshd -T 2>/dev/null | awk "/^passwordauthentication /{print \$2}")"
test -f /var/run/reboot-required && echo "reboot=yes" || echo "reboot=no"
echo "banned=$(fail2ban-client status sshd 2>/dev/null | awk "/Currently banned/{print \$NF}")"
min=99999; name="-"
for c in /etc/letsencrypt/live/*/cert.pem; do
    [ -e "$c" ] || continue
    end=$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)
    [ -n "$end" ] || continue
    days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
    if [ "$days" -lt "$min" ]; then min=$days; name=$(basename $(dirname "$c")); fi
done
echo "cert_days=$min"; echo "cert_name=$name"
'

DATA=$(ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" "$REMOTE" 2>&1)
SSH_RC=$?

if [ $SSH_RC -ne 0 ]; then
    level="FAIL"
    problems="  [FAIL] SSH unreachable (rc=$SSH_RC): $(echo "$DATA" | tail -1)"$'\n'
else
    for k in disk_pct mem_avail load1 cores svc_nginx svc_ssh svc_fail2ban svc_ufw \
             passauth reboot banned cert_days cert_name; do
        eval "$k=\$(echo \"\$DATA\" | awk -F= -v K=\"\$k\" '\$1==K{print \$2; exit}')"
    done

    [ "${disk_pct:-0}" -ge "$DISK_FAIL" ] && note FAIL "Disk full: ${disk_pct}%" \
        || { [ "${disk_pct:-0}" -ge "$DISK_WARN" ] && note WARN "Disk: ${disk_pct}%"; }

    [ "${mem_avail:-9999}" -lt "$MEM_WARN" ] && note WARN "Low memory: ${mem_avail} MB"

    lw=$(echo "${load1:-0} ${cores:-1} $LOAD_WARN_PER_CORE" | awk '{print ($1 > $2*$3) ? 1 : 0}')
    [ "$lw" = "1" ] && note WARN "High load: ${load1} (${cores} cores)"

    for s in nginx ssh fail2ban ufw; do
        eval "v=\${svc_$s:-}"
        [ -n "$v" ] && [ "$v" != "active" ] && note FAIL "Service $s not active: $v"
    done

    # Silent regression here is the failure nothing else would catch.
    [ -n "${passauth:-}" ] && [ "${passauth}" != "no" ] \
        && note FAIL "SSH hardening regressed: PasswordAuthentication=${passauth}"

    [ "${reboot:-no}" = "yes" ] && note WARN "Reboot required (kernel update)"

    if [ "${cert_days:-99999}" != "99999" ] && [ -n "${cert_days:-}" ]; then
        [ "${cert_days}" -le "$CERT_FAIL" ] && note FAIL "Cert ${cert_name} expires in ${cert_days}d" \
            || { [ "${cert_days}" -le "$CERT_WARN" ] && note WARN "Cert ${cert_name} expires in ${cert_days}d"; }
    fi
fi

# --- domains, checked from HERE --------------------------------------------
# From the client this also exercises DNS, the firewall, the vhost mapping and
# certificate validity — curl without -k fails on a bad cert, which is wanted.
dom_total=0; dom_bad=0
prev_slow=$(cat "$SLOW_STATE" 2>/dev/null || true)
cur_slow=""
if [ -f "$DOMAINS_FILE" ]; then
    TMPD=$(mktemp -d 2>/dev/null || echo "")
    if [ -n "$TMPD" ]; then
        # In parallel: serial checks cost one timeout per domain.
        while read -r d; do
            case "$d" in ''|\#*) continue ;; esac
            dom_total=$((dom_total+1))
            (
                r=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' \
                        --max-time "$HTTP_TIMEOUT" "https://$d" 2>/dev/null)
                echo "$d|$?|$r" > "$TMPD/$dom_total"
            ) &
        done < "$DOMAINS_FILE"
        wait

        for f in "$TMPD"/*; do
            [ -e "$f" ] || continue
            IFS='|' read -r d rc r < "$f"
            code=$(echo "$r" | awk '{print $1}')
            secs=$(echo "$r" | awk '{print $2}')
            if [ "${rc:-1}" != "0" ]; then
                # A curl exit code is unreadable in a notification; translate it.
                case "$rc" in
                    6)  why="DNS did not resolve" ;;
                    7)  why="connection refused" ;;
                    28) why="timeout (>${HTTP_TIMEOUT}s)" ;;
                    35) why="TLS handshake failed" ;;
                    51|60) why="bad or expired certificate" ;;
                    *)  why="curl rc=$rc" ;;
                esac
                note FAIL "$d: $why"; dom_bad=$((dom_bad+1))
            elif [ "${code:-0}" -ge 500 ] 2>/dev/null; then
                note FAIL "$d: HTTP $code"; dom_bad=$((dom_bad+1))
            elif [ "${code:-0}" -ge 400 ] 2>/dev/null; then
                note WARN "$d: HTTP $code"; dom_bad=$((dom_bad+1))
            else
                slow=$(echo "${secs:-0} $HTTP_SLOW_WARN" | awk '{print ($1 > $2) ? 1 : 0}')
                if [ "$slow" = "1" ]; then
                    cur_slow="${cur_slow}${d}"$'\n'
                    # Only on the second consecutive reading: one slow response
                    # is usually a backend waking from idle, not a problem.
                    if printf '%s' "$prev_slow" | grep -qxF "$d" 2>/dev/null; then
                        note WARN "$d: slow response ${secs}s (2 in a row)"
                    fi
                fi
            fi
        done
        # Written after all domains are evaluated, so a crash cannot truncate it.
        printf '%s' "$cur_slow" > "$SLOW_STATE"
        rm -rf "$TMPD"
    fi
fi

# --- output ----------------------------------------------------------------
mkdir -p "$(dirname "$LOG")" 2>/dev/null
if [ "$level" = "OK" ]; then
    echo "$TS  OK  disk=${disk_pct:-?}% mem=${mem_avail:-?}MB load=${load1:-?} cert=${cert_days:-?}d domains=$((dom_total-dom_bad))/${dom_total}" >> "$LOG"
else
    { echo "$TS  $level"; printf '%s' "$problems"; } >> "$LOG"
fi

J_TS="$TS" J_LEVEL="$level" J_PROBLEMS="$problems" \
J_DISK="${disk_pct:-}" J_MEM="${mem_avail:-}" J_LOAD="${load1:-}" J_CORES="${cores:-}" \
J_CERTD="${cert_days:-}" J_CERTN="${cert_name:-}" J_BANNED="${banned:-}" \
J_DOMT="${dom_total:-0}" J_DOMB="${dom_bad:-0}" J_REBOOT="${reboot:-}" \
python3 -c '
import json, os
def num(v):
    try: return int(v)
    except:
        try: return float(v)
        except: return None
g = os.environ.get
print(json.dumps({
    "ts": g("J_TS",""), "level": g("J_LEVEL","OK"),
    "disk_pct": num(g("J_DISK","")), "mem_avail_mb": num(g("J_MEM","")),
    "load1": num(g("J_LOAD","")), "cores": num(g("J_CORES","")),
    "cert_days": num(g("J_CERTD","")), "cert_name": g("J_CERTN","") or None,
    "banned": num(g("J_BANNED","")), "reboot_required": g("J_REBOOT","") == "yes",
    "domains_total": num(g("J_DOMT","0")), "domains_bad": num(g("J_DOMB","0")),
    "problems": [l.strip() for l in g("J_PROBLEMS","").splitlines() if l.strip()],
}, ensure_ascii=False, indent=2))' > "$HEALTH_JSON" 2>/dev/null

if [ -f "$LOG" ] && [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then
    tail -500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# --- notify on CHANGE only --------------------------------------------------
# Alerting every run during a two-hour outage trains people to ignore alerts.
PREV=$(cat "$STATE" 2>/dev/null || echo "OK")
echo "$level" > "$STATE"
if [ "$level" != "$PREV" ] && command -v osascript >/dev/null 2>&1; then
    if [ "$level" = "OK" ]; then MSG="Server is healthy again"
    else MSG=$(printf '%s' "$problems" | head -3 | sed 's/^ *//' | tr '\n' ' '); fi
    # NOTE: exit 0 here does NOT mean anything was displayed — see
    # references/monitoring.md on macOS notification delivery.
    osascript -e "display notification \"${MSG//\"/\\\"}\" with title \"Server health: $level\"" 2>/dev/null
fi

exit 0
