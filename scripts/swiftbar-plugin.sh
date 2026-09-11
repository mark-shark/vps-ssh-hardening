#!/bin/bash
# <bitbar.title>Server health</bitbar.title>
# <bitbar.version>1.0</bitbar.version>
# <bitbar.desc>Menu-bar status for a server. Reads the JSON written by healthcheck.sh</bitbar.desc>
# <bitbar.dependencies>bash,python3</bitbar.dependencies>
#
# Install: put in your SwiftBar/xbar plugin folder, keeping the interval in the
# filename (e.g. server.1m.sh). One minute is fine — it only reads a file.
#
# This plugin performs NO checks of its own. The scheduled healthcheck.sh does
# the measuring; this only renders its result. Two independent schedulers would
# double the load on the server and make the menu bar wait on the network.

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:$PATH"
JSON="${VPS_JSON:-$HOME/.vps-health.json}"
LOG="${VPS_LOG:-$HOME/Library/Logs/vps-healthcheck.log}"
CHECK="${VPS_CHECK:-$HOME/.ssh/healthcheck.sh}"
STALE_MIN=25    # roughly 1.5x the check interval

if [ ! -f "$JSON" ]; then
    echo "SRV ? | sfimage=questionmark.circle.fill sfcolor=gray"
    echo "---"
    echo "No data yet"
    echo "Run check now | bash=$CHECK terminal=false refresh=true"
    exit 0
fi

eval "$(python3 - "$JSON" "$STALE_MIN" <<'PY'
import json, sys, datetime, shlex
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("PARSE_FAIL=1"); sys.exit()
stale_min = int(sys.argv[2])
age = 9999
try:
    t = datetime.datetime.strptime(d.get("ts",""), "%Y-%m-%d %H:%M:%S")
    age = int((datetime.datetime.now() - t).total_seconds() // 60)
except Exception:
    pass
def q(k, v): print(f"{k}={shlex.quote(str(v))}")
q("PARSE_FAIL", 0); q("LEVEL", d.get("level","OK"))
q("AGE", age); q("STALE", 1 if age > stale_min else 0); q("TS", d.get("ts",""))
for k in ("disk_pct","mem_avail_mb","load1","cores","cert_days","cert_name",
          "banned","domains_total","domains_bad"):
    q(k.upper(), d.get(k) if d.get(k) is not None else "-")
q("REBOOT", 1 if d.get("reboot_required") else 0)
probs = d.get("problems", [])
q("NPROB", len(probs))
for i, p in enumerate(probs[:12]):
    q(f"PROB{i}", p)
PY
)"

if [ "${PARSE_FAIL:-1}" = "1" ]; then
    echo "SRV ! | sfimage=exclamationmark.circle.fill sfcolor=gray"
    echo "---"; echo "Cannot read $JSON"
    echo "Run check now | bash=$CHECK terminal=false refresh=true"
    exit 0
fi

# Stale data is its own alarm: it means the monitoring stopped, which is
# invisible if you only ever render the last known status.
if [ "${STALE:-0}" = "1" ]; then
    echo "SRV | sfimage=clock.badge.exclamationmark.fill sfcolor=gray"
else
    case "$LEVEL" in
        OK)   echo "SRV | sfimage=checkmark.circle.fill sfcolor=systemGreen" ;;
        WARN) echo "SRV ${NPROB} | sfimage=exclamationmark.triangle.fill sfcolor=systemOrange" ;;
        *)    echo "SRV ${NPROB} | sfimage=xmark.octagon.fill sfcolor=systemRed" ;;
    esac
fi

echo "---"

if [ "${STALE:-0}" = "1" ]; then
    echo "⚠ Data ${AGE} min old — is the scheduled check running? | color=orange"
    echo "---"
fi

echo "Status: $LEVEL   ($TS, ${AGE} min ago) | font=Menlo"

if [ "${NPROB:-0}" -gt 0 ]; then
    echo "---"; echo "Findings:"
    i=0
    while [ "$i" -lt "$NPROB" ] && [ "$i" -lt 12 ]; do
        eval "p=\${PROB$i:-}"
        case "$p" in *FAIL*) c=red ;; *) c=orange ;; esac
        echo "${p} | color=$c font=Menlo size=12"
        i=$((i+1))
    done
fi

echo "---"
echo "Disk:      ${DISK_PCT}% | font=Menlo"
echo "Free mem:  ${MEM_AVAIL_MB} MB | font=Menlo"
echo "Load:      ${LOAD1}  (${CORES} cores) | font=Menlo"
echo "Cert:      ${CERT_DAYS} days (${CERT_NAME}) | font=Menlo"
echo "Domains:   $((DOMAINS_TOTAL - DOMAINS_BAD))/${DOMAINS_TOTAL} reachable | font=Menlo"
echo "Fail2ban:  ${BANNED} banned IPs | font=Menlo"
[ "${REBOOT:-0}" = "1" ] && echo "Reboot required | color=orange font=Menlo"

echo "---"
echo "Run check now | bash=$CHECK terminal=false refresh=true"
echo "Open log | bash=/usr/bin/open param1=-a param2=Console param3=$LOG terminal=false"
echo "Refresh | refresh=true"
