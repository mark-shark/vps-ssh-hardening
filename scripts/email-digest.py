#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Daily security digest for a hardened server, delivered as HTML e-mail.

Run it from a systemd timer or cron. Everything it needs is on the server it
runs on, so it also works when your workstation is off — which is the gap a
menu-bar indicator leaves open.

Why one digest instead of a mail per ban: a server facing the open internet is
banned dozens of times a day. Per-event mail stops being read within a week,
and a notification nobody reads is worse than none, because it feels like
coverage. The digest leads with whether anything needs attention; the numbers
are context.

The part actually worth reading daily is *successful* logins — who got in and
from where. Ban counts are noise.

Configuration, all via environment (see the systemd unit example at the end):

    DIGEST_TO        recipient                     (required in practice)
    DIGEST_FROM      envelope/From address
    DIGEST_BRAND     name in header and footer
    DIGEST_URL       link shown in the footer
    DIGEST_TAGLINE   one line under the brand name
    DIGEST_ASSETS    directory with header-brand.png / header-warn.png /
                     header-danger.png (1200x320). Unset - a text header is
                     used instead, which is the safer default.

Layout is a 600px table with inline styles. That is not archaism: Outlook on
Windows renders through Word, which knows neither flex, grid, nor <style>
rules, so anything that must survive has to be inline and inside <table>.

Sends multipart/alternative (HTML + plain text) so it stays readable in a
text client and in a watch notification.
"""
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from html import escape

TO = os.environ.get("DIGEST_TO", "root@localhost")
FROM = os.environ.get("DIGEST_FROM", "noreply@localhost")
BRAND = os.environ.get("DIGEST_BRAND", "server monitoring")
BRAND_URL = os.environ.get("DIGEST_URL", "")
TAGLINE = os.environ.get("DIGEST_TAGLINE", "")
ASSETS = os.environ.get("DIGEST_ASSETS", "")

F2B_LOG = os.environ.get("DIGEST_F2B_LOG", "/var/log/fail2ban.log")
AUTH_LOG = os.environ.get("DIGEST_AUTH_LOG", "/var/log/auth.log")
SERVICES = os.environ.get("DIGEST_SERVICES", "ssh ufw fail2ban nginx").split()
CERT_WARN_DAYS = int(os.environ.get("DIGEST_CERT_WARN_DAYS", "14"))

FONT = ("-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, "
        "Arial, sans-serif")
FONT_MONO = "Menlo, Consolas, 'Courier New', monospace"

# A neutral light palette. Swap the values for your own; the structure does
# not depend on them.
C = {
    "page": "#f1f2f4", "card": "#ffffff", "border": "#e1e3e8",
    "headerBg": "#151922", "text1": "#1f2430", "text2": "#3b4152",
    "text3": "#6b7280", "footerBg": "#090a0f", "footerText": "#ffffff",
    "footerMuted": "#94a3b8", "footerBorder": "rgba(255,255,255,0.08)",
}
ACCENT = {
    "brand":  {"tint": "#e8edff", "text": "#1f45d6"},
    "warn":   {"tint": "#fff0e6", "text": "#c2410c"},
    "danger": {"tint": "#fdeaea", "text": "#b91c1c"},
}


def sh(cmd):
    """Run a CONSTANT shell pipeline, return stdout.

    shell=True is needed here because these commands use pipes, awk and globs.
    The safety condition is that every string passed to this function is a
    literal defined in this file. Anything that carries a configured value —
    a log path, a service name — must go through run() instead, or an operator
    could put `; rm -rf /` in an environment variable and have it executed.
    """
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=25).stdout.strip()
    except Exception:
        return ""


def run(args):
    """Run a command as an argument list — no shell, so no injection.

    Use this whenever any part of the command comes from configuration.
    """
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=25).stdout.strip()
    except Exception:
        return ""


def collect():
    d, cutoff = {}, datetime.now() - timedelta(hours=24)

    bans, ips = 0, {}
    try:
        with open(F2B_LOG, errors="replace") as fh:
            for line in fh:
                if "NOTICE" not in line or " Ban " not in line:
                    continue
                m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
                if m and datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S") >= cutoff:
                    bans += 1
                    ip = re.search(r"Ban ([\d.]+)", line)
                    if ip:
                        ips[ip.group(1)] = ips.get(ip.group(1), 0) + 1
    except OSError:
        pass
    d["bans"] = bans
    d["top_ips"] = sorted(ips.items(), key=lambda kv: -kv[1])[:5]

    logins, seen = [], set()
    try:
        with open(AUTH_LOG, errors="replace") as fh:
            for line in fh:
                m = re.search(r"Accepted (\w+) for (\S+) from ([\d.]+)", line)
                if m:
                    key = (m.group(2), m.group(3), m.group(1))
                    if key not in seen:
                        seen.add(key)
                        logins.append(key)
    except OSError:
        pass
    d["logins"] = logins[-8:]

    # AUTH_LOG is configurable, so this must not go through a shell.
    d["failed"] = run(["grep", "-c", "Failed password", AUTH_LOG]) or "0"
    d["banned_now"] = sh("fail2ban-client status sshd 2>/dev/null "
                         "| awk '/Currently banned/{print $NF}'") or "?"
    d["passauth"] = sh("sshd -T 2>/dev/null "
                       "| awk '/^passwordauthentication /{print $2}'") or "?"
    d["disk"] = sh("df -h / | awk 'NR==2{print $5}'") or "?"
    d["load"] = sh("cut -d' ' -f1-3 /proc/loadavg") or "?"
    d["uptime"] = sh("uptime -p") or "?"
    d["host"] = sh("hostname -f") or sh("hostname") or "server"
    d["reboot"] = bool(sh("test -f /var/run/reboot-required && echo y"))

    certs = sh(
        "for c in /etc/letsencrypt/live/*/cert.pem; do [ -e \"$c\" ] || continue; "
        "e=$(openssl x509 -enddate -noout -in \"$c\" 2>/dev/null | cut -d= -f2); "
        "[ -n \"$e\" ] && echo \"$(( ($(date -d \"$e\" +%s) - $(date +%s)) / 86400 ))"
        " $(basename $(dirname \"$c\"))\"; done | sort -n | head -1")
    if certs:
        parts = certs.split(None, 1)
        d["cert_days"], d["cert_name"] = int(parts[0]), (parts[1] if len(parts) > 1 else "?")
    else:
        d["cert_days"], d["cert_name"] = None, "-"

    # Service names come from configuration - argument list, not a shell.
    d["services"] = {s: (run(["systemctl", "is-active", s]) or "?") for s in SERVICES}
    return d


def evaluate(d):
    """Return (level, problems). Level drives accent colour and subject."""
    problems, level = [], "ok"

    # The highest-value check in the whole script: hardening that silently
    # regressed. A package update or a helpful script can undo it, and nothing
    # else would tell you.
    if d["passauth"] not in ("no", "?"):
        problems.append(("danger", "Hardening regressed",
                         f"PasswordAuthentication is {d['passauth']}; "
                         "the server accepts passwords again."))
        level = "danger"
    for s, st in d["services"].items():
        if st not in ("active", "?"):
            problems.append(("danger", f"Service {s} is not running", f"State: {st}."))
            level = "danger"
    if d["cert_days"] is not None and d["cert_days"] <= CERT_WARN_DAYS:
        problems.append(("warn", "Certificate expiring",
                         f"{d['cert_name']} in {d['cert_days']} days."))
        level = "danger" if level == "danger" else "warn"
    if d["reboot"]:
        problems.append(("warn", "Reboot required", "Pending kernel update."))
        level = "danger" if level == "danger" else "warn"
    return level, problems


def accent_name(level):
    return "brand" if level == "ok" else ("warn" if level == "warn" else "danger")


def header_path(level):
    if not ASSETS:
        return None
    p = os.path.join(ASSETS, f"header-{accent_name(level)}.png")
    return p if os.path.isfile(p) else None


def rows(items):
    out = []
    for label, value, mono in items:
        vf = FONT_MONO if mono else FONT
        out.append(
            f'<tr><td style="padding:9px 0;border-bottom:1px solid {C["border"]};'
            f'font-family:{FONT};font-size:14px;color:{C["text3"]};">{escape(label)}</td>'
            f'<td align="right" style="padding:9px 0;border-bottom:1px solid {C["border"]};'
            f'font-family:{vf};font-size:14px;font-weight:700;color:{C["text1"]};">'
            f'{escape(str(value))}</td></tr>')
    return "".join(out)


def build_html(d, level, problems):
    a = ACCENT[accent_name(level)]
    title = ("All clear" if level == "ok"
             else "Needs attention" if level == "warn" else "Something is wrong")
    year = datetime.now().year

    alerts = ""
    for kind, head, body in problems:
        ac = ACCENT[kind]
        alerts += (
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'border="0" style="margin:0 0 12px;"><tr><td bgcolor="{ac["tint"]}" '
            f'style="background-color:{ac["tint"]};border-radius:12px;padding:14px 18px;'
            f'font-family:{FONT};font-size:14px;line-height:1.6;color:{ac["text"]};">'
            f'<strong>{escape(head)}</strong><br />{escape(body)}</td></tr></table>')

    if d["logins"]:
        lr = "".join(
            f'<tr><td style="padding:6px 0;font-family:{FONT_MONO};font-size:13px;'
            f'color:{C["text2"]};">{escape(u)}</td>'
            f'<td style="padding:6px 0;font-family:{FONT_MONO};font-size:13px;'
            f'color:{C["text3"]};">{escape(ip)}</td>'
            f'<td align="right" style="padding:6px 0;font-family:{FONT};font-size:12px;'
            f'color:{C["text3"]};">{escape(m)}</td></tr>' for u, ip, m in d["logins"])
        logins_html = f'<table role="presentation" width="100%" border="0">{lr}</table>'
    else:
        logins_html = (f'<p style="margin:0;font-family:{FONT};font-size:14px;'
                       f'color:{C["text3"]};">None in the log.</p>')

    if d["top_ips"]:
        ir = "".join(
            f'<tr><td style="padding:5px 0;font-family:{FONT_MONO};font-size:13px;'
            f'color:{C["text2"]};">{escape(ip)}</td><td align="right" '
            f'style="padding:5px 0;font-family:{FONT};font-size:13px;'
            f'color:{C["text3"]};">{n}x</td></tr>' for ip, n in d["top_ips"])
        ips_html = f'<table role="presentation" width="100%" border="0">{ir}</table>'
    else:
        ips_html = (f'<p style="margin:0;font-family:{FONT};font-size:14px;'
                    f'color:{C["text3"]};">No bans in the last 24 hours.</p>')

    # Image header when assets are configured; otherwise a text bar. The
    # fallback matters — an empty strip with a broken-image icon looks worse
    # than plain text, and assets are the thing most likely to be missing
    # after a move or a fresh deploy.
    if header_path(level):
        header = (f'<tr><td bgcolor="{C["headerBg"]}" style="background-color:{C["headerBg"]};'
                  f'border-radius:18px 18px 0 0;font-size:0;line-height:0;">'
                  f'<img src="cid:digest-header" width="600" alt="{escape(BRAND)}" '
                  f'style="display:block;width:100%;max-width:600px;height:auto;'
                  f'border-radius:18px 18px 0 0;" /></td></tr>')
    else:
        header = (f'<tr><td bgcolor="{C["headerBg"]}" style="background-color:{C["headerBg"]};'
                  f'border-radius:18px 18px 0 0;padding:26px 36px;">'
                  f'<p style="margin:0;font-family:{FONT};font-size:18px;font-weight:700;'
                  f'color:#ffffff;">{escape(BRAND)}</p></td></tr>')

    h2 = (f'margin:28px 0 10px;font-family:{FONT};font-size:15px;font-weight:700;'
          f'letter-spacing:0.03em;text-transform:uppercase;color:{C["text3"]};')
    svc = " - ".join(f"{k} {v}" for k, v in d["services"].items())
    cert = (f'{d["cert_days"]} days ({d["cert_name"]})'
            if d["cert_days"] is not None else "-")
    pre = f'{d["bans"]} bans in 24h, {len(d["logins"])} logins, disk {d["disk"]}'

    foot_links = ""
    if BRAND_URL:
        foot_links = (f'<a href="{escape(BRAND_URL)}" style="color:{C["footerMuted"]};'
                      f'text-decoration:none;">'
                      f'{escape(re.sub(r"^https?://", "", BRAND_URL))}</a><br />')
    tagline = (f'<p style="margin:0;font-family:{FONT};font-size:13px;line-height:1.65;'
               f'color:{C["footerMuted"]};">{escape(TAGLINE)}</p>') if TAGLINE else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{escape(title)}</title>
<style>
  @media only screen and (max-width:620px) {{
    .m-pad {{ padding-left:22px !important; padding-right:22px !important; }}
    .m-title {{ font-size:22px !important; }}
  }}
</style></head>
<body style="margin:0;padding:0;width:100%;background-color:{C['page']};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;">{escape(pre)}</div>
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" bgcolor="{C['page']}" style="background-color:{C['page']};">
<tr><td align="center" style="padding:32px 12px 44px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px;max-width:600px;">
{header}
<tr><td class="m-pad" bgcolor="{C['card']}" style="background-color:{C['card']};border-left:1px solid {C['border']};border-right:1px solid {C['border']};padding:34px 36px 4px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
<td bgcolor="{a['tint']}" style="background-color:{a['tint']};border-radius:999px;padding:7px 15px;font-family:{FONT};font-size:11px;font-weight:700;line-height:1;letter-spacing:0.09em;text-transform:uppercase;color:{a['text']};">Security digest</td>
</tr></table>
<h1 class="m-title" style="margin:18px 0 6px;font-family:{FONT};font-size:26px;font-weight:700;line-height:1.28;color:{C['text1']};">{escape(title)}</h1>
<p style="margin:0 0 22px;font-family:{FONT};font-size:14px;color:{C['text3']};"><span style="font-family:{FONT_MONO};">{escape(d['host'])}</span> - last 24 hours - {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
{alerts}
<p style="{h2}">SSH</p>
<table role="presentation" width="100%" border="0">
{rows([("Bans in 24 hours", d["bans"], True), ("Currently banned", d["banned_now"], True),
       ("Failed passwords in log", d["failed"], True)])}
</table>
<p style="{h2}">Successful logins</p>
{logins_html}
<p style="{h2}">Most active sources</p>
{ips_html}
<p style="{h2}">Server state</p>
<table role="presentation" width="100%" border="0">
{rows([("PasswordAuthentication", d["passauth"], True), ("Disk /", d["disk"], True),
       ("Load", d["load"], True), ("Nearest certificate", cert, False),
       ("Services", svc, False), ("Uptime", d["uptime"], False)])}
</table>
</td></tr>
<tr><td class="m-pad" bgcolor="{C['card']}" style="background-color:{C['card']};border-left:1px solid {C['border']};border-right:1px solid {C['border']};border-bottom:1px solid {C['border']};padding:8px 36px 30px;">
<p style="margin:20px 0 0;padding-top:20px;border-top:1px solid {C['border']};font-family:{FONT};font-size:13px;line-height:1.65;color:{C['text3']};">Generated on the server. Disable with <span style="font-family:{FONT_MONO};">systemctl disable --now security-digest.timer</span>.</p>
</td></tr>
<tr><td bgcolor="{C['footerBg']}" style="background-color:{C['footerBg']};border-radius:0 0 18px 18px;padding:28px 36px 26px;">
<p style="margin:0 0 8px;font-family:{FONT};font-size:15px;font-weight:700;line-height:1.3;color:{C['footerText']};">{escape(BRAND)}</p>
{tagline}
<p style="margin:22px 0 0;padding-top:16px;border-top:1px solid {C['footerBorder']};font-family:{FONT};font-size:12px;line-height:1.8;color:{C['footerMuted']};">
{foot_links}{year}
</p>
</td></tr>
</table></td></tr></table></body></html>"""


def build_text(d, level, problems):
    L = [f"Security digest - {d['host']}",
         datetime.now().strftime("%Y-%m-%d %H:%M"), ""]
    if problems:
        L.append("NEEDS ATTENTION")
        L += [f"  - {h}: {b}" for _, h, b in problems]
        L.append("")
    L += ["SSH",
          f"  bans in 24h:        {d['bans']}",
          f"  currently banned:   {d['banned_now']}",
          f"  failed passwords:   {d['failed']}", "",
          "Successful logins:"]
    L += [f"  {u} <- {ip} ({m})" for u, ip, m in d["logins"]] or ["  (none)"]
    L += ["", "Most active sources:"]
    L += [f"  {ip}  {n}x" for ip, n in d["top_ips"]] or ["  (none)"]
    L += ["", "Server state",
          f"  PasswordAuthentication: {d['passauth']}",
          f"  disk /:                 {d['disk']}",
          f"  load:                   {d['load']}",
          f"  certificate:            "
          f"{d['cert_days'] if d['cert_days'] is not None else '-'} days ({d['cert_name']})",
          "  services:               "
          + " ".join(f"{k}={v}" for k, v in d["services"].items()),
          f"  uptime:                 {d['uptime']}"]
    return "\n".join(L)


def main():
    d = collect()
    level, problems = evaluate(d)
    tag = {"ok": "all clear", "warn": "needs attention", "danger": "PROBLEM"}[level]
    subject = f"[{d['host'].split('.')[0]}] Digest: {d['bans']} bans, {tag}"

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(build_text(d, level, problems), "plain", "utf-8"))
    alt.attach(MIMEText(build_html(d, level, problems), "html", "utf-8"))

    hdr = header_path(level)
    if hdr:
        # related( alternative(...), image ). The image must be a sibling of
        # the alternative part, not inside it — some clients will not resolve
        # the cid: reference otherwise and show a broken image.
        msg = MIMEMultipart("related")
        msg.attach(alt)
        with open(hdr, "rb") as fh:
            img = MIMEImage(fh.read(), _subtype="png")
        img.add_header("Content-ID", "<digest-header>")
        img.add_header("Content-Disposition", "inline", filename="header.png")
        msg.attach(img)
    else:
        msg = alt

    msg["Subject"] = subject
    msg["From"] = f"{BRAND} <{FROM}>"
    msg["To"] = TO
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    # Stops out-of-office autoresponders from replying to a robot.
    msg["Auto-Submitted"] = "auto-generated"

    if "--dry-run" in sys.argv:
        out = "/tmp/digest-preview.html"
        with open(out, "w") as fh:
            fh.write(build_html(d, level, problems))
        print(build_text(d, level, problems))
        print(f"\n[dry-run] subject: {subject}\n[dry-run] HTML: {out}")
        return 0

    p = subprocess.run(["/usr/sbin/sendmail", "-t", "-oi"],
                       input=msg.as_bytes(), capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode(errors="replace"))
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())

# systemd unit, for reference:
#
#   /etc/systemd/system/security-digest.service
#     [Service]
#     Type=oneshot
#     Environment=DIGEST_TO=you@example.com
#     Environment=DIGEST_FROM=noreply@example.com
#     Environment=DIGEST_BRAND=Example
#     ExecStart=/usr/bin/python3 /opt/security-digest.py
#
#   /etc/systemd/system/security-digest.timer
#     [Timer]
#     OnCalendar=*-*-* 07:00:00
#     Persistent=true
#     RandomizedDelaySec=300
#     [Install]
#     WantedBy=timers.target
#
# Delivery needs a working sendmail. msmtp as a relay is the light option;
# see references/monitoring.md for the AppArmor and setgid traps it brings.
