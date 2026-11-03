"""
Pentest Workflow Manager v4 — app.py
Extended: API vuln detection (OWASP API Top-10), Database vuln scanning,
verified findings, fixed PDF report with PoC + code-fix examples,
enriched popup data (path, command, remediation).
"""

import os, re, uuid, json, time, queue, threading, subprocess, shutil, html, socket, signal, ipaddress, select, urllib.request, urllib.parse, math as _math, inspect, shlex, hmac, tempfile
from datetime import datetime
from flask import Flask, request, Response, jsonify, send_file, redirect
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Preformatted, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

app = Flask(__name__)
app.secret_key = os.environ.get('PWM_SECRET_KEY') or os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1 MiB request body cap
PWM_API_TOKEN = os.environ.get('PWM_API_TOKEN', '')
PWM_BIND = os.environ.get('PWM_BIND', '127.0.0.1')
PWM_PORT = int(os.environ.get('PWM_PORT', '5000'))
PWM_CMD_TIMEOUT = os.environ.get('PWM_CMD_TIMEOUT', '0')
try:
    PWM_CMD_TIMEOUT = float(PWM_CMD_TIMEOUT)
except (TypeError, ValueError):
    PWM_CMD_TIMEOUT = 0.0
if PWM_CMD_TIMEOUT < 0:
    PWM_CMD_TIMEOUT = 0.0
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _nuclei_templates_dir():
    """Resolve the installed nuclei template directory at import time instead
    of hardcoding one user's home path (the old value only worked on the
    original author's machine)."""
    candidates = [
        os.environ.get('NUCLEI_TEMPLATES_DIR', ''),
        os.path.expanduser('~/.local/nuclei-templates'),
        os.path.expanduser('~/nuclei-templates'),
        '/usr/share/nuclei-templates',
        os.path.expanduser('~/.config/nuclei-templates'),
    ]
    for cand in candidates:
        if cand and os.path.isdir(os.path.join(cand, 'http')):
            return cand
    # Last resort: whatever path nuclei itself reports as its config/template
    # home — never an invented path.
    try:
        proc = subprocess.run(['nuclei', '-version'], capture_output=True,
                              text=True, timeout=5)
        out = (proc.stdout or '') + '\n' + (proc.stderr or '')
        m = re.search(r'(?:Nuclei\s+)?[Tt]emplate[s]?\s+[Dd]irector(?:y|ies)\s*:\s*(\S+)', out)
        if m and os.path.isdir(m.group(1)):
            return m.group(1).rstrip('/')
    except Exception:
        pass
    return os.path.expanduser('~/.local/nuclei-templates')


NUCLEI_TPL = _nuclei_templates_dir()

@app.before_request
def _api_token_gate():
    """Protect /api/* when PWM_API_TOKEN is configured.

    Accepted credentials (any one):
      - X-API-Token header (scripts / curl)
      - pwm_api_token cookie (set by /auth; browsers + EventSource send it
        automatically, so the bundled UI works without custom SSE headers)
      - ?token= query parameter (handy for one-off requests)
    """
    if PWM_API_TOKEN and request.path.startswith('/api/'):
        if not _token_ok():
            return jsonify(error='Unauthorized'), 401


def _token_ok():
    supplied = (request.headers.get('X-API-Token')
                or request.cookies.get('pwm_api_token')
                or request.args.get('token')
                or '')
    return bool(supplied) and hmac.compare_digest(supplied, PWM_API_TOKEN)


def _login_page(error=''):
    msg = f'<p class="err">{html.escape(error)}</p>' if error else ''
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PWM — API token required</title>
<style>
 body{{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:#0d1117;color:#e6edf3;display:flex;min-height:100vh;
       align-items:center;justify-content:center}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;
        padding:2rem;width:min(92vw,380px)}}
 h1{{font-size:1.1rem;margin:0 0 .4rem}} p{{color:#8b949e;font-size:.85rem}}
 .err{{color:#f85149;font-size:.85rem}}
 input{{width:100%;box-sizing:border-box;padding:.6rem;margin:.6rem 0;
        background:#0d1117;border:1px solid #30363d;border-radius:6px;
        color:#e6edf3;font-size:.95rem}}
 button{{width:100%;padding:.6rem;border:0;border-radius:6px;
         background:#238636;color:#fff;font-weight:600;cursor:pointer}}
</style></head><body><form class="card" method="post" action="/auth">
<h1>API token required</h1>
<p>This PWM instance is protected by PWM_API_TOKEN.
Enter it once — a HttpOnly cookie will keep the dashboard authenticated.</p>
{msg}
<input name="token" type="password" autofocus autocomplete="current-password"
       placeholder="PWM_API_TOKEN" required>
<button type="submit">Unlock dashboard</button>
</form></body></html>"""

sessions: dict = {}
output_queues: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# KILL CHAIN DEFINITION
# ─────────────────────────────────────────────────────────────────────────────
CHAIN = [
    {
        "id": "recon", "label": "Stage 1 — Reconnaissance",
        "color": "blue", "icon": "01", "parallel": True,
        "substages": [
            {
                "id": "recon_ports", "label": "Port & Service Scan", "tool": "nmap / masscan",
                "description": "Full TCP port scan (all 65535 ports at fast rate) then light version detection on open ports only. Uses SYN scan when run with privileges, TCP connect scan otherwise.",
                "cmd_template": "nmap -p- --min-rate 1000 --max-rate 3000 -T4 --open -oG {outdir}/nmap_full.gnmap {target} 2>&1; echo '---SERVICE SCAN---'; PORTS=$(grep -oE '[0-9]+/open/tcp' {outdir}/nmap_full.gnmap 2>/dev/null | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//'); if [ -n \"$PORTS\" ]; then nmap -sV --version-light --max-retries 1 -p \"$PORTS\" -T4 {target} 2>&1; else echo 'No open TCP ports found'; fi",
                "fallback_cmd": "nmap -sV --version-light --open -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,9200,27017 -T4 -oN {outdir}/nmap_common.txt {target} 2>&1",
                "parse": "nmap",
            },
            {
                "id": "recon_udp", "label": "UDP Top-20 Probe", "tool": "nmap -sU",
                "description": "UDP scan for SNMP, DNS, TFTP, NTP, LDAP and other UDP services.",
                "cmd_template": "timeout -k 5 90 nmap -sU --open -p 53,67,68,69,123,137,138,161,162,389,500,514,623,1194,5353 -T4 -oN {outdir}/nmap_udp.txt {target} 2>&1",
                "fallback_cmd": "python3 -c \"import socket\nsvc={53:'domain',67:'dhcp',68:'dhcp',69:'tftp',123:'ntp',137:'netbios-ns',138:'netbios-dgm',161:'snmp',162:'snmptrap',389:'ldap',500:'isakmp',514:'syslog',623:'ipmi',1194:'openvpn',5353:'mdns'}\nfor p in [53,67,68,69,123,137,138,161,162,389,500,514,623,1194,5353]:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n s.settimeout(1)\n try:\n  s.connect(('{target}',p)); s.send(b''); s.recv(1)\n  print(str(p)+'/udp open '+svc.get(p,'unknown'))\n except socket.timeout:\n  print(str(p)+'/udp open|filtered')\n except ConnectionRefusedError:\n  print(str(p)+'/udp closed')\n except OSError:\n  print(str(p)+'/udp error')\n finally:\n  s.close()\"",
                "parse": "nmap", "requires_root": True,
            },
            {
                "id": "recon_dns", "label": "DNS Enumeration", "tool": "dig / dnsrecon / dnsx",
                "description": "Zone transfer attempt, NS/MX/TXT records, DMARC, wildcard detection, standard DNS enumeration (SOA/NS/A/AAAA/MX/SRV).",
                "cmd_template": "dig +nocmd {target} ANY +multiline +noall +answer 2>&1; host -t ns {target} 2>&1; host -t mx {target} 2>&1; host -t txt {target} 2>&1; dig axfr {target} 2>&1 | head -40; echo '---DMARC---'; dig _dmarc.{target} TXT 2>&1; echo '---WILDCARD---'; dig test.{target} A 2>&1 | head -5; echo '---DNSRECON---'; dnsrecon -d {target} -t std,axfr --xml {outdir}/dnsrecon.xml 2>&1 | head -60",
                "fallback_cmd": "dig +nocmd {target} ANY +multiline +noall +answer 2>&1; host -t ns {target} 2>&1; host -t mx {target} 2>&1; dig axfr {target} 2>&1 | head -40",
                "parse": "generic",
            },
            {
                "id": "recon_web", "label": "HTTP/S Fingerprint", "tool": "curl / whatweb",
                "description": "Banner grab, redirect chain, server headers, X-Powered-By, CSP, CORS, cookie flags, WAF detection, technology stack.",
                "cmd_template": "curl -sIL --max-time 8 http://{target} 2>&1; echo '=HTTPS='; curl -skIL --max-time 8 https://{target} 2>&1; curl -skI --max-time 8 http://{target}:8080 2>&1; curl -skI --max-time 8 https://{target}:8443 2>&1; echo '=DISCOVERED PORTS='; for p in $(echo \"{ports}\" | tr ',' '\\n' | grep -vE '^(80|443|8080|8443)$' | head -8); do [ -z \"$p\" ] && continue; echo \"--- HTTP on :$p ---\"; curl -skI --max-time 3 \"http://{target}:$p\" 2>&1 | head -8; done; echo '=WHATWEB='; timeout -k 5 60 whatweb -a 1 http://{target} 2>&1 | head -20; echo '=WAF='; timeout -k 5 45 wafw00f http://{target} 2>&1 | head -15",
                "fallback_cmd": "curl -sIL --max-time 8 http://{target} 2>&1; curl -skIL --max-time 8 https://{target} 2>&1",
                "parse": "headers",
            },
            {
                "id": "recon_smb", "label": "SMB / RPC / NetBIOS Enumeration", "tool": "smbclient / enum4linux",
                "description": "NetBIOS lookup, null-session share listing, domain/user enumeration, SMB signing check.",
                "cmd_template": "nmblookup -A {target} 2>&1; smbclient -L //{target} -N 2>&1; rpcclient -U '' -N {target} -c 'srvinfo; enumdomusers; enumdomgroups; getdompwinfo' 2>&1; echo '---ENUM4LINUX---'; enum4linux -a {target} 2>&1 | head -80; echo '---SMB SIGNING---'; nmap --script=smb2-security-mode -p 445 {target} 2>&1 | head -20",
                "fallback_cmd": "nmblookup -A {target} 2>&1; smbclient -L //{target} -N 2>&1",
                "parse": "smb",
            },
            {
                "id": "recon_osint", "label": "WHOIS / ASN / OSINT / Subdomain", "tool": "whois / theHarvester",
                "description": "Registration data, ASN, certificate transparency logs, email harvesting, subdomain enumeration.",
                "cmd_template": "timeout -k 5 30 whois {target} 2>&1 | head -70; echo '---CRT.SH---'; case {target} in *[a-zA-Z]*) if command -v crt.sh >/dev/null 2>&1; then (cd {outdir} && timeout -k 5 60 crt.sh -d {target}) 2>/dev/null | tail -n +8 | head -80; else curl -s --max-time 8 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); [print(x.get('name_value','')) for x in d[:30]]\" 2>/dev/null || echo 'crt.sh unavailable'; fi;; *) echo '[crt.sh skipped — IP target]';; esac; echo '---THEHARVESTER---'; if command -v theHarvester >/dev/null 2>&1; then timeout -k 5 120 theHarvester -d {target} -b baidu,yahoo,dnsdumpster,certspotter,crtsh,hackertarget,rapiddns -l 100 2>&1 | head -60; else echo '[theHarvester not installed — skipped]'; fi",
                "fallback_cmd": "timeout -k 5 30 whois {target} 2>&1 | head -70; curl -s --max-time 8 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); [print(x.get('name_value','')) for x in d[:30]]\" 2>/dev/null || echo 'unavailable'",
                "parse": "generic",
            },
            {
                "id": "recon_waf_cdn", "label": "WAF / CDN / Load Balancer Detection", "tool": "wafw00f / nmap",
                "description": "Detect Web Application Firewalls, CDN providers, load balancers and cloud platform indicators.",
                "cmd_template": "timeout -k 5 45 wafw00f -a http://{target} 2>&1; timeout -k 5 45 wafw00f -a https://{target} 2>&1; echo '---NMAP WAF NSE---'; timeout -k 5 60 nmap --script=http-waf-detect,http-waf-fingerprint -p 80,443 {target} 2>&1 | head -30; echo '---CLOUDFLARE CHECK---'; curl -skI --max-time 8 https://{target} 2>&1 | grep -iE 'cf-ray|x-cdn|via|x-cache|x-amz|x-azure|server' | head -10",
                "fallback_cmd": "curl -skI --max-time 8 http://{target} 2>&1 | grep -iE 'server|via|x-powered|x-cache'",
                "parse": "waf",
            },
            {
                "id": "recon_subdomains", "label": "Subdomain Discovery", "tool": "crt.sh / dnsrecon / amass / dig",
                "description": "Multi-source subdomain discovery: certificate-transparency logs (crt.sh) and amass passive enumeration, a dnsrecon standard + brute-force pass, and a resolver sweep over common names. Every candidate is DNS-validated — the parser only reports subdomains that actually resolved to an address; unresolved names are never reported.",
                "cmd_template": "echo '=CRT.SH RESOLVED='; if echo '{target}' | grep -q '[a-zA-Z]'; then curl -s --max-time 15 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | python3 -c \"import json,sys\ntry:\n d=json.load(sys.stdin)\nexcept Exception:\n d=[]\ns=set()\nfor x in d:\n for n in (x.get('name_value') or '').split(chr(10)):\n  n=n.strip().lstrip('*.').lower()\n  if n.endswith('.{target}') or n==('{target}'):\n   s.add(n)\nfor n in sorted(s)[:80]:\n print(n)\" 2>/dev/null | while read h; do ip=$(dig +short \"$h\" A 2>/dev/null | head -1); [ -n \"$ip\" ] && echo \"$h -> $ip\"; done; else echo '[crt.sh skipped — IP target]'; fi; echo '=DNSRECON='; if command -v dnsrecon >/dev/null 2>&1; then timeout -k 5 90 dnsrecon -d {target} -t std,brt -D /usr/share/wordlists/dnsrecon/top-level-names.txt 2>&1 | grep -iE '\\[+\\] (A|CNAME)' | head -60; else echo '[dnsrecon not installed]'; fi; echo '=AMASS PASSIVE='; if command -v amass >/dev/null 2>&1; then timeout -k 5 120 amass enum -passive -d {target} 2>&1 | grep -iE '^[a-z0-9_.-]+\\.{target}$' | sort -u | head -60; else echo '[amass not installed]'; fi; echo '=RESOLVED SUBS='; for s in www api dev admin mail vpn portal staging stage app test beta m mobile login dashboard auth sso oauth gateway proxy cdn static assets img media files docs support intranet internal hr crm jenkins git gitlab ci registry db mysql postgres redis cache queue analytics monitor status; do ip=$(dig +short $s.{target} A 2>/dev/null | head -1); if [ -n \"$ip\" ]; then echo \"$s.{target} -> $ip\"; fi; done",
                "fallback_cmd": "echo '=RESOLVED SUBS='; for s in www api dev admin mail; do ip=$(dig +short $s.{target} A 2>/dev/null | head -1); [ -n \"$ip\" ] && echo \"$s.{target} -> $ip\"; done",
                "parse": "subdomains",
            },
            {
                "id": "recon_urls", "label": "URL & Endpoint Discovery", "tool": "katana / curl",
                "description": "Enumerates every URL the application exposes: robots.txt and sitemap.xml entries plus a katana crawl (link following, JavaScript endpoint parsing, known-file discovery). Informational only — each reported URL was actually reached or declared by the site; nothing is guessed.",
                "cmd_template": "echo '=ROBOTS='; curl -sk --max-time 8 {base_url}/robots.txt 2>&1 | head -60; echo '=SITEMAP='; curl -sk --max-time 8 {base_url}/sitemap.xml 2>&1 | grep -oiE '<loc>[^<]+' | sed 's/<loc>//I' | head -60; echo '=KATANA='; if command -v katana >/dev/null 2>&1; then timeout -k 5 180 katana -u {base_url} -silent -d 3 -jc -kf all 2>/dev/null | sort -u | head -200; else echo '[katana not installed]'; fi",
                "fallback_cmd": "echo '=ROBOTS='; curl -sk --max-time 8 {base_url}/robots.txt 2>&1 | head -40; echo '=SITEMAP='; curl -sk --max-time 8 {base_url}/sitemap.xml 2>&1 | grep -oE 'https?://[^ ]+' | head -40",
                "parse": "urls",
            },
            {
                "id": "recon_osint_passive", "label": "Passive OSINT", "tool": "whois / RIPE / geoip",
                "description": "Registration data, ASN/organisation, routing visibility and geolocation context for the target. Information-only — never a vulnerability claim on its own.",
                "cmd_template": "echo '=WHOIS='; timeout -k 5 30 whois {target} 2>&1 | grep -iE 'registrant|org-name|organization|netname|descr|country|abuse-c|created:|expires:' | head -20; echo '=ROUTING PREFIX='; timeout -k 5 20 python3 -c \"import json,urllib.request\ntry:\n d=json.load(urllib.request.urlopen('https://stat.ripe.net/data/prefix/data.json?resource={target}',timeout=6))\n p=(d.get('data',{}) or {}).get('prefixes')\n print('prefix:', p[0].get('prefix') if p else 'none')\nexcept Exception:\n print('prefix: unknown')\"; echo '=GEOIP='; timeout -k 5 15 python3 -c \"import json,urllib.request\ntry:\n d=json.load(urllib.request.urlopen('https://ipwho.is/{target}',timeout=6))\n print('country:',d.get('country'))\n print('org:',d.get('connection',{}).get('org'))\nexcept Exception:\n print('geoip: unavailable')\"",
                "fallback_cmd": "timeout -k 5 30 whois {target} 2>&1 | grep -iE 'org-name|netname|descr|country' | head -15",
                "parse": "generic",
            },
            {
                "id": "recon_breach_osint", "label": "Employee / Email Breach OSINT", "tool": "theHarvester / HIBP",
                "description": "Harvests employee emails via theHarvester (written to {outdir}/theharvester_emails.txt). If PWM_HIBP_KEY is set, each unique address is checked against Have I Been Pwned; a COMPROMISED finding is only emitted for a real 200 breach response.",
                "cmd_template": "mkdir -p {outdir}/osint; if command -v theHarvester >/dev/null 2>&1; then timeout -k 5 120 theHarvester -d {target} -b baidu,yahoo,dnsdumpster,certspotter,crtsh,hackertarget,rapiddns -l 300 2>&1 | tee {outdir}/theharvester_emails.txt | sed -n '/Emails found/,$p' | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+' | sort -u | head -40; else echo '[theHarvester not installed]'; fi; echo '=HIBP CHECK='; if [ -n \"$PWM_HIBP_KEY\" ]; then python3 -c \"import os,re,urllib.request,urllib.error,json\nkey=os.environ.get('PWM_HIBP_KEY'); em=[]\ntry:\n for line in open('{outdir}/theharvester_emails.txt',errors='ignore'):\n  em += re.findall(r'[a-z0-9._%+-]+@[a-z0-9.-]+',line)\nexcept Exception:\n pass\nfor e in list(dict.fromkeys(em))[:15]:\n try:\n  req=urllib.request.Request('https://haveibeenpwned.com/api/v3/breachedaccount/'+e,headers={'hibp-api-key':key,'user-agent':'pwm-osint'})\n  r=urllib.request.urlopen(req,timeout=10)\n  d=json.load(r)\n  if isinstance(d,list) and d: print('COMPROMISED:'+e+'|'+','.join((x.get('Name') or '') for x in d[:5]))\n  else: print('NO_BREACH:'+e)\n except urllib.error.HTTPError as he:\n  if he.code==404: print('NO_BREACH:'+e)\n  else: print('HIBP_ERROR:'+e+'|http_'+str(he.code))\n except Exception as ex:\n  print('HIBP_ERROR:'+e+'|'+str(ex)[:60])\n\"; else echo '[PWM_HIBP_KEY not set — breach lookup skipped; discovery only]'; fi",
                "fallback_cmd": "echo '[theHarvester not available — no email OSINT run]'",
                "parse": "breach_osint",
            },
            {
                "id": "recon_js_leak", "label": "JS / Endpoint Leakage", "tool": "python / curl",
                "description": "Crawls script references on the app, downloads each JS bundle, and extracts API endpoints. Emits a high finding ONLY when a real secret pattern (AWS/stripe/GitHub/GCP/slack/JWT/private key/password) is present in bundle content.",
                "cmd_template": "python3 - <<'PY'\nimport urllib.request,re\nhtml=''\nfor page in ('/', '/spa'):\n    try:\n        html+=urllib.request.urlopen('http://{target}'+page,timeout=8).read().decode('utf-8','ignore')\n    except Exception:\n        pass\nscripts=re.findall(r'''<script[^>]+src=[\"']([^\"']+)[\"']''',html)\nscripts=[s for s in scripts if s.endswith('.js')][:12]\njs=''\nfor s in scripts:\n    u2=s if s.startswith('http') else ('http://{target}'+s if s.startswith('/') else 'http://{target}/'+s)\n    try:\n        js+=urllib.request.urlopen(u2,timeout=6).read().decode('utf-8','ignore')+'\\n'\n    except Exception:\n        pass\nprint('=====JS-SRC-LIST=====')\nfor s in scripts: print(s)\nprint('=====JS-ENDPOINTS=====')\npat=r'''[\"']((?:/|https?://)[A-Za-z0-9_\\-\\./]*(?:/api/|/v1/|/v2/|/graphql|/rest|/wp-json|/upload|/download|/assets)[A-Za-z0-9_\\-\\./]*)[\"']'''\nfor m in sorted(set(re.findall(pat,js)))[:40]: print(m)\nprint('=====JS-SECRETS=====')\npats=[(r'sk_[A-Za-z0-9_]{20,}','stripe'),(r'AKIA[0-9A-Z]{16}','aws'),(r'ghp_[A-Za-z0-9]{30,}','github'),(r'AIza[0-9A-Za-z_-]{30,}','gcp'),(r'xox[baprs]-[A-Za-z0-9-]{10,}','slack'),(r'(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.)[A-Za-z0-9_-]{10,}','jwt'),(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----','private_key'),(r'password\\?\\s*[:=]\\s*[\"\\']([^\"\\']{6,})[\"\\']','password')]\nfor pat,name in pats:\n    for m in list(set(re.findall(pat,js)))[:5]:\n        v=m if isinstance(m,str) else (m[-1] if m[-1] else m[0])\n        print('SECRET:'+name+':'+(v[:70] if v else ''))\nprint('=====SOURCEMAP=====')\nfor s in scripts[:8]:\n    u2=s if s.startswith('http') else ('http://{target}'+s if s.startswith('/') else 'http://{target}/'+s)\n    try:\n        b=urllib.request.urlopen(u2+'.map',timeout=6).read()\n        if b[:1]==b'{': print('MAP:'+u2+'.map')\n    except Exception:\n        pass\nPY",
                "fallback_cmd": "echo 'JS_SCAN_ERROR: no python3 urllib available'",
                "parse": "js_leak",
            },
            {
                "id": "recon_version_cve", "label": "Service Version → NVD CVE Cross-Reference", "tool": "nmap -sV / NVD API",
                "description": "Re-runs light version detection, then each service/version pair is looked up as an exact CPE against the NVD cpeName API (verified vectors only, never keyword guesses). CVE findings carry the real NVD vector.",
                "cmd_template": "nmap -sV --version-light --max-retries 1 -p {ports} -T4 -oN {outdir}/nmap_versions.txt {target} 2>&1 | grep -iE '^[0-9]+/tcp.*open' | head -40",
                "fallback_cmd": "echo 'NO_NMAP'",
                "parse": "version_cve",
            },
            {
                "id": "recon_tech", "label": "Web Stack / Technology Fingerprint", "tool": "whatweb / curl / nuclei",
                "description": "Fingerprint the web stack from four real evidence sources — whatweb plugins, response headers, HTML asset/meta tags and the nuclei technologies template set. Every observed technology is classified into Analytics, CDN, Security, UI/Web Frameworks, Advertising, Payment Processors, Font Scripts, Libraries, RUM, Web Servers, Customer Data Platform, Programming Languages or Miscellaneous. Informational only; a technology is never reported unless its signature is literally present in the output.",
                "cmd_template": "echo '=WHATWEB='; if command -v whatweb >/dev/null 2>&1; then timeout -k 5 60 whatweb -a 3 {base_url} 2>&1 | head -20; else echo '[whatweb not installed]'; fi; echo '=HEADERS='; timeout -k 5 20 curl -skIL --max-time 8 {base_url} 2>&1 | head -40; echo '=BODY='; timeout -k 5 25 curl -sk --max-time 10 {base_url} 2>&1 | grep -oiE '<(script|link|meta|img)[^>]*>|(__NEXT_DATA__|__NUXT__|data-reactroot|wp-content|wp-includes)' | head -60; echo '=NUCLEI TECHNOLOGIES='; if command -v nuclei >/dev/null 2>&1 && [ -d {nuclei_dir}/http/technologies ]; then timeout -k 5 150 nuclei -u {base_url} -t {nuclei_dir}/http/technologies -silent -duc 2>&1 | head -60; else echo '[nuclei or templates not installed]'; fi",
                "fallback_cmd": "curl -skIL --max-time 8 {base_url} 2>&1 | head -30",
                "parse": "tech",
            },
            {
                "id": "recon_nuclei", "label": "Nuclei Exposure & Misconfig Recon", "tool": "nuclei",
                "description": "Scan against exposures, misconfiguration, exposed-panels and token-spray templates only — recon-grade detection feeding later verification.",
                "cmd_template": "if command -v nuclei >/dev/null 2>&1 && [ -d {nuclei_dir}/http ]; then timeout -k 5 180 nuclei -u http://{target} -t {nuclei_dir}/http/exposures -t {nuclei_dir}/http/misconfiguration -t {nuclei_dir}/http/exposed-panels -t {nuclei_dir}/http/token-spray -severity critical,high,medium -silent -duc -o {outdir}/nuclei_recon.txt 2>&1 | head -80; else echo '[nuclei or templates not installed]'; fi",
                "fallback_cmd": "echo '[nuclei not installed]'",
                "parse": "nuclei",
            },
            {
                "id": "recon_content", "label": "Content Discovery", "tool": "ffuf / gobuster",
                "description": "Directory/file discovery with ffuf and gobuster wordlists against the discovered web origin ({base_url}). Both tools are wall-clock bounded (240s gobuster / 120s ffuf) with 5s per-request timeouts so a stalled or filtered host can never hang the substage. Findings are informational paths — never vulnerabilities by status alone. 3xx statuses are explicitly ignored for vuln claims.",
                "cmd_template": "echo '=GOBUSTER='; if command -v gobuster >/dev/null 2>&1; then timeout -k 5 240 gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt -t 40 -q --no-error --timeout 5s -x php,txt,bak,bak2,sql,zip,tar.gz,conf,xml,json,log,env -o {outdir}/gobuster_recon.txt 2>&1 | head -80; else echo '[gobuster not installed]'; fi; echo '=FFUF='; if command -v ffuf >/dev/null 2>&1; then timeout -k 5 120 ffuf -u {base_url}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,202,204,301,302,307,308,401,403 -fc 404 -t 40 -timeout 5 2>&1 | grep -viE 'INFO|WARNING' | head -60; else echo '[ffuf not installed]'; fi",
                "fallback_cmd": "echo '[content discovery tools not available]'",
                "parse": "dirb",
            },
            {
                "id": "recon_ad_enum", "label": "Active Directory Enumeration", "tool": "ldapsearch / nmap NSE",
                "description": "Attempts an anonymous LDAP base query and common default naming contexts, plus nmap NSE for LDAP/Kerberos/SMB. Anything reported is gated on the service actually responding with directory data.",
                "cmd_template": "echo '=LDAP BASE='; if command -v ldapsearch >/dev/null 2>&1; then timeout -k 5 20 ldapsearch -x -H ldap://{target} -s base namingContexts 2>&1 | head -15 || echo '[ldap bind failed]'; else echo '[ldapsearch not installed]'; fi; echo '=DEFAULT CONTEXTS='; if command -v ldapsearch >/dev/null 2>&1; then for dc in 'DC=corp,DC=local' 'DC=ad,DC=corp,DC=local' 'DC=domain,DC=local'; do timeout -k 3 8 ldapsearch -x -H ldap://{target} -b \"$dc\" -s base dn 2>&1 | head -4; done; fi; echo '=NSE LDAP='; timeout -k 5 40 nmap --script=ldap-rootdse,ldap-search,ldap-anonymous -p 389,636,88,3268,3269 {target} 2>&1 | head -40",
                "fallback_cmd": "echo '[ad enum unavailable]'",
                "parse": "ad_enum",
            },
            {
                "id": "recon_cloud", "label": "Cloud / CDN Misconfig Baseline", "tool": "curl / python",
                "description": "Provider and CDN header fingerprinting plus cloud well-known endpoint checks. Emits informational provider findings from real header evidence only.",
                "cmd_template": "echo '=PROVIDER HEADERS (HTTP)='; curl -skI --max-time 8 http://{target} 2>&1 | grep -iE 'server|x-amz-|x-azure-|x-gcs-|x-goog-|via|x-sucuri|x-cld-|cf-ray|x-host' | head -12; echo '=PROVIDER HEADERS (HTTPS)='; curl -skI --max-time 8 https://{target} 2>&1 | grep -iE 'server|x-amz-|x-azure-|x-gcs-|x-cf-|via|cf-ray' | head -8; echo '=CLOUD WELL-KNOWN='; for u in .well-known/openid-configuration .well-known/security.txt robots.txt; do code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 'http://{target}/'$u); echo \"$u -> $code\"; done",
                "fallback_cmd": "curl -skI --max-time 8 http://{target} 2>&1 | grep -iE 'server|x-amz-|cf-ray|via' | head -8",
                "parse": "cloud",
            },
        ],
    },
    {
        "id": "vuln", "label": "Stage 2 — Vulnerability Analysis",
        "color": "amber", "icon": "02", "parallel": True,
        "substages": [
            {
                "id": "vuln_cve", "label": "CVE / Vulners + Vulscan", "tool": "nmap vulners / vulscan",
                "description": "Map each open service version to CVE database via nmap vulners and vulscan NSE scripts. Dual CVE source for broader coverage.",
                "cmd_template": "nmap -sV --script=vulners --script-args mincvss=4.0 -p {ports} -T4 {target} 2>&1; echo '---VULSCAN---'; nmap -sV --script=vulscan/vulscan.nse --script-args vulscandb=scipvuldb.csv -p {ports} -T4 {target} 2>&1 | grep -E 'CVE|vuln|CVSS' | head -40",
                "fallback_cmd": "nmap -sV --script=vulners --script-args mincvss=4.0 -p {ports} -T4 {target} 2>&1",
                "parse": "vulners",
            },
            {
                "id": "vuln_nuclei", "label": "Nuclei Template Scan", "tool": "nuclei",
                "description": "Fast template-based vulnerability scanner covering CVEs, misconfigs, exposures, default-logins and takeovers.",
                "cmd_template": "nuclei -u http://{target} -severity critical,high,medium -t {nuclei_dir}/http/cves -t {nuclei_dir}/http/vulnerabilities -t {nuclei_dir}/http/misconfiguration -t {nuclei_dir}/http/exposures -t {nuclei_dir}/http/default-logins -t {nuclei_dir}/http/takeovers -o {outdir}/nuclei.txt -rate-limit 50 -duc 2>&1 | head -80",
                "fallback_cmd": "echo '[nuclei not installed] Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'",
                "parse": "nuclei",
            },
            {
                "id": "vuln_searchsploit", "label": "ExploitDB Lookup", "tool": "searchsploit",
                "description": "Search offline ExploitDB for each discovered service banner.",
                "cmd_template": "searchsploit {banner_search} 2>&1 | head -60",
                "parse": "searchsploit",
            },
            {
                "id": "vuln_web_dirs", "label": "Web Directory & File Brute", "tool": "gobuster / ffuf",
                "description": "Enumerate hidden directories, admin panels, config files, backup files, API paths.",
                "cmd_template": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 60 -q --no-error -x php,asp,aspx,jsp,txt,bak,conf,xml,json,sql,log,zip,tar.gz -o {outdir}/gobuster.txt 2>&1 | head -80; echo '---FFUF FUZZ---'; ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,401,403 -t 50 -o {outdir}/ffuf.json 2>&1 | grep -v INFO | head -40",
                "fallback_cmd": "dirb http://{target} /usr/share/wordlists/dirb/common.txt -S 2>&1 | head -80",
                "parse": "dirb",
            },
            {
                "id": "vuln_nikto", "label": "Nikto Web Audit", "tool": "nikto",
                "description": "Checks 6700+ dangerous files, outdated software, misconfigs, XSS, SQLi indicators.",
                "cmd_template": "nikto -h {target} -maxtime 90 -Tuning 1234567890abcde 2>&1 | head -120",
                "parse": "nikto",
            },
            {
                "id": "vuln_ssl", "label": "TLS / SSL Deep Check", "tool": "sslscan / testssl",
                "description": "Cipher suites, certificate chain, Heartbleed, POODLE, ROBOT, CRIME, BEAST, SWEET32.",
                "cmd_template": "sslscan --no-colour {target}:443 2>&1 | head -80; echo '---OPENSSL---'; echo '' | openssl s_client -connect {target}:443 -servername {target} 2>&1 | head -50; echo '---TESTSSL---'; if command -v testssl.sh >/dev/null 2>&1; then testssl.sh --fast --quiet {target} 2>&1 | head -60; else echo '[testssl.sh not installed — skipped]'; fi",
                "fallback_cmd": "echo '' | openssl s_client -connect {target}:443 -servername {target} 2>&1 | head -60",
                "parse": "ssl",
            },
            {
                "id": "vuln_snmp", "label": "SNMP Community Probe", "tool": "onesixtyone / snmpwalk",
                "description": "Default and custom community strings, full MIB walk on success, SNMP version detection.",
                "cmd_template": "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {target} 2>&1; snmpwalk -v2c -c public -t 5 {target} 1.3.6.1.2.1.1 2>&1 | head -30; snmpwalk -v2c -c public {target} 1.3.6.1.2.1.25 2>&1 | head -20; echo '---SNMP v3---'; nmap --script=snmp-info,snmp-processes,snmp-interfaces -p 161 {target} 2>&1 | head -40",
                "parse": "snmp",
            },
            {
                "id": "vuln_smtp_ldap", "label": "SMTP / LDAP / FTP Audit", "tool": "nmap NSE",
                "description": "SMTP open relay, user enumeration, LDAP anonymous bind, FTP anonymous login and version checks.",
                "cmd_template": "echo '---SMTP---'; nmap --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 -p 25,465,587 {target} 2>&1 | head -40; echo '---LDAP---'; nmap --script=ldap-rootdse,ldap-search,ldap-brute -p 389,636 {target} 2>&1 | head -30; echo '---FTP---'; nmap --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p 21 {target} 2>&1 | head -30",
                "parse": "nse_deep",
            },
            {
                "id": "vuln_evidence", "label": "Evidence Capture — Screenshot / PCAP", "tool": "chromium / tcpdump",
                "description": "For every scorable finding (critical/high/medium with a reachable http endpoint), a headless-chrome screenshot and a tcpdump PCAP of a short re-probe are captured into {outdir}/evidence. Evidence is attached to the finding; captures that fail are reported, not fabricated.",
                "cmd_template": "echo 'evidence capture substage (in-process)'",
                "parse": "evidence",
            },
            {
                "id": "vuln_assess", "label": "CVSS Scoring & False-Positive Triage", "tool": "in-process",
                "description": "Computes a CVSS v3.1 vector + base score for every finding, assigns an automated triage verdict (confirmed / tool-confirmed / needs_review / info), records the log, and prints a reviewable assessment. Analyst overrides land via POST /api/session/<sid>/triage.",
                "cmd_template": "echo 'assessment substage (in-process)'",
                "parse": "assess",
            },
        ],
    },
    {
        "id": "deep", "label": "Stage 3 — Deep & Zero-Day Analysis",
        "color": "zday", "icon": "03", "parallel": True,
        "substages": [
            {
                "id": "deep_banner_anomaly", "label": "Banner Anomaly Detection", "tool": "nmap NSE",
                "description": "Banner grabs via nmap NSE. Flags version mismatches and unexpected protocol behaviour.",
                "cmd_template": "nmap -sV -p {ports} --script=banner,http-headers,ssh-hostkey --open -T4 {target} 2>&1 | head -80",
                "parse": "banner_anomaly",
            },
            {
                "id": "deep_version_gap", "label": "Version Gap / Unpatched Analysis", "tool": "nmap",
                "description": "Compares discovered service versions against latest known-stable; flags EOL and outdated builds.",
                "cmd_template": "nmap -sV -p {ports} --version-intensity 9 -T4 {target} 2>&1 | grep -E 'open|version' | head -40",
                "parse": "version_gap",
            },
            {
                "id": "deep_http_anomaly", "label": "HTTP Behaviour Anomaly", "tool": "curl probes",
                "description": "Path traversal, verb tampering, host header injection, sensitive file exposure.",
                "cmd_template": "echo '---TRAVERSAL---'; curl -sk --max-time 8 'http://{target}/../../../../etc/passwd' -o - 2>&1 | head -5; echo '---VERB TAMPER---'; curl -skI -X TRACE 'http://{target}/' 2>&1 | head -10; echo '---HOST INJECT---'; curl -skI -H 'Host: evil.com' 'http://{target}/' 2>&1 | head -8; echo '---OPTIONS---'; curl -skI -X OPTIONS 'http://{target}/' 2>&1 | head -8; echo '---ADMIN---'; body=$(curl -skL --max-time 8 -r 0-199 'http://{target}/admin' 2>/dev/null | tr '\\n' ' '); code=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/admin' 2>/dev/null); echo \"body:admin[$code] $body\"; echo '---GIT---'; body=$(curl -skL --max-time 8 -r 0-199 'http://{target}/.git/config' 2>/dev/null | tr '\\n' ' '); code=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/.git/config' 2>/dev/null); echo \"body:.git[$code] $body\"; echo '---ENV---'; body=$(curl -skL --max-time 8 -r 0-199 'http://{target}/.env' 2>/dev/null | tr '\\n' ' '); code=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/.env' 2>/dev/null); echo \"body:.env[$code] $body\"",
                "parse": "http_anomaly",
            },
            {
                "id": "deep_timing", "label": "Timing / Side-Channel Probe", "tool": "curl timing",
                "description": "Response time variance for blind SQLi, auth oracle, and timing-based info leaks.",
                "cmd_template": "for i in 1 2 3 4 5; do curl -sk -o /dev/null -w \"t=%{time_total} code=%{http_code}\\n\" 'http://{target}/' 2>&1; done; echo '---LOGIN TIMING---'; curl -sk -o /dev/null -w \"valid_user=%{time_total}\\n\" -X POST 'http://{target}/login' -d 'user=admin&pass=wrong' 2>&1; curl -sk -o /dev/null -w \"invalid_user=%{time_total}\\n\" -X POST 'http://{target}/login' -d 'user=zzzinvalid999&pass=wrong' 2>&1; echo '---SQLI SLEEP---'; curl -sk -o /dev/null -w \"sqli_probe=%{time_total}\\n\" 'http://{target}/?id=1+AND+SLEEP(3)' 2>&1; curl -sk -o /dev/null -w \"sqli_baseline=%{time_total}\\n\" 'http://{target}/?id=1' 2>&1",
                "parse": "timing",
            },
            {
                "id": "deep_auth_probe", "label": "Auth & Session Weaknesses", "tool": "curl probes",
                "description": "Session fixation, token flags, default credentials on SSH/FTP/HTTP.",
                "cmd_template": "echo '---SESSION HEADERS---'; curl -skI --max-time 8 'http://{target}/login' 2>&1 | grep -iE 'set-cookie|www-auth|x-frame|x-xss|strict-transport|content-security' | head -15; echo '---BASIC AUTH PROBE---'; anon=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/' 2>/dev/null); echo \"anon=$anon\"; curl -sku admin:admin --max-time 8 -o /dev/null -w 'admin:admin=%{http_code}\\n' 'http://{target}/' 2>&1; curl -sku admin:password --max-time 8 -o /dev/null -w 'admin:password=%{http_code}\\n' 'http://{target}/' 2>&1; curl -sku root:root --max-time 8 -o /dev/null -w 'root:root=%{http_code}\\n' 'http://{target}/' 2>&1; echo '---FTP ANON---'; curl -s --max-time 8 ftp://{target}/ 2>&1 | head -10; echo '---SSH VERSION---'; nc -w 4 {target} 22 2>&1 | head -3",
                "parse": "auth_probe",
            },
            {
                "id": "deep_service_proto", "label": "Protocol-Level Anomaly", "tool": "nmap NSE deep",
                "description": "DNS recursion, NTP monlist, SMTP open relay, LDAP anon bind, Redis/MongoDB unauth.",
                "cmd_template": "nmap --script=dns-recursion,ntp-monlist,smtp-open-relay,ldap-rootdse,ftp-anon,ftp-bounce,redis-info,mongodb-info -p 25,53,110,123,389,443,636,6379,27017 -T4 {target} 2>&1 | head -80",
                "parse": "nse_deep",
            },{
                "id": "deep_xss_probe", "label": "XSS & Injection Surface Probe", "tool": "dalfox / curl",
                "description": "Reflected XSS, open redirect, XXE, SSTI and DOM injection probes across common parameters.",
                "cmd_template": "echo '---XSS REFLECT---'; for p in q search id name input; do code=$(curl -skL -o /dev/null -w '%{http_code}' http://{target}/?$p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E 2>/dev/null); body=$(curl -skL http://{target}/?$p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E 2>/dev/null | grep -oi 'onerror\\|alert' | head -1); echo $p' XSS '${code}': '$body; done; echo '---OPEN REDIRECT---'; for p in next redirect url return dest; do r=$(curl -skI http://{target}/?$p=https://evil.com 2>/dev/null | grep -i 'location.*evil' | head -1); echo $p': '$r; done; echo '---XXE PROBE---'; curl -sk -X POST -H 'Content-Type: application/xml' --data-binary '<root></root>' http://{target}/ -o - 2>&1 | grep -iE 'root:|xxe|entity' | head -3; echo '---SSTI PROBE---'; curl -sk http://{target}/?name=%7B%7B7*7%7D%7D -o - 2>&1 | grep -o '49' | head -2; echo '---DALFOX---'; if command -v dalfox >/dev/null 2>&1; then dalfox url http://{target}/ --silence --no-spinner 2>&1 | head -20; else echo '[dalfox not installed — skipped]'; fi",
                "fallback_cmd": "echo '---XSS CHECK---'; for p in q search id; do curl -sk http://{target}/?$p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E -o - 2>&1 | grep -oi 'alert' | head -1; done",
                "parse": "xss_probe",
            },
            {
                "id": "deep_cms_scan", "label": "CMS & Framework Detection", "tool": "wpscan / droopescan",
                "description": "Detect WordPress, Drupal, Joomla, Laravel, Django, Rails installs. Enumerate plugins, themes, users.",
                "cmd_template": "echo '---WP DETECT---'; wb=$(curl -sk --max-time 8 'http://{target}/wp-login.php' 2>/dev/null | tr '\\n' ' ' | head -c 200); wc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/wp-login.php' 2>/dev/null); echo \"wp-login:$wc|$wb\"; curl -sk --max-time 8 'http://{target}/wp-json/wp/v2/users' -o - 2>&1 | head -5; echo '---WPSCAN---'; wpscan --url http://{target} --enumerate vp,u,m --no-update 2>&1 | head -60; echo '---DRUPAL---'; curl -sk --max-time 8 'http://{target}/CHANGELOG.txt' -o - 2>&1 | head -5; db=$(curl -sk --max-time 8 'http://{target}/user/login' 2>/dev/null | tr '\\n' ' ' | head -c 200); dc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/user/login' 2>/dev/null); echo \"drupal_login:$dc|$db\"; echo '---JOOMLA---'; jb=$(curl -sk --max-time 8 'http://{target}/administrator/' 2>/dev/null | tr '\\n' ' ' | head -c 200); jc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/administrator/' 2>/dev/null); echo \"joomla_admin:$jc|$jb\"",
                "fallback_cmd": "wb=$(curl -sk --max-time 8 'http://{target}/wp-login.php' 2>/dev/null | tr '\\n' ' ' | head -c 200); wc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/wp-login.php' 2>/dev/null); echo \"wp-login:$wc|$wb\"; curl -sk --max-time 8 'http://{target}/CHANGELOG.txt' -o - 2>&1 | head -5",
                "parse": "cms_scan",
            },
        ],
    },
    {
        "id": "api_scan", "label": "Stage 4 — API Vulnerability Scan",
        "color": "cyan", "icon": "04", "parallel": True,
        "substages": [
            {
                "id": "api_discovery", "label": "API Endpoint Discovery", "tool": "curl / gobuster",
                "description": "Discover REST/GraphQL endpoints, API versioning, swagger/openapi docs, and common API paths.",
                "cmd_template": "echo '---API PATHS---'; for p in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /graphql /swagger /swagger-ui /swagger.json /openapi.json /api-docs /rest /ws /wsdl /.well-known /health /metrics /actuator /actuator/env /actuator/mappings; do out=$(curl -skL --max-time 8 -w '%{http_code}' -o /tmp/pwm_apid_$$ 'http://{target}'$p 2>/dev/null); body=$(tr '\\n' ' ' < /tmp/pwm_apid_$$ 2>/dev/null | head -c 180); rm -f /tmp/pwm_apid_$$; echo \"$p:$out|$body\"; done; echo '---GRAPHQL INTROSPECT---'; curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' http://{target}/graphql 2>&1 | head -20",
                "parse": "api_discovery",
            },
            {
                "id": "api_bola", "label": "BOLA / IDOR Testing", "tool": "curl probes",
                "description": "Broken Object Level Authorization — test ID enumeration across common API object endpoints.",
                "cmd_template": "echo '---BOLA/IDOR PROBES---'; for id in 1 2 3 100 999 0 -1; do echo \"=== id=$id ===\"; curl -sk 'http://{target}/api/v1/users/'$id -o - 2>&1 | head -5; curl -sk 'http://{target}/api/users/'$id -o - 2>&1 | head -5; curl -sk 'http://{target}/api/v1/orders/'$id -o - 2>&1 | head -5; done; echo '---UUID PROBE---'; curl -sk 'http://{target}/api/v1/users/00000000-0000-0000-0000-000000000001' -o - 2>&1 | head -5",
                "parse": "api_bola",
            },
            {
                "id": "api_auth", "label": "Broken Authentication Probe", "tool": "curl probes",
                "description": "Test JWT weaknesses, missing auth on endpoints, token reuse, and brute-force protection.",
                "cmd_template": "echo '---NO AUTH---'; anon=$(curl -sk --max-time 8 'http://{target}/api/v1/admin' -o /dev/null -w '%{http_code}' 2>/dev/null); echo \"anon:$anon|\"; curl -sk --max-time 8 'http://{target}/api/v1/users' -o /dev/null -w 'users: %{http_code}\\n' 2>/dev/null; curl -sk --max-time 8 'http://{target}/api/v1/config' -o /dev/null -w 'config: %{http_code}\\n' 2>/dev/null; echo '---JWT NONE ALG---'; curl -sk --max-time 8 -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.' 'http://{target}/api/v1/admin' -o /dev/null -w 'jwt_none: %{http_code}\\n' 2>/dev/null; echo '---NULL TOKEN---'; curl -sk --max-time 8 -H 'Authorization: Bearer null' 'http://{target}/api/v1/users' -o /dev/null -w 'null_token: %{http_code}\\n' 2>/dev/null; echo '---NO TOKEN---'; curl -sk --max-time 8 'http://{target}/api/v1/profile' -o - 2>&1 | head -5",
                "parse": "api_auth",
            },
            {
                "id": "api_injection", "label": "API Injection Testing", "tool": "curl probes",
                "description": "SQL injection, NoSQL injection, command injection and SSTI via API parameters.",
                "cmd_template": "echo '---SQL INJECT---'; curl -sk --max-time 8 'http://{target}/api/v1/users?id=1%27' -o - 2>&1 | head -8; curl -sk --max-time 8 'http://{target}/api/v1/search?q=test%27+OR+1%3D1--' -o - 2>&1 | head -8; echo '---NOSQL INJECT---'; curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{{\"username\":{{\"$gt\":\"\"}},\"password\":{{\"$gt\":\"\"}}}}' 'http://{target}/api/login' 2>&1 | head -8; curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{{\"username\":{{\"$ne\":null}},\"password\":{{\"$ne\":null}}}}' 'http://{target}/api/v1/login' 2>&1 | head -8; echo '---SSTI PROBE---'; echo \"SSTI_RESULT:$(curl -sk --max-time 8 'http://{target}/api/v1/search?q={{7*7}}' -o - 2>&1 | head -c 80 | tr '\\n' ' ')\"; echo \"SSTI_RESULT:$(curl -sk --max-time 8 'http://{target}/api/v1/render?template={{7*7}}' -o - 2>&1 | head -c 80 | tr '\\n' ' ')\"",
                "parse": "api_injection",
            },
            {
                "id": "api_ssrf", "label": "SSRF Detection", "tool": "curl probes",
                "description": "Server-Side Request Forgery — test URL parameters for internal service access.",
                "cmd_template": "echo '---SSRF PROBES---'; for param in url redirect next return callback dest destination link; do base=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' \"http://{target}/api/v1/fetch?$param=0\" 2>/dev/null); imds=$(curl -skL --max-time 8 -w '%{http_code}' -o /tmp/pwm_ssrf_$$ \"http://{target}/api/v1/fetch?$param=http://169.254.169.254/latest/meta-data/\" 2>/dev/null); ibody=$(tr '\\n' ' ' < /tmp/pwm_ssrf_$$ 2>/dev/null | head -c 120); rm -f /tmp/pwm_ssrf_$$; local=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' \"http://{target}/api/v1/proxy?$param=http://127.0.0.1:22\" 2>/dev/null); echo \"$param=baseline:$base|imds:$imds|$ibody|local22:$local\"; done; echo '---FILE SSRF---'; curl -skL --max-time 8 'http://{target}/api/v1/fetch?url=file:///etc/passwd' -o - 2>&1 | head -5",
                "parse": "api_ssrf",
            },
            {
                "id": "api_mass_assign", "label": "Mass Assignment / Overpost", "tool": "curl probes",
                "description": "Broken Object Property Level Auth — test for mass assignment and privilege escalation via API body.",
                "cmd_template": "echo '---MASS ASSIGN---'; curl -sk --max-time 8 -X PUT -H 'Content-Type: application/json' -d '{{\"role\":\"admin\",\"is_admin\":true,\"admin\":true,\"privilege\":\"admin\"}}' 'http://{target}/api/v1/users/1' -o - 2>&1 | head -8; curl -sk --max-time 8 -X PATCH -H 'Content-Type: application/json' -d '{{\"role\":\"superuser\",\"verified\":true,\"credits\":99999}}' 'http://{target}/api/v1/profile' -o - 2>&1 | head -8; echo '---FUNC LEVEL---'; del=$(curl -sk --max-time 8 -X DELETE 'http://{target}/api/v1/users/1' -o /dev/null -w '%{http_code}' 2>/dev/null); echo \"DELETE user:$del|\"; au=$(curl -sk --max-time 8 'http://{target}/api/v1/admin/users' 2>/dev/null | tr '\\n' ' ' | head -c 180); auc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/api/v1/admin/users' 2>/dev/null); echo \"admin/users:$auc|$au\"; idb=$(curl -sk --max-time 8 'http://{target}/api/v1/internal/debug' 2>/dev/null | tr '\\n' ' ' | head -c 180); idc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/api/v1/internal/debug' 2>/dev/null); echo \"internal/debug:$idc|$idb\"",
                "parse": "api_mass_assign",
            },
            {
                "id": "api_misc", "label": "API Misconfiguration & Rate Limit", "tool": "curl probes",
                "description": "Security misconfigs, missing rate limiting, CORS, verbose errors, third-party API exposure.",
                "cmd_template": "echo '---CORS---'; curl -skL -H 'Origin: https://evil.com' -I 'http://{target}/api/v1/users' 2>&1 | grep -i 'access-control'; echo '---RATE LIMIT TEST---'; for i in $(seq 1 15); do curl -sk -o /dev/null -w '%{http_code} ' 'http://{target}/api/v1/login' -d 'user=admin&pass=test'; done; echo ''; echo '---VERBOSE ERROR---'; curl -sk 'http://{target}/api/v1/users/INVALID_ID' -o - 2>&1 | head -10; curl -sk -X POST -H 'Content-Type: application/json' -d '{{\"bad\":\"json\"' 'http://{target}/api/v1/users' -o - 2>&1 | head -10; echo '---THIRD PARTY KEYS---'; curl -sk 'http://{target}/api/v1/config' -o - 2>&1 | grep -iE 'api_key|secret|token|password|key|credential' | head -10",
                "parse": "api_misc",
            },
        ],
    },
    {
        "id": "db_scan", "label": "Stage 5 — Database Vulnerability Scan",
        "color": "purple", "icon": "05", "parallel": True,
        "substages": [
            {
                "id": "db_discovery", "label": "Database Service Discovery", "tool": "nmap",
                "description": "Detect exposed database services: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, Cassandra, Elasticsearch, InfluxDB, Neo4j.",
                "cmd_template": "nmap -sV -p 1433,1521,3306,5432,5984,6379,7474,8086,8529,9042,9200,9300,11211,27017,27018,28015,50000 --open -T4 --script=banner {target} 2>&1",
                "parse": "db_discovery",
            },
            {
                "id": "db_unauth", "label": "Unauthenticated DB Access", "tool": "nmap NSE / curl / redis-cli",
                "description": "Test for unauthenticated access to all exposed database services.",
                "cmd_template": "echo '---REDIS UNAUTH---'; redis-cli -h {target} -p 6379 --no-auth-warning ping 2>&1 | head -5; redis-cli -h {target} -p 6379 --no-auth-warning info server 2>&1 | head -10; redis-cli -h {target} -p 6379 --no-auth-warning CONFIG GET requirepass 2>&1 | head -5; echo '---MONGODB UNAUTH---'; curl -sk 'http://{target}:27017' -o - 2>&1 | head -5; nmap --script=mongodb-info,mongodb-databases -p 27017 {target} 2>&1 | head -30; echo '---ELASTICSEARCH---'; curl -sk 'http://{target}:9200/_cat/indices?v' 2>&1 | head -20; curl -sk 'http://{target}:9200/_cluster/health' 2>&1 | head -10; curl -sk 'http://{target}:9200/_nodes' 2>&1 | head -15; echo '---COUCHDB---'; curl -sk 'http://{target}:5984/_all_dbs' 2>&1 | head -5; echo '---INFLUXDB---'; curl -sk 'http://{target}:8086/query?q=SHOW+DATABASES' 2>&1 | head -5; echo '---MEMCACHED---'; nmap --script=memcached-info -p 11211 {target} 2>&1 | head -20",
                "parse": "db_unauth",
            },
            {
                "id": "db_default_creds", "label": "Default DB Credentials", "tool": "nmap NSE / hydra",
                "description": "Test default credentials for MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Oracle.",
                "cmd_template": "echo '---MYSQL DEFAULT---'; nmap --script=mysql-empty-password,mysql-databases,mysql-users -p 3306 {target} 2>&1 | head -30; echo '---MSSQL DEFAULT---'; nmap --script=ms-sql-empty-password,ms-sql-info,ms-sql-config -p 1433 {target} 2>&1 | head -30; echo '---MYSQL ROOT NOPASS---'; mysqladmin -h {target} -u root status 2>&1 | head -5; echo '---POSTGRES---'; PGPASSWORD='' psql -h {target} -U postgres -c '\\l' 2>&1 | head -10; echo '---HYDRA MYSQL---'; WP=/usr/share/wordlists/metasploit/unix_passwords.txt; [ -f \"$WP\" ] || WP=/usr/share/wordlists/fasttrack.txt; if [ -f \"$WP\" ]; then hydra -l root -P \"$WP\" -t 4 -f {target} mysql 2>&1 | tail -10; else echo '[wordlist missing — hydra skipped]'; fi",
                "fallback_cmd": "nmap --script=mysql-empty-password,mysql-databases,mysql-users -p 3306 {target} 2>&1 | head -30; nmap --script=ms-sql-empty-password,ms-sql-info -p 1433 {target} 2>&1 | head -20",
                "parse": "db_default_creds",
            },
            {
                "id": "db_sqlmap", "label": "sqlmap — Deep SQL Injection Audit", "tool": "sqlmap",
                "description": "Automated SQL injection detection and database fingerprinting using sqlmap across GET/POST parameters and forms. Detection and enumeration only.",
                "cmd_template": "echo '---SQLMAP GET PARAMS---'; sqlmap -u 'http://{target}/?id=1' --batch --level=3 --risk=2 --technique=BEUST --threads=5 --dbs --banner --current-user --current-db --output-dir={outdir}/sqlmap_get 2>&1 | tail -40; echo '---SQLMAP FORMS---'; sqlmap -u 'http://{target}/' --forms --batch --level=3 --risk=2 --technique=BEUST --threads=5 --dbs --output-dir={outdir}/sqlmap_forms 2>&1 | tail -30; echo '---SQLMAP LOGIN---'; sqlmap -u 'http://{target}/login' --data='username=admin&password=test' --batch --level=3 --risk=2 --technique=BEUST --output-dir={outdir}/sqlmap_login 2>&1 | tail -20; echo '---SQLMAP SEARCH---'; sqlmap -u 'http://{target}/search?q=test' --batch --level=3 --risk=2 --technique=BEUST --output-dir={outdir}/sqlmap_search 2>&1 | tail -20",
                "fallback_cmd": "echo '[sqlmap not installed] apt-get install sqlmap'",
                "parse": "sqlmap",
            },
            {
                "id": "db_sqli", "label": "Manual SQL Injection Probes", "tool": "curl / nmap NSE",
                "description": "Error-based, time-based, boolean-based and union-based SQL injection probes.",
                "cmd_template": "echo '---ERROR BASED SQLi---'; for payload in \"'\" \"''\" \"' OR '1'='1\" \"' OR 1=1--\" \"1; SELECT 1\" \"1 UNION SELECT NULL--\" \"1 AND 1=2\"; do encoded=$(python3 -c \"import urllib.parse; print(urllib.parse.quote('$payload'))\" 2>/dev/null || echo '%27'); resp=$(curl -sk \"http://{target}/?id=$encoded\" -o - 2>&1 | grep -iE 'sql|mysql|syntax|error|warning|ORA-' | head -2); echo \"PAYLOAD[$payload]: $resp\"; done; echo '---TIME BASED---'; t1=$(curl -sk -o /dev/null -w '%{time_total}' \"http://{target}/?id=1+AND+SLEEP(4)\" 2>/dev/null); t2=$(curl -sk -o /dev/null -w '%{time_total}' \"http://{target}/?id=1\" 2>/dev/null); echo \"sleep_probe=${t1}s baseline=${t2}s\"; echo '---POST SQLI---'; curl -sk -X POST -d \"username='&password=test\" 'http://{target}/login' -o - 2>&1 | head -5",
                "parse": "db_sqli",
            },
            {
                "id": "db_nosql", "label": "NoSQL Injection Detection", "tool": "curl probes",
                "description": "MongoDB, Redis and Cassandra operator injection, authentication bypass.",
                "cmd_template": "echo '---NOSQL OPERATOR INJECT---'; curl -sk -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}' 'http://{target}/login' -o - 2>&1 | head -8; curl -sk -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}' 'http://{target}/api/login' -o - 2>&1 | head -8; curl -sk -X POST -H 'Content-Type: application/json' -d '{\"$where\":\"1==1\"}' 'http://{target}/api/v1/users' -o - 2>&1 | head -8; echo '---REDIS CMD INJECT---'; redis-cli -h {target} -p 6379 --no-auth-warning CONFIG GET requirepass 2>&1 | head -5; redis-cli -h {target} -p 6379 --no-auth-warning KEYS '*' 2>&1 | head -20",
                "parse": "db_nosql",
            },
            {
                "id": "db_privesc", "label": "DB Privilege & Config Audit", "tool": "nmap NSE / curl",
                "description": "Excessive privileges, verbose errors, missing encryption, audit logging, stored procedures.",
                "cmd_template": "echo '---MYSQL PRIVS---'; nmap --script=mysql-info,mysql-variables,mysql-audit -p 3306 {target} 2>&1 | head -50; echo '---POSTGRES INFO---'; nmap --script=pgsql-info -p 5432 {target} 2>&1 | head -30; echo '---MSSQL INFO---'; nmap --script=ms-sql-info,ms-sql-config,ms-sql-xp-cmdshell -p 1433 {target} 2>&1 | head -40; echo '---ELASTIC SECURITY---'; curl -sk 'http://{target}:9200/_xpack/security?pretty' 2>&1 | head -10; echo '---VERBOSE DB ERRORS---'; curl -sk http://{target}/?id=1%27 -o - 2>&1 | grep -iE 'sql|mysql|syntax error|ora-' | head -10",
                "parse": "db_privesc",
            },
            {
                "id": "db_second_order", "label": "Second-Order SQLi & Stored Payloads", "tool": "sqlmap / curl",
                "description": "Detect second-order SQL injection by registering payloads and observing trigger points.",
                "cmd_template": "echo '---REGISTER PAYLOAD---'; curl -sk -X POST -H 'Content-Type: application/json' -d \"{\\\"username\\\":\\\"admin' OR 1=1--\\\",\\\"email\\\":\\\"test@test.com\\\",\\\"password\\\":\\\"test123\\\"}\" 'http://{target}/api/v1/register' -o - 2>&1 | head -5; echo '---CHECK PROFILE---'; curl -sk 'http://{target}/profile' -o - 2>&1 | grep -iE 'sql|error|syntax' | head -5; echo '---SQLMAP CRAWL---'; sqlmap -u 'http://{target}/' --crawl=2 --batch --level=2 --risk=1 --technique=B --output-dir={outdir}/sqlmap_crawl 2>&1 | tail -20",
                "fallback_cmd": "echo '---SECOND ORDER PROBE---'; curl -sk -X POST -d \"username=admin'--&password=test\" 'http://{target}/register' -o - 2>&1 | head -5",
                "parse": "db_sqli",
            },
        ],
    },
    {
        "id": "reg_scan", "label": "Stage 6 — Registration & Account Provisioning",
        "color": "teal", "icon": "06", "parallel": False,
        "substages": [
            {
                "id": "reg_discovery", "label": "Signup Endpoint Discovery", "tool": "in-process HTTP",
                "description": "Probes common registration paths for a real signup form (password field / register markers), extracts form fields and action, and records whether a CAPTCHA is present. Discovery only — emits informational path findings.",
                "parse": "inprocess",
            },
            {
                "id": "reg_captcha", "label": "Signup CAPTCHA / Anti-Automation", "tool": "in-process HTTP",
                "description": "Reports whether the discovered registration form challenges automated abuse with a CAPTCHA. Emits a low finding only when a real signup form was found and no challenge marker is present.",
                "parse": "inprocess",
            },
            {
                "id": "reg_enum", "label": "Account Enumeration at Signup", "tool": "in-process HTTP",
                "description": "Submits one new and one duplicate registration probe and compares the responses. Emits a finding only when the duplicate is distinguishable and the response explicitly indicates the account already exists.",
                "parse": "inprocess",
            },
            {
                "id": "reg_password_policy", "label": "Password Policy at Signup", "tool": "in-process HTTP",
                "description": "Submits a single weak-password registration probe. Emits a finding only when the registration is accepted and no policy-rejection language is returned.",
                "parse": "inprocess",
            },
            {
                "id": "reg_verification_bypass", "label": "Email-Verification Bypass", "tool": "in-process HTTP",
                "description": "Uses the account created during enumeration to test whether an authenticated session is issued while the response simultaneously demands email verification. Never claims bypass without both conditions.",
                "parse": "inprocess",
            },
            {
                "id": "reg_mass_assign", "label": "Signup Mass-Assignment (Overposting)", "tool": "in-process HTTP",
                "description": "Submits a registration probe carrying role/isAdmin/admin attributes and emits a finding only when the response reflects the injected privileged value.",
                "parse": "inprocess",
            },
            {
                "id": "reg_rate_limit", "label": "Registration Rate Limiting", "tool": "in-process HTTP",
                "description": "Sends a bounded burst (6) of registration attempts reusing one identity (no extra accounts created). Emits a finding only when the endpoint responded and no throttling/block occurred.",
                "parse": "inprocess",
            },
        ],
    },
    {
        "id": "auth_scan", "label": "Stage 7 — Authentication & Login",
        "color": "purple", "icon": "07", "parallel": False,
        "substages": [
            {
                "id": "auth_discovery", "label": "Login Endpoint Discovery", "tool": "in-process HTTP",
                "description": "Probes common login paths for a real authentication form, extracts its field names and action, and records whether MFA is present. Discovery only — informational path findings.",
                "parse": "inprocess",
            },
            {
                "id": "auth_enum", "label": "Username Enumeration at Login", "tool": "in-process HTTP",
                "description": "Compares the login response for a known identity with a wrong password against an unknown identity. Emits a finding only when responses are distinguishable AND the unknown response explicitly says the user is absent while the known response says the password is wrong.",
                "parse": "inprocess",
            },
            {
                "id": "auth_lockout", "label": "Login Lockout / Throttling", "tool": "in-process HTTP",
                "description": "Sends a bounded burst (6) of wrong-password attempts for one existing identity. Emits a finding only when the endpoint kept responding and never throttled or locked (CWE-307). Never performs credential stuffing.",
                "parse": "inprocess",
            },
            {
                "id": "auth_password_reset", "label": "Password-Reset Flow", "tool": "in-process HTTP",
                "description": "Discovers a password-reset endpoint and triggers one reset for a known identity. Emits a finding only when the response discloses the reset token/link in the HTTP body (CWE-640).",
                "parse": "inprocess",
            },
            {
                "id": "auth_oauth", "label": "OAuth / SSO redirect_uri", "tool": "in-process HTTP",
                "description": "Probes OAuth authorize endpoints with an attacker redirect_uri. Emits a finding only when the Location reflects the attacker host without validation (CWE-346).",
                "parse": "inprocess",
            },
            {
                "id": "auth_logout", "label": "Session Invalidation on Logout", "tool": "in-process HTTP", "requires_creds": True,
                "description": "Logs in with an operator account, calls logout, then reuses the old cookie against protected paths. Emits a finding only when the stale cookie still returns protected content (CWE-613).",
                "parse": "inprocess",
            },
        ],
    },
    {
        "id": "session_scan", "label": "Stage 8 — Session Management",
        "color": "indigo", "icon": "08", "parallel": False,
        "substages": [
            {
                "id": "session_cookie_flags", "label": "Session Cookie Flags", "tool": "in-process HTTP", "requires_creds": True,
                "description": "Logs in with an operator account and inspects the Set-Cookie attributes. Emits a finding only for missing HttpOnly/Secure/SameSite flags on the actual session cookie.",
                "parse": "inprocess",
            },
            {
                "id": "session_entropy", "label": "Session Identifier Entropy", "tool": "in-process HTTP", "requires_creds": True,
                "description": "Collects a few session cookies via repeated logins and flags low entropy only when the identifier is short (<12) or uses a tiny character set (<8) (CWE-330).",
                "parse": "inprocess",
            },
            {
                "id": "session_fixation", "label": "Session Fixation on Login", "tool": "in-process HTTP", "requires_creds": True,
                "description": "Compares the pre-authentication cookie with the post-authentication cookie. Emits a finding only when the identifier is not rotated on authentication (CWE-384).",
                "parse": "inprocess",
            },
            {
                "id": "session_jwt", "label": "JWT Session Token", "tool": "in-process HTTP", "requires_creds": True,
                "description": "Decodes the session token if it is a JWT. Emits a finding only when the header declares alg 'none'/empty (unsigned); otherwise records an informational observation.",
                "parse": "inprocess",
            },
        ],
    },
    {
        "id": "authz_scan", "label": "Stage 9 — Authorization & Access Control",
        "color": "rose", "icon": "09", "parallel": False,
        "substages": [
            {
                "id": "authz_forced_browsing", "label": "Unauthenticated Privileged Access", "tool": "in-process HTTP",
                "description": "Requests common administrative/privileged paths without authentication. Emits a finding only when such a path returns HTTP 200 with administrative content and no login form.",
                "parse": "inprocess",
            },
            {
                "id": "authz_vertical", "label": "Vertical Privilege Escalation", "tool": "in-process HTTP", "requires_creds": True,
                "description": "Compares unauthenticated vs non-admin-authenticated access to admin functions. Emits a finding only when a path that rejects anonymous users returns admin content to a non-admin session.",
                "parse": "inprocess",
            },
            {
                "id": "authz_idor", "label": "Object-Level Authorization (BOLA/IDOR)", "tool": "in-process HTTP", "requires_creds": True,
                "description": "With an operator account, requests another identity's object on discovered object endpoints. Emits a finding only when the endpoint is auth-protected yet returns the other identity's distinct data.",
                "parse": "inprocess",
            },
        ],
    },
    {
        "id": "bizlogic_scan", "label": "Stage 10 — Business Logic",
        "color": "amber", "icon": "10", "parallel": False,
        "substages": [
            {
                "id": "bizlogic_csrf", "label": "CSRF Protection on State-Changing Forms", "tool": "in-process HTTP",
                "description": "Inspects discovered state-changing forms for an anti-CSRF token. Emits a finding only when a cookie-based session is in use, the form has no token field, and the session cookie has no SameSite attribute.",
                "parse": "inprocess",
            },
            {
                "id": "bizlogic_workflow", "label": "Business-Logic Coverage", "tool": "in-process HTTP",
                "description": "Records an honest informational coverage note: application-specific workflow/price/quantity logic cannot be verified generically and is not tested (never emitted as a vulnerability).",
                "parse": "inprocess",
            },
        ],
    },
    {
        "id": "exploit_prep", "label": "Stage 11 — Exploitation Prep",
        "color": "coral", "icon": "11", "parallel": False,
        "substages": [
            {
                "id": "ep_hydra", "label": "Default Credential Test", "tool": "hydra",
                "description": "Top-50 default credentials against SSH, FTP, HTTP-Auth, MySQL, RDP.",
                "cmd_template": "WU=/usr/share/wordlists/metasploit/unix_users.txt; WP=/usr/share/wordlists/metasploit/unix_passwords.txt; [ -f \"$WU\" ] || WU=/usr/share/wordlists/fasttrack.txt; [ -f \"$WP\" ] || WP=/usr/share/wordlists/fasttrack.txt; if [ ! -f \"$WU\" ] || [ ! -f \"$WP\" ]; then echo '[wordlists missing — hydra skipped]'; else echo '---SSH BRUTE---'; hydra -L \"$WU\" -P \"$WP\" -t 6 -T 15 -f {target} ssh 2>&1 | tail -20; echo '---FTP BRUTE---'; hydra -L \"$WU\" -P \"$WP\" -t 4 -f {target} ftp 2>&1 | tail -10; echo '---MYSQL BRUTE---'; hydra -l root -P \"$WP\" -t 4 -f {target} mysql 2>&1 | tail -10; fi",
                "fallback_cmd": "WU=/usr/share/wordlists/metasploit/unix_users.txt; WP=/usr/share/wordlists/metasploit/unix_passwords.txt; [ -f \"$WU\" ] || WU=/usr/share/wordlists/fasttrack.txt; [ -f \"$WP\" ] || WP=/usr/share/wordlists/fasttrack.txt; if [ -f \"$WU\" ] && [ -f \"$WP\" ]; then hydra -L \"$WU\" -P \"$WP\" -t 6 -T 15 -f {target} ssh 2>&1 | tail -30; else echo '[wordlists missing — hydra skipped]'; fi",
                "parse": "hydra",
            },
            {
                "id": "ep_msf_check", "label": "Metasploit Safe Check", "tool": "msfconsole",
                "description": "Non-destructive check — confirms vulnerability without exploitation.",
                "cmd_template": "if command -v msfconsole >/dev/null 2>&1; then msfconsole -q -x 'db_nmap -sV -p {ports} {target}; vulns; hosts; services; exit' 2>&1 | grep -vE '^\\[\\*\\] exec|msf6>' | tail -50; else echo '[msfconsole not installed — skipped]'; fi",
                "fallback_cmd": "echo '[msfconsole not installed or timed out — skipped]'",
                "parse": "msf",
            },
            {
                "id": "ep_sqli_verify", "label": "sqlmap Injection Verification", "tool": "sqlmap",
                "description": "Verify and enumerate confirmed SQL injection points. Banner, DBMS, current user, databases.",
                "cmd_template": "timeout -k 5 1200 sqlmap -u 'http://{target}/?id=1' --batch --level=5 --risk=3 --technique=BEUSTQ --threads=10 --timeout=10 --retries=1 --banner --current-user --current-db --hostname --dbs --output-dir={outdir}/sqlmap_verify 2>&1 | tail -60",
                "fallback_cmd": "echo '[sqlmap not installed] apt-get install sqlmap'",
                "parse": "sqlmap",
            },
            {
                "id": "ep_vuln_verify", "label": "CVE / Exploit Verification", "tool": "searchsploit",
                "description": "Cross-reference all discovered service versions against ExploitDB. List applicable modules.",
                "cmd_template": "searchsploit {banner_search} 2>&1 | head -40",
                "parse": "searchsploit",
            },
            {
                "id": "ep_payload_ref", "label": "Payload Reference List", "tool": "msfvenom",
                "description": "Applicable payload types for identified OS. Reference only — no payload generated.",
                "cmd_template": "msfvenom --list payloads 2>&1 | grep -iE 'windows/x64/meterpreter|linux/x64/meterpreter|python/meterpreter|java/meterpreter|php/meterpreter|cmd/unix' | head -25",
                "parse": "generic",
            },
        ],
    },
    {
        "id": "postex", "label": "Stage 12 — Post-Exploitation Review",
        "color": "purple", "icon": "12", "parallel": True,
        "substages": [
            {
                "id": "pe_network_map", "label": "Network Segment Discovery", "tool": "nmap / arp-scan",
                "description": "Discover additional hosts on adjacent subnet, identify live hosts for lateral movement.",
                "cmd_template": "nmap -sn {network} --min-rate 2000 -T4 2>&1 | head -60; echo '---ARP SCAN---'; arp-scan --localnet 2>&1 | head -40",
                "fallback_cmd": "nmap -sn {network} --min-rate 2000 -T4 2>&1 | head -60",
                "parse": "nmap",
            },
            {
                "id": "pe_privesc_ref", "label": "Privilege Escalation Vectors", "tool": "searchsploit / linux-exploit-suggester",
                "description": "Known kernel/sudo/SUID escalation paths for target OS version.",
                "cmd_template": "searchsploit linux kernel local privilege escalation 2>&1 | head -25; echo '---SUDO---'; searchsploit sudo local privilege 2>&1 | head -15; echo '---DIRTY COW---'; searchsploit 'dirty cow' 2>&1 | head -10; echo '---POLKIT---'; searchsploit polkit 2>&1 | head -10; echo '---SUDO MISCONFIG CHECK---'; nmap --script=ssh-run --script-args='ssh-run.cmd=sudo -l,ssh-run.username=,ssh-run.password=' -p 22 {target} 2>&1 | head -20",
                "fallback_cmd": "searchsploit linux kernel local privilege escalation 2>&1 | head -25",
                "parse": "searchsploit",
            },
            {
                "id": "pe_hv_targets", "label": "High-Value Service Map", "tool": "nmap",
                "description": "Probe for databases, Active Directory, backup services, secret stores, cloud metadata.",
                "cmd_template": "nmap -sV -p 88,389,636,445,1433,1521,3306,5432,6379,9200,27017,5985,5986 --open -T4 {target} 2>&1; echo '---CLOUD METADATA---'; curl -sk 'http://169.254.169.254/latest/meta-data/' 2>&1 | head -10; curl -sk 'http://169.254.169.254/computeMetadata/v1/' -H 'Metadata-Flavor: Google' 2>&1 | head -10",
                "parse": "nmap",
            },
            {
                "id": "pe_cred_harvest", "label": "Credential & Secret Harvesting", "tool": "curl / nmap",
                "description": "Search for exposed credentials, keys, tokens in common paths and service responses.",
                "cmd_template": "echo '---SECRET PATHS---'; for p in .env .env.local wp-config.php config.php config/database.yml application.properties secrets.yaml backup.sql database.sql id_rsa .git/config .aws/credentials; do out=$(curl -skL --max-time 8 -w '%{http_code}' -o /tmp/pwm_cred_$$ 'http://{target}/'$p 2>/dev/null); body=$(tr '\\n' ' ' < /tmp/pwm_cred_$$ 2>/dev/null | head -c 200); rm -f /tmp/pwm_cred_$$; echo \"$p:$out|$body\"; done; echo '---GIT EXPOSURE---'; curl -skL --max-time 8 http://{target}/.git/COMMIT_EDITMSG -o - 2>&1 | head -5; curl -skL --max-time 8 http://{target}/.git/config -o - 2>&1 | head -10",
                "parse": "cred_harvest",
            },
            {
                "id": "pe_ad_enum", "label": "Active Directory Enumeration", "tool": "nmap / ldapsearch",
                "description": "Enumerate AD domain controllers, Kerberos, LDAP, SYSVOL, GPO, trust relationships.",
                "cmd_template": "echo '---AD PORTS---'; nmap -sV -p 88,389,445,464,636,3268,3269 --script=krb5-enum-users,ldap-rootdse,smb-security-mode {target} 2>&1 | head -60; echo '---LDAP ANON BIND---'; ldapsearch -x -H ldap://{target} -b '' -s base '(objectclass=*)' 2>&1 | head -20; echo '---KERBEROS---'; nmap --script=krb5-enum-users --script-args krb5-enum-users.realm={target} -p 88 {target} 2>&1 | head -20",
                "fallback_cmd": "nmap -sV -p 88,389,445,636 --script=ldap-rootdse {target} 2>&1 | head -40",
                "parse": "nse_deep",
            },
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# VERSION DATABASE & ANOMALY SIGNATURES (unchanged from v2)
# ─────────────────────────────────────────────────────────────────────────────
VERSION_DB = {
    "openssh":      {"latest":"9.7",  "eol":"7.4",   "cve_prefix":"CVE-2023-"},
    "apache":       {"latest":"2.4.59","eol":"2.4.49","cve_prefix":"CVE-2021-"},
    "nginx":        {"latest":"1.26", "eol":"1.18",  "cve_prefix":"CVE-2022-"},
    "vsftpd":       {"latest":"3.0.5","eol":"2.3.4", "cve_prefix":"CVE-2011-"},
    "proftpd":      {"latest":"1.3.8","eol":"1.3.5", "cve_prefix":"CVE-2019-"},
    "openssl":      {"latest":"3.3",  "eol":"1.0.2", "cve_prefix":"CVE-2022-"},
    "php":          {"latest":"8.3",  "eol":"7.4",   "cve_prefix":"CVE-2023-"},
    "mysql":        {"latest":"8.4",  "eol":"5.7",   "cve_prefix":"CVE-2023-"},
    "postgresql":   {"latest":"16",   "eol":"11",    "cve_prefix":"CVE-2023-"},
    "samba":        {"latest":"4.20", "eol":"4.9",   "cve_prefix":"CVE-2022-"},
    "iis":          {"latest":"10",   "eol":"7.5",   "cve_prefix":"CVE-2021-"},
    "tomcat":       {"latest":"10.1", "eol":"8.5",   "cve_prefix":"CVE-2023-"},
    "exim":         {"latest":"4.97", "eol":"4.89",  "cve_prefix":"CVE-2023-"},
    "bind":         {"latest":"9.18", "eol":"9.11",  "cve_prefix":"CVE-2023-"},
    "redis":        {"latest":"7.2",  "eol":"5.0",   "cve_prefix":"CVE-2023-"},
    "mongodb":      {"latest":"7.0",  "eol":"4.2",   "cve_prefix":"CVE-2022-"},
    "elasticsearch":{"latest":"8.13", "eol":"6.8",   "cve_prefix":"CVE-2023-"},
    "jenkins":      {"latest":"2.459","eol":"2.332", "cve_prefix":"CVE-2024-"},
}

ANOMALY_SIGNATURES = [
    (r"X-Powered-By:\s*PHP/[34567]\.", "Outdated PHP in X-Powered-By header", "high"),
    (r"Server:\s*Apache/2\.4\.4[0-9]", "Apache in EOL/critical CVE range (CVE-2021-41773)", "critical"),
    (r"Server:\s*nginx/1\.1[0-8]\.", "Outdated nginx — multiple known CVEs", "high"),
    (r"Server:\s*Microsoft-IIS/[567]\.", "EOL IIS version — no security patches", "critical"),
    (r"Access-Control-Allow-Origin:\s*\*", "CORS wildcard — data exfiltration vector", "medium"),
    (r"(?i)set-cookie:(?!.*httponly)", "Cookie missing HttpOnly flag", "medium"),
    (r"(?i)set-cookie:(?!.*secure)", "Cookie missing Secure flag", "medium"),
    (r"Windows\s+[56789]\.0", "Legacy Windows OS — EternalBlue likely", "critical"),
    (r"Samba\s+[234]\.", "Outdated Samba — SambaCry risk", "high"),
    (r"220.*FTP.*[Aa]nonymous", "Anonymous FTP login accepted", "high"),
    (r"root@", "Root prompt in service banner", "critical"),
    (r"(?i)debug mode|debug=true|DEBUG=1", "Debug mode in production service", "high"),
    (r"(?i)phpinfo\(\)", "phpinfo() exposed", "high"),
    (r"(?i)\.git/config\s*[^\n]*\[core\]|(?:^|\n)\s*\[remote\s+\"origin\"\]|repositoryformatversion", "Git repository exposed (config content)", "critical"),
    (r"(?i)\.env[^\n]*[A-Za-z0-9_]{3,}\s*=\s*\S+", ".env with credential content exposed", "critical"),
    (r"(?i)SSLv2|SSLv3|TLSv1\.0|TLSv1\.1", "Deprecated TLS/SSL protocol enabled", "high"),
    (r"(?i)(cipher|protocol|ssl [cv]|tlsv|ssl3|accepted|preferred)\s*[:=]?[^\n]*\b(RC4|DES|3DES|EXPORT|NULL|anon)\b", "Weak cipher suite enabled", "high"),
    (r"(?i)heartbleed|CVE-2014-0160|\bVULNERABLE\b", "Heartbleed or script-confirmed VULNERABLE service", "critical"),
    (r"SNMPv2-MIB::sysDescr", "SNMP public community string accepted", "high"),
]


# Redirect status codes must never constitute a finding by themselves: a
# 3xx answer means "resource moved", it says nothing about a vulnerability.
# Findings may only claim a weakness from the FINAL response after following
# the redirect chain (curl -L), and only where redirect semantics are the
# verified vulnerability itself (open redirect / host-header reflection) is a
# 3xx-with-reflected-Location an actual finding.
REDIRECT_CODES = frozenset({'300', '301', '302', '303', '304', '305', '307', '308'})


# Negated-result guard: a line/detail asserting NON-vulnerability ("NOT
# VULNERABLE", "isn't vulnerable", "does not appear to be vulnerable",
# "non-vulnerable", "is not exploitable", …) must never become a finding.
_NEGATED_RESULT = re.compile(
    r"\bnot\b[^.!?\n;]{0,40}\b(?:vulnerable|exploitable|injectable)\b"
    r"|\b(?:isn't|aren't|wasn't|don't|doesn't|didn't|can't)\b[^.!?\n;]{0,40}\b(?:vulnerable|injectable)\b"
    r"|\bnon[-\s]?vulnerable\b"
    r"|\bnever\s+vulnerable\b",
    re.I)


def sig_matches(output):
    """Line-based anomaly-signature scan yielding (msg, sev) once per signature.

    Negated script results ("NOT VULNERABLE", "isn't vulnerable",
    "does not appear to be vulnerable", …) never yield a finding."""
    seen = set()
    for line in output.splitlines():
        if not line.strip() or _NEGATED_RESULT.search(line):
            continue
        for sig, msg, sev in ANOMALY_SIGNATURES:
            if msg in seen:
                continue
            if re.search(sig, line, re.I):
                seen.add(msg)
                yield msg, sev

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 — deterministic calculator + per-finding-class vector profiles
# ─────────────────────────────────────────────────────────────────────────────
# Nothing here is guessed: the base score is computed from an explicit vector
# string via the published CVSS v3.1 formulas. When the resulting severity band
# differs from the finding's own severity label the mismatch is surfaced
# (`band_mismatch`) instead of being silently normalised — that is the trigger
# for analyst review rather than an assumption.

_CVSS_METRIC = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},          # Scope=Unchanged
    'PRc': {'N': 0.85, 'L': 0.68, 'H': 0.50},         # Scope=Changed
    'UI': {'N': 0.85, 'R': 0.62},
    'CIA': {'H': 0.56, 'L': 0.22, 'N': 0.00},
}

def _roundup1(x):
    return _math.ceil((x - 1e-9) * 10) / 10

def cvss31_base_score(vector: str):
    """Compute the CVSS v3.1 base score for a 'CVSS:3.1/...' vector string.

    Returns None if the vector is malformed. Pure arithmetic — deterministic."""
    if not vector or not vector.startswith('CVSS:3.1/'):
        return None
    m = {}
    for part in vector.split('/')[1:]:
        if ':' in part:
            k, _, v = part.partition(':')
            m[k] = v
    if not {'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'}.issubset(m):
        return None
    try:
        av, ac, ui = _CVSS_METRIC['AV'][m['AV']], _CVSS_METRIC['AC'][m['AC']], _CVSS_METRIC['UI'][m['UI']]
        pr = _CVSS_METRIC['PR' if m['S'] == 'U' else 'PRc'][m['PR']]
        c, i, a = (_CVSS_METRIC['CIA'][m[x]] for x in ('C', 'I', 'A'))
        ist = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 6.42 * ist if m['S'] == 'U' else (7.52 * (ist - 0.029) - 3.25 * ((ist - 0.02) ** 15))
        if impact <= 0:          # CVSS v3.1 spec: base score is 0 when impact is nil
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        if m['S'] == 'U':
            score = _roundup1(impact + exploitability)
        else:
            score = _roundup1(min(1.08 * (impact + exploitability), 10))
        return round(min(max(score, 0.0), 10.0), 1)
    except KeyError:
        return None

def cvss31_band(score):
    if score is None: return None
    if score == 0: return 'none'
    if score < 4.0: return 'low'
    if score < 7.0: return 'medium'
    if score < 9.0: return 'high'
    return 'critical'

# Curated base vectors per confirmed finding class. Static, reviewable strings;
# AV:N everywhere (every finding is remotely reachable from the scan host).
FINDING_CVSS = {
    "sql_injection":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "blind_sqli":          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "nosql_injection":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "default_cred_http":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "broken_auth":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "broken_function_auth":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "mass_assignment":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "bola_idor":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sensitive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf_lfi":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "unauth_endpoint":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "env_exposed":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "git_exposed":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "git_config":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "git_config_content":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "api_key_exposure":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "db_unauth_access":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "redis_no_auth":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "db_default_cred":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "null_session":        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "path_traversal":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "host_header_injection":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "trace_method":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "api_cors_wildcard":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "missing_rate_limit":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
    "verbose_error":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "weak_tls":            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "weak_cipher":         "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "heartbleed":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "expired_cert":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "self_signed_cert":    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "protocol_vuln":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "version_eol":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "version_outdated":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "exploit_available":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "open_port":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "db_exposed":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cms_wordpress":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cms_joomla":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cms_drupal":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "breach_exposure":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "imds_reachable":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "js_secret_leak":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# Fallback vectors when a finding class has no curated profile — also the
# honest default for anything unclassified (lowest plausible for the label).
_FINDING_CVSS_FALLBACK = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N",
    "low":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
}

def score_finding(f):
    """Attach a CVSS v3.1 vector + computed base score to a finding (in place).

    The vector is either the curated profile for the finding class or the
    severity-fallback vector; both are explicit, reviewable strings. If the
    computed severity band disagrees with the finding's own label, that
    disagreement is recorded (`band_mismatch`) rather than hidden.

    A finding that already carries a parser-supplied vector (e.g. NVD
    CPE-verified CVEs) keeps it — the parser's real vector is never replaced
    by a curated profile; only the band/mismatch fields are (re)derived."""
    sev = f.get('severity', 'info')
    existing = f.get('cvss')
    if isinstance(existing, dict) and existing.get('vector'):
        cv = dict(existing)
        if cv.get('base_score') is None:
            cv['base_score'] = cvss31_base_score(cv['vector'])
        band = cv.get('severity_band') or cvss31_band(cv.get('base_score'))
        cv['severity_band'] = band
        cv['band_mismatch'] = bool(band and sev in
                                   ('critical', 'high', 'medium', 'low') and band != sev)
        f['cvss'] = cv
        return f
    if sev not in ('critical', 'high', 'medium', 'low'):
        f['cvss'] = {"vector": None, "base_score": 0.0, "severity_band": None, "note": "informational — not scored"}
        return f
    vector = FINDING_CVSS.get(f.get('type')) or _FINDING_CVSS_FALLBACK.get(sev)
    score = cvss31_base_score(vector)
    band = cvss31_band(score)
    f['cvss'] = {
        "vector": vector, "base_score": score,
        "severity_band": band,
        "band_mismatch": bool(score is not None and band != sev),
        "source": "computed-cvss3.1" if score is not None else "error",
    }
    return f

# ─────────────────────────────────────────────────────────────────────────────
# FALSE-POSITIVE TRIAGE — deterministic verdict attached to every finding
# ─────────────────────────────────────────────────────────────────────────────
# A vulnerability finding is only 'confirmed' when it rests on concrete artifact
# or contrast evidence (probe body == the real thing, backend behaviour change);
# tool-reported lines are 'tool-confirmed'; everything else is 'needs_review'.
# Status-only recon results are informational. This is the automated triage —
# an analyst can override any verdict via POST /api/session/<sid>/triage.
_EVIDENCE_CONFIRMED_TYPES = {
    "env_exposed", "git_exposed", "git_config", "git_config_content",
    "api_key_exposure", "cms_wordpress", "cms_joomla", "cms_drupal",
    "mass_assignment", "broken_function_auth", "bola_idor", "ssrf", "ssrf_lfi",
    "ssti", "default_cred_http", "broken_auth", "unauth_endpoint",
    "path_traversal", "host_header_injection", "trace_method",
    "sensitive_data_exposure", "db_unauth_access", "redis_no_auth",
    "null_session", "snmp_public", "smb_share", "imds_reachable",
    "js_secret_leak", "breach_exposure", "s3_public_list", "open_redirect",
    "sql_injection", "nosql_injection", "blind_sqli", "drupal_login",
}
_TOOL_CONFIRMED_TYPES = {
    "version_eol", "version_outdated", "exploit_available", "weak_tls",
    "weak_cipher", "heartbleed", "expired_cert", "self_signed_cert",
    "protocol_vuln", "web_finding", "db_default_cred", "db_exposed",
    "open_port", "legacy_os", "cve", "signature_match",
}
_INFO_TYPES = {
    "web_path", "api_endpoint", "subdomain", "tech_fingerprint", "email_discovered",
    "js_endpoint", "sourcemap_exposed", "s3_bucket_probe", "cloud_provider",
    "evidence_capture", "no_breach",
}

def _triage_finding(f):
    sev = f.get('severity', 'info')
    ftype = f.get('type', '')
    if ftype in _INFO_TYPES or sev == 'info':
        verdict, basis = 'info', "informational / status-only recon result — not a vulnerability claim"
    elif ftype in _EVIDENCE_CONFIRMED_TYPES:
        verdict, basis = 'confirmed', "probe body or backend contrast matched the artifact directly"
    elif ftype in _TOOL_CONFIRMED_TYPES:
        verdict, basis = 'tool-confirmed', "reported by an upstream scanner (nmap/nikto/nuclei/sslscan/searchsploit)"
    else:
        verdict, basis = 'needs_review', "single-probe or no artifact content — confirm manually"
    f['triage'] = {"verdict": verdict, "basis": basis, "provenance": "auto", "note": None, "ts": None}
    return f

# Session triage log: one record per finding per substage, appended at the
# single choke point so SSE, /status, PDF and UI stay identical.
def _append_triage_log(sess, sub_id, findings):
    log = sess.get('triage_log', {})
    recs = []
    for i, f in enumerate(findings):
        t = f.get('triage', {})
        recs.append({
            "index": i, "type": f.get('type'), "severity": f.get('severity'),
            "verdict": t.get('verdict'), "basis": t.get('basis'),
            "provenance": t.get('provenance', 'auto'), "note": t.get('note'),
            "ts": t.get('ts') or datetime.now().isoformat(),
        })
    log[sub_id] = recs
    sess['triage_log'] = log

# ─────────────────────────────────────────────────────────────────────────────
# NVD VERIFICATION — service version → CVE cross-reference (no guessing)
# ─────────────────────────────────────────────────────────────────────────────
# CPEs are only built for products with a known vendor/product mapping. The
# NVD `cpeName` filter matches CVEs whose affected config references that exact
# product+version CPE — an NVD-maintained fact, not a keyword guess. Only CVEs
# carrying a real CVSSv3 vector are reported; lookups are cached and timeout.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_TIMEOUT = 8
NVD_CACHE = {}

# Curated (service token → (vendor, product-name)) CPE mappings. Products not
# listed here are reported as "no CPE mapping — manual review" (never assumed).
CPE_TABLE = {
    "openssh":      ("openbsd", "openssh"),
    "apache":       ("apache", "http_server"),
    "nginx":        ("nginx", "nginx"),
    "vsftpd":       ("vsftpd", "vsftpd"),
    "proftpd":      ("proftpd", "proftpd"),
    "mysql":        ("oracle", "mysql"),
    "mariadb":      ("mariadb", "mariadb"),
    "postgres":     ("postgresql", "postgresql"),
    "postgresql":   ("postgresql", "postgresql"),
    "mongodb":      ("mongodb", "mongodb"),
    "redis":        ("redis", "redis"),
    "elasticsearch":("elastic", "elasticsearch"),
    "php":          ("php", "php"),
    "openssl":      ("openssl", "openssl"),
    "tomcat":       ("apache", "tomcat"),
    "samba":        ("samba", "samba"),
    "exim":         ("exim", "exim"),
    "bind":         ("isc", "bind"),
    "jenkins":      ("jenkins", "jenkins"),
    "iis":          ("microsoft", "internet_information_services"),
    "grafana":      ("grafana", "grafana"),
    "wordpress":    ("wordpress", "wordpress"),
    "drupal":       ("drupal", "drupal"),
    "joomla":       ("joomla", "joomla"),
}

def _nvd_verify_cpe(product_cpe, version):
    """Return NVD-verified CVEs for (cpe vendor:product, version) or [].
    [] means genuinely no NVD CPE match (honest negative)."""
    key = (product_cpe, version)
    if key in NVD_CACHE:
        return NVD_CACHE[key]
    results = []
    candidates = list(dict.fromkeys([version] + ([_strip_ver_suffix(version)] if _strip_ver_suffix(version) else [])))
    for cand in candidates:
        if not cand:
            continue
        cpe = f"cpe:2.3:a:{product_cpe}:{cand}:*:*:*:*:*:*:*"
        try:
            req = urllib.request.Request(
                f"{NVD_API}?cpeName={urllib.parse.quote(cpe)}",
                headers={'User-Agent': 'pwm-cve-verify'})
            with urllib.request.urlopen(req, timeout=_NVD_TIMEOUT) as r:
                data = json.load(r)
        except Exception:
            continue
        vulns = data.get('vulnerabilities', [])
        for v in vulns:
            c = v.get('cve', {})
            cid = c.get('id', '')
            met = (c.get('metrics') or {}).get('cvssMetricV31') or (c.get('metrics') or {}).get('cvssMetricV30') or []
            if not met:
                continue
            cv = (met[0].get('cvssData') or {})
            if not cv.get('vectorString') or cv.get('baseScore') is None:
                continue
            results.append({
                "cve": cid, "score": cv['baseScore'], "vector": cv['vectorString'],
                "published": (c.get('published') or '')[:10],
                "reference": ((c.get('references') or [{}])[0].get('url')) or '',
            })
        if results:
            break
    dedup = list({(x['cve'], x['score'], x['vector']): x for x in results}.values())
    dedup.sort(key=lambda x: x['score'], reverse=True)
    NVD_CACHE[key] = dedup[:8]
    return NVD_CACHE[key]

def _strip_ver_suffix(version):
    m = re.match(r'(\d+(?:\.\d+){1,2})', version or '')
    return m.group(1) if m and m.group(1) != version else None

# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE CAPTURE — screenshot + PCAP per confirmed finding (pre-exploitation)
# ─────────────────────────────────────────────────────────────────────────────
_CHROME_BINS = ['google-chrome', 'chromium', 'chromium-browser']

def _finding_url(f, sess):
    """Best-effort URL for evidence capture. Returns None when we only have a
    host, so no fabricated evidence is produced."""
    target = sess.get('target', '')
    p = str(f.get('path') or '')
    cmd = str(f.get('command') or '')
    if p.startswith('/'):
        return f"http://{target}{p}"
    m = re.search(r'https?://\S+', cmd)
    if m:
        return m.group(0).rstrip('.').replace('"', '')
    return None

def _capture_evidence(f, sess):
    """Screenshot + PCAP for one finding; writes into <outdir>/evidence.
    Returns info dict; never fabricates — if the capture tool errors, the
    record states the error instead of claiming a file exists."""
    evdir = os.path.join(sess['outdir'], 'evidence')
    os.makedirs(evdir, exist_ok=True, mode=0o700)
    idx = len(os.listdir(evdir))
    stamp = datetime.now().strftime('%H%M%S')
    url = _finding_url(f, sess)
    rec = {"finding_type": f.get('type'), "path": f.get('path'), "url": url,
           "screenshots": [], "pcap": None, "errors": []}
    if not url:
        rec["errors"].append("no http(s) endpoint in finding — screenshot skipped")
        return rec

    # Screenshot via headless chrome.
    shot = None
    chrome_found = False
    for binname in _CHROME_BINS:
        path = shutil.which(binname)
        if not path:
            continue
        chrome_found = True
        shot = os.path.join(evdir, f"{idx:02d}_{stamp}_{f.get('type','x')}.png")
        ok = True
        try:
            subprocess.run(
                [path, '--headless=new', '--no-sandbox', '--disable-gpu',
                 '--hide-scrollbars', '--window-size=1280,800',
                 '--virtual-time-budget=4000', f'--screenshot={shot}', url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=25)
            if os.path.exists(shot) and os.path.getsize(shot) > 800:
                with open(shot, 'rb') as fh:
                    magic = fh.read(8)
                if magic.startswith(b'\x89PNG'):
                    rec["screenshots"].append(shot)
            else:
                ok = False
        except Exception:
            ok = False
        if rec["screenshots"]:
            break
        if not ok:
            rec["errors"].append(f"{binname} screenshot produced no valid PNG")
    if not chrome_found:
        rec["errors"].append("no headless chrome binary found — screenshot skipped")
    if shot and shot not in rec["screenshots"] and os.path.exists(shot):
        # only remove a capture that failed validation; a valid screenshot is
        # the evidence artifact and must survive (it used to be deleted here).
        try: os.remove(shot)
        except OSError: pass

    # PCAP: tcpdump during a short re-probe of the same URL.
    if shutil.which('tcpdump'):
        pcap = os.path.join(evdir, f"{idx:02d}_{stamp}_{f.get('type','x')}.pcap")
        try:
            host = sess['target']
            if ':' in host: host = host.split(':')[0]
            proc = subprocess.Popen(
                f"tcpdump -i any -s 0 -c 100 -w '{pcap}' host '{host}' 2>/dev/null",
                shell=True)
            try:
                subprocess.run(['curl', '-skL', '--max-time', '5', '-o', '/dev/null', url],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            if os.path.exists(pcap) and os.path.getsize(pcap) > 24:
                with open(pcap, 'rb') as fh:
                    magic = fh.read(4)
                if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
                    rec["pcap"] = pcap
                else:
                    rec["errors"].append("pcap magic mismatch — file discarded")
            else:
                rec["errors"].append("tcpdump produced no capture")
        except Exception as e:
            rec["errors"].append(f"pcap capture failed: {e}")
    else:
        rec["errors"].append("tcpdump not installed — pcap skipped")
    return rec

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def detect_target_type(t):
    """Classify the operator input. IPv6 literals and CIDR ranges are
    recognised explicitly (they used to fall through to 'domain')."""
    t = (t or '').strip()
    if re.match(r'^https?://', t, re.I):
        return 'url'
    host = clean_target(t)
    if '/' in host:
        try:
            ipaddress.ip_network(host, strict=False)
            return 'network'
        except ValueError:
            return 'domain'
    try:
        ipaddress.ip_address(host)
        return 'ip'
    except ValueError:
        return 'domain'


def clean_target(raw):
    """Reduce operator input to a host (or host/CIDR) for command templates.

    CIDR prefixes and IPv6 literals are preserved; only URL scheme, path and
    host:port are stripped.  Dropping the prefix here was silently turning a
    /24 request into a single-host scan."""
    t = re.sub(r'^https?://', '', (raw or '').strip(), flags=re.I).rstrip('/')
    if not t:
        return ''
    if t.startswith('['):                          # [::1] or [::1]:8080[/cidr]
        inner = t[1:].split(']', 1)[0]
        rest = t.split(']', 1)[1] if ']' in t else ''
        m = re.match(r'^/(\d{1,3})$', rest)
        return f"{inner}/{m.group(1)}" if m else inner
    if ':' in t:
        host = t.split('/')[0]
        if host.count(':') >= 2:                   # bare IPv6 literal (with optional /CIDR)
            try:
                if '/' in t:
                    return str(ipaddress.ip_interface(t))
                return str(ipaddress.ip_address(host))
            except ValueError:
                return host
        if re.fullmatch(r'[^:]+:\d{1,5}', host):   # hostname:port / ip:port
            return host.rsplit(':', 1)[0]
        return host
    # IPv4 with optional CIDR: keep the prefix (nmap scans the range)
    m = re.fullmatch(r'(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?', t)
    if m:
        return f"{m.group(1)}/{m.group(2)}" if m.group(2) is not None else m.group(1)
    return t.split('/')[0]


def _origin_from_raw(raw):
    """Preserve an operator-supplied scheme://host:port for the auth-tier
    in-process probes (the host-based shell templates intentionally use the
    port-less {target})."""
    m = re.match(r'^(https?)://([^/\s]+)', (raw or '').strip(), re.I)
    return f"{m.group(1).lower()}://{m.group(2)}" if m else None


def is_valid_target(t):
    """Allow only hostnames, IPv4 (optionally with CIDR) and IPv6 literals.
    Rejects anything containing shell metacharacters (command injection guard).
    IP/CIDR values are validated by the stdlib parser, not by a loose regex."""
    if not t or len(t) > 253:
        return False
    if re.fullmatch(r'[0-9A-Fa-f:.]+/\d{1,3}', t):
        try:
            ipaddress.ip_network(t, strict=False)
            return True
        except ValueError:
            return False
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', t) or (':' in t and re.fullmatch(r'[0-9A-Fa-f:.]+', t)):
        try:
            ipaddress.ip_address(t)
            return True
        except ValueError:
            return False
    # hostname / FQDN
    return bool(re.match(r'^[A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?$', t)) and '..' not in t


def infer_network(target):
    """Derive a scan scope without inventing ranges.
    A single IP or hostname scans only that host; an explicit CIDR is
    normalised to its network address and kept as a range."""
    if '/' in target:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return target
    return target

def make_cmd(template, sess):
    ports = sess.get('ports_found') or '21,22,23,25,53,80,110,443,445,3306,3389,8080'
    # Every substituted value is shell-quoted: {banner_search} carries raw
    # target-controlled banner text and would otherwise be parsed as shell
    # syntax (command injection). For validated hostnames/IPs/ports/outdirs
    # shlex.quote() is a no-op — the command string is unchanged.
    vals = {
        'target': shlex.quote(sess['target']),
        'outdir': shlex.quote(sess['outdir']),
        'base_url': shlex.quote(_base_url(sess)),
        'ports': shlex.quote(ports),
        'banner_search': shlex.quote(sess.get('banner_search', sess['target'])),
        'network': shlex.quote(sess.get('network', infer_network(sess['target']))),
        'nuclei_dir': shlex.quote(NUCLEI_TPL),
    }
    def repl(m):
        if m.group(0) == '{{':
            return '{'
        if m.group(0) == '}}':
            return '}'
        key = m.group(1)
        return str(vals.get(key, m.group(0)))
    return re.sub(r'\{\{|\}\}|\{(\w+)\}', repl, template)

_QUEUE_LOCK = threading.Lock()

def push(sid, event, data):
    """Enqueue an SSE event without ever blocking a producer.

    The previous check-then-block (full() → get_nowait() → put()) was racy:
    two parallel substage threads could both pass the check and then block
    forever.  All queue mutation now happens under one lock using only
    non-blocking calls."""
    q = output_queues.get(sid)
    if not q:
        return
    item = {"event": event, "data": json.dumps(data)}
    with _QUEUE_LOCK:
        if q.full():
            try:
                q.get_nowait()          # drop the oldest event (drop-oldest policy)
            except queue.Empty:
                pass
        try:
            q.put_nowait(item)
        except queue.Full:
            # A concurrent consumer/producer changed capacity; never spin or block.
            pass

def find_sub(sub_id):
    for stage in CHAIN:
        for sub in stage['substages']:
            if sub['id'] == sub_id:
                return sub
    return None

def find_stage_for_sub(sub_id):
    for stage in CHAIN:
        for sub in stage['substages']:
            if sub['id'] == sub_id:
                return stage
    return None

# ─────────────────────────────────────────────────────────────────────────────
# COMMAND RUNNER
# ─────────────────────────────────────────────────────────────────────────────
_SUDO_OK = None
def _sudo_available():
    """Probe whether passwordless sudo works. Result is cached — never prompts."""
    global _SUDO_OK
    if _SUDO_OK is None:
        try:
            _SUDO_OK = subprocess.run(['sudo', '-n', 'true'],
                                      capture_output=True, timeout=5).returncode == 0
        except Exception:
            _SUDO_OK = False
    return _SUDO_OK

def run_command(sid, sub_id, cmd, timeout=PWM_CMD_TIMEOUT):
    push(sid, "output", {"substage": sub_id, "line": f"$ {cmd}", "type": "cmd"})
    if timeout is not None and timeout <= 0:
        timeout = None
    lines = []
    ansi = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
    MAX_LINES = 100000
    stop_reader = threading.Event()

    def _emit(raw):
        line = ansi.sub('', raw.decode('utf-8', 'replace').rstrip('\r\n'))
        lines.append(line)
        if len(lines) > MAX_LINES:
            del lines[:len(lines) - MAX_LINES]
        push(sid, "output", {"substage": sub_id, "line": line, "type": "stdout"})

    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=False, bufsize=0,
                                env={**os.environ, 'TERM': 'dumb'},
                                start_new_session=True)
    except Exception as e:
        msg = f"[ERROR: {e}]"
        push(sid, "output", {"substage": sub_id, "line": msg, "type": "error"})
        push(sid, "output", {"substage": sub_id, "line": f"[exit -1]", "type": "meta"})
        return msg, -1

    fd = proc.stdout.fileno()

    def reader():
        buf = b''
        try:
            while True:
                rlist, _, _ = select.select([fd], [], [], 1.0)
                if rlist:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    buf += chunk
                    *complete, buf = buf.split(b'\n')
                    for raw in complete:
                        _emit(raw)
                    if len(buf) > 1_000_000:
                        _emit(buf)
                        buf = b''
                    continue
                if stop_reader.is_set():
                    while True:
                        rlist2, _, _ = select.select([fd], [], [], 0)
                        if not rlist2:
                            break
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        buf += chunk
                        *complete, buf = buf.split(b'\n')
                        for raw in complete:
                            _emit(raw)
                    break
        except (OSError, ValueError):
            pass
        finally:
            if buf:
                _emit(buf)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    rc = 0
    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = -1
        msg = f"[TIMEOUT {timeout:g}s]" if timeout else "[TIMEOUT]"
        lines.append(msg)
        push(sid, "output", {"substage": sub_id, "line": msg, "type": "error"})
    finally:
        if timed_out or proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.kill()
                except Exception:
                    pass
        stop_reader.set()
        t.join(timeout=3)
        if t.is_alive():
            try:
                proc.stdout.close()
            except Exception:
                pass
        try:
            proc.stdout.close()
        except Exception:
            pass
    push(sid, "output", {"substage": sub_id, "line": f"[exit {rc}]", "type": "meta"})
    return "\n".join(lines), rc


# ─────────────────────────────────────────────────────────────────────────────
# PARSERS — existing
# ─────────────────────────────────────────────────────────────────────────────
def parse_nmap(output):
    findings = []
    best = {}
    for line in output.splitlines():
        m = re.match(r'(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)', line)
        if m:
            svc, ver = m.group(4), m.group(5).strip()
            key = (m.group(1), m.group(2))
            f = {"type":"open_port","port":m.group(1),"proto":m.group(2),
                 "service":svc,"version":ver,"severity":"info",
                 "detail":f"{m.group(1)}/{m.group(2)} {svc} {ver}",
                 "path":f":{m.group(1)}"}
            prev = best.get(key)
            if prev is None:
                best[key] = f
                findings.append(f)
            elif ver or not prev['version']:
                # a later table (e.g. -sV run after the full-port sweep) wins
                prev.update(f)
    if 'OS details:' in output or 'OS CPE:' in output:
        for line in output.splitlines():
            if 'OS details:' in line or 'Running:' in line:
                findings.append({"type":"os_detect","detail":line.strip(),"severity":"info","path":"network"})
    return findings

def parse_vulners(output):
    findings = []
    seen = set()
    for line in output.splitlines():
        cve = re.search(r'(CVE-\d{4}-\d{4,})', line)
        port_m = re.search(r'(\d+)/tcp', line)
        if cve and cve.group(1) not in seen:
            seen.add(cve.group(1))
            score_m = re.search(r'(\d+\.\d+)', line)
            score = float(score_m.group(1)) if score_m else 0.0
            sev = "critical" if score>=9 else "high" if score>=7 else "medium" if score>=4 else "low"
            path = f":{port_m.group(1)}" if port_m else "service"
            findings.append({"type":"cve","cve":cve.group(1),"score":score,"severity":sev,
                              "detail":line.strip(),"path":path,
                              "command":f"nmap -sV --script=vulners --script-args mincvss=4.0"})
    return findings

def parse_searchsploit(output):
    """searchsploit result rows: '<Title> | <edb/path>'. Usage/help/error text
    (which contains '|' characters) must never become findings — that was
    fabricating 'exploit_available' highs from the tool's own usage banner.
    The path column must look like a real EDB path (dir/dir/id.ext)."""
    if 'Usage: searchsploit' in output or 'illegal option' in output \
            or 'invalid option' in output:
        return []
    output = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', output)   # strip colour codes
    findings = []
    for line in output.splitlines():
        if '|' not in line or 'Exploit Title' in line or '---' in line or len(line.strip()) <= 5:
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) < 2 or not parts[0]:
            continue
        path = parts[-1]
        if '/' not in path or not re.match(r'^[\w./-]+\.[A-Za-z0-9]{1,5}$', path):
            continue
        findings.append({"type":"exploit_available","title":parts[0],
                          "path":"searchsploit match","severity":"high",
                          "detail":parts[0],
                          "command":f"searchsploit -m {path}"})
    return findings

def parse_nikto(output):
    findings = []
    for line in output.splitlines():
        if line.startswith('+ ') and 'Target' not in line and 'Start Time' not in line:
            body = line[2:].strip()
            sev = ("critical" if any(x in body.lower() for x in ['rce','remote code','execut','inject','cve-20'])
                   else "high" if any(x in body.lower() for x in ['vulner','dangerous','default','exposed','outdated'])
                   else "medium" if any(x in body.lower() for x in ['allow','enable','disclos'])
                   else "low")
            uri_m = re.search(r'((?:/[^\s:]+)+)', body)
            path = uri_m.group(1) if uri_m else "web"
            findings.append({"type":"web_finding","detail":body,"severity":sev,
                              "path":path,"command":"nikto -h <target>"})
    return findings

_SSL_NEG = re.compile(r'(?:\bnot\b|\bno\b|\bdisabled\b|<\s*not\b)', re.I)

def parse_ssl(output):
    """sslscan / openssl / testssl output.

    Real sslscan 2.1.x prints ``SSLv2     disabled`` / ``SSLv3     disabled``
    for protocols that are OFF, and ``TLSv1.x not vulnerable to heartbleed``
    for checks that passed — neither is a finding. A line is only considered
    when it makes an affirmative statement about a weak protocol/cipher/cert.
    """
    findings = []
    for line in output.splitlines():
        if _NEGATED_RESULT.search(line) or _SSL_NEG.search(line):
            continue
        ll = line.lower()
        if any(x in ll for x in ['sslv2','sslv3','tlsv1.0','tlsv1.1']):
            findings.append({"type":"weak_tls","detail":line.strip(),"severity":"high",
                              "path":":443","command":"sslscan <target>:443"})
        if any(x in ll for x in ['rc4','des ','3des','export','null cipher','anonymous']):
            findings.append({"type":"weak_cipher","detail":line.strip(),"severity":"high",
                              "path":":443","command":"sslscan <target>:443"})
        if 'heartbleed' in ll and 'vulnerable' in ll:
            findings.append({"type":"heartbleed","detail":line.strip(),"severity":"critical",
                              "path":":443","command":"nmap --script=ssl-heartbleed -p 443 <target>"})
        if 'self signed' in ll or 'self-signed' in ll:
            findings.append({"type":"self_signed_cert","detail":line.strip(),"severity":"medium",
                              "path":":443","command":"openssl s_client -connect <target>:443"})
        if 'expired' in ll:
            findings.append({"type":"expired_cert","detail":line.strip(),"severity":"high",
                              "path":":443","command":"openssl s_client -connect <target>:443"})
    return findings

def parse_headers(output):
    findings = []
    for msg, sev in sig_matches(output):
        findings.append({"type":"header_anomaly","detail":msg,"severity":sev,
                          "path":"HTTP headers","command":"curl -sIL http://<target>"})
    # curl -sIL prints the header block of every hop; the LAST HTTP/ line is
    # the terminal response. Missing security headers are only a real finding
    # against a terminal 2xx/4xx/5xx — a redirect-only host (every hop a 3xx)
    # says nothing about the resource's final headers, so don't claim a
    # "missing CSP/HSTS" weakness off a bare 301.
    statuses = re.findall(r'HTTP/\S+\s+(\d{3})', output)
    if not statuses or not any(s not in REDIRECT_CODES for s in statuses):
        return findings
    missing = []
    if 'Content-Security-Policy' not in output: missing.append('CSP')
    if 'X-Frame-Options' not in output and 'frame-ancestors' not in output: missing.append('X-Frame-Options')
    if 'X-Content-Type-Options' not in output: missing.append('X-Content-Type-Options')
    if 'Strict-Transport-Security' not in output: missing.append('HSTS')
    if missing:
        findings.append({"type":"missing_headers","detail":f"Missing: {', '.join(missing)}",
                          "severity":"medium","path":"HTTP response headers",
                          "command":"curl -sI http://<target>"})
    return findings

def parse_smb(output):
    findings = []
    if re.search(r'Windows\s+[56789]\.0', output):
        findings.append({"type":"legacy_os","detail":"Legacy Windows OS — EternalBlue range",
                          "severity":"critical","path":"SMB :445",
                          "command":"nmap --script=smb-vuln-ms17-010 -p 445 <target>"})
    for line in output.splitlines():
        if re.search(r'Disk\s*\|', line, re.I) or re.search(r'IPC\$|ADMIN\$|C\$', line):
            findings.append({"type":"smb_share","detail":line.strip(),"severity":"medium",
                              "path":"SMB :445","command":"smbclient -L //<target> -N"})
    if ('NT_STATUS_ACCESS_DENIED' not in output and
            'session setup failed' not in output.lower() and 'Sharename' in output):
        findings.append({"type":"null_session","detail":"Null session authenticated",
                          "severity":"high","path":"SMB :445",
                          "command":"rpcclient -U '' -N <target> -c 'enumdomusers'"})
    return findings

def parse_snmp(output):
    findings = []
    if 'SNMPv2-MIB::sysDescr' in output:
        findings.append({"type":"snmp_public","detail":"SNMP 'public' community string accepted",
                          "severity":"high","path":"SNMP :161",
                          "command":"snmpwalk -v2c -c public <target>"})
    return findings

def parse_dirb(output, sess=None):
    findings = []
    ansi_re = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
    # absolute origin the tools actually scanned ({base_url} in make_cmd), so
    # reported URLs/commands are reproducible — never a bare port-80 guess
    origin = _base_url(sess) if isinstance(sess, dict) else None
    emitted = set()

    def emit(code, url, path):
        key = (path, code)
        if key in emitted:
            return
        emitted.add(key)
        # Status-only content discovery is recon, never a vuln claim: a
        # catch-all router returns 200 for anything. Body verification is
        # the job of the dedicated .env/.git/etc probes.
        findings.append({"type": "web_path", "detail": f"HTTP {code} {url}",
                         "severity": "info", "path": path,
                         "command": f"curl -skL {url}"})

    for line in output.splitlines():
        m = re.search(r'(https?://\S+)\s+\(CODE:(\d+)', line)
        if m:
            code, url = m.group(2), m.group(1)
            if code in REDIRECT_CODES or code not in ('200', '201', '204', '401', '403'):
                continue
            path = re.sub(r'https?://[^/]+', '', url)
            emit(code, url, path)
            continue
        # gobuster: index.html (Status: 200) [Size: 1234]
        g = re.search(r'(/?\S+)\s+\(Status:\s*(\d+)\)', line)
        if g:
            code, path = g.group(2), g.group(1).rstrip('/')
            if not path.startswith('/'):
                path = '/' + path
            if code in REDIRECT_CODES or code not in ('200', '201', '204', '401', '403'):
                continue
            base = origin or 'http://<target>'
            emit(code, f"{base}{path}", path)
            continue
        # ffuf (2.x writes path-only lines, ANSI-prefixed, with progress glued on \r):
        #   '\x1b[2K.bash_history   [Status: 200, Size: 41, Words: 3, ...]'
        # older builds print the full URL instead. Split per \r segment so a
        # progress line can never be mistaken for a result.
        for seg in re.split(r'\r', ansi_re.sub('', line)):
            f = re.match(r'\s*(https?://\S+?|\S+)\s+\[Status:\s*(\d+)[,\]]', seg)
            if not f:
                continue
            url, code = f.group(1), f.group(2)
            if code in REDIRECT_CODES or code not in ('200', '201', '204', '401', '403'):
                continue
            if url.startswith('http'):
                path = re.sub(r'https?://[^/]+', '', url)
                emit(code, url, path)
            else:
                path = url if url.startswith('/') else '/' + url
                base = origin or 'http://<target>'
                emit(code, f"{base}{path}", path)
    return findings

def parse_banner_anomaly(output):
    findings = []
    for msg, sev in sig_matches(output):
        findings.append({"type":"banner_anomaly","detail":msg,"severity":sev,
                          "path":"service banner","command":"nmap --script=banner -p <ports> <target>"})
    for line in output.splitlines():
        port_m = re.match(r'(\d+)/tcp\s+open\s+\S+\s+(.*)', line)
        if port_m:
            port, info = port_m.group(1), port_m.group(2)
            if len(info) > 80:
                findings.append({"type":"verbose_banner","detail":f"Port {port} verbose banner: {info[:100]}",
                                  "severity":"low","path":f":{port}",
                                  "command":f"nmap --script=banner -p {port} <target>"})
    return findings

def parse_version_gap(output, sess):
    findings = []
    for line in output.splitlines():
        for svc_key, vdb in VERSION_DB.items():
            if svc_key in line.lower():
                ver_m = re.search(r'(\d+\.\d+[\.\d]*)', line)
                if ver_m:
                    found_ver = ver_m.group(1)
                    try:
                        fv = [int(x) for x in found_ver.split('.')[:2]]
                        ev = [int(x) for x in vdb['eol'].split('.')[:2]]
                        lv = [int(x) for x in vdb['latest'].split('.')[:2]]
                        gap = (lv[0]*100+lv[1]) - (fv[0]*100+fv[1])
                        port_m = re.search(r'(\d+)/tcp', line)
                        path = f":{port_m.group(1)}" if port_m else "service"
                        if fv <= ev:
                            findings.append({"type":"version_eol","severity":"critical","path":path,
                                "detail":f"{svc_key} {found_ver} is EOL (latest {vdb['latest']}) — {vdb['cve_prefix']}* exposure",
                                "command":f"nmap -sV -p {path.lstrip(':')} <target>"})
                        elif gap >= 4:
                            findings.append({"type":"version_outdated","severity":"high","path":path,
                                "detail":f"{svc_key} {found_ver} is {gap} versions behind (latest {vdb['latest']})",
                                "command":f"nmap -sV -p {path.lstrip(':')} <target>"})
                    except (ValueError, IndexError):
                        pass
    return findings

def parse_http_anomaly(output):
    findings = []
    if re.search(r'root:.*:/bin/', output):
        findings.append({"type":"path_traversal","severity":"critical","path":"/../../../../etc/passwd",
            "detail":"Path traversal returned /etc/passwd content — LFI confirmed",
            "command":"curl -sk 'http://<target>/../../../../etc/passwd'"})
    if re.search(r'HTTP/\S+ 200', output) and 'TRACE' in output:
        findings.append({"type":"trace_method","detail":"HTTP TRACE enabled — XST risk","severity":"medium",
            "path":"/","command":"curl -skI -X TRACE 'http://<target>/'"})
    if 'evil.com' in output and re.search(r'(Location|Host).*evil\.com', output):
        findings.append({"type":"host_header_injection","severity":"high","path":"Host header",
            "detail":"Host header value reflected in redirect — SSRF/cache poisoning",
            "command":"curl -skI -H 'Host: evil.com' 'http://<target>/'"})
    # .git / .env / admin — status alone proves nothing (catch-all routers 200
    # anything); findings require the probe body to actually BE the artifact.
    m = re.search(r'body:\.git\[(\d+)\] (.*)', output)
    if m and m.group(1) not in REDIRECT_CODES and m.group(1) in ('200', '201', '204') and \
       re.search(r'\[(core|remote|branch|user)\]|repositoryformatversion|refs/heads|packed-refs', m.group(2), re.I):
        findings.append({"type":"git_exposed","severity":"critical","path":"/.git/config",
            "detail":".git/config exposed — source/configuration disclosure",
            "command":"curl -skL 'http://<target>/.git/config'"})
    m = re.search(r'body:\.env\[(\d+)\] (.*)', output)
    if m and m.group(1) not in REDIRECT_CODES and m.group(1) in ('200', '201', '204') and \
       re.search(r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}', m.group(2)):
        findings.append({"type":"env_exposed","severity":"critical","path":"/.env",
            "detail":".env file exposed — credentials, API keys at risk",
            "command":"curl -skL 'http://<target>/.env'"})
    m = re.search(r'body:admin\[(\d+)\] (.*)', output)
    if m and m.group(1) not in REDIRECT_CODES and m.group(1) in ('200', '201', '204'):
        findings.append({"type":"admin_panel","severity":"info","path":"/admin",
            "detail":"Admin interface reachable (HTTP 200) — access control must be verified separately",
            "command":"curl -skL 'http://<target>/admin'"})
    return findings

def parse_timing(output):
    findings = []
    times = re.findall(r't=([\d.]+)', output)
    if len(times) >= 3:
        vals = [float(t) for t in times]
        avg, mx = sum(vals)/len(vals), max(vals)
        if mx > avg * 2.5:
            findings.append({"type":"timing_anomaly","severity":"medium","path":"/?id=",
                "detail":f"Response time variance avg={avg:.2f}s max={mx:.2f}s — possible blind injection",
                "command":"curl -sk -o /dev/null -w '%{time_total}' 'http://<target>/?id=1+AND+SLEEP(3)'"})
    valid = re.search(r'valid_user=([\d.]+)', output)
    invalid = re.search(r'invalid_user=([\d.]+)', output)
    if valid and invalid:
        vt, it = float(valid.group(1)), float(invalid.group(1))
        if abs(vt-it) > 0.3:
            findings.append({"type":"auth_timing_oracle","severity":"high","path":"/login",
                "detail":f"Login timing differs valid={vt:.3f}s vs invalid={it:.3f}s — username enumeration",
                "command":"curl -sk -X POST 'http://<target>/login' -d 'user=admin&pass=wrong'"})
    sqli = re.search(r'sqli_probe=([\d.]+)', output)
    baseline = re.search(r'sqli_baseline=([\d.]+)', output)
    if sqli and baseline:
        sp, bp = float(sqli.group(1)), float(baseline.group(1))
        if sp > bp + 2.5:
            findings.append({"type":"blind_sqli","severity":"critical","path":"/?id=",
                "detail":f"SLEEP-based SQLi: probe={sp:.2f}s vs baseline={bp:.2f}s — blind SQL injection confirmed",
                "command":"sqlmap -u 'http://<target>/?id=1' --level=5 --risk=3 --dbs"})
    return findings

def parse_auth_probe(output):
    findings = []
    # Unauthenticated baseline: a homepage that returns 200 to everyone (e.g.
    # catch-all) means a "200 with admin:admin" is NOT proof the credential was
    # accepted — only report default HTTP creds when auth is actually enforced.
    anon = re.search(r'anon=(\d{3})', output)
    anon_code = anon.group(1) if anon else None
    enforced = bool(anon_code) and anon_code not in REDIRECT_CODES and anon_code not in ('000', '200', '201', '204')
    if enforced:
        for cred in ['admin:admin=200', 'admin:password=200', 'root:root=200']:
            if cred in output:
                pair = cred.replace('=200', '')
                findings.append({"type": "default_cred_http", "severity": "critical",
                    "path": "/ (HTTP Basic Auth)",
                    "detail": f"HTTP Basic Auth accepted default credential: {pair}",
                    "command": f"curl -sku {pair} http://<target>/"})
    if re.search(r'ftp.*230|230.*logged', output, re.I):
        findings.append({"type":"ftp_anon","severity":"high","path":"FTP :21",
            "detail":"FTP anonymous login accepted",
            "command":"ftp <target>  # user: anonymous"})
    ssh_ver = re.search(r'SSH-[\d.]+-(\S+)', output)
    if ssh_ver:
        if re.search(r'SSH-1\.|SSH-2\.0-OpenSSH_[1-6]\.', output):
            findings.append({"type":"ssh_outdated","severity":"high","path":"SSH :22",
                "detail":f"Outdated SSH: {ssh_ver.group(0)}",
                "command":"nc -w 4 <target> 22"})
    missing_flags = []
    if 'httponly' not in output.lower(): missing_flags.append('HttpOnly')
    if 'secure' not in output.lower(): missing_flags.append('Secure')
    if 'samesite' not in output.lower(): missing_flags.append('SameSite')
    if missing_flags and 'set-cookie' in output.lower():
        findings.append({"type":"cookie_flags","severity":"medium","path":"/login (Set-Cookie header)",
            "detail":f"Session cookie missing: {', '.join(missing_flags)}",
            "command":"curl -skI 'http://<target>/login'"})
    return findings

def parse_nse_deep(output):
    findings = []
    checks = [
        (r'recursion:\s*Recursion appears to be enabled', "DNS recursion enabled — amplification DDoS risk", "high", "DNS :53", "nmap --script=dns-recursion -p 53 <target>"),
        (r'ntp-monlist', "NTP monlist enabled — DDoS amplification", "high", "NTP :123", "nmap --script=ntp-monlist -p 123 <target>"),
        (r'smtp.*open relay|relay.*accepted', "SMTP open relay confirmed", "critical", "SMTP :25", "nmap --script=smtp-open-relay -p 25 <target>"),
        (r'ldap.*rootDSE|namingContexts', "LDAP anonymous bind", "medium", "LDAP :389", "nmap --script=ldap-rootdse -p 389 <target>"),
        (r'ftp-anon.*Login with password', "FTP anonymous read/write", "high", "FTP :21", "nmap --script=ftp-anon -p 21 <target>"),
        # redis_version must be a REAL version string — "Redis server not
        # running" must never become "Redis accessible without auth".
        (r'redis_version\s*[:=]\s*\d', "Redis accessible without auth", "critical", "Redis :6379", "redis-cli -h <target> ping"),
        # Positive MongoDB data evidence only — "db with 0 databases" (closed
        # port) is NOT an access finding.
        (r'totalSize|\bb*db\b.*with [1-9]|databases:\s*[1-9]|total\s+size\s*[1-9]', "MongoDB accessible without auth", "critical", "MongoDB :27017", "nmap --script=mongodb-info -p 27017 <target>"),
    ]
    for pattern, msg, sev, path, cmd in checks:
        if re.search(pattern, output, re.I):
            findings.append({"type":"protocol_vuln","detail":msg,"severity":sev,
                "path":path,"command":cmd})
    return findings

def parse_hydra(output):
    findings = []
    for line in output.splitlines():
        if 'login:' in line and 'password:' in line:
            findings.append({"type":"default_cred","detail":line.strip(),"severity":"critical",
                "path":"SSH :22","command":"hydra -l <user> -p <pass> ssh://<target>"})
    return findings

def parse_msf(output):
    findings = []
    for line in output.splitlines():
        if _NEGATED_RESULT.search(line):
            continue
        if 'vulnerable' in line.lower() or re.search(r'CVE-\d{4}-\d+', line):
            findings.append({"type":"msf_finding","detail":line.strip(),"severity":"high",
                "path":"service","command":"msfconsole -q"})
    return findings

def parse_generic(output):
    findings = []
    keywords = ['error','warning','open','found','vuln','allow','enabled','accessible',
                'weak','default','anonymous','expired','misconfig','exposed','no auth',
                'unauthenticated','world-readable','writable']
    for line in output.splitlines():
        stripped = line.strip()
        ll = stripped.lower()
        if not stripped or len(stripped) < 20:
            continue
        if stripped.startswith(';;'):
            continue
        if '\x1b[' in stripped:
            continue
        if re.match(r'^(error|warn|info|fatal|debug)\s*:', ll):
            continue
        if re.match(r'^\w[\w\- ]*:', stripped):
            continue
        if re.match(r'^(?:\[\*\]\s*)?no\s+[\w\s-]{0,40}found\.?\s*$', stripped, re.I):
            continue
        if any(k in ll for k in keywords):
            findings.append({"type":"generic","detail":stripped,"severity":"info",
                "path":"various","command":"manual review"})
    return findings


def parse_waf(output):
    """Report ONLY real WAF/CDN detections — never banner art, errors or tool noise."""
    findings = []
    detection = re.compile(
        r'is behind|behind the|in front of the site|waf[ -]?detected|'
        r'identified.*waf|wafw00f.*found|the site .* is behind', re.I)
    vendor = re.compile(
        r'\b(cloudflare|mod[\s_-]?security|imperva|akamai|barracuda|f5[\s-]?big[\s-]?ip|'
        r'fortiweb|aws[\s-]?waf|fastly|incapsula|sucuri|wordfence|citrix[\s-]?netscaler|'
        r'dosarrest|stackpath|sitelock|qrator)\b', re.I)
    for line in output.splitlines():
        s = line.strip()
        if not s or len(s) < 12:
            continue
        if detection.search(s):
            findings.append({"type":"waf_detected","detail":s[:160],"severity":"info",
                "path":"HTTP WAF/CDN","command":"wafw00f / nmap --script=http-waf-detect"})
        elif vendor.search(s) and re.search(r'waf|firewall|shield|protect|cdn', s, re.I):
            findings.append({"type":"waf_detected","detail":s[:160],"severity":"info",
                "path":"HTTP WAF/CDN","command":"wafw00f / nmap --script=http-waf-detect"})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW PARSERS — API & DATABASE
# ─────────────────────────────────────────────────────────────────────────────
def _api_evidence(path, code, body):
    """Body-evidence gate for discovery probes: a code alone proves nothing
    (catch-all routers 200 anything). Sensitive/spec paths only become
    findings when the returned content is actually the artifact they name."""
    if code in REDIRECT_CODES:
        return False
    if any(k in path for k in ('openapi', 'swagger', 'api-docs', 'api_docs')):
        return bool(body) and any(m in body for m in (
            '"openapi"', '"swagger"', '"paths"', '"components"',
            '"definitions"', '"info"', 'swagger-ui'))
    if 'actuator/env' in path:
        return bool(body) and any(m in body for m in (
            '"propertySources"', '"activeProfiles"', '"systemEnvironment"', '"env"'))
    if '/actuator' in path:
        return bool(body) and any(m in body for m in (
            '"status"', '"beans"', '"mappings"', '"configprops"', '"heapdump"',
            '"caches"', '"loggers"', '"metrics"', '"threaddump"'))
    if path == '/graphql':
        return bool(body) and any(m in body for m in (
            '"queryType"', '"__schema"', '"types"', '"data"', 'graphql'))
    if path == '/metrics':
        return bool(body) and any(m in body for m in (
            'jvm_', 'process_', 'http_server_', 'prometheus', '_samples'))
    if path == '/health':
        return bool(body) and '"status"' in body
    # Default deny: a bare status code on an arbitrary path is what a catch-all
    # router returns for everything, so it proves nothing. Any other path only
    # becomes a finding when the body is an actual JSON/API document.
    if code in ('401', '403', '405'):
        return False
    return bool(body) and len(body.strip()) > 2 and body.lstrip()[:1] in ('{', '[')


def parse_api_discovery(output):
    findings = []
    sensitive = {'/swagger':'/swagger — API docs exposed (schema disclosure)','swagger.json':'swagger.json — full API schema accessible',
                 '/openapi':'/openapi — OpenAPI spec exposed','/api-docs':'/api-docs exposed',
                 '/actuator':'/actuator — Spring Boot actuator exposed (env, mappings, beans)',
                 '/actuator/env':'/actuator/env — environment variables exposed',
                 '/graphql':'/graphql endpoint found','/metrics':'/metrics — internal metrics exposed',
                 '/health':'/health endpoint (may disclose internal state)'}
    sensitive_keys = sorted(sensitive, key=len, reverse=True)
    for line in output.splitlines():
        m = re.match(r'(/[^\s|]+):(\d{3})\|(.*)', line)
        if not m:
            continue
        path, code, body = m.group(1), m.group(2), m.group(3)
        if code in REDIRECT_CODES:                      # 3xx proves nothing
            continue
        if code not in ('200', '201', '204', '401', '403', '405', '500'):
            continue
        if not _api_evidence(path, code, body):
            continue
        if 'actuator/env' in path and code in ('200', '201', '204'):
            sev = 'critical'
        elif any(s in path for s in ('swagger', 'openapi', 'api-docs', 'graphql')):
            sev = 'high'
        elif '/actuator' in path:
            sev = 'medium'
        else:
            sev = 'info'                                # mapping recon, not a vuln
        desc = next((sensitive[k] for k in sensitive_keys if path.startswith(k)),
                    (f"API endpoint {path} requires authentication (HTTP {code})" if code in ('401', '403') else
                     f"API endpoint {path} responds (HTTP {code})"))
        findings.append({"type": "api_endpoint", "detail": desc, "severity": sev,
                         "path": path, "command": f"curl -skL http://<target>{path}"})
    if '__schema' in output and 'types' in output:
        findings.append({"type": "graphql_introspection", "severity": "high",
            "detail": "GraphQL introspection enabled — full schema disclosed",
            "path": "/graphql",
            "command": "curl -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'  http://<target>/graphql"})
    return findings

def parse_api_bola(output):
    findings = []
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if '=== id=' in line:
            id_m = re.search(r'id=(\S+)', line)
            if not id_m:
                continue
            obj_id = id_m.group(1)
            block = '\n'.join(lines[i:i+10])
            # IDOR evidence: the queried object id is echoed back, or the
            # response carries a concrete user identity (email/username) — a
            # bare JSON wrapper or catch-all page is not data disclosure.
            id_echo = re.escape(obj_id)
            if (re.search(r'"id"\s*:\s*["\']?' + id_echo + r'["\']?(?:\s*[,}])', block, re.I) or
                    re.search(r'"email"\s*:\s*"[^"]*@[^"]+"', block, re.I) or
                    re.search(r'"username"\s*:\s*"[^"]{2,}"|"name"\s*:\s*"[^"]{2,}"', block, re.I)):
                findings.append({"type": "bola_idor", "severity": "critical",
                    "detail": f"BOLA/IDOR: unauthenticated data returned for id={obj_id} — object-level auth missing",
                    "path": f"/api/v1/users/{obj_id}",
                    "command": f"curl -sk 'http://<target>/api/v1/users/{obj_id}'"})
            if re.search(r'"(password|secret|token|ssn|credit|card|hash|api_key|access_key)"\s*:\s*"?[^"]{3,}"?', block, re.I):
                findings.append({"type": "sensitive_data_exposure", "severity": "critical",
                    "detail": f"Sensitive fields exposed via IDOR (id={obj_id})",
                    "path": f"/api/v1/users/{obj_id}",
                    "command": f"curl -sk 'http://<target>/api/v1/users/{obj_id}'"})
    return findings

def parse_api_auth(output):
    findings = []
    checks = [
        ('jwt_none: 200', "JWT algorithm=none accepted — auth bypass", "critical", "/api/v1/admin",
         "curl -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.' http://<target>/api/v1/admin"),
        ('null_token: 200', "Null Bearer token accepted — auth bypass", "critical", "/api/v1/users",
         "curl -H 'Authorization: Bearer null' http://<target>/api/v1/users"),
    ]
    # Baseline: the unauthenticated admin call. If it already returns 200 there
    # is no auth to bypass — a "JWT none bypass" claim would be a hallucination.
    anon = re.search(r'anon:(\d{3})\|', output)
    anon_code = anon.group(1) if anon else None
    if anon_code and anon_code not in REDIRECT_CODES and anon_code != '000':
        if anon_code in ('200', '201', '204'):
            findings.append({"type": "unauth_endpoint", "severity": "high",
                "detail": "No authentication enforced — /api/v1/admin returns HTTP 200 without credentials",
                "path": "/api/v1/admin",
                "command": "curl -sk http://<target>/api/v1/admin"})
        else:
            for marker, msg, sev, path, cmd in checks:
                if marker in output:
                    findings.append({"type": "broken_auth", "detail": msg, "severity": sev,
                        "path": path, "command": cmd})
            for line in output.splitlines():
                m = re.match(r'(users|config):\s*(200)', line)
                if m:
                    findings.append({"type": "unauth_endpoint", "severity": "high",
                        "detail": f"API endpoint accessible without auth: {m.group(1)} → HTTP 200",
                        "path": f"/api/v1/{m.group(1)}",
                        "command": f"curl -sk http://<target>/api/v1/{m.group(1)}"})
    return findings

def parse_api_injection(output):
    findings = []
    error_patterns = [
        (r"SQL syntax|mysql_fetch|ORA-\d+|PSQLException|SQLiteException|you have an error in your sql",
         "SQL error in API response — SQL injection confirmed", "critical", "sqli"),
        (r"Warning.*mysql|Warning.*pg_|Fatal error.*mysqli",
         "PHP DB warning in API — SQL injection / verbose errors", "critical", "sqli"),
        (r"\{.*\$gt|operator.*\$ne|\$regex.*matched",
         "NoSQL operator reflected in response — NoSQL injection", "critical", "nosqli"),
        (r"SSTI_RESULT:[^\n]*\b49\b|\{\{7\*7\}\}.*\b49\b",
         "SSTI confirmed: 7*7=49 in response — Server-Side Template Injection", "critical", "ssti"),
        (r"Traceback|stack trace|at.*\(.*\)\s*$|Exception in thread",
         "Stack trace / exception in API response — code disclosure", "high", "error_disclosure"),
    ]
    lines_text = output
    for pattern, msg, sev, ftype in error_patterns:
        if re.search(pattern, lines_text, re.I):
            findings.append({"type":ftype,"detail":msg,"severity":sev,
                "path":"/api/v1 endpoint","command":"sqlmap -u 'http://<target>/api/v1/users?id=1' --level=5"})
    return findings

def parse_api_ssrf(output):
    findings = []
    imds_markers = re.compile(r'ami-id|instance-id|security-credentials|latest/meta-data|dynamic|local-ipv4|mac\b', re.I)
    for line in output.splitlines():
        m = re.match(r'(\w+)=baseline:(\d+)\|imds:(\d+)\|(.*?)\|local22:(\d+)$', line)
        if not m:
            continue
        param, base, imds, ibody, local = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        # IMDS SSRF: an HTTP 200 alone can be a catch-all; the response must
        # actually contain AWS IMDS metadata for a firm finding. 3xx proves
        # nothing.
        if imds not in REDIRECT_CODES and imds in ('200', '201', '202', '204') and \
           imds != base and imds_markers.search(ibody):
            findings.append({"type": "ssrf", "severity": "critical",
                "detail": f"SSRF via '{param}' parameter — AWS IMDS metadata returned (HTTP {imds})",
                "path": f"/api/v1/fetch?{param}=http://169.254.169.254/",
                "command": f"curl -skL 'http://<target>/api/v1/fetch?{param}=http://169.254.169.254/latest/meta-data/'"})
        # localhost:22 SSRF: the probe must CHANGE the response relative to the
        # inert baseline (catch-all apps return the same code for any param).
        if local not in REDIRECT_CODES and local not in ('000', '') and local != base:
            findings.append({"type": "ssrf", "severity": "high",
                "detail": f"SSRF via '{param}' — internal network probe altered the response ({base} → {local})",
                "path": f"/api/v1/proxy?{param}=http://127.0.0.1:22",
                "command": f"curl -skL 'http://<target>/api/v1/proxy?{param}=http://127.0.0.1:22'"})
    if re.search(r'root:.*:/bin/', output):
        findings.append({"type":"ssrf_lfi","severity":"critical",
            "detail":"SSRF + file:// scheme confirmed — /etc/passwd retrieved",
            "path":"/api/v1/fetch?url=file:///etc/passwd",
            "command":"curl -sk 'http://<target>/api/v1/fetch?url=file:///etc/passwd'"})
    return findings

def parse_api_mass_assign(output):
    findings = []
    # Mass assignment requires the response to be a stored resource (an id in
    # the same output) carrying the elevated field — request-body echo alone is
    # not proof the field was accepted.
    entity_id = re.search(r'"?\s*"id"\s*:\s*', output)
    if entity_id and re.search(r'"role"\s*:\s*"admin"|"is_admin"\s*:\s*true|"admin"\s*:\s*true|"privilege"\s*:\s*"admin"', output, re.I):
        findings.append({"type":"mass_assignment","severity":"critical",
            "detail":"Mass assignment: admin role field accepted in API body",
            "path":"/api/v1/users/1 (PUT/PATCH body)",
            "command":"curl -X PUT -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}' http://<target>/api/v1/users/1"})
    if entity_id and re.search(r'"credits"\s*:\s*\d{4,}|"balance"\s*:\s*\d{4,}', output, re.I):
        findings.append({"type":"mass_assignment","severity":"high",
            "detail":"Mass assignment: numeric privilege field accepted (credits/balance manipulation)",
            "path":"/api/v1/profile (PATCH body)",
            "command":"curl -X PATCH -H 'Content-Type: application/json' -d '{\"credits\":99999}' http://<target>/api/v1/profile"})
    # Function-level access: an arbitrary bare 200 is not proof — the
    # unauthenticated admin endpoint must return real JSON data (>=2 members,
    # which catch-all HTML / single-key error wrappers don't).
    def _json_data(body):
        return body and len(re.findall(r'"[A-Za-z_][A-Za-z0-9_]{1,}"\s*:', body)) >= 2
    unauth_proven = False
    for line in output.splitlines():
        m = re.match(r'(admin/users|internal/debug):(\d{3})\|(.*)', line)
        if m and m.group(2) not in REDIRECT_CODES and m.group(2) in ('200', '201', '202', '204') and _json_data(m.group(3)):
            unauth_proven = True
            findings.append({"type":"broken_function_auth","severity":"critical",
                "detail":f"Admin endpoint accessible without auth: /{m.group(1)} → HTTP {m.group(2)} (JSON data returned)",
                "path":f"/api/v1/{m.group(1)}",
                "command":f"curl -skL http://<target>/api/v1/{m.group(1)}"})
    # DELETE corroboration only counts once unauth access was already proven.
    delete_m = re.search(r'DELETE user:(\d{3})\|', output)
    if delete_m and unauth_proven and delete_m.group(1) in ('200', '204'):
        findings.append({"type":"broken_function_auth","severity":"critical",
            "detail":f"Broken Function Level Auth: DELETE /api/v1/users/1 returned HTTP {delete_m.group(1)} without authentication",
            "path":"/api/v1/users/1 (DELETE)",
            "command":"curl -X DELETE http://<target>/api/v1/users/1"})
    return findings

def parse_api_misc(output):
    findings = []
    if re.search(r'access-control-allow-origin:\s*\*', output, re.I):
        findings.append({"type":"api_cors_wildcard","severity":"high",
            "detail":"API CORS wildcard — any origin can read API responses",
            "path":"/api/v1 (CORS headers)",
            "command":"curl -H 'Origin: https://evil.com' -I http://<target>/api/v1/users"})
    # Rate-limit evidence: only the burst line counts. Scanning the first 500
    # characters for any 3-digit run picked up ids, versions and byte counts and
    # reported "no rate limiting" from unrelated numbers.
    rl_codes = []
    for line in output.splitlines():
        codes = re.findall(r'(?<![\w.])(\d{3})(?![\w.])', line)
        codes = [c for c in codes if c[0] in '12345']
        if len(codes) >= 10:            # the burst itself (>=10 responses)
            rl_codes.extend(codes)
    total = len(rl_codes)
    if total >= 10 and '429' not in rl_codes:
        findings.append({"type":"missing_rate_limit","severity":"medium",
            "detail":f"No rate limiting detected — {total} requests returned without any 429/throttle",
            "path":"/api/v1/login (rate limit test)",
            "command":"for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code}' http://<target>/api/v1/login; done"})
    # A key/secret *field name* is not an exposed credential; require an actual
    # assignment with a value long enough to be a real secret.
    key_m = re.search(
        r'["\']?(?:api[_-]?key|secret[_-]?key|aws[_-]?secret[_-]?(?:access[_-]?key)?|'
        r'stripe[_-]?(?:secret[_-]?)?key|twilio[_-]?(?:auth[_-]?)?token|sendgrid[_-]?(?:api[_-]?)?key)'
        r'["\']?\s*[:=]\s*["\']([^"\'\s]{12,})["\']', output, re.I)
    if not key_m:
        key_m = re.search(r'\b(AKIA[0-9A-Z]{16})\b', output)
    if key_m:
        findings.append({"type":"api_key_exposure","severity":"critical",
            "detail":"API key or secret token visible in /api/v1/config response",
            "path":"/api/v1/config",
            "command":"curl -sk http://<target>/api/v1/config | grep -iE 'key|secret|token'"})
    if re.search(r'(Traceback \(most recent call last\)|stack trace:|SQLSTATE\[|ORA-\d{5}|'
                 r'at [\w.$]+\([\w.$]+:\d+\)|on line \d+</b>|php on line \d+)', output, re.I):
        findings.append({"type":"verbose_error","severity":"medium",
            "detail":"Verbose error messages in API response — internal stack trace disclosed",
            "path":"/api/v1 (error endpoint)",
            "command":"curl -sk -X POST -H 'Content-Type: application/json' -d '{\"bad\":' http://<target>/api/v1/users"})
    return findings

def parse_db_discovery(output):
    findings = []
    db_ports = {
        '1433': ('mssql','MSSQL','high'),
        '1521': ('oracle','Oracle DB','high'),
        '3306': ('mysql','MySQL','medium'),
        '5432': ('postgres','PostgreSQL','medium'),
        '5984': ('couchdb','CouchDB','medium'),
        '6379': ('redis','Redis','high'),
        '7474': ('neo4j','Neo4j','medium'),
        '9200': ('elasticsearch','Elasticsearch','high'),
        '27017': ('mongodb','MongoDB','high'),
        '11211': ('memcached','Memcached','high'),
        '9042': ('cassandra','Cassandra','medium'),
    }
    for line in output.splitlines():
        m = re.match(r'(\d+)/tcp\s+open', line)
        if m:
            port = m.group(1)
            if port in db_ports:
                db_id, db_name, sev = db_ports[port]
                findings.append({"type":"db_exposed","detail":f"{db_name} port {port} open — database directly accessible",
                    "severity":sev,"path":f":{port}",
                    "command":f"nmap -sV -p {port} <target>"})
    return findings

def parse_db_unauth(output):
    findings = []
    if re.search(r'PONG|redis_version', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"critical",
            "detail":"Redis accessible without authentication — full read/write/config access",
            "path":"Redis :6379",
            "command":"redis-cli -h <target> ping; redis-cli -h <target> KEYS '*'"})
    if re.search(r'mongodb-databases|totalSize|databases\s*=\s*\[|admin\s*\.\s*local', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"critical",
            "detail":"MongoDB accessible without authentication — all databases enumerable",
            "path":"MongoDB :27017",
            "command":"mongo <target>:27017 --eval 'db.adminCommand({listDatabases:1})'"})
    if re.search(r'health.*green|indices.*pri|index.*docs', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"critical",
            "detail":"Elasticsearch accessible without auth — all indices readable",
            "path":"Elasticsearch :9200",
            "command":"curl http://<target>:9200/_cat/indices?v"})
    if re.search(r'\["_all_dbs"\]|\["[a-z_]+"\]', output):
        findings.append({"type":"db_unauth_access","severity":"high",
            "detail":"CouchDB accessible without auth — database list exposed",
            "path":"CouchDB :5984",
            "command":"curl http://<target>:5984/_all_dbs"})
    if re.search(r'results.*series|databases.*name', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"high",
            "detail":"InfluxDB accessible without auth — SHOW DATABASES returned data",
            "path":"InfluxDB :8086",
            "command":"curl 'http://<target>:8086/query?q=SHOW+DATABASES'"})
    return findings

def parse_db_default_creds(output):
    findings = []
    if re.search(r'mysql.*Empty password|root.*empty', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"MySQL root account has empty password",
            "path":"MySQL :3306",
            "command":"mysql -h <target> -u root"})
    if re.search(r'pgsql.*brute.*\+|postgres.*password.*postgres', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"PostgreSQL default credential (postgres/postgres) accepted",
            "path":"PostgreSQL :5432",
            "command":"psql -h <target> -U postgres"})
    if re.search(r'ms-sql.*sa.*Empty|MSSQL.*sa.*blank', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"MSSQL sa account has empty/blank password",
            "path":"MSSQL :1433",
            "command":"sqlcmd -S <target> -U sa -P ''"})
    if re.search(r'mysqladmin.*uptime|Version.*Uptime', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"MySQL root accessible without password (mysqladmin status success)",
            "path":"MySQL :3306",
            "command":"mysqladmin -h <target> -u root status"})
    if re.search(r'List of databases|postgres=|template0|template1', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"PostgreSQL accessible without password (empty password accepted)",
            "path":"PostgreSQL :5432",
            "command":"PGPASSWORD='' psql -h <target> -U postgres -c '\\l'"})
    return findings

def parse_db_sqli(output):
    findings = []
    sql_errors = [
        r"SQL syntax.*near|syntax error.*at line|mysql_fetch_array|pg_query\(\)|ORA-\d{5}",
        r"SQLSTATE\[\w+\]|PDOException|SQLiteException|Unclosed quotation mark",
        r"Warning.*mysql_|Fatal error.*mysql|Microsoft OLE DB.*error",
    ]
    for pattern in sql_errors:
        if re.search(pattern, output, re.I):
            findings.append({"type":"sql_injection","severity":"critical",
                "detail":"SQL error in response — error-based SQL injection confirmed",
                "path":"/?id= or /login (query parameter)",
                "command":"sqlmap -u 'http://<target>/?id=1' --level=5 --risk=3 --dbs --batch"})
            break
    sleep_m = re.search(r'sleep_probe=([\d.]+)s baseline=([\d.]+)s', output)
    if sleep_m:
        sp, bp = float(sleep_m.group(1)), float(sleep_m.group(2))
        if sp > bp + 2.5:
            findings.append({"type":"blind_sqli","severity":"critical",
                "detail":f"Time-based blind SQLi confirmed: SLEEP probe={sp:.2f}s vs baseline={bp:.2f}s",
                "path":"/?id= (time-based blind)",
                "command":"sqlmap -u 'http://<target>/?id=1' --technique=T --level=5 --dbs"})
    if re.search(r"POST.*'.*\|.*ERROR|username.*'.*login.*error", output, re.I):
        findings.append({"type":"sql_injection","severity":"critical",
            "detail":"SQL error triggered via POST login form — authentication bypass possible",
            "path":"/login (POST body username parameter)",
            "command":"sqlmap -u http://<target>/login --data='username=*&password=test' --level=5"})
    return findings

def parse_db_nosql(output):
    findings = []
    # Response-artifact evidence only. A healthy endpoint returning
    # {"success":true} is not NoSQL injection; a bypass must have produced a
    # session/credential artifact (the request echo is stripped before parsing).
    auth_art = re.search(
        r'"(?:access_token|id_token|refresh_token|token|jwt|session(?:id|_token)?)"\s*:\s*"[^"]{10,}"',
        output, re.I)
    auth_flag = re.search(r'"(?:authenticated|logged_in)"\s*:\s*true', output, re.I)
    if auth_art or auth_flag:
        findings.append({"type":"nosql_injection","severity":"critical",
            "detail":"NoSQL operator injection ($gt/$ne/$regex) bypassed authentication",
            "path":"/login or /api/login (POST body JSON)",
            "command":"curl -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}' http://<target>/login"})
    # $where injection must have produced a server-side JS error, otherwise the
    # text could simply be reflected input.
    if re.search(r'\$where\b', output, re.I) and re.search(
            r'(SyntaxError|TypeError|ReferenceError|not a function|is not defined)', output):
        findings.append({"type":"nosql_injection","severity":"critical",
            "detail":"NoSQL $where JS injection accepted — server-side JS execution possible",
            "path":"/api/v1/users (POST body)",
            "command":"curl -X POST -H 'Content-Type: application/json' -d '{\"$where\":\"1==1\"}' http://<target>/api/v1/users"})
    if re.search(r'requirepass.*\(empty\)|1\)\s*"requirepass"\s*\n\s*2\)\s*""', output, re.I):
        findings.append({"type":"redis_no_auth","severity":"critical",
            "detail":"Redis requirepass is empty — no authentication configured",
            "path":"Redis :6379 (CONFIG GET requirepass)",
            "command":"redis-cli -h <target> CONFIG GET requirepass"})
    if re.search(r'KEYS.*\*.*:\d+|KEYS.*session|KEYS.*user|KEYS.*token', output, re.I):
        findings.append({"type":"redis_data_exposure","severity":"high",
            "detail":"Redis KEYS enumeration returned session/user/token data",
            "path":"Redis :6379 (KEYS *)",
            "command":"redis-cli -h <target> KEYS '*'"})
    return findings

def parse_db_privesc(output):
    findings = []
    if re.search(r'FILE_PRIV.*Y|super_priv.*Y|grant_priv.*Y', output, re.I):
        findings.append({"type":"db_excessive_priv","severity":"critical",
            "detail":"MySQL FILE/SUPER/GRANT privilege granted — potential OS file read/write and privilege escalation",
            "path":"MySQL :3306 (SHOW GRANTS)",
            "command":"mysql -h <target> -u <user> -e 'SHOW GRANTS FOR CURRENT_USER()'"})
    if re.search(r'general_log\s*[:=|]?\s*(?:OFF|0)|slow_query_log\s*[:=|]?\s*(?:OFF|0)', output, re.I):
        findings.append({"type":"db_no_audit_log","severity":"medium",
            "detail":"MySQL query logging disabled — no audit trail for malicious queries",
            "path":"MySQL :3306 (SHOW VARIABLES)",
            "command":"mysql -h <target> -u root -e \"SHOW VARIABLES LIKE '%log%'\""})
    # Only explicit "SSL/TLS is off" statements count. Matching any `ssl_type`
    # token flagged every MySQL host (the column is empty when the *user* has no
    # SSL requirement, which says nothing about server transport encryption).
    if re.search(r'have_ssl\s*[:=|]?\s*(?:DISABLED|NO)\b|'
                 r'have_ssl\s*[:=|]?\s*["\']?\s*(?:OFF|0|NONE)\b|'
                 r'(?:ssl|tls)\s*(?:support|enabled)?\s*[:=]\s*(?:false|no|off|disabled)\b|'
                 r'(?:server\s+)?does\s+not\s+support\s+(?:ssl|tls)', output, re.I):
        findings.append({"type":"db_unencrypted_conn","severity":"high",
            "detail":"Database connections not encrypted — traffic readable in transit",
            "path":"MySQL/PostgreSQL (SSL status)",
            "command":"mysql -h <target> -e 'SHOW VARIABLES LIKE \\'%ssl%\\''"})
    if re.search(r'(SQL syntax|ORA-|SQLSTATE|mysql_error|pg_query.*fail)', output, re.I):
        findings.append({"type":"verbose_db_error","severity":"medium",
            "detail":"Verbose DB error message in HTTP response — DBMS type/version disclosed",
            "path":"/?id=' (error response)",
            "command":"curl -sk 'http://<target>/?id=1\\'' | grep -iE 'sql|mysql|postgres|oracle'"})
    # Explicit NSE "not supported" wording only; "SSLv2 disabled" from an SSL
    # scan is a good result, not an unencrypted database.
    if re.search(r'(?:mysql|pgsql|mssql)[^\n]{0,40}(?:ssl|tls)[^\n]{0,40}(?:disabled|not supported|not enabled)|'
                 r'(?:ssl|tls)[^\n]{0,20}(?:is\s+)?not\s+enabled[^\n]{0,20}(?:mysql|postgres)', output, re.I):
        findings.append({"type":"db_unencrypted_conn","severity":"high",
            "detail":"Database connection unencrypted — data at rest and in transit unprotected",
            "path":"DB port (TLS check)",
            "command":"nmap --script=mysql-ssl -p 3306 <target>"})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────

def parse_sqlmap(output):
    findings = []
    # sqlmap's own negative verdicts ("does not seem to be injectable",
    # "all tested parameters do not appear to be injectable", …) must never
    # become findings; usage/error text is skipped wholesale.
    if re.search(r'^Usage: (?:python3 )?sqlmap', output, re.M):
        return []
    # Detected injection type
    for line in output.splitlines():
        if _NEGATED_RESULT.search(line):
            continue
        ll = line.lower()
        # Injection confirmed lines
        if re.search(r'(parameter|place).*appears to be.*injectable|sqlmap identified.*injection point', line, re.I):
            param_m = re.search(r"Parameter: '?([^']+)'? \(", line)
            param = param_m.group(1) if param_m else 'unknown parameter'
            findings.append({"type":"sql_injection","severity":"critical",
                "detail":f"sqlmap confirmed SQL injection: {line.strip()[:150]}",
                "path":f"/?{param}= or form field",
                "command":f"sqlmap -u 'http://<target>/?{param}=1' --batch --level=5 --risk=3 --dbs"})
        # Technique identified
        if re.search(r"Type: (boolean-based|error-based|time-based|UNION query|stacked queries|inline query)", line, re.I):
            tech_m = re.search(r"Type: (.+)", line)
            tech = tech_m.group(1) if tech_m else line.strip()
            findings.append({"type":"sqli_technique","severity":"critical",
                "detail":f"SQLi technique confirmed: {tech}",
                "path":"injection point",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --technique=BEUSTQ --dbs"})
        # DBMS fingerprint
        if re.search(r"back-end DBMS:", line, re.I):
            findings.append({"type":"db_fingerprint","severity":"high",
                "detail":f"Database fingerprinted: {line.strip()}",
                "path":"server",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --banner --current-db"})
        # Current user
        if re.search(r"current user is|current user:", line, re.I):
            findings.append({"type":"db_user_disclosed","severity":"high",
                "detail":f"DB user: {line.strip()}",
                "path":"database",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --current-user"})
        # Databases
        if re.search(r"available databases|found.*database", line, re.I):
            findings.append({"type":"db_enumerated","severity":"high",
                "detail":f"Databases enumerated: {line.strip()[:120]}",
                "path":"information_schema",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --dbs"})
        # DBA privilege
        if re.search(r"current user is DBA|running as DBA", line, re.I):
            findings.append({"type":"db_dba_privilege","severity":"critical",
                "detail":"sqlmap confirmed current DB user has DBA privileges",
                "path":"database privilege",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --privileges"})
        # File system access
        if re.search(r"file-read|INTO OUTFILE|INTO DUMPFILE|file privilege", line, re.I):
            findings.append({"type":"sqli_file_access","severity":"critical",
                "detail":"SQL injection allows file system read/write (FILE privilege confirmed)",
                "path":"server filesystem via SQL",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --file-read='/etc/passwd'"})
        # OS shell
        if re.search(r"os-shell|command execution|xp_cmdshell", line, re.I):
            findings.append({"type":"sqli_os_rce","severity":"critical",
                "detail":"SQL injection may allow OS command execution (os-shell / xp_cmdshell)",
                "path":"OS via SQL injection",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --os-shell"})
        # Second-order detected
        if re.search(r"second.order|stored.injection|second order", line, re.I):
            findings.append({"type":"second_order_sqli","severity":"critical",
                "detail":"Second-order (stored) SQL injection detected",
                "path":"input stored then triggered",
                "command":"sqlmap -u 'http://<target>/' --second-url='http://<target>/profile' --batch"})
    return findings

def parse_nuclei(output):
    findings = []
    for line in output.splitlines():
        # nuclei output format: [template-id] [severity] url
        m = re.match(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(https?://\S+)\s*(.*)', line)
        if m:
            tmpl, proto, sev_raw, url, extra = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            sev = sev_raw.lower().strip()
            if sev not in ('critical','high','medium','low','info'):
                sev = 'medium'
            path = re.sub(r'https?://[^/]+', '', url) or '/'
            findings.append({"type":"nuclei_finding","severity":sev,
                "detail":f"[{tmpl}] {extra.strip() or proto} at {url}",
                "path":path,
                "command":f"nuclei -u http://<target> -t {tmpl}"})
        # alternate format: [severity] [template] detail
        elif re.match(r'\[(critical|high|medium|low)\]', line, re.I):
            sev_m = re.match(r'\[(\w+)\]', line)
            sev = sev_m.group(1).lower() if sev_m else 'medium'
            if sev in ('critical','high','medium','low'):
                findings.append({"type":"nuclei_finding","severity":sev,
                    "detail":line.strip()[:200],"path":"web application",
                    "command":"nuclei -u http://<target> -severity " + sev})
    return findings

def parse_subdomains(output, sess):
    """Only pre-validated resolvable subdomains become findings — crt.sh /
    dnsrecon candidate lines are printed but never emitted (no resolution
    proof). Everything here is informational."""
    findings = []
    seen = set()
    target = str(sess.get('target', ''))
    tgt = re.escape(target) if target else r'[a-z0-9.-]+'
    for line in output.splitlines():
        m = re.search(r'(?i)([a-z0-9_.-]+\.' + tgt + r')\s*->\s*([0-9.]+)', line)
        if m:
            name, ip = m.group(1), m.group(2)
            if name in seen: continue
            seen.add(name)
            findings.append({"type": "subdomain", "severity": "info",
                "detail": f"Resolved subdomain: {name} -> {ip}",
                "path": name, "command": f"dig +short {name} A"})
            continue
        m = re.search(r'\[\+\]\s+A\s+([a-z0-9_.-]+\.' + tgt + r')\s+([0-9.]+)', line, re.I)
        if m:
            name, ip = m.group(1), m.group(2)
            if name in seen: continue
            seen.add(name)
            findings.append({"type": "subdomain", "severity": "info",
                "detail": f"dnsrecon A record: {name} -> {ip}",
                "path": name, "command": f"dig +short {name} A"})
    return findings

def parse_urls(output, sess):
    """Reports URLs/endpoints actually discovered by crawling or declared in
    robots.txt / sitemap.xml. Informational only: same-host URLs only, each one
    was reached or explicitly listed; nothing is inferred and no placeholders
    are emitted."""
    findings = []
    seen = set()
    target = str((sess or {}).get('target', ''))
    try:
        base = _base_url(sess)
    except Exception:
        base = 'http://' + target if target else ''
    host = re.sub(r'^https?://', '', base).split('/')[0].split(':')[0] if base else ''
    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        url = ''
        m = re.search(r'https?://[^\s"\'<>]+', s)
        if m:
            url = m.group(0).rstrip('.,;)\'"')
        else:
            m = re.match(r'(?i)(?:Allow|Disallow|Sitemap|Location):\s*(\S+)', s)
            if m:
                p = m.group(1)
                if p.startswith('http'):
                    url = p
                elif base:
                    url = base.rstrip('/') + '/' + p.lstrip('/')
        if not url or not url.startswith('http'):
            continue
        uhost = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
        if base:
            host = re.sub(r'^https?://', '', base).split('/')[0].split(':')[0]
            if uhost and uhost != host and not uhost.endswith('.' + host):
                continue
        key = url.rstrip('/')
        if key in seen:
            continue
        seen.add(key)
        path = re.sub(r'^https?://[^/]+', '', url) or '/'
        findings.append({"type": "web_path", "severity": "info",
            "detail": f"URL discovered: {url}",
            "path": path,
            "command": f"curl -sk {url}"})
        if len(findings) >= 250:
            break
    return findings


def parse_breach_osint(output, sess):
    """Breach findings require a real HIBP 200 breach response (COMPROMISED:).
    Discovered emails are informational; NO_BREACH lines show the lookup ran
    and returned clean, which is itself worth recording."""
    findings = []
    target = str(sess.get('target', ''))
    emails = set()
    for line in output.splitlines():
        s = line.strip()
        if s.startswith('COMPROMISED:'):
            rest = s.split(':', 1)[1]
            email, _, breaches = rest.partition('|')
            if email:
                findings.append({"type": "breach_exposure", "severity": "critical",
                    "path": email,
                    "detail": f"Email {email} appears in breaches (HIBP v3): {breaches[:120]}",
                    "command": "PWM_HIBP_KEY set — haveibeenpwned breachedaccount lookup"})
        elif s.startswith('NO_BREACH:'):
            email = s.split(':', 1)[1]
            if email:
                findings.append({"type": "no_breach", "severity": "info",
                    "path": email,
                    "detail": f"HIBP check ran for {email} — no breach found",
                    "command": "haveibeenpwned breachedaccount lookup"})
        elif re.search(r'[a-z0-9._%+-]+@[a-z0-9.-]+', s):
            em = re.match(r'[a-z0-9._%+-]+@[a-z0-9.-]+', s)
            if em:
                emails.add(em.group(0))
    if target and target.replace('.', '').isalnum() and len(emails) <= 200:
        for em in sorted(emails)[:40]:
            domain = em.split('@', 1)[1] if '@' in em else ''
            if domain and (domain.endswith(target) or domain.endswith('.' + target)):
                findings.append({"type": "email_discovered", "severity": "info",
                    "path": em, "detail": f"Employee email discovered via theHarvester: {em}",
                    "command": "theHarvester -d <target> -b all"})
    return findings

def _js_bundle_url(src, target):
    """Real URL of a JS bundle reference as written in the page."""
    if src.startswith('http://') or src.startswith('https://'):
        return src
    if src.startswith('/'):
        return f'http://{target}{src}'
    return f'http://{target}/{src}'


def parse_js_leak(output, sess):
    """High findings only for real secret-format matches (SECRET:<kind>:<value>);
    endpoints and sourcemaps are informational. Paths and commands reference
    the real bundle URLs the scan fetched — never placeholder text."""
    findings = []
    seen_secrets = set()
    seen_eps = set()
    srcs = []
    section = ''
    target = (sess or {}).get('target', '')
    for line in output.splitlines():
        s = line.strip()
        if s.startswith('=====') and s.endswith('====='):
            section = s.strip('=')
            continue
        if not s:
            continue
        if section == 'JS-SRC-LIST':
            srcs.append(s)
            continue
        if s.startswith('SECRET:'):
            parts = s.split(':', 2)
            if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
                continue        # malformed marker — never crash the whole scan
            _, kind, value = parts
            key = (kind, value[:40])
            if key in seen_secrets: continue
            seen_secrets.add(key)
            js_url = _js_bundle_url(srcs[0], target) if srcs else ''
            findings.append({"type": "js_secret_leak", "severity": "high",
                "path": re.sub(r'^https?://[^/]+', '', js_url) if js_url else '-',
                "detail": f"Possible {kind} secret in JS bundle"
                          + (f" ({js_url})" if js_url else "") + f": {value[:70]}",
                "command": f"curl -sk {js_url}" if js_url else ""})
            continue
        if s.startswith('MAP:'):
            u = s.split(':', 1)[1]
            findings.append({"type": "sourcemap_exposed", "severity": "info",
                "path": re.sub(r'^https?://[^/]+', '', u) or '/',
                "detail": f"Sourcemap file reachable — original source may be recoverable: {u}",
                "command": f"curl -sk {u}"})
            continue
        if section != 'JS-ENDPOINTS':
            continue
        if len(seen_eps) >= 30: continue
        ep = re.match(r'^((?:/|https?://)[^ ]+)$', s)
        if ep and ('/api/' in s or '/v1/' in s or '/v2/' in s or '/graphql' in s or '/rest' in s):
            if s in seen_eps: continue
            seen_eps.add(s)
            js_url = _js_bundle_url(srcs[0], target) if srcs else ''
            findings.append({"type": "js_endpoint", "severity": "info",
                "path": s, "detail": f"API endpoint extracted from JS bundle: {s}",
                "command": f"curl -sk {js_url}" if js_url else ""})
    return findings

# product-version regex -> CPE (vendor, product) mappings for NVD verification.
# Only products with a known vendor/product CPE are cross-referenced; anything
# else is reported nowhere rather than guessed.
CPE_PATTERNS = [
    (r'OpenSSH[_\s-]?([\d.]+)',           ('openbsd', 'openssh'), 'OpenSSH'),
    (r'Apache httpd[ /\-]?([\d.]+)',      ('apache', 'http_server'), 'Apache'),
    (r'nginx/([\d.]+)',                   ('nginx', 'nginx'), 'nginx'),
    (r'MySQL[ /]([\d.]+)',                ('oracle', 'mysql'), 'MySQL'),
    (r'MariaDB[ /]([\d.]+)',              ('mariadb', 'mariadb'), 'MariaDB'),
    (r'PostgreSQL[ /]([\d.]+)',           ('postgresql', 'postgresql'), 'PostgreSQL'),
    (r'redis[ -]?server[ =\w/]*([\d.]+)|redis_version[^\d]*([\d.]+)', ('redis', 'redis'), 'Redis'),
    (r'MongoDB[ /]([\d.]+)',              ('mongodb', 'mongodb'), 'MongoDB'),
    (r'Tomcat/([\d.]+)',                  ('apache', 'tomcat'), 'Tomcat'),
    (r'vsftpd[ /]([\d.]+)',               ('vsftpd', 'vsftpd'), 'vsftpd'),
    (r'ProFTPD[ /]([\d.]+)',              ('proftpd', 'proftpd'), 'ProFTPD'),
    (r'PHP[ /]([\d.]+)',                  ('php', 'php'), 'PHP'),
    (r'OpenSSL[ /]([\d.]+[a-z]?)',        ('openssl', 'openssl'), 'OpenSSL'),
    (r'Samba[ /]([\d.]+)',                ('samba', 'samba'), 'Samba'),
    (r'Jenkins[ :](\d+)',                 ('jenkins', 'jenkins'), 'Jenkins'),
]

def parse_version_cve(output, sess):
    """Cross-references each nmap service/version pairing against the NVD
    cpeName API. Findings are emitted only for CVEs NVD assigns to that exact
    product+version CPE, carrying NVD's real CVSS vector; the finding severity
    is derived from that score's band."""
    findings = []
    for line in output.splitlines():
        if not re.search(r'\d+/tcp\s+open', line):
            continue
        port_m = re.search(r'(\d+)/tcp', line)
        path = f":{port_m.group(1)}" if port_m else "service"
        for pat, (vend, prod), tok in CPE_PATTERNS:
            m = re.search(pat, line, re.I)
            if not m:
                continue
            ver = next((g for g in m.groups() if g), None)
            if not ver:
                continue
            vm = re.match(r'(\d+(?:\.\d+){1,3})', ver)
            if not vm:
                # Single-component versions (e.g. "Jenkins 2") cannot form an
                # exact-version CPE — skip instead of crashing on .group(1).
                continue
            ver = vm.group(1)
            nvd = _nvd_verify_cpe(f"{vend}:{prod}", ver)
            for c in nvd[:5]:
                band = cvss31_band(c['score'])
                sev = band if band in ('critical', 'high', 'medium') else 'low'
                findings.append({"type": "cve", "severity": sev, "path": path,
                    "detail": f"{tok} {ver} — {c['cve']} (CVSS {c['score']}, NVD-verified) — {c['reference'][:80]}",
                    "command": f"nmap -sV -p {path.lstrip(':')} <target>",
                    "cvss": {"vector": c['vector'], "base_score": c['score'],
                             "severity_band": band, "band_mismatch": False,
                             "source": "nvd-cpe-verified"}})
            break
    return findings

# ── Technology fingerprint classification ───────────────────────────────────
# Categories reported by the Web Stack / Technology Fingerprint substage.
# The rule table below only CLASSIFIES evidence that a tool actually printed;
# it can never introduce a technology that was not observed.
TECH_CATEGORY_LIST = [
    "Analytics", "CDN", "Security", "UI/Web Frameworks", "Advertising",
    "Payment Processors", "Font Scripts", "Libraries", "Miscellaneous",
    "RUM", "Web Servers", "Customer Data Platform", "Programming Languages",
]

# whatweb plugins that describe geo/IP/status metadata, not a technology
TECH_NON_TECH = {
    "country", "ip", "ip-address", "ipv6", "status-line", "title",
    "redirectlocation", "script", "scripts", "uncommonheaders",
    "commonheaders", "cookies", "meta-author", "meta-description",
    "meta-viewport", "image-size", "favicon", "uncommon-headers",
}

# (pattern on lowercased evidence, technology label, category) — first match wins
_TECH_RULES = [
    # CDN / edge (asset CDNs before the provider rules: cdnjs.cloudflare.com
    # is a library CDN, while the cf-ray header below still names Cloudflare)
    (r"cdnjs|jsdelivr|unpkg|bootstrapcdn|bootcdn|ajax\.googleapis|code\.jquery",
     "JavaScript CDN", "CDN"),
    (r"cf-ray|cf-cache-status|\bcloudflare\b", "Cloudflare", "CDN"),
    (r"x-amz-cf|\bcloudfront\b", "Amazon CloudFront", "CDN"),
    (r"\bfastly\b|x-fastly", "Fastly", "CDN"),
    (r"\bakamai\b|x-akamai", "Akamai", "CDN"),
    (r"\bbunnycdn\b|x-bunnycdn", "BunnyCDN", "CDN"),
    (r"\bstackpath\b|x-stackpath", "StackPath", "CDN"),
    (r"azureedge", "Microsoft Azure CDN", "CDN"),
    # Security products / WAF
    (r"\bsucuri\b|x-sucuri", "Sucuri", "Security"),
    (r"\bimperva\b|\bincapsula\b|x-iinfo", "Imperva/Incapsula", "Security"),
    (r"x-amzn-waf|amzn-waf|aws waf", "AWS WAF", "Security"),
    (r"\bfortiweb\b|\bfortigate\b|\bfortinet\b", "Fortinet", "Security"),
    (r"\bbigip\b|x-f5-", "F5 BIG-IP", "Security"),
    (r"\bmodsecurity\b", "ModSecurity", "Security"),
    (r"\bbarracuda\b", "Barracuda WAF", "Security"),
    # RUM / observability agents
    (r"newrelic|nr-data\.net|new relic", "New Relic", "RUM"),
    (r"datadoghq|datadog", "Datadog", "RUM"),
    (r"\bsentry\b|sentry-cdn", "Sentry", "RUM"),
    (r"cloudflareinsights", "Cloudflare Insights", "RUM"),
    (r"\bfullstory\b", "FullStory", "RUM"),
    (r"\bspeedcurve\b", "SpeedCurve", "RUM"),
    (r"\bpingdom\b|ptmstats", "Pingdom", "RUM"),
    (r"\bdynatrace\b", "Dynatrace", "RUM"),
    (r"appdynamics", "AppDynamics", "RUM"),
    (r"clarity\.ms|microsoft clarity", "Microsoft Clarity", "RUM"),
    (r"elastic-apm|elasticapm", "Elastic APM", "RUM"),
    # Customer data platforms (before analytics: segment ships analytics.js)
    (r"segment\.com|segment\.io|analytics\.load\.segment", "Segment", "Customer Data Platform"),
    (r"\bmparticle\b", "mParticle", "Customer Data Platform"),
    (r"\blytics\b", "Lytics", "Customer Data Platform"),
    (r"\bblueconic\b", "BlueConic", "Customer Data Platform"),
    (r"\btealium\b|utag\.", "Tealium", "Customer Data Platform"),
    (r"treasuredata", "Treasure Data", "Customer Data Platform"),
    # Analytics
    (r"google-analytics|googletagmanager|google tag manager|ga\.js|\bgtag\b",
     "Google Analytics / Tag Manager", "Analytics"),
    (r"\bmatomo\b|\bpiwik\b", "Matomo", "Analytics"),
    (r"\bmixpanel\b", "Mixpanel", "Analytics"),
    (r"\bamplitude\b", "Amplitude", "Analytics"),
    (r"kissmetrics", "Kissmetrics", "Analytics"),
    (r"\bhotjar\b", "Hotjar", "Analytics"),
    (r"crazyegg", "Crazy Egg", "Analytics"),
    (r"heapanalytics|heap\.io", "Heap", "Analytics"),
    (r"statcounter", "StatCounter", "Analytics"),
    (r"chartbeat", "Chartbeat", "Analytics"),
    (r"\bplausible\b", "Plausible", "Analytics"),
    (r"fathom\.analytics|fathom\.cc", "Fathom", "Analytics"),
    # Advertising
    (r"adsense|googlesyndication|googleadservices|doubleclick", "Google Ads / AdSense", "Advertising"),
    (r"connect\.facebook\.net|fbevents", "Meta Pixel", "Advertising"),
    (r"\badnxs\b", "AppNexus", "Advertising"),
    (r"\bcriteo\b", "Criteo", "Advertising"),
    (r"\btaboola\b", "Taboola", "Advertising"),
    (r"\boutbrain\b", "Outbrain", "Advertising"),
    (r"amazon-adsystem", "Amazon Advertising", "Advertising"),
    (r"bat\.bing\.com", "Microsoft Advertising", "Advertising"),
    (r"adsrvr\.org|demdex", "The Trade Desk / Adobe Demdex", "Advertising"),
    (r"doubleverify", "DoubleVerify", "Advertising"),
    (r"\bmoatads\b", "Moat", "Advertising"),
    # Payment processors
    (r"js\.stripe\.com|api\.stripe", "Stripe", "Payment Processors"),
    (r"paypal\.com|paypalobjects", "PayPal", "Payment Processors"),
    (r"\bbraintree\b", "Braintree", "Payment Processors"),
    (r"squareup|sqpayment", "Square", "Payment Processors"),
    (r"\badyen\b", "Adyen", "Payment Processors"),
    (r"checkout\.com", "Checkout.com", "Payment Processors"),
    (r"\brecurly\b", "Recurly", "Payment Processors"),
    (r"\bpaddle\.(com|net)", "Paddle", "Payment Processors"),
    (r"\brazorpay\b", "Razorpay", "Payment Processors"),
    (r"\bmollie\b", "Mollie", "Payment Processors"),
    (r"\bchargebee\b", "Chargebee", "Payment Processors"),
    # Font scripts
    (r"fonts\.googleapis|fonts\.gstatic|google font", "Google Fonts", "Font Scripts"),
    (r"typekit|fonts\.adobe", "Adobe Typekit", "Font Scripts"),
    (r"fonts\.com", "Fonts.com", "Font Scripts"),
    (r"\bfontdeck\b", "Fontdeck", "Font Scripts"),
    (r"typotheque", "Typotheque", "Font Scripts"),
    (r"webfontloader", "Web Font Loader", "Font Scripts"),
    # UI / web frameworks
    (r"_next/static|__next_data__|\bnextjs\b|next\.js", "Next.js", "UI/Web Frameworks"),
    (r"__nuxt__|\bnuxt\b", "Nuxt", "UI/Web Frameworks"),
    (r"data-reactroot|react[-.]?dom|\breact\b", "React", "UI/Web Frameworks"),
    (r"data-v-|vue\.js|vuejs|\bvue\b", "Vue.js", "UI/Web Frameworks"),
    (r"ng-version|\bangular\.?js\b|\bangular\b", "Angular", "UI/Web Frameworks"),
    (r"\bbackbone\b", "Backbone.js", "UI/Web Frameworks"),
    (r"\bember\b", "Ember.js", "UI/Web Frameworks"),
    (r"\bsvelte\b", "Svelte", "UI/Web Frameworks"),
    (r"\bgatsby\b", "Gatsby", "UI/Web Frameworks"),
    (r"\bmeteor\b", "Meteor", "UI/Web Frameworks"),
    (r"\bdjango\b", "Django", "UI/Web Frameworks"),
    (r"ruby on rails", "Ruby on Rails", "UI/Web Frameworks"),
    (r"\blaravel\b", "Laravel", "UI/Web Frameworks"),
    (r"\bexpress\b", "Express", "UI/Web Frameworks"),
    (r"asp\.net|x-powered-by:.*\.net", "ASP.NET", "UI/Web Frameworks"),
    (r"\bsymfony\b", "Symfony", "UI/Web Frameworks"),
    (r"\bflask\b", "Flask", "UI/Web Frameworks"),
    (r"fastapi", "FastAPI", "UI/Web Frameworks"),
    # Web servers (before programming languages: server headers carry both)
    (r"\bnginx\b", "nginx", "Web Servers"),
    (r"\bapache\b|\bhttpd\b", "Apache HTTP Server", "Web Servers"),
    (r"microsoft-iis|microsoft iis|\biis\b", "Microsoft IIS", "Web Servers"),
    (r"\blitespeed\b", "LiteSpeed", "Web Servers"),
    (r"\bgunicorn\b", "Gunicorn", "Web Servers"),
    (r"\buwsgi\b", "uWSGI", "Web Servers"),
    (r"\bcaddy\b", "Caddy", "Web Servers"),
    (r"\bopenresty\b", "OpenResty", "Web Servers"),
    (r"\btomcat\b", "Apache Tomcat", "Web Servers"),
    (r"\bjetty\b", "Jetty", "Web Servers"),
    (r"wildfly|\bjboss\b", "WildFly/JBoss", "Web Servers"),
    (r"weblogic", "Oracle WebLogic", "Web Servers"),
    (r"websphere", "IBM WebSphere", "Web Servers"),
    (r"\blighttpd\b", "lighttpd", "Web Servers"),
    (r"simplehttp", "SimpleHTTP", "Web Servers"),
    (r"\bwerkzeug\b", "Werkzeug", "Web Servers"),
    (r"\bvarnish\b", "Varnish", "Web Servers"),
    # Programming languages
    (r"\bphp\b", "PHP", "Programming Languages"),
    (r"\bpython\b", "Python", "Programming Languages"),
    (r"\bruby\b", "Ruby", "Programming Languages"),
    (r"\bperl\b", "Perl", "Programming Languages"),
    (r"\bnode(\.js)?\b", "Node.js", "Programming Languages"),
    (r"\bjava\b", "Java", "Programming Languages"),
    (r"\bgolang\b|go1\.", "Go", "Programming Languages"),
    # Libraries
    (r"jquery-ui|jquery\.ui", "jQuery UI", "Libraries"),
    (r"\bjquery\b", "jQuery", "Libraries"),
    (r"\blodash\b", "lodash", "Libraries"),
    (r"\bunderscore\b", "Underscore.js", "Libraries"),
    (r"\bmoment\b", "Moment.js", "Libraries"),
    (r"\baxios\b", "Axios", "Libraries"),
    (r"d3\.js|d3\.min|d3\.v\d", "D3.js", "Libraries"),
    (r"\bbootstrap\b", "Bootstrap", "Libraries"),
    (r"font-?awesome", "Font Awesome", "Libraries"),
    (r"hammer\.js", "Hammer.js", "Libraries"),
    (r"\bmodernizr\b", "Modernizr", "Libraries"),
    (r"requirejs|require\.js", "RequireJS", "Libraries"),
    (r"\bhandlebars\b", "Handlebars", "Libraries"),
    (r"\bmustache\b", "Mustache", "Libraries"),
    (r"chart\.js", "Chart.js", "Libraries"),
    (r"\bhighcharts\b", "Highcharts", "Libraries"),
    (r"slick-carousel|slick\.min", "Slick", "Libraries"),
    (r"\bswiper\b", "Swiper", "Libraries"),
    (r"\bpopper\b", "Popper.js", "Libraries"),
    (r"prototype\.js", "Prototype.js", "Libraries"),
    (r"\bmootools\b", "MooTools", "Libraries"),
    (r"\bdojo\b", "Dojo", "Libraries"),
    (r"\byui\b", "YUI", "Libraries"),
    (r"\bpolyfill", "Polyfill", "Libraries"),
    (r"\bmathjax\b", "MathJax", "Libraries"),
    (r"highlight\.js", "highlight.js", "Libraries"),
    (r"three\.js", "three.js", "Libraries"),
    (r"anime\.js", "anime.js", "Libraries"),
    (r"fullcalendar", "FullCalendar", "Libraries"),
    (r"\bselect2\b", "Select2", "Libraries"),
    (r"\bdatatables\b", "DataTables", "Libraries"),
    # Known platforms that fall outside the categories above
    (r"wordpress|wp-content|wp-includes", "WordPress", "Miscellaneous"),
    (r"\bdrupal\b", "Drupal", "Miscellaneous"),
    (r"\bjoomla\b", "Joomla", "Miscellaneous"),
    (r"\bshopify\b", "Shopify", "Miscellaneous"),
    (r"wix\.com|wixsite", "Wix", "Miscellaneous"),
    (r"squarespace", "Squarespace", "Miscellaneous"),
    (r"\bmagento\b", "Magento", "Miscellaneous"),
    (r"\btypo3\b", "TYPO3", "Miscellaneous"),
    (r"prestashop", "PrestaShop", "Miscellaneous"),
    (r"opencart", "OpenCart", "Miscellaneous"),
    (r"\bhubspot\b", "HubSpot", "Miscellaneous"),
    (r"\bintercom\b", "Intercom", "Miscellaneous"),
    (r"zendesk", "Zendesk", "Miscellaneous"),
    (r"tawk\.to", "Tawk.to", "Miscellaneous"),
    (r"\boptimizely\b", "Optimizely", "Miscellaneous"),
    (r"\bvwo\b", "VWO", "Miscellaneous"),
]

# response headers that name a product directly (header prefix -> tech, category)
_HDR_PRODUCT = [
    ("cf-ray", "Cloudflare", "CDN"),
    ("cf-cache-status", "Cloudflare", "CDN"),
    ("cf-mitigated", "Cloudflare", "Security"),
    ("x-sucuri-", "Sucuri", "Security"),
    ("x-iinfo", "Imperva/Incapsula", "Security"),
    ("x-amzn-waf", "AWS WAF", "Security"),
    ("x-amz-cf-", "Amazon CloudFront", "CDN"),
    ("x-fastly", "Fastly", "CDN"),
    ("fastly-", "Fastly", "CDN"),
    ("x-akamai", "Akamai", "CDN"),
    ("x-bunnycdn", "BunnyCDN", "CDN"),
    ("x-stackpath", "StackPath", "CDN"),
    ("x-newrelic", "New Relic", "RUM"),
    ("newrelic", "New Relic", "RUM"),
    ("x-datadog", "Datadog", "RUM"),
    ("x-sentry", "Sentry", "RUM"),
]


def _tech_classify(text):
    """Map literal evidence text to (technology, category); None if no rule matches."""
    low = str(text).lower()
    for pat, name, cat in _TECH_RULES:
        if re.search(pat, low):
            return name, cat
    return None


def parse_tech(output, sess):
    """Classify *observed* web-stack evidence into technology categories.

    Sources (section markers from the recon_tech template): whatweb plugins,
    response headers, HTML asset/meta tags, nuclei technology hits. A finding
    is emitted only when the evidence literally contains the signature — an
    unknown whatweb/nuclei technology is reported verbatim under Miscellaneous,
    unknown headers/assets are skipped entirely (never guessed)."""
    findings, seen = [], set()
    base = _base_url(sess) if isinstance(sess, dict) else ''
    cmd = f"curl -skIL {base}" if base else ''

    def add(tech, cat, evidence, path='/'):
        key = (str(tech).lower(), cat)
        if key in seen or len(findings) >= 40:
            return
        seen.add(key)
        findings.append({"type": "tech_fingerprint", "severity": "info",
                         "tech": str(tech), "category": cat,
                         "detail": f"{tech} — {cat} (evidence: {evidence})",
                         "path": path or '/', "command": cmd})

    ansi = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
    section = None
    for raw in output.splitlines():
        line = ansi.sub('', raw).strip()
        if not line:
            continue
        if len(line) > 2 and line.startswith('=') and line.endswith('=') and line.strip('='):
            section = line.strip('=').strip()
            continue
        # whatweb: '<url> [status] Plugin[Value], Plugin, ...'
        m = re.match(r'^(https?://\S+)\s+\[.*?\](.*)$', line)
        if m:
            url, rest = m.group(1), m.group(2)
            path = re.sub(r'https?://[^/]+', '', url) or '/'
            for name, ver in re.findall(
                    r'([A-Za-z0-9][A-Za-z0-9+_.-]*)\[([^\]\[]{0,30})\]', rest):
                if name.lower() in TECH_NON_TECH:
                    continue
                evidence = f"{name}[{ver}]" if ver else name
                cls = _tech_classify(f"{name} {ver}") or (name, "Miscellaneous")
                add(cls[0], cls[1], f"whatweb: {evidence}", path)
            # bare plugins carry no value: 'JQuery', 'HTML5', 'Script'
            for seg in (s.strip() for s in rest.split(',')):
                if '[' in seg or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', seg):
                    continue
                if seg.lower() in TECH_NON_TECH:
                    continue
                cls = _tech_classify(seg) or (seg, "Miscellaneous")
                add(cls[0], cls[1], f"whatweb: {seg}", path)
            continue
        # nuclei: '[tech-id] [http] [info] url' (silent mode; older builds omit [type] [severity])
        n = re.match(r'^\[([A-Za-z0-9._:/ -]+)\]', line)
        if n and re.search(r'https?://', line):
            tech_id = n.group(1).strip()
            if tech_id.lower() in ('info', 'http'):
                continue
            cls = _tech_classify(tech_id)
            if not cls:
                # template id we cannot map to a named technology — never
                # report a raw template id as if it were a product
                continue
            url_m = re.search(r'https?://\S+', line)
            path = re.sub(r'https?://[^/]+', '', url_m.group(0)) or '/'
            add(cls[0], cls[1], f"nuclei: [{tech_id}]", path)
            continue
        if section == 'HEADERS':
            h = re.match(r'^([A-Za-z0-9-]+)\s*:\s*(.+)$', line)
            if not h:
                continue
            hname, hval = h.group(1).lower(), h.group(2).strip()
            if hname == 'server':
                cls = _tech_classify(hval) or (hval.split()[0], "Web Servers")
                add(cls[0], cls[1], f"header: {line}")
            elif hname in ('x-powered-by', 'x-generator', 'x-aspnet-version',
                           'x-aspnetmvc-version'):
                cls = _tech_classify(hval) or (hval, "Miscellaneous")
                add(cls[0], cls[1], f"header: {line}")
            elif hname == 'via':
                cls = _tech_classify(hval)      # 'via: 1.1 cloudflare' etc.
                if cls:
                    add(cls[0], cls[1], f"header: {line}")
            else:
                for prefix, tech, cat in _HDR_PRODUCT:
                    if hname.startswith(prefix):
                        add(tech, cat, f"header: {line}")
                        break
            continue
        if section == 'BODY':
            gen = re.search(r'content=["\']([^"\']+)["\'][^>]*name=["\']?generator', line, re.I)
            if not gen:
                gen = re.search(r'name=["\']?generator["\']?[^>]*content=["\']([^"\']+)["\']', line, re.I)
            if gen:
                val = gen.group(1).strip()
                cls = _tech_classify(val) or (val, "Miscellaneous")
                add(cls[0], cls[1], f"meta generator: {val}")
                continue
            if re.search(r'<(script|link|meta|img)\b', line, re.I):
                cls = _tech_classify(line)       # asset tag: only report a known signature
                if cls:
                    add(cls[0], cls[1], f"html: {line[:120]}")
            else:
                cls = _tech_classify(line)       # inline marker (__NEXT_DATA__, wp-content, ...)
                if cls:
                    add(cls[0], cls[1], f"html: {line[:120]}")
    return findings

PROVIDER_PATTERNS = [
    (r'cf-ray|^server:.*cloudflare', 'Cloudflare (CDN/WAF)'),
    (r'x-amz-|x-amz-cf-|x-amz-apigw', 'Amazon Web Services (S3/CloudFront/API Gateway)'),
    (r'x-azure-|azurewebsites', 'Microsoft Azure'),
    (r'x-gcs-|x-goog-|google.*storage', 'Google Cloud Platform'),
    (r'x-sucuri', 'Sucuri (CDN/WAF)'),
]

def parse_cloud(output, sess):
    """CDN/cloud provider fingerprinting and well-known endpoint baseline. All
    informational: a provider header or a reachable path is not a vuln."""
    findings = []
    prov = set()
    for line in output.splitlines():
        for pat, label in PROVIDER_PATTERNS:
            if re.search(pat, line, re.I):
                m = re.match(r'^([A-Za-z0-9-]+):\s*(.*)', line.strip())
                header = f" ({m.group(1)}: {m.group(2)[:40]})" if m else ''
                key = label
                if key not in prov:
                    prov.add(key)
                    findings.append({"type": "cloud_provider", "severity": "info",
                        "detail": f"Cloud/CDN provider detected: {label}{header}",
                        "path": "/", "command": "curl -skI http://<target>"})
                break
        w = re.match(r'^(\.well-known/[^ ]+|\S+\.txt)\s+->\s*(\d{3})', line.strip())
        if w and w.group(2) == '200':
            findings.append({"type": "cloud_endpoint", "severity": "info",
                "detail": f"Baseline probe {w.group(1)} returned HTTP 200",
                "path": f"/{w.group(1)}", "command": f"curl -sk -o /dev/null -w '%{{http_code}}' http://<target>/{w.group(1)}"})
    return findings

def parse_ad_enum(output, sess):
    """Anonymous LDAP bind / naming-context exposure is a recon baseline —
    reported as informational context, never as an assumed takeover."""
    findings = []
    text = output
    if re.search(r'[Nn]amingContexts[:\s]*(DC=|dn:)', text):
        findings.append({"type": "ad_enum", "severity": "info",
            "detail": "LDAP anonymous base query returned naming contexts — directory data visible unauthenticated",
            "path": "ldap://<target>", "command": "ldapsearch -x -H ldap://<target> -s base namingContexts"})
    if re.search(r'result:\s*0\s+Success', text, re.I) and re.search(r'DC=', text, re.I):
        findings.append({"type": "ad_enum", "severity": "info",
            "detail": "Active Directory naming context responded to anonymous LDAP probe",
            "path": "ldap://<target>", "command": "ldapsearch -x -H ldap://<target> -s base dn"})
    return findings

def parse_evidence(output, sess):
    return []

def parse_assess(output, sess):
    return []

def parse_xss_probe(output):
    findings = []
    for line in output.splitlines():
        # XSS reflection
        if re.search(r'onerror|alert\(|<script', line, re.I) and re.search(r'\d{3}', line):
            param_m = re.search(r'(\w+)\s+XSS\s+(\d+):\s*(\S+)', line)
            if param_m:
                param, code, refl = param_m.group(1), param_m.group(2), param_m.group(3)
                if refl and refl != 'None':
                    findings.append({"type":"xss_reflected","severity":"high",
                        "detail":f"XSS payload reflected via parameter '{param}' (HTTP {code}): {refl}",
                        "path":f"/?{param}=<payload>",
                        "command":f"curl -sk 'http://<target>/?{param}=<script>alert(1)</script>'"})
        # Open redirect
        if re.search(r'location.*evil\.com|location.*https?://', line, re.I):
            param_m = re.search(r'(\w+):\s*(Location.*evil)', line, re.I)
            if param_m:
                findings.append({"type":"open_redirect","severity":"medium",
                    "detail":f"Open redirect via '{param_m.group(1)}' parameter: {param_m.group(2)[:80]}",
                    "path":f"/?{param_m.group(1)}=https://evil.com",
                    "command":f"curl -skI 'http://<target>/?{param_m.group(1)}=https://evil.com'"})
        # XXE
        if re.search(r'root:.*:/bin/|xxe.*success|SYSTEM.*file://', line, re.I):
            findings.append({"type":"xxe_injection","severity":"critical",
                "detail":"XXE injection confirmed — /etc/passwd content returned",
                "path":"/ (XML POST body — xxe entity in DOCTYPE)",
                "command":"curl -X POST -d @xxe.xml http://<target>/ (see remediation for payload)"})
    return findings

def parse_cms_scan(output):
    findings = []
    # WordPress: the login page must actually render WP fingerprints — a bare
    # 200 on /wp-login.php is not proof a CMS is installed.
    wpm = re.search(r'wp-login:(\d{3})\|(.*)', output)
    if wpm and wpm.group(1) not in REDIRECT_CODES and \
       re.search(r'name="log"|wp-submit|wordpress|wp-content', wpm.group(2), re.I):
        findings.append({"type": "cms_wordpress", "severity": "medium",
            "detail": "WordPress installation detected",
            "path": "/wp-login.php",
            "command": "wpscan --url http://<target> --enumerate vp,u,m"})
    # WordPress user enumeration
    if re.search(r'"id":\s*\d+.*"name":|wp/v2/users.*200', output, re.I):
        findings.append({"type": "wp_user_enum", "severity": "high",
            "detail": "WordPress REST API exposes user enumeration at /wp-json/wp/v2/users",
            "path": "/wp-json/wp/v2/users",
            "command": "curl -sk http://<target>/wp-json/wp/v2/users"})
    # WPScan findings
    for line in output.splitlines():
        if re.search(r'\[!\]|\[i\].*found|vulnerability|outdated|CVE-', line, re.I):
            sev = ('critical' if 'critical' in line.lower() else
                   'high' if any(x in line.lower() for x in ['vulnerability','exploit','rce','cve-','outdated plugin']) else 'medium')
            findings.append({"type":"cms_vulnerability","severity":sev,
                "detail":line.strip()[:200],"path":"WordPress",
                "command":"wpscan --url http://<target> --enumerate vp,u --plugins-detection aggressive"})
    # Drupal: CHANGELOG version line or the login form fingerprint (body, not
    # status) — a 200 on a redirect-to-HTTPS catch-all is no detection.
    drupal_evidence = re.search(r'Drupal\s+\d+\.\d+|SA-CORE-\d{4}-\d{4}', output, re.I)
    dm = re.search(r'drupal_login:(\d{3})\|(.*)', output)
    if drupal_evidence or (dm and dm.group(1) not in REDIRECT_CODES and
            re.search(r'user-login-form|form_id.*user_login|drupal', dm.group(2), re.I)):
        findings.append({"type": "cms_drupal", "severity": "medium",
            "detail": "Drupal CMS detected — check for Drupalgeddon (SA-CORE-2018-002)",
            "path": "/CHANGELOG.txt or /user/login",
            "command": "droopescan scan drupal -u http://<target>"})
    # Joomla: admin panel requires its form/module fingerprint in the body.
    jm = re.search(r'joomla_admin:(\d{3})\|(.*)', output)
    if jm and jm.group(1) not in REDIRECT_CODES and \
       re.search(r'mod-login|com_login|joomla|user\s*name.*password', jm.group(2), re.I):
        findings.append({"type": "cms_joomla", "severity": "medium",
            "detail": "Joomla CMS admin panel detected",
            "path": "/administrator/",
            "command": "joomscan --url http://<target>"})
    return findings

def parse_cred_harvest(output):
    findings = []
    secret_paths = {
        '.env': ('env_exposed', 'critical', '.env file exposed — credentials, API keys at risk'),
        '.env.local': ('env_exposed', 'critical', '.env.local exposed'),
        '.env.backup': ('env_exposed', 'critical', '.env.backup exposed — old credentials'),
        'wp-config.php': ('wp_config', 'critical', 'wp-config.php accessible — DB credentials exposed'),
        'config.php': ('config_exposed', 'critical', 'config.php accessible'),
        'config/database.yml': ('db_config', 'critical', 'database.yml accessible — Rails DB credentials'),
        'application.properties': ('app_props', 'high', 'application.properties exposed — Spring Boot config'),
        'secrets.yaml': ('secrets_exposed', 'critical', 'secrets.yaml exposed'),
        '.aws/credentials': ('aws_creds', 'critical', 'AWS credentials file exposed'),
        'id_rsa': ('ssh_key', 'critical', 'SSH private key exposed'),
        '.ssh/id_rsa': ('ssh_key', 'critical', 'SSH private key at .ssh/id_rsa exposed'),
        'backup.sql': ('db_backup', 'critical', 'SQL database backup exposed'),
        'database.sql': ('db_backup', 'critical', 'database.sql exposed'),
        '.git/COMMIT_EDITMSG': ('git_exposed', 'high', 'Git repository exposed — source code at risk'),
        '.git/config': ('git_config', 'high', 'Git config exposed — may contain remote credentials'),
    }
    # Content evidence per sensitive file: an HTTP 200 alone proves nothing
    # (catch-all routers return 200 for any path). The probe returns the body
    # (following redirects), so only the actual artifact — real .env syntax, a
    # PEM private key, an ini-section git config — becomes a finding.
    evidence_map = {
        '.env': r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}',
        '.env.local': r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}',
        '.env.backup': r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}',
        'wp-config.php': r'define\s*\(|DB_NAME|DB_PASSWORD|DB_HOST|table_prefix',
        'config.php': r'["\'](?:db|DB_|host|user|password|secret|app_key|key)["\']\s*=>',
        'config/database.yml': r'(?:username|password|database|adapter)\s*:\s*\S',
        'application.properties': r'(?:spring|jdbc|password|secret|api[_-]?key|access[_-]?key)\s*[=:]',
        'secrets.yaml': r'(?:secret|api[_-]?key|token|password)\s*:\s*\S',
        '.aws/credentials': r'aws_access_key_id|aws_secret_access_key|\[(?:default|profile)\b',
        'id_rsa': r'PRIVATE KEY-----',
        '.ssh/id_rsa': r'PRIVATE KEY-----',
        'backup.sql': r'CREATE TABLE|INSERT INTO|DROP TABLE|CREATE DATABASE',
        'database.sql': r'CREATE TABLE|INSERT INTO|DROP TABLE|CREATE DATABASE',
        '.git/config': r'\[(?:core|remote|branch|user)\]|repositoryformatversion',
    }
    secret_keys_sorted = sorted(secret_paths, key=len, reverse=True)
    for line in output.splitlines():
        m = re.search(r'([^:|]+):(\d{3})\|(.*)', line)
        if not m:
            continue
        path_key, code, body = m.group(1).strip(), m.group(2), m.group(3)
        if code in REDIRECT_CODES or code not in ('200', '201', '204'):
            continue
        for key in secret_keys_sorted:
            if key in path_key:
                rex = evidence_map.get(key)
                if rex and not re.search(rex, body, re.I):
                    break
                ftype, sev, msg = secret_paths[key]
                findings.append({"type": ftype, "severity": sev,
                    "detail": f"{msg} (HTTP {code})",
                    "path": f"/{path_key}",
                    "command": f"curl -skL http://<target>/{path_key}"})
                break
    # Git content exposure (evidence-based: real ini sections / remote URLs)
    if re.search(r'remote.*url.*github|remote.*url.*gitlab|remote.*url.*bitbucket', output, re.I):
        findings.append({"type":"git_remote_exposed","severity":"high",
            "detail":"Git remote URL leaked in .git/config — repository URL and potential credentials disclosed",
            "path":"/.git/config",
            "command":"curl -sk http://<target>/.git/config"})
    if re.search(r'\[(core|remote|branch)\]', output, re.I):
        findings.append({"type":"git_config_content","severity":"high",
            "detail":"Git config content accessible — project metadata and remote URLs visible",
            "path":"/.git/config",
            "command":"git clone http://<target>/.git /tmp/dumped_repo"})
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# STANDARDS MAPPING — OWASP Top 10 (2021) + CWE per finding type, and MITRE
# ATT&CK for authentication/session findings.
#
# Only *vulnerability* finding types carry a category. Informational findings
# (open ports, fingerprints, paths, discovery) are deliberately unclassified —
# assigning them an OWASP vulnerability category would be a fabricated claim.
# Types whose class depends on the concrete signature (nuclei/msf/signature
# matches, banner/timing anomalies) are marked "indeterminate" rather than
# guessed. A unit test asserts every type the codebase can emit is covered by
# exactly one bucket, so nothing silently falls through unmapped.
# ─────────────────────────────────────────────────────────────────────────────
STANDARDS = {
    # A01 — Broken Access Control
    "bola_idor":            ("A01:2021 - Broken Access Control", "CWE-639"),
    "broken_function_auth": ("A01:2021 - Broken Access Control", "CWE-285"),
    "mass_assignment":      ("A01:2021 - Broken Access Control", "CWE-915"),
    "path_traversal":       ("A01:2021 - Broken Access Control", "CWE-22"),
    "open_redirect":        ("A01:2021 - Broken Access Control", "CWE-601"),
    "admin_panel":          ("A01:2021 - Broken Access Control", "CWE-284"),
    "git_exposed":          ("A01:2021 - Broken Access Control", "CWE-538"),
    "git_config_content":   ("A01:2021 - Broken Access Control", "CWE-538"),
    "git_remote_exposed":   ("A01:2021 - Broken Access Control", "CWE-538"),
    "env_exposed":          ("A01:2021 - Broken Access Control", "CWE-200"),
    "sensitive_data_exposure": ("A01:2021 - Broken Access Control", "CWE-200"),
    "redis_data_exposure":  ("A01:2021 - Broken Access Control", "CWE-200"),
    "db_user_disclosed":    ("A01:2021 - Broken Access Control", "CWE-200"),
    "db_exposed":           ("A01:2021 - Broken Access Control", "CWE-200"),
    "db_excessive_priv":    ("A01:2021 - Broken Access Control", "CWE-269"),
    "db_dba_privilege":     ("A01:2021 - Broken Access Control", "CWE-269"),
    "smb_share":            ("A01:2021 - Broken Access Control", "CWE-200"),
    # A02 — Cryptographic Failures
    "weak_tls":             ("A02:2021 - Cryptographic Failures", "CWE-327"),
    "weak_cipher":          ("A02:2021 - Cryptographic Failures", "CWE-327"),
    "self_signed_cert":     ("A02:2021 - Cryptographic Failures", "CWE-295"),
    "expired_cert":         ("A02:2021 - Cryptographic Failures", "CWE-298"),
    "db_unencrypted_conn":  ("A02:2021 - Cryptographic Failures", "CWE-319"),
    # A03 — Injection
    "sql_injection":        ("A03:2021 - Injection", "CWE-89"),
    "blind_sqli":           ("A03:2021 - Injection", "CWE-89"),
    "sqli_technique":       ("A03:2021 - Injection", "CWE-89"),
    "second_order_sqli":    ("A03:2021 - Injection", "CWE-89"),
    "sqli_file_access":     ("A03:2021 - Injection", "CWE-89"),
    "sqli_os_rce":          ("A03:2021 - Injection", "CWE-78"),
    "nosql_injection":      ("A03:2021 - Injection", "CWE-943"),
    "xss_reflected":        ("A03:2021 - Injection", "CWE-79"),
    "host_header_injection": ("A03:2021 - Injection", "CWE-644"),
    # A04 — Insecure Design
    "missing_rate_limit":   ("A04:2021 - Insecure Design", "CWE-770"),
    "verbose_error":        ("A04:2021 - Insecure Design", "CWE-209"),
    "verbose_db_error":     ("A04:2021 - Insecure Design", "CWE-209"),
    # A05 — Security Misconfiguration
    "api_cors_wildcard":    ("A05:2021 - Security Misconfiguration", "CWE-942"),
    "missing_headers":      ("A05:2021 - Security Misconfiguration", "CWE-693"),
    "trace_method":         ("A05:2021 - Security Misconfiguration", "CWE-693"),
    "cookie_flags":         ("A05:2021 - Security Misconfiguration", "CWE-1004"),
    "header_anomaly":       ("A05:2021 - Security Misconfiguration", "CWE-693"),
    "verbose_banner":       ("A05:2021 - Security Misconfiguration", "CWE-200"),
    "xxe_injection":        ("A05:2021 - Security Misconfiguration", "CWE-611"),
    "graphql_introspection": ("A05:2021 - Security Misconfiguration", "CWE-200"),
    # A06 — Vulnerable and Outdated Components
    "cve":                  ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "version_eol":          ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "version_outdated":     ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "ssh_outdated":         ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "legacy_os":            ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "cms_vulnerability":    ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "exploit_available":    ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "protocol_vuln":        ("A06:2021 - Vulnerable and Outdated Components", "CWE-1104"),
    "heartbleed":           ("A06:2021 - Vulnerable and Outdated Components", "CWE-125"),
    # A07 — Identification and Authentication Failures
    "broken_auth":          ("A07:2021 - Identification and Authentication Failures", "CWE-287"),
    "null_session":         ("A07:2021 - Identification and Authentication Failures", "CWE-287"),
    "unauth_endpoint":      ("A07:2021 - Identification and Authentication Failures", "CWE-306"),
    "api_key_exposure":     ("A07:2021 - Identification and Authentication Failures", "CWE-798"),
    "js_secret_leak":       ("A07:2021 - Identification and Authentication Failures", "CWE-798"),
    "default_cred":         ("A07:2021 - Identification and Authentication Failures", "CWE-1392"),
    "default_cred_http":    ("A07:2021 - Identification and Authentication Failures", "CWE-1392"),
    "db_default_cred":      ("A07:2021 - Identification and Authentication Failures", "CWE-1392"),
    "snmp_public":          ("A07:2021 - Identification and Authentication Failures", "CWE-1392"),
    "redis_no_auth":        ("A07:2021 - Identification and Authentication Failures", "CWE-306"),
    "db_unauth_access":     ("A07:2021 - Identification and Authentication Failures", "CWE-306"),
    "ftp_anon":             ("A07:2021 - Identification and Authentication Failures", "CWE-287"),
    "auth_timing_oracle":   ("A07:2021 - Identification and Authentication Failures", "CWE-208"),
    "wp_user_enum":         ("A07:2021 - Identification and Authentication Failures", "CWE-204"),
    "breach_exposure":      ("A07:2021 - Identification and Authentication Failures", "CWE-522"),
    # A09 — Security Logging and Monitoring Failures
    "db_no_audit_log":      ("A09:2021 - Security Logging and Monitoring Failures", "CWE-778"),
    # A10 — Server-Side Request Forgery
    "ssrf":                 ("A10:2021 - Server-Side Request Forgery", "CWE-918"),
    "ssrf_lfi":             ("A10:2021 - Server-Side Request Forgery", "CWE-918"),
    # ZDAY / misc
    "s3_public_list":       ("A01:2021 - Broken Access Control", "CWE-732"),
    # Registration / signup
    "signup_enum":          ("A07:2021 - Identification and Authentication Failures", "CWE-204"),
    "signup_verification_bypass": ("A07:2021 - Identification and Authentication Failures", "CWE-287"),
    "signup_duplicate":     ("A04:2021 - Insecure Design", "CWE-362"),
    "signup_password_policy": ("A07:2021 - Identification and Authentication Failures", "CWE-521"),
    "signup_captcha":       ("A07:2021 - Identification and Authentication Failures", "CWE-804"),
    "signup_mass_assign":   ("A01:2021 - Broken Access Control", "CWE-915"),
    "signup_rate_limit":    ("A04:2021 - Insecure Design", "CWE-770"),
    # Authentication / login flow
    "login_enum":           ("A07:2021 - Identification and Authentication Failures", "CWE-204"),
    "login_bruteforce":     ("A07:2021 - Identification and Authentication Failures", "CWE-307"),
    "password_reset_flaw":  ("A07:2021 - Identification and Authentication Failures", "CWE-640"),
    "mfa_bypass":           ("A07:2021 - Identification and Authentication Failures", "CWE-287"),
    "remember_me":          ("A07:2021 - Identification and Authentication Failures", "CWE-539"),
    "oauth_misconfig":      ("A07:2021 - Identification and Authentication Failures", "CWE-346"),
    "logout_invalidation":  ("A07:2021 - Identification and Authentication Failures", "CWE-613"),
    "concurrent_session":   ("A07:2021 - Identification and Authentication Failures", "CWE-384"),
    # Session management
    "session_entropy":      ("A07:2021 - Identification and Authentication Failures", "CWE-330"),
    "session_fixation":     ("A07:2021 - Identification and Authentication Failures", "CWE-384"),
    "jwt_weakness":         ("A07:2021 - Identification and Authentication Failures", "CWE-347"),
    "session_timeout":      ("A07:2021 - Identification and Authentication Failures", "CWE-613"),
    "csrf_missing":         ("A01:2021 - Broken Access Control", "CWE-352"),
    # Authorization
    "horiz_privesc":        ("A01:2021 - Broken Access Control", "CWE-639"),
    "vert_privesc":         ("A01:2021 - Broken Access Control", "CWE-269"),
    "function_level_auth":  ("A01:2021 - Broken Access Control", "CWE-285"),
    # Input validation
    "ssti":                 ("A03:2021 - Injection", "CWE-1336"),
    "file_upload":          ("A04:2021 - Insecure Design", "CWE-434"),
    "deserialization":      ("A08:2021 - Software and Data Integrity Failures", "CWE-502"),
    "request_smuggling":    ("A04:2021 - Insecure Design", "CWE-444"),
    # Business logic
    "price_manipulation":   ("A04:2021 - Insecure Design", "CWE-840"),
    "workflow_bypass":      ("A04:2021 - Insecure Design", "CWE-841"),
    "ato_chain":            ("A07:2021 - Identification and Authentication Failures", "CWE-287"),
    "multi_tenancy":        ("A01:2021 - Broken Access Control", "CWE-639"),
    # API-specific
    "graphql_abuse":        ("A04:2021 - Insecure Design", "CWE-770"),
    "graphql_field_auth":   ("A01:2021 - Broken Access Control", "CWE-285"),
    "mobile_api_reuse":     ("A01:2021 - Broken Access Control", "CWE-284"),
}

# classification depends on the concrete match — never guessed
STANDARDS_INDETERMINATE = {
    "signature_match", "nuclei_finding", "msf_finding",
    "banner_anomaly", "timing_anomaly",
}

# recon / discovery / telemetry — not a vulnerability class by itself
INFORMATIONAL_TYPES = {
    "open_port", "os_detect", "tech_fingerprint", "waf_detected", "subdomain",
    "email_discovered", "ad_enum", "db_fingerprint", "db_enumerated",
    "web_path", "web_finding", "api_endpoint", "js_endpoint",
    "sourcemap_exposed", "cloud_provider", "cloud_endpoint", "no_breach",
    "evidence_capture", "not_tested", "info", "generic", "cmd", "stdout",
    "meta", "error", "cms_wordpress", "cms_drupal", "cms_joomla",
}

# MITRE ATT&CK techniques for authentication / session / credential findings.
ATTACK_BY_TYPE = {
    "default_cred":        "T1078.001",
    "default_cred_http":   "T1078.001",
    "db_default_cred":     "T1078.001",
    "snmp_public":         "T1078.001",
    "broken_auth":         "T1078",
    "null_session":        "T1078",
    "unauth_endpoint":     "T1078",
    "api_key_exposure":    "T1552.001",
    "js_secret_leak":      "T1552.001",
    "env_exposed":         "T1552.001",
    "breach_exposure":     "T1589.001",
    "cookie_flags":        "T1539",
    "session_entropy":     "T1539",
    "remember_me":         "T1539",
    "session_fixation":    "T1550",
    "wp_user_enum":        "T1087.002",
    "auth_timing_oracle":  "T1087.002",
    "login_enum":          "T1087.002",
    "login_bruteforce":    "T1110",
    "signup_rate_limit":   "T1110",
    "jwt_weakness":        "T1550.001",
    "oauth_misconfig":     "T1550",
    "password_reset_flaw": "T1550",
}

# ATO chain contributors: attacker action → defender detection guidance.
ATO_DETECTIONS = {
    "bola_idor":       ("Enumerate object identifiers to read/write other users' records",
                        "Per-object authorization failures in app logs (403/401 spikes per user id); alert when one principal touches many distinct object ids"),
    "mass_assignment": ("Inject role/isAdmin/verified fields into profile update and re-auth",
                        "Audit records where privilege attributes change via self-service endpoints; diff role fields against approval workflow"),
    "broken_auth":     ("Forge/alter tokens (alg=none, null token, missing authz check) to assume another identity",
                        "Auth middleware denials, token parse failures, impossible-travel between principal and token claims"),
    "null_session":    ("Present null/empty session to bypass authentication on protected routes",
                        "Requests to protected routes with empty/invalid session ids; 401/200 anomaly by route"),
    "password_reset_flaw":("Guess/reuse password-reset tokens then take over the account",
                        "Reset-token reuse, wrong-token attempts, resets initiated for high-value accounts from new ASNs"),    "api_key_exposure":("Reuse a leaked API key/token to authenticate as the victim",
                        "Use of revoked/unknown key ids; key used from new IP/user-agent; key enumeration attempts"),
    "js_secret_leak":  ("Extract embedded secrets from JS bundles and call the backend as the app",
                        "Static-scan noise aside: track calls using client-embedded key material; rotate on exposure"),
    "env_exposed":     ("Read .env/config for DB/API credentials then authenticate directly",
                        "Direct DB/admin access from web tier IPs; config file requests in access logs"),
    "session_fixation":("Fixate a session id pre-auth, victim logs in, attacker reuses the id",
                        "Session id observed before and after authentication for the same client"),
    "login_bruteforce":("Password-spray a valid username list until one succeeds",
                        "Many failed logins per account/IP, distributed source spray, success-after-many-failures"),
    "login_enum":      ("Enumerate valid usernames via error/timing/registration/reset differences",
                        "User-not-found response skew, enumeration patterns across reset/registration endpoints"),
}

ACCOUNT_FIELDS = ("role", "username", "password", "cookie", "token")
MAX_ACCOUNTS = 8


def _norm_accounts(raw):
    """Sanitize operator-supplied role accounts. Kept in memory only — never
    written to disk, never included in /status or the report."""
    out = []
    if not isinstance(raw, list):
        return out
    for a in raw[:MAX_ACCOUNTS]:
        if not isinstance(a, dict):
            continue
        rec = {}
        for k in ACCOUNT_FIELDS:
            v = a.get(k)
            if isinstance(v, str) and v.strip():
                rec[k] = v.strip()
        if not (rec.get("role") or rec.get("username")):
            continue
        rec["role"] = (rec.get("role") or "user").lower()
        out.append(rec)
    return out


def _has_creds_for(sess, roles=None):
    """True when the session has at least one account for the requested role(s)."""
    accts = sess.get("accounts") or []
    if not accts:
        return False
    if not roles:
        return True
    have = {(a.get("role") or "").lower() for a in accts}
    return bool(have & {r.lower() for r in roles})


def classify_standards(f):
    """Attach OWASP 2021 + CWE (+ ATT&CK where applicable) to a finding.
    Vulnerability types get a definite class; informational and signature-
    dependent types are marked honestly instead of being given a fake class."""
    t = f.get("type")
    if t in STANDARDS:
        ow, cw = STANDARDS[t]
        f["owasp"], f["cwe"] = ow, cw
        if t in ATTACK_BY_TYPE:
            f["attack"] = ATTACK_BY_TYPE[t]
        if t in ATO_DETECTIONS:
            action, detect = ATO_DETECTIONS[t]
            f["ato"] = {"action": action, "detection": detect}
    elif t in STANDARDS_INDETERMINATE:
        f["owasp"], f["cwe"] = None, None
        f["standards_note"] = "classification depends on the matched signature — verify per evidence"
    else:
        # informational (or not yet classified) — no vulnerability claim
        f["owasp"], f["cwe"] = None, None
        if t in INFORMATIONAL_TYPES or f.get("severity") == "info":
            f["standards_note"] = "informational — no vulnerability classification"
        else:
            f["standards_note"] = "unclassified"
    return f


def _normalize_findings(findings, sess, sub_id):
    """Real-target normalization: findings must reference the user's actual
    target and the command that actually ran — never <target> placeholders,
    other unresolved placeholders, or empty/junk commands.
    Also drops any negated-result finding ("not vulnerable" style) so it can
    never reach /status, SSE, the PDF or the findings popups."""
    findings[:] = [f for f in findings
                   if not any(isinstance(f.get(k), str) and _NEGATED_RESULT.search(f[k])
                              for k in ('detail', 'line', 'title', 'cve'))]
    real_target = sess.get('target', '')
    real_cmd = sess['commands'].get(sub_id, '')
    for f in findings:
        for key in ('command', 'detail', 'path'):
            val = f.get(key)
            if isinstance(val, str) and '<target>' in val:
                f[key] = val.replace('<target>', real_target)
        cmd = str(f.get('command') or '').strip()
        if not cmd or cmd.lower() in ('manual review', 'msfconsole -q') \
                or re.search(r'<[^<>\n]{1,60}>', cmd):
            f['command'] = real_cmd
        pth = f.get('path')
        if isinstance(pth, str) and re.search(r'<[^<>\n]{1,60}>', pth):
            f['path'] = '-'
        if isinstance(f.get('role'), str):
            f['role'] = f['role'].lower()[:32]
        else:
            f.pop('role', None)
        score_finding(f)        # CVSS v3.1 vector + base score (choke point)
        _triage_finding(f)      # automated false-positive verdict (choke point)
        classify_standards(f)   # OWASP 2021 / CWE / ATT&CK (choke point)
    _append_triage_log(sess, sub_id, findings)
    return findings


def dispatch_parser(parse_type, output, sess):
    parsers = {
        "nmap": parse_nmap, "vulners": parse_vulners,
        "searchsploit": parse_searchsploit, "nikto": parse_nikto,
        "ssl": parse_ssl, "headers": parse_headers, "smb": parse_smb,
        "snmp": parse_snmp, "dirb": parse_dirb,
        "banner_anomaly": parse_banner_anomaly,
        "http_anomaly": parse_http_anomaly, "timing": parse_timing,
        "auth_probe": parse_auth_probe, "nse_deep": parse_nse_deep,
        "hydra": parse_hydra, "msf": parse_msf, "generic": parse_generic,
        "waf": parse_waf,
        # New parsers
        "sqlmap": parse_sqlmap,
        "nuclei": parse_nuclei,
        "xss_probe": parse_xss_probe,
        "cms_scan": parse_cms_scan,
        "cred_harvest": parse_cred_harvest,
        "subdomains": parse_subdomains,
        "urls": parse_urls,
        "breach_osint": parse_breach_osint,
        "js_leak": parse_js_leak,
        "version_cve": parse_version_cve,
        "tech": parse_tech,
        "cloud": parse_cloud,
        "ad_enum": parse_ad_enum,
        "evidence": parse_evidence,
        "assess": parse_assess,
        # API
        "api_discovery": parse_api_discovery,
        "api_bola": parse_api_bola,
        "api_auth": parse_api_auth,
        "api_injection": parse_api_injection,
        "api_ssrf": parse_api_ssrf,
        "api_mass_assign": parse_api_mass_assign,
        "api_misc": parse_api_misc,
        # Database
        "db_discovery": parse_db_discovery,
        "db_unauth": parse_db_unauth,
        "db_default_creds": parse_db_default_creds,
        "db_sqli": parse_db_sqli,
        "db_nosql": parse_db_nosql,
        "db_privesc": parse_db_privesc,
    }
    if parse_type == "version_gap":
        return parse_version_gap(output, sess)
    fn = parsers.get(parse_type, parse_generic)
    try:
        arity = len(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        arity = 1
    return fn(output, sess) if arity >= 2 else fn(output)


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
LONG_SUBSTAGE_TIMEOUT = {
    "recon_ports": 1500,
    "vuln_nuclei": 1800,
    "vuln_web_dirs": 1200,
    "deep_cms_scan": 1200,
    "deep_xss_probe": 1200,
    "db_sqlmap": 1800,
    "db_second_order": 1200,
    "ep_hydra": 1800,
    "ep_msf_check": 1200,
    "ep_sqli_verify": 2400,
    "recon_subdomains": 1200,
    "recon_urls": 600,
    "recon_osint_passive": 300,
    "recon_breach_osint": 900,
    "recon_js_leak": 480,
    "recon_version_cve": 900,
    "recon_tech": 400,
    "recon_nuclei": 1800,
    "recon_content": 420,
    "recon_ad_enum": 300,
    "recon_cloud": 300,
    "vuln_evidence": 900,
    "vuln_assess": 60,
}

def execute_substage(sid, sub_id):
    """Safety net: a substage must ALWAYS reach 'completed' (or the chain stalls forever)."""
    try:
        _execute_substage(sid, sub_id)
    except Exception as e:
        print(f"[execute_substage] {sub_id} crashed: {e!r}", flush=True)
        sess = sessions.get(sid)
        if not sess:
            return
        push(sid, "output", {"substage": sub_id, "line": f"[ERROR: substage crashed: {e}]", "type": "error"})
        _complete_substage(sid, sub_id, [], rc=-1)


def _run_assessment(sid, sub_id, sub):
    """vuln_assess — in-process CVSS scoring + false-positive triage summary.
    Reads the session's accumulated findings, recomputes CVSS scores and triage
    verdicts (already attached at the choke point), and writes an assessment log
    the analyst can audit. Emits no vulnerability findings itself."""
    sess = sessions.get(sid)
    lines = []
    all_f = []
    for sub_f in list(sess.get('findings', {}).values()):
        all_f.extend(sub_f)
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_f.sort(key=lambda f: (sev_order.get(f.get('severity'), 9), str(f.get('type'))))
    lines.append(f"CVSS SCORING & FALSE-POSITIVE TRIAGE — {len(all_f)} finding(s) across all substages")
    lines.append(f"{'':=^92}")
    confirmed = toolconf = review = info = 0
    for f in all_f:
        sev = f.get('severity', 'info')
        typ = f.get('type', '')
        v = f.get('triage', {}).get('verdict', 'needs_review')
        cv = f.get('cvss', {})
        if v == 'confirmed': confirmed += 1
        elif v == 'tool-confirmed': toolconf += 1
        elif v == 'info': info += 1
        else: review += 1
        band = cv.get('severity_band', '')
        mismatch = '  <-- BAND MISMATCH (review)' if cv.get('band_mismatch') else ''
        lines.append(f"[{sev.upper():<8}] {typ:<26} cvss={cv.get('base_score','-')} ({band})"
                     f" verdict={v}{mismatch} | {f.get('detail','')[:90]}")
        if cv.get('vector'):
            lines.append(f"{'':>13}vector: {cv['vector']}")
        if f.get('evidence'):
            ev = f['evidence']
            sht = ', '.join(os.path.basename(x) for x in ev.get('screenshots', []))
            pcap = os.path.basename(ev['pcap']) if ev.get('pcap') else '-'
            lines.append(f"{'':>13}evidence: screenshot=[{sht}] pcap=[{pcap}]")
    lines.append("")
    lines.append(f"SUMMARY — confirmed={confirmed} tool-confirmed={toolconf} "
                 f"needs_review={review} informational={info}")
    lines.append(f"Band-mismatch rows above mean the computed CVSS severity disagrees with the label; "
                 f"resolve manually before relying on them.")
    recap = "\n".join(lines)
    outdir = sess.get('outdir', '/tmp')
    try:
        a_file = os.path.join(outdir, 'assessment.txt')
        with open(a_file, 'w') as fh:
            fh.write(recap + "\n")
    except OSError as ex:
        recap += f"\n[warn] could not write assessment file: {ex}"
    sess['assessment'] = recap
    for ln in recap.splitlines():
        push(sid, "output", {"substage": sub_id, "line": ln, "type": "info"})
    _complete_substage(sid, sub_id, [], rc=0)


def _run_evidence_capture(sid, sub_id, sub):
    """vuln_evidence — capture screenshot + PCAP for each scorable finding that
    has a reachable http endpoint. Evidence is attached to the finding and an
    `evidence_capture` info finding is emitted per capture. Nothing is
    fabricated: a failed capture produces an error string, not a fake file."""
    sess = sessions.get(sid)
    outdir = sess.get('outdir', '/tmp')
    evdir = os.path.join(outdir, 'evidence')
    os.makedirs(evdir, exist_ok=True, mode=0o700)
    captured = []
    all_f = []
    for sub_f in list(sess.get('findings', {}).values()):
        all_f.extend(sub_f)
    cands = [f for f in all_f
             if f.get('severity') in ('critical', 'high', 'medium')
             and f.get('cvss', {}).get('vector') is not None]
    push(sid, "output", {"substage": sub_id,
         "line": f"[evidence capture] {len(cands)} scorable finding(s) eligible (critical/high/medium)", "type": "meta"})
    for f in cands[:8]:
        url = _finding_url(f, sess)
        if not url:
            push(sid, "output", {"substage": sub_id,
                 "line": f"[evidence] no http endpoint for {f.get('type')} — skipped", "type": "meta"})
            continue
        push(sid, "output", {"substage": sub_id, "line": f"[evidence] capturing {f.get('type')} → {url}", "type": "meta"})
        rec = _capture_evidence(f, sess)
        f['evidence'] = rec
        sht = len(rec.get('screenshots', []))
        pcap = rec.get('pcap')
        detail = (f"Evidence for '{f.get('type')}' at {url}: {sht} screenshot(s) "
                  + (f", pcap {os.path.basename(pcap)}" if pcap else ", pcap=error"))
        captured.append({"type": "evidence_capture", "severity": "info",
                         "detail": detail, "path": f.get('path') or url,
                         "command": f"capture evidence for {url}",
                         "evidence": {"screenshots": rec.get('screenshots', []),
                                      "pcap": rec.get('pcap'),
                                      "errors": rec.get('errors', [])}})
        if pcap:
            push(sid, "output", {"substage": sub_id,
                 "line": f"[evidence] {os.path.basename(pcap)} — {os.path.getsize(pcap)} bytes",
                 "type": "info"})
        for e in rec.get('errors', []):
            push(sid, "output", {"substage": sub_id, "line": f"[evidence] {e}", "type": "meta"})
    _normalize_findings(captured, sess, sub_id)
    if not captured:
        captured.append({"type": "evidence_capture", "severity": "info",
                         "detail": "No screenshot/pcap capture run — no scorable finding had a reachable http endpoint",
                         "path": "-", "command": "-"})
        _normalize_findings(captured, sess, sub_id)
    sess['findings'][sub_id] = captured
    _complete_substage(sid, sub_id, captured, rc=0)


# ─────────────────────────────────────────────────────────────────────────────
# AUTH-TIER IN-PROCESS ENGINE
#
# Registration / authentication / session / authorization / business-logic
# checks run in Python rather than as shell templates: operator credentials
# never touch a command line, shell history, the process table or the report,
# and response comparison (enumeration, lockout, token reuse) is exact instead
# of parsed from curl text. Every finding cites the concrete request that
# produced it and is gated on observed evidence — no response pattern, no
# finding. Active probes are bounded and rate-capped.
# ─────────────────────────────────────────────────────────────────────────────
import ssl as _ssl
import urllib.error as _urlerror


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response itself instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_SSL_CTX = _ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = _ssl.CERT_NONE
_PW_OPENER = urllib.request.build_opener(
    _NoRedirectHandler, urllib.request.HTTPSHandler(context=_SSL_CTX))


SIGNUP_PATHS = ['/register', '/signup', '/sign-up', '/join', '/create-account',
                '/account/register', '/users/register', '/auth/register',
                '/api/register', '/api/signup', '/api/v1/register', '/user/new']
LOGIN_PATHS = ['/login', '/signin', '/sign-in', '/auth/login', '/api/login',
               '/api/auth/login', '/api/v1/login', '/session', '/account/login']
_FORM_INPUT_RE = re.compile(r'<(?:input|select|textarea)[^>]*name=["\']([^"\']+)["\']', re.I)
_FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.I)
_PW_FIELD_RE = re.compile(r'<input[^>]*type=["\']password["\']', re.I)
_CAPTCHA_RE = re.compile(r'recaptcha|hcaptcha|turnstile|grecaptcha|cf-turnstile|data-sitekey', re.I)
_EXISTS_RE = re.compile(r'already\s+(?:registered|exists|taken|in use|been)|is taken|'
                        r'(?:email|username|account)\s+(?:already\s+)?exists|in use|duplicate', re.I)
_POLICY_RE = re.compile(r'too\s+short|at least|minimum|weak password|password must|'
                        r'complexity|characters|special character', re.I)
_VERIFY_RE = re.compile(r'verif|confirm your (?:email|account)|activation|'
                        r'check your (?:email|inbox)|activate your', re.I)


def _http(method, url, data=None, headers=None, timeout=7, cookie=None,
          json_body=None, max_bytes=262144):
    """One HTTP request, redirects NOT followed. Returns
    {ok,status,headers(lowercased),body,url,error}. Never raises."""
    h = dict(headers or {})
    h.setdefault('User-Agent', 'PWM-AuthScan/1.0')
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        h.setdefault('Content-Type', 'application/json')
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
    if cookie:
        h['Cookie'] = cookie
    req = urllib.request.Request(url, data=body, headers=h, method=method.upper())
    try:
        with _PW_OPENER.open(req, timeout=timeout) as r:
            raw = r.read(max_bytes)
            return {"ok": True, "status": r.status,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": raw.decode('utf-8', 'ignore'), "url": r.geturl(), "error": None}
    except _urlerror.HTTPError as e:
        raw = b''
        try:
            raw = e.read(max_bytes)
        except Exception:
            pass
        return {"ok": True, "status": e.code,
                "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "body": raw.decode('utf-8', 'ignore'), "url": url, "error": None}
    except Exception as e:
        return {"ok": False, "status": None, "headers": {}, "body": "",
                "url": url, "error": str(e)[:120]}


def _base_url(sess):
    o = sess.get('web_origin')
    if o:
        return o.rstrip('/')
    ctx = sess.get('context') or {}
    if ctx.get('web_base'):
        return ctx['web_base'].rstrip('/')
    t = sess.get('target', '')
    if t.startswith('http'):
        return t.rstrip('/')
    ports = [p.strip() for p in str(sess.get('ports_found') or '').split(',') if p.strip().isdigit()]
    if '443' in ports or '8443' in ports:
        return f"https://{t}"
    if '80' in ports:
        return f"http://{t}"
    for p in ports:
        if p not in ('22', '23', '25', '53', '110', '143', '445', '3306',
                     '5432', '6379', '27017'):
            return f"http://{t}:{p}"
    return f"http://{t}"


def _req_line(method, url, data=None, secret_keys=('password', 'pass', 'pwd')):
    if data:
        safe = {k: ('***' if any(s in k.lower() for s in secret_keys) else v)
                for k, v in data.items()}
        return f"{method} {url} {urllib.parse.urlencode(safe)[:200]}"
    return f"{method} {url}"


def _resp_cookie(resp):
    sc = (resp.get('headers') or {}).get('set-cookie')
    return sc.split(';')[0] if sc else None


def _norm_body(b):
    return re.sub(r'\s+', ' ', re.sub(r'\d+', '#', b or '')).strip()[:2000]


def _classify_signup(body):
    return bool(_PW_FIELD_RE.search(body)) or bool(
        re.search(r'\b(sign\s*up|register|create.{0,12}account|join)\b', body or '', re.I))


def _finish_inproc(sid, sub_id, findings, lines):
    sess = sessions.get(sid)
    if sess is None:
        return
    for ln, typ in lines:
        push(sid, "output", {"substage": sub_id, "line": ln, "type": typ})
    _normalize_findings(findings, sess, sub_id)
    sess.setdefault('findings', {})[sub_id] = findings
    _complete_substage(sid, sub_id, findings, rc=0)


def _context(sess):
    return sess.setdefault('context', {})


def _signup_body(fields, tag, extra=None):
    fields = fields or ['username', 'email', 'password']
    body = {}
    for f in fields:
        fl = f.lower()
        if 'confirm' in fl or 'pass' in fl:
            body[f] = 'PwmProbe!23x'
        elif 'email' in fl or 'mail' in fl:
            body[f] = f'pwm-probe-{tag}@example.invalid'
        elif 'user' in fl or 'name' in fl or 'login' in fl:
            body[f] = f'pwmprobe{tag}'
        else:
            body[f] = f'pwm{tag}'
    if extra:
        body.update(extra)
    return body


def _reg_discovery(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); ctx = _context(sess)
    findings, lines = [], []
    found = None
    for p in SIGNUP_PATHS:
        r = _http('GET', base + p)
        if not r['ok'] or r['status'] not in (200, 405):
            continue
        if r['status'] == 405:
            fields, pw, captcha = [], False, False
        else:
            if not _classify_signup(r['body']):
                continue
            fields = sorted(set(_FORM_INPUT_RE.findall(r['body'])))
            pw = bool(_PW_FIELD_RE.search(r['body']))
            captcha = bool(_CAPTCHA_RE.search(r['body']))
        action = p
        m = _FORM_ACTION_RE.search(r['body'] or '')
        if m and m.group(1):
            action = m.group(1)
        url = action if action.startswith('http') else (
            base + action if action.startswith('/') else base + '/' + action.lstrip('/'))
        if not fields and pw:
            fields = ['username', 'email', 'password']
        found = {"url": url, "path": p, "fields": fields, "status": r['status'], "captcha": captcha}
        lines.append((f"[signup] candidate {p} → {url} "
                      f"(fields: {', '.join(fields) or 'n/a'}; captcha: {captcha})", "info"))
        findings.append({"type": "web_path", "severity": "info", "path": p,
                         "detail": f"Registration/signup endpoint discovered at {p}"
                                   + (f" (form fields: {', '.join(fields)})" if fields else ""),
                         "command": _req_line('GET', base + p)})
        break
    if found:
        ctx['signup'] = found
    else:
        lines.append(("[signup] no registration endpoint discovered on common paths", "meta"))
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No registration/signup endpoint discovered on common paths — "
                                   "signup checks not applicable (nothing inferred).", "command": ""})
    _finish_inproc(sid, sub_id, findings, lines)


def _reg_captcha(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess)
    sup = ctx.get('signup'); findings, lines = [], []
    if not sup:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No signup endpoint discovered — CAPTCHA check not applicable.",
                         "command": ""})
    elif sup.get('captcha'):
        lines.append(("[signup] CAPTCHA challenge detected on the registration form", "info"))
        findings.append({"type": "info", "severity": "info", "path": sup['path'],
                         "detail": "CAPTCHA challenge (reCAPTCHA/hCaptcha/Turnstile) present on the "
                                   "registration form — automated abuse is challenged.",
                         "command": _req_line('GET', sup['url'])})
    else:
        lines.append(("[signup] no CAPTCHA marker on the registration form", "meta"))
        findings.append({"type": "signup_captcha", "severity": "low", "path": sup['path'],
                         "detail": "Registration form has no CAPTCHA challenge — automated mass "
                                   "account creation is not front-line challenged (CWE-804).",
                         "command": _req_line('GET', sup['url'])})
    _finish_inproc(sid, sub_id, findings, lines)


def _reg_enum(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess)
    sup = ctx.get('signup'); findings, lines = [], []
    if not sup:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No signup endpoint discovered — enumeration check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    tag = uuid.uuid4().hex[:10]
    body = _signup_body(sup.get('fields'), tag)
    r_new = _http('POST', sup['url'], data=body)
    r_dup = _http('POST', sup['url'], data=body)
    lines.append((f"[signup] probe new → HTTP {r_new['status']}", "info"))
    lines.append((f"[signup] probe duplicate → HTTP {r_dup['status']}", "info"))
    distinct = (r_new['status'] != r_dup['status']) or (_norm_body(r_new['body']) != _norm_body(r_dup['body']))
    if r_new['status'] in (200, 201):
        ctx['created'] = {"body": body, "cookie": _resp_cookie(r_new),
                          "resp_body": r_new['body'], "status": r_new['status']}
    if r_new['status'] in (200, 201) and distinct and _EXISTS_RE.search(r_dup['body'] or ''):
        findings.append({"type": "signup_enum", "severity": "medium", "path": sup['path'],
                         "detail": "Registration responses distinguish an existing account from a new "
                                   "one (duplicate submission returned a distinct 'already exists' "
                                   "response) — username/email enumeration vector.",
                         "command": _req_line('POST', sup['url'], body)})
    else:
        lines.append(("[signup] no distinguishing response between new vs existing account", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _reg_password_policy(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess)
    sup = ctx.get('signup'); findings, lines = [], []
    if not sup:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No signup endpoint discovered — password-policy check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    body = _signup_body(sup.get('fields'), uuid.uuid4().hex[:10])
    for k in list(body):
        if 'pass' in k.lower():
            body[k] = '123456'
    r = _http('POST', sup['url'], data=body)
    lines.append((f"[signup] weak-password probe → HTTP {r['status']}", "info"))
    if (r['status'] in (200, 201) and not _POLICY_RE.search(r['body'] or '')
            and not _EXISTS_RE.search(r['body'] or '')):
        findings.append({"type": "signup_password_policy", "severity": "medium", "path": sup['path'],
                         "detail": "Registration accepted the weak password '123456' — no effective "
                                   "password-strength policy enforced at signup (CWE-521).",
                         "command": _req_line('POST', sup['url'], body)})
    else:
        lines.append(("[signup] weak password rejected or policy response observed", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _reg_verification_bypass(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess)
    sup = ctx.get('signup'); created = ctx.get('created')
    findings, lines = [], []
    if not sup or not created:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No account was created during probing — email-verification-bypass "
                                   "check not applicable (nothing inferred).", "command": ""})
    elif created.get('cookie') and _VERIFY_RE.search(created.get('resp_body') or ''):
        findings.append({"type": "signup_verification_bypass", "severity": "high", "path": sup['path'],
                         "detail": "Registration issued an authenticated session cookie while the "
                                   "response simultaneously asks for email verification — the account "
                                   "is usable before verification completes.",
                         "command": _req_line('POST', sup['url'], created['body'])})
    else:
        lines.append(("[signup] registration did not return a session alongside a verification notice",
                      "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _reg_mass_assign(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess)
    sup = ctx.get('signup'); findings, lines = [], []
    if not sup:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No signup endpoint discovered — signup mass-assignment check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    extra = {'role': 'admin', 'isAdmin': 'true', 'admin': 'true'}
    body = _signup_body(sup.get('fields'), uuid.uuid4().hex[:10], extra=extra)
    r = _http('POST', sup['url'], data=body)
    lines.append((f"[signup] overpost probe (role/isAdmin/admin) → HTTP {r['status']}", "info"))
    if r['status'] in (200, 201) and re.search(
            r'"?(?:role|isAdmin|is_admin|admin)"?\s*[:=]\s*"?(?:admin|true|1)"?',
            r['body'] or '', re.I):
        findings.append({"type": "signup_mass_assign", "severity": "high", "path": sup['path'],
                         "detail": "Registration response reflected an injected privileged attribute "
                                   "(role/isAdmin/admin) — overposting accepted at signup (CWE-915).",
                         "command": _req_line('POST', sup['url'], body)})
    else:
        lines.append(("[signup] no privileged attribute reflected in the registration response", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _reg_rate_limit(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess)
    sup = ctx.get('signup'); findings, lines = [], []
    if not sup:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No signup endpoint discovered — rate-limit check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    # reuse ONE probe identity so no additional accounts are created
    body = _signup_body(sup.get('fields'), uuid.uuid4().hex[:10])
    throttled = 0; had_response = False; attempts = 6
    for _ in range(attempts):
        r = _http('POST', sup['url'], data=body, timeout=5)
        # Only a real HTTP response counts as evidence. A connection error is
        # not throttling and must not be reported as "no rate limit" either.
        if r['status'] is not None:
            had_response = True
        if r['status'] == 429 or (r['status'] is not None and r['status'] == 503):
            throttled += 1
    lines.append((f"[signup] {attempts} rapid attempts, throttled={throttled}", "info"))
    if had_response and throttled == 0:
        findings.append({"type": "signup_rate_limit", "severity": "medium", "path": sup['path'],
                         "detail": f"No rate limiting observed across {attempts} rapid registration "
                                   f"attempts (no 429/block) — mass account-creation abuse is unrestricted "
                                   f"(CWE-770).",
                         "command": _req_line('POST', sup['url'], body)})
    elif not had_response:
        findings.append({"type": "not_tested", "severity": "info", "path": sup['path'],
                         "detail": "Registration endpoint never returned an HTTP response — "
                                   "rate-limit check could not be performed.",
                         "command": ""})
    else:
        lines.append(("[signup] throttling/blocking observed", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


RESET_PATHS = ['/forgot-password', '/forgot', '/password/reset', '/reset-password',
               '/account/recover', '/password/forgot', '/api/forgot-password',
               '/api/password/reset']
OAUTH_PATHS = ['/oauth/authorize', '/oauth2/authorize', '/authorize',
               '/auth/oauth/authorize', '/login/oauth/authorize']
LOGOUT_PATHS = ['/logout', '/signout', '/sign-out', '/api/logout', '/api/auth/logout']
PROTECTED_PATHS = ['/api/me', '/account', '/profile', '/dashboard', '/api/v1/me', '/user/profile']
_LOCKOUT_RE = re.compile(r'locked|too many|try again later|rate limit|please wait|account disabled', re.I)
_ENUM_UNKNOWN_RE = re.compile(r'unknown|not found|no such|invalid (?:user|account|login)|'
                              r'does not exist|user does not', re.I)
_ENUM_WRONGPW_RE = re.compile(r'incorrect password|wrong password|invalid password|'
                              r'password is incorrect|bad credentials', re.I)
_JWT_RE = re.compile(r'^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+$')
ADMIN_PATHS = ['/admin', '/admin/', '/admin/users', '/admin/settings', '/administrator',
               '/manage', '/console', '/api/admin', '/api/admin/users', '/api/users',
               '/api/v1/users', '/api/user/list']
OBJECT_PATH_TMPL = ['/api/user/{id}', '/api/users/{id}', '/api/v1/users/{id}',
                    '/api/accounts/{id}', '/api/orders/{id}', '/api/profile/{id}']
_ADMIN_MARKER_RE = re.compile(
    r'"?(?:role|admin|superuser|isAdmin)"?\s*[:=]|'
    r'\b(?:admin dashboard|user management|manage users|settings)\b|'
    r'<title>[^<]*(?:admin|dashboard|管理)[^<]*</title>', re.I)
_CSRF_FIELD_RE = re.compile(r'csrf|xsrf|_token|authenticity|anticsrf|nonce', re.I)


def _build_login(lg, user, password):
    body = {}
    for f in (lg.get('fields') or ['username', 'password']):
        fl = f.lower()
        if 'pass' in fl:
            body[f] = password
        elif any(k in fl for k in ('otp', 'mfa', '2fa', 'code', 'token', 'captcha')):
            body[f] = '000000'
        else:
            body[f] = user
    return body


def _operator_creds(sess):
    for a in (sess.get('accounts') or []):
        if a.get('username') and a.get('password'):
            return a
    return None


def _probe_identity(sess):
    ctx = _context(sess); lg = ctx.get('login') or {}
    cr = ctx.get('created') or {}; b = cr.get('body') or {}
    for lf in (lg.get('fields') or []):
        if lf in b and 'pass' not in lf.lower():
            return b[lf]
    for k, v in b.items():
        if 'pass' not in k.lower():
            return v
    ac = _operator_creds(sess)
    return (ac.get('username') if ac else None)


def _other_identity(sess):
    """A second, distinct principal if one is known (e.g. a signup probe)."""
    ctx = _context(sess); cr = ctx.get('created') or {}; b = cr.get('body') or {}
    op = _operator_creds(sess)
    opname = str(op.get('username')) if op else None
    for key in ('username', 'user', 'login', 'login_name', 'email'):
        if b.get(key) and str(b[key]) != opname:
            return str(b[key])
    for k, v in b.items():
        if 'pass' not in k.lower() and v and str(v) != opname:
            return str(v)
    return None


def _login_cookie(sess, base, lg, ac):
    r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']))
    return _resp_cookie(r)


def _login_raw(sess, base, lg, ac):
    r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']))
    return (r['headers'] or {}).get('set-cookie', '')


def _authz_forced_browsing(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); findings, lines = [], []
    for p in ADMIN_PATHS:
        r = _http('GET', base + p)
        if not r['ok']:
            continue
        lines.append((f"[authz] unauthenticated GET {p} → HTTP {r['status']}", "info"))
        body = r['body'] or ''
        if (r['status'] == 200 and not _PW_FIELD_RE.search(body) and len(body) > 100
                and _ADMIN_MARKER_RE.search(body)):
            findings.append({"type": "unauth_endpoint", "severity": "high", "path": p,
                             "detail": f"Privileged resource {p} returned HTTP 200 with "
                                       f"administrative content to an unauthenticated request "
                                       f"(no login redirect, no 401/403) — broken access control.",
                             "command": _req_line('GET', base + p)})
            break
    if not findings:
        lines.append(("[authz] no unauthenticated administrative exposure observed", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _authz_vertical(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); ctx = _context(sess)
    lg = ctx.get('login'); ac = _operator_creds(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — vertical authorization "
                                   "check not applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    role = str(ac.get('role') or '').lower()
    if role in ('admin', 'administrator', 'superuser', 'root'):
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "Operator account is privileged — non-admin escalation to "
                                   "admin functions is not testable with this account.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    cookie = _login_cookie(sess, base, lg, ac)
    if not cookie:
        findings.append({"type": "not_tested", "severity": "info", "path": lg['path'],
                         "detail": "Operator login did not yield a session — vertical authorization "
                                   "check not applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    for p in ADMIN_PATHS:
        anon = _http('GET', base + p)
        auth = _http('GET', base + p, cookie=cookie)
        if not auth['ok']:
            continue
        lines.append((f"[authz] {p}: anon={anon['status']} auth({role})={auth['status']}", "info"))
        if (anon['status'] in (401, 403, 302, 303) and auth['status'] == 200
                and not _PW_FIELD_RE.search(auth['body'] or '')
                and _ADMIN_MARKER_RE.search(auth['body'] or '')):
            findings.append({"type": "function_level_auth", "severity": "high", "path": p,
                             "detail": f"Administrative function {p} requires authentication but not "
                                       f"the admin role: unauthenticated → HTTP {anon['status']}, while "
                                       f"a non-admin ('{role}') session → HTTP 200 with admin content "
                                       f"(CWE-285).",
                             "command": _req_line('GET', base + p)})
            break
    if not findings:
        lines.append(("[authz] no vertical privilege escalation observed", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _authz_idor(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); ctx = _context(sess)
    lg = ctx.get('login'); ac = _operator_creds(sess); other = _other_identity(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — object-level authorization "
                                   "check not applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    if not other:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No second identity available (register a probe account or supply "
                                   "a second account) — BOLA/IDOR comparison not performed.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    cookie = _login_cookie(sess, base, lg, ac)
    if not cookie:
        findings.append({"type": "not_tested", "severity": "info", "path": lg['path'],
                         "detail": "Operator login did not yield a session — BOLA/IDOR check not "
                                   "applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    me = str(ac['username'])
    for tmpl in OBJECT_PATH_TMPL:
        own = _http('GET', base + tmpl.format(id=urllib.parse.quote(me)), cookie=cookie)
        oth = _http('GET', base + tmpl.format(id=urllib.parse.quote(other)), cookie=cookie)
        anon = _http('GET', base + tmpl.format(id=urllib.parse.quote(other)))
        if not (own['ok'] and oth['ok']):
            continue
        lines.append((f"[authz] {tmpl}: own={own['status']} other={oth['status']} "
                      f"anon={anon['status']}", "info"))
        if (own['status'] == 200 and oth['status'] == 200 and anon['status'] in (401, 403)
                and other in (oth['body'] or '')
                and _norm_body(oth['body']) != _norm_body(own['body'])):
            findings.append({"type": "bola_idor", "severity": "high", "path": tmpl,
                             "detail": f"Authenticated as '{me}' but {tmpl.format(id=other)} returned "
                                       f"another user's record (contains '{other}') although the "
                                       f"endpoint is protected (unauthenticated → HTTP {anon['status']}) "
                                       f"— broken object-level authorization (CWE-639).",
                             "command": _req_line('GET', base + tmpl.format(id=other))})
            break
    if not findings:
        lines.append(("[authz] no object-level authorization bypass observed", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _auth_discovery(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); ctx = _context(sess)
    findings, lines = [], []
    found = None
    for p in LOGIN_PATHS:
        r = _http('GET', base + p)
        if not r['ok'] or r['status'] not in (200, 405):
            continue
        if r['status'] == 200 and not _PW_FIELD_RE.search(r['body'] or ''):
            continue
        fields = sorted(set(_FORM_INPUT_RE.findall(r['body'] or ''))) if r['status'] == 200 else []
        m = _FORM_ACTION_RE.search(r['body'] or '')
        action = (m.group(1) if m and m.group(1) else p)
        url = action if action.startswith('http') else (
            base + action if action.startswith('/') else base + '/' + action.lstrip('/'))
        mfa = bool(re.search(r'otp|mfa|2fa|one[- ]?time|authenticator code|verification code',
                             r['body'] or '', re.I)) or any(
            any(k in f.lower() for k in ('otp', 'mfa', '2fa')) for f in fields)
        if not fields:
            fields = ['username', 'password']
        found = {"url": url, "path": p, "fields": fields, "mfa": mfa}
        lines.append((f"[login] candidate {p} → {url} (fields: {', '.join(fields)}; mfa: {mfa})", "info"))
        findings.append({"type": "web_path", "severity": "info", "path": p,
                         "detail": f"Authentication/login endpoint discovered at {p}"
                                   f" (form fields: {', '.join(fields)})",
                         "command": _req_line('GET', base + p)})
        break
    if found:
        ctx['login'] = found
    else:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint discovered on common paths — authentication "
                                   "checks not applicable (nothing inferred).", "command": ""})
    _finish_inproc(sid, sub_id, findings, lines)


def _auth_enum(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess); lg = ctx.get('login')
    findings, lines = [], []
    if not lg:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint discovered — enumeration check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    known = _probe_identity(sess)
    if not known:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No known account identity available (no registered probe and no "
                                   "operator account) — login enumeration comparison not possible "
                                   "(nothing inferred).", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    pw = 'PwmWrong!999'
    unknown = 'pwm-nosuch-' + uuid.uuid4().hex[:8]
    rk = _http('POST', lg['url'], data=_build_login(lg, known, pw))
    ru = _http('POST', lg['url'], data=_build_login(lg, unknown, pw))
    lines.append((f"[login] known-user wrong-pw → HTTP {rk['status']}", "info"))
    lines.append((f"[login] unknown-user wrong-pw → HTTP {ru['status']}", "info"))
    distinct = (rk['status'] != ru['status']) or (_norm_body(rk['body']) != _norm_body(ru['body']))
    if distinct and _ENUM_UNKNOWN_RE.search(ru['body'] or '') and _ENUM_WRONGPW_RE.search(rk['body'] or ''):
        findings.append({"type": "login_enum", "severity": "medium", "path": lg['path'],
                         "detail": "Login responses distinguish an unknown username ('not found') from a "
                                   "known username with a wrong password ('incorrect password') — "
                                   "account enumeration vector.",
                         "command": _req_line('POST', lg['url'], _build_login(lg, unknown, pw))})
    else:
        lines.append(("[login] no distinguishing response between unknown vs known user", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _auth_lockout(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess); lg = ctx.get('login')
    findings, lines = [], []
    ident = _probe_identity(sess)
    if not lg or not ident:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / known account identity available — login "
                                   "lockout check not applicable (nothing inferred).", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    attempts = 6; throttled = 0; responded = False
    for i in range(attempts):
        r = _http('POST', lg['url'], data=_build_login(lg, ident, f'PwmWrong!{i}x9'), timeout=5)
        # Only a real HTTP answer proves the endpoint was exercised; a
        # connection error is neither throttling nor a usable negative.
        if r['status'] is not None:
            responded = True
        if r['status'] in (429, 503) or _LOCKOUT_RE.search(r['body'] or ''):
            throttled += 1
    lines.append((f"[login] {attempts} wrong-password attempts, throttled={throttled}", "info"))
    if responded and throttled == 0:
        findings.append({"type": "login_bruteforce", "severity": "medium", "path": lg['path'],
                         "detail": f"No account lockout or rate limiting across {attempts} consecutive "
                                   f"wrong-password attempts for an existing account — online password "
                                   f"guessing is unrestricted (CWE-307).",
                         "command": _req_line('POST', lg['url'], _build_login(lg, ident, 'PwmWrong!0x9'))})
    elif not responded:
        findings.append({"type": "not_tested", "severity": "info", "path": lg['path'],
                         "detail": "Login endpoint never returned an HTTP response — lockout check "
                                   "could not be performed.", "command": ""})
    else:
        lines.append(("[login] lockout/throttling observed", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _auth_password_reset(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); findings, lines = [], []
    ident = _probe_identity(sess)
    hit = None
    for p in RESET_PATHS:
        r = _http('GET', base + p)
        if r['ok'] and r['status'] in (200, 405):
            hit = p
            break
    if not hit:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No password-reset endpoint discovered — reset-flow check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    if not ident:
        findings.append({"type": "not_tested", "severity": "info", "path": hit,
                         "detail": "No known account identity available — password-reset abuse check "
                                   "not performed (nothing inferred).", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    r = _http('POST', base + hit, data={'username': ident, 'email': ident})
    lines.append((f"[reset] POST {hit} → HTTP {r['status']}", "info"))
    tok = re.search(r'(?:[?&]token=|["\']token["\']\s*[:=]\s*["\']|reset\?token=|'
                    r'code=)([A-Za-z0-9._-]{8,})', r['body'] or '')
    if r['status'] in (200, 201) and tok:
        findings.append({"type": "password_reset_flaw", "severity": "high", "path": hit,
                         "detail": "Password-reset response discloses the reset token/link in the HTTP "
                                   "body — an attacker who can trigger a reset for a victim can complete "
                                   "it (CWE-640).",
                         "command": _req_line('POST', base + hit, {'username': ident})})
    else:
        lines.append(("[reset] no reset token disclosed in the response", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _auth_oauth(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); findings, lines = [], []
    evil = 'https://pwm-evil.example/cb'
    hit = None
    for p in OAUTH_PATHS:
        probe = f"{base}{p}?client_id=pwm&response_type=code&redirect_uri={urllib.parse.quote(evil)}"
        r = _http('GET', probe)
        if r['ok'] and r['status'] in (200, 302, 303):
            loc = (r['headers'].get('location') or '')
            lines.append((f"[oauth] GET {p} → HTTP {r['status']} location={loc[:80]}", "info"))
            if 'pwm-evil.example' in loc:
                findings.append({"type": "oauth_misconfig", "severity": "high", "path": p,
                                 "detail": "OAuth authorize endpoint reflects an arbitrary redirect_uri "
                                           "(pwm-evil.example) in the redirect Location without "
                                           "validation — authorization-code / token theft (CWE-346).",
                                 "command": _req_line('GET', probe)})
                hit = p
                break
            hit = p
    if not hit:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No OAuth/SSO authorize endpoint discovered — redirect_uri check not "
                                   "applicable (nothing inferred).", "command": ""})
    _finish_inproc(sid, sub_id, findings, lines)


def _auth_logout(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); ctx = _context(sess)
    lg = ctx.get('login'); ac = _operator_creds(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — logout invalidation check "
                                   "not applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']))
    cookie = _resp_cookie(r)
    if not cookie:
        findings.append({"type": "not_tested", "severity": "info", "path": lg['path'],
                         "detail": "Login did not return a session cookie (token-based?) — logout "
                                   "invalidation check not applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    lopath = None
    for p in LOGOUT_PATHS:
        rr = _http('GET', base + p, cookie=cookie)
        if rr['ok'] and rr['status'] in (200, 302, 303, 204):
            lopath = p
            break
    if not lopath:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No logout endpoint discovered — session-invalidation check not "
                                   "applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    stale = None
    for p in PROTECTED_PATHS:
        rr = _http('GET', base + p, cookie=cookie)
        if rr['ok'] and rr['status'] == 200 and _norm_body(rr['body']):
            stale = p
            break
    lines.append((f"[logout] after GET {lopath}, stale cookie on {stale or 'none'}", "info"))
    if stale:
        findings.append({"type": "logout_invalidation", "severity": "medium", "path": lopath,
                         "detail": f"Session cookie remains valid against {stale} after logout — the "
                                   f"session is not invalidated server-side (CWE-613).",
                         "command": _req_line('GET', base + lopath)})
    else:
        lines.append(("[logout] session invalidated server-side (stale cookie rejected)", "info"))
    _finish_inproc(sid, sub_id, findings, lines)


def _session_cookie_flags(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess); lg = ctx.get('login'); ac = _operator_creds(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — cookie-flag check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']))
    sc = (r['headers'] or {}).get('set-cookie', '')
    if not sc:
        findings.append({"type": "not_tested", "severity": "info", "path": lg['path'],
                         "detail": "Login did not set a cookie (token/header session?) — cookie-flag "
                                   "check not applicable.", "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    low = sc.lower(); missing = []
    if 'httponly' not in low:
        missing.append('HttpOnly')
    if 'secure' not in low:
        missing.append('Secure')
    if 'samesite' not in low:
        missing.append('SameSite')
    lines.append((f"[session] Set-Cookie: {sc[:120]}", "info"))
    if missing:
        findings.append({"type": "cookie_flags", "severity": "low", "path": lg['path'],
                         "detail": f"Session cookie missing flag(s): {', '.join(missing)} "
                                   f"(observed Set-Cookie: {sc[:160]}) — susceptible to theft/CSRF (CWE-1004).",
                         "command": _req_line('POST', lg['url'], _build_login(lg, ac['username'], '***'))})
    else:
        lines.append(("[session] session cookie sets HttpOnly, Secure and SameSite", "info"))
    _finish_inproc(sid, sub_id, findings, lines)


def _session_entropy(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess); lg = ctx.get('login'); ac = _operator_creds(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — session-entropy check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    vals = []
    for _ in range(3):
        r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']))
        c = _resp_cookie(r)
        if c and '=' in c:
            vals.append(c.split('=', 1)[1])
    if not vals:
        findings.append({"type": "not_tested", "severity": "info", "path": lg['path'],
                         "detail": "No session cookie value observed — entropy check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    v = max(vals, key=len)
    uniq = set(vals)
    # Charset is estimated over every observed value, not one sample; estimated
    # bits = length x log2(charset). The old length/charset-only test passed a
    # 12-character token with 8 distinct characters (~36 bits) as "random".
    charset = len(set(''.join(vals)))
    est_bits = len(v) * _math.log2(max(charset, 2))
    lines.append((f"[session] {len(vals)} cookie(s); sample len={len(v)} charset={charset} "
                  f"est_bits={est_bits:.0f}", "info"))
    if len(vals) > 1 and len(uniq) == 1:
        findings.append({"type": "session_entropy", "severity": "critical", "path": lg['path'],
                         "detail": f"Session identifier is identical across {len(vals)} separate "
                                   f"logins — the value is static/predictable and can be replayed "
                                   f"or guessed (CWE-330).",
                         "command": _req_line('POST', lg['url'], _build_login(lg, ac['username'], '***'))})
    elif len(v) < 16 or est_bits < 64:
        findings.append({"type": "session_entropy", "severity": "medium", "path": lg['path'],
                         "detail": f"Session identifier appears low-entropy (length {len(v)}, "
                                   f"{charset} distinct characters, ~{est_bits:.0f} bits estimated) — "
                                   f"predictable session ids enable hijacking (CWE-330).",
                         "command": _req_line('POST', lg['url'], _build_login(lg, ac['username'], '***'))})
    elif len(vals) > 1 and len(uniq) < len(vals):
        findings.append({"type": "session_entropy", "severity": "medium", "path": lg['path'],
                         "detail": f"Session identifier repeated across separate logins "
                                   f"({len(uniq)} unique values from {len(vals)} logins) — session IDs "
                                   f"may not be generated randomly (CWE-330).",
                         "command": _req_line('POST', lg['url'], _build_login(lg, ac['username'], '***'))})
    else:
        lines.append(("[session] session id length/charset/estimated entropy consistent "
                      "with a random token", "info"))
    _finish_inproc(sid, sub_id, findings, lines)


def _session_fixation(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess); lg = ctx.get('login'); ac = _operator_creds(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — session-fixation check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    pre = _http('GET', lg['url'])
    prec = _resp_cookie(pre)
    r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']), cookie=prec)
    postc = _resp_cookie(r)
    lines.append((f"[session] pre-auth cookie={prec}; post-auth cookie={postc}", "info"))
    if prec and postc and prec == postc:
        findings.append({"type": "session_fixation", "severity": "high", "path": lg['path'],
                         "detail": "Session identifier is not rotated on authentication (pre-auth cookie "
                                   "equals post-auth cookie) — session fixation is possible (CWE-384).",
                         "command": _req_line('POST', lg['url'], _build_login(lg, ac['username'], '***'))})
    else:
        lines.append(("[session] session id rotated (or no pre-auth cookie issued)", "info"))
    _finish_inproc(sid, sub_id, findings, lines)


def _session_jwt(sid, sub_id, sub):
    sess = sessions[sid]; ctx = _context(sess); lg = ctx.get('login'); ac = _operator_creds(sess)
    findings, lines = [], []
    if not lg or not ac:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No login endpoint / operator account — JWT check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    r = _http('POST', lg['url'], data=_build_login(lg, ac['username'], ac['password']))
    c = _resp_cookie(r); val = c.split('=', 1)[1] if c and '=' in c else ''
    if val and _JWT_RE.match(val):
        try:
            import base64 as _b64
            hdr = json.loads(_b64.urlsafe_b64decode(val.split('.')[0] + '===').decode('utf-8', 'ignore'))
        except Exception:
            hdr = {}
        alg = str(hdr.get('alg', ''))
        lines.append((f"[session] JWT session token, alg={alg or 'unknown'}", "info"))
        if alg.lower() in ('none', ''):
            findings.append({"type": "jwt_weakness", "severity": "high", "path": lg['path'],
                             "detail": f"Session JWT declares alg='{alg or 'none'}' (unsecured/absent) — "
                                       f"signature can be stripped or forged (CWE-347).",
                             "command": _req_line('POST', lg['url'], _build_login(lg, ac['username'], '***'))})
        else:
            findings.append({"type": "info", "severity": "info", "path": lg['path'],
                             "detail": f"JWT-based session observed with alg='{alg}'; signature/secret "
                                       f"strength not assessed here.", "command": _req_line('POST', lg['url'])})
    else:
        lines.append(("[session] no JWT-format session token observed (opaque cookie)", "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _bizlogic_csrf(sid, sub_id, sub):
    sess = sessions[sid]; base = _base_url(sess); ctx = _context(sess)
    findings, lines = [], []
    forms = []
    if ctx.get('signup'):
        forms.append(('signup', ctx['signup']))
    if ctx.get('login'):
        forms.append(('login', ctx['login']))
    if not forms:
        findings.append({"type": "not_tested", "severity": "info", "path": "-",
                         "detail": "No state-changing form discovered — CSRF check not applicable.",
                         "command": ""})
        _finish_inproc(sid, sub_id, findings, lines); return
    # cookie-based session? login (or a login GET) must set a cookie
    raw = ''
    lg = ctx.get('login'); ac = _operator_creds(sess)
    if lg and ac:
        raw = _login_raw(sess, base, lg, ac)
    if not raw and lg:
        raw = (_http('GET', lg['url'])['headers'] or {}).get('set-cookie', '')
    cookie = raw.split(';')[0] if raw else None
    same_site = bool(re.search(r';\s*samesite', raw, re.I))
    for name, f in forms:
        fields = f.get('fields') or []
        has_token = any(_CSRF_FIELD_RE.search(x) for x in fields)
        lines.append((f"[bizlogic] {name} form fields: {', '.join(fields)} "
                      f"(anti-CSRF token: {has_token})", "info"))
        if cookie and not has_token and not same_site:
            findings.append({"type": "csrf_missing", "severity": "medium",
                             "path": f.get('path', '-'),
                             "detail": f"The {name} form ({f.get('path', '?')}) has no anti-CSRF "
                                       f"token field and its session cookie has no SameSite attribute "
                                       f"— cross-site requests can drive this action (CWE-352).",
                             "command": _req_line('POST', f.get('url') or (base + f.get('path', '/')),
                                                  {x: '...' for x in fields})})
            break
    if not findings:
        lines.append(("[bizlogic] no CSRF weakness observed (token present or SameSite enforced)",
                      "meta"))
    _finish_inproc(sid, sub_id, findings, lines)


def _bizlogic_workflow(sid, sub_id, sub):
    sess = sessions[sid]; findings, lines = [], []
    tested = []
    ctx = _context(sess)
    if ctx.get('signup'):
        tested.append('signup')
    if ctx.get('login'):
        tested.append('login')
    lines.append((f"[bizlogic] generic flows exercised: {', '.join(tested) or 'none'}", "info"))
    findings.append({"type": "not_tested", "severity": "info", "path": "-",
                     "detail": "Application-specific business logic (multi-step workflows, price/"
                               "quantity manipulation, coupon/refund abuse, race conditions) cannot be "
                               "verified generically without domain knowledge of the target's "
                               "workflows; not tested to avoid fabricated findings.",
                     "command": ""})
    _finish_inproc(sid, sub_id, findings, lines)


INPROC_SUBSTAGES = {
    'reg_discovery': _reg_discovery,
    'reg_captcha': _reg_captcha,
    'reg_enum': _reg_enum,
    'reg_password_policy': _reg_password_policy,
    'reg_verification_bypass': _reg_verification_bypass,
    'reg_mass_assign': _reg_mass_assign,
    'reg_rate_limit': _reg_rate_limit,
    'auth_discovery': _auth_discovery,
    'auth_enum': _auth_enum,
    'auth_lockout': _auth_lockout,
    'auth_password_reset': _auth_password_reset,
    'auth_oauth': _auth_oauth,
    'auth_logout': _auth_logout,
    'session_cookie_flags': _session_cookie_flags,
    'session_entropy': _session_entropy,
    'session_fixation': _session_fixation,
    'session_jwt': _session_jwt,
    'authz_forced_browsing': _authz_forced_browsing,
    'authz_vertical': _authz_vertical,
    'authz_idor': _authz_idor,
    'bizlogic_csrf': _bizlogic_csrf,
    'bizlogic_workflow': _bizlogic_workflow,
}


_TOOL_ALIASES = {'python': ('python3', 'python'),
                 'testssl': ('testssl.sh', 'testssl'),
                 'theHarvester': ('theHarvester', 'theharvester')}


def _declared_tools(sub):
    """Extract the binary names from a substage's human-readable 'tool' field
    (e.g. 'nmap / masscan' -> ['nmap', 'masscan'])."""
    raw = (sub.get('tool') or '').strip()
    if not raw or raw.lower().startswith(('in-process', 'inprocess')):
        return []
    names = []
    for tok in re.split(r'[/,|]', raw):
        m = re.match(r'([A-Za-z0-9][A-Za-z0-9._+-]*)', tok.strip())
        if m:
            names.append(m.group(1))
    return names


def _tool_present(name):
    return any(shutil.which(c) for c in _TOOL_ALIASES.get(name, (name,)))


def _missing_declared_tool(sub, cmd=''):
    """Return the primary declared binary if none of the tools the command
    actually invokes are installed, otherwise None.

    The old implementation took the first whitespace token of the shell
    command. For compound templates (ep_hydra starts with 'WU=...;') that
    token was a variable assignment, shutil.which() always failed, and the
    code always ran the fallback path."""
    names = _declared_tools(sub)
    if not names:
        return None
    referenced = [n for n in names
                  if re.search(rf'(?<![\w.-]){re.escape(n)}(?![\w.-])', cmd or '', re.I)]
    candidates = referenced or names
    if any(_tool_present(n) for n in candidates):
        return None
    return candidates[0]


def _execute_substage(sid, sub_id):
    sess = sessions.get(sid)
    sub = find_sub(sub_id)
    if not sess or not sub:
        return

    push(sid, "running", {"substage": sub_id, "label": sub['label']})

    if sub_id == 'vuln_assess':
        _run_assessment(sid, sub_id, sub)
        return
    if sub_id == 'vuln_evidence':
        _run_evidence_capture(sid, sub_id, sub)
        return

    # Auth-tier gate: substages that need a logged-in account are skipped
    # honestly (one informational coverage finding) when none was supplied —
    # never fabricated, never reported as a vulnerability.
    if sub.get('requires_creds') and not _has_creds_for(sess, sub.get('cred_roles')):
        roles = ", ".join(sub.get('cred_roles') or ['any authenticated role'])
        push(sid, "output", {"substage": sub_id,
             "line": f"[auth-tier: credentials required ({roles}) — not tested]", "type": "meta"})
        fnd = [{"type": "not_tested", "severity": "info", "path": "-",
                "detail": f"Not tested — requires authenticated account(s): {roles}. "
                          f"Supply accounts[] (role + username/password and/or token/cookie) "
                          f"to the session to run this check.",
                "command": ""}]
        _normalize_findings(fnd, sess, sub_id)
        sess.setdefault('findings', {})[sub_id] = fnd
        _complete_substage(sid, sub_id, fnd, rc=0)
        return

    if sub_id in INPROC_SUBSTAGES:
        INPROC_SUBSTAGES[sub_id](sid, sub_id, sub)
        return

    # Per-substage wall-clock cap. Previously every LONG_SUBSTAGE_TIMEOUT was
    # ignored unless PWM_CMD_TIMEOUT>0 (default 0), leaving sqlmap/nuclei/hydra
    # unbounded. The per-substage value now always applies; the global value is
    # used as a fallback and as an upper bound when set.
    timeout = None
    sub_timeout = sub.get('timeout') or LONG_SUBSTAGE_TIMEOUT.get(sub_id)
    try:
        if sub_timeout:
            timeout = float(sub_timeout)
        elif PWM_CMD_TIMEOUT > 0:
            timeout = PWM_CMD_TIMEOUT
    except (TypeError, ValueError):
        timeout = None
    if PWM_CMD_TIMEOUT > 0 and (timeout is None or timeout > PWM_CMD_TIMEOUT):
        timeout = PWM_CMD_TIMEOUT
    if timeout is not None and timeout <= 0:
        timeout = None

    cmd_template = sub.get('cmd_template', 'echo "no command"')
    cmd = make_cmd(cmd_template, sess)
    tool_bin = _missing_declared_tool(sub)

    if tool_bin and not shutil.which(tool_bin):
        fallback = sub.get('fallback_cmd')
        if fallback:
            cmd = make_cmd(fallback, sess)
            push(sid, "output", {"substage": sub_id, "line": f"[{tool_bin} not found → fallback]", "type": "meta"})
        else:
            push(sid, "output", {"substage": sub_id, "line": f"[{tool_bin} not installed — skipped]", "type": "error"})
            _complete_substage(sid, sub_id, [], rc=-1)
            return

    if sub.get('requires_root') and os.geteuid() != 0:
        if _sudo_available():
            cmd = 'sudo -n ' + cmd
            push(sid, "output", {"substage": sub_id, "line": "[requires root → running with sudo]", "type": "meta"})
        else:
            fallback = sub.get('fallback_cmd')
            if fallback:
                cmd = make_cmd(fallback, sess)
                push(sid, "output", {"substage": sub_id, "line": "[requires root → fallback]", "type": "meta"})
            else:
                push(sid, "output", {"substage": sub_id, "line": "[requires root — skipped]", "type": "error"})
                _complete_substage(sid, sub_id, [], rc=-1)
                return

    sess['commands'][sub_id] = cmd
    output, rc = run_command(sid, sub_id, cmd, timeout=timeout)
    sess['outputs'][sub_id] = output

    parse_output = output
    if parse_output.startswith('$ '):
        parse_output = '\n'.join(parse_output.splitlines()[1:])
    findings = dispatch_parser(sub.get('parse', 'generic'), parse_output, sess)
    # Signature scan on output (command echo stripped, negated results excluded)
    for msg, sev in sig_matches(parse_output):
        if not any(f.get('detail') == msg for f in findings):
            findings.append({"type":"signature_match","detail":msg,"severity":sev,
                "path":"detected in output","command":"manual review"})

    _normalize_findings(findings, sess, sub_id)
    sess['findings'][sub_id] = findings

    if sub_id == 'recon_ports':
        port_matches = re.findall(r'(\d+)/tcp\s+open', output)
        if port_matches:
            sess['ports_found'] = ','.join(list(dict.fromkeys(port_matches))[:35])
        for svc_key in VERSION_DB:
            for line in output.splitlines():
                if svc_key in line.lower() and 'open' in line.lower():
                    parts = line.split()
                    if len(parts) >= 4:
                        sess['banner_search'] = ' '.join(parts[3:5])
                    break

    _complete_substage(sid, sub_id, findings, rc=rc)


def _complete_substage(sid, sub_id, findings=None, rc=0):
    """Single completion path for every substage.

    Guarantees the substage is recorded exactly once, never resurrects a
    substage the operator skipped while it was running, and mutates the
    session's completed list under its lock. Returns True when this call
    performed the transition."""
    sess = sessions.get(sid)
    if sess is None:
        return False
    findings = findings or []
    with sess['lock']:
        if sub_id in sess['skipped'] or sub_id in sess['completed']:
            return False
        sess['completed'].append(sub_id)
    push(sid, "completed", {"substage": sub_id, "findings": findings,
                            "finding_count": len(findings), "rc": rc})
    _advance_chain(sid, sub_id)
    return True


def _advance_chain(sid, completed_sub_id):
    """Notify stage completion and sequence the next substage.

    Parallel stages complete once every substage is done. Serial stages only
    auto-advance when the whole stage was approved via /approve_stage — a
    single /approve must never start the rest of the stage."""
    sess = sessions.get(sid)
    if not sess:
        return
    stage = find_stage_for_sub(completed_sub_id)
    if not stage:
        return
    stage_sub_ids = [s['id'] for s in stage['substages']]
    approved_stages = sess.get('stage_approved') or set()
    with sess['lock']:
        done = set(sess['completed']) | set(sess['skipped'])
    if stage.get('parallel'):
        if set(stage_sub_ids).issubset(done):
            push(sid, "stage_complete", {"stage": stage['id']})
        return
    if stage['id'] in approved_stages:
        for s_id in stage_sub_ids:
            if s_id in done:
                continue
            _launch_substage(sid, s_id)
            break
    if set(stage_sub_ids).issubset(done):
        push(sid, "stage_complete", {"stage": stage['id']})


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

def _launch_substage(sid, sub_id):
    """Idempotent, thread-safe substage launcher — prevents duplicate runs."""
    sess = sessions.get(sid)
    if not sess or not find_sub(sub_id):
        return False
    with sess['lock']:
        if sub_id in sess['launched'] or sub_id in sess['completed'] or sub_id in sess['skipped']:
            return False
        sess['launched'].add(sub_id)
    threading.Thread(target=execute_substage, args=(sid, sub_id), daemon=True).start()
    return True

_ASSETS_DIR = os.path.realpath(os.path.join(BASE_DIR, 'assets'))
PWM_LOGO = os.path.join(_ASSETS_DIR, 'pwm.png')


@app.route('/')
def index():
    if PWM_API_TOKEN and not _token_ok():
        return Response(_login_page(), status=401, mimetype='text/html')
    return send_file(os.path.join(BASE_DIR, 'frontend.html'))


@app.route('/auth', methods=['GET', 'POST'])
def auth_page():
    """Exchange the operator token for a HttpOnly cookie so the bundled UI
    (including EventSource, which cannot send custom headers) can authenticate."""
    if not PWM_API_TOKEN:
        return redirect('/')
    token = request.values.get('token', '')
    if token and hmac.compare_digest(token, PWM_API_TOKEN):
        resp = redirect('/')
        resp.set_cookie('pwm_api_token', PWM_API_TOKEN, httponly=True,
                        samesite='Strict', secure=request.is_secure,
                        max_age=8 * 3600, path='/')
        return resp
    if request.method == 'POST':
        return Response(_login_page('Invalid token.'), status=401, mimetype='text/html')
    return Response(_login_page(), status=401, mimetype='text/html')


@app.route('/assets/<path:fname>')
def asset(fname):
    """Serve bundled assets (logo/screenshots). Path-traversal safe."""
    path = os.path.realpath(os.path.join(_ASSETS_DIR, fname))
    if not path.startswith(_ASSETS_DIR + os.sep) or not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path)


@app.route('/favicon.ico')
def favicon():
    """PWM logo as favicon (served as PNG — browsers honour <link rel=icon>)."""
    if not os.path.isfile(PWM_LOGO):
        return Response(status=204)
    return send_file(PWM_LOGO, mimetype='image/png')

@app.route('/api/chain')
def get_chain():
    return jsonify(CHAIN)

@app.route('/api/session/new', methods=['POST'])
def new_session():
    data = request.json or {}
    raw = data.get('target', '').strip()
    if not raw:
        return jsonify({"error": "No target"}), 400
    target = clean_target(raw)
    if not is_valid_target(target):
        return jsonify({"error": "Invalid target. Use a hostname, IPv4 (with optional /CIDR), IPv6 or http(s) URL."}), 400
    sid = str(uuid.uuid4())
    # mkdtemp creates a unique 0700 directory atomically — a predictable
    # /tmp/pwm_<sid-prefix> path with exist_ok could be pre-created/symlinked
    # by another local user and redirect evidence writes.
    outdir = tempfile.mkdtemp(prefix='pwm_')
    try:
        os.chmod(outdir, 0o700)
    except OSError:
        pass
    sessions[sid] = {
        "sid": sid, "raw_target": raw, "target": target,
        "target_type": detect_target_type(raw),
        "created": datetime.now().isoformat(),
        "outdir": outdir,
        "findings": {}, "outputs": {}, "commands": {},
        "completed": [], "approved": [], "skipped": [], "launched": set(),
        "stage_approved": set(),
        "lock": threading.Lock(),
        "ports_found": "", "banner_search": target,
        "network": infer_network(target), "notes": {},
        "triage_log": {}, "assessment": None,
        "accounts": _norm_accounts(data.get('accounts')),
        "web_origin": _origin_from_raw(raw),
    }
    output_queues[sid] = queue.Queue(maxsize=20000)
    return jsonify({"sid": sid, "target": target, "target_type": sessions[sid]['target_type']})

@app.route('/api/session/<sid>', methods=['DELETE'])
def delete_session(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    with sess['lock']:
        if output_queues.get(sid) is not None:
            push(sid, "session_gone", {})
        output_queues.pop(sid, None)
        sessions.pop(sid, None)
    shutil.rmtree(sess['outdir'], ignore_errors=True)
    return jsonify({"ok": True})

@app.route('/api/session/<sid>/triage', methods=['POST'])
def manual_triage(sid):
    """Analyst override of an automated triage verdict. Verdicts: confirmed,
    tool-confirmed, needs_review, info (dismiss). Records the override in the
    session triage log with provenance=analyst."""
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    data = request.json or {}
    sub_id = data.get('substage_id')
    index = data.get('index')
    verdict = data.get('verdict')
    note = data.get('note', '')
    if not sub_id or sub_id not in sess['findings']:
        return jsonify({"error":"unknown substage"}), 400
    try:
        index = int(index)
    except (TypeError, ValueError):
        return jsonify({"error":"invalid index"}), 400
    if verdict not in ('confirmed', 'tool-confirmed', 'needs_review', 'info'):
        return jsonify({"error":"invalid verdict"}), 400
    with sess['lock']:
        fs = sess['findings'].get(sub_id, [])
        if index < 0 or index >= len(fs):
            return jsonify({"error":"index out of range"}), 400
        f = fs[index]
        f['triage'] = {"verdict": verdict, "basis": f.get('triage', {}).get('basis', ''),
                       "provenance": "analyst", "note": note,
                       "ts": datetime.now().isoformat()}
        log = sess.get('triage_log', {})
        recs = log.get(sub_id, [])
        if recs and any(r.get('index') == index for r in recs):
            for r in recs:
                if r.get('index') == index:
                    r.update({"verdict": verdict, "note": note, "provenance": "analyst",
                              "ts": f['triage']['ts']})
        else:
            recs.append({"index": index, "type": f.get('type'), "severity": f.get('severity'),
                         "verdict": verdict, "basis": f['triage']['basis'], "provenance": "analyst",
                         "note": note, "ts": f['triage']['ts']})
        log[sub_id] = recs
        sess['triage_log'] = log
    return jsonify({"ok": True, "verdict": verdict})

@app.route('/api/session/<sid>/approve', methods=['POST'])
def approve(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    data = request.json or {}
    sub_id = data.get('substage_id')
    note = data.get('note','')
    if not sub_id or not find_sub(sub_id):
        return jsonify({"error":"unknown substage"}), 400
    with sess['lock']:
        if sub_id not in sess['approved']:
            sess['approved'].append(sub_id)
        if note:
            sess['notes'][sub_id] = note
    # A per-substage approval starts exactly that substage. Expanding to the
    # whole parallel stage ignored the operator's choice and ran unapproved
    # probes (including intrusive ones) without consent.
    _launch_substage(sid, sub_id)
    return jsonify({"ok": True})

@app.route('/api/session/<sid>/approve_stage', methods=['POST'])
def approve_stage(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    data = request.json or {}
    stage_id = data.get('stage_id')
    stage = next((s for s in CHAIN if s['id'] == stage_id), None)
    if not stage: return jsonify({"error":"unknown stage"}), 404
    with sess['lock']:
        sess.setdefault('stage_approved', set()).add(stage['id'])
        for sub in stage['substages']:
            if sub['id'] not in sess['approved']:
                sess['approved'].append(sub['id'])
    launched = []
    if stage.get('parallel'):
        targets = [s['id'] for s in stage['substages']]
    else:
        # Serial stages run one substage at a time; _advance_chain starts the
        # next one when the current one completes. Launching them all here ran
        # a strictly ordered chain concurrently and corrupted its dependencies.
        targets = [stage['substages'][0]['id']] if stage['substages'] else []
    for s_id in targets:
        if _launch_substage(sid, s_id):
            launched.append(s_id)
    return jsonify({"ok": True, "launched": launched})

@app.route('/api/session/<sid>/skip', methods=['POST'])
def skip(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    sub_id = (request.json or {}).get('substage_id')
    if not sub_id or not find_sub(sub_id):
        return jsonify({"error":"unknown substage"}), 400
    with sess['lock']:
        if sub_id in sess['completed']:
            return jsonify({"ok": True, "note": "already completed"})
        if sub_id not in sess['skipped']:
            sess['skipped'].append(sub_id)
        if sub_id in sess['approved']:
            sess['approved'].remove(sub_id)
        sess['launched'].add(sub_id)
    push(sid, "skipped", {"substage": sub_id})
    _advance_chain(sid, sub_id)
    return jsonify({"ok": True})

@app.route('/api/session/<sid>/stream')
def stream(sid):
    if sid not in output_queues or sid not in sessions:
        return jsonify({"error": "unknown session"}), 404
    def gen():
        yield f"data: {json.dumps({'event':'connected','sid':sid})}\n\n"
        while True:
            try:
                q = output_queues.get(sid)
                if q is None or sid not in sessions:
                    yield "event: session_gone\ndata: {}\n\n"
                    return
                item = q.get(timeout=28)
                yield f"event: {item['event']}\ndata: {item['data']}\n\n"
            except queue.Empty:
                yield ": hb\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/api/session/<sid>/status')
def status(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    return jsonify({
        "completed": sess['completed'], "approved": sess['approved'],
        "skipped": sess['skipped'],
        "finding_counts": {k:len(v) for k,v in sess['findings'].items()},
        "findings": sess['findings'],
        "ports_found": sess.get('ports_found',''),
        "triage_log": sess.get('triage_log', {}),
        "assessment": sess.get('assessment'),
        "roles": [a.get('role') for a in sess.get('accounts', [])],
    })

@app.route('/api/session/<sid>/report')
def report(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    try:
        pdf = build_pdf(sess)
        return send_file(
            pdf, as_attachment=True,
            download_name=f"pwm_report_{sess['target']}_{sid[:8]}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500


@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('X-XSS-Protection', '0')
    if request.path.startswith('/api/'):
        resp.headers.setdefault('Cache-Control', 'no-store')
        resp.headers.setdefault('Content-Security-Policy',
                                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    return resp


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
def json_error(e):
    return jsonify({"error": getattr(e, 'description', 'request failed')}), e.code or 400


@app.errorhandler(500)
def json_500(e):
    app.logger.exception("Unhandled error")
    return jsonify({"error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION & EXPLOIT KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    "open_port":         ("Firewall unused ports with stateful rules. Apply ingress/egress filtering.",
                          "# iptables — block port\niptables -A INPUT -p tcp --dport 8080 -j DROP\n# or ufw\nufw deny 8080"),
    "cve":               ("Apply vendor patch immediately. If unavailable: WAF/IPS virtual patch or upgrade.",
                          "# Check installed version\ndpkg -l <package>\n# Upgrade\napt-get update && apt-get upgrade <package>"),
    "exploit_available": ("Patch to latest stable. Subscribe to vendor security advisories.",
                          "# Ubuntu\napt-get update && apt-get upgrade\n# CentOS/RHEL\nyum update"),
    "web_finding":       ("Remove default files. Disable directory listing. Apply CSP/HSTS/X-Frame-Options.",
                          "# Apache httpd.conf\nServerTokens Prod\nServerSignature Off\nHeader always set X-Frame-Options DENY\nHeader always set X-Content-Type-Options nosniff"),
    "default_cred":      ("Change all default credentials. Implement MFA, account lockout.",
                          "# Linux\npasswd root  # change immediately\n# MySQL\nALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPass!1';"),
    "default_cred_http": ("Enforce strong passwords on admin interfaces. Place behind VPN/IP allowlist + MFA.",
                          "# nginx: restrict admin to internal IP\nlocation /admin {\n  allow 192.168.1.0/24;\n  deny all;\n}"),
    "weak_tls":          ("Disable SSLv2/3 and TLS 1.0/1.1. Use TLS 1.2+ with AEAD ciphers.",
                          "# nginx ssl config\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers off;"),
    "weak_cipher":       ("Remove RC4, DES, 3DES, EXPORT, NULL ciphers. Use Mozilla SSL Config Generator.",
                          "# Apache ssl.conf\nSSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"),
    "heartbleed":        ("Update OpenSSL >= 1.0.1g. Revoke and reissue all TLS certs. Invalidate sessions.",
                          "# Ubuntu\napt-get update && apt-get install --only-upgrade openssl libssl-dev\nopenssl version  # must be >= 1.0.1g"),
    "banner_anomaly":    ("Suppress version banners in server config.",
                          "# Apache\nServerTokens Prod\n# nginx\nserver_tokens off;\n# OpenSSH\n# Edit /etc/ssh/sshd_config\nDebianBanner no"),
    "version_eol":       ("Upgrade to supported version. Subscribe to CVE feed.",
                          "# Check current version and upgrade path\napt-cache policy <package>\napt-get install <package>=<new_version>"),
    "version_outdated":  ("Establish patch SLA. Use automated patching.",
                          "# Auto security updates (Ubuntu)\napt-get install unattended-upgrades\ndpkg-reconfigure unattended-upgrades"),
    "null_session":      ("Disable anonymous RPC. Set RestrictAnonymous=2 in registry.",
                          "# Windows registry (PowerShell)\nSet-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RestrictAnonymous -Value 2"),
    "smb_share":         ("Restrict SMB to authenticated users. Enable SMB signing.",
                          "# Disable SMBv1\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n# Enable signing\nSet-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
    "blind_sqli":        ("Use parameterised queries everywhere. Enable WAF SQLi rules.",
                          "# Python (parameterised)\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n# PHP (PDO)\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $id]);"),
    "sql_injection":     ("Use parameterised queries. Remove verbose DB errors from responses.",
                          "# Node.js (mysql2)\nconn.execute('SELECT * FROM users WHERE email = ?', [email])\n\n# Java (PreparedStatement)\nPreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?');\nps.setInt(1, userId);"),
    "auth_timing_oracle":("Constant-time comparison for auth. Return identical responses.",
                          "# Python — constant time compare\nimport hmac\nif not hmac.compare_digest(provided_hash, stored_hash):\n    return 'Invalid credentials'"),
    "timing_anomaly":    ("Audit timing-dependent auth. Jitter response times.",
                          "# Add random jitter to prevent timing attacks\nimport time, random\ntime.sleep(random.uniform(0.1, 0.3))  # add to auth handler"),
    "path_traversal":    ("Validate all file path inputs. Chroot to webroot.",
                          "# Python — safe path join\nimport os\ndef safe_open(base, user_path):\n    full = os.path.realpath(os.path.join(base, user_path))\n    if not full.startswith(base):\n        raise ValueError('Path traversal detected')\n    return open(full)"),
    "host_header_injection":("Whitelist valid Host headers in reverse proxy.",
                              "# nginx\nserver {\n  if ($host !~* ^(yourdomain\\.com|www\\.yourdomain\\.com)$) {\n    return 444;\n  }\n}"),
    "snmp_public":       ("Change community strings. Upgrade to SNMPv3.",
                          "# /etc/snmp/snmpd.conf — remove public, set strong community\nrocommunity StrongSecret 127.0.0.1\n# Or use SNMPv3\ncreateUser myuser SHA 'AuthPass' AES 'PrivPass'"),
    "protocol_vuln":     ("Disable unused protocol features. Restrict to trusted IPs.",
                          "# DNS — disable recursion (BIND)\noptions { recursion no; };\n# NTP — disable monlist\nrestrict default kod nomodify nopeer noquery"),
    "bola_idor":         ("Implement server-side object-level authorisation checks on every request.",
                          "# Python (Flask example)\n@app.route('/api/v1/users/<int:user_id>')\n@login_required\ndef get_user(user_id):\n    if current_user.id != user_id and not current_user.is_admin:\n        abort(403)  # enforce ownership\n    return jsonify(User.query.get_or_404(user_id).to_dict())"),
    "broken_auth":       ("Validate JWTs server-side. Reject alg=none. Use short-lived tokens.",
                          "# Python (PyJWT) — always specify algorithm\nimport jwt\npayload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # never ['none']"),
    "unauth_endpoint":   ("Apply auth middleware to all API routes. Deny-by-default.",
                          "# Express.js — global auth middleware\napp.use('/api', (req, res, next) => {\n  if (!req.headers.authorization) return res.status(401).json({error:'Unauthorized'});\n  next();\n});"),
    "api_endpoint":      ("Restrict Swagger/OpenAPI docs in production. Require auth for actuator.",
                          "# Spring Boot — disable actuator endpoints\nmanagement.endpoints.web.exposure.include=health\nmanagement.endpoint.env.enabled=false"),
    "graphql_introspection":("Disable introspection in production GraphQL.",
                              "# Apollo Server\nconst server = new ApolloServer({\n  introspection: process.env.NODE_ENV !== 'production'\n});"),
    "ssrf":              ("Validate and whitelist URL parameters. Block internal IP ranges.",
                          "# Python — SSRF mitigation\nimport ipaddress, urllib.parse\ndef is_safe_url(url):\n    host = urllib.parse.urlparse(url).hostname\n    try:\n        ip = ipaddress.ip_address(host)\n        if ip.is_private or ip.is_loopback: raise ValueError\n    except: pass\n    return True"),
    "mass_assignment":   ("Use allowlists for fields that users can modify. Never bind raw request body.",
                          "# Django — use explicit field serializer\nclass UserUpdateSerializer(serializers.ModelSerializer):\n    class Meta:\n        model = User\n        fields = ['display_name', 'bio']  # never 'role' or 'is_admin'"),
    "broken_function_auth":("Check function-level permissions separately from object-level.",
                             "# Python decorator for role check\nfrom functools import wraps\ndef require_role(role):\n    def decorator(f):\n        @wraps(f)\n        def wrapper(*args, **kwargs):\n            if current_user.role != role: abort(403)\n            return f(*args, **kwargs)\n        return wrapper\n    return decorator\n\n@app.route('/api/v1/admin/users')\n@require_role('admin')\ndef admin_users(): ..."),
    "api_cors_wildcard": ("Set specific CORS origins. Never use wildcard in production.",
                          "# Express.js\nconst cors = require('cors');\napp.use(cors({\n  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n  credentials: true\n}));"),
    "missing_rate_limit":("Implement rate limiting on all API endpoints.",
                          "# Express.js\nconst rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({ windowMs: 15*60*1000, max: 100 });\napp.use('/api/', limiter);"),
    "api_key_exposure":  ("Remove secrets from API responses. Use secrets manager.",
                          "# Use environment variables — never hardcode\nimport os\nAPI_KEY = os.environ['STRIPE_API_KEY']\n\n# .env file (never commit)\nSTRIPE_API_KEY=sk_live_..."),
    "verbose_error":     ("Return generic error messages to clients. Log details server-side only.",
                          "# Express.js global error handler\napp.use((err, req, res, next) => {\n  console.error(err.stack);  // log full error\n  res.status(500).json({ error: 'Internal server error' });  // generic to client\n});"),
    "db_exposed":        ("Bind database to localhost only. Use SSH tunnel or VPN for remote access.",
                          "# MySQL — bind to localhost in /etc/mysql/my.cnf\n[mysqld]\nbind-address = 127.0.0.1\n\n# Redis — /etc/redis/redis.conf\nbind 127.0.0.1"),
    "db_unauth_access":  ("Enable authentication on all database services immediately.",
                          "# Redis — set password in /etc/redis/redis.conf\nrequirepass YourStrongPassword123!\n\n# MongoDB — enable auth in /etc/mongod.conf\nsecurity:\n  authorization: 'enabled'"),
    "db_default_cred":   ("Change all default DB credentials. Enforce password complexity.",
                          "# MySQL\nALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongP@ss!23';\nDELETE FROM mysql.user WHERE User='';\nFLUSH PRIVILEGES;\n\n# PostgreSQL\npsql -c \"ALTER USER postgres PASSWORD 'StrongPass!';\""),
    "nosql_injection":   ("Use query builders. Never pass raw user input to $where or operators.",
                          "# Node.js (mongoose) — sanitise operator injection\nconst mongoSanitize = require('express-mongo-sanitize');\napp.use(mongoSanitize());\n\n// Alternatively: explicitly cast input\nUser.findOne({ username: String(req.body.username) })"),
    "db_excessive_priv": ("Grant minimum required privileges. Revoke FILE/SUPER/GRANT where unnecessary.",
                          "# MySQL — least privilege\nCREATE USER 'appuser'@'localhost' IDENTIFIED BY 'pass';\nGRANT SELECT, INSERT, UPDATE ON mydb.* TO 'appuser'@'localhost';\n-- Never GRANT ALL or FILE privilege to app user"),
    "db_no_audit_log":   ("Enable query logging and audit trail.",
                          "# MySQL — enable general log\n[mysqld]\ngeneral_log = 1\ngeneral_log_file = /var/log/mysql/general.log\nslow_query_log = 1"),
    "db_unencrypted_conn":("Enable TLS for all database connections.",
                            "# MySQL ssl config\n[mysqld]\nssl-ca=/etc/mysql/ca.pem\nssl-cert=/etc/mysql/server-cert.pem\nssl-key=/etc/mysql/server-key.pem\n\n[client]\nssl-mode=REQUIRED"),
    "verbose_db_error":  ("Suppress DB errors in application responses.",
                          "# PHP — disable error display\nini_set('display_errors', '0');\nini_set('log_errors', '1');\n\n# Python/Django\nDEBUG = False  # in production settings.py"),
    "redis_no_auth":     ("Set requirepass in redis.conf and restart.",
                          "# /etc/redis/redis.conf\nrequirepass 'YourStrongRedisPassword!'\n\n# After restart, verify:\nredis-cli AUTH YourStrongRedisPassword!"),
    "redis_data_exposure":("Disable KEYS command. Use SCAN. Encrypt sensitive cached data.",
                            "# redis.conf — rename dangerous commands\nrename-command KEYS \"\"\nrename-command CONFIG \"\"\nrename-command FLUSHALL \"\""),
    "cookie_flags":      ("Set HttpOnly, Secure, SameSite=Strict on all session cookies.",
                          "# Express.js\napp.use(session({\n  secret: 'strong-secret',\n  cookie: { httpOnly: true, secure: true, sameSite: 'strict' }\n}));\n\n# PHP\nsession_set_cookie_params(['httponly'=>true,'secure'=>true,'samesite'=>'Strict']);"),
    "missing_headers":   ("Add all security headers to all responses.",
                          "# nginx\nadd_header X-Frame-Options 'DENY';\nadd_header X-Content-Type-Options 'nosniff';\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';\nadd_header Content-Security-Policy \"default-src 'self'\";"),
    "generic":           ("Review against OWASP Top-10 and CIS Benchmarks.",
                          "# Run authenticated scan\nnmap -sV --script=auth,vuln -p- <target>"),
}

EXPLOIT_HOW = {
    "open_port":        "Scan open ports to match service versions to ExploitDB/Metasploit modules.",
    "cve":              "Use matching Metasploit module or public PoC. Check NVD for CVSS vector and attack path.",
    "exploit_available":"Retrieve with `searchsploit -m <id>`, modify LHOST/RHOST, execute.",
    "web_finding":      "Misconfigs chain: info disclosure → credential harvest → auth bypass → RCE.",
    "default_cred":     "Authenticate with leaked cred, gain shell, pivot laterally.",
    "weak_tls":         "POODLE/BEAST downgrade attack decrypts traffic in MITM position.",
    "weak_cipher":      "RC4/3DES broken — MITM attacker decrypts in minutes.",
    "heartbleed":       "Send malformed heartbeat — leaks up to 64KB RAM per request (keys, sessions).",
    "banner_anomaly":   "Verbose banners feed directly into CVE/exploit matching.",
    "version_eol":      "All CVEs after EOL date are permanently unpatched on this build.",
    "blind_sqli":       "Time-based blind SQLi → dump DB → credential extraction → possible OS RCE.",
    "sql_injection":    "Error-based SQLi confirms injection — use sqlmap to dump databases.",
    "auth_timing_oracle":"Username enumeration via timing enables targeted password spraying.",
    "path_traversal":   "LFI /etc/passwd → /etc/shadow → SSH keys → log poisoning → RCE.",
    "host_header_injection":"Reflected Host enables cache poisoning, password reset hijacking, SSRF.",
    "bola_idor":        "Increment/change object IDs to access other users' data without authorization.",
    "broken_auth":      "alg=none JWT → forge any identity. Null token → auth bypass.",
    "ssrf":             "Internal metadata (AWS IMDS) → cloud credentials → full account takeover.",
    "mass_assignment":  "Send role=admin in body → privilege escalation without breaking any auth.",
    "nosql_injection":  "$gt/$ne operator bypass → login without credentials.",
    "db_unauth_access": "Direct DB access → dump all data, insert backdoor users, exfiltrate PII.",
    "db_default_cred":  "Login with default creds → full DB read/write → OS command via xp_cmdshell/UDF.",
    "redis_no_auth":    "CONFIG SET dir / CONFIG SET dbfilename → write SSH authorized_keys → root.",
    "protocol_vuln":    "Open relay, anon bind, DNS recursion → amplification/data exfiltration.",
    "generic":          "Manual analysis required in controlled environment.",
}


# ─────────────────────────────────────────────────────────────────────────────
# PDF BUILDER — full detailed report
# ─────────────────────────────────────────────────────────────────────────────
SEV_C = {
    "critical": colors.HexColor('#c53030'),
    "high":     colors.HexColor('#c05621'),
    "medium":   colors.HexColor('#b7791f'),
    "low":      colors.HexColor('#276749'),
    "info":     colors.HexColor('#2b6cb0'),
}
SEV_BG = {
    "critical": colors.HexColor('#fff5f5'),
    "high":     colors.HexColor('#fffaf0'),
    "medium":   colors.HexColor('#fffff0'),
    "low":      colors.HexColor('#f0fff4'),
    "info":     colors.HexColor('#ebf8ff'),
}

def build_pdf(sess: dict) -> str:
    path = f"{sess['outdir']}/report_{sess['sid'][:8]}.pdf"
    W = A4[0] - 3.6*cm

    doc = SimpleDocTemplate(path, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm, bottomMargin=1.8*cm,
        title=f"Pentest Report — {sess['target']}")

    S = getSampleStyleSheet()
    def sty(name, **kw):
        return ParagraphStyle(name, **kw)

    N    = sty('N',  fontName='Helvetica',      fontSize=9,  leading=13)
    H1   = sty('H1', fontName='Helvetica-Bold', fontSize=20, spaceAfter=6,  textColor=colors.HexColor('#0d1117'))
    H2   = sty('H2', fontName='Helvetica-Bold', fontSize=13, spaceAfter=4,  spaceBefore=14, textColor=colors.HexColor('#0366d6'))
    H3   = sty('H3', fontName='Helvetica-Bold', fontSize=11, spaceAfter=3,  spaceBefore=8,  textColor=colors.HexColor('#24292e'))
    H4   = sty('H4', fontName='Helvetica-Bold', fontSize=9.5,spaceAfter=2,  spaceBefore=5,  textColor=colors.HexColor('#444d56'))
    META = sty('MT', fontName='Helvetica-Oblique', fontSize=8.5, textColor=colors.HexColor('#586069'))
    CODE = sty('CO', fontName='Courier-Bold', fontSize=8.5,
               backColor=colors.HexColor('#f6f8fa'),
               textColor=colors.HexColor('#1f2328'),
               borderColor=colors.HexColor('#d0d7de'), borderWidth=0.75,
               borderPadding=8, leading=13, leftIndent=4)
    WARN = sty('WN', fontName='Helvetica-Oblique', fontSize=8,
               textColor=colors.HexColor('#b31d28'),
               backColor=colors.HexColor('#ffeef0'), borderPadding=5)
    LABEL = sty('LB', fontName='Helvetica-Bold', fontSize=8,
                textColor=colors.HexColor('#586069'))
    SEC  = sty('SEC', fontName='Helvetica-Bold', fontSize=10,
               spaceBefore=8, spaceAfter=2, textColor=colors.HexColor('#0366d6'))

    story = []
    all_f = [f for flist in sess['findings'].values() for f in flist]
    sc = {s: sum(1 for f in all_f if f.get('severity')==s)
          for s in ['critical','high','medium','low','info']}

    # ── COVER ─────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 0.8*cm),
        Paragraph("PENETRATION TEST REPORT", H1),
        HRFlowable(width="100%", thickness=3, color=colors.HexColor('#0366d6')),
        Spacer(1, 0.4*cm),
    ]
    cover_meta = [
        ["Target",        sess['raw_target']],
        ["Resolved Host", sess['target']],
        ["Target Type",   sess['target_type'].upper()],
        ["Scan Date",     sess['created'][:10]],
        ["Session ID",    sess['sid'][:8]],
        ["Stages Run",    str(len(sess['completed']))],
        ["Total Findings",str(len(all_f))],
        ["Critical",      str(sc.get('critical',0))],
        ["High",          str(sc.get('high',0))],
        ["Medium",        str(sc.get('medium',0))],
    ]
    cm_t = Table(cover_meta, colWidths=[4*cm, W-4*cm])
    cm_t.setStyle(TableStyle([
        ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'), ('FONTNAME',(1,0),(1,-1),'Helvetica'),
        ('FONTSIZE',(0,0),(-1,-1),9),
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
        ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
        ('TOPPADDING',(0,0),(-1,-1),4), ('BOTTOMPADDING',(0,0),(-1,-1),4),
    ]))
    story += [cm_t, Spacer(1,0.4*cm),
              Paragraph("⚠ AUTHORISED USE ONLY — Confidential. For the named recipient only.", WARN),
              PageBreak()]

    # ── EXEC SUMMARY ──────────────────────────────────────────────────────
    story += [
        Paragraph("1. Executive Summary", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
        Spacer(1,0.2*cm),
    ]
    sla = {"critical":("Immediate","24 hours"),"high":("High","7 days"),
           "medium":("Medium","30 days"),"low":("Low","90 days"),"info":("Informational","Next cycle")}
    sev_rows = [["Severity","Count","Risk","Remediation SLA"]]
    for s in ["critical","high","medium","low","info"]:
        sev_rows.append([s.upper(), str(sc.get(s,0)), sla[s][0], sla[s][1]])
    st = Table(sev_rows, colWidths=[4*cm,2.5*cm,4*cm,6*cm])
    sev_ts = [
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTNAME',(0,1),(-1,-1),'Helvetica'),
        ('FONTSIZE',(0,0),(-1,-1),9),
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0366d6')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
        ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
    ]
    for i,s in enumerate(['critical','high','medium','low','info'],1):
        sev_ts += [('TEXTCOLOR',(0,i),(0,i),SEV_C[s]),('FONTNAME',(0,i),(0,i),'Helvetica-Bold')]
    st.setStyle(TableStyle(sev_ts))
    story += [st, Spacer(1,0.3*cm)]

    # ── VULNERABILITY INDEX ────────────────────────────────────────────────
    story += [
        Paragraph("2. Vulnerability Index", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
        Spacer(1,0.15*cm),
    ]
    idx_rows = [["#","Severity","Type","Path / Location","Stage"]]
    crit_high = [f for f in all_f if f.get('severity') in ('critical','high','medium')]
    for i, f in enumerate(crit_high[:60], 1):
        ftype = f.get('type','').replace('_',' ')
        detail = (f.get('detail') or f.get('cve') or '')[:60]
        fpath_idx = f.get('path','—')[:50]
        stage_name = '—'
        for stage in CHAIN:
            for sub in stage['substages']:
                if sub['id'] in sess['findings'] and f in sess['findings'][sub['id']]:
                    stage_name = stage['label'].replace('Stage ','S').split(' ')[0]
        idx_rows.append([str(i), f.get('severity','info').upper(), ftype[:25], fpath_idx, stage_name])
    if len(idx_rows) > 1:
        idx_t = Table(idx_rows, colWidths=[0.7*cm,2*cm,3.5*cm,7.5*cm,2.8*cm])
        idx_ts = [
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#24292e')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]
        for ri, f in enumerate(crit_high[:60], 1):
            c = SEV_C.get(f.get('severity','info'), colors.black)
            idx_ts += [('TEXTCOLOR',(1,ri),(1,ri),c),('FONTNAME',(1,ri),(1,ri),'Helvetica-Bold')]
        idx_t.setStyle(TableStyle(idx_ts))
        story += [idx_t, Spacer(1,0.3*cm)]
    story.append(PageBreak())

    # ── DETAILED FINDINGS ─────────────────────────────────────────────────
    story += [
        Paragraph("3. Detailed Findings with PoC & Remediation", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
    ]
    finding_num = 0
    for stage in CHAIN:
        stage_findings_exist = any(
            sess['findings'].get(sub['id']) for sub in stage['substages']
        )
        if not stage_findings_exist:
            continue
        story.append(Paragraph(stage['label'], H2))

        for sub in stage['substages']:
            sub_findings = sess['findings'].get(sub['id'], [])
            if not sub_findings:
                continue
            stat = ("COMPLETED" if sub['id'] in sess['completed'] else
                    "SKIPPED" if sub['id'] in sess['skipped'] else "NOT RUN")
            story.append(Paragraph(
                f"{sub['label']} <font color='#586069' size='7.5'>[{stat}]</font>", H3))
            story.append(Paragraph(sub['description'], META))
            note = sess['notes'].get(sub['id'],'')
            if note:
                story.append(Paragraph(f"<b>Operator note:</b> {html.escape(note)}", META))
            story.append(Spacer(1,0.15*cm))

            for f in sub_findings:
                sev = f.get('severity','info')
                if sev not in ('critical','high','medium','low','info'):
                    sev = 'info'
                finding_num += 1
                ftype = f.get('type','generic')
                detail = f.get('detail') or f.get('cve') or f.get('line') or ''
                fpath = f.get('path','—')
                cmd = f.get('command') or sess['commands'].get(sub['id']) or '—'
                rem_tuple = REMEDIATION.get(ftype, REMEDIATION['generic'])
                rem_text, rem_code = (rem_tuple if isinstance(rem_tuple, tuple)
                                      else (rem_tuple, '# See vendor documentation'))
                exploit = EXPLOIT_HOW.get(ftype, EXPLOIT_HOW['generic'])

                # finding header bar
                hdr_data = [[
                    Paragraph(f"<b>#{finding_num}</b>", LABEL),
                    Paragraph(f"<b>{html.escape(detail[:120])}</b>", sty('FH',
                        fontName='Helvetica-Bold', fontSize=9,
                        textColor=SEV_C.get(sev, colors.black))),
                    Paragraph(sev.upper(), sty('SV',
                        fontName='Helvetica-Bold', fontSize=8,
                        textColor=colors.white,
                        backColor=SEV_C.get(sev, colors.gray),
                        borderPadding=3)),
                ]]
                hdr_t = Table(hdr_data, colWidths=[1*cm, W-4*cm, 3*cm])
                hdr_t.setStyle(TableStyle([
                    ('BACKGROUND',(0,0),(-1,-1),SEV_BG.get(sev, colors.white)),
                    ('BOX',(0,0),(-1,-1),0.8,SEV_C.get(sev,colors.gray)),
                    ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                    ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
                ]))

                # detail rows
                cvss = f.get('cvss', {}) or {}
                triage = f.get('triage', {}) or {}
                cvss_line = (f"CVSS {cvss.get('base_score','—')} ({cvss.get('severity_band','—')})"
                             + ("  ⚠ BAND MISMATCH" if cvss.get('band_mismatch') else ""))
                vector_line = cvss.get('vector') or '—'
                triage_line = triage.get('verdict', '—')
                if triage.get('provenance') == 'analyst':
                    triage_line += "  (operator overridden)"
                detail_rows = [
                    ["Type",         ftype.replace('_',' ').title()],
                    ["Path/Location",fpath],
                    ["CVSS v3.1",    cvss_line],
                    ["CVSS Vector",  vector_line],
                    ["Triage",       triage_line],
                    ["Detection Cmd",cmd],
                    ["How Exploited", exploit],
                    ["Remediation",  rem_text],
                ]
                std_bits = [x for x in (f.get('owasp'), f.get('cwe'), f.get('attack')) if x]
                if std_bits:
                    detail_rows.insert(5, ["Standards", " · ".join(std_bits)])
                if f.get('role'):
                    detail_rows.insert(1, ["Tested Role", f['role']])
                evidence = f.get('evidence', {}) or {}
                ev_paths = []
                if isinstance(evidence, dict):
                    ev_paths = [os.path.basename(x) for x in evidence.get('screenshots', [])]
                    if evidence.get('pcap'):
                        ev_paths.append(os.path.basename(evidence['pcap']))
                if ev_paths:
                    detail_rows.append(["Evidence", ", ".join(ev_paths)])
                det_t = Table(detail_rows, colWidths=[3*cm, W-3*cm])
                det_t.setStyle(TableStyle([
                    ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),
                    ('FONTNAME',(1,0),(1,-1),'Helvetica'),
                    ('FONTSIZE',(0,0),(-1,-1),8.5),
                    ('LEADING',(0,0),(-1,-1),12),
                    ('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.HexColor('#fafbfc'),colors.white]),
                    ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
                    ('VALIGN',(0,0),(-1,-1),'TOP'),
                    ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
                ]))

                # PoC / code fix
                poc_title = Paragraph("Proof of Concept / Detection", SEC)
                poc_code  = Preformatted(cmd if cmd and cmd != '—' else '# No detection command recorded.', CODE)
                fix_title = Paragraph("Remediation Code Example", SEC)
                fix_code  = Preformatted(rem_code if rem_code and rem_code != '#' else '# See vendor documentation.', CODE)

                story.append(KeepTogether([
                    hdr_t, Spacer(1,3),
                    det_t, Spacer(1,3),
                    poc_title, poc_code, Spacer(1,3),
                    fix_title, fix_code,
                    Spacer(1,0.3*cm),
                ]))

    story.append(PageBreak())

    # ── API VULNERABILITY SUMMARY ─────────────────────────────────────────
    api_findings = []
    for stage in CHAIN:
        if stage['id'] in ('api_scan',):
            for sub in stage['substages']:
                api_findings.extend(sess['findings'].get(sub['id'], []))

    if api_findings:
        story += [Paragraph("4. API Vulnerability Summary (OWASP API Top-10)", H2),
                  HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
                  Spacer(1,0.15*cm)]
        api_map = {
            'bola_idor':          'API1 — Broken Object Level Authorization (BOLA/IDOR)',
            'broken_auth':        'API2 — Broken Authentication',
            'unauth_endpoint':    'API2 — Broken Authentication (unprotected endpoint)',
            'mass_assignment':    'API3 — Broken Object Property Level Authorization',
            'missing_rate_limit': 'API4 — Unrestricted Resource Consumption',
            'broken_function_auth':'API5 — Broken Function Level Authorization',
            'sql_injection':      'API8 — Security Misconfiguration / Injection',
            'nosql_injection':    'API8 — Security Misconfiguration / NoSQL Injection',
            'ssrf':               'API7 — Server-Side Request Forgery (SSRF)',
            'api_endpoint':       'API9 — Improper Inventory Management',
            'graphql_introspection':'API9 — Improper Inventory Management',
            'api_cors_wildcard':  'API8 — Security Misconfiguration (CORS)',
            'api_key_exposure':   'API10 — Unsafe Consumption of Third-Party APIs',
            'verbose_error':      'API8 — Security Misconfiguration (Verbose Errors)',
        }
        for f in api_findings:
            ftype = f.get('type','generic')
            owasp = api_map.get(ftype, 'API — Other')
            sev = f.get('severity','info')
            story.append(KeepTogether([
                Paragraph(f"<b>{owasp}</b> — <font color='{SEV_C.get(sev,colors.black).hexval() if hasattr(SEV_C.get(sev,colors.black),'hexval') else '#333333'}'>{sev.upper()}</font>", sty('AI', fontName='Helvetica-Bold', fontSize=9, spaceBefore=6)),
                Paragraph(f"<b>Path:</b> {html.escape(f.get('path','—'))}", N),
                Paragraph(f"<b>Detail:</b> {html.escape(f.get('detail','')[:200])}", N),
                Paragraph(f"<b>Command:</b> {html.escape(f.get('command','—'))}", META),
                Spacer(1,0.15*cm),
            ]))
        story.append(PageBreak())

    # ── DATABASE VULNERABILITY SUMMARY ────────────────────────────────────
    db_findings = []
    for stage in CHAIN:
        if stage['id'] == 'db_scan':
            for sub in stage['substages']:
                db_findings.extend(sess['findings'].get(sub['id'], []))

    if db_findings:
        story += [Paragraph("5. Database Vulnerability Summary", H2),
                  HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
                  Spacer(1,0.15*cm)]
        for f in db_findings:
            sev = f.get('severity','info')
            story.append(KeepTogether([
                Paragraph(f"<b>{f.get('type','').replace('_',' ').upper()}</b>", sty('DT', fontName='Helvetica-Bold', fontSize=9, spaceBefore=6, textColor=SEV_C.get(sev,colors.black))),
                Paragraph(f"<b>Severity:</b> {sev.upper()} &nbsp; <b>Path:</b> {html.escape(f.get('path','—'))}", N),
                Paragraph(f"<b>Detail:</b> {html.escape(f.get('detail','')[:250])}", N),
                Paragraph(f"<b>Detection Command:</b> {html.escape(f.get('command','—'))}", META),
                Spacer(1,0.15*cm),
            ]))
        story.append(PageBreak())

    # ── CVSS SCORING & FALSE-POSITIVE TRIAGE ───────────────────────────────
    all_scored = [f for f in all_f if f.get('cvss', {}).get('base_score')]
    if all_scored or sess.get('assessment'):
        story += [
            Paragraph("6. CVSS Scoring & False-Positive Triage", H2),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
            Spacer(1,0.15*cm),
        ]
        if sess.get('assessment'):
            for ln in sess['assessment'].splitlines()[:60]:
                story.append(Paragraph(html.escape(ln), META)
                             if ('—' in ln or '|' in ln or 'cvss=' in ln)
                             else Preformatted(ln, CODE))
            story.append(Spacer(1,0.2*cm))
        t_rows = [["Type","Severity","CVSS","Band","Triage","Path"]]
        for f in all_scored[:60]:
            cvss = f.get('cvss', {})
            tgt = f.get('triage', {})
            t_rows.append([
                f.get('type','').replace('_',' ')[:22],
                f.get('severity','info').upper(),
                str(cvss.get('base_score','—')),
                cvss.get('severity_band','—') or '—',
                tgt.get('verdict','—'),
                (f.get('path') or '—')[:30],
            ])
        t_t = Table(t_rows, colWidths=[3.2*cm,1.8*cm,1.4*cm,1.8*cm,2.6*cm,5.7*cm])
        t_t.setStyle(TableStyle([
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),7.5),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#2d3748')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story += [t_t, Spacer(1,0.2*cm),
                  Paragraph("Confirmed findings carry an explicit CVSS v3.1 vector; values come from the "
                            "computed vector or from NVD for CVE-sourced findings.", META)]
        story.append(PageBreak())

    # ── STANDARDS MAPPING ─────────────────────────────────────────────────
    mapped = sorted({f.get('type') for f in all_f if f.get('type') in STANDARDS})
    if mapped:
        story += [
            Paragraph("7. Standards Mapping (OWASP 2021 · CWE · MITRE ATT&CK)", H2),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
            Spacer(1,0.15*cm),
        ]
        s_rows = [["Finding Type", "OWASP Top 10 (2021)", "CWE", "ATT&CK"]]
        for t in mapped:
            ow, cw = STANDARDS[t]
            s_rows.append([t.replace('_',' ')[:26], ow[:34], cw, ATTACK_BY_TYPE.get(t, '—')])
        st2 = Table(s_rows, colWidths=[4.4*cm,6.2*cm,2.2*cm,2.7*cm])
        st2.setStyle(TableStyle([
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#2d3748')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story += [st2, Spacer(1,0.2*cm),
                  Paragraph("Informational/discovery findings are intentionally left unclassified; "
                            "signature-dependent findings are marked indeterminate pending per-evidence "
                            "verification. No vulnerability category is asserted without evidence.", META),
                  PageBreak()]

    # ── ACCOUNT-TAKEOVER CHAIN ────────────────────────────────────────────
    ato_f = [f for f in all_f if f.get('ato')]
    if ato_f:
        story += [
            Paragraph("8. Account-Takeover Chain — Attacker Actions → Detections", H2),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
            Spacer(1,0.15*cm),
            Paragraph("Findings that individually or chained can lead to account takeover, with "
                      "concrete detection guidance for defenders.", META),
            Spacer(1,0.15*cm),
        ]
        a_rows = [["Finding", "Attacker Action", "Detection"]]
        seen = set()
        for f in ato_f:
            t = f.get('type')
            if t in seen:
                continue
            seen.add(t)
            a_rows.append([t.replace('_',' ')[:22], f['ato']['action'], f['ato']['detection']])
        at = Table(a_rows, colWidths=[3.2*cm,6.3*cm,6*cm])
        at.setStyle(TableStyle([
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#7d1d1d')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#fff5f5')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story += [at, Spacer(1,0.2*cm), PageBreak()]

    # ── RAW TOOL OUTPUT ───────────────────────────────────────────────────
    story += [
        Paragraph("9. Raw Tool Output", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
    ]
    for stage in CHAIN:
        for sub in stage['substages']:
            out = sess['outputs'].get(sub['id'],'')
            if not out: continue
            story.append(Paragraph(f"{stage['label']} › {sub['label']}", H3))
            lines = out.splitlines()[:50]
            if len(out.splitlines()) > 50:
                lines.append(f'... [{len(out.splitlines())-50} lines truncated]')
            story.append(Preformatted('\n'.join(lines), CODE))
            story.append(Spacer(1,0.1*cm))
    story.append(PageBreak())

    # ── ZERO-DAY APPENDIX ─────────────────────────────────────────────────
    ZDAY_TYPES = {'banner_anomaly','version_eol','version_outdated','blind_sqli',
                  'auth_timing_oracle','timing_anomaly','path_traversal',
                  'host_header_injection','protocol_mismatch','signature_match',
                  'ssrf','nosql_injection','redis_no_auth'}
    zday = [f for f in all_f if f.get('type') in ZDAY_TYPES]
    story += [Paragraph("Appendix A — Zero-Day & Unknown Vulnerability Surface", H2),
              HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
              Spacer(1,0.15*cm)]
    if zday:
        z_rows = [["#","Type","Path","Detail","Sev"]]
        for i,f in enumerate(zday[:30],1):
            z_rows.append([str(i), f.get('type','').replace('_',' ')[:20],
                f.get('path','—')[:30], (f.get('detail',''))[:80],
                f.get('severity','info').upper()])
        zt = Table(z_rows, colWidths=[0.7*cm,3.5*cm,3*cm,8*cm,2*cm])
        zt.setStyle(TableStyle([
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),7.5),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a2332')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#30a0ff')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story += [zt, Spacer(1,0.2*cm)]
    else:
        story.append(Paragraph("No zero-day surface findings detected in this session.", META))

    # footer
    story += [
        Spacer(1,0.5*cm),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC | "
            f"Pentest Workflow Manager v4 | Session {sess['sid'][:8]} | "
            "AUTHORISED USE ONLY",
            ParagraphStyle('FT', fontName='Helvetica', fontSize=7,
                           textColor=colors.HexColor('#586069'), alignment=TA_CENTER))
    ]

    doc.build(story)
    return path


if __name__ == '__main__':
    print(f"Pentest Workflow Manager v4 → http://{PWM_BIND}:{PWM_PORT}")
    print(f"  Overrides: PWM_BIND (default 127.0.0.1), PWM_PORT (default 5000), PWM_SECRET_KEY, PWM_API_TOKEN")
    print(f"  Command timeout: PWM_CMD_TIMEOUT={PWM_CMD_TIMEOUT:g}s default — 0 = no timeout (per-substage overrides only when >0)")

    def _janitor():
        import time as _t
        while True:
            try:
                _t.sleep(300)
                stale = []
                # Snapshot the dict: iterating sessions.items() directly raced
                # with request threads and killed this thread permanently.
                for sid, sess in list(sessions.items()):
                    created = datetime.fromisoformat(sess.get('created', '')) if sess.get('created') else None
                    if created and (_t.time() - created.timestamp()) > 6 * 3600:
                        stale.append(sid)
                for sid in stale:
                    sess = sessions.get(sid)
                    if sess:
                        with sess['lock']:
                            if sessions.get(sid) is not sess:
                                continue
                            if output_queues.get(sid) is not None:
                                push(sid, "session_gone", {})
                            output_queues.pop(sid, None)
                            sessions.pop(sid, None)
                        shutil.rmtree(sess['outdir'], ignore_errors=True)
                        print(f"[janitor] purged stale session {sid}")
            except Exception as e:
                # Never let one transient failure stop cleanup forever.
                print(f"[janitor] error: {e!r}", flush=True)

    threading.Thread(target=_janitor, daemon=True).start()
    app.run(debug=False, threaded=True, host=PWM_BIND, port=PWM_PORT)
