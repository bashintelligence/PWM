#!/usr/bin/env python3
"""Verify the PWM audit fixes against real tool output shapes."""
import base64
import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app  # noqa: E402

TMP = tempfile.mkdtemp(prefix='pwm_test_')

PASS = FAIL = 0
def check(name, cond, extra=''):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name} {extra}")

print("== parse_nmap ==")
out = """
PORT     STATE         SERVICE   VERSION
22/tcp   open          ssh
80/tcp   open          http      nginx 1.18.0
443/tcp  closed        https
53/udp   open|filtered domain
161/udp  open          snmp
"""
f = app.parse_nmap(out)
by = {(x['port'], x['proto']): x for x in f}
check("version-less open port kept (22/tcp)", ('22','tcp') in by, by.keys())
check("versioned open port kept (80/tcp)", by.get(('80','tcp'), {}).get('version') == 'nginx 1.18.0')
check("open UDP port kept (161/udp)", ('161','udp') in by)
check("open|filtered NOT a finding", ('53','udp') not in by)
check("closed NOT a finding", ('443','tcp') not in by)
check("detail has no trailing space/no false version",
      by[('22','tcp')]['detail'].strip() == '22/tcp ssh', by[('22','tcp')]['detail'])

print("== ports_found extraction ==")
import re
pat = r'(?m)^(\d+)/tcp\s+open(?!\|)'
got = re.findall(pat, "80/tcp   open  http\n8443/tcp open|filtered https-alt\n22/tcp open ssh")
check("open|filtered excluded from ports_found", got == ['80', '22'], got)

print("== db_exposed gate ==")
db = {x['path'] for x in app.parse_db_discovery("3306/tcp open|filtered mysql\n6379/tcp open redis")}
check("open|filtered DB port not claimed exposed", db == {':6379'}, db)

print("== sig_matches ==")
def msgs(o): return [m for m, _ in app.sig_matches(o)]
check("TLSv1.0 disabled -> no finding", msgs("TLSv1.0:  disabled") == [], msgs("TLSv1.0:  disabled"))
check("TLSv1.1 not supported -> no finding", msgs("TLSv1.1   not supported") == [])
check("TLSv1.0 enabled -> finding", "Deprecated TLS/SSL protocol enabled" in msgs("TLSv1.0:  enabled"))
check("RC4 rejected -> no weak-cipher finding", "Weak cipher suite enabled" not in msgs("RC4:  rejected"))
check("RC4 accepted -> weak-cipher finding", "Weak cipher suite enabled" in msgs("Accepted  TLSv1.2  128 bits  RC4-SHA"))
check("not vulnerable to heartbleed -> nothing", msgs("TLSv1.2:  not vulnerable to heartbleed") == [],
      msgs("TLSv1.2:  not vulnerable to heartbleed"))
check("script VULNERABLE -> heartbleed finding",
      any('Heartbleed' in m for m in msgs("State: VULNERABLE")))
check("searchsploit title mentioning Heartbleed -> no finding",
      msgs("OpenSSL 1.0.1 - Heartbleed | exploits/linux/remote/1.py") == [],
      msgs("OpenSSL 1.0.1 - Heartbleed | exploits/linux/remote/1.py"))
check("CVE id alone in a vulners row -> no heartbleed finding",
      msgs("CVE-2014-0160  5.0  https://vulners.com/cve/CVE-2014-0160") == [])

print("== _jwt_header ==")
def jwt(hdr_obj, pad=False):
    b = base64.urlsafe_b64encode(json.dumps(hdr_obj, separators=(',', ':')).encode()).decode()
    if not pad: b = b.rstrip('=')
    return b + '.eyJzdWIiOiIxIn0.sig'
for obj in ({"alg": "HS256"}, {"alg": "RS256", "kid": "a"}, {"alg": "HS256", "typ": "JWT"}):
    check(f"decode {obj} (unpadded)", app._jwt_header(jwt(obj)) == obj)
    check(f"decode {obj} (padded segment)", app._jwt_header(jwt(obj, pad=True)) == obj)
check("garbage header -> {} (not alg=none)", app._jwt_header("!!!.abc.def") == {})
check("JSON array header -> {}", app._jwt_header(base64.urlsafe_b64encode(b'[1]').decode() + '.a.b') == {})
check("empty token -> {}", app._jwt_header("") == {})

print("== _finding_url (port-aware) ==")
sess = {"target": "127.0.0.1", "ports_found": "8090", "web_origin": "http://127.0.0.1:8090"}
url = app._finding_url({"path": "/admin", "command": ""}, sess)
check("uses web_origin port", url == "http://127.0.0.1:8090/admin", url)
url2 = app._finding_url({"path": "-", "command": "curl -s http://127.0.0.1:9090/y"}, {"target": "127.0.0.1"})
check("falls back to command URL", url2 == "http://127.0.0.1:9090/y", url2)
check("no endpoint -> None (no fabricated evidence)", app._finding_url({"path": "", "command": ""}, sess) is None)

print("== approve_stage serial dead-end ==")
sid = 'testsid-serial'
stage = next(s for s in app.CHAIN if s['id'] == 'reg_scan')
first, second = stage['substages'][0]['id'], stage['substages'][1]['id']
app.sessions[sid] = {
    "sid": sid, "target": "127.0.0.1", "outdir": TMP, "findings": {}, "outputs": {},
    "commands": {}, "completed": [first], "approved": [first], "skipped": [],
    "launched": {first}, "stage_approved": set(), "lock": threading.Lock(),
    "ports_found": "", "banner_search": "127.0.0.1", "network": "", "notes": {},
    "triage_log": {}, "assessment": None, "accounts": [], "web_origin": "",
}
import queue as _q
app.output_queues[sid] = _q.Queue(maxsize=100)
launched = []
orig = app._launch_substage
app._launch_substage = lambda s, sub: (launched.append(sub), True)[1]
try:
    client = app.app.test_client()
    r = client.post(f'/api/session/{sid}/approve_stage', json={'stage_id': 'reg_scan'})
    body = r.get_json()
    check("approve_stage 200", r.status_code == 200, r.status_code)
    check("launches the next unrun substage, not the completed one",
          body.get('launched') == [second], body)
    # second call: next still-unrun must be substage 3
    third = stage['substages'][2]['id']
    app.sessions[sid]['completed'].append(second)
    launched.clear()
    r2 = client.post(f'/api/session/{sid}/approve_stage', json={'stage_id': 'reg_scan'})
    check("advances to the following substage", r2.get_json().get('launched') == [third],
          r2.get_json())
    # all done -> nothing to launch, no crash
    app.sessions[sid]['completed'] = [s['id'] for s in stage['substages']]
    launched.clear()
    r3 = client.post(f'/api/session/{sid}/approve_stage', json={'stage_id': 'reg_scan'})
    check("stage fully done -> launches nothing", r3.status_code == 200 and r3.get_json().get('launched') == [],
          r3.get_json())
finally:
    app._launch_substage = orig
    app.sessions.pop(sid, None)
    app.output_queues.pop(sid, None)

print(f"\n{PASS}/{PASS+FAIL} checks passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
