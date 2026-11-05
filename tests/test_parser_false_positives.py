#!/usr/bin/env python3
"""False-positive audit for the remaining substage parsers.

Each case is a NEGATIVE fixture (healthy / rejected / unauthenticated tool
output in the format the real tool emits) that must yield ZERO vulnerability
findings, plus a POSITIVE fixture that must still fire. Run before and after
the fixes to show the delta.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app  # noqa: E402

PASS = FAIL = 0
def check(name, cond, extra=''):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}  {extra}")

VULN = {'critical', 'high', 'medium'}   # severities that enter the popups

def vulns(f):
    return [(x.get('severity'), x.get('type'), str(x.get('detail'))[:78]) for x in f
            if x.get('severity') in VULN]

def show(label, f):
    v = vulns(f)
    print(f"    {label}: {len(f)} findings, {len(v)} vuln-severity")
    for s, t, d in v: print(f"       {s:8} {t:22} {d}")

print("== 1. nse_deep: nmap NSE NEGATIVE results ==")
nse_neg = """PORT     STATE SERVICE
25/tcp   open  smtp
| smtp-open-relay: Server doesn't seem to be an open relay, all tests failed
|_  smtp-open-relay: Server is not an open relay
123/udp  open  ntp
| ntp-monlist: ERROR: Script execution failed (use -d to debug)
|_ntp-monlist: ERROR: Script execution failed
389/tcp  open  ldap
| ldap-rootdse:
|   result: 32 No such object
|_  namingContexts:
21/tcp   open  ftp
|_ftp-anon: FTP server denies anonymous login
53/udp   open  domain
|_dns-recursion: Recursion appears to be disabled
"""
f = app.parse_nse_deep(nse_neg); show("negative", f)
check("smtp 'doesn't seem to be an open relay' -> no critical relay claim",
      not [x for x in f if 'relay' in str(x.get('detail','')).lower()])
check("ntp-monlist ERROR -> no amplification claim",
      not [x for x in f if 'NTP' in str(x.get('path',''))])
check("failed LDAP base query -> no anonymous-bind claim",
      not [x for x in f if 'LDAP' in str(x.get('path',''))])
check("'Recursion appears to be disabled' -> no recursion claim",
      not [x for x in f if 'recursion' in str(x.get('detail','')).lower()])

nse_pos = """25/tcp   open  smtp
| smtp-open-relay: Server is an open relay (16 tests out of 30 completed)
|_  smtp-open-relay: Server is an open relay
123/udp  open  ntp
| ntp-monlist:
|   Target
|     127.0.0.1
|_  monlist replies received from 127.0.0.1
53/udp   open  domain
|_dns-recursion: Recursion appears to be enabled
[REDIS] redis_version:7.0.11
"""
f = app.parse_nse_deep(nse_pos); show("positive", f)
check("open relay still fires", any('relay' in str(x.get('detail','')).lower() for x in f))
check("monlist data still fires", any('NTP' in str(x.get('path','')) for x in f))
check("enabled recursion still fires", any('recursion' in str(x.get('detail','')).lower() for x in f))
check("redis_version still fires", any('Redis' in str(x.get('path','')) for x in f))

print("== 2. http_anomaly: server REJECTS the forged Host ==")
http_neg = """---TRAVERSAL---
<!doctype html><html><body>not found</body></html>
---VERB TAMPER---
HTTP/1.1 405 METHOD NOT ALLOWED
Allow: GET, HEAD, POST, OPTIONS
---HOST INJECT---
HTTP/1.1 400 BAD REQUEST
Content-Type: text/html

<html><body>Invalid Host header: evil.com</body></html>
---OPTIONS---
HTTP/1.1 200 OK
Allow: GET, HEAD, POST, OPTIONS
---ADMIN---
body:admin[404] not found
---GIT---
body:.git[404] not found
---ENV---
body:.env[404] not found
"""
f = app.parse_http_anomaly(http_neg); show("negative", f)
check("Host rejected with 400 -> no host-header-injection claim",
      not [x for x in f if x.get('type') == 'host_header_injection'])
check("TRACE 405 (Allow lacks TRACE) -> no XST claim",
      not [x for x in f if x.get('type') == 'trace_method'])

http_pos = """---VERB TAMPER---
HTTP/1.1 200 OK
Allow: GET, HEAD, POST, OPTIONS, TRACE
---HOST INJECT---
HTTP/1.1 302 FOUND
Location: http://evil.com/
---TRAVERSAL---
root:x:0:0:root:/root:/bin/bash
"""
f = app.parse_http_anomaly(http_pos); show("positive", f)
check("real TRACE 200 still fires", any(x.get('type') == 'trace_method' for x in f))
check("real Location: evil.com redirect still fires",
      any(x.get('type') == 'host_header_injection' for x in f))
check("real /etc/passwd content still fires", any(x.get('type') == 'path_traversal' for x in f))

print("== 3. api_injection: healthy API log lines ==")
inj_neg = """{"status":"ok","message":"Request completed at 12:00 (UTC)"}
2024-05-01 10:00:00 INFO GET /api/v1/users (200)
{"id":1,"name":"alice","email":"alice@example.com"}
"""
f = app.parse_api_injection(inj_neg); show("negative", f)
check("normal '(UTC)' line -> no stack-trace disclosure",
      not [x for x in f if x.get('type') == 'error_disclosure'])

inj_pos = """{"error":"java.lang.NullPointerException: boom","trace":"see below"}
\tat com.example.UserController.get(UserController.java:42)
Traceback (most recent call last):
  File "/app/server.py", line 42, in handler
"""
f = app.parse_api_injection(inj_pos); show("positive", f)
check("real Java stack frame still fires error_disclosure",
      any(x.get('type') == 'error_disclosure' for x in f))

print("== 4. xss_probe: page that merely contains the word 'alert' ==")
xss_neg = """q XSS 200: alert
"""
f = app.parse_xss_probe(xss_neg); show("negative", f)
check("word 'alert' with no payload reflection -> no XSS claim",
      not [x for x in f if x.get('type') == 'xss_reflected'])

xss_pos = """q XSS 200: <script>alert(1)</script>
"""
f = app.parse_xss_probe(xss_pos); show("positive", f)
check("real payload reflection still fires", any(x.get('type') == 'xss_reflected' for x in f))

print("== 5. timing: single-sample jitter on a healthy login ==")
tim_neg = """t=0.041 code=200
t=0.038 code=200
t=0.036 code=200
t=0.040 code=200
t=0.039 code=200
valid_user=0.221
invalid_user=0.203
sqli_probe=0.045
sqli_baseline=0.042
"""
f = app.parse_timing(tim_neg); show("negative", f)
check("5-sample stable timings -> no blind-SQLi claim",
      not [x for x in f if x.get('type') == 'timing_anomaly'])
check("300ms->200ms single-sample jitter -> no enumeration claim",
      not [x for x in f if x.get('type') == 'auth_timing_oracle'])

tim_pos = """valid_user=1.284
invalid_user=0.021
sqli_probe=3.412
sqli_baseline=0.038
"""
f = app.parse_timing(tim_pos); show("positive", f)
check("large login timing gap (60x) still fires",
      any(x.get('type') == 'auth_timing_oracle' for x in f))
check("SLEEP(3) probe vs baseline still fires",
      any(x.get('type') == 'blind_sqli' for x in f))

print("== 6. hydra: hit on FTP/MySQL must not be labelled SSH :22 ==")
hyd = """[21][ftp] host: 127.0.0.1   login: anonymous   password: anon@example.com
1 of 1 target successfully completed, 1 valid password found
"""
f = app.parse_hydra(hyd); show("hydra", f)
check("FTP hit labelled with the real service", not [x for x in f if str(x.get('path','')) == 'SSH :22'],
      [x.get('path') for x in f])

print("== 7. sqlmap: payload text must not 'confirm' FILE privilege ==")
sm_neg = """[10:00:01] [INFO] testing connection to the target URL
[10:00:05] [INFO] the back-end DBMS is MySQL
[10:00:09] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap'
[*] ending @ 10:00:12
"""
f = app.parse_sqlmap(sm_neg); show("negative", f)
check("no file-access / OS-shell claim without sqlmap confirmation",
      not [x for x in f if x.get('type') in ('sqli_file_access', 'sqli_os_rce')])

sm_pos = """[10:00:05] [INFO] the back-end DBMS is MySQL
[10:00:07] [INFO] fetching file: '/etc/passwd'
[10:00:08] [INFO] the file has been saved to '/tmp/passwd'
sqlmap identified the following injection point(s) with a total of 4 HTTP(s) requests:
Parameter: id (GET)
    Type: boolean-based blind
"""
f = app.parse_sqlmap(sm_pos); show("positive", f)
check("real file read still fires", any(x.get('type') == 'sqli_file_access' for x in f))
check("real injection point still fires", any(x.get('type') == 'sql_injection' for x in f))

print("== 8. db_unauth: a single-element JSON array is not CouchDB ==")
db_neg = """---REDIS UNAUTH---
(error) NOAUTH Authentication required.
---COUCHDB---
{"error":"unauthorized","reason":"You are not authorized to access this db."}
---ELASTICSEARCH---
{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication"}]},"status":401}
---INFLUXDB---
{"error":"unable to parse authentication credentials"}
"""
f = app.parse_db_unauth(db_neg); show("negative", f)
check("auth-required responses -> no unauthenticated DB claim", not vulns(f), vulns(f))

db_pos = """---REDIS UNAUTH---
PONG
redis_version:7.0.11
---COUCHDB---
["_replicator","_users"]
---ELASTICSEARCH---
health status index    uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   logs-2024 7p0xQ2m1RT2v 1   0        412            0    200.1kb        200.1kb
"""
f = app.parse_db_unauth(db_pos); show("positive", f)
check("real Redis PONG still fires", any('Redis' in str(x.get('path','')) for x in f))
check("real CouchDB DB list still fires", any('CouchDB' in str(x.get('path','')) for x in f))
check("real ES index listing still fires", any('Elasticsearch' in str(x.get('path','')) for x in f))

print(f"\n{PASS}/{PASS+FAIL} checks passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
