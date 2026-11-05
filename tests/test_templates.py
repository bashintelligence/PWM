"""Tests for the cmd_template audit: bounds, dead checks, timeout-vs-delay."""
import os
import re
import subprocess
import sys
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app

checks = []


def check(name, ok, detail=''):
    checks.append((name, ok))
    print(('  PASS  ' if ok else '  FAIL  ') + name + (f'   [{detail}]' if detail else ''))


def types(fs):
    return [f.get('type') for f in fs]


# ---- 1. every curl request is bounded -------------------------------------
unbounded = []
for stage in app.CHAIN:
    for sub in stage['substages']:
        for field in ('cmd_template', 'fallback_cmd'):
            tpl = sub.get(field) or ''
            for seg in re.split(r';|&&|\|\||\|', tpl):
                if re.search(r'(?<![\w./-])curl\b', seg) and '--max-time' not in seg:
                    unbounded.append((sub['id'], field))
check('every curl invocation has --max-time', not unbounded, str(unbounded[:3]))

# ---- 2. every substage has a finite wall clock ----------------------------
no_cap = [s['id'] for st in app.CHAIN for s in st['substages']
          if not (s.get('timeout') or app.LONG_SUBSTAGE_TIMEOUT.get(s['id'])
                  or app.DEFAULT_SUBSTAGE_TIMEOUT)]
check('every substage has a finite timeout', not no_cap, str(no_cap[:3]))

# ---- 3. mysqladmin status is recognised (command echo is not in output) ---
fs = app.parse_db_default_creds('Uptime: 4271  Threads: 2  Questions: 9912  '
                                'Slow queries: 0  Opens: 41  Flush tables: 1')
check('mysqladmin status line -> db_default_cred', 'db_default_cred' in types(fs))
fs = app.parse_db_default_creds('mysqladmin -h 10.0.0.5 -u root status')
check('echoed command alone -> no finding', 'db_default_cred' not in types(fs))

# ---- 4. a timed-out probe is not a timing anomaly ------------------------
slow_cap = '\n'.join(['t=0.10 code=200'] * 4 + ['t=12.00 code=000'])
check('4 fast + 1 timed-out sample -> no timing_anomaly',
      'timing_anomaly' not in types(app.parse_timing(slow_cap)))
slow_real = '\n'.join(['t=0.10 code=200'] * 4 + ['t=1.90 code=200'])
check('4 fast + 1 genuinely slow sample -> timing_anomaly',
      'timing_anomaly' in types(app.parse_timing(slow_real)))

# ---- 5. login oracle: timeout must not look like a slow path -------------
cap_login = 'valid_user=0.10\ninvalid_user=12.00'
check('oracle from a timed-out sample -> none',
      'auth_timing_oracle' not in types(app.parse_timing(cap_login)))
real_login = 'valid_user=0.10\ninvalid_user=0.90'
check('oracle from a real 9x difference -> fires',
      'auth_timing_oracle' in types(app.parse_timing(real_login)))

# ---- 6. SLEEP probe at the cap is a timeout, not injection ---------------
check('sleep_probe at cap -> no blind_sqli',
      'blind_sqli' not in types(app.parse_timing('sqli_probe=20.00\nsqli_baseline=0.10')))
check('sleep_probe=4.5 vs 0.1 -> blind_sqli',
      'blind_sqli' in types(app.parse_timing('sqli_probe=4.50\nsqli_baseline=0.10')))
check('db_sqli sleep at cap -> no blind_sqli',
      'blind_sqli' not in types(app.parse_db_sqli('sleep_probe=20.00s baseline=0.10s')))
check('db_sqli sleep=4.5 vs 0.1 -> blind_sqli',
      'blind_sqli' in types(app.parse_db_sqli('sleep_probe=4.50s baseline=0.10s')))

# ---- 7. FTP anon is observable (curl needs -v to print 230) --------------
ftp = app.find_sub('deep_auth_probe')['cmd_template']
check('FTP probe requests verbose output', 'curl -sv' in ftp and 'ftp://' in ftp)
check('parse_auth_probe reads the 230 line',
      'ftp_anon' in types(app.parse_auth_probe('outer: ftp\n< 230 Logged in\n'
                                               'drwxr-xr-x 2 root root 4096 pub')))


# ---- 7b. cookie evidence: session cookie only, and HEAD is not enough -----
check('auth probe reads headers from a GET',
      '-D - -o /dev/null' in app.find_sub('deep_auth_probe')['cmd_template'])
csrf_only = 'set-cookie: csrftoken=abc; Path=/'
check('CSRF cookie alone -> no cookie_flags',
      'cookie_flags' not in types(app.parse_auth_probe(csrf_only)))
sess_bare = 'set-cookie: session=abc123; Path=/'
check('unflagged session cookie -> cookie_flags (named)',
      any(f['type'] == 'cookie_flags' and "'session'" in f['detail']
          for f in app.parse_auth_probe(sess_bare)))
sess_ok = 'set-cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/'
check('flagged session cookie -> none',
      'cookie_flags' not in types(app.parse_auth_probe(sess_ok)))


# ---- 7c. cookie-flag signatures must also ignore non-session cookies -----
sigs = lambda line: [m for m, _ in app.sig_matches(line)]
check('CSRF cookie -> no cookie signature', sigs('Set-Cookie: csrftoken=abc; Path=/') == [])
check('prefs cookie -> no cookie signature', sigs('Set-Cookie: prefs=x; Path=/') == [])
check('unflagged session -> both signatures',
      sigs('Set-Cookie: session=abc; Path=/')
      == ['Cookie missing HttpOnly flag', 'Cookie missing Secure flag'])
check('flagged session -> no signature',
      sigs('Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict') == [])

# ---- 8. all templates still parse ---------------------------------------
sess = {'target': '127.0.0.1', 'outdir': tempfile.mkdtemp(prefix='pwm_x_'), 'ports_found': '8100',
        'web_origin': 'http://127.0.0.1:8100', 'network': '127.0.0.0/32',
        'banner_search': '127.0.0.1', 'context': {}}
bad, n = [], 0
for stage in app.CHAIN:
    for sub in stage['substages']:
        for field in ('cmd_template', 'fallback_cmd'):
            tpl = sub.get(field)
            if not tpl:
                continue
            n += 1
            r = subprocess.run(['bash', '-n', '-c', app.make_cmd(tpl, sess)],
                               capture_output=True, text=True)
            if r.returncode:
                bad.append((sub['id'], field))
check(f'all {n} templates pass bash -n', not bad, str(bad[:3]))

# ---- 9. payload escaping survives make_cmd -------------------------------
# make_cmd collapses `{{`->`{` and `}}`->`}`, so a literal double-braced or
# JSON payload must be written doubled in the template. A payload that renders
# one brace short is sent as malformed JSON and the server rejects it, which
# silently kills the check that depends on the response.
import json as _json
bad_json, bad_tpl, json_bodies = [], [], 0
for stage in app.CHAIN:
    for sub in stage['substages']:
        tpl = sub.get('cmd_template')
        if not tpl:
            continue
        cmd = app.make_cmd(tpl, sess)
        for m in re.finditer(r"(?:-d|--data(?:-raw)?)\s+'([^']*)'", cmd):
            body = m.group(1)
            if not body.lstrip().startswith('{'):
                continue
            json_bodies += 1
            try:
                _json.loads(body)
            except ValueError:
                # api_misc deliberately posts broken JSON to provoke an error.
                if sub['id'] != 'api_misc':
                    bad_json.append((sub['id'], body))
        # a template-expression payload must reach the server verbatim
        for m in re.finditer(r"\{\{(\d+\*\d+)\}\}", cmd):
            if '{' + m.group(1) + '}' not in cmd[max(0, m.start() - 4):m.end() + 1]:
                bad_tpl.append((sub['id'], m.group(0)))
check(f'all {json_bodies} rendered JSON bodies parse', not bad_json, str(bad_json[:2]))
ssti_cmd = app.make_cmd(app.find_sub('api_injection')['cmd_template'], sess)
check('SSTI payload reaches the server as {{7*7}}',
      '?q={{7*7}}' in ssti_cmd and '?template={{7*7}}' in ssti_cmd, ssti_cmd[-160:])
check('SSTI probe disables curl brace globbing', ssti_cmd.count('curl -gsk') >= 2,
      str(ssti_cmd.count('curl -gsk')))

bad_n = sum(1 for _, ok in checks if not ok)
print(f'\n{len(checks) - bad_n}/{len(checks)} checks passed, {bad_n} failed')
sys.exit(1 if bad_n else 0)
