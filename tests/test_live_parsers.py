#!/usr/bin/env python3
"""Live contract tests: does a substage's real command emit the evidence its
parser requires?

For every covered substage this renders the actual ``cmd_template`` with
``make_cmd()``, runs it through bash against the two-mode fixture, and feeds the
output to the real parser through ``dispatch_parser()``.

    vuln mode   -> the listed finding types must appear
    secure mode -> no critical/high/medium finding may appear

A parser that can never see its evidence (the failure mode these tests exist
for) shows up here as a missing vuln-mode finding; a parser that over-reads
shows up as a finding on the secure target.

Only substages whose tools exist on this machine are asserted; the rest are
reported as skipped rather than silently passing.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app  # noqa: E402

FIXTURE = ROOT / 'tests' / 'fixtures' / 'vuln_app.py'
VULN_PORT = int(os.environ.get('PWM_FIXTURE_VULN_PORT', '8110'))
SEC_PORT = int(os.environ.get('PWM_FIXTURE_SEC_PORT', '8111'))
SUBPROC_TIMEOUT = 300

VULN_SEV = {'critical', 'high', 'medium'}

# These probe fixed localhost ports (6379/8086/9200/5984) shared with the vuln
# fixture's service stubs, so they cannot be asserted against the secure target
# in the same process — the stubs would answer. They are covered on the vuln
# target only, where the stub state is known.
VULN_ONLY = {'db_unauth', 'db_nosql'}

# substage id -> finding types the vulnerable target must produce
COVERED = [
    ('api_discovery', {'api_endpoint', 'graphql_introspection'}),
    ('api_bola', {'bola_idor'}),
    ('api_auth', {'unauth_endpoint', 'broken_auth'}),
    ('api_injection', {'sqli', 'nosqli', 'ssti'}),
    ('api_ssrf', {'ssrf', 'ssrf_lfi'}),
    ('api_mass_assign', {'mass_assignment', 'broken_function_auth'}),
    ('api_misc', {'api_cors_wildcard', 'missing_rate_limit',
                  'api_key_exposure', 'verbose_error'}),
    ('deep_cms_scan', {'cms_wordpress', 'wp_user_enum', 'cms_drupal',
                       'cms_joomla'}),
    ('db_unauth', {'db_unauth_access'}),
    ('db_sqli', {'sql_injection', 'blind_sqli'}),
    ('db_nosql', {'nosql_injection', 'redis_no_auth', 'redis_data_exposure'}),
]

# Tools each substage needs for its assertions to be meaningful.
REQUIRED_TOOLS = {
    'api_discovery': ['curl'],
    'api_bola': ['curl'],
    'api_auth': ['curl'],
    'api_injection': ['curl'],
    'api_ssrf': ['curl'],
    'api_mass_assign': ['curl'],
    'api_misc': ['curl'],
    'deep_cms_scan': ['curl'],
    'db_unauth': ['curl', 'redis-cli', 'nmap'],
    'db_sqli': ['curl'],
    'db_nosql': ['curl', 'redis-cli'],
}

PASS = FAIL = SKIP = 0


def check(name, cond, extra=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  PASS  {name}')
    else:
        FAIL += 1
        print(f'  FAIL  {name}  {extra}')


def skip(name, why):
    global SKIP
    SKIP += 1
    print(f'  SKIP  {name} ({why})')


def free_port(port):
    with socket.socket() as s:
        try:
            s.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


def wait_ready(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/login',
                                        timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def start_fixture(mode, port, services):
    env = dict(os.environ, FIXTURE_MODE=mode,
               FIXTURE_SERVICES='1' if services else '0')
    proc = subprocess.Popen([sys.executable, str(FIXTURE), str(port)],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    if not wait_ready(port):
        proc.kill()
        raise SystemExit(f'fixture ({mode}) failed to start on :{port}\n'
                         + (proc.stdout.read() if proc.stdout else ''))
    return proc


def make_session(port):
    return {
        'target': '127.0.0.1',
        'outdir': tempfile.mkdtemp(prefix=f'pwm-live-{port}-'),
        'ports_found': str(port),
        'web_origin': f'http://127.0.0.1:{port}',
        'banner_search': '127.0.0.1',
        'network': '127.0.0.1',
        'notes': {}, 'triage_log': {}, 'findings': {}, 'outputs': {},
        'commands': {}, 'completed': [], 'approved': [], 'skipped': [],
        'launched': set(), 'stage_approved': set(), 'lock': threading.Lock(),
        'assessment': None, 'accounts': [], 'context': {},
    }


def substage(sub_id):
    for st in app.CHAIN:
        for s in st['substages']:
            if s['id'] == sub_id:
                return s
    raise KeyError(sub_id)


def run_substage(sub_id, sess):
    sub = substage(sub_id)
    cmd = app.make_cmd(sub['cmd_template'], sess)
    proc = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True,
                          timeout=SUBPROC_TIMEOUT, cwd=sess['outdir'])
    output = (proc.stdout or '') + (proc.stderr or '')
    findings = app.dispatch_parser(sub['parse'], output, sess)
    return findings, output, cmd


def types_of(findings):
    return {f.get('type') for f in findings}


def vuln_sev(findings):
    return [f for f in findings if f.get('severity') in VULN_SEV]


def main():
    if not FIXTURE.exists():
        raise SystemExit(f'fixture missing: {FIXTURE}')
    for p in (VULN_PORT, SEC_PORT):
        if not free_port(p):
            raise SystemExit(f'port {p} already in use — set '
                             'PWM_FIXTURE_VULN_PORT / PWM_FIXTURE_SEC_PORT')

    svc_ok = all(free_port(p) for p in (6379, 8086, 9200, 5984))
    print(f'== starting fixtures (secure :{SEC_PORT} services=off, '
          f'vuln :{VULN_PORT} services={svc_ok})')
    procs = []
    try:
        # The secure target starts FIRST, while the DB ports are still free, so
        # the fixed-port probes get an honest "nothing listening" baseline.
        procs.append(start_fixture('secure', SEC_PORT, services=False))
        vsess, ssess = make_session(VULN_PORT), make_session(SEC_PORT)

        print('\n== secure target, DB ports free: fixed-port probes must find nothing ==')
        for sub_id in sorted(VULN_ONLY):
            missing_tools = [t for t in REQUIRED_TOOLS.get(sub_id, [])
                             if not shutil.which(t)]
            if missing_tools:
                skip(sub_id, 'missing ' + ', '.join(missing_tools))
                continue
            if not svc_ok:
                skip(sub_id, 'DB ports busy — cannot establish a free baseline')
                continue
            findings, _, _ = run_substage(sub_id, ssess)
            bad = vuln_sev(findings)
            check(f'{sub_id}: no vuln-severity finding with nothing listening',
                  not bad,
                  [(f.get('severity'), f.get('type'), str(f.get('detail'))[:70])
                   for f in bad])

        procs.append(start_fixture('vuln', VULN_PORT, services=svc_ok))

        print('\n== vuln target: each parser must see its evidence ==')
        for sub_id, expected in COVERED:
            if not expected:
                continue
            missing_tools = [t for t in REQUIRED_TOOLS.get(sub_id, [])
                             if not shutil.which(t)]
            if missing_tools:
                skip(sub_id, 'missing ' + ', '.join(missing_tools))
                continue
            if sub_id == 'db_unauth' and not svc_ok:
                skip(sub_id, 'DB stub ports busy — services not started')
                continue
            findings, _, _ = run_substage(sub_id, vsess)
            got = types_of(findings)
            missing = expected - got
            check(f'{sub_id}: produces {sorted(expected)}', not missing,
                  f'missing={sorted(missing)} got={sorted(got)}')

        print('\n== secure target: the same parsers must stay silent ==')
        for sub_id, _ in COVERED:
            missing_tools = [t for t in REQUIRED_TOOLS.get(sub_id, [])
                             if not shutil.which(t)]
            if missing_tools:
                skip(sub_id, 'missing ' + ', '.join(missing_tools))
                continue
            if sub_id in VULN_ONLY:
                continue        # already asserted against the free-port baseline
            findings, _, _ = run_substage(sub_id, ssess)
            bad = vuln_sev(findings)
            check(f'{sub_id}: no vuln-severity finding on a correct app',
                  not bad,
                  [(f.get('severity'), f.get('type'), str(f.get('detail'))[:70])
                   for f in bad])

    finally:
        for p in procs:
            p.kill()
            p.wait(timeout=10)

    print(f'\n{PASS}/{PASS + FAIL} live checks passed, {FAIL} failed, '
          f'{SKIP} skipped')
    sys.exit(1 if FAIL else 0)


if __name__ == '__main__':
    main()
