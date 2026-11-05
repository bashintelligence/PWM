"""Prove false positives in PWM's in-process probes against a correct fixture.

For every scenario two runs are made:
  secure fixture  -> a correct tool must emit ZERO vulnerability findings
  vuln   fixture  -> a correct tool must emit the expected finding

Usage: python3 tests/test_inprocess_probes.py
"""
import json
import os
import queue
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'vuln_app.py'

SECURE_PORT = 8099
VULN_PORT = 8100
NOT_FINDINGS = {'not_tested', 'info', 'evidence_capture', 'web_path'}


def start_fixture(mode, port):
    p = subprocess.Popen([sys.executable, str(FIXTURE), str(port)],
                         env={**os.environ, 'FIXTURE_MODE': mode},
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(60):
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/login', timeout=1).read()
            return p
        except Exception:
            time.sleep(0.1)
    p.kill()
    raise RuntimeError(f'fixture {mode} did not start')


def mk_session(port):
    sid = f'test-{port}-{time.time_ns()}'
    app.sessions[sid] = {
        'sid': sid, 'raw_target': f'127.0.0.1:{port}',
        'target': '127.0.0.1', 'target_type': 'ip',
        'created': '2026-11-04T00:00:00', 'outdir': '/tmp',
        'findings': {}, 'outputs': {}, 'commands': {},
        'completed': [], 'approved': [], 'skipped': [], 'launched': set(),
        'stage_approved': set(), 'lock': app.threading.Lock(),
        'ports_found': str(port), 'banner_search': '127.0.0.1',
        'network': '', 'notes': {}, 'triage_log': {}, 'assessment': None,
        'accounts': [{'role': 'user', 'username': 'operator',
                      'password': 'CorrectHorse!23'}],
        'web_origin': f'http://127.0.0.1:{port}',
    }
    app.output_queues[sid] = queue.Queue(maxsize=5000)
    return sid


def run(sid, sub_id, fn):
    err = None
    try:
        fn(sid, sub_id, {})
    except Exception as e:  # a probe crash is a failure too
        err = f'{type(e).__name__}: {e}'
    fs = app.sessions[sid]['findings'].get(sub_id, [])
    vuln = [f for f in fs if (f.get('severity') or 'info') in
            ('critical', 'high', 'medium', 'low')
            and f.get('type') not in NOT_FINDINGS]
    logs = []
    try:
        while True:
            it = app.output_queues[sid].get_nowait()
            d = it.get('data') or {}
            if isinstance(d, dict) and d.get('line'):
                logs.append(d['line'])
    except queue.Empty:
        pass
    return vuln, err, logs


def scenario_cookie(port):
    sid = mk_session(port)
    run(sid, 'auth_discovery', app._auth_discovery)
    return run(sid, 'session_cookie_flags', app._session_cookie_flags)


def scenario_logout(port):
    sid = mk_session(port)
    run(sid, 'auth_discovery', app._auth_discovery)
    return run(sid, 'auth_logout', app._auth_logout)


def scenario_admin(port):
    sid = mk_session(port)
    return run(sid, 'authz_forced_browsing', app._authz_forced_browsing)


def scenario_ratelimit(port):
    sid = mk_session(port)
    run(sid, 'reg_discovery', app._reg_discovery)
    return run(sid, 'reg_rate_limit', app._reg_rate_limit)


def scenario_oauth(port):
    sid = mk_session(port)
    return run(sid, 'auth_oauth', app._auth_oauth)


SCEN = [
    ('cookie_flags    ', scenario_cookie, None),
    ('logout_invalidate', scenario_logout, 'logout_invalidation'),
    ('forced_browsing ', scenario_admin, 'unauth_endpoint'),
    ('signup_rate_limit', scenario_ratelimit, 'signup_rate_limit'),
    ('oauth_redirect  ', scenario_oauth, 'oauth_misconfig'),
]


def show(label, res, expect):
    vuln, err, logs = res
    print(f'\n--- {label} ---')
    if err:
        print(f'  CRASH: {err}')
    for f in vuln:
        print(f"  FP? {f.get('severity'):<8} {f.get('type'):<22} {str(f.get('detail'))[:96]}")
    if not vuln:
        print('  (no vulnerability findings)')
    for ln in logs:
        if 'session]' in ln or 'logout]' in ln or 'oauth]' in ln or 'signup]' in ln or 'authz]' in ln:
            print(f'    log: {ln[:150]}')


def main():
    procs = [start_fixture('secure', SECURE_PORT), start_fixture('vuln', VULN_PORT)]
    fails = 0
    try:
        for label, fn, expect in SCEN:
            sec = fn(SECURE_PORT)
            vul = fn(VULN_PORT)
            show(f'{label} [SECURE — must be silent]', sec, expect)
            show(f'{label} [VULN — must fire {expect or "nothing expected"}]', vul, expect)
            # secure mode must be silent
            if sec[0]:
                print(f'  >>> FALSE POSITIVE in {label.strip()}')
                fails += 1
            if sec[1]:
                fails += 1
            # vuln mode must raise the expected type
            types = [f.get('type') for f in vul[0]]
            if expect and expect not in types:
                print(f'  >>> MISSED DETECTION in {label.strip()} (got {types})')
                fails += 1
    finally:
        for p in procs:
            p.kill()
    print(f'\nRESULT: {fails} failing check(s)')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
