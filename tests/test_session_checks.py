"""Focused tests for the fact-based session-id check and same-cookie SameSite.

_http is monkeypatched so each case controls exactly what the server 'returned'.
"""
import os
import queue
import re
import sys
from pathlib import Path
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app

ORIG = app._http


def resp(cookie_headers, status=200, body=''):
    return {'ok': True, 'status': status,
            'headers': {'set-cookie': ', '.join(cookie_headers)} if cookie_headers else {},
            'cookies': list(cookie_headers), 'body': body, 'url': '', 'error': None}


def use(maker):
    state = {'n': 0}

    def fake(*a, **k):
        i = state['n']
        state['n'] += 1
        return maker(i)
    app._http = fake
    return state


def session():
    sid = f'sa-{time.time_ns()}'
    app.sessions[sid] = {
        'sid': sid, 'raw_target': '127.0.0.1', 'target': '127.0.0.1',
        'target_type': 'ip', 'created': '2026-11-04T00:00:00', 'outdir': '/tmp',
        'findings': {}, 'outputs': {}, 'commands': {}, 'rc': {},
        'completed': [], 'approved': [], 'skipped': [], 'launched': set(),
        'stage_approved': set(), 'lock': app.threading.Lock(),
        'ports_found': '80', 'banner_search': '', 'network': '', 'notes': {},
        'triage_log': {}, 'assessment': None, 'web_origin': 'http://127.0.0.1:8081',
        'accounts': [{'role': 'user', 'username': 'op', 'password': 'pw'}],
    }
    app.output_queues[sid] = queue.Queue(maxsize=2000)
    app.sessions[sid]['context'] = {
        'login': {'url': 'http://127.0.0.1:8081/login', 'path': '/login',
                  'fields': ['username', 'password'], 'mfa': False},
    }
    return sid


def findings(sid, sub_id):
    return app.sessions[sid]['findings'].get(sub_id, [])


def vuln(fs):
    return [(f.get('type'), f.get('severity')) for f in fs
            if (f.get('severity') or 'info') in ('critical', 'high', 'medium', 'low')
            and f.get('type') not in ('not_tested', 'info')]


checks = []


def check(name, ok, detail=''):
    checks.append((name, ok))
    print(('  PASS  ' if ok else '  FAIL  ') + name + (f'   [{detail}]' if detail else ''))


try:
    # ---- session id: 32-hex, distinct every login -> nothing -----------------
    sid = session()
    vals = ['a1b2c3d4e5f60718293a4b5c6d7e8f90', '0f1e2d3c4b5a69788796a5b4c3d2e1f0',
            '112233445566778899aabbccddeeff00']
    use(lambda i: resp([f'session={vals[min(i, 2)]}; Path=/']))
    app._session_entropy(sid, 'session_entropy', {})
    check('32-hex distinct ids -> no finding', vuln(findings(sid, 'session_entropy')) == [])

    # ---- identical every login -> critical ----------------------------------
    sid = session()
    use(lambda i: resp(['session=deadbeefdeadbeefdeadbeefdeadbeef; Path=/']))
    app._session_entropy(sid, 'session_entropy', {})
    check('static id -> critical',
          ('session_entropy', 'critical') in vuln(findings(sid, 'session_entropy')))

    # ---- short id -> medium, stated as a measured length --------------------
    sid = session()
    vals = ['ab12cd34', 'ef56gh78', 'ij90kl12']
    use(lambda i: resp([f'session={vals[min(i, 2)]}; Path=/']))
    app._session_entropy(sid, 'session_entropy', {})
    fs = vuln(findings(sid, 'session_entropy'))
    detail = ' '.join(f.get('detail', '') for f in findings(sid, 'session_entropy'))
    check('8-char id -> medium', ('session_entropy', 'medium') in fs)
    check('short-id text states the measured length', 'only 8 characters' in detail, detail[:70])
    check('no estimated-bits claim', 'bits' not in detail)

    # ---- numeric-only -> medium --------------------------------------------
    sid = session()
    vals = ['12345678901234567890', '09876543210987654321', '11111222223333344444']
    use(lambda i: resp([f'session={vals[min(i, 2)]}; Path=/']))
    app._session_entropy(sid, 'session_entropy', {})
    fs = vuln(findings(sid, 'session_entropy'))
    detail = ' '.join(f.get('detail', '') for f in findings(sid, 'session_entropy'))
    check('numeric-only 20-digit id -> medium', ('session_entropy', 'medium') in fs)
    check('numeric finding cites digits', 'numeric-only' in detail)

    # ---- repeated across logins -> medium ----------------------------------
    sid = session()
    same = 'abcdefghij0123456789'
    vals = [same, same, 'zyxwvutsrq9876543210']
    use(lambda i: resp([f'session={vals[min(i, 2)]}; Path=/']))
    app._session_entropy(sid, 'session_entropy', {})
    fs = vuln(findings(sid, 'session_entropy'))
    detail = ' '.join(f.get('detail', '') for f in findings(sid, 'session_entropy'))
    check('repeated across logins -> medium', ('session_entropy', 'medium') in fs)
    check('repeat finding cites the counts', 'unique values from 3' in detail)

    # ---- CSRF: SameSite on a DIFFERENT cookie must not suppress ------------
    def csrf_case(session_cookie, expect):
        sid = session()
        app.sessions[sid]['context']['signup'] = {
            'url': 'http://127.0.0.1:8081/signup', 'path': '/signup',
            'fields': ['username', 'email', 'password'], 'captcha': False}
        use(lambda i: resp([session_cookie, 'prefs=compact; Path=/; SameSite=Strict']))
        app._bizlogic_csrf(sid, 'bizlogic_csrf', {})
        got = vuln(findings(sid, 'bizlogic_csrf'))
        return got, expect

    got, expect = csrf_case('session=abc123; Path=/', True)
    check('session cookie without SameSite -> finding (other cookie SameSite ignored)',
          (('csrf_missing', 'medium') in got) == expect, str(got))

    got, expect = csrf_case('session=abc123; Path=/; SameSite=Strict', False)
    check('session cookie with SameSite -> no finding',
          (('csrf_missing', 'medium') in got) == expect, str(got))
finally:
    app._http = ORIG

bad = sum(1 for _, ok in checks if not ok)
print(f'\n{len(checks) - bad}/{len(checks)} checks passed, {bad} failed')
sys.exit(1 if bad else 0)
