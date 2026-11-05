"""Two-mode fixture used by the PWM audit suites.

    FIXTURE_MODE=secure  behaves correctly — a correct scanner must report NOTHING
    FIXTURE_MODE=vuln    deliberately flawed — each listed detection must fire

Run:  FIXTURE_MODE=vuln python3 tests/fixtures/vuln_app.py 8100

The web app always listens on the given port. In `vuln` mode it also starts the
database-service stubs that the DB probes expect on their real ports (6379
Redis, 8086 InfluxDB, 9200 Elasticsearch, 5984 CouchDB); set FIXTURE_SERVICES=0
to skip them or if those ports are already in use (a bind failure is reported
and ignored). MongoDB (:27017) is deliberately NOT emulated — its wire protocol
is not something a stub can honestly fake, so that probe stays uncovered.
"""
import base64
import json
import os
import socketserver
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get('FIXTURE_MODE', 'secure')
VULN = MODE == 'vuln'
SERVICES = os.environ.get('FIXTURE_SERVICES', '1' if VULN else '0') == '1'

VALID_SESSIONS = set()

# The real MySQL error text, including the `near '...' at line N` tail: a probe
# that greps for the DB error must still match when the message is what a live
# server actually returns.
SQL_ERROR = ("You have an error in your SQL syntax; check the manual that "
             "corresponds to your MySQL server version for the right syntax "
             "to use near ''1''' at line 1")
STACK = ('{"error":"Traceback (most recent call last):","detail":'
         '"File \\"/srv/app.py\\", line 42, in handler"}')


def _session_id():
    return uuid.uuid4().hex


class WebHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    _head = False

    def log_message(self, *a):
        pass

    # ---- response helpers -------------------------------------------------
    def _send(self, code, body, extra=(), ctype='text/html; charset=utf-8'):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            ctype = 'application/json'
        raw = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if not self._head:
            self.wfile.write(raw)

    def _json(self, code, obj, extra=()):
        self._send(code, obj, extra, ctype='application/json')

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(n).decode('utf-8', 'ignore') if n else ''

    def _auth(self):
        return self.headers.get('Authorization', '')

    def _alg_none(self):
        """True when the bearer token is null or carries alg=none.

        The probe sends a real alg=none JWT, so the header must be decoded —
        matching a literal prefix would silently miss it.
        """
        tok = self._auth().replace('Bearer', '').strip()
        if tok == 'null':
            return True
        if not tok:
            return False
        try:
            hdr = tok.split('.')[0]
            hdr += '=' * (-len(hdr) % 4)
            return json.loads(base64.urlsafe_b64decode(hdr).decode()).get('alg') == 'none'
        except Exception:
            return False

    # ---- pages ------------------------------------------------------------
    def login_page(self, err=''):
        return ('<html><head><title>Sign in</title></head><body>'
                '<h1>Sign in to your workspace</h1>'
                + (f'<p class="err">{err}</p>' if err else '') +
                '<form method="post" action="/login">'
                '<input name="username" type="text">'
                '<input name="password" type="password">'
                '<input type="hidden" name="csrf_token" value="c1">'
                '</form><p>Use your work email address to continue. '
                'Forgot your password? Contact your administrator.</p></body></html>')

    def help_page(self):
        return ('<html><head><title>Help Centre</title></head><body>'
                '<h1>Help Centre</h1><p>Manage your notification settings and '
                'alert preferences from the account panel. This page is public '
                'documentation for all users and contains no customer records.</p>'
                '<a href="/docs">Documentation</a></body></html>')

    def admin_page(self):
        return ('<html><head><title>Admin Dashboard</title></head><body>'
                '<h1>Admin Dashboard</h1><h2>User Management</h2>'
                '<table><tr><td>alice</td><td>admin</td></tr>'
                '<tr><td>bob</td><td>user</td></tr></table>'
                '<p>Manage users, roles and global account settings here.</p>'
                '</body></html>')

    def account_page(self):
        return ('<html><head><title>Your account</title></head><body>'
                '<h1>Your account</h1><p>Signed in successfully. This is private '
                'account content for the logged-in user only.</p></body></html>')

    # ---- GET --------------------------------------------------------------
    def do_HEAD(self):
        self._head = True
        try:
            self.do_GET()
        finally:
            self._head = False

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path, q = p.path, urllib.parse.parse_qs(p.query)

        # ---- session / registration surface ------------------------------
        if path == '/':
            qid = (q.get('id') or [''])[0]
            if VULN and "'" in qid:
                self._send(500, f'<html><body>SQL error: {SQL_ERROR}</body></html>')
            elif VULN and 'SLEEP(4)' in qid.upper():
                time.sleep(4)
                self._send(200, '<html><body>ok</body></html>')
            else:
                self._send(200, '<html><body><h1>Demo shop</h1></body></html>')
            return

        if path == '/login':
            attrs = ('; Path=/' if VULN
                     else '; HttpOnly; Secure; SameSite=Strict; Path=/')
            self._send(200, self.login_page(),
                       [('Set-Cookie', 'session=guest-' + _session_id()[:16] + attrs),
                        ('Set-Cookie', 'csrftoken=pre-auth-value; Path=/')])
            return

        if path == '/signup':
            if VULN:
                body = ('<html><body><h1>Create your account</h1>'
                        '<form method="post" action="/signup">'
                        '<input name="username"><input name="email" type="email">'
                        '<input name="password" type="password">'
                        '</form></body></html>')
            else:
                body = ('<html><body><h1>Create your account</h1>'
                        '<form method="post" action="/signup">'
                        '<input name="username"><input name="email" type="email">'
                        '<input name="password" type="password">'
                        '<div class="g-recaptcha" data-sitekey="k"></div>'
                        '</form></body></html>')
            self._send(200, body)
            return

        if path == '/logout':
            if not VULN:
                VALID_SESSIONS.discard(self._cookie_session())
            self._send(200, '<html><body><p>You have been logged out.</p></body></html>')
            return

        if path in ('/account', '/profile', '/dashboard', '/api/me',
                    '/user/profile', '/api/v1/me'):
            if self._cookie_session() and self._cookie_session() in VALID_SESSIONS:
                self._send(200, self.account_page())
            else:
                self._send(200, self.login_page())      # 200 login page
            return

        if path in ('/admin', '/admin/', '/admin/users', '/admin/settings',
                    '/administrator', '/manage', '/console', '/api/admin',
                    '/api/admin/users', '/api/users', '/api/v1/users',
                    '/api/user/list'):
            if path.startswith('/api/v1/users'):
                self._api_users(path)
                return
            self._send(200, self.admin_page() if VULN else self.help_page())
            return

        if path == '/oauth/authorize':
            ru = (q.get('redirect_uri') or [''])[0]
            if VULN:
                self._send(302, '', [('Location', ru)])
            else:
                self._send(302, '', [('Location',
                    '/login?next=' + urllib.parse.quote(ru, safe=''))])
            return

        # ---- CMS ---------------------------------------------------------
        if path == '/wp-login.php':
            if VULN:
                self._send(200, '<html><body><h1>WordPress</h1>'
                                '<form name="loginform" action="/wp-login.php">'
                                '<input name="log"><input type="password" name="pwd">'
                                '<input type="submit" name="wp-submit" value="Log In">'
                                '</form></body></html>')
            else:
                self._send(404, 'Not found')
            return

        if path == '/wp-json/wp/v2/users':
            if VULN:
                self._json(200, [{'id': 1, 'name': 'admin', 'slug': 'admin'}])
            else:
                self._json(401, {'error': 'unauthorized'})
            return

        if path == '/CHANGELOG.txt':
            if VULN:
                self._send(200, 'Drupal 7.58, 2017-11-01\n-----------------------\n',
                           ctype='text/plain')
            else:
                self._send(404, 'Not found')
            return

        if path == '/administrator/':
            if VULN:
                self._send(200, '<html><body><div class="mod-login">'
                                '<form action="/administrator/index.php" '
                                'id="form-login" class="com_login">'
                                'user name <input name="username">'
                                'password <input type="password" name="passwd">'
                                '</form></div></body></html>')
            else:
                self._send(404, 'Not found')
            return

        # ---- leaky files (pe_cred_harvest) --------------------------------
        if path == '/.env':
            if VULN:
                self._send(200, 'APP_ENV=production\nDB_HOST=127.0.0.1\n'
                                'DB_PASSWORD=SuperSecret123\nAPP_KEY=base64:xyz\n',
                           ctype='text/plain')
            else:
                self._send(404, 'Not found')
            return

        # ---- API surface --------------------------------------------------
        if path.startswith('/api/v1/users/'):
            self._api_user(str(path.rsplit('/', 1)[-1]))
            return
        if path == '/api/v1/users':
            self._api_users(path)
            return
        if path == '/api/v1/admin':
            if not VULN:
                self._json(401, {'error': 'authentication required'})
            elif self._alg_none():
                self._json(200, {'id': 1, 'role': 'admin'})
            else:
                self._json(401, {'error': 'authentication required'})
            return
        if path == '/api/v1/admin/users':
            if VULN:
                self._json(200, {'users': [{'id': 1, 'username': 'alice'},
                                           {'id': 2, 'username': 'bob'}],
                                 'total': 2})
            else:
                self._json(401, {'error': 'authentication required'})
            return
        if path == '/api/v1/config':
            if VULN:
                self._json(200, {'api_key': 'AKIAIOSFODNN7EXAMPLE',
                                 'environment': 'production'})
            else:
                self._json(401, {'error': 'authentication required'})
            return
        if path == '/api/v1/profile':
            if VULN:
                self._json(200, {'id': 1, 'role': 'admin', 'credits': 99999})
            else:
                self._json(401, {'error': 'authentication required'})
            return
        if path == '/api/v1/internal/debug':
            if VULN:
                self._send(200, STACK, ctype='application/json')
            else:
                self._json(404, {'error': 'not found'})
            return
        if path == '/api/v1/login':
            # The rate-limit probe issues 15 GETs; a correct app throttles.
            self._send(401 if VULN else 429,
                       'invalid credentials' if VULN else 'too many requests',
                       ctype='text/plain')
            return
        if path in ('/api/v1/search', '/api/v1/render'):
            term = ((q.get('q') or q.get('template') or [''])[0])
            if "'" in term:
                if VULN:
                    self._send(500, SQL_ERROR, ctype='text/plain')
                else:
                    self._json(400, {'error': 'invalid search term'})
            elif '{{7*7}}' in term:
                # A vulnerable renderer evaluates it; a correct one echoes the
                # template back verbatim (so 49 must NOT appear).
                self._send(200, '49' if VULN else '7*7', ctype='text/plain')
            else:
                self._send(200, '[]' if VULN else '[]', ctype='application/json')
            return
        if path == '/api/v1/fetch':
            val = next((v[0] for k, v in q.items() if v), '')
            if not VULN:
                self._json(400, {'error': 'invalid url'})
            elif val == '0':
                self._json(400, {'error': 'invalid target'})
            elif val.startswith('http://169.254.169.254'):
                self._send(200, 'ami-id=i-0123456789\ninstance-id=i-abcdef\n'
                                'local-ipv4=10.0.0.5\n', ctype='text/plain')
            elif val.startswith('file://'):
                self._send(200, 'root:x:0:0:root:/root:/bin/bash\n'
                                'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n',
                           ctype='text/plain')
            else:
                self._json(400, {'error': 'invalid target'})
            return
        if path == '/api/v1/proxy':
            self._json(400 if not VULN else 502,
                       {'error': 'invalid url' if not VULN else 'connection refused'})
            return
        if path == '/forgot-password':
            self._send(404, '<html><body>Not found</body></html>')
            return

        if path == '/swagger.json':
            if VULN:
                self._json(200, {'openapi': '3.0.0',
                                 'info': {'title': 'Demo API'},
                                 'paths': {'/api/v1/users': {}}})
            else:
                self._json(404, {'error': 'not found'})
            return
        if path == '/actuator/env':
            if VULN:
                self._json(200, {'propertySources': [
                    {'name': 'systemEnvironment', 'properties': {}}]})
            else:
                self._json(404, {'error': 'not found'})
            return

        self._send(404, 'Not found')

    # ---- API helpers ------------------------------------------------------
    def _api_users(self, path):
        extra = [('Access-Control-Allow-Origin', '*')] if VULN else []
        if VULN:
            self._json(200, [{'id': 1, 'username': 'alice',
                              'email': 'alice@example.test', 'role': 'user'},
                             {'id': 2, 'username': 'bob',
                              'email': 'bob@example.test', 'role': 'user'}], extra)
        else:
            self._json(401, {'error': 'authentication required'}, extra)

    def _api_user(self, oid):
        if not oid.isdigit() and not (oid.startswith('-') and oid[1:].isdigit()):
            if VULN:
                self._send(200, STACK, ctype='application/json')
            else:
                self._json(400, {'error': 'invalid id'})
            return
        if not VULN:
            self._json(401, {'error': 'authentication required'})
            return
        n = int(oid)
        self._json(200, {'id': n, 'username': f'user{n}',
                         'email': f'user{n}@example.test', 'role': 'user'})

    def _cookie_session(self):
        raw = self.headers.get('Cookie', '')
        for part in raw.split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                if k.strip() == 'session':
                    return v.strip()
        return ''

    # ---- POST / PUT / PATCH / DELETE -------------------------------------
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        body = self._body()

        if path == '/login':
            data = urllib.parse.parse_qs(body)
            user = (data.get('username') or [''])[0]
            pw = (data.get('password') or [''])[0]
            if user == 'operator' and pw == 'CorrectHorse!23':
                tok = _session_id()
                VALID_SESSIONS.add(tok)
                attrs = ('; Path=/' if VULN
                         else '; HttpOnly; Secure; SameSite=Strict; Path=/')
                self._send(200, '<html><body><p>Welcome back.</p></body></html>',
                           [('Set-Cookie', f'session={tok}{attrs}'),
                            ('Set-Cookie', 'prefs=compact; Path=/')])
            else:
                self._send(401, self.login_page('Invalid credentials'))
            return

        if path == '/signup':
            data = urllib.parse.parse_qs(body)
            user = (data.get('username') or [''])[0]
            hits = _SIGNUP_HITS.get(user, 0) + 1
            _SIGNUP_HITS[user] = hits
            if not VULN and hits > 3:
                self._send(200, '<html><body><p>Too many attempts. '
                                'Please try again later.</p></body></html>')
            else:
                self._send(200, '<html><body><p>Account created.</p></body></html>')
            return

        if path in ('/api/login', '/api/v1/login'):
            if not VULN:
                # A correct app throttles a credential burst.
                hits = _LOGIN_HITS.get(path, 0) + 1
                _LOGIN_HITS[path] = hits
                if hits > 5:
                    self._send(429, 'too many requests', ctype='text/plain')
                else:
                    self._send(401, 'invalid credentials', ctype='text/plain')
                return
            try:
                parsed = json.loads(body or '{}')
            except ValueError:
                parsed = {}
            user = parsed.get('username')
            if isinstance(user, dict) or isinstance(parsed.get('password'), dict):
                # Vulnerable: the operator object is accepted and the effective
                # query is echoed with the session it created.
                self._json(200, {'query': {'username': user or {'$gt': ''}},
                                 'id': 1, 'username': 'admin',
                                 'token': 'session-token-abc123456'})
            else:
                self._json(401, {'error': 'invalid credentials'})
            return

        if path == '/api/v1/users':
            if not VULN:
                self._json(400, {'error': 'malformed json'})
                return
            try:
                json.loads(body or '{}')
                self._json(201, {'id': 3, 'created': True})
            except ValueError:
                self._send(500, STACK, ctype='application/json')
            return

        if path == '/graphql':
            if VULN:
                self._json(200, {'data': {'__schema': {'types': [
                    {'name': 'User'}, {'name': 'Order'}]}}})
            else:
                self._json(400, {'error': 'introspection disabled'})
            return

        if path == '/.env':
            self._send(405, 'Not allowed')
            return

        self._send(404, 'Not found')

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        body = self._body()
        if path.startswith('/api/v1/users/'):
            if not VULN:
                self._json(403, {'error': 'forbidden'})
                return
            try:
                sent = json.loads(body or '{}')
            except ValueError:
                sent = {}
            self._json(200, {'id': 1, 'role': sent.get('role', 'user'),
                             'is_admin': bool(sent.get('is_admin', False))})
            return
        if path == '/api/v1/profile':
            if not VULN:
                self._json(403, {'error': 'forbidden'})
                return
            try:
                sent = json.loads(body or '{}')
            except ValueError:
                sent = {}
            self._json(200, {'id': 1, 'credits': sent.get('credits', 10),
                             'role': 'user'})
            return
        self._send(404, 'Not found')

    def do_PATCH(self):
        self.do_PUT()

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith('/api/v1/users/'):
            if VULN:
                self._json(200, {'deleted': True})
            else:
                self._json(403, {'error': 'forbidden'})
            return
        self._send(404, 'Not found')


_SIGNUP_HITS = {}
_LOGIN_HITS = {}


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE-SERVICE STUBS (vuln mode only)
# ─────────────────────────────────────────────────────────────────────────────
class _Quiet(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = self.service_body(self.path)
        raw = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ElasticStub(_Quiet):
    def service_body(self, path):
        if path.startswith('/_cat/indices'):
            return ('health status index uuid pri rep docs.count\n'
                    'green  open   users   1    0   42\n'
                    'green  open   orders  1    0   7\n')
        if path.startswith('/_cluster/health'):
            return json.dumps({'cluster_name': 'demo', 'status': 'green'})
        if path.startswith('/_nodes'):
            return json.dumps({'nodes': {'n1': {'name': 'es-1'}}})
        return json.dumps({'ok': True})


class CouchStub(_Quiet):
    def service_body(self, path):
        if path.startswith('/_all_dbs'):
            return json.dumps(['_users', '_replicator', 'customers'])
        return json.dumps({'couchdb': 'Welcome', 'version': '3.3.2'})


class InfluxStub(_Quiet):
    def service_body(self, path):
        if path.startswith('/query'):
            return json.dumps({'results': [{'series': [
                {'name': 'databases', 'columns': ['name'],
                 'values': [['telegraf'], ['_internal']]}]}]})
        return json.dumps({'results': [{}]})


def _resp_array(items):
    out = [f'*{len(items)}\r\n'.encode()]
    for it in items:
        out.append(f'${len(it)}\r\n'.encode() + it + b'\r\n')
    return b''.join(out)


class RedisStub(socketserver.StreamRequestHandler):
    """Just enough RESP for PING / KEYS / CONFIG GET used by the DB probes."""

    def handle(self):
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if line.startswith(b'*'):
                try:
                    count = int(line[1:].strip())
                except ValueError:
                    return
                args = []
                for _ in range(count):
                    hdr = self.rfile.readline()
                    if not hdr.startswith(b'$'):
                        return
                    try:
                        ln = int(hdr[1:].strip())
                    except ValueError:
                        return
                    args.append(self.rfile.read(ln + 2)[:-2])
            else:
                args = line.strip().split()
            if not args:
                continue
            cmd = args[0].upper()
            if cmd == b'PING':
                self.wfile.write(b'+PONG\r\n')
            elif cmd in (b'COMMAND', b'INFO', b'SELECT'):
                self.wfile.write(b'*0\r\n')
            elif cmd == b'KEYS':
                self.wfile.write(_resp_array([b'session:abc123', b'user:1',
                                              b'token:reset-xyz']))
            elif cmd == b'CONFIG':
                if len(args) > 1 and args[1].upper() == b'GET':
                    self.wfile.write(_resp_array([b'requirepass', b'']))
                else:
                    self.wfile.write(b'*0\r\n')
            else:
                self.wfile.write(b'-ERR unknown command\r\n')


class _NoReuse(ThreadingHTTPServer):
    allow_reuse_address = True


def _serve(cls, port, name):
    try:
        srv = _NoReuse(('127.0.0.1', port), cls)
    except OSError as e:
        print(f'[fixture] {name} :{port} not started ({e})', flush=True)
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f'[fixture] {name} on 127.0.0.1:{port}', flush=True)
    return srv


def _serve_redis(port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    try:
        srv = socketserver.ThreadingTCPServer(('127.0.0.1', port), RedisStub)
    except OSError as e:
        print(f'[fixture] Redis :{port} not started ({e})', flush=True)
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f'[fixture] Redis on 127.0.0.1:{port}', flush=True)
    return srv


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    if SERVICES:
        _serve(ElasticStub, 9200, 'Elasticsearch')
        _serve(CouchStub, 5984, 'CouchDB')
        _serve(InfluxStub, 8086, 'InfluxDB')
        _serve_redis(6379)
    srv = ThreadingHTTPServer(('127.0.0.1', port), WebHandler)
    print(f'[fixture] web {MODE} on 127.0.0.1:{port}', flush=True)
    srv.serve_forever()


if __name__ == '__main__':
    main()
