# Pentest Workflow Manager (PWM)

![PWM Dashboard](assets/dashboard.png)

## Features

- 12-stage automated "kill chain" workflow: Reconnaissance, Vulnerability Analysis, Deep & Zero-Day Analysis, API Vulnerability Scan, Database Vulnerability Scan, Registration & Account Provisioning, Authentication & Login, Session Management, Authorization & Access Control, Business Logic, Exploitation Prep, and Post-Exploitation Review
- Flask-based web app with live, real-time output streaming (Server-Sent Events) to a browser frontend
- Port and service scanning via nmap / masscan (full TCP sweep + targeted service/version detection)
- UDP service probing (SNMP, DNS, TFTP, NTP, LDAP, etc.)
- DNS enumeration, zone transfer attempts, and DMARC/wildcard checks
- HTTP/S fingerprinting, WAF/CDN detection, and technology stack identification
- SMB/RPC/NetBIOS enumeration (null sessions, share listing, domain/user enumeration)
- WHOIS, ASN, certificate transparency, and OSINT/subdomain discovery
- CVE mapping via nmap vulners/vulscan and Nuclei template scanning
- ExploitDB lookups via searchsploit
- Web directory/file brute-forcing (gobuster/ffuf) and Nikto web audits
- Deep TLS/SSL analysis: protocol and cipher-suite audit via sslscan/testssl, certificate checks, and Heartbleed detection
- SNMP community string probing
- SMTP/LDAP/FTP security audits
- Banner anomaly detection and version-gap/EOL analysis against a built-in version database
- HTTP behaviour anomaly probes (path traversal, verb tampering, host header injection)
- Timing/side-channel probes for blind SQL injection and authentication oracles
- Authentication and session weakness checks (default credentials, cookie flags)
- XSS, SSTI, XXE, and open-redirect injection surface probing
- CMS and framework detection (WordPress, Drupal, Joomla, Laravel, Django, Rails)
- OWASP API Top-10 style testing: endpoint discovery, BOLA/IDOR, broken authentication, injection, SSRF, mass assignment, and misconfiguration checks
- Database vulnerability scanning across MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, Cassandra, Elasticsearch, InfluxDB, and Neo4j
- Unauthenticated database access and default credential testing
- Automated SQL injection auditing via sqlmap, plus manual and second-order SQLi probes
- NoSQL injection detection
- Database privilege and configuration auditing
- Exploitation preparation: default credential brute-forcing (hydra), Metasploit safe (non-destructive) checks, sqlmap verification, and exploit/CVE cross-referencing
- Post-exploitation review: network segment discovery, privilege escalation vector lookup, high-value service mapping, credential/secret harvesting, and Active Directory enumeration
- Structured findings output with severity ratings, affected paths, and remediation commands
- PDF report generation with proof-of-concept and code-fix remediation examples
- Command injection safeguards via target input validation and sanitization
- Optional API token authentication (`PWM_API_TOKEN`): header/query token for scripts, and a `/auth` page that stores the token in an HttpOnly cookie so the bundled UI and its EventSource stream work without custom headers

## Installation

```bash
git clone https://github.com/spidermalops/PWM.git
```

## Setup

```bash
cd PWM
```

**Linux / macOS**

```bash
python3 -m venv venv && source venv/bin/activate
```

**Windows**

```bash
python -m venv venv
source venv\Scripts\activate
```

## Usage

**Linux / macOS**

```bash
python3 app.py
```

**Windows**

```bash
python app.py
```
## Testing

Seven standalone audit suites cover the "no fabricated results" guards:

| Suite | Covers |
|---|---|
| `test_engine_fixes.py` | port-state parsing, signature false positives, JWT header decode, evidence URLs, stage sequencing |
| `test_parser_false_positives.py` | negative/positive tool-output fixtures for every substage parser |
| `test_templates.py` | probe time bounds, template↔parser contracts, timeout-vs-delay handling |
| `test_session_checks.py` | session-id and cookie/SameSite evidence rules |
| `test_inprocess_probes.py` | in-process auth/registration probes against a correct vs. flawed app |
| `test_live_parsers.py` | runs the real API/CMS/DB commands against the fixture and dispatches output to the real parsers |
| `test_report_status.py` | report metrics and exit-status truth |

```bash
# all suites (use the venv interpreter that has requirements installed)
venv/bin/python3 tests/run_all.py

# one suite only
venv/bin/python3 tests/run_all.py templates
```

Each suite runs in-process and needs no server or external target. Two of them
start the bundled fixture `tests/fixtures/vuln_app.py`: `test_inprocess_probes.py`
on 127.0.0.1:8099/8100 and `test_live_parsers.py` on 127.0.0.1:8110/8111. The
fixture has a `secure` mode (correct behaviour — a correct tool must stay
silent) and a `vuln` mode (deliberately flawed — detections must still fire).
It serves the login/registration surface, an API surface (users, admin, config,
search/render, fetch/proxy, swagger, actuator, GraphQL) and CMS fingerprints
(WordPress, Drupal, Joomla), and in `vuln` mode also starts database-service
stubs on their real ports (Redis 6379, InfluxDB 8086, Elasticsearch 9200,
CouchDB 5984) so the DB probes have a live target. Set `FIXTURE_SERVICES=0` to
skip those stubs, `FIXTURE_MODE=vuln|secure` to choose the mode, and
`PWM_FIXTURE_VULN_PORT` / `PWM_FIXTURE_SEC_PORT` to move the web listeners.
`test_live_parsers.py` therefore needs `curl`, `nmap` and `redis-cli` (and uses
`wpscan` when present); substages whose tools are missing are reported as
skipped rather than passing. A suite exits non-zero on failure and the runner
exits non-zero if any suite fails.
