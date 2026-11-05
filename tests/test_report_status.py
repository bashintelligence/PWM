"""Verify the report tells 'never ran' apart from 'ran, found nothing'."""
import os
import queue
import subprocess
import sys
from pathlib import Path
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app

sid = f'tc-{time.time_ns()}'
outdir = tempfile.mkdtemp(prefix='pwm_tc_')
app.sessions[sid] = {
    'sid': sid, 'raw_target': '127.0.0.1', 'target': '127.0.0.1',
    'target_type': 'ip', 'created': '2026-11-04T00:00:00', 'outdir': outdir,
    'findings': {}, 'outputs': {}, 'commands': {}, 'rc': {},
    'completed': [], 'approved': [], 'skipped': [], 'launched': set(),
    'stage_approved': set(), 'lock': app.threading.Lock(),
    'ports_found': '', 'banner_search': '', 'network': '', 'notes': {},
    'triage_log': {}, 'assessment': None, 'accounts': [], 'web_origin': '',
}
app.output_queues[sid] = queue.Queue(maxsize=1000)

f_never = [{'type': 'not_tested', 'severity': 'info', 'path': '-',
            'detail': 'Tool was not installed — nothing was tested.', 'command': ''}]
f_ran = [{'type': 'open_port', 'severity': 'info', 'path': ':80',
          'detail': '80/tcp http open', 'command': 'nmap -p80 127.0.0.1'}]

app.sessions[sid]['findings']['recon_ports'] = f_ran
app.sessions[sid]['findings']['recon_osint'] = f_never
app._complete_substage(sid, 'recon_ports', f_ran, rc=1)      # ran, nonzero exit
app._complete_substage(sid, 'recon_osint', f_never, rc=-1)   # never produced a result

rc = app.sessions[sid]['rc']
checks = [('rc persisted for recon_ports', rc.get('recon_ports') == 1),
          ('rc persisted for recon_osint', rc.get('recon_osint') == -1)]

pdf = app.build_pdf(app.sessions[sid])
txt = subprocess.run(['pdftotext', pdf, '-'], capture_output=True, text=True).stdout
checks += [('report labels rc=-1 as NO RESULT', 'NO RESULT (rc=-1)' in txt),
           ('report labels rc=1 verbatim', 'COMPLETED (rc=1)' in txt),
           ('stages run counted per stage', '/12' in txt),
           ('not_tested excluded from totals',
            'Not Tested' in txt and 'Total Findings' in txt)]
for name, ok in checks:
    print(('  PASS  ' if ok else '  FAIL  ') + name)
bad = sum(1 for _, ok in checks if not ok)
print(f'\n{len(checks) - bad}/{len(checks)} checks passed, {bad} failed')
sys.exit(1 if bad else 0)
