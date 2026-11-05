#!/usr/bin/env python3
"""Run every PWM audit suite.

Each suite is a standalone script that exits non-zero on failure; this runner
executes them in a fixed order and aggregates the result.

    python3 tests/run_all.py              # all suites
    python3 tests/run_all.py templates    # suites matching that word

Run it with the interpreter that has the app's requirements installed (the
project venv), e.g. ``venv/bin/python3 tests/run_all.py``.
"""
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SUITES = [
    ('engine', 'test_engine_fixes.py'),
    ('parsers', 'test_parser_false_positives.py'),
    ('templates', 'test_templates.py'),
    ('sessions', 'test_session_checks.py'),
    ('inprocess', 'test_inprocess_probes.py'),
    ('live', 'test_live_parsers.py'),
    ('report', 'test_report_status.py'),
]


def main(argv):
    want = argv[1].lower() if len(argv) > 1 else ''
    selected = [(tag, TESTS / name) for tag, name in SUITES
                if want in (tag + name).lower()]
    if not selected:
        print(f'no suite matches {want!r}; available: '
              + ', '.join(tag for tag, _ in SUITES))
        return 2

    results = []
    for tag, path in selected:
        print(f'\n===== {tag}: {path.name} =====', flush=True)
        proc = subprocess.run([sys.executable, str(path)],
                              capture_output=True, text=True)
        lines = proc.stdout.strip().splitlines()
        for line in lines:
            if line.lstrip().startswith(('FAIL', '>>>')) or 'RESULT' in line \
                    or 'checks passed' in line:
                print(line)
        if proc.returncode and proc.stderr.strip():
            print(proc.stderr.strip()[-1500:])
        results.append((tag, proc.returncode == 0,
                        lines[-1] if lines else '(no output)'))

    print('\n===== summary =====')
    for tag, ok, summary in results:
        print(f'  {"PASS" if ok else "FAIL"}  {tag:<10} {summary}')
    failed = [tag for tag, ok, _ in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} suites passed'
          + (f' — failed: {", ".join(failed)}' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
