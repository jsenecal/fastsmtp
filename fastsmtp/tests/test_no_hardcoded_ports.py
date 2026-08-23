"""Guard: no test may hard-code a bindable port number.

Fixed ports collide across concurrent test runs (issue #87), and a port
probed for freeness ahead of time can be stolen before the server binds it
(issue #98). The sanctioned pattern is binding port 0 and reading the
OS-assigned port back after start -- ``SMTPServer.bound_smtp_port`` /
``bound_smtp_tls_port``; conftest's ``make_smtp_settings`` does this by
default, and the live-server fixture does the same for uvicorn.

``conftest.py`` is exempt: its port literals are never bound, and the comment
on them records that invariant.

The scan is deliberately dumb -- a regex over file text, no AST -- so it stays
readable and cheap. Port 0 is allowed everywhere; it is the "let the OS pick"
value, not a stealable reservation.
"""

import re
from pathlib import Path

TESTS_DIR = Path(__file__).parent

# A bound-port kwarg assigned a nonzero integer literal. Matches a single "="
# (keyword argument or assignment), not "==" comparisons.
HARDCODED_PORT = re.compile(r"\b(smtp_port|smtp_tls_port|api_port)\s*=\s*0*[1-9][0-9]*")


def test_no_hardcoded_bindable_ports() -> None:
    """Scan the test tree for literal bound-port kwargs outside conftest.py."""
    offenders = []
    for path in sorted(TESTS_DIR.glob("*.py")):
        if path.name == "conftest.py":
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if HARDCODED_PORT.search(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")

    assert not offenders, (
        "Hard-coded bindable port(s) in tests -- bind port 0 and read the "
        "OS-assigned port back instead (see make_smtp_settings in conftest.py):\n"
        + "\n".join(offenders)
    )
