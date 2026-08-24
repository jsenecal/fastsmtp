"""Every public-facing surface is plain ASCII.

Docs, README, CLI help strings and output, and code comments are read in
terminals, diffs, and rendered pages that do not all agree on encodings or
fonts. The repo rule is therefore that no ``.py``, ``.md`` or workflow YAML
file under the two ``src`` trees, ``docs/``, ``README.md``, the Alembic tree
or ``.github/`` carries a byte above 0x7F:
dashes are ``-``, ellipses are ``...``, arrows are ``->``, quotes are
straight, and diagrams are drawn with ``+ - |``.

The test trees (``fastsmtp/tests``, ``fastsmtp-cli/tests``) sit outside those
roots and are deliberately not scanned: unicode test data (the RE2
sanitizer's surrogate cases, for instance) is legitimate there.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Roots to scan, relative to the repository. A file is either a directory
#: walked recursively or a single file.
SCANNED_ROOTS = (
    "fastsmtp/src",
    "fastsmtp-cli/src",
    "docs",
    "README.md",
    "fastsmtp/alembic",
    ".github",
)

SCANNED_SUFFIXES = {".py", ".md", ".yml", ".yaml"}

#: Directory names skipped wherever they appear under a root. No scanned root
#: holds one today; this keeps an in-package ``tests/`` directory, should one
#: ever be added under ``src``, on the same footing as the top-level test trees.
EXCLUDED_DIRS = {"tests"}


def _scanned_files() -> list[Path]:
    files: list[Path] = []
    for root in SCANNED_ROOTS:
        path = REPO_ROOT / root
        if path.is_file():
            files.append(path)
            continue
        for candidate in sorted(path.rglob("*")):
            if candidate.suffix not in SCANNED_SUFFIXES or not candidate.is_file():
                continue
            if EXCLUDED_DIRS & set(candidate.relative_to(path).parts[:-1]):
                continue
            files.append(candidate)
    return files


def _violations(path: Path) -> list[str]:
    """Return ``file:line: <offending characters>`` for every non-ASCII line."""
    found: list[str] = []
    for number, raw in enumerate(path.read_bytes().splitlines(), start=1):
        if all(byte < 0x80 for byte in raw):
            continue
        offending = "".join(
            sorted({char for char in raw.decode("utf-8", errors="replace") if ord(char) > 0x7F})
        )
        found.append(f"{path.relative_to(REPO_ROOT)}:{number}: {offending!r}")
    return found


def test_scanned_roots_exist():
    """A renamed root would silently scan nothing; fail instead."""
    for root in SCANNED_ROOTS:
        assert (REPO_ROOT / root).exists(), root


def test_public_surfaces_are_ascii_only():
    violations = [line for path in _scanned_files() for line in _violations(path)]
    assert not violations, "non-ASCII characters on a public surface:\n" + "\n".join(violations)
