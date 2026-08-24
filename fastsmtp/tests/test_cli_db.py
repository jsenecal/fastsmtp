"""``fastsmtp db`` must run with nothing configured but the database URL.

A one-off migration pod given only ``FASTSMTP_DATABASE_URL`` died with a
pydantic ``ValidationError`` for ``root_api_key`` (issue #110). Two things
loaded the full ``Settings`` on that path, and both have to stay fixed:

* ``fastsmtp/db/__init__.py`` imported the lazily-built ``engine`` from
  ``db/session.py``, so *importing* ``fastsmtp.db`` built the engine and the
  settings. The ``fastsmtp`` entry point reaches it through ``fastsmtp.auth``,
  and ``alembic/env.py`` through ``fastsmtp.db.models`` -- every subcommand
  failed before doing anything, ``version`` included.
* ``alembic/env.py`` resolved the URL from ``get_settings()`` rather than from
  a view scoped to the database.

These tests run the real command in a child process with the
``scrubbed_environ`` fixture: every ``FASTSMTP_*`` variable the test session
carries is dropped, and only what the test sets is passed through.
"""

import subprocess
import sys
from pathlib import Path

import pytest


def _run_cli(
    environ: dict[str, str], env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    """Run ``fastsmtp <args>`` with ``env`` as the only FastSMTP configuration.

    ``environ`` is the ``scrubbed_environ`` fixture. PATH is cut down to the
    system directories on top of that: the command is started by interpreter
    path, the way a cron job or systemd unit would, so the venv's ``bin`` is
    not on PATH and Alembic has to be found through the interpreter rather
    than by name.
    """
    return subprocess.run(
        [sys.executable, "-m", "fastsmtp.cli", *args],
        env={**environ, "PATH": "/usr/bin:/bin", **env},
        capture_output=True,
        text=True,
    )


def _assert_succeeded(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"exited {result.returncode}\n--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )
    assert "ValidationError" not in result.stderr


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    """A throwaway SQLite database; ``db current`` only reads ``alembic_version``."""
    return f"sqlite+aiosqlite:///{tmp_path}/cli.db"


def test_cli_loads_without_any_configuration(scrubbed_environ: dict[str, str]) -> None:
    """Importing the CLI must not build settings; ``version`` reads none."""
    result = _run_cli(scrubbed_environ, {}, "version")
    _assert_succeeded(result)
    assert "FastSMTP version" in result.stdout


def test_db_current_needs_only_the_database_url(
    scrubbed_environ: dict[str, str], database_url: str
) -> None:
    """No root API key, no S3 settings: the migration path must not ask for them."""
    result = _run_cli(scrubbed_environ, {"FASTSMTP_DATABASE_URL": database_url}, "db", "current")
    _assert_succeeded(result)


def test_db_current_is_not_subject_to_the_s3_cross_field_validation(
    scrubbed_environ: dict[str, str], database_url: str
) -> None:
    """``attachment_storage=s3`` without credentials is a ``serve`` startup error.

    The migration path reads nothing but the URL, so it must not trip
    ``validate_s3_config`` on settings it never uses -- a config map shared with
    the serving pods must not break the migration Job.
    """
    result = _run_cli(
        scrubbed_environ,
        {"FASTSMTP_DATABASE_URL": database_url, "FASTSMTP_ATTACHMENT_STORAGE": "s3"},
        "db",
        "current",
    )
    _assert_succeeded(result)
