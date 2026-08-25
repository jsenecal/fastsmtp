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

import os
import subprocess
import sys
from pathlib import Path

import pytest


def _run_cli(
    environ: dict[str, str],
    env: dict[str, str],
    *args: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``fastsmtp <args>`` with ``env`` as the only FastSMTP configuration.

    ``environ`` is the ``scrubbed_environ`` fixture. PATH is cut down to the
    system directories on top of that: the command is started by interpreter
    path, the way a cron job or systemd unit would, so the venv's ``bin`` is
    not on PATH and Alembic has to be found through the interpreter rather
    than by name.

    ``cwd`` is the operator's working directory, which is where a ``.env``
    is looked up.
    """
    return subprocess.run(
        [sys.executable, "-m", "fastsmtp.cli", *args],
        env={**environ, "PATH": "/usr/bin:/bin", **env},
        cwd=cwd,
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


def test_importing_the_cli_does_not_load_the_api(scrubbed_environ: dict[str, str]) -> None:
    """``fastsmtp.api`` pulls in every router, FastAPI, the SMTP server and S3.

    None of that belongs on the path of ``version`` or ``db upgrade``: the CLI
    imports what a command needs inside that command, and a module-level import
    of the API package undoes that for every invocation.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, fastsmtp.cli; "
            "assert 'fastsmtp.api' not in sys.modules and 'fastapi' not in sys.modules, "
            "sorted(m for m in sys.modules if m.startswith(('fastsmtp.api', 'fastapi')))",
        ],
        env={**scrubbed_environ, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    _assert_succeeded(result)


def test_cli_binds_the_uniqueness_helpers_at_module_level() -> None:
    """``_commit_or_conflict`` used to import the violation predicate from
    ``fastsmtp.api`` inside its body to stay clear of FastAPI, and the create
    and restore commands spelled their own duplicate pre-check. Both helpers
    live in the database layer now, so the CLI binds them like any other
    module-level name, sharing the routers' exact query, and the guard above
    proves that costs no API import.
    """
    import fastsmtp.cli
    from fastsmtp.db.integrity import is_unique_violation, live_value_taken

    assert fastsmtp.cli.is_unique_violation is is_unique_violation
    assert fastsmtp.cli.live_value_taken is live_value_taken


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


class TestDotenvInTheWorkingDirectory:
    """``fastsmtp db`` and ``fastsmtp serve`` must read the same configuration
    from the same shell (issue #114).

    ``_run_alembic`` spawns Alembic with ``cwd`` set to the package directory
    so ``alembic.ini`` resolves, and settings are loaded from ``.env``
    relative to the working directory. Without the resolved URL being handed
    to the child, ``db upgrade head`` migrated the default database while
    ``serve`` in the same shell used the one the operator configured.
    """

    @staticmethod
    def _workdir(tmp_path: Path, database_url: str) -> Path:
        """An operator working directory holding a ``.env``."""
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / ".env").write_text(
            f"FASTSMTP_DATABASE_URL={database_url}\nFASTSMTP_ROOT_API_KEY=from-dotenv\n"
        )
        return workdir

    def test_db_uses_the_database_url_from_the_dotenv(
        self, scrubbed_environ: dict[str, str], tmp_path: Path
    ) -> None:
        """Connecting creates the SQLite file, so its existence proves which
        database Alembic actually opened."""
        database_path = tmp_path / "from-dotenv.db"
        workdir = self._workdir(tmp_path, f"sqlite+aiosqlite:///{database_path}")

        result = _run_cli(scrubbed_environ, {}, "db", "current", cwd=workdir)

        _assert_succeeded(result)
        assert database_path.exists()

    def test_db_and_show_config_resolve_the_same_url(
        self, scrubbed_environ: dict[str, str], tmp_path: Path
    ) -> None:
        """``show-config`` is what ``serve`` loads; both must name one database."""
        database_url = f"sqlite+aiosqlite:///{tmp_path}/agreed.db"
        workdir = self._workdir(tmp_path, database_url)

        # Rich truncates a cell wider than the console, so the table is given
        # room rather than the assertion being loosened.
        shown = _run_cli(scrubbed_environ, {"COLUMNS": "250"}, "show-config", cwd=workdir)
        _assert_succeeded(shown)

        assert database_url in shown.stdout

    def test_an_explicit_environment_variable_still_wins(
        self, scrubbed_environ: dict[str, str], tmp_path: Path
    ) -> None:
        """The usual pydantic-settings precedence: the environment beats ``.env``."""
        database_path = tmp_path / "from-environ.db"
        workdir = self._workdir(tmp_path, f"sqlite+aiosqlite:///{tmp_path}/from-dotenv.db")

        result = _run_cli(
            scrubbed_environ,
            {"FASTSMTP_DATABASE_URL": f"sqlite+aiosqlite:///{database_path}"},
            "db",
            "current",
            cwd=workdir,
        )

        _assert_succeeded(result)
        assert database_path.exists()
        assert not (tmp_path / "from-dotenv.db").exists()


class TestAlembicEnvironment:
    """The same contract as the class above, in process.

    Everything above proves it end to end through a child process, which is
    where the bug lived and the only place it can be shown; none of it
    executes a line of ``fastsmtp.cli`` in the test interpreter. These pin the
    two pieces directly: what the environment is built from, and that
    ``_run_alembic`` actually hands it to Alembic.
    """

    def test_the_url_is_resolved_from_the_working_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from fastsmtp import cli

        (tmp_path / ".env").write_text("FASTSMTP_DATABASE_URL=sqlite+aiosqlite:///from-dotenv.db\n")
        monkeypatch.delenv("FASTSMTP_DATABASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)

        environ = cli._alembic_environ()

        assert environ["FASTSMTP_DATABASE_URL"] == "sqlite+aiosqlite:///from-dotenv.db"
        # The rest of the environment is carried through, not replaced.
        assert environ["PATH"] == os.environ["PATH"]

    def test_run_alembic_hands_that_environment_to_the_child(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from fastsmtp.db.migrations import alembic_ini_path

        from fastsmtp import cli

        (tmp_path / ".env").write_text("FASTSMTP_DATABASE_URL=sqlite+aiosqlite:///child.db\n")
        monkeypatch.delenv("FASTSMTP_DATABASE_URL", raising=False)
        monkeypatch.chdir(tmp_path)

        recorded: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            recorded["cmd"] = cmd
            recorded.update(kwargs)
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(cli.subprocess, "run", fake_run)

        cli._run_alembic("current")

        # The child still runs from the package directory, so alembic.ini and
        # the script location resolve; only the environment is new.
        assert recorded["cwd"] == alembic_ini_path().parent
        env = recorded["env"]
        assert isinstance(env, dict)
        assert env["FASTSMTP_DATABASE_URL"] == "sqlite+aiosqlite:///child.db"
