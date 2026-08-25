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

import logging
import subprocess
import sys
from pathlib import Path

import pytest
import typer
from alembic.config import Config
from alembic.util.exc import CommandError


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

    Settings are loaded from a ``.env`` relative to the working directory.
    Alembic used to run in a child process started from the package directory,
    where that lookup found nothing, so ``db upgrade head`` migrated the
    default database while ``serve`` in the same shell used the one the
    operator configured. Alembic runs in this process now, which is what makes
    the two agree; these hold that end result whatever moves underneath.
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


class TestAlembicInvocation:
    """``fastsmtp db`` drives Alembic in process against the packaged scripts.

    The commands used to be spawned as ``python -m alembic -c <ini>`` from the
    package directory, which is what forced the ini to be located by walking up
    from ``__file__`` and what made the child resolve settings against the
    wrong working directory. The class above proves the end result end to end;
    these pin the two pieces the CLI is now responsible for.
    """

    def test_the_config_names_the_packaged_scripts(self) -> None:
        from fastsmtp.db.migrations import alembic_config, alembic_script_location

        location = Path(alembic_config().get_main_option("script_location") or "")

        assert location == alembic_script_location()
        assert (location / "versions" / "001_initial_schema.py").is_file()
        # Inside the package, which is what puts it in a wheel.
        assert location.parent.name == "fastsmtp"

    def test_run_alembic_passes_that_config_and_the_arguments(self) -> None:
        from fastsmtp.db.migrations import alembic_script_location

        from fastsmtp import cli

        recorded: dict[str, object] = {}

        def fake_command(config: Config, *args: object, **kwargs: object) -> None:
            recorded["script_location"] = config.get_main_option("script_location")
            recorded["args"] = args
            recorded["kwargs"] = kwargs

        cli._run_alembic(fake_command, "head")

        assert recorded["script_location"] == str(alembic_script_location())
        assert recorded["args"] == ("head",)
        assert recorded["kwargs"] == {}

    def test_a_bad_revision_exits_1_rather_than_raising(self) -> None:
        """Alembic reports an unknown revision as a CommandError. That is a
        typo, not a crash, so it is printed and exits 1 - the same shape the
        child process's non-zero exit used to produce."""
        from fastsmtp import cli

        def fake_command(config: Config, *args: object, **kwargs: object) -> None:
            raise CommandError("Can't locate revision identified by 'nope'")

        with pytest.raises(typer.Exit) as exc_info:
            cli._run_alembic(fake_command, "nope")

        assert exc_info.value.exit_code == 1


class TestMigrationLogging:
    """``db upgrade`` must say what it applied.

    Alembic reports each revision through the ``alembic`` logger at INFO. The
    ini used to configure a console handler for it, and ``fileConfig`` wiped
    the library's own handlers on the way; with the ini gone the CLI attaches
    that handler itself, and an operator who gets no output cannot tell a
    successful chain from a no-op.
    """

    @staticmethod
    def _reset() -> logging.Logger:
        """The ``alembic`` logger as a fresh process would see it: importing
        ``alembic`` installs a ``NullHandler`` on it and nothing else."""
        logger = logging.getLogger("alembic")
        logger.handlers = [logging.NullHandler()]
        return logger

    def test_a_real_handler_is_attached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The trap: ``alembic/util/messaging.py`` adds a ``NullHandler`` at
        import time, so "does this logger already have handlers" is true before
        anything useful is attached, and a guard written that way silently
        leaves the output going nowhere."""
        from fastsmtp import cli

        logger = self._reset()
        monkeypatch.setattr(logger, "handlers", logger.handlers, raising=False)

        cli._configure_migration_logging()

        emitting = [h for h in logger.handlers if not isinstance(h, logging.NullHandler)]
        assert emitting, "only a NullHandler is attached; migration output goes nowhere"
        assert logger.getEffectiveLevel() <= logging.INFO

    def test_it_does_not_stack_handlers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every db command calls it, and a process that runs two would
        otherwise print each line twice."""
        from fastsmtp import cli

        logger = self._reset()
        monkeypatch.setattr(logger, "handlers", logger.handlers, raising=False)

        cli._configure_migration_logging()
        cli._configure_migration_logging()

        emitting = [h for h in logger.handlers if not isinstance(h, logging.NullHandler)]
        assert len(emitting) == 1
