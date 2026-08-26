"""A database password must never reach rendered output (issue #140).

``fastsmtp show-config`` in an environment holding ``FASTSMTP_DATABASE_URL`` but
no ``FASTSMTP_ROOT_API_KEY`` printed the password. The pydantic
``ValidationError`` message itself was clean; the disclosure came from Typer's
pretty traceback rendering *frame locals*, one of which was pydantic's ``data``
dict holding the raw URL.

Two independent causes, so two independent defences, and these tests are written
against the observable rather than against either mechanism:

* Typer's ``pretty_exceptions_show_locals`` is off, which closes the whole class
  -- any secret in any frame local on any exception path.
* ``database_url`` is a ``SecretStr``, so the value renders as ``**********``
  wherever it is echoed. ``show-config`` is the one deliberate exception: it
  prints the URL with only the password redacted, by SQLAlchemy's own
  renderer, because an operator who cannot see which database they are
  pointed at will go and read the raw environment instead.

The end-to-end test below is the one that matters: it runs the real command in a
child process and asserts the password is absent from everything the operator
sees. "Is this field a ``SecretStr``" is not the regression; "can a credential
reach a terminal" is.
"""

import subprocess
import sys

import pytest
from fastsmtp.config import DatabaseSettings, Settings

#: Distinctive enough that no assertion below can pass by coincidence.
PASSWORD = "SUPERSECRETPW"
DATABASE_URL = f"postgresql+asyncpg://fastsmtp:{PASSWORD}@db/fastsmtp"


def _run_cli(
    environ: dict[str, str], env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    """Run ``fastsmtp <args>`` with ``env`` as the only FastSMTP configuration.

    ``COLUMNS`` is pinned wide so that a Rich panel cannot wrap or truncate the
    password into something an ``in`` check would miss: the test must fail on
    the unfixed code for the right reason.
    """
    return subprocess.run(
        [sys.executable, "-m", "fastsmtp.cli", *args],
        env={**environ, "PATH": "/usr/bin:/bin", "COLUMNS": "250", **env},
        capture_output=True,
        text=True,
    )


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


class TestTheCommandLineNeverPrintsIt:
    """The end-to-end proof, in a child process, exactly as reported."""

    def test_a_validation_failure_does_not_print_the_database_password(
        self, scrubbed_environ: dict[str, str]
    ) -> None:
        """The reported reproduction: a database URL, no root API key.

        ``Settings()`` raises for the missing ``root_api_key``. The command is
        expected to fail; what it must not do is show the password while it
        fails.
        """
        result = _run_cli(scrubbed_environ, {"FASTSMTP_DATABASE_URL": DATABASE_URL}, "show-config")

        assert result.returncode != 0, "the missing root API key should still be an error"
        assert PASSWORD not in _output(result)

    def test_show_config_redacts_only_the_password(self, scrubbed_environ: dict[str, str]) -> None:
        """The password goes; the host and database name stay.

        Masking the whole URL would be safe and useless: "which database am I
        pointed at" is most of why anyone runs ``show-config``, and an operator
        who cannot answer it from the tool will read the raw environment
        instead, which shows them the password anyway.

        The redaction is SQLAlchemy's own ``render_as_string(hide_password=True)``
        rather than anything hand-written here, so there is no parser of ours
        between the credential and the terminal.
        """
        result = _run_cli(
            scrubbed_environ,
            {"FASTSMTP_DATABASE_URL": DATABASE_URL, "FASTSMTP_ROOT_API_KEY": "root-key"},
            "show-config",
        )

        assert result.returncode == 0, _output(result)
        assert "database_url" in result.stdout
        assert PASSWORD not in _output(result)
        # Rich truncates the cell to the terminal width, so assert on the part
        # that always survives: the scheme, and the redaction marker.
        assert "postgresql+asyncpg://" in result.stdout
        assert "***" in result.stdout

    def test_show_config_redaction_runs_in_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The same assertion as above, in this process rather than a child.

        The subprocess test is the honest one: it runs the real entry point the
        way an operator does. But nothing it executes is visible to coverage, so
        the branch that does the redacting looked untested and would have been
        free to rot. This drives the same code through Typer's runner in-process
        so the rendering path is actually exercised where it can be seen.

        Both are kept deliberately. Drop the subprocess one and the end-to-end
        guarantee goes; drop this one and the redaction is only ever run where
        no tool is watching.
        """
        from fastsmtp.config import clear_settings_cache
        from typer.testing import CliRunner

        from fastsmtp import cli

        monkeypatch.setenv("FASTSMTP_DATABASE_URL", DATABASE_URL)
        monkeypatch.setenv("FASTSMTP_ROOT_API_KEY", "root-key")
        monkeypatch.setenv("COLUMNS", "250")
        clear_settings_cache()

        try:
            result = CliRunner().invoke(cli.app, ["show-config"])

            assert result.exit_code == 0, result.output
            assert PASSWORD not in result.output
            assert "postgresql+asyncpg://" in result.output
            assert "***" in result.output
        finally:
            clear_settings_cache()

    def test_typer_does_not_render_frame_locals(self) -> None:
        """The class-wide defence, pinned so it is not turned back on.

        The two tests above would keep passing if only ``SecretStr`` were in
        place, and the next unmasked secret to sit in a frame local would leak
        exactly the same way.
        """
        from fastsmtp.cli import app

        assert app.pretty_exceptions_show_locals is False


class TestTheSettingsObjectNeverShowsIt:
    @pytest.fixture
    def settings(self) -> Settings:
        return Settings(_env_file=None, database_url=DATABASE_URL, root_api_key="root-key")

    def test_repr_does_not_contain_the_password(self, settings: Settings) -> None:
        assert PASSWORD not in repr(settings)

    def test_str_does_not_contain_the_password(self, settings: Settings) -> None:
        assert PASSWORD not in str(settings)

    def test_model_dump_does_not_contain_the_password(self, settings: Settings) -> None:
        """Anything that logs a settings dump -- a debug endpoint, a crash
        reporter -- renders the values, and rendering a ``SecretStr`` masks it."""
        assert PASSWORD not in str(settings.model_dump())


class TestTheValueStillWorks:
    """Masking that broke the plumbing would be worse than the leak."""

    def test_the_full_settings_hand_back_the_real_url(self) -> None:
        settings = Settings(_env_file=None, database_url=DATABASE_URL, root_api_key="root-key")

        assert settings.database_dsn == DATABASE_URL

    def test_the_database_scoped_settings_hand_back_the_real_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``fastsmtp db`` and ``alembic/env.py`` load this narrower view."""
        monkeypatch.delenv("FASTSMTP_ROOT_API_KEY", raising=False)
        monkeypatch.setenv("FASTSMTP_DATABASE_URL", DATABASE_URL)

        assert DatabaseSettings(_env_file=None).database_dsn == DATABASE_URL

    def test_the_default_url_is_a_usable_string(self) -> None:
        """Pydantic does not validate defaults, so a plain ``str`` default would
        survive as a ``str`` and break ``.get_secret_value()`` for anyone who
        configured nothing."""
        settings = DatabaseSettings(_env_file=None)

        assert settings.database_dsn.startswith("postgresql+asyncpg://")

    def test_an_engine_can_still_be_built_from_it(self) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine

        settings = Settings(
            _env_file=None,
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="root-key",
        )
        engine = create_async_engine(settings.database_dsn)

        assert engine.url.drivername == "sqlite+aiosqlite"

    def test_the_application_engine_is_built_from_the_masked_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real path, not a stand-in: ``get_engine`` is what the app runs on.

        The test above builds an engine itself, which proves the accessor
        returns something usable but not that the one place the application
        opens its own connection was converted. ``get_engine`` also branches on
        the URL text to decide whether to pass pool arguments, so a SecretStr
        reaching it would fail on ``.startswith`` before ``create_async_engine``
        ever saw it.
        """
        from fastsmtp.config import clear_settings_cache
        from fastsmtp.db import session as session_module

        monkeypatch.setenv("FASTSMTP_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
        monkeypatch.setenv("FASTSMTP_ROOT_API_KEY", "root-key")
        monkeypatch.setattr(session_module, "_engine", None)
        clear_settings_cache()

        try:
            engine = session_module.get_engine()
            assert engine.url.drivername == "sqlite+aiosqlite"
        finally:
            monkeypatch.setattr(session_module, "_engine", None)
            clear_settings_cache()

    def test_the_pooled_branch_also_reads_the_masked_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-sqlite URL takes the other branch, where the pool arguments are
        added. ``create_async_engine`` opens no connection, so this needs no
        database."""
        from fastsmtp.config import clear_settings_cache
        from fastsmtp.db import session as session_module

        monkeypatch.setenv("FASTSMTP_DATABASE_URL", DATABASE_URL)
        monkeypatch.setenv("FASTSMTP_ROOT_API_KEY", "root-key")
        monkeypatch.setattr(session_module, "_engine", None)
        clear_settings_cache()

        try:
            engine = session_module.get_engine()
            assert engine.url.drivername == "postgresql+asyncpg"
            assert PASSWORD not in repr(engine)
        finally:
            monkeypatch.setattr(session_module, "_engine", None)
            clear_settings_cache()

    async def test_the_startup_guard_opens_its_own_connection(self) -> None:
        """The lifespan builds a second, throwaway engine for the startup checks.

        It is a separate call site from ``get_engine`` - deliberately, so that a
        ``create_app(settings=...)`` override checks the database it was handed
        rather than the process-wide one - and therefore needed converting
        separately. Running the lifespan is the only way to prove it was.

        The schema check finds no ``alembic_version`` table here, which it
        treats as "cannot compare" and allows, so this asserts the guard ran
        without raising rather than asserting a revision.
        """
        from fastsmtp.main import create_app, lifespan

        settings = Settings(
            _env_file=None,
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="root-key",
            verify_schema_on_startup=True,
            verify_encryption_on_startup=False,
        )
        app = create_app(settings)

        async with lifespan(app):
            pass
