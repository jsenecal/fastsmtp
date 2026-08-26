"""The startup guards run for every mode of ``fastsmtp serve`` (issue #138).

``verify_schema_is_current`` used to run only from the FastAPI lifespan, and
the lifespan runs only when uvicorn does. ``serve --worker-only`` and
``serve --smtp-only`` start no uvicorn, so they connected to whatever database
they were given and began claiming deliveries against a schema they did not
match - exactly the failure #83 added the guard to prevent, absent for the one
component the Compose and Kubernetes examples scale out.

How this is tested
------------------
``serve`` is driven for real, not through a stand-in for the guard: the
property is "a --worker-only process refuses to start", and only the command
itself can show that. What is replaced is the components, so nothing binds a
port or opens a delivery loop. That substitution is also what makes the
control test possible - with fake components ``serve --worker-only`` starts
them and returns, so a run that gets past the guard is observable as "the
worker started" rather than as a hang.

The stale database is real: an ``alembic_version`` table naming the revision
below head, which is what an unmigrated deployment looks like. The suite
builds its schema with ``create_all`` and so has no such table at all, and an
unmanaged database is deliberately allowed - that is the control below, and it
is why the fixture has to write the table rather than leave the check to find
nothing.
"""

import pytest
import pytest_asyncio
from alembic.script import ScriptDirectory
from fastsmtp.db.encryption_guard import EncryptionKeyMissingError
from fastsmtp.db.migrations import alembic_config, expected_head_revision
from sqlalchemy import text


def revision_below_head() -> str:
    """The revision one step behind this build's head.

    Derived from the migration chain rather than hard-coded, so it keeps
    meaning "behind by one" as revisions are added.
    """
    head = expected_head_revision()
    down = ScriptDirectory.from_config(alembic_config()).get_revision(head).down_revision
    assert isinstance(down, str), "expected a linear migration chain below head"
    return down


class StartedFlag:
    """Records that a component was started, and starts nothing."""

    def __init__(self) -> None:
        self.started = False


class FakeWorker:
    """Stands in for WebhookWorker and CleanupWorker (sync ``start``)."""

    def __init__(self, flag: StartedFlag) -> None:
        self._flag = flag
        self.enabled = False  # CleanupWorker's console line reads this

    def __call__(self, settings) -> "FakeWorker":
        return self

    def start(self) -> None:
        self._flag.started = True


class FakeSMTPServer:
    """Stands in for SMTPServer, whose ``start`` is a coroutine that binds."""

    def __init__(self, flag: StartedFlag) -> None:
        self._flag = flag

    def __call__(self, settings) -> "FakeSMTPServer":
        return self

    async def start(self) -> None:
        self._flag.started = True


class FakeUvicornServer:
    """Stands in for uvicorn.Server, which would otherwise bind and never return."""

    def __init__(self, flag: StartedFlag) -> None:
        self._flag = flag

    def __call__(self, config) -> "FakeUvicornServer":
        return self

    async def serve(self) -> None:
        self._flag.started = True


@pytest.fixture
def components(monkeypatch):
    """Replace every component ``serve`` can start; returns the started flags.

    ``serve`` imports them inside the command body, so patching the defining
    modules is what the lookup sees. Replacing them all is what keeps a
    regression in the guard a failing assertion rather than a hung test: no
    port is bound, no delivery loop opens, and ``serve`` returns as soon as it
    has started what it was asked for.
    """
    worker, cleanup, smtp, api = StartedFlag(), StartedFlag(), StartedFlag(), StartedFlag()
    monkeypatch.setattr("fastsmtp.webhook.WebhookWorker", FakeWorker(worker))
    monkeypatch.setattr("fastsmtp.cleanup.CleanupWorker", FakeWorker(cleanup))
    monkeypatch.setattr("fastsmtp.smtp.SMTPServer", FakeSMTPServer(smtp))
    monkeypatch.setattr("uvicorn.Server", FakeUvicornServer(api))
    return {"worker": worker, "cleanup": cleanup, "smtp": smtp, "api": api}


@pytest.fixture
def serve_settings(test_settings, monkeypatch):
    """Point ``serve`` at the test database. Returns a mutator for overrides."""

    def use(**overrides) -> None:
        settings = test_settings.model_copy(update=overrides) if overrides else test_settings
        monkeypatch.setattr("fastsmtp.config.get_settings", lambda: settings)

    use()
    return use


@pytest_asyncio.fixture
async def stale_schema(test_engine):
    """Give the test database an ``alembic_version`` one revision behind head."""
    revision = revision_below_head()
    async with test_engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
        await conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        await conn.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:rev)"), {"rev": revision}
        )

    yield revision

    # Not part of Base.metadata, so the per-test drop_all would leave it behind
    # for every test that follows in this session.
    async with test_engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))


class TestSchemaGuardCoversEveryServeMode:
    @pytest.mark.parametrize("mode", ["--worker-only", "--smtp-only", "--api-only"])
    def test_a_database_behind_its_migrations_refuses_to_start(
        self, run, serve_settings, components, stale_schema, mode
    ):
        code, out = run("serve", mode)
        assert code == 1
        assert f"Database schema is at revision {stale_schema}" in out
        assert "fastsmtp db upgrade head" in out
        assert "Traceback" not in out
        # The guard runs before any component, so none of them started.
        assert not any(flag.started for flag in components.values())

    def test_the_worker_starts_when_the_check_passes(self, run, serve_settings, components):
        """The control: without the stale table this run reaches the worker.

        Without it the refusal above could pass for a reason that has nothing
        to do with the guard - a serve that never gets that far at all. The
        suite's schema has no ``alembic_version``, which the guard reports and
        allows.
        """
        code, out = run("serve", "--worker-only")
        assert code == 0, out
        assert components["worker"].started
        assert not components["smtp"].started

    def test_the_check_can_be_turned_off(self, run, serve_settings, components, stale_schema):
        code, out = run("serve", "--worker-only")
        assert code == 1

        serve_settings(verify_schema_on_startup=False)
        code, out = run("serve", "--worker-only")
        assert code == 0, out
        assert components["worker"].started


class TestEncryptionGuardIsReportedTheSameWay:
    """Wired into serve before this change; pinned here so both guards keep the shape."""

    def test_worker_only_refuses_and_reports_without_a_traceback(
        self, run, serve_settings, components, monkeypatch
    ):
        async def raise_missing(engine):
            raise EncryptionKeyMissingError("headers are encrypted, no key configured")

        # Patched where ``db.startup`` bound it, not where it is defined: the
        # shared module imports the name at module load, so the definition site
        # is no longer what the call resolves.
        monkeypatch.setattr(
            "fastsmtp.db.startup.verify_encryption_key_is_configured", raise_missing
        )

        code, out = run("serve", "--worker-only")
        assert code == 1
        assert "headers are encrypted, no key configured" in out
        assert "Traceback" not in out
        assert not components["worker"].started
