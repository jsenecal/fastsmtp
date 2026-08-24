"""The Alembic migration chain, exercised against a throwaway database.

Every other test in this suite gets its schema from ``Base.metadata.create_all``
(see the ``test_engine`` fixture in conftest), so the migrations never run. A
migration can be broken, irreversible, or produce a schema the models do not
describe, and the rest of the suite still passes.

These tests close that gap: they apply the chain to an empty database, roll it
back to base and re-apply it, then diff the result against ``Base.metadata``.

Marked ``migrations`` so it can be deselected locally with ``-m "not
migrations"``. CI runs the suite unfiltered, so it always runs there.
"""

import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from anyio import to_thread
from fastsmtp.db.models import Base
from sqlalchemy import Connection, make_url, text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

pytestmark = pytest.mark.migrations

# alembic.ini lives in the package directory and its script_location is relative
# to it, so alembic has to be invoked from there rather than from the repo root.
PACKAGE_ROOT = Path(__file__).resolve().parents[1]

# The session container's default database holds the create_all schema the rest
# of the suite drops and rebuilds per test, so the chain gets its own.
MIGRATION_DATABASE = "fastsmtp_migration_test"


def _run_alembic(
    environ: dict[str, str], database_url: str, *args: str
) -> subprocess.CompletedProcess[str]:
    """Run one alembic command against ``database_url`` in a child process.

    ``alembic/env.py`` drives the migrations with ``asyncio.run``, which makes
    it hostile to in-process invocation from an async test; a child process
    also matches how migrations are applied for real.

    ``environ`` is the ``scrubbed_environ`` fixture: no ``FASTSMTP_*`` variable
    from the session leaks in, so the chain runs the way a migration Job does,
    with the database URL and nothing else.
    """
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=PACKAGE_ROOT,
        env={**environ, "FASTSMTP_DATABASE_URL": database_url},
        capture_output=True,
        text=True,
    )


async def alembic(environ: dict[str, str], database_url: str, *args: str) -> None:
    """Run an alembic command off the event loop, failing on a non-zero exit."""
    result = await to_thread.run_sync(partial(_run_alembic, environ, database_url, *args))
    if result.returncode != 0:
        pytest.fail(
            f"`alembic {' '.join(args)}` exited {result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )


@asynccontextmanager
async def connected(database_url: str, **engine_kwargs: Any) -> AsyncIterator[AsyncConnection]:
    """Yield a connection to ``database_url``, disposing the engine afterwards."""
    engine = create_async_engine(database_url, **engine_kwargs)
    try:
        async with engine.connect() as connection:
            yield connection
    finally:
        await engine.dispose()


async def run_autocommit(database_url: str, *statements: str) -> None:
    """Run statements that cannot sit in a transaction, such as CREATE DATABASE."""
    async with connected(database_url, isolation_level="AUTOCOMMIT") as connection:
        for statement in statements:
            await connection.execute(text(statement))


async def public_tables(database_url: str) -> set[str]:
    """Return the table names in the public schema."""
    async with connected(database_url) as connection:
        result = await connection.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        return {row[0] for row in result}


def _diff_against_models(sync_connection: Connection) -> list[Any]:
    """Diff the connected database against the models. Runs on a sync connection.

    Server defaults are deliberately left out of the comparison (alembic's
    default): the models set most defaults Python-side while the migrations set
    them in DDL, and that difference is by design rather than drift.
    """
    return compare_metadata(MigrationContext.configure(sync_connection), Base.metadata)


@pytest_asyncio.fixture
async def migration_database_url(postgres_url: str) -> AsyncIterator[str]:
    """Create an empty database for a migration run and drop it afterwards."""
    drop = f'DROP DATABASE IF EXISTS "{MIGRATION_DATABASE}" WITH (FORCE)'
    await run_autocommit(postgres_url, drop, f'CREATE DATABASE "{MIGRATION_DATABASE}"')
    try:
        yield (
            make_url(postgres_url)
            .set(database=MIGRATION_DATABASE)
            .render_as_string(hide_password=False)
        )
    finally:
        await run_autocommit(postgres_url, drop)


async def test_migration_chain_is_reversible(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    """upgrade head -> downgrade base -> upgrade head, with nothing left behind.

    A downgrade that leaves a table standing makes the next upgrade fail on an
    already-existing object, which only shows up on a rollback in production.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")
    await alembic(scrubbed_environ, migration_database_url, "downgrade", "base")

    left_behind = await public_tables(migration_database_url) - {"alembic_version"}
    assert not left_behind, f"downgrade base left tables behind: {sorted(left_behind)}"

    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")


async def test_migrated_schema_matches_models(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    """`alembic upgrade head` must produce exactly the schema the models declare.

    This is the check that turns "the migration ran" into "the migration built
    what the code expects" - a model change merged without its migration fails
    here instead of on deploy.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")

    async with connected(migration_database_url) as connection:
        differences = await connection.run_sync(_diff_against_models)

    assert not differences, "migrated schema differs from Base.metadata:\n" + "\n".join(
        f"  {difference!r}" for difference in differences
    )
