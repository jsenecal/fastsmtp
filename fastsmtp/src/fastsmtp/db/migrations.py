"""Locating Alembic, and checking the database against the code that connects.

The schema only ever advances when someone runs it, so the two things that keep
a deployment honest are that the migration command works and that a stale
database is refused loudly rather than discovered on the first query.
"""

import logging
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


class SchemaRevisionError(RuntimeError):
    """Raised when the database is older than the code connecting to it."""


def alembic_ini_path() -> Path:
    """Absolute path to alembic.ini, which ships beside the package's src tree.

    Layout, in the repo and in the image alike::

        <root>/alembic.ini
        <root>/alembic/versions/
        <root>/src/fastsmtp/db/migrations.py   <- this file

    so the root is three levels up from this module's directory.
    """
    return Path(__file__).resolve().parents[3] / "alembic.ini"


def alembic_script_location() -> Path:
    """Absolute path to the migration scripts.

    alembic.ini says ``script_location = alembic``, and Alembic resolves that
    against the current working directory rather than against the ini file. Any
    caller that is not sitting in the package root therefore has to override it
    with an absolute path.
    """
    return alembic_ini_path().parent / "alembic"


def alembic_config() -> Config:
    """An Alembic config that works regardless of the caller's directory."""
    config = Config(str(alembic_ini_path()))
    config.set_main_option("script_location", str(alembic_script_location()))
    return config


def expected_head_revision() -> str:
    """The head revision of the migrations shipped with this code."""
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:  # pragma: no cover - only reachable with no migrations at all
        raise SchemaRevisionError("No Alembic migrations found")
    return head


async def current_db_revision(engine: AsyncEngine) -> str | None:
    """The revision the database reports, or None if it is not Alembic-managed.

    None is not an error: the test suite builds its schema with
    ``Base.metadata.create_all``, which never creates ``alembic_version``.
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version_num FROM alembic_version"))
            row = result.first()
    except DatabaseError:
        return None
    return row[0] if row else None


async def verify_schema_is_current(engine: AsyncEngine) -> None:
    """Refuse to start against a database older than this code.

    Only a *stale* database raises. A newer one is normal during a rolling
    deploy -- migrations run before the old pods are gone -- and taking those
    pods down would turn a routine upgrade into an outage. An unmanaged
    database cannot be compared at all, so it is reported and allowed.
    """
    expected = expected_head_revision()
    current = await current_db_revision(engine)

    if current is None:
        logger.warning(
            "Database has no alembic_version table; schema is unmanaged and was "
            "not checked against migration head %s",
            expected,
        )
        return

    if current == expected:
        logger.info("Database schema is at migration head %s", expected)
        return

    script = ScriptDirectory.from_config(alembic_config())
    try:
        pending = [rev.revision for rev in script.iterate_revisions(expected, current)]
    except RevisionError:
        # The database names a revision this build has never heard of, so it
        # cannot be behind us. Either a rolling deploy migrated first, or the
        # database belongs to a different lineage; neither is ours to refuse.
        pending = []

    if not pending:
        logger.warning(
            "Database is at revision %s, which is not behind this build's head "
            "%s; assuming a rolling deploy",
            current,
            expected,
        )
        return

    raise SchemaRevisionError(
        f"Database schema is at revision {current} but this build expects "
        f"{expected}. {len(pending)} migration(s) have not been applied: "
        f"{', '.join(reversed(pending))}. Run 'fastsmtp db upgrade head' before "
        f"starting this version -- queries would otherwise fail on columns that "
        f"do not exist yet."
    )
