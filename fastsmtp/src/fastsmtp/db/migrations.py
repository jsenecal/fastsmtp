"""Locating the migrations, and checking the database against the code that connects.

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


def alembic_script_location() -> Path:
    """Absolute path to the migration scripts, which ship inside the package::

        fastsmtp/alembic/versions/
        fastsmtp/db/migrations.py   <- this file

    Being inside the package is what makes them survive a wheel build, and it
    is what lets this path be derived from ``__file__`` alone. The scripts used
    to sit beside the src tree and be found by walking three directories up,
    which held only in a source checkout and in an image that reproduced that
    layout; from site-packages it resolved to nowhere.
    """
    return Path(__file__).resolve().parent.parent / "alembic"


def alembic_config() -> Config:
    """An Alembic config built in code, with no ini file to locate.

    ``script_location`` is absolute, so nothing depends on the caller's
    directory. Everything else alembic.ini used to carry is either irrelevant
    here (``prepend_sys_path``, needed only to import an uninstalled package)
    or set by the caller: the URL comes from ``env.py``, and logging from
    whoever is running the command.
    """
    config = Config()
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
