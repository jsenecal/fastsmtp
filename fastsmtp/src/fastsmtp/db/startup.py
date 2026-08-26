"""The checks a process makes against its database before it serves anything.

Two guards, one engine: the schema must not be behind the migrations this
build ships (issue #83), and any encrypted column must be readable by the key
this process holds (issue #135). Both belong to every entry point that is
about to touch the database, and there are two of those - ``fastsmtp serve``,
which starts whichever components it was asked for, and the API lifespan,
because ``uvicorn fastsmtp.main:app`` is documented and never goes through
``serve``. A full ``serve`` therefore asks twice, which is one extra query at
startup; the alternative was a ``--worker-only`` process that asked nothing at
all (issue #138).

Only the reporting differs between the callers, so that is all they keep: the
CLI turns a failure into a console message and exit 1, the app lets it stop
startup. The engine is built here and disposed here, from the settings the
caller passes rather than the process-wide one - ``create_app`` accepts a
settings override and the test suite uses it, so checking "the" database could
mean checking a different one.
"""

from sqlalchemy.ext.asyncio import create_async_engine

from fastsmtp.config import Settings
from fastsmtp.db.encryption_guard import verify_encryption_key_is_configured
from fastsmtp.db.migrations import verify_schema_is_current


async def verify_database_is_serviceable(settings: Settings) -> None:
    """Run the enabled startup guards against ``settings``' database.

    Raises:
        SchemaRevisionError: the database is behind this build's migrations
        EncryptionKeyMissingError: it holds encrypted rows this process cannot read
    """
    if not settings.verify_schema_on_startup and not settings.verify_encryption_on_startup:
        return

    engine = create_async_engine(settings.database_dsn)
    try:
        if settings.verify_schema_on_startup:
            await verify_schema_is_current(engine)
        if settings.verify_encryption_on_startup:
            await verify_encryption_key_is_configured(engine)
    finally:
        await engine.dispose()
