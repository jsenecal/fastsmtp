"""Async database session factory."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.requests import Request

from fastsmtp.config import get_settings

#: Attribute the request-scoped session is published under on ``request.state``.
#: DBSessionMiddleware writes it; get_session reads it. Keep them in step.
REQUEST_SESSION_ATTR = "db"

# Module-level singletons (lazily initialized)
_engine: AsyncEngine | None = None
_async_session: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get or create the database engine (lazy initialization)."""
    global _engine
    if _engine is None:
        settings = get_settings()

        # SQLite doesn't support connection pooling parameters
        engine_kwargs: dict = {
            "echo": settings.database_echo,
        }

        # Only add pool parameters for non-SQLite databases
        if not settings.database_dsn.startswith("sqlite"):
            engine_kwargs["pool_size"] = settings.database_pool_size
            engine_kwargs["max_overflow"] = settings.database_pool_max_overflow
            engine_kwargs["pool_pre_ping"] = True

        _engine = create_async_engine(settings.database_dsn, **engine_kwargs)

    return _engine


def get_async_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the async session factory (lazy initialization)."""
    global _async_session
    if _async_session is None:
        _async_session = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _async_session


# Convenience function that returns a session factory for use in with statements
def async_session() -> AsyncSession:
    """Get a new async session from the factory.

    Usage:
        async with async_session() as session:
            ...
    """
    return get_async_session_factory()()


async def get_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Dependency yielding the request-scoped database session.

    The session is created and committed by DBSessionMiddleware. Committing here
    instead would happen in this dependency's teardown, which runs after the
    response has been flushed to the client - losing read-your-own-write for any
    caller that reads back what it just wrote.
    """
    session = getattr(request.state, REQUEST_SESSION_ATTR, None)
    if session is None:  # pragma: no cover - defensive
        raise RuntimeError(
            "No request-scoped database session. DBSessionMiddleware must be "
            "installed on the application."
        )
    yield session


async def close_engine() -> None:
    """Close the database engine and dispose of connection pool."""
    global _engine, _async_session
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session = None


# Backwards compatibility: expose engine property for code that directly imports it
# This will trigger lazy initialization on first access
def __getattr__(name: str):
    if name == "engine":
        return get_engine()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
