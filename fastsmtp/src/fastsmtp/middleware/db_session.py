"""Per-request database session middleware."""

import logging
from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from fastsmtp.db.session import REQUEST_SESSION_ATTR, get_async_session_factory

logger = logging.getLogger(__name__)


class DBSessionMiddleware(BaseHTTPMiddleware):
    """Own the request's database session, committing before the response is sent.

    The commit must happen here rather than in a ``yield`` dependency's teardown.
    Teardown starts before the response is sent, so as soon as it awaits the
    commit the event loop flushes the response; a client reading back what it
    just wrote can then reach a fresh session before the commit lands and get a
    404. Committing inside the middleware keeps the write inside the request, so
    the response cannot overtake it.

    The session is published on ``request.state`` for ``get_session`` to yield,
    which also means every dependency and route in one request shares a session
    rather than opening several.

    The session closes when this middleware returns, which is before the response
    body is streamed and before any FastAPI ``BackgroundTasks`` run. Nothing in
    the app uses either today; a future StreamingResponse whose generator touches
    the session would need its own, and would fail only over real TCP.
    """

    @staticmethod
    def _factory(request: Request) -> async_sessionmaker[AsyncSession]:
        """Resolve the session factory, letting tests swap it per application."""
        override = getattr(request.app.state, "session_factory", None)
        return override or get_async_session_factory()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Run the request with a session, committing it before returning."""
        async with self._factory(request)() as session:
            setattr(request.state, REQUEST_SESSION_ATTR, session)

            # An exception propagating out of this block leaves the session
            # uncommitted, and closing it rolls the transaction back - so no
            # explicit rollback is needed on that path.
            response = await call_next(request)

            # FastAPI turns HTTPException into a response before it reaches this
            # middleware, so a failed request arrives as a status code rather
            # than an exception. Its partial writes must still be discarded.
            if response.status_code >= 400:
                # A rollback failure must not replace an already-formed response:
                # /ready answers 503 when the database is unreachable, and letting
                # a driver error escape here would turn that into an opaque 500.
                try:
                    await session.rollback()
                except Exception:
                    logger.exception("Rollback failed for %s %s", request.method, request.url.path)
                return response

            await session.commit()
            return response
