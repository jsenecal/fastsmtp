"""FastSMTP main application entry point."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy.ext.asyncio import create_async_engine

from fastsmtp import __version__
from fastsmtp.api.router import api_router
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.encryption_guard import verify_encryption_key_is_configured
from fastsmtp.db.migrations import verify_schema_is_current
from fastsmtp.db.session import close_engine
from fastsmtp.metrics import MetricsMiddleware
from fastsmtp.metrics.access import require_metrics_access
from fastsmtp.middleware import (
    DBSessionMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup. Refuse a database older than this build rather than discovering
    # it on the first query that touches a column the migration would add.
    #
    # The engine is built from the app's own settings, not the process-wide
    # get_engine(): create_app() accepts a settings override and the test suite
    # uses it, so the shared engine can point somewhere else entirely. Checking
    # the wrong database would be worse than not checking.
    settings = getattr(app.state, "settings", None) or get_settings()
    if settings.verify_schema_on_startup or settings.verify_encryption_on_startup:
        engine = create_async_engine(settings.database_url)
        try:
            if settings.verify_schema_on_startup:
                await verify_schema_is_current(engine)
            # Refuse a database holding encrypted columns this process has no key
            # for. Without this the failure lands later and far worse: every read
            # of the column raises inside a SELECT, so the delivery worker cannot
            # reach the webhook auth headers it is supposed to send.
            if settings.verify_encryption_on_startup:
                await verify_encryption_key_is_configured(engine)
        finally:
            await engine.dispose()
    yield
    # Shutdown
    await close_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional settings override for testing. If not provided,
                  default settings will be loaded from environment.
    """
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="FastSMTP",
        description="SMTP-to-Webhook Relay Server",
        version=__version__,
        lifespan=lifespan,
    )

    # Store settings on app state for access in routes
    app.state.settings = settings

    # Database session middleware. Added first so it is the innermost layer:
    # it must wrap the routes, and its commit must land before the response is
    # handed back up the stack.
    app.add_middleware(DBSessionMiddleware)

    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)

    # Add Prometheus metrics middleware
    app.add_middleware(MetricsMiddleware)

    # Add rate limiting middleware (requires Redis)
    if settings.redis_url and settings.rate_limit_enabled:
        app.add_middleware(RateLimitMiddleware)

    # Add CORS middleware only if origins are configured
    if settings.cors_origins:
        # Don't allow credentials with wildcard origins (security risk)
        allow_credentials = "*" not in settings.cors_origins
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Include API router
    app.include_router(api_router)

    # Add Prometheus metrics endpoint at root level
    @app.get(
        "/metrics",
        include_in_schema=False,
        dependencies=[Depends(require_metrics_access)],
    )
    async def metrics() -> Response:
        """Expose Prometheus metrics."""
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    return app


app = create_app()
