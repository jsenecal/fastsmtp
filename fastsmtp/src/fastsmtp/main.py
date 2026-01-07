"""FastSMTP main application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from fastsmtp import __version__
from fastsmtp.api.router import api_router
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.session import close_engine
from fastsmtp.metrics import MetricsMiddleware
from fastsmtp.middleware import RateLimitMiddleware, RequestLoggingMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
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
    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Expose Prometheus metrics."""
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    return app


app = create_app()
