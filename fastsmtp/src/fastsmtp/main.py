"""FastSMTP main application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from fastsmtp import __version__
from fastsmtp.api.router import api_router
from fastsmtp.config import Settings
from fastsmtp.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    yield
    # Shutdown
    await engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional settings override for testing. If not provided,
                  default settings will be loaded from environment.
    """
    app = FastAPI(
        title="FastSMTP",
        description="SMTP-to-Webhook Relay Server",
        version=__version__,
        lifespan=lifespan,
    )

    # Store settings on app state for access in routes if provided
    if settings is not None:
        app.state.settings = settings

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API router
    app.include_router(api_router)

    return app


app = create_app()
