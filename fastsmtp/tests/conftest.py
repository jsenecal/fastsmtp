"""Pytest configuration and fixtures for fastsmtp tests."""

import asyncio
import os
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Generator
from contextlib import asynccontextmanager

import pytest
from testcontainers.community.postgres import PostgresContainer

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")
os.environ.setdefault("FASTSMTP_SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("FASTSMTP_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")

import anyio
import pytest_asyncio
import uvicorn
from fastapi import FastAPI
from fastsmtp.config import Settings, clear_settings_cache, get_settings
from fastsmtp.db.models import Base
from fastsmtp.main import create_app
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def postgres_container() -> Generator[PostgresContainer, None, None]:
    """Create PostgreSQL container for test session."""
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres


@pytest.fixture(scope="session")
def postgres_url(postgres_container: PostgresContainer) -> str:
    """Get async PostgreSQL connection URL from container."""
    # testcontainers returns psycopg2 URL, convert to asyncpg
    url = postgres_container.get_connection_url()
    return url.replace("psycopg2", "asyncpg")


@pytest.fixture
def test_settings(postgres_url: str) -> Settings:
    """Create test settings with PostgreSQL database."""
    # Clear settings cache to ensure fresh settings
    clear_settings_cache()
    return Settings(
        database_url=postgres_url,
        root_api_key="test_root_api_key_12345",
        smtp_host="127.0.0.1",
        # INVARIANT: nothing may ever bind these ports. API tests run through
        # ASGITransport and the live-server fixture passes port=0 to uvicorn.
        # A test that actually listens must bind port 0 and read the OS-assigned
        # port back after start (SMTPServer.bound_smtp_port; see
        # make_smtp_settings below) -- fixed ports collide across concurrent
        # runs (issue #87), and ports probed for freeness ahead of time are
        # stealable before the server binds them (issue #98).
        # test_no_hardcoded_ports.py enforces this outside this file.
        smtp_port=12525,
        api_host="127.0.0.1",
        api_port=18000,
        secret_key="test-secret-key-for-testing",
        instance_id="test-instance",
    )


@pytest.fixture
def make_smtp_settings() -> Callable[..., Settings]:
    """Build the Settings the SMTP server tests need, with overrides.

    The base binds smtp_port/smtp_tls_port to 0 so the OS assigns free ports
    at bind time -- read the real ports back through
    ``SMTPServer.bound_smtp_port`` / ``bound_smtp_tls_port`` after ``start()``.
    Pre-probing for a free port (unused_tcp_port_factory) leaves a window in
    which another process can steal it before the server binds (issue #98).

    Exposed as a fixture rather than a module-level function because the tests
    directory is not an importable package.
    """

    def make(**overrides: object) -> Settings:
        base: dict[str, object] = {
            "database_url": "sqlite+aiosqlite:///:memory:",
            "root_api_key": "test_key_12345",
            "secret_key": "test-secret-key",
            "smtp_host": "127.0.0.1",
            "smtp_port": 0,
            "smtp_tls_port": 0,
            "smtp_verify_dkim": False,
            "smtp_verify_spf": False,
        }
        base.update(overrides)
        return Settings(**base)

    return make


@pytest.fixture
def scrubbed_environ() -> dict[str, str]:
    """``os.environ`` with every ``FASTSMTP_*`` variable removed.

    This module exports a root API key (and more) for the whole session, so a
    child process that has to prove it needs *less* than the server -- the
    migration chain, ``fastsmtp db`` -- must start from an environment with
    that namespace cleared and add back only what it is entitled to.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith("FASTSMTP_")}


@pytest_asyncio.fixture
async def test_engine(test_settings: Settings):
    """Create test database engine with fresh tables."""
    engine = create_async_engine(
        test_settings.database_url,
        echo=False,
    )

    # Create all tables fresh for each test
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def app(test_settings: Settings, test_engine) -> AsyncGenerator[FastAPI, None]:
    """Create test FastAPI application."""
    application = create_app(test_settings)

    # Override the database session dependency
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # DBSessionMiddleware creates and commits the request's session, so tests
    # swap the factory rather than overriding the dependency. Overriding
    # get_session would reintroduce a teardown commit and with it the
    # read-your-own-write race - see test_api_read_after_write.py.
    application.state.session_factory = session_factory
    application.dependency_overrides[get_settings] = lambda: test_settings

    yield application

    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create test HTTP client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_client(
    app: FastAPI,
    test_settings: Settings,
) -> AsyncGenerator[AsyncClient, None]:
    """Create authenticated test HTTP client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-API-Key": test_settings.root_api_key.get_secret_value()},
    ) as ac:
        yield ac


SERVER_START_TIMEOUT = 10.0


@asynccontextmanager
async def serving(app, **uvicorn_kwargs) -> AsyncIterator[str]:
    """Serve an ASGI app over real TCP and yield its base URL.

    Most API tests drive the app in-process through httpx's ASGITransport, which
    awaits the entire app call before returning. Anything that depends on when
    bytes actually reach the client - response/commit ordering, connection reuse -
    or on layers ASGITransport does not have, such as uvicorn's proxy-header
    rewriting, is invisible under that transport and needs a real socket.

    The server runs inside the test's own event loop, so handlers share the loop
    the test-database engine was created on. Blocking clients must therefore run
    on a worker thread; see :func:`run_blocking`.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", **uvicorn_kwargs)
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    serving_task = asyncio.create_task(server.serve())

    deadline = asyncio.get_running_loop().time() + SERVER_START_TIMEOUT
    while not server.started:
        if serving_task.done():  # pragma: no cover - startup failure
            serving_task.result()
            raise RuntimeError("uvicorn server exited before starting")
        if asyncio.get_running_loop().time() > deadline:  # pragma: no cover - hung bind
            serving_task.cancel()
            raise TimeoutError(f"uvicorn did not start within {SERVER_START_TIMEOUT}s")
        await anyio.sleep(0.02)

    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving_task, timeout=SERVER_START_TIMEOUT)


@pytest_asyncio.fixture
async def server_url(app: FastAPI) -> AsyncGenerator[str, None]:
    """Serve the standard test app over real TCP and yield its base URL."""
    async with serving(app) as url:
        yield url


@pytest.fixture
def serve_app():
    """Expose :func:`serving` to tests needing their own app or uvicorn options."""
    return serving


@pytest.fixture
def run_blocking():
    """Return a helper running a blocking client body off the serving loop.

    The app is served in the test's own event loop, so a synchronous HTTP client
    would deadlock it. Exposed as a fixture rather than a module-level function
    because the tests directory is not an importable package.
    """

    async def run(body):
        return await anyio.to_thread.run_sync(body)

    return run


@pytest.fixture
def sample_email_content() -> bytes:
    """Sample email content for testing."""
    return b"""From: sender@example.com
To: recipient@test.com
Subject: Test Email
Message-ID: <test123@example.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This is a test email body.
"""


@pytest.fixture
def sample_multipart_email() -> bytes:
    """Sample multipart email for testing."""
    return b"""From: sender@example.com
To: recipient@test.com
Subject: Test Multipart Email
Message-ID: <test456@example.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

This is the plain text version.

--boundary123
Content-Type: text/html; charset="utf-8"

<html><body><p>This is the HTML version.</p></body></html>

--boundary123--
"""
