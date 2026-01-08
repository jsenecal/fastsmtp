"""Pytest configuration and fixtures for fastsmtp tests."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator

import pytest
from testcontainers.postgres import PostgresContainer

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")
os.environ.setdefault("FASTSMTP_SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("FASTSMTP_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fastsmtp.config import Settings, clear_settings_cache, get_settings
from fastsmtp.db.models import Base
from fastsmtp.db.session import get_session
from fastsmtp.main import create_app


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
        smtp_port=12525,
        api_host="127.0.0.1",
        api_port=18000,
        secret_key="test-secret-key-for-testing",
        instance_id="test-instance",
    )


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

    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session
            await session.commit()

    application.dependency_overrides[get_session] = override_get_session
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
