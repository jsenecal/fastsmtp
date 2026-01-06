"""Pytest configuration and fixtures for fastsmtp tests."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator

import pytest

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")
os.environ.setdefault("FASTSMTP_SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("FASTSMTP_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.config import Settings
from fastsmtp.db.models import Base
from fastsmtp.db.session import get_session
from fastsmtp.main import create_app
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings() -> Settings:
    """Create test settings."""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
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
    """Create test database engine."""
    engine = create_async_engine(
        test_settings.database_url,
        echo=False,
    )

    async with engine.begin() as conn:
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

    application.dependency_overrides[get_session] = override_get_session

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
        headers={"Authorization": f"Bearer {test_settings.root_api_key}"},
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
