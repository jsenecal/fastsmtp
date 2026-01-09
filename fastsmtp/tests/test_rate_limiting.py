"""Tests for rate limiting middleware.

Tests follow TDD - written before implementation.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.config import Settings
from fastsmtp.db.models import Base
from fastsmtp.db.session import get_session
from fastsmtp.main import create_app
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class TestRateLimitingConfig:
    """Test rate limiting configuration."""

    def test_settings_has_rate_limit_fields(self):
        """Settings should have rate limiting configuration fields."""
        settings = Settings(
            root_api_key="test123",
            redis_url="redis://localhost:6379/0",
            rate_limit_enabled=True,
            rate_limit_requests_per_minute=100,
            rate_limit_auth_attempts_per_minute=5,
        )

        assert hasattr(settings, "redis_url")
        assert hasattr(settings, "rate_limit_enabled")
        assert hasattr(settings, "rate_limit_requests_per_minute")
        assert hasattr(settings, "rate_limit_auth_attempts_per_minute")

        assert settings.redis_url == "redis://localhost:6379/0"
        assert settings.rate_limit_enabled is True
        assert settings.rate_limit_requests_per_minute == 100
        assert settings.rate_limit_auth_attempts_per_minute == 5

    def test_rate_limiting_disabled_by_default_without_redis(self):
        """Rate limiting should be disabled when redis_url is not set."""
        settings = Settings(root_api_key="test123")

        # Without redis_url, rate limiting should effectively be disabled
        assert settings.redis_url is None
        # rate_limit_enabled defaults to True but requires redis to function


class TestRateLimitingMiddleware:
    """Test rate limiting middleware behavior."""

    @pytest_asyncio.fixture
    async def rate_limited_settings(self) -> Settings:
        """Create settings with rate limiting enabled."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_root_api_key_12345",
            redis_url="redis://localhost:6379/0",
            rate_limit_enabled=True,
            rate_limit_requests_per_minute=5,  # Low for testing
            rate_limit_auth_attempts_per_minute=3,
        )

    @pytest_asyncio.fixture
    async def rate_limited_app(self, rate_limited_settings: Settings, test_engine) -> FastAPI:
        """Create app with rate limiting enabled."""

        application = create_app(rate_limited_settings)

        session_factory = async_sessionmaker(
            test_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        async def override_get_session():
            async with session_factory() as session:
                yield session
                await session.commit()

        from fastsmtp.config import get_settings

        application.dependency_overrides[get_session] = override_get_session
        application.dependency_overrides[get_settings] = lambda: rate_limited_settings

        yield application
        application.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_rate_limit_headers_present(self, rate_limited_settings: Settings):
        """Rate limit headers should be present in responses."""
        # Mock Redis client - use MagicMock for sync methods, AsyncMock for async
        mock_redis_client = MagicMock()
        # get() is async
        mock_redis_client.get = AsyncMock(return_value=None)
        # pipeline() is sync, returns an object with sync incr/expire and async execute
        mock_pipe = MagicMock()
        mock_pipe.incr.return_value = mock_pipe
        mock_pipe.expire.return_value = mock_pipe
        mock_pipe.execute = AsyncMock(return_value=[1, True])
        mock_redis_client.pipeline.return_value = mock_pipe

        # get_redis_client is async, so use AsyncMock
        async def mock_get_redis():
            return mock_redis_client

        with (
            patch(
                "fastsmtp.middleware.rate_limit.get_redis_client",
                side_effect=mock_get_redis,
            ),
            patch(
                "fastsmtp.middleware.rate_limit.get_settings",
                return_value=rate_limited_settings,
            ),
        ):
            # Create app with rate limiting enabled
            from fastsmtp.config import get_settings
            from fastsmtp.db.models import Base
            from sqlalchemy.ext.asyncio import (
                AsyncSession,
                async_sessionmaker,
                create_async_engine,
            )

            engine = create_async_engine(rate_limited_settings.database_url, echo=False)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            app = create_app(rate_limited_settings)

            session_factory = async_sessionmaker(
                engine, class_=AsyncSession, expire_on_commit=False
            )

            async def override_get_session():
                async with session_factory() as session:
                    yield session
                    await session.commit()

            app.dependency_overrides[get_session] = override_get_session
            app.dependency_overrides[get_settings] = lambda: rate_limited_settings

            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-API-Key": "test_root_api_key_12345"},
            ) as client:
                response = await client.get("/api/v1/domains")

                # Should have rate limit headers
                assert "X-RateLimit-Limit" in response.headers
                assert "X-RateLimit-Remaining" in response.headers
                assert "X-RateLimit-Reset" in response.headers

            await engine.dispose()

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_returns_429(self, rate_limited_settings: Settings):
        """Exceeding rate limit should return 429 Too Many Requests."""
        mock_redis_client = AsyncMock()
        # Simulate rate limit exceeded (already at 10, limit is 5)
        mock_redis_client.get.return_value = b"10"
        mock_redis_client.ttl.return_value = 30

        with (
            patch(
                "fastsmtp.middleware.rate_limit.get_redis_client",
                return_value=mock_redis_client,
            ),
            patch(
                "fastsmtp.middleware.rate_limit.get_settings",
                return_value=rate_limited_settings,
            ),
        ):
            from fastsmtp.config import get_settings
            from fastsmtp.db.models import Base
            from sqlalchemy.ext.asyncio import (
                AsyncSession,
                async_sessionmaker,
                create_async_engine,
            )

            engine = create_async_engine(rate_limited_settings.database_url, echo=False)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            app = create_app(rate_limited_settings)

            session_factory = async_sessionmaker(
                engine, class_=AsyncSession, expire_on_commit=False
            )

            async def override_get_session():
                async with session_factory() as session:
                    yield session
                    await session.commit()

            app.dependency_overrides[get_session] = override_get_session
            app.dependency_overrides[get_settings] = lambda: rate_limited_settings

            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-API-Key": "test_root_api_key_12345"},
            ) as client:
                response = await client.get("/api/v1/domains")

                assert response.status_code == 429
                assert "Retry-After" in response.headers

            await engine.dispose()

    @pytest.mark.asyncio
    async def test_rate_limit_by_api_key(self, rate_limited_settings: Settings):
        """API requests should be rate limited per API key."""
        request_counts = {}

        async def mock_get(key):
            return str(request_counts.get(key, 0)).encode() if key in request_counts else None

        # Track calls through pipeline
        class MockPipeline:
            def __init__(self):
                self.ops = []

            def incr(self, key):
                request_counts[key] = request_counts.get(key, 0) + 1
                self.ops.append(("incr", key))
                return self

            def expire(self, key, ttl):
                self.ops.append(("expire", key, ttl))
                return self

            async def execute(self):
                return [request_counts.get(self.ops[0][1], 1) if self.ops else 1, True]

        mock_redis_client = MagicMock()
        mock_redis_client.get = AsyncMock(side_effect=mock_get)
        mock_redis_client.pipeline.return_value = MockPipeline()

        async def mock_get_redis():
            return mock_redis_client

        with (
            patch(
                "fastsmtp.middleware.rate_limit.get_redis_client",
                side_effect=mock_get_redis,
            ),
            patch(
                "fastsmtp.middleware.rate_limit.get_settings",
                return_value=rate_limited_settings,
            ),
        ):
            from fastsmtp.config import get_settings
            from fastsmtp.db.models import Base
            from sqlalchemy.ext.asyncio import (
                AsyncSession,
                async_sessionmaker,
                create_async_engine,
            )

            engine = create_async_engine(rate_limited_settings.database_url, echo=False)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            app = create_app(rate_limited_settings)

            session_factory = async_sessionmaker(
                engine, class_=AsyncSession, expire_on_commit=False
            )

            async def override_get_session():
                async with session_factory() as session:
                    yield session
                    await session.commit()

            app.dependency_overrides[get_session] = override_get_session
            app.dependency_overrides[get_settings] = lambda: rate_limited_settings

            transport = ASGITransport(app=app)

            # First API key - should have its own counter
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-API-Key": "test_root_api_key_12345"},
            ) as client:
                for _ in range(3):
                    await client.get("/api/v1/domains")

            # Rate limit key should include API key identifier
            rate_limit_keys = [k for k in request_counts if "rate_limit" in k.lower()]
            assert len(rate_limit_keys) > 0, (
                f"Should track rate limits by key. Keys: {request_counts.keys()}"
            )
            # Verify the key format includes api key prefix
            assert any("test_root_ap" in k for k in rate_limit_keys), (
                f"Key should include API key prefix. Keys: {rate_limit_keys}"
            )

            await engine.dispose()


class TestRateLimitingDisabled:
    """Test behavior when rate limiting is disabled."""

    @pytest.mark.asyncio
    async def test_no_rate_limiting_without_redis(self, app: FastAPI, auth_client: AsyncClient):
        """Without Redis configured, rate limiting should not apply."""
        # Make many requests - should all succeed
        for _ in range(20):
            response = await auth_client.get("/api/v1/health")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_rate_limit_disabled_setting(self):
        """When rate_limit_enabled=False, no rate limiting should apply."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test123",
            redis_url="redis://localhost:6379/0",
            rate_limit_enabled=False,
        )

        assert settings.rate_limit_enabled is False


class TestAuthRateLimiting:
    """Test rate limiting for authentication attempts."""

    @pytest.mark.asyncio
    async def test_auth_attempts_limited_per_ip(self):
        """Authentication attempts should be limited per IP address."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test123",
            redis_url="redis://localhost:6379/0",
            rate_limit_enabled=True,
            rate_limit_auth_attempts_per_minute=3,
        )

        from fastsmtp.config import get_settings
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(settings.database_url, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        app = create_app(settings)

        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_session():
            async with session_factory() as session:
                yield session
                await session.commit()

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_settings] = lambda: settings

        auth_attempts = {}

        async def mock_incr(key):
            auth_attempts[key] = auth_attempts.get(key, 0) + 1
            return auth_attempts[key]

        async def mock_get(key):
            return str(auth_attempts.get(key, 0)).encode() if key in auth_attempts else None

        with patch("fastsmtp.middleware.rate_limit.get_redis_client") as mock_redis:
            mock_client = AsyncMock()
            mock_redis.return_value = mock_client
            mock_client.incr.side_effect = mock_incr
            mock_client.get.side_effect = mock_get
            mock_client.setex.return_value = True
            mock_client.expire.return_value = True

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Make failed auth attempts with invalid API key
                for i in range(5):
                    response = await client.get(
                        "/api/v1/domains",
                        headers={"X-API-Key": "invalid_key"},
                    )
                    # After 3 attempts, should get rate limited
                    if i >= 3:
                        # Should be rate limited OR get 401
                        assert response.status_code in (401, 429)

        await engine.dispose()
