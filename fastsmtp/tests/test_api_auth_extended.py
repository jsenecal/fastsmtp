"""Extended tests for auth API endpoints to improve coverage."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.auth import generate_api_key
from fastsmtp.config import Settings
from fastsmtp.db.models import APIKey, User


class TestAuthWhoami:
    """Tests for whoami endpoint."""

    @pytest.mark.asyncio
    async def test_whoami_root_user(self, auth_client: AsyncClient):
        """Test whoami for root user."""
        response = await auth_client.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["is_root"] is True
        assert data["user"]["username"] == "root"


class TestAuthKeysExtended:
    """Extended tests for API key management."""

    @pytest_asyncio.fixture
    async def regular_user_with_key(
        self, test_session: AsyncSession
    ) -> tuple[User, str]:
        """Create a regular user with an API key."""
        user = User(
            username="keyuser",
            email="keyuser@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.flush()

        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="Test Key",
            scopes=["recipients:read", "recipients:write"],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(api_key)

        return user, full_key

    @pytest.mark.asyncio
    async def test_list_keys_root_empty(self, auth_client: AsyncClient):
        """Test root user has no API keys to list."""
        response = await auth_client.get("/api/v1/auth/keys")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_create_key_as_root_fails(self, auth_client: AsyncClient):
        """Test root user cannot create API keys."""
        response = await auth_client.post(
            "/api/v1/auth/keys",
            json={"name": "Test Key"},
        )
        assert response.status_code == 400
        assert "Root user cannot create" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_delete_key_as_root_fails(self, auth_client: AsyncClient):
        """Test root user cannot delete API keys."""
        fake_id = uuid.uuid4()
        response = await auth_client.delete(f"/api/v1/auth/keys/{fake_id}")
        assert response.status_code == 400
        assert "Root user has no API keys" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_rotate_key_as_root_fails(self, auth_client: AsyncClient):
        """Test root user cannot rotate API keys."""
        fake_id = uuid.uuid4()
        response = await auth_client.post(f"/api/v1/auth/keys/{fake_id}/rotate")
        assert response.status_code == 400
        assert "Root user has no API keys" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_keys_for_user(
        self,
        app,
        regular_user_with_key: tuple[User, str],
    ):
        """Test listing keys for a regular user."""
        _, api_key = regular_user_with_key

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as user_client:
            response = await user_client.get("/api/v1/auth/keys")
            assert response.status_code == 200
            data = response.json()
            assert len(data) >= 1
            assert data[0]["name"] == "Test Key"

    @pytest.mark.asyncio
    async def test_create_key_for_user(
        self,
        app,
        regular_user_with_key: tuple[User, str],
    ):
        """Test creating an API key for a regular user."""
        _, api_key = regular_user_with_key

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as user_client:
            response = await user_client.post(
                "/api/v1/auth/keys",
                json={"name": "New Key", "scopes": ["recipients:read"]},
            )
            assert response.status_code == 201
            data = response.json()
            assert data["name"] == "New Key"
            assert "key" in data  # Full key is returned on create

    @pytest.mark.asyncio
    async def test_delete_key_not_found(
        self,
        app,
        regular_user_with_key: tuple[User, str],
    ):
        """Test deleting non-existent API key returns 404."""
        _, api_key = regular_user_with_key

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as user_client:
            fake_id = uuid.uuid4()
            response = await user_client.delete(f"/api/v1/auth/keys/{fake_id}")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_rotate_key_not_found(
        self,
        app,
        regular_user_with_key: tuple[User, str],
    ):
        """Test rotating non-existent API key returns 404."""
        _, api_key = regular_user_with_key

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as user_client:
            fake_id = uuid.uuid4()
            response = await user_client.post(f"/api/v1/auth/keys/{fake_id}/rotate")
            assert response.status_code == 404


class TestAuthDependencies:
    """Tests for auth dependencies."""

    @pytest.mark.asyncio
    async def test_invalid_api_key(
        self, app, test_settings: Settings
    ):
        """Test invalid API key returns 401."""
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": "invalid_key_12345"},
        ) as client:
            response = await client.get("/api/v1/domains")
            assert response.status_code == 401
            assert "Invalid API key" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_api_key(self, client: AsyncClient):
        """Test missing API key returns 401."""
        response = await client.get("/api/v1/domains")
        assert response.status_code == 401
        assert "API key required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_inactive_api_key(
        self, app, test_session: AsyncSession
    ):
        """Test inactive API key returns 401."""
        user = User(
            username="inactivekey",
            email="inactive@example.com",
            is_active=True,
        )
        test_session.add(user)
        await test_session.flush()

        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="Inactive Key",
            is_active=False,
        )
        test_session.add(api_key)
        await test_session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": full_key},
        ) as client:
            response = await client.get("/api/v1/domains")
            assert response.status_code == 401
            assert "inactive" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_inactive_user(
        self, app, test_session: AsyncSession
    ):
        """Test inactive user returns 401."""
        user = User(
            username="inactiveuser",
            email="inactiveuser@example.com",
            is_active=False,
        )
        test_session.add(user)
        await test_session.flush()

        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="User Key",
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": full_key},
        ) as client:
            response = await client.get("/api/v1/domains")
            assert response.status_code == 401
            assert "User account is inactive" in response.json()["detail"]
