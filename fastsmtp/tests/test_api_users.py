"""Tests for user and API key endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.models import APIKey, User


class TestUsersCRUD:
    """Tests for user CRUD operations."""

    @pytest.mark.asyncio
    async def test_list_users_empty(self, auth_client: AsyncClient):
        """Test listing users when none exist (besides root)."""
        response = await auth_client.get("/api/v1/users")
        assert response.status_code == 200
        # May be empty or have some users depending on setup
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_create_user(self, auth_client: AsyncClient):
        """Test creating a user."""
        response = await auth_client.post(
            "/api/v1/users",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["is_active"] is True
        assert data["is_superuser"] is False

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test creating user with duplicate username fails."""
        user = User(username="existinguser", email="existing@test.com", is_active=True)
        test_session.add(user)
        await test_session.commit()

        response = await auth_client.post(
            "/api/v1/users",
            json={
                "username": "existinguser",
                "email": "another@example.com",
            },
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_get_user(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test getting a user by ID."""
        user = User(username="getuser", email="get@test.com", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        response = await auth_client.get(f"/api/v1/users/{user.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "getuser"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, auth_client: AsyncClient):
        """Test getting non-existent user returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.get(f"/api/v1/users/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_user(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test updating a user."""
        user = User(username="updateuser", email="update@test.com", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        response = await auth_client.put(
            f"/api/v1/users/{user.id}",
            json={"email": "newemail@test.com", "is_active": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "newemail@test.com"
        assert data["is_active"] is False

    @pytest.mark.asyncio
    async def test_delete_user(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test deleting a user."""
        user = User(username="deleteuser", email="delete@test.com", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        response = await auth_client.delete(f"/api/v1/users/{user.id}")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]


class TestUsersAuth:
    """Tests for user authentication/authorization."""

    @pytest.mark.asyncio
    async def test_list_users_unauthenticated(self, client: AsyncClient):
        """Test listing users requires authentication."""
        response = await client.get("/api/v1/users")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_user_unauthenticated(self, client: AsyncClient):
        """Test creating user requires authentication."""
        response = await client.post(
            "/api/v1/users",
            json={"username": "unauth", "email": "unauth@test.com"},
        )
        assert response.status_code == 401


class TestAuthEndpoints:
    """Tests for auth-specific endpoints."""

    @pytest.mark.asyncio
    async def test_get_current_user_root(self, auth_client: AsyncClient):
        """Test getting current authenticated user info (root user)."""
        response = await auth_client.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        # Response is WhoamiResponse with nested user
        assert "user" in data
        assert data["user"]["username"] == "root"
        assert data["user"]["is_superuser"] is True
        assert data["is_root"] is True

    @pytest.mark.asyncio
    async def test_get_current_user_unauthenticated(self, client: AsyncClient):
        """Test getting current user requires authentication."""
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_list_api_keys_root_returns_empty(self, auth_client: AsyncClient):
        """Test listing API keys for root user returns empty list."""
        response = await auth_client.get("/api/v1/auth/keys")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_create_api_key_root_fails(self, auth_client: AsyncClient):
        """Test root user cannot create API keys."""
        response = await auth_client.post(
            "/api/v1/auth/keys",
            json={
                "name": "Test Key",
                "scopes": ["domains:read"],
            },
        )
        assert response.status_code == 400
        assert "Root user cannot create API keys" in response.json()["detail"]


class TestAPIKeysWithRegularUser:
    """Tests for API key operations with regular user."""

    @pytest_asyncio.fixture
    async def regular_user_client(
        self, app, test_session: AsyncSession
    ) -> AsyncClient:
        """Create a regular user and authenticated client."""
        from fastsmtp.auth import generate_api_key

        # Create user
        user = User(
            username="apikey_user",
            email="apikey@test.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.flush()

        # Create API key for user
        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="Test Key",
            scopes=["domains:read", "domains:write"],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": full_key},
        ) as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_regular_user_whoami(self, regular_user_client: AsyncClient):
        """Test getting current user info for regular user."""
        response = await regular_user_client.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["username"] == "apikey_user"
        assert data["is_root"] is False

    @pytest.mark.asyncio
    async def test_list_api_keys_regular_user(self, regular_user_client: AsyncClient):
        """Test listing API keys for regular user."""
        response = await regular_user_client.get("/api/v1/auth/keys")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(k["name"] == "Test Key" for k in data)

    @pytest.mark.asyncio
    async def test_create_api_key_regular_user(self, regular_user_client: AsyncClient):
        """Test creating an API key as regular user."""
        response = await regular_user_client.post(
            "/api/v1/auth/keys",
            json={
                "name": "New Key",
                "scopes": ["domains:read"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Key"
        assert "key" in data
        assert data["key"].startswith("fsmtp_")

    @pytest.mark.asyncio
    async def test_delete_api_key_regular_user(
        self,
        regular_user_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test deleting an API key as regular user."""
        from fastsmtp.auth import generate_api_key

        # First create another key to delete
        response = await regular_user_client.post(
            "/api/v1/auth/keys",
            json={
                "name": "Key to Delete",
                "scopes": [],
            },
        )
        assert response.status_code == 201
        key_id = response.json()["id"]

        # Now delete it
        response = await regular_user_client.delete(f"/api/v1/auth/keys/{key_id}")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_regular_user_cannot_list_all_users(
        self, regular_user_client: AsyncClient
    ):
        """Test regular user cannot access user management."""
        response = await regular_user_client.get("/api/v1/users")
        assert response.status_code == 403
