"""Extended tests for users API endpoints to improve coverage."""

import uuid

import pytest
from fastsmtp.db.models import User
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestUsersCRUDExtended:
    """Extended tests for user CRUD operations."""

    @pytest.mark.asyncio
    async def test_list_users_empty(self, auth_client: AsyncClient):
        """Test listing users when none exist (besides root)."""
        response = await auth_client.get("/api/v1/users")
        assert response.status_code == 200
        # May have existing test users
        assert isinstance(response.json(), list)

    @pytest.mark.asyncio
    async def test_list_users_with_users(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test listing users with data."""
        user1 = User(username="testuser1", email="test1@example.com", is_active=True)
        user2 = User(username="testuser2", email="test2@example.com", is_active=True)
        test_session.add_all([user1, user2])
        await test_session.commit()

        response = await auth_client.get("/api/v1/users")
        assert response.status_code == 200
        data = response.json()
        usernames = {u["username"] for u in data}
        assert "testuser1" in usernames
        assert "testuser2" in usernames

    @pytest.mark.asyncio
    async def test_create_user_success(self, auth_client: AsyncClient):
        """Test creating a user successfully."""
        response = await auth_client.post(
            "/api/v1/users",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "is_superuser": False,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["is_superuser"] is False

    @pytest.mark.asyncio
    async def test_create_user_superuser(self, auth_client: AsyncClient):
        """Test creating a superuser."""
        response = await auth_client.post(
            "/api/v1/users",
            json={
                "username": "superadmin",
                "email": "super@example.com",
                "is_superuser": True,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["is_superuser"] is True

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test creating user with duplicate username fails."""
        user = User(username="existing", email="existing@example.com", is_active=True)
        test_session.add(user)
        await test_session.commit()

        response = await auth_client.post(
            "/api/v1/users",
            json={
                "username": "existing",
                "email": "new@example.com",
            },
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_user_success(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test getting a user by ID."""
        user = User(username="getuser", email="get@example.com", is_active=True)
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
    async def test_update_user_success(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test updating a user."""
        user = User(username="updateuser", email="update@example.com", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        response = await auth_client.put(
            f"/api/v1/users/{user.id}",
            json={"username": "updateduser", "is_superuser": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "updateduser"
        assert data["is_superuser"] is True

    @pytest.mark.asyncio
    async def test_update_user_duplicate_username(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test updating user with duplicate username fails."""
        user1 = User(username="userA", email="a@example.com", is_active=True)
        user2 = User(username="userB", email="b@example.com", is_active=True)
        test_session.add_all([user1, user2])
        await test_session.commit()
        await test_session.refresh(user2)

        response = await auth_client.put(
            f"/api/v1/users/{user2.id}",
            json={"username": "userA"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, auth_client: AsyncClient):
        """Test updating non-existent user returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.put(
            f"/api/v1/users/{fake_id}",
            json={"username": "newname"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_user_success(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test deleting a user."""
        user = User(username="deleteuser", email="delete@example.com", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        response = await auth_client.delete(f"/api/v1/users/{user.id}")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, auth_client: AsyncClient):
        """Test deleting non-existent user returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.delete(f"/api/v1/users/{fake_id}")
        assert response.status_code == 404


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
            json={"username": "test", "email": "test@example.com"},
        )
        assert response.status_code == 401
