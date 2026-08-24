"""Extended tests for users API endpoints to improve coverage."""

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.auth import generate_api_key
from fastsmtp.db.models import APIKey, User
from fastsmtp.db.soft_delete import soft_delete_user
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
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
    async def test_get_user_success(self, auth_client: AsyncClient, test_session: AsyncSession):
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
    async def test_update_user_success(self, auth_client: AsyncClient, test_session: AsyncSession):
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
    async def test_delete_user_success(self, auth_client: AsyncClient, test_session: AsyncSession):
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


class TestUpdateUserPrecheck:
    """The duplicate pre-check only runs when the username actually changes.

    A full-representation PUT carries the current username; querying the
    index for a name the row already holds is a wasted round trip on every
    such update.
    """

    @pytest.mark.asyncio
    async def test_unchanged_username_skips_the_query(
        self, auth_client: AsyncClient, test_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ):
        import fastsmtp.api.users as users_api

        checked: list[str] = []

        async def record(session: AsyncSession, model, column, value, *, exclude_id=None) -> bool:
            checked.append(value)
            return False

        monkeypatch.setattr(users_api, "live_value_taken", record)
        user = User(username="steady", email="old@example.com", is_active=True)
        test_session.add(user)
        await test_session.commit()

        same = await auth_client.put(
            f"/api/v1/users/{user.id}", json={"username": "steady", "email": "new@example.com"}
        )
        assert same.status_code == 200
        assert same.json()["email"] == "new@example.com"
        assert checked == []

        renamed = await auth_client.put(f"/api/v1/users/{user.id}", json={"username": "moved"})
        assert renamed.status_code == 200
        assert checked == ["moved"]


class TestUserConflictRace:
    """The loser of a concurrent duplicate username write must get the pre-check's 409.

    create_user and update_user are check-then-flush, so two concurrent
    requests can both pass the duplicate check; the loser then hits the
    unique index on users.username at flush time. The loser is simulated
    deterministically by patching the pre-check filter to match nothing,
    which is exactly what its stale read saw.
    """

    @pytest.fixture
    def losing_precheck(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make the duplicate pre-check see no conflict, as the race's loser does."""
        import fastsmtp.api.users as users_api

        async def username_is_free(
            session: AsyncSession, model, column, value, *, exclude_id=None
        ) -> bool:
            return False

        monkeypatch.setattr(users_api, "live_value_taken", username_is_free)

    @pytest.mark.asyncio
    async def test_raced_duplicate_create_returns_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """A create that loses the race gets 409, not a 500 from the index."""
        test_session.add(User(username="raced", is_active=True))
        await test_session.commit()

        response = await auth_client.post("/api/v1/users", json={"username": "raced"})
        assert response.status_code == 409
        assert response.json()["detail"] == "Username already exists"

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post("/api/v1/users", json={"username": "unraced"})
        assert fresh.status_code == 201

    @pytest.mark.asyncio
    async def test_raced_duplicate_update_returns_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """An update that loses the race gets 409, not a 500 from the index."""
        target = User(username="target", is_active=True)
        test_session.add_all([User(username="keep", is_active=True), target])
        await test_session.commit()
        await test_session.refresh(target)

        response = await auth_client.put(f"/api/v1/users/{target.id}", json={"username": "keep"})
        assert response.status_code == 409
        assert response.json()["detail"] == "Username already exists"

    @pytest.mark.asyncio
    async def test_raced_restore_returns_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """A restore that loses the race to a re-created name hits the 008 index -> 409.

        The partial unique index only covers live rows, so clearing the
        tombstone while a live row holds the name is the violation.
        """
        old = User(username="phoenix", is_active=True)
        test_session.add(old)
        await test_session.commit()
        await soft_delete_user(test_session, old)
        await test_session.commit()
        test_session.add(User(username="phoenix", is_active=True))
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/users/{old.id}/restore")
        assert response.status_code == 409
        assert response.json()["detail"] == "Username already exists"

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post("/api/v1/users", json={"username": "unraced"})
        assert fresh.status_code == 201


ClientFor = Callable[[User], Awaitable[AsyncClient]]


class TestUserSoftDelete:
    """DELETE tombstones, restore clears it, purge is the old hard delete on a tombstone."""

    @pytest_asyncio.fixture
    async def client_for(
        self, app: FastAPI, test_session: AsyncSession
    ) -> AsyncIterator[ClientFor]:
        """Build an authenticated client for a (persisted) user with a fresh key."""
        clients: list[AsyncClient] = []

        async def make(user: User) -> AsyncClient:
            full_key, key_prefix, key_hash, key_salt = generate_api_key()
            test_session.add(
                APIKey(
                    user_id=user.id,
                    key_hash=key_hash,
                    key_salt=key_salt,
                    key_prefix=key_prefix,
                    name=f"{user.username} key",
                    scopes=[],
                    is_active=True,
                )
            )
            await test_session.commit()
            client = AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                headers={"X-API-Key": full_key},
            )
            clients.append(client)
            return client

        yield make
        for client in clients:
            await client.aclose()

    @pytest_asyncio.fixture
    async def user(self, test_session: AsyncSession) -> User:
        user = User(username="alice", email="alice@example.com", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)
        return user

    @pytest_asyncio.fixture
    async def deleted_user(
        self, auth_client: AsyncClient, test_session: AsyncSession, user: User
    ) -> User:
        response = await auth_client.delete(f"/api/v1/users/{user.id}")
        assert response.status_code == 200
        await test_session.refresh(user)
        assert user.deleted_at is not None
        return user

    # -- delete -------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_delete_tombstones_and_keeps_message(
        self, auth_client: AsyncClient, test_session: AsyncSession, user: User
    ):
        response = await auth_client.delete(f"/api/v1/users/{user.id}")
        assert response.status_code == 200
        assert response.json()["message"] == "User alice deleted"

        await test_session.refresh(user)
        assert user.deleted_at is not None

    @pytest.mark.asyncio
    async def test_delete_revokes_keys(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        user: User,
        client_for: ClientFor,
    ):
        await client_for(user)

        response = await auth_client.delete(f"/api/v1/users/{user.id}")
        assert response.status_code == 200

        keys = (
            (await test_session.execute(select(APIKey).where(APIKey.user_id == user.id)))
            .scalars()
            .all()
        )
        assert len(keys) == 1
        await test_session.refresh(keys[0])
        assert keys[0].deleted_at is not None
        assert keys[0].is_active is False

    @pytest.mark.asyncio
    async def test_delete_tombstone_again_is_404(
        self, auth_client: AsyncClient, deleted_user: User
    ):
        response = await auth_client.delete(f"/api/v1/users/{deleted_user.id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"

    @pytest.mark.asyncio
    async def test_self_delete_400_in_both_modes(
        self, test_session: AsyncSession, client_for: ClientFor
    ):
        admin = User(username="admin", is_active=True, is_superuser=True)
        test_session.add(admin)
        await test_session.commit()
        await test_session.refresh(admin)
        client = await client_for(admin)

        for params in ({}, {"purge": "true"}):
            response = await client.delete(f"/api/v1/users/{admin.id}", params=params)
            assert response.status_code == 400, params
            assert response.json()["detail"] == "Cannot delete your own account"

        await test_session.refresh(admin)
        assert admin.deleted_at is None

    # -- reads --------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_hides_tombstone_unless_include_deleted(
        self, auth_client: AsyncClient, deleted_user: User
    ):
        response = await auth_client.get(f"/api/v1/users/{deleted_user.id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"

        response = await auth_client.get(
            f"/api/v1/users/{deleted_user.id}", params={"include_deleted": "true"}
        )
        assert response.status_code == 200
        assert response.json()["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_list_hides_tombstone_unless_include_deleted(
        self, auth_client: AsyncClient, deleted_user: User
    ):
        response = await auth_client.get("/api/v1/users")
        assert response.status_code == 200
        assert "alice" not in {u["username"] for u in response.json()}

        response = await auth_client.get("/api/v1/users", params={"include_deleted": "true"})
        assert response.status_code == 200
        rows = {u["username"]: u for u in response.json()}
        assert rows["alice"]["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_include_deleted_below_superuser_is_403(
        self, test_session: AsyncSession, client_for: ClientFor, deleted_user: User
    ):
        plain = User(username="plain", is_active=True)
        test_session.add(plain)
        await test_session.commit()
        await test_session.refresh(plain)
        client = await client_for(plain)

        for url in ("/api/v1/users", f"/api/v1/users/{deleted_user.id}"):
            response = await client.get(url, params={"include_deleted": "true"})
            assert response.status_code == 403, url

    @pytest.mark.asyncio
    async def test_update_tombstone_is_404(self, auth_client: AsyncClient, deleted_user: User):
        response = await auth_client.put(
            f"/api/v1/users/{deleted_user.id}", json={"email": "x@example.com"}
        )
        assert response.status_code == 404

    # -- name reuse (S18) ---------------------------------------------------

    @pytest.mark.asyncio
    async def test_create_after_delete_is_201(self, auth_client: AsyncClient, deleted_user: User):
        response = await auth_client.post("/api/v1/users", json={"username": "alice"})
        assert response.status_code == 201
        assert response.json()["id"] != str(deleted_user.id)

    @pytest.mark.asyncio
    async def test_update_to_tombstoned_name_is_200(
        self, auth_client: AsyncClient, test_session: AsyncSession, deleted_user: User
    ):
        other = User(username="bob", is_active=True)
        test_session.add(other)
        await test_session.commit()
        await test_session.refresh(other)

        response = await auth_client.put(f"/api/v1/users/{other.id}", json={"username": "alice"})
        assert response.status_code == 200
        assert response.json()["username"] == "alice"

    # -- restore ------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restore_clears_tombstone(self, auth_client: AsyncClient, deleted_user: User):
        response = await auth_client.post(f"/api/v1/users/{deleted_user.id}/restore")
        assert response.status_code == 200
        body = response.json()
        assert body["id"] == str(deleted_user.id)
        assert body["deleted_at"] is None

        response = await auth_client.get(f"/api/v1/users/{deleted_user.id}")
        assert response.status_code == 200
        assert response.json()["deleted_at"] is None

    @pytest.mark.asyncio
    async def test_restore_leaves_keys_revoked(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        user: User,
        client_for: ClientFor,
    ):
        key_client = await client_for(user)
        assert (await auth_client.delete(f"/api/v1/users/{user.id}")).status_code == 200
        assert (await auth_client.post(f"/api/v1/users/{user.id}/restore")).status_code == 200

        response = await key_client.get("/api/v1/auth/me")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_restore_live_is_409(self, auth_client: AsyncClient, user: User):
        response = await auth_client.post(f"/api/v1/users/{user.id}/restore")
        assert response.status_code == 409
        assert response.json()["detail"] == "User is not deleted"

    @pytest.mark.asyncio
    async def test_restore_unknown_is_404(self, auth_client: AsyncClient):
        response = await auth_client.post(f"/api/v1/users/{uuid.uuid4()}/restore")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_restore_retaken_name_is_409(self, auth_client: AsyncClient, deleted_user: User):
        assert (
            await auth_client.post("/api/v1/users", json={"username": "alice"})
        ).status_code == 201

        response = await auth_client.post(f"/api/v1/users/{deleted_user.id}/restore")
        assert response.status_code == 409
        assert response.json()["detail"] == "Username already exists"

    @pytest.mark.asyncio
    async def test_restore_below_superuser_is_403(
        self, test_session: AsyncSession, client_for: ClientFor, deleted_user: User
    ):
        plain = User(username="plain", is_active=True)
        test_session.add(plain)
        await test_session.commit()
        await test_session.refresh(plain)
        client = await client_for(plain)

        response = await client.post(f"/api/v1/users/{deleted_user.id}/restore")
        assert response.status_code == 403

    # -- purge --------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_purge_live_is_409(
        self, auth_client: AsyncClient, test_session: AsyncSession, user: User
    ):
        response = await auth_client.delete(f"/api/v1/users/{user.id}", params={"purge": "true"})
        assert response.status_code == 409
        assert response.json()["detail"] == "User must be deleted before it can be purged"

        await test_session.refresh(user)
        assert user.deleted_at is None

    @pytest.mark.asyncio
    async def test_purge_below_superuser_is_403(
        self, test_session: AsyncSession, client_for: ClientFor, deleted_user: User
    ):
        plain = User(username="plain", is_active=True)
        test_session.add(plain)
        await test_session.commit()
        await test_session.refresh(plain)
        client = await client_for(plain)

        response = await client.delete(f"/api/v1/users/{deleted_user.id}", params={"purge": "true"})
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_purge_tombstone_removes_row_and_keys(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        user: User,
        client_for: ClientFor,
    ):
        await client_for(user)
        assert (await auth_client.delete(f"/api/v1/users/{user.id}")).status_code == 200

        response = await auth_client.delete(f"/api/v1/users/{user.id}", params={"purge": "true"})
        assert response.status_code == 200
        assert response.json()["message"] == "User alice purged"

        assert (
            await test_session.execute(select(User).where(User.id == user.id))
        ).scalar_one_or_none() is None
        assert (
            await test_session.execute(select(APIKey).where(APIKey.user_id == user.id))
        ).scalars().all() == []

        response = await auth_client.get(
            f"/api/v1/users/{user.id}", params={"include_deleted": "true"}
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_purge_unknown_is_404(self, auth_client: AsyncClient):
        response = await auth_client.delete(
            f"/api/v1/users/{uuid.uuid4()}", params={"purge": "true"}
        )
        assert response.status_code == 404
