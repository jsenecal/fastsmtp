"""Extended tests for auth API endpoints to improve coverage."""

import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from fastsmtp.auth import generate_api_key
from fastsmtp.auth.dependencies import AuthContext, get_domain_with_access
from fastsmtp.config import Settings
from fastsmtp.db.models import APIKey, Domain, DomainMember, User
from fastsmtp.db.soft_delete import (
    restore_user,
    soft_delete_api_key,
    soft_delete_domain,
    soft_delete_user,
)
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


def user_client(app: FastAPI, api_key: str) -> AsyncClient:
    """HTTP client authenticating with ``api_key`` instead of the root key."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-API-Key": api_key},
    )


async def create_user_with_key(
    session: AsyncSession,
    username: str,
    *,
    user_is_active: bool = True,
    **key_fields: object,
) -> tuple[User, APIKey, str]:
    """Create a user and one API key; returns ``(user, key row, full secret)``."""
    user = User(username=username, email=f"{username}@example.com", is_active=user_is_active)
    session.add(user)
    await session.flush()
    api_key, full_key = await create_key(session, user, **key_fields)
    await session.commit()
    await session.refresh(user)
    return user, api_key, full_key


async def create_key(session: AsyncSession, user: User, **fields: object) -> tuple[APIKey, str]:
    """Add one API key to ``user``; returns ``(key row, full secret)``."""
    full_key, key_prefix, key_hash, key_salt = generate_api_key()
    fields.setdefault("name", "Test Key")
    api_key = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        key_salt=key_salt,
        key_prefix=key_prefix,
        **fields,
    )
    session.add(api_key)
    await session.flush()
    return api_key, full_key


async def create_domain_with_member(
    session: AsyncSession, name: str, user: User | None, role: str = "member"
) -> Domain:
    """Create a domain and, when ``user`` is given, its membership."""
    domain = Domain(domain_name=name, is_enabled=True)
    session.add(domain)
    await session.flush()
    if user is not None:
        session.add(DomainMember(domain_id=domain.id, user_id=user.id, role=role))
    await session.commit()
    await session.refresh(domain)
    return domain


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

    @pytest.mark.asyncio
    async def test_whoami_omits_tombstoned_domains(self, app: FastAPI, test_session: AsyncSession):
        """A membership in a soft-deleted domain is not listed (spec S6)."""
        user, _, full_key = await create_user_with_key(test_session, "whoami")
        await create_domain_with_member(test_session, "live.example.com", user)
        gone = await create_domain_with_member(test_session, "gone.example.com", user)
        await soft_delete_domain(test_session, gone)
        await test_session.commit()

        async with user_client(app, full_key) as client:
            response = await client.get("/api/v1/auth/me")

        assert response.status_code == 200
        assert response.json()["domains"] == ["live.example.com"]


class TestAuthKeysExtended:
    """Extended tests for API key management."""

    @pytest_asyncio.fixture
    async def regular_user_with_key(self, test_session: AsyncSession) -> tuple[User, str]:
        """Create a regular user with an API key."""
        user, _, full_key = await create_user_with_key(
            test_session,
            "keyuser",
            scopes=["recipients:read", "recipients:write"],
        )
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

        async with user_client(app, api_key) as client:
            response = await client.get("/api/v1/auth/keys")
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

        async with user_client(app, api_key) as client:
            response = await client.post(
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

        async with user_client(app, api_key) as client:
            fake_id = uuid.uuid4()
            response = await client.delete(f"/api/v1/auth/keys/{fake_id}")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_rotate_key_not_found(
        self,
        app,
        regular_user_with_key: tuple[User, str],
    ):
        """Test rotating non-existent API key returns 404."""
        _, api_key = regular_user_with_key

        async with user_client(app, api_key) as client:
            fake_id = uuid.uuid4()
            response = await client.post(f"/api/v1/auth/keys/{fake_id}/rotate")
            assert response.status_code == 404


class TestKeyTombstones:
    """``DELETE`` / rotate tombstone keys; listings hide them unless asked (spec S19)."""

    @pytest_asyncio.fixture
    async def user_with_two_keys(self, test_session: AsyncSession) -> tuple[User, str, APIKey]:
        """A user, the secret of their current key, and a second key to act on."""
        user, _, full_key = await create_user_with_key(test_session, "twokeys", name="current")
        other, _ = await create_key(test_session, user, name="other")
        await test_session.commit()
        await test_session.refresh(other)
        return user, full_key, other

    @pytest.mark.asyncio
    async def test_delete_key_tombstones_and_second_delete_404s(
        self, app: FastAPI, test_session: AsyncSession, user_with_two_keys
    ):
        _, full_key, other = user_with_two_keys

        async with user_client(app, full_key) as client:
            first = await client.delete(f"/api/v1/auth/keys/{other.id}")
            second = await client.delete(f"/api/v1/auth/keys/{other.id}")

        assert first.status_code == 200
        assert first.json()["message"] == "API key deleted"
        assert second.status_code == 404
        assert second.json()["detail"] == "API key not found"

        await test_session.refresh(other)
        assert other.deleted_at is not None
        assert other.is_active is False

    @pytest.mark.asyncio
    async def test_rotate_tombstones_old_key(
        self, app: FastAPI, test_session: AsyncSession, user_with_two_keys
    ):
        _, full_key, other = user_with_two_keys

        async with user_client(app, full_key) as client:
            rotated = await client.post(f"/api/v1/auth/keys/{other.id}/rotate")
            again = await client.post(f"/api/v1/auth/keys/{other.id}/rotate")

        assert rotated.status_code == 200
        assert rotated.json()["name"] == "other (rotated)"
        assert again.status_code == 404

        await test_session.refresh(other)
        assert other.deleted_at is not None
        assert other.is_active is False

    @pytest.mark.asyncio
    async def test_list_keys_hides_tombstones_unless_include_deleted(
        self, app: FastAPI, test_session: AsyncSession, user_with_two_keys
    ):
        user, full_key, other = user_with_two_keys
        # A key retired by a v0.4.0 server: is_active=False, deleted_at NULL.
        retired, _ = await create_key(test_session, user, name="retired", is_active=False)
        await soft_delete_api_key(test_session, other)
        await test_session.commit()

        async with user_client(app, full_key) as client:
            default = await client.get("/api/v1/auth/keys")
            everything = await client.get("/api/v1/auth/keys", params={"include_deleted": "true"})

        assert default.status_code == 200
        assert [k["name"] for k in default.json()] == ["current"]
        assert all(k["deleted_at"] is None for k in default.json())

        assert everything.status_code == 200
        by_name = {k["name"]: k for k in everything.json()}
        assert set(by_name) == {"current", "other", "retired"}
        assert by_name["current"]["deleted_at"] is None
        assert by_name["other"]["deleted_at"] is not None
        assert by_name["other"]["is_active"] is False
        assert by_name["retired"]["deleted_at"] is None
        assert by_name["retired"]["is_active"] is False
        assert by_name["retired"]["id"] == str(retired.id)

    def test_keys_have_no_restore_route(self, app: FastAPI):
        """Credential revocation is one-way: no ``POST /auth/keys/{id}/restore``."""
        key_paths = [p for p in app.openapi()["paths"] if "/auth/keys" in p]
        assert key_paths, "auth key routes missing from OpenAPI"
        assert not [p for p in key_paths if p.endswith("/restore")]


class TestAuthDependencies:
    """Tests for auth dependencies."""

    @pytest.mark.asyncio
    async def test_invalid_api_key(self, app, test_settings: Settings):
        """Test invalid API key returns 401."""
        async with user_client(app, "invalid_key_12345") as client:
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
    async def test_inactive_api_key(self, app, test_session: AsyncSession):
        """Test inactive API key returns 401."""
        _, _, full_key = await create_user_with_key(
            test_session, "inactivekey", name="Inactive Key", is_active=False
        )

        async with user_client(app, full_key) as client:
            response = await client.get("/api/v1/domains")
            assert response.status_code == 401
            assert "inactive" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_inactive_user(self, app, test_session: AsyncSession):
        """Test inactive user returns 401."""
        _, _, full_key = await create_user_with_key(
            test_session, "inactiveuser", user_is_active=False
        )

        async with user_client(app, full_key) as client:
            response = await client.get("/api/v1/domains")
            assert response.status_code == 401
            assert "User account is inactive" in response.json()["detail"]


class TestTombstonedCredentials:
    """A tombstoned key or user can never authenticate (spec S1-S3)."""

    @pytest.mark.asyncio
    async def test_tombstoned_key_is_invalid(self, app: FastAPI, test_session: AsyncSession):
        """The key is excluded from the lookup, so the uniform "Invalid API key" answers.

        Not "API key is inactive": that branch would reveal the key once existed.
        """
        _, api_key, full_key = await create_user_with_key(test_session, "tombkey")
        await soft_delete_api_key(test_session, api_key)
        await test_session.commit()

        async with user_client(app, full_key) as client:
            response = await client.get("/api/v1/domains")

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid API key"

    @pytest.mark.asyncio
    async def test_user_soft_delete_revokes_keys_and_restore_keeps_them_revoked(
        self, app: FastAPI, test_session: AsyncSession
    ):
        user, api_key, full_key = await create_user_with_key(test_session, "tombuser")
        await soft_delete_user(test_session, user)
        await test_session.commit()
        await test_session.refresh(api_key)
        assert api_key.deleted_at == user.deleted_at
        assert api_key.is_active is False

        async with user_client(app, full_key) as client:
            while_deleted = await client.get("/api/v1/domains")

        await restore_user(test_session, user)
        await test_session.commit()
        await test_session.refresh(user)
        assert user.deleted_at is None

        async with user_client(app, full_key) as client:
            after_restore = await client.get("/api/v1/domains")

        assert while_deleted.status_code == 401
        assert while_deleted.json()["detail"] == "Invalid API key"
        assert after_restore.status_code == 401
        assert after_restore.json()["detail"] == "Invalid API key"

    @pytest.mark.asyncio
    async def test_live_key_of_tombstoned_user_is_rejected(
        self, app: FastAPI, test_session: AsyncSession
    ):
        """A key that escaped the cascade (created after the delete) is still refused."""
        user, _, _ = await create_user_with_key(test_session, "escaped")
        await soft_delete_user(test_session, user)
        _, full_key = await create_key(test_session, user, name="escaped")
        await test_session.commit()

        async with user_client(app, full_key) as client:
            response = await client.get("/api/v1/domains")

        assert response.status_code == 401
        assert response.json()["detail"] == "User account is inactive"


class TestGetDomainWithAccessTombstones:
    """``get_domain_with_access`` hides tombstones below the owner role (spec section 3)."""

    async def _tombstoned_domain(
        self, session: AsyncSession, user: User | None, role: str = "member"
    ) -> Domain:
        domain = await create_domain_with_member(session, "tomb.example.com", user, role)
        await soft_delete_domain(session, domain)
        await session.commit()
        return domain

    @staticmethod
    async def _user(session: AsyncSession, username: str, **fields: object) -> User:
        user = User(username=username, email=f"{username}@example.com", **fields)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    @staticmethod
    def _auth(user: User) -> AuthContext:
        return AuthContext(user=user, api_key=None, is_root=False, scopes=set())

    @pytest.mark.asyncio
    async def test_tombstone_is_not_found_by_default(self, test_session: AsyncSession):
        """Even a superuser gets 404 without ``include_deleted``."""
        superuser = await self._user(test_session, "su", is_superuser=True)
        domain = await self._tombstoned_domain(test_session, None)

        with pytest.raises(HTTPException) as exc_info:
            await get_domain_with_access(domain.id, self._auth(superuser), test_session)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Domain not found"

    @pytest.mark.asyncio
    async def test_include_deleted_returns_tombstone_to_superuser(self, test_session: AsyncSession):
        superuser = await self._user(test_session, "su", is_superuser=True)
        domain = await self._tombstoned_domain(test_session, None)

        found = await get_domain_with_access(
            domain.id, self._auth(superuser), test_session, include_deleted=True
        )

        assert found.id == domain.id
        assert found.is_deleted

    @pytest.mark.asyncio
    async def test_include_deleted_returns_tombstone_to_owner(self, test_session: AsyncSession):
        owner = await self._user(test_session, "owner")
        domain = await self._tombstoned_domain(test_session, owner, "owner")

        found = await get_domain_with_access(
            domain.id, self._auth(owner), test_session, "owner", include_deleted=True
        )

        assert found.id == domain.id

    @pytest.mark.parametrize("role", ["admin", "member"])
    @pytest.mark.asyncio
    async def test_include_deleted_hides_tombstone_below_owner(
        self, test_session: AsyncSession, role: str
    ):
        """A non-owner member gets the same 404 as for a nonexistent id, never 403."""
        member = await self._user(test_session, "member")
        domain = await self._tombstoned_domain(test_session, member, role)

        with pytest.raises(HTTPException) as exc_info:
            await get_domain_with_access(
                domain.id, self._auth(member), test_session, include_deleted=True
            )

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Domain not found"

    @pytest.mark.parametrize("include_deleted", [False, True])
    @pytest.mark.asyncio
    async def test_non_member_gets_403_on_a_tombstone(
        self, test_session: AsyncSession, include_deleted: bool
    ):
        """A non-member gets the same 403 as on a live domain, flag or not (#126)."""
        outsider = await self._user(test_session, "outsider")
        domain = await self._tombstoned_domain(test_session, None)

        with pytest.raises(HTTPException) as exc_info:
            await get_domain_with_access(
                domain.id, self._auth(outsider), test_session, include_deleted=include_deleted
            )

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Access denied to this domain"

    @pytest.mark.asyncio
    async def test_include_deleted_is_keyword_only(self, test_session: AsyncSession):
        """The flag must never be passed positionally in the ``required_role`` slot."""
        superuser = await self._user(test_session, "su", is_superuser=True)
        domain = await self._tombstoned_domain(test_session, None)

        with pytest.raises(TypeError):
            await get_domain_with_access(
                domain.id, self._auth(superuser), test_session, "owner", True
            )


class TestNonMemberAnswerIsDeletionBlind:
    """Every domain-scoped route answers a non-member identically for a live and
    a soft-deleted domain (#126), so the status code is never an oracle for
    whether the domain was deleted.
    """

    ROUTES = [
        "/api/v1/domains/{domain_id}",
        "/api/v1/domains/{domain_id}/members",
        "/api/v1/domains/{domain_id}/recipients",
        "/api/v1/domains/{domain_id}/rulesets",
        "/api/v1/domains/{domain_id}/delivery-log",
    ]

    SCOPES = [
        "domains:read",
        "members:read",
        "recipients:read",
        "rules:read",
        "logs:read",
    ]

    @pytest.mark.parametrize("route", ROUTES)
    @pytest.mark.parametrize("include_deleted", [False, True])
    @pytest.mark.asyncio
    async def test_same_answer_live_and_deleted(
        self,
        app: FastAPI,
        test_session: AsyncSession,
        route: str,
        include_deleted: bool,
    ):
        _, _, full_key = await create_user_with_key(test_session, "outsider", scopes=self.SCOPES)
        live = await create_domain_with_member(test_session, "live-blind.example.com", None)
        gone = await create_domain_with_member(test_session, "gone-blind.example.com", None)
        await soft_delete_domain(test_session, gone)
        await test_session.commit()

        params = {"include_deleted": "true"} if include_deleted else None
        async with user_client(app, full_key) as client:
            on_live = await client.get(route.format(domain_id=live.id), params=params)
            on_tombstone = await client.get(route.format(domain_id=gone.id), params=params)

        assert on_tombstone.status_code == on_live.status_code
        assert on_tombstone.json()["detail"] == on_live.json()["detail"]
        assert on_live.status_code == 403
