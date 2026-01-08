"""Extended tests for domain API endpoints to improve coverage."""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.auth import generate_api_key
from fastsmtp.db.models import APIKey, Domain, DomainMember, User


class TestDomainMembersExtended:
    """Extended tests for domain member operations."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(domain_name="members-extended.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest_asyncio.fixture
    async def test_owner(self, test_session: AsyncSession) -> User:
        """Create a test owner user."""
        user = User(
            username="owner",
            email="owner@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)
        return user

    @pytest.mark.asyncio
    async def test_add_member_user_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test adding non-existent user as member fails."""
        fake_user_id = uuid.uuid4()
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/members",
            json={"user_id": str(fake_user_id), "role": "member"},
        )
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_member_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test updating non-existent member fails."""
        fake_user_id = uuid.uuid4()
        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/members/{fake_user_id}",
            json={"role": "admin"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_member_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test removing non-existent member fails."""
        fake_user_id = uuid.uuid4()
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/members/{fake_user_id}"
        )
        assert response.status_code == 404


class TestDomainAccessControl:
    """Tests for domain access control."""

    @pytest_asyncio.fixture
    async def non_superuser_with_domain(
        self, test_session: AsyncSession, app
    ) -> tuple[User, Domain, str]:
        """Create a non-superuser with domain access."""
        # Create user
        user = User(
            username="regular_user",
            email="regular@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.flush()

        # Create domain
        domain = Domain(domain_name="user-domain.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Add user as member
        member = DomainMember(
            domain_id=domain.id,
            user_id=user.id,
            role="member",
        )
        test_session.add(member)

        # Create API key
        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="User Key",
            scopes=[
                "domains:read",
                "domains:write",
                "recipients:read",
                "recipients:write",
            ],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        return user, domain, full_key

    @pytest.mark.asyncio
    async def test_list_domains_as_regular_user(
        self, app, non_superuser_with_domain: tuple[User, Domain, str]
    ):
        """Test regular user sees only their domains."""
        user, domain, api_key = non_superuser_with_domain

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as user_client:
            response = await user_client.get("/api/v1/domains")
            assert response.status_code == 200
            data = response.json()
            domain_names = {d["domain_name"] for d in data}
            assert "user-domain.com" in domain_names

    @pytest.mark.asyncio
    async def test_access_other_domain_denied(
        self, app, test_session: AsyncSession, non_superuser_with_domain: tuple[User, Domain, str]
    ):
        """Test regular user cannot access other domains."""
        user, _, api_key = non_superuser_with_domain

        # Create another domain that user is NOT a member of
        other_domain = Domain(domain_name="other-domain.com", is_enabled=True)
        test_session.add(other_domain)
        await test_session.commit()
        await test_session.refresh(other_domain)

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as user_client:
            response = await user_client.get(f"/api/v1/domains/{other_domain.id}")
            assert response.status_code == 403
            assert "Access denied" in response.json()["detail"]


class TestDomainRoleHierarchy:
    """Tests for domain role hierarchy."""

    @pytest_asyncio.fixture
    async def admin_user_with_domain(
        self, test_session: AsyncSession, app
    ) -> tuple[User, Domain, str]:
        """Create an admin user with domain access."""
        user = User(
            username="admin_user",
            email="admin@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.flush()

        domain = Domain(domain_name="admin-domain.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        member = DomainMember(
            domain_id=domain.id,
            user_id=user.id,
            role="admin",
        )
        test_session.add(member)

        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="Admin Key",
            scopes=["domains:read", "domains:write", "domains:delete"],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        return user, domain, full_key

    @pytest.mark.asyncio
    async def test_admin_can_update_domain(
        self, app, admin_user_with_domain: tuple[User, Domain, str]
    ):
        """Test admin can update domain settings."""
        user, domain, api_key = admin_user_with_domain

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as admin_client:
            response = await admin_client.put(
                f"/api/v1/domains/{domain.id}",
                json={"verify_dkim": True},
            )
            assert response.status_code == 200
            assert response.json()["verify_dkim"] is True

    @pytest.mark.asyncio
    async def test_admin_cannot_delete_domain(
        self, app, admin_user_with_domain: tuple[User, Domain, str]
    ):
        """Test admin cannot delete domain (requires owner)."""
        user, domain, api_key = admin_user_with_domain

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-API-Key": api_key},
        ) as admin_client:
            response = await admin_client.delete(f"/api/v1/domains/{domain.id}")
            assert response.status_code == 403
            assert "owner" in response.json()["detail"].lower()
