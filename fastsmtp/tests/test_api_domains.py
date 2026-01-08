"""Tests for domain and member API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.models import Domain, DomainMember, User


class TestListDomains:
    """Tests for GET /api/v1/domains."""

    @pytest.mark.asyncio
    async def test_list_domains_empty(self, auth_client: AsyncClient):
        """Test listing domains when none exist."""
        response = await auth_client.get("/api/v1/domains")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_list_domains_with_domains(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test listing domains returns all domains for superuser."""
        # Create test domains
        domain1 = Domain(domain_name="test1.com", is_enabled=True)
        domain2 = Domain(domain_name="test2.com", is_enabled=True)
        test_session.add_all([domain1, domain2])
        await test_session.commit()

        response = await auth_client.get("/api/v1/domains")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        domain_names = {d["domain_name"] for d in data}
        assert "test1.com" in domain_names
        assert "test2.com" in domain_names

    @pytest.mark.asyncio
    async def test_list_domains_unauthenticated(self, client: AsyncClient):
        """Test listing domains requires authentication."""
        response = await client.get("/api/v1/domains")
        assert response.status_code == 401


class TestCreateDomain:
    """Tests for POST /api/v1/domains."""

    @pytest.mark.asyncio
    async def test_create_domain_success(self, auth_client: AsyncClient):
        """Test creating a domain successfully."""
        response = await auth_client.post(
            "/api/v1/domains",
            json={"domain_name": "newdomain.com"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["domain_name"] == "newdomain.com"
        assert data["is_enabled"] is True
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_domain_with_settings(self, auth_client: AsyncClient):
        """Test creating domain with custom settings."""
        response = await auth_client.post(
            "/api/v1/domains",
            json={
                "domain_name": "custom.com",
                "verify_dkim": True,
                "verify_spf": True,
                "reject_dkim_fail": True,
                "reject_spf_fail": False,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["verify_dkim"] is True
        assert data["verify_spf"] is True
        assert data["reject_dkim_fail"] is True
        assert data["reject_spf_fail"] is False

    @pytest.mark.asyncio
    async def test_create_domain_duplicate(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test creating duplicate domain fails."""
        domain = Domain(domain_name="existing.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        response = await auth_client.post(
            "/api/v1/domains",
            json={"domain_name": "existing.com"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_domain_unauthenticated(self, client: AsyncClient):
        """Test creating domain requires authentication."""
        response = await client.post(
            "/api/v1/domains",
            json={"domain_name": "unauth.com"},
        )
        assert response.status_code == 401


class TestGetDomain:
    """Tests for GET /api/v1/domains/{domain_id}."""

    @pytest.mark.asyncio
    async def test_get_domain_success(self, auth_client: AsyncClient, test_session: AsyncSession):
        """Test getting a domain by ID."""
        domain = Domain(domain_name="gettest.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        response = await auth_client.get(f"/api/v1/domains/{domain.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["domain_name"] == "gettest.com"
        assert data["id"] == str(domain.id)

    @pytest.mark.asyncio
    async def test_get_domain_not_found(self, auth_client: AsyncClient):
        """Test getting non-existent domain returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.get(f"/api/v1/domains/{fake_id}")
        assert response.status_code == 404


class TestUpdateDomain:
    """Tests for PUT /api/v1/domains/{domain_id}."""

    @pytest.mark.asyncio
    async def test_update_domain_success(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test updating a domain."""
        domain = Domain(domain_name="updatetest.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}",
            json={"is_enabled": False, "verify_dkim": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_enabled"] is False
        assert data["verify_dkim"] is True


class TestDeleteDomain:
    """Tests for DELETE /api/v1/domains/{domain_id}."""

    @pytest.mark.asyncio
    async def test_delete_domain_success(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test deleting a domain."""
        domain = Domain(domain_name="deletetest.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        response = await auth_client.delete(f"/api/v1/domains/{domain.id}")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]


class TestDomainMembers:
    """Tests for domain member endpoints."""

    @pytest_asyncio.fixture
    async def test_user(self, test_session: AsyncSession) -> User:
        """Create a test user."""
        user = User(
            username="testmember",
            email="member@test.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)
        return user

    @pytest_asyncio.fixture
    async def test_domain_with_member(self, test_session: AsyncSession, test_user: User) -> Domain:
        """Create a domain with a member."""
        domain = Domain(domain_name="membertest.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        member = DomainMember(
            domain_id=domain.id,
            user_id=test_user.id,
            role="member",
        )
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_list_members(self, auth_client: AsyncClient, test_domain_with_member: Domain):
        """Test listing domain members."""
        response = await auth_client.get(f"/api/v1/domains/{test_domain_with_member.id}/members")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["role"] == "member"

    @pytest.mark.asyncio
    async def test_add_member(self, auth_client: AsyncClient, test_session: AsyncSession):
        """Test adding a member to a domain."""
        domain = Domain(domain_name="addmember.com", is_enabled=True)
        test_session.add(domain)

        user = User(
            username="newmember",
            email="new@test.com",
            is_active=True,
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(domain)
        await test_session.refresh(user)

        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/members",
            json={"user_id": str(user.id), "role": "admin"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["role"] == "admin"
        assert data["user_id"] == str(user.id)

    @pytest.mark.asyncio
    async def test_add_member_duplicate(
        self, auth_client: AsyncClient, test_domain_with_member: Domain, test_user: User
    ):
        """Test adding duplicate member fails."""
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain_with_member.id}/members",
            json={"user_id": str(test_user.id), "role": "admin"},
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_update_member_role(
        self,
        auth_client: AsyncClient,
        test_domain_with_member: Domain,
        test_user: User,
    ):
        """Test updating a member's role."""
        response = await auth_client.put(
            f"/api/v1/domains/{test_domain_with_member.id}/members/{test_user.id}",
            json={"role": "admin"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "admin"

    @pytest.mark.asyncio
    async def test_remove_member(
        self,
        auth_client: AsyncClient,
        test_domain_with_member: Domain,
        test_user: User,
    ):
        """Test removing a member from a domain."""
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain_with_member.id}/members/{test_user.id}"
        )
        assert response.status_code == 200
        assert "removed" in response.json()["message"]
