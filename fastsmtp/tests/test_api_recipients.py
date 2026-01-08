"""Tests for recipient API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.models import Domain, Recipient


class TestRecipientsCRUD:
    """Tests for recipient CRUD operations."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(domain_name="recipients-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_list_recipients_empty(self, auth_client: AsyncClient, test_domain: Domain):
        """Test listing recipients when none exist."""
        response = await auth_client.get(f"/api/v1/domains/{test_domain.id}/recipients")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_create_recipient(self, auth_client: AsyncClient, test_domain: Domain):
        """Test creating a recipient."""
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "info",
                "webhook_url": "https://example.com/webhook",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["local_part"] == "info"
        assert data["webhook_url"] == "https://example.com/webhook"
        assert data["is_enabled"] is True

    @pytest.mark.asyncio
    async def test_create_catchall_recipient(self, auth_client: AsyncClient, test_domain: Domain):
        """Test creating a catch-all recipient (null local_part)."""
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": None,
                "webhook_url": "https://example.com/catchall",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["local_part"] is None

    @pytest.mark.asyncio
    async def test_create_recipient_with_headers(
        self, auth_client: AsyncClient, test_domain: Domain
    ):
        """Test creating recipient with custom webhook headers."""
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "secure",
                "webhook_url": "https://example.com/secure",
                "webhook_headers": {"Authorization": "Bearer token123"},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["webhook_headers"]["Authorization"] == "Bearer token123"

    @pytest.mark.asyncio
    async def test_create_duplicate_recipient(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test creating duplicate recipient fails."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="existing",
            webhook_url="https://example.com/existing",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "existing",
                "webhook_url": "https://example.com/new",
            },
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_list_recipients_with_recipients(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test listing recipients returns all recipients."""
        r1 = Recipient(
            domain_id=test_domain.id,
            local_part="user1",
            webhook_url="https://example.com/1",
            is_enabled=True,
        )
        r2 = Recipient(
            domain_id=test_domain.id,
            local_part="user2",
            webhook_url="https://example.com/2",
            is_enabled=True,
        )
        test_session.add_all([r1, r2])
        await test_session.commit()

        response = await auth_client.get(f"/api/v1/domains/{test_domain.id}/recipients")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_get_recipient(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test getting a recipient by ID."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="gettest",
            webhook_url="https://example.com/get",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.get(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["local_part"] == "gettest"

    @pytest.mark.asyncio
    async def test_get_recipient_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test getting non-existent recipient returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.get(f"/api/v1/domains/{test_domain.id}/recipients/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_recipient(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test updating a recipient."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="updatetest",
            webhook_url="https://example.com/old",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}",
            json={
                "webhook_url": "https://example.com/new",
                "is_enabled": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["webhook_url"] == "https://example.com/new"
        assert data["is_enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_recipient(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test deleting a recipient."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="deletetest",
            webhook_url="https://example.com/delete",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]


class TestRecipientsAuth:
    """Tests for recipient authentication/authorization."""

    @pytest.mark.asyncio
    async def test_list_recipients_unauthenticated(self, client: AsyncClient):
        """Test listing recipients requires authentication."""
        fake_domain_id = uuid.uuid4()
        response = await client.get(f"/api/v1/domains/{fake_domain_id}/recipients")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_recipient_unauthenticated(self, client: AsyncClient):
        """Test creating recipient requires authentication."""
        fake_domain_id = uuid.uuid4()
        response = await client.post(
            f"/api/v1/domains/{fake_domain_id}/recipients",
            json={
                "local_part": "test",
                "webhook_url": "https://example.com",
            },
        )
        assert response.status_code == 401
