"""Extended tests for recipient API endpoints to improve coverage."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.models import Domain, Recipient


class TestRecipientsUpdateExtended:
    """Extended tests for recipient update operations."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(domain_name="recipients-update-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_update_recipient_local_part(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test updating recipient local_part."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="oldlocal",
            webhook_url="https://example.com/hook",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}",
            json={"local_part": "newlocal"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["local_part"] == "newlocal"

    @pytest.mark.asyncio
    async def test_update_recipient_to_catchall(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test updating recipient to catch-all (empty local_part)."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="specific",
            webhook_url="https://example.com/hook",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}",
            json={"local_part": "*"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["local_part"] is None  # * becomes NULL

    @pytest.mark.asyncio
    async def test_update_recipient_duplicate_local_part(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test updating recipient with duplicate local_part fails."""
        r1 = Recipient(
            domain_id=test_domain.id,
            local_part="existing",
            webhook_url="https://example.com/1",
            is_enabled=True,
        )
        r2 = Recipient(
            domain_id=test_domain.id,
            local_part="other",
            webhook_url="https://example.com/2",
            is_enabled=True,
        )
        test_session.add_all([r1, r2])
        await test_session.commit()
        await test_session.refresh(r2)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{r2.id}",
            json={"local_part": "existing"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_recipient_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test updating non-existent recipient returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{fake_id}",
            json={"webhook_url": "https://example.com/new"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_recipient_webhook_url(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test updating recipient webhook_url."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part="webhook",
            webhook_url="https://old.example.com/hook",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}",
            json={"webhook_url": "https://new.example.com/hook"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["webhook_url"] == "https://new.example.com/hook"

    @pytest.mark.asyncio
    async def test_delete_recipient_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test deleting non-existent recipient returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{fake_id}"
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_catchall_recipient(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test deleting catch-all recipient."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part=None,  # Catch-all
            webhook_url="https://example.com/catchall",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 200
        assert "*" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_create_recipient_with_star_local_part(
        self, auth_client: AsyncClient, test_domain: Domain
    ):
        """Test creating recipient with '*' as local_part creates catch-all."""
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "*",
                "webhook_url": "https://example.com/catchall",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["local_part"] is None

    @pytest.mark.asyncio
    async def test_create_duplicate_catchall(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test creating duplicate catch-all recipient fails."""
        recipient = Recipient(
            domain_id=test_domain.id,
            local_part=None,
            webhook_url="https://example.com/existing",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "*",
                "webhook_url": "https://example.com/new",
            },
        )
        assert response.status_code == 409
        assert "catch-all" in response.json()["detail"]
