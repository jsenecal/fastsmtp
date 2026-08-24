"""Extended tests for recipient API endpoints to improve coverage."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from fastsmtp.db.models import Domain, Recipient
from httpx import AsyncClient
from sqlalchemy import false
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def test_domain(test_session: AsyncSession) -> Domain:
    """Create a test domain (the schema is rebuilt fresh for every test)."""
    domain = Domain(domain_name="recipients-extended-test.com", is_enabled=True)
    test_session.add(domain)
    await test_session.commit()
    await test_session.refresh(domain)
    return domain


async def _seed_recipient(
    session: AsyncSession, domain: Domain, local_part: str | None, **overrides: object
) -> Recipient:
    """Insert a committed recipient row directly, bypassing the API."""
    recipient = Recipient(
        domain_id=domain.id,
        local_part=local_part,
        webhook_url="https://example.com/hook",
        is_enabled=True,
        **overrides,
    )
    session.add(recipient)
    await session.commit()
    await session.refresh(recipient)
    return recipient


class TestRecipientsUpdateExtended:
    """Extended tests for recipient update operations."""

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

    @pytest.mark.asyncio
    async def test_create_catchall_after_soft_delete(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """A soft-deleted catch-all must not block creating a replacement."""
        tombstone = Recipient(
            domain_id=test_domain.id,
            local_part=None,
            webhook_url="https://example.com/old",
            is_enabled=True,
            deleted_at=datetime.now(UTC),
        )
        test_session.add(tombstone)
        await test_session.commit()

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "*",
                "webhook_url": "https://example.com/new",
            },
        )
        assert response.status_code == 201
        assert response.json()["local_part"] is None

    @pytest.mark.asyncio
    async def test_create_named_after_soft_delete(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """A soft-deleted named recipient must not block recreating the local part."""
        tombstone = Recipient(
            domain_id=test_domain.id,
            local_part="sales",
            webhook_url="https://example.com/old",
            is_enabled=True,
            deleted_at=datetime.now(UTC),
        )
        test_session.add(tombstone)
        await test_session.commit()

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={
                "local_part": "sales",
                "webhook_url": "https://example.com/new",
            },
        )
        assert response.status_code == 201
        assert response.json()["local_part"] == "sales"

    @pytest.mark.asyncio
    async def test_update_to_named_local_part_held_by_tombstone(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Updating to a local part held only by a tombstone must succeed."""
        tombstone = Recipient(
            domain_id=test_domain.id,
            local_part="sales",
            webhook_url="https://example.com/old",
            is_enabled=True,
            deleted_at=datetime.now(UTC),
        )
        live = Recipient(
            domain_id=test_domain.id,
            local_part="support",
            webhook_url="https://example.com/live",
            is_enabled=True,
        )
        test_session.add_all([tombstone, live])
        await test_session.commit()
        await test_session.refresh(live)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{live.id}",
            json={"local_part": "sales"},
        )
        assert response.status_code == 200
        assert response.json()["local_part"] == "sales"


class TestRecipientConflictRace:
    """The loser of a concurrent duplicate write must get the pre-check's 409.

    create/update are check-then-flush, so two concurrent requests can both
    pass the duplicate check; the loser then hits a unique index at flush
    time. These tests simulate the loser deterministically by patching the
    pre-check filter to match nothing, which is exactly what the loser's
    stale read saw.
    """

    @pytest_asyncio.fixture
    def losing_precheck(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make the duplicate pre-check see no conflict, as the race's loser does."""
        import fastsmtp.api.recipients as recipients_api

        monkeypatch.setattr(recipients_api, "_conflicting_local_part", lambda local_part: false())

    @pytest.mark.asyncio
    async def test_raced_duplicate_create_returns_409(
        self,
        auth_client: AsyncClient,
        test_domain: Domain,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """A create that loses the race gets 409, not a 500 from the index."""
        await _seed_recipient(test_session, test_domain, "raced")

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={"local_part": "raced", "webhook_url": "https://example.com/other"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={"local_part": "unraced", "webhook_url": "https://example.com/other"},
        )
        assert fresh.status_code == 201

    @pytest.mark.asyncio
    async def test_raced_duplicate_catchall_create_returns_409(
        self,
        auth_client: AsyncClient,
        test_domain: Domain,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """The catch-all index (ix_recipients_domain_catchall) translates too."""
        await _seed_recipient(test_session, test_domain, None)

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={"local_part": "*", "webhook_url": "https://example.com/other"},
        )
        assert response.status_code == 409
        assert "catch-all" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_raced_duplicate_update_returns_409(
        self,
        auth_client: AsyncClient,
        test_domain: Domain,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """An update that loses the race gets 409, not a 500 from the index."""
        await _seed_recipient(test_session, test_domain, "keep")
        target = await _seed_recipient(test_session, test_domain, "target")

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{target.id}",
            json={"local_part": "keep"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]
