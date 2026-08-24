"""Extended tests for recipient API endpoints to improve coverage."""

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.auth import generate_api_key
from fastsmtp.db import soft_delete
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import APIKey, DeliveryLog, Domain, DomainMember, Recipient, User
from httpx import ASGITransport, AsyncClient
from sqlalchemy import false, select
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

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("local_part", "detail"),
        [
            ("phoenix", "Recipient 'phoenix' already exists for this domain"),
            (None, "Recipient 'catch-all (*)' already exists for this domain"),
        ],
        ids=["named", "catch-all"],
    )
    async def test_raced_restore_returns_409(
        self,
        auth_client: AsyncClient,
        test_domain: Domain,
        test_session: AsyncSession,
        losing_precheck: None,
        local_part: str | None,
        detail: str,
    ):
        """A restore that loses the race to a re-created local part hits the index -> 409.

        Both partial unique indexes (``uq_recipient_local_part`` and
        ``ix_recipients_domain_catchall``) only cover live rows, so clearing
        the tombstone while a live row holds the local part is the violation.
        """
        old = await _seed_recipient(test_session, test_domain, local_part)
        await soft_delete.soft_delete_recipient(test_session, old)
        await test_session.commit()
        await _seed_recipient(test_session, test_domain, local_part)

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients/{old.id}/restore"
        )
        assert response.status_code == 409
        assert response.json()["detail"] == detail

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={"local_part": "unraced", "webhook_url": "https://example.com/other"},
        )
        assert fresh.status_code == 201


ClientFor = Callable[[str], Awaitable[AsyncClient]]


async def _seed_delivery(
    session: AsyncSession, domain: Domain, recipient: Recipient, status: str
) -> DeliveryLog:
    """Insert a committed delivery-log row for ``recipient`` in ``status``."""
    delivery = DeliveryLog(
        domain_id=domain.id,
        recipient_id=recipient.id,
        message_id=f"<{uuid.uuid4()}@example.com>",
        webhook_url=recipient.webhook_url,
        payload_hash="abc123",
        payload={},
        status=status,
        attempts=1,
        next_retry_at=datetime.now(UTC) - timedelta(minutes=1),
        instance_id="test-instance",
    )
    session.add(delivery)
    await session.commit()
    await session.refresh(delivery)
    return delivery


class TestRecipientSoftDelete:
    """DELETE tombstones, restore clears it, purge is the old hard delete on a tombstone.

    Spec 4.4: reads hide tombstones unless ``include_deleted`` (admin-gated up
    front), restore needs a live domain and a free local part, purge is
    superuser-only and only reachable on a tombstone.
    """

    @pytest_asyncio.fixture
    async def client_for(
        self, app: FastAPI, test_session: AsyncSession, test_domain: Domain
    ) -> AsyncIterator[ClientFor]:
        """Build a non-superuser client holding ``role`` on ``test_domain``.

        The key carries the recipient scopes, so any 403 is about role, not
        scope.
        """
        clients: list[AsyncClient] = []

        async def make(role: str) -> AsyncClient:
            user = User(username=f"{role}-user", is_active=True)
            test_session.add(user)
            await test_session.flush()
            test_session.add(DomainMember(domain_id=test_domain.id, user_id=user.id, role=role))
            full_key, key_prefix, key_hash, key_salt = generate_api_key()
            test_session.add(
                APIKey(
                    user_id=user.id,
                    key_hash=key_hash,
                    key_salt=key_salt,
                    key_prefix=key_prefix,
                    name=f"{role} key",
                    scopes=["recipients:read", "recipients:write"],
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
    async def recipient(self, test_session: AsyncSession, test_domain: Domain) -> Recipient:
        return await _seed_recipient(test_session, test_domain, "sales")

    @pytest_asyncio.fixture
    async def deleted_recipient(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        recipient: Recipient,
    ) -> Recipient:
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 200
        await test_session.refresh(recipient)
        assert recipient.deleted_at is not None
        return recipient

    @pytest_asyncio.fixture
    async def tombstoned_domain(
        self, test_session: AsyncSession, test_domain: Domain, recipient: Recipient
    ) -> Domain:
        """``test_domain`` soft-deleted through the service, ``recipient`` stamped with it."""
        await soft_delete.soft_delete_domain(test_session, test_domain)
        await test_session.commit()
        await test_session.refresh(test_domain)
        return test_domain

    # -- delete -------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_delete_tombstones_and_keeps_message(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        recipient: Recipient,
    ):
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Recipient 'sales' deleted"

        await test_session.refresh(recipient)
        assert recipient.deleted_at is not None

    @pytest.mark.asyncio
    async def test_delete_tombstone_again_is_404(
        self, auth_client: AsyncClient, test_domain: Domain, deleted_recipient: Recipient
    ):
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}"
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Recipient not found"

    @pytest.mark.asyncio
    async def test_delete_cancels_queued_deliveries_only(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        recipient: Recipient,
    ):
        """Pending/failed rows become ``cancelled``; history and other recipients are untouched.

        The rows keep ``recipient_id`` - a soft delete never severs history.
        """
        other = await _seed_recipient(test_session, test_domain, "support")
        rows = {
            status: await _seed_delivery(test_session, test_domain, recipient, status)
            for status in (
                DeliveryStatus.PENDING,
                DeliveryStatus.FAILED,
                DeliveryStatus.DELIVERED,
                DeliveryStatus.EXHAUSTED,
            )
        }
        other_pending = await _seed_delivery(
            test_session, test_domain, other, DeliveryStatus.PENDING
        )

        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 200

        for row in (*rows.values(), other_pending):
            await test_session.refresh(row)
        assert rows[DeliveryStatus.PENDING].status == DeliveryStatus.CANCELLED
        assert rows[DeliveryStatus.FAILED].status == DeliveryStatus.CANCELLED
        assert rows[DeliveryStatus.FAILED].last_error == "Recipient deleted"
        assert rows[DeliveryStatus.FAILED].next_retry_at is None
        assert rows[DeliveryStatus.DELIVERED].status == DeliveryStatus.DELIVERED
        assert rows[DeliveryStatus.EXHAUSTED].status == DeliveryStatus.EXHAUSTED
        assert other_pending.status == DeliveryStatus.PENDING
        assert all(row.recipient_id == recipient.id for row in rows.values())

    @pytest.mark.asyncio
    async def test_delete_under_tombstoned_domain_is_404(
        self, auth_client: AsyncClient, tombstoned_domain: Domain, recipient: Recipient
    ):
        response = await auth_client.delete(
            f"/api/v1/domains/{tombstoned_domain.id}/recipients/{recipient.id}"
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Domain not found"

    # -- reads --------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_hides_tombstone_unless_include_deleted(
        self, auth_client: AsyncClient, test_domain: Domain, deleted_recipient: Recipient
    ):
        url = f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}"
        response = await auth_client.get(url)
        assert response.status_code == 404
        assert response.json()["detail"] == "Recipient not found"

        response = await auth_client.get(url, params={"include_deleted": "true"})
        assert response.status_code == 200
        assert response.json()["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_list_hides_tombstone_unless_include_deleted(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        deleted_recipient: Recipient,
    ):
        await _seed_recipient(test_session, test_domain, "support")
        url = f"/api/v1/domains/{test_domain.id}/recipients"

        response = await auth_client.get(url)
        assert response.status_code == 200
        assert [r["local_part"] for r in response.json()] == ["support"]

        response = await auth_client.get(url, params={"include_deleted": "true"})
        assert response.status_code == 200
        rows = {r["local_part"]: r for r in response.json()}
        assert set(rows) == {"sales", "support"}
        assert rows["sales"]["deleted_at"] is not None
        assert rows["support"]["deleted_at"] is None

    @pytest.mark.asyncio
    async def test_update_tombstone_is_404(
        self, auth_client: AsyncClient, test_domain: Domain, deleted_recipient: Recipient
    ):
        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}",
            json={"webhook_url": "https://example.com/new"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_include_deleted_is_admin_gated(
        self, client_for: ClientFor, test_domain: Domain, deleted_recipient: Recipient
    ):
        """A member may read live rows but the flag needs admin, tombstone or not."""
        member = await client_for("member")
        admin = await client_for("admin")
        urls = (
            f"/api/v1/domains/{test_domain.id}/recipients",
            f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}",
            f"/api/v1/domains/{test_domain.id}/recipients/{uuid.uuid4()}",
        )
        for url in urls:
            response = await member.get(url, params={"include_deleted": "true"})
            assert response.status_code == 403, url
            assert response.json()["detail"] == "Requires admin role or higher"

        assert (await member.get(urls[0])).status_code == 200
        response = await admin.get(urls[1], params={"include_deleted": "true"})
        assert response.status_code == 200
        assert response.json()["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_include_deleted_audits_tombstoned_domain_for_owner_only(
        self,
        auth_client: AsyncClient,
        client_for: ClientFor,
        tombstoned_domain: Domain,
        recipient: Recipient,
    ):
        """Recipients of a tombstoned domain can be audited before restore - by owners.

        The domain is resolved with the same flag, so the helper's tombstone
        gate applies: superuser and owner see it, an admin gets the same 404
        as for a domain that never existed.
        """
        url = f"/api/v1/domains/{tombstoned_domain.id}/recipients"
        params = {"include_deleted": "true"}

        assert (await auth_client.get(url)).status_code == 404
        response = await auth_client.get(url, params=params)
        assert response.status_code == 200
        assert [r["local_part"] for r in response.json()] == ["sales"]
        assert response.json()[0]["deleted_at"] is not None

        owner = await client_for("owner")
        assert (await owner.get(url, params=params)).status_code == 200

        admin = await client_for("admin")
        response = await admin.get(url, params=params)
        assert response.status_code == 404
        assert response.json()["detail"] == "Domain not found"

    # -- restore ------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restore_clears_tombstone(
        self, auth_client: AsyncClient, test_domain: Domain, deleted_recipient: Recipient
    ):
        url = f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}"
        response = await auth_client.post(f"{url}/restore")
        assert response.status_code == 200
        body = response.json()
        assert body["id"] == str(deleted_recipient.id)
        assert body["deleted_at"] is None

        response = await auth_client.get(url)
        assert response.status_code == 200
        assert response.json()["deleted_at"] is None

    @pytest.mark.asyncio
    async def test_restore_leaves_cancelled_deliveries_alone(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        recipient: Recipient,
    ):
        """Re-queuing is the explicit retry endpoint's job, never restore's."""
        pending = await _seed_delivery(test_session, test_domain, recipient, DeliveryStatus.PENDING)
        url = f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"
        assert (await auth_client.delete(url)).status_code == 200
        assert (await auth_client.post(f"{url}/restore")).status_code == 200

        await test_session.refresh(pending)
        assert pending.status == DeliveryStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_restore_live_is_409(
        self, auth_client: AsyncClient, test_domain: Domain, recipient: Recipient
    ):
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}/restore"
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "Recipient is not deleted"

    @pytest.mark.asyncio
    async def test_restore_unknown_is_404(self, auth_client: AsyncClient, test_domain: Domain):
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients/{uuid.uuid4()}/restore"
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Recipient not found"

    @pytest.mark.asyncio
    async def test_restore_retaken_named_local_part_is_409(
        self, auth_client: AsyncClient, test_domain: Domain, deleted_recipient: Recipient
    ):
        created = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={"local_part": "sales", "webhook_url": "https://example.com/new"},
        )
        assert created.status_code == 201

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}/restore"
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "Recipient 'sales' already exists for this domain"

    @pytest.mark.asyncio
    async def test_restore_retaken_catchall_is_409(
        self, auth_client: AsyncClient, test_session: AsyncSession, test_domain: Domain
    ):
        old = await _seed_recipient(test_session, test_domain, None)
        url = f"/api/v1/domains/{test_domain.id}/recipients/{old.id}"
        assert (await auth_client.delete(url)).status_code == 200
        created = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/recipients",
            json={"local_part": "*", "webhook_url": "https://example.com/new"},
        )
        assert created.status_code == 201

        response = await auth_client.post(f"{url}/restore")
        assert response.status_code == 409
        assert (
            response.json()["detail"] == "Recipient 'catch-all (*)' already exists for this domain"
        )

    @pytest.mark.asyncio
    async def test_restore_under_tombstoned_domain_is_404(
        self, auth_client: AsyncClient, tombstoned_domain: Domain, recipient: Recipient
    ):
        """Restore the domain first; a recipient cannot come back into a tombstone."""
        response = await auth_client.post(
            f"/api/v1/domains/{tombstoned_domain.id}/recipients/{recipient.id}/restore"
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Domain not found"

    @pytest.mark.asyncio
    async def test_restore_permissions_mirror_delete(
        self, client_for: ClientFor, test_domain: Domain, deleted_recipient: Recipient
    ):
        url = f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}/restore"
        member = await client_for("member")
        response = await member.post(url)
        assert response.status_code == 403
        assert response.json()["detail"] == "Requires admin role or higher"

        admin = await client_for("admin")
        response = await admin.post(url)
        assert response.status_code == 200
        assert response.json()["deleted_at"] is None

    # -- purge --------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_purge_live_is_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        recipient: Recipient,
    ):
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}",
            params={"purge": "true"},
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "Recipient must be deleted before it can be purged"

        await test_session.refresh(recipient)
        assert recipient.deleted_at is None

    @pytest.mark.asyncio
    async def test_purge_below_superuser_is_403_regardless_of_state(
        self,
        client_for: ClientFor,
        test_session: AsyncSession,
        test_domain: Domain,
        recipient: Recipient,
    ):
        """A domain admin can soft-delete but never purge - live or tombstoned."""
        admin = await client_for("admin")
        url = f"/api/v1/domains/{test_domain.id}/recipients/{recipient.id}"

        response = await admin.delete(url, params={"purge": "true"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Superuser access required"

        assert (await admin.delete(url)).status_code == 200
        response = await admin.delete(url, params={"purge": "true"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Superuser access required"

        await test_session.refresh(recipient)
        assert recipient.deleted_at is not None

    @pytest.mark.asyncio
    async def test_purge_tombstone_removes_row_and_orphans_history(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        test_domain: Domain,
        deleted_recipient: Recipient,
    ):
        """Purge is the v0.4.0 hard delete: the row goes, delivery logs get SET NULL."""
        delivered = await _seed_delivery(
            test_session, test_domain, deleted_recipient, DeliveryStatus.DELIVERED
        )
        url = f"/api/v1/domains/{test_domain.id}/recipients/{deleted_recipient.id}"

        response = await auth_client.delete(url, params={"purge": "true"})
        assert response.status_code == 200
        assert response.json()["message"] == "Recipient 'sales' purged"

        assert (
            await test_session.execute(
                select(Recipient).where(Recipient.id == deleted_recipient.id)
            )
        ).scalar_one_or_none() is None
        await test_session.refresh(delivered)
        assert delivered.recipient_id is None
        assert delivered.domain_id == test_domain.id

        response = await auth_client.get(url, params={"include_deleted": "true"})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_purge_under_tombstoned_domain(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        tombstoned_domain: Domain,
        recipient: Recipient,
    ):
        """A superuser may purge a recipient stamped by its domain's tombstone."""
        response = await auth_client.delete(
            f"/api/v1/domains/{tombstoned_domain.id}/recipients/{recipient.id}",
            params={"purge": "true"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Recipient 'sales' purged"
        assert (
            await test_session.execute(select(Recipient).where(Recipient.id == recipient.id))
        ).scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_purge_unknown_is_404(self, auth_client: AsyncClient, test_domain: Domain):
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/recipients/{uuid.uuid4()}",
            params={"purge": "true"},
        )
        assert response.status_code == 404
