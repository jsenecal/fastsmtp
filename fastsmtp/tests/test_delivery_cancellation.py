"""Queue-level delivery cancellation for soft-deleted recipients and domains.

A soft-deleted recipient keeps its row, so without these checks a queued
delivery would keep going out - with the recipient's authentication headers -
for the whole retry window. Three layers close that: delete-time cancellation
(``cancel_pending_deliveries``), claim-time exclusion (``get_pending_deliveries``
never hands out a delivery whose recipient or domain is tombstoned), and the
sticky ``cancelled`` status that ``mark_failed`` / ``mark_delivered`` refuse to
overwrite. The dispatcher's own guard is tested in test_webhook.py.

The claim-query tests run against the PostgreSQL testcontainer on purpose:
``get_pending_deliveries`` uses ``FOR UPDATE SKIP LOCKED``, which PostgreSQL
rejects on the nullable side of an outer join, so the tombstone exclusions
have to be shaped in a way the real engine accepts.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastsmtp.config import Settings
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog, Domain, Recipient
from fastsmtp.webhook import queue
from fastsmtp.webhook.queue import (
    cancel_pending_deliveries,
    get_pending_count,
    get_pending_deliveries,
    mark_cancelled,
    mark_delivered,
    mark_failed,
    retry_delivery,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)


async def make_domain(session: AsyncSession, name: str, **fields: object) -> Domain:
    domain = Domain(domain_name=name, **fields)
    session.add(domain)
    await session.flush()
    return domain


async def make_recipient(
    session: AsyncSession, domain: Domain, local_part: str, **fields: object
) -> Recipient:
    recipient = Recipient(
        domain_id=domain.id,
        local_part=local_part,
        webhook_url="https://example.com/hook",
        webhook_headers={"Authorization": "Bearer secret"},
        **fields,
    )
    session.add(recipient)
    await session.flush()
    return recipient


async def make_delivery(
    session: AsyncSession,
    domain: Domain,
    recipient: Recipient | None,
    status: DeliveryStatus = DeliveryStatus.PENDING,
    *,
    attempts: int = 0,
) -> DeliveryLog:
    delivery = DeliveryLog(
        domain_id=domain.id,
        recipient_id=recipient.id if recipient else None,
        message_id=f"<{uuid.uuid4()}@example.com>",
        webhook_url="https://example.com/hook",
        payload_hash="abc123",
        payload={},
        status=status,
        attempts=attempts,
        next_retry_at=datetime.now(UTC) - timedelta(minutes=1),
        instance_id="test-instance",
    )
    session.add(delivery)
    await session.flush()
    return delivery


async def statuses(session: AsyncSession, *deliveries: DeliveryLog) -> list[str]:
    for delivery in deliveries:
        await session.refresh(delivery)
    return [delivery.status for delivery in deliveries]


class TestCancelPendingDeliveries:
    @pytest.mark.asyncio
    async def test_by_recipient_ids_touches_only_pending_and_failed(
        self, test_session: AsyncSession
    ):
        domain = await make_domain(test_session, "cancel.com")
        sales = await make_recipient(test_session, domain, "sales")
        support = await make_recipient(test_session, domain, "support")
        pending = await make_delivery(test_session, domain, sales, DeliveryStatus.PENDING)
        failed = await make_delivery(test_session, domain, sales, DeliveryStatus.FAILED)
        delivered = await make_delivery(test_session, domain, sales, DeliveryStatus.DELIVERED)
        exhausted = await make_delivery(test_session, domain, sales, DeliveryStatus.EXHAUSTED)
        other = await make_delivery(test_session, domain, support, DeliveryStatus.PENDING)

        count = await cancel_pending_deliveries(
            test_session, recipient_ids=[sales.id], reason="Recipient deleted", now=NOW
        )

        assert count == 2
        assert await statuses(test_session, pending, failed, delivered, exhausted, other) == [
            "cancelled",
            "cancelled",
            "delivered",
            "exhausted",
            "pending",
        ]
        for row in (pending, failed):
            assert row.next_retry_at is None
            assert row.last_error == "Recipient deleted"
            assert row.updated_at == NOW
        assert delivered.last_error is None

    @pytest.mark.asyncio
    async def test_by_domain_covers_legacy_rows_without_a_recipient(
        self, test_session: AsyncSession
    ):
        """Rows whose recipient_id was nulled by a pre-0.5 hard delete still carry
        the domain, and go with it."""
        domain = await make_domain(test_session, "cancel-domain.com")
        other_domain = await make_domain(test_session, "untouched.com")
        sales = await make_recipient(test_session, domain, "sales")
        with_recipient = await make_delivery(test_session, domain, sales)
        legacy = await make_delivery(test_session, domain, None, DeliveryStatus.FAILED)
        elsewhere = await make_delivery(test_session, other_domain, None)

        count = await cancel_pending_deliveries(
            test_session, domain_id=domain.id, reason="Domain deleted", now=NOW
        )

        assert count == 2
        assert await statuses(test_session, with_recipient, legacy, elsewhere) == [
            "cancelled",
            "cancelled",
            "pending",
        ]
        assert legacy.last_error == "Domain deleted"

    @pytest.mark.asyncio
    async def test_with_nothing_to_target_touches_nothing(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "no-target.com")
        delivery = await make_delivery(test_session, domain, None)

        count = await cancel_pending_deliveries(test_session, reason="nothing", now=NOW)

        assert count == 0
        assert await statuses(test_session, delivery) == ["pending"]


class TestClaimQuerySkipsTombstones:
    """S10: the claim query is the second layer. Postgres-backed (FOR UPDATE SKIP LOCKED)."""

    @pytest_asyncio.fixture
    async def fixture_rows(self, test_session: AsyncSession) -> dict[str, DeliveryLog]:
        live_domain = await make_domain(test_session, "live.com")
        dead_domain = await make_domain(test_session, "dead.com", deleted_at=NOW)
        live_recipient = await make_recipient(test_session, live_domain, "live")
        dead_recipient = await make_recipient(test_session, live_domain, "dead", deleted_at=NOW)
        orphaned_recipient = await make_recipient(test_session, dead_domain, "orphan")
        rows = {
            "live": await make_delivery(test_session, live_domain, live_recipient),
            "dead_recipient": await make_delivery(test_session, live_domain, dead_recipient),
            "dead_domain": await make_delivery(test_session, dead_domain, orphaned_recipient),
            "legacy_live_domain": await make_delivery(test_session, live_domain, None),
            "legacy_dead_domain": await make_delivery(test_session, dead_domain, None),
        }
        await test_session.commit()
        return rows

    @pytest.mark.asyncio
    async def test_claims_only_deliveries_with_live_recipient_and_domain(
        self, test_session: AsyncSession, fixture_rows: dict[str, DeliveryLog]
    ):
        claimed = await get_pending_deliveries(test_session, batch_size=10, instance_id="w1")
        await test_session.commit()

        assert {d.id for d in claimed} == {
            fixture_rows["live"].id,
            fixture_rows["legacy_live_domain"].id,
        }
        # Only the claimed rows were stamped with the instance id.
        for name, row in fixture_rows.items():
            await test_session.refresh(row)
            expected = "w1" if name in ("live", "legacy_live_domain") else "test-instance"
            assert row.instance_id == expected, name

    @pytest.mark.asyncio
    async def test_claimed_deliveries_carry_the_recipient_domain(
        self, test_session: AsyncSession, fixture_rows: dict[str, DeliveryLog]
    ):
        """The dispatcher guard reads ``delivery.recipient.domain.is_deleted``;
        ``DeliveryLog.recipient`` is ``lazy="raise"`` and an unloaded
        ``Recipient.domain`` would need a lazy load the worker cannot do."""
        claimed = await get_pending_deliveries(test_session, batch_size=10, instance_id="w1")
        await test_session.commit()

        by_id = {d.id: d for d in claimed}
        live = by_id[fixture_rows["live"].id]
        assert live.recipient is not None
        assert live.recipient.domain.domain_name == "live.com"
        assert by_id[fixture_rows["legacy_live_domain"].id].recipient is None

    @pytest.mark.asyncio
    async def test_skip_locked_still_applies(
        self,
        test_engine: AsyncEngine,
        test_session: AsyncSession,
        fixture_rows: dict[str, DeliveryLog],
    ):
        """Another worker holding a row lock must not block or receive that row.

        Proves the tombstone exclusions did not disturb ``FOR UPDATE SKIP
        LOCKED`` - the reason this file runs against PostgreSQL.
        """
        locker = async_sessionmaker(test_engine, class_=AsyncSession)()
        try:
            held = await locker.execute(
                select(DeliveryLog)
                .where(DeliveryLog.id == fixture_rows["live"].id)
                .with_for_update()
            )
            assert held.scalar_one().id == fixture_rows["live"].id

            claimed = await get_pending_deliveries(test_session, batch_size=10, instance_id="w2")
            await test_session.commit()
        finally:
            await locker.rollback()
            await locker.close()

        assert [d.id for d in claimed] == [fixture_rows["legacy_live_domain"].id]


class TestCancelledIsSticky:
    """S13: a delivery claimed just before the tombstone landed must stay cancelled."""

    @pytest.mark.asyncio
    async def test_mark_failed_does_not_overwrite_cancelled_nor_notify_dlq(
        self, test_session: AsyncSession, test_settings: Settings, monkeypatch
    ):
        domain = await make_domain(test_session, "sticky.com")
        delivery = await make_delivery(
            test_session,
            domain,
            None,
            DeliveryStatus.CANCELLED,
            attempts=test_settings.webhook_max_retries - 1,
        )
        delivery.last_error = "Recipient deleted"
        await test_session.flush()
        dlq = AsyncMock()
        monkeypatch.setattr(queue, "_send_dlq_notification", dlq)
        settings = test_settings.model_copy(update={"dlq_webhook_url": "https://dlq.example.com"})

        await mark_failed(test_session, delivery.id, "Connection refused", 503, settings=settings)

        await test_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.CANCELLED
        assert delivery.attempts == test_settings.webhook_max_retries - 1
        assert delivery.last_error == "Recipient deleted"
        assert delivery.last_status_code is None
        dlq.assert_not_called()

    @pytest.mark.asyncio
    async def test_mark_failed_after_a_concurrent_cancel_stays_cancelled_and_skips_dlq(
        self,
        test_engine: AsyncEngine,
        test_session: AsyncSession,
        test_settings: Settings,
        monkeypatch,
    ):
        """The claimed-then-cancelled race: the worker's session still holds the
        row as pending (a select() does not refresh the identity map), so only
        the guarded UPDATE can tell. It must match nothing, and the DLQ must stay
        quiet even though this attempt would have exhausted the delivery."""
        domain = await make_domain(test_session, "race.com")
        delivery = await make_delivery(
            test_session,
            domain,
            None,
            DeliveryStatus.PENDING,
            attempts=test_settings.webhook_max_retries - 1,
        )
        await test_session.commit()

        other = async_sessionmaker(test_engine, class_=AsyncSession)()
        try:
            await mark_cancelled(other, delivery.id, "Recipient deleted")
            await other.commit()
        finally:
            await other.close()
        assert delivery.status == DeliveryStatus.PENDING  # stale in this session, on purpose

        dlq = AsyncMock()
        monkeypatch.setattr(queue, "_send_dlq_notification", dlq)
        settings = test_settings.model_copy(update={"dlq_webhook_url": "https://dlq.example.com"})

        await mark_failed(test_session, delivery.id, "Connection refused", 503, settings=settings)
        await test_session.commit()

        await test_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.CANCELLED
        assert delivery.attempts == test_settings.webhook_max_retries - 1
        assert delivery.last_error == "Recipient deleted"
        dlq.assert_not_called()

    @pytest.mark.asyncio
    async def test_mark_delivered_does_not_overwrite_cancelled(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "sticky-delivered.com")
        delivery = await make_delivery(test_session, domain, None, DeliveryStatus.CANCELLED)

        await mark_delivered(test_session, delivery.id)

        await test_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.CANCELLED
        assert delivery.delivered_at is None

    @pytest.mark.asyncio
    async def test_mark_cancelled_writes_the_same_shape_as_bulk_cancellation(
        self, test_session: AsyncSession
    ):
        domain = await make_domain(test_session, "mark-cancelled.com")
        delivery = await make_delivery(test_session, domain, None, DeliveryStatus.PENDING)
        before = datetime.now(UTC)

        await mark_cancelled(test_session, delivery.id, "Recipient deleted")

        await test_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.CANCELLED
        assert delivery.next_retry_at is None
        assert delivery.last_error == "Recipient deleted"
        assert delivery.updated_at >= before


class TestRetryAndCounts:
    @pytest.mark.asyncio
    async def test_retry_delivery_accepts_cancelled(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "retry-cancelled.com")
        delivery = await make_delivery(test_session, domain, None, DeliveryStatus.CANCELLED)
        delivery.next_retry_at = None
        await test_session.flush()

        result = await retry_delivery(test_session, delivery.id)

        assert result is not None
        await test_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.PENDING
        assert delivery.next_retry_at is not None

    @pytest.mark.asyncio
    async def test_pending_count_ignores_cancelled(self, test_session: AsyncSession):
        """Backpressure drops the moment a delete cancels the queue."""
        domain = await make_domain(test_session, "count.com")
        await make_delivery(test_session, domain, None, DeliveryStatus.PENDING)
        await make_delivery(test_session, domain, None, DeliveryStatus.FAILED)
        await make_delivery(test_session, domain, None, DeliveryStatus.CANCELLED)

        assert await get_pending_count(test_session) == 2
