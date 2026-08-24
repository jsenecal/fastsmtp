"""Tests for the cleanup package: delivery-log cleanup, soft-delete purge, worker."""

import asyncio
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastsmtp.config import Settings
from fastsmtp.db.models import (
    APIKey,
    DeliveryLog,
    Domain,
    DomainMember,
    Recipient,
    Rule,
    RuleSet,
    User,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from typer.testing import CliRunner

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")

# ANSI escape code pattern for stripping colors from CLI output
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return ANSI_ESCAPE.sub("", text)


class TestCleanupSettings:
    """Tests for cleanup configuration settings."""

    def test_default_retention_days(self):
        """Test default retention is 90 days."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_retention_days == 90

    def test_default_cleanup_interval(self):
        """Test default cleanup interval is 24 hours."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_interval_hours == 24

    def test_default_cleanup_enabled(self):
        """Test cleanup is enabled by default."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_enabled is True

    def test_default_cleanup_batch_size(self):
        """Test default batch size is 1000."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_batch_size == 1000

    def test_retention_days_from_env(self, monkeypatch):
        """Test retention days can be set via environment."""
        monkeypatch.setenv("FASTSMTP_DELIVERY_LOG_RETENTION_DAYS", "30")

        # No reload: pydantic-settings reads the environment when a Settings
        # instance is constructed. Reloading fastsmtp.config would rebind
        # get_settings to a new function object, so every module that imported
        # it keeps the old one and FastAPI dependency_overrides stop matching -
        # silently, in whichever test module happens to run next.
        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_retention_days == 30

    def test_cleanup_can_be_disabled(self, monkeypatch):
        """Test cleanup can be disabled via environment."""
        monkeypatch.setenv("FASTSMTP_DELIVERY_LOG_CLEANUP_ENABLED", "false")

        # No reload: pydantic-settings reads the environment when a Settings
        # instance is constructed. Reloading fastsmtp.config would rebind
        # get_settings to a new function object, so every module that imported
        # it keeps the old one and FastAPI dependency_overrides stop matching -
        # silently, in whichever test module happens to run next.
        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_enabled is False


class TestCleanupResult:
    """Tests for CleanupResult dataclass."""

    def test_cleanup_result_creation(self):
        """Test CleanupResult can be created with all fields."""
        from fastsmtp.cleanup.service import CleanupResult

        cutoff = datetime.now(UTC)
        result = CleanupResult(
            deleted_count=100,
            dry_run=False,
            cutoff_date=cutoff,
        )

        assert result.deleted_count == 100
        assert result.dry_run is False
        assert result.cutoff_date == cutoff

    def test_cleanup_result_dry_run(self):
        """Test CleanupResult with dry_run=True."""
        from fastsmtp.cleanup.service import CleanupResult

        result = CleanupResult(
            deleted_count=50,
            dry_run=True,
            cutoff_date=datetime.now(UTC),
        )

        assert result.dry_run is True


class TestDeliveryLogCleanupService:
    """Tests for DeliveryLogCleanupService."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="cleanup-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()
        return domain

    @pytest_asyncio.fixture
    async def old_deliveries(
        self, test_session: AsyncSession, test_domain: Domain
    ) -> list[DeliveryLog]:
        """Create old delivery logs (older than 90 days)."""
        deliveries = []
        old_date = datetime.now(UTC) - timedelta(days=100)

        for i in range(5):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<old{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="abc123",
                payload={"index": i},
                status="delivered",
                attempts=1,
                instance_id="test-instance",
            )
            test_session.add(delivery)
            deliveries.append(delivery)

        await test_session.flush()

        # Manually set created_at to old date (bypassing server_default)
        for delivery in deliveries:
            await test_session.execute(
                DeliveryLog.__table__.update()
                .where(DeliveryLog.id == delivery.id)
                .values(created_at=old_date)
            )
        await test_session.commit()

        return deliveries

    @pytest_asyncio.fixture
    async def recent_deliveries(
        self, test_session: AsyncSession, test_domain: Domain
    ) -> list[DeliveryLog]:
        """Create recent delivery logs (within retention period)."""
        deliveries = []

        for i in range(3):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<recent{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="def456",
                payload={"index": i},
                status="delivered",
                attempts=1,
                instance_id="test-instance",
            )
            test_session.add(delivery)
            deliveries.append(delivery)

        await test_session.flush()
        return deliveries

    @pytest.mark.asyncio
    async def test_cleanup_dry_run_counts_without_deleting(
        self,
        test_session: AsyncSession,
        test_settings: Settings,
        test_domain: Domain,
        old_deliveries: list[DeliveryLog],
        recent_deliveries: list[DeliveryLog],
    ):
        """Test dry run counts records but doesn't delete them."""
        from fastsmtp.cleanup.service import DeliveryLogCleanupService
        from sqlalchemy import select

        service = DeliveryLogCleanupService(test_settings, test_session)
        result = await service.cleanup(dry_run=True)

        assert result.dry_run is True
        assert result.deleted_count == 5  # Only old deliveries

        # Verify nothing was actually deleted
        stmt = select(DeliveryLog)
        db_result = await test_session.execute(stmt)
        all_deliveries = db_result.scalars().all()
        assert len(all_deliveries) == 8  # 5 old + 3 recent

    @pytest.mark.asyncio
    async def test_cleanup_deletes_old_records(
        self,
        test_session: AsyncSession,
        test_settings: Settings,
        test_domain: Domain,
        old_deliveries: list[DeliveryLog],
        recent_deliveries: list[DeliveryLog],
    ):
        """Test cleanup deletes old records and keeps recent ones."""
        from fastsmtp.cleanup.service import DeliveryLogCleanupService
        from sqlalchemy import select

        service = DeliveryLogCleanupService(test_settings, test_session)
        result = await service.cleanup(dry_run=False)

        assert result.dry_run is False
        assert result.deleted_count == 5

        # Verify old deliveries were deleted
        stmt = select(DeliveryLog)
        db_result = await test_session.execute(stmt)
        remaining = db_result.scalars().all()
        assert len(remaining) == 3  # Only recent deliveries remain

        # Verify the remaining ones are the recent ones
        remaining_ids = {d.id for d in remaining}
        recent_ids = {d.id for d in recent_deliveries}
        assert remaining_ids == recent_ids

    @pytest.mark.asyncio
    async def test_cleanup_respects_batch_size(
        self,
        test_session: AsyncSession,
        test_domain: Domain,
        old_deliveries: list[DeliveryLog],
    ):
        """Test cleanup processes in batches."""
        from fastsmtp.cleanup.service import DeliveryLogCleanupService

        # Create settings with small batch size
        settings = Settings(
            root_api_key="test123",
            delivery_log_cleanup_batch_size=2,
        )

        service = DeliveryLogCleanupService(settings, test_session)
        result = await service.cleanup(dry_run=False)

        # Should still delete all 5, just in batches of 2
        assert result.deleted_count == 5

    @pytest.mark.asyncio
    async def test_cleanup_with_custom_retention_days(
        self,
        test_session: AsyncSession,
        test_settings: Settings,
        test_domain: Domain,
    ):
        """Test cleanup with custom retention period."""
        from fastsmtp.cleanup.service import DeliveryLogCleanupService
        from sqlalchemy import select

        # Create deliveries at different ages
        now = datetime.now(UTC)
        ages = [10, 20, 40, 60]  # days old

        for i, days in enumerate(ages):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<age{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="abc123",
                payload={},
                status="delivered",
                attempts=1,
                instance_id="test-instance",
            )
            test_session.add(delivery)
            await test_session.flush()

            old_date = now - timedelta(days=days)
            await test_session.execute(
                DeliveryLog.__table__.update()
                .where(DeliveryLog.id == delivery.id)
                .values(created_at=old_date)
            )

        await test_session.commit()

        service = DeliveryLogCleanupService(test_settings, test_session)

        # Delete records older than 30 days
        result = await service.cleanup(dry_run=False, retention_days=30)

        assert result.deleted_count == 2  # 40 and 60 days old

        # Verify correct records remain
        stmt = select(DeliveryLog)
        db_result = await test_session.execute(stmt)
        remaining = db_result.scalars().all()
        assert len(remaining) == 2  # 10 and 20 days old


class TestPurgeResult:
    """PurgeResult aggregates the per-table counts."""

    def test_total_and_breakdown(self):
        from fastsmtp.cleanup.purge import PurgeResult

        result = PurgeResult(
            cutoff_date=datetime.now(UTC),
            dry_run=True,
            counts={"recipients": 1, "api_keys": 0, "domains": 2, "users": 3},
        )

        assert result.total == 6
        assert result.breakdown == "recipients=1, api_keys=0, domains=2, users=3"


RETENTION_DAYS = 30
OLD_STAMP = datetime.now(UTC) - timedelta(days=40)
YOUNG_STAMP = datetime.now(UTC) - timedelta(days=5)


@dataclass
class TombstoneGraph:
    """Ids of a fixture graph mixing expired, young and live rows.

    ``old_*`` rows are tombstoned past the retention window, ``young_*`` rows
    inside it, ``live_*`` rows not at all. ``stale_key`` and ``stale_recipient``
    are expired tombstones hanging off *live* parents, so they prove each table
    is purged on its own clock.
    """

    old_user: uuid.UUID
    old_user_key: uuid.UUID
    live_user: uuid.UUID
    live_key: uuid.UUID
    stale_key: uuid.UUID
    old_domain: uuid.UUID
    old_recipient: uuid.UUID
    old_ruleset: uuid.UUID
    old_rule: uuid.UUID
    old_domain_member: uuid.UUID
    live_domain_member: uuid.UUID
    old_delivery: uuid.UUID
    young_domain: uuid.UUID
    young_recipient: uuid.UUID
    live_domain: uuid.UUID
    live_recipient: uuid.UUID
    stale_recipient: uuid.UUID
    stale_delivery: uuid.UUID


async def _count(session: AsyncSession, model: type, *criteria) -> int:
    result = await session.execute(select(func.count()).select_from(model).where(*criteria))
    return result.scalar_one()


async def _exists(session: AsyncSession, model: type, row_id: uuid.UUID) -> bool:
    # Query rather than session.get(): a row the database removed by cascade is
    # still in the identity map, and get() would hand it back without a query.
    return await _count(session, model, model.id == row_id) == 1


def _delivery(domain: Domain, recipient: Recipient) -> DeliveryLog:
    return DeliveryLog(
        domain_id=domain.id,
        recipient_id=recipient.id,
        message_id=f"<{uuid.uuid4()}@example.com>",
        webhook_url="https://example.com/hook",
        payload_hash="abc123",
        payload={},
        status="delivered",
        attempts=1,
        instance_id="test-instance",
    )


def _key(user: User, name: str, **fields: object) -> APIKey:
    return APIKey(
        user_id=user.id,
        key_hash=f"hash-{uuid.uuid4()}",
        key_prefix="fsk_test",
        name=name,
        **fields,
    )


def _recipient(domain: Domain, local_part: str, **fields: object) -> Recipient:
    return Recipient(
        domain_id=domain.id,
        local_part=local_part,
        webhook_url="https://example.com/hook",
        **fields,
    )


@pytest_asyncio.fixture
async def graph(test_session: AsyncSession) -> TombstoneGraph:
    old_user = User(username="old-user", deleted_at=OLD_STAMP)
    live_user = User(username="live-user")
    old_domain = Domain(domain_name="old.com", deleted_at=OLD_STAMP)
    young_domain = Domain(domain_name="young.com", deleted_at=YOUNG_STAMP)
    live_domain = Domain(domain_name="live.com")
    test_session.add_all([old_user, live_user, old_domain, young_domain, live_domain])
    await test_session.flush()

    old_user_key = _key(old_user, "old", deleted_at=OLD_STAMP, is_active=False)
    live_key = _key(live_user, "live")
    stale_key = _key(live_user, "stale", deleted_at=OLD_STAMP, is_active=False)
    old_recipient = _recipient(old_domain, "sales", deleted_at=OLD_STAMP)
    young_recipient = _recipient(young_domain, "sales", deleted_at=YOUNG_STAMP)
    live_recipient = _recipient(live_domain, "sales")
    stale_recipient = _recipient(live_domain, "stale", deleted_at=OLD_STAMP)
    old_ruleset = RuleSet(domain_id=old_domain.id, name="default")
    old_domain_member = DomainMember(user_id=old_user.id, domain_id=old_domain.id, role="owner")
    live_domain_member = DomainMember(user_id=old_user.id, domain_id=live_domain.id, role="member")
    test_session.add_all(
        [
            old_user_key,
            live_key,
            stale_key,
            old_recipient,
            young_recipient,
            live_recipient,
            stale_recipient,
            old_ruleset,
            old_domain_member,
            live_domain_member,
        ]
    )
    await test_session.flush()

    old_rule = Rule(
        ruleset_id=old_ruleset.id, order=0, field="subject", operator="contains", value="x"
    )
    old_delivery = _delivery(old_domain, old_recipient)
    stale_delivery = _delivery(live_domain, stale_recipient)
    test_session.add_all([old_rule, old_delivery, stale_delivery])
    await test_session.commit()

    return TombstoneGraph(
        old_user=old_user.id,
        old_user_key=old_user_key.id,
        live_user=live_user.id,
        live_key=live_key.id,
        stale_key=stale_key.id,
        old_domain=old_domain.id,
        old_recipient=old_recipient.id,
        old_ruleset=old_ruleset.id,
        old_rule=old_rule.id,
        old_domain_member=old_domain_member.id,
        live_domain_member=live_domain_member.id,
        old_delivery=old_delivery.id,
        young_domain=young_domain.id,
        young_recipient=young_recipient.id,
        live_domain=live_domain.id,
        live_recipient=live_recipient.id,
        stale_recipient=stale_recipient.id,
        stale_delivery=stale_delivery.id,
    )


@pytest.fixture
def purge_settings() -> Settings:
    return Settings(root_api_key="test123", soft_delete_retention_days=RETENTION_DAYS)


EXPIRED_COUNTS = {"recipients": 2, "api_keys": 2, "domains": 1, "users": 1}


class TestSoftDeletePurgeService:
    """Bulk purge of tombstones older than the retention window."""

    @pytest.mark.asyncio
    async def test_dry_run_counts_without_deleting(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        result = await SoftDeletePurgeService(purge_settings, test_session).purge(dry_run=True)

        assert result.dry_run is True
        assert result.counts == EXPIRED_COUNTS
        assert result.total == 6
        assert await _count(test_session, User) == 2
        assert await _count(test_session, APIKey) == 3
        assert await _count(test_session, Domain) == 3
        assert await _count(test_session, Recipient) == 4

    @pytest.mark.asyncio
    async def test_cutoff_is_retention_days_before_now(
        self, test_session: AsyncSession, purge_settings: Settings
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        before = datetime.now(UTC)
        result = await SoftDeletePurgeService(purge_settings, test_session).purge(dry_run=True)
        after = datetime.now(UTC)

        assert result.cutoff_date.tzinfo is not None
        assert before - timedelta(days=RETENTION_DAYS) <= result.cutoff_date
        assert result.cutoff_date <= after - timedelta(days=RETENTION_DAYS)

    @pytest.mark.asyncio
    async def test_purges_only_rows_past_the_cutoff_per_table(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        result = await SoftDeletePurgeService(purge_settings, test_session).purge()

        assert result.dry_run is False
        assert result.counts == EXPIRED_COUNTS
        # Expired tombstones are gone, on every table
        assert not await _exists(test_session, User, graph.old_user)
        assert not await _exists(test_session, APIKey, graph.old_user_key)
        assert not await _exists(test_session, APIKey, graph.stale_key)
        assert not await _exists(test_session, Domain, graph.old_domain)
        assert not await _exists(test_session, Recipient, graph.old_recipient)
        assert not await _exists(test_session, Recipient, graph.stale_recipient)
        # Young tombstones and live rows survive, including the stale rows' live parents
        assert await _exists(test_session, Domain, graph.young_domain)
        assert await _exists(test_session, Recipient, graph.young_recipient)
        assert await _exists(test_session, User, graph.live_user)
        assert await _exists(test_session, APIKey, graph.live_key)
        assert await _exists(test_session, Domain, graph.live_domain)
        assert await _exists(test_session, Recipient, graph.live_recipient)

    @pytest.mark.asyncio
    async def test_purge_survives_a_second_run(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        service = SoftDeletePurgeService(purge_settings, test_session)
        await service.purge()
        result = await service.purge()

        assert result.total == 0
        assert result.counts == {"recipients": 0, "api_keys": 0, "domains": 0, "users": 0}

    @pytest.mark.asyncio
    async def test_domain_purge_cascades_children_and_orphans_history(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        await SoftDeletePurgeService(purge_settings, test_session).purge()

        assert not await _exists(test_session, RuleSet, graph.old_ruleset)
        assert not await _exists(test_session, Rule, graph.old_rule)
        assert not await _exists(test_session, DomainMember, graph.old_domain_member)
        delivery = (
            await test_session.execute(
                select(DeliveryLog).where(DeliveryLog.id == graph.old_delivery)
            )
        ).scalar_one()
        await test_session.refresh(delivery)
        assert delivery.domain_id is None
        assert delivery.recipient_id is None

    @pytest.mark.asyncio
    async def test_user_purge_cascades_keys_and_memberships(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        await SoftDeletePurgeService(purge_settings, test_session).purge()

        assert not await _exists(test_session, APIKey, graph.old_user_key)
        # The membership on the *live* domain went with the user, not the domain
        assert not await _exists(test_session, DomainMember, graph.live_domain_member)
        assert await _exists(test_session, Domain, graph.live_domain)

    @pytest.mark.asyncio
    async def test_recipient_purge_nulls_only_the_recipient_link(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        await SoftDeletePurgeService(purge_settings, test_session).purge()

        delivery = (
            await test_session.execute(
                select(DeliveryLog).where(DeliveryLog.id == graph.stale_delivery)
            )
        ).scalar_one()
        await test_session.refresh(delivery)
        assert delivery.recipient_id is None
        assert delivery.domain_id == graph.live_domain

    @pytest.mark.asyncio
    async def test_retention_override_beats_settings(
        self, test_session: AsyncSession, purge_settings: Settings, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        result = await SoftDeletePurgeService(purge_settings, test_session).purge(retention_days=3)

        assert result.counts == {"recipients": 3, "api_keys": 2, "domains": 2, "users": 1}
        assert not await _exists(test_session, Domain, graph.young_domain)
        assert not await _exists(test_session, Recipient, graph.young_recipient)

    @pytest.mark.asyncio
    async def test_override_works_when_settings_are_unconfigured(
        self, test_session: AsyncSession, graph: TombstoneGraph
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        settings = Settings(root_api_key="test123", soft_delete_retention_days=None)
        result = await SoftDeletePurgeService(settings, test_session).purge(
            dry_run=True, retention_days=RETENTION_DAYS
        )

        assert result.counts == EXPIRED_COUNTS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dry_run", [False, True])
    async def test_raises_when_retention_is_unconfigured(
        self, test_session: AsyncSession, graph: TombstoneGraph, dry_run: bool
    ):
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        settings = Settings(root_api_key="test123", soft_delete_retention_days=None)
        service = SoftDeletePurgeService(settings, test_session)

        with pytest.raises(ValueError, match="soft-delete retention is not configured"):
            await service.purge(dry_run=dry_run)

        # Nothing was touched, not even by a dry run
        assert await _count(test_session, User) == 2
        assert await _count(test_session, Domain) == 3

    @pytest.mark.asyncio
    @pytest.mark.parametrize("retention_days", [0, -1])
    async def test_rejects_an_override_below_one_day(
        self,
        test_session: AsyncSession,
        purge_settings: Settings,
        graph: TombstoneGraph,
        retention_days,
    ):
        """An explicit 0 must not fall back to the setting, and a negative cutoff
        would lie in the future and purge every tombstone."""
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        service = SoftDeletePurgeService(purge_settings, test_session)

        with pytest.raises(ValueError, match="at least 1 day"):
            await service.purge(retention_days=retention_days)

        assert await _count(test_session, User) == 2
        assert await _count(test_session, Domain) == 3


runner = CliRunner()


class TestCleanupCLI:
    """Tests for cleanup CLI command."""

    def test_cleanup_command_help(self):
        """Test cleanup command is registered with expected flags."""
        from fastsmtp.cli import app

        result = runner.invoke(app, ["cleanup", "--help"])
        assert result.exit_code == 0
        output = strip_ansi(result.stdout)
        # Check command description
        assert "delivery log" in output.lower() or "cleanup" in output.lower()
        # Check required flags are present
        assert "--dry-run" in output
        assert "--older-than" in output


class TestCleanupWorker:
    """Tests for CleanupWorker background task."""

    @pytest.mark.asyncio
    async def test_worker_creation(self, test_settings: Settings):
        """Test CleanupWorker can be created."""
        from fastsmtp.cleanup.worker import CleanupWorker

        worker = CleanupWorker(settings=test_settings)
        assert worker.settings == test_settings
        assert worker._running is False

    @pytest.mark.asyncio
    async def test_worker_start_stop(self, test_settings: Settings):
        """Test worker start and stop lifecycle."""
        from fastsmtp.cleanup.worker import CleanupWorker

        worker = CleanupWorker(settings=test_settings)

        # Mock the cleanup run to prevent actual DB operations
        with patch.object(worker, "run_cleanup", new_callable=AsyncMock) as mock_cleanup:
            mock_cleanup.return_value = None

            worker.start()
            assert worker._task is not None

            await asyncio.sleep(0.05)
            assert worker._running is True

            await worker.stop()
            assert worker._running is False

    @pytest.mark.asyncio
    async def test_worker_disabled_does_not_start(self):
        """Neither job enabled: no task at all."""
        from fastsmtp.cleanup.worker import CleanupWorker

        settings = Settings(
            root_api_key="test123",
            delivery_log_cleanup_enabled=False,
            soft_delete_retention_days=None,
        )

        worker = CleanupWorker(settings=settings)
        worker.start()

        # Worker should not have started a task
        assert worker._task is None
        assert worker._running is False

    @pytest.mark.asyncio
    async def test_worker_starts_with_only_soft_delete_retention(self, caplog):
        """The purge job alone is enough to run the worker."""
        from fastsmtp.cleanup.worker import CleanupWorker

        settings = Settings(
            root_api_key="test123",
            delivery_log_cleanup_enabled=False,
            soft_delete_retention_days=30,
        )
        worker = CleanupWorker(settings=settings)

        caplog.set_level(logging.INFO, logger="fastsmtp.cleanup.worker")
        with patch.object(worker, "run_cleanup", new_callable=AsyncMock):
            worker.start()
            assert worker._task is not None
            await asyncio.sleep(0.05)
            assert worker._running is True
            await worker.stop()

        assert "soft-delete retention: 30d" in caplog.text

    @pytest.mark.asyncio
    async def test_startup_line_says_never_when_retention_is_unset(
        self, test_settings: Settings, caplog
    ):
        from fastsmtp.cleanup.worker import CleanupWorker

        assert test_settings.soft_delete_retention_days is None
        worker = CleanupWorker(settings=test_settings)

        caplog.set_level(logging.INFO, logger="fastsmtp.cleanup.worker")
        with patch.object(worker, "run_cleanup", new_callable=AsyncMock):
            worker.start()
            await asyncio.sleep(0.05)
            await worker.stop()

        assert "soft-delete retention: never" in caplog.text


class TestCleanupWorkerRun:
    """``run_cleanup`` runs each enabled job in its own session; a failure skips nothing."""

    @pytest.fixture
    def session_factory(self) -> MagicMock:
        """Stand-in for ``async_session``; records how many sessions were opened."""

        @asynccontextmanager
        async def open_session() -> AsyncIterator[AsyncMock]:
            yield AsyncMock(spec=AsyncSession)

        factory = MagicMock(side_effect=open_session)
        with patch("fastsmtp.cleanup.worker.async_session", factory):
            yield factory

    @pytest.fixture
    def cleanup_job(self) -> AsyncMock:
        from fastsmtp.cleanup.service import CleanupResult

        result = CleanupResult(deleted_count=2, dry_run=False, cutoff_date=datetime.now(UTC))
        with patch(
            "fastsmtp.cleanup.worker.DeliveryLogCleanupService.cleanup",
            new_callable=AsyncMock,
            return_value=result,
        ) as mock:
            yield mock

    @pytest.fixture
    def purge_job(self) -> AsyncMock:
        from fastsmtp.cleanup.purge import PurgeResult

        result = PurgeResult(
            cutoff_date=datetime.now(UTC),
            dry_run=False,
            counts={"recipients": 1, "api_keys": 0, "domains": 1, "users": 0},
        )
        with patch(
            "fastsmtp.cleanup.worker.SoftDeletePurgeService.purge",
            new_callable=AsyncMock,
            return_value=result,
        ) as mock:
            yield mock

    @staticmethod
    def make_settings(**overrides: object) -> Settings:
        return Settings(root_api_key="test123", **overrides)

    @pytest.fixture
    def make_worker(self) -> Callable[..., object]:
        from fastsmtp.cleanup.worker import CleanupWorker

        return lambda **overrides: CleanupWorker(settings=self.make_settings(**overrides))

    @pytest.mark.asyncio
    async def test_skips_purge_when_retention_is_none(
        self, session_factory, cleanup_job, purge_job, make_worker
    ):
        worker = make_worker(delivery_log_cleanup_enabled=True, soft_delete_retention_days=None)

        result = await worker.run_cleanup()

        cleanup_job.assert_awaited_once_with(dry_run=False)
        purge_job.assert_not_awaited()
        assert result.delivery_logs is cleanup_job.return_value
        assert result.purge is None
        assert session_factory.call_count == 1

    @pytest.mark.asyncio
    async def test_runs_purge_after_delivery_cleanup_each_in_its_own_session(
        self, session_factory, cleanup_job, purge_job, make_worker, caplog
    ):
        worker = make_worker(delivery_log_cleanup_enabled=True, soft_delete_retention_days=30)
        order: list[str] = []
        cleanup_job.side_effect = lambda **_: order.append("cleanup") or cleanup_job.return_value
        purge_job.side_effect = lambda **_: order.append("purge") or purge_job.return_value

        caplog.set_level(logging.INFO, logger="fastsmtp.cleanup.worker")
        result = await worker.run_cleanup()

        assert order == ["cleanup", "purge"]
        purge_job.assert_awaited_once_with(dry_run=False)
        assert result.delivery_logs is cleanup_job.return_value
        assert result.purge is purge_job.return_value
        assert session_factory.call_count == 2
        assert (
            "Purged 2 soft-deleted rows (recipients=1, api_keys=0, domains=1, users=0)"
            in caplog.text
        )

    @pytest.mark.asyncio
    async def test_purges_alone_when_delivery_cleanup_is_disabled(
        self, session_factory, cleanup_job, purge_job, make_worker
    ):
        worker = make_worker(delivery_log_cleanup_enabled=False, soft_delete_retention_days=30)

        result = await worker.run_cleanup()

        cleanup_job.assert_not_awaited()
        purge_job.assert_awaited_once_with(dry_run=False)
        assert result.delivery_logs is None
        assert result.has_more is False

    @pytest.mark.asyncio
    async def test_nothing_purged_is_not_logged(
        self, session_factory, cleanup_job, purge_job, make_worker, caplog
    ):
        from fastsmtp.cleanup.purge import PurgeResult

        purge_job.return_value = PurgeResult(
            cutoff_date=datetime.now(UTC),
            dry_run=False,
            counts={"recipients": 0, "api_keys": 0, "domains": 0, "users": 0},
        )
        worker = make_worker(delivery_log_cleanup_enabled=False, soft_delete_retention_days=30)

        caplog.set_level(logging.INFO, logger="fastsmtp.cleanup.worker")
        await worker.run_cleanup()

        assert "Purged" not in caplog.text

    @pytest.mark.asyncio
    async def test_failing_delivery_cleanup_does_not_skip_purge(
        self, session_factory, cleanup_job, purge_job, make_worker
    ):
        worker = make_worker(delivery_log_cleanup_enabled=True, soft_delete_retention_days=30)
        cleanup_job.side_effect = RuntimeError("delivery cleanup exploded")

        with pytest.raises(ExceptionGroup) as info:
            await worker.run_cleanup()

        purge_job.assert_awaited_once()
        assert info.group_contains(RuntimeError, match="delivery cleanup exploded")

    @pytest.mark.asyncio
    async def test_failing_purge_does_not_hide_the_delivery_result(
        self, session_factory, cleanup_job, purge_job, make_worker
    ):
        worker = make_worker(delivery_log_cleanup_enabled=True, soft_delete_retention_days=30)
        purge_job.side_effect = RuntimeError("purge exploded")

        with pytest.raises(ExceptionGroup) as info:
            await worker.run_cleanup()

        cleanup_job.assert_awaited_once()
        assert info.group_contains(RuntimeError, match="purge exploded")

    @pytest.mark.asyncio
    async def test_has_more_follows_the_delivery_log_job_only(
        self, session_factory, cleanup_job, purge_job, make_worker
    ):
        from fastsmtp.cleanup.service import CleanupResult

        cleanup_job.return_value = CleanupResult(
            deleted_count=5, dry_run=False, cutoff_date=datetime.now(UTC), has_more=True
        )
        worker = make_worker(delivery_log_cleanup_enabled=True, soft_delete_retention_days=30)

        result = await worker.run_cleanup()

        assert result.has_more is True


class TestCleanupIntegration:
    """Tests for cleanup integration with server."""

    def test_serve_command_has_no_cleanup_flag(self):
        """Test serve command doesn't have explicit cleanup flags (auto-enabled)."""
        from fastsmtp.cli import app

        result = runner.invoke(app, ["serve", "--help"], color=False)
        # Cleanup worker starts automatically based on config
        # No explicit flag needed
        assert result.exit_code == 0


class TestCleanupEndToEnd:
    """End-to-end tests for cleanup functionality."""

    @pytest.mark.asyncio
    async def test_full_cleanup_workflow(
        self,
        test_session: AsyncSession,
        test_settings: Settings,
    ):
        """Test complete cleanup workflow: create records, run cleanup, verify."""
        from fastsmtp.cleanup.service import DeliveryLogCleanupService
        from sqlalchemy import select

        # Create a domain
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="e2e-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        now = datetime.now(UTC)

        # Create mix of old and new records
        for i, days_old in enumerate([1, 30, 60, 100, 150]):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=domain.id,
                message_id=f"<e2e{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="abc123",
                payload={"age_days": days_old},
                status="delivered",
                attempts=1,
                instance_id="test-instance",
            )
            test_session.add(delivery)
            await test_session.flush()

            old_date = now - timedelta(days=days_old)
            await test_session.execute(
                DeliveryLog.__table__.update()
                .where(DeliveryLog.id == delivery.id)
                .values(created_at=old_date)
            )

        await test_session.commit()

        # Verify initial state
        stmt = select(DeliveryLog).where(DeliveryLog.domain_id == domain.id)
        result = await test_session.execute(stmt)
        assert len(result.scalars().all()) == 5

        # Run dry-run first
        service = DeliveryLogCleanupService(test_settings, test_session)
        dry_result = await service.cleanup(dry_run=True)
        assert dry_result.deleted_count == 2  # 100 and 150 days old

        # Verify nothing deleted yet
        result = await test_session.execute(stmt)
        assert len(result.scalars().all()) == 5

        # Run actual cleanup
        cleanup_result = await service.cleanup(dry_run=False)
        assert cleanup_result.deleted_count == 2

        # Verify correct records remain
        result = await test_session.execute(stmt)
        remaining = result.scalars().all()
        assert len(remaining) == 3

        remaining_ages = sorted([d.payload["age_days"] for d in remaining])
        assert remaining_ages == [1, 30, 60]
