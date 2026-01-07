"""Tests for delivery log cleanup functionality."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from fastsmtp.config import Settings
from fastsmtp.db.models import DeliveryLog, Domain
from sqlalchemy.ext.asyncio import AsyncSession

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")


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
        from importlib import reload

        import fastsmtp.config

        reload(fastsmtp.config)
        settings = fastsmtp.config.Settings(root_api_key="test123")
        assert settings.delivery_log_retention_days == 30

    def test_cleanup_can_be_disabled(self, monkeypatch):
        """Test cleanup can be disabled via environment."""
        monkeypatch.setenv("FASTSMTP_DELIVERY_LOG_CLEANUP_ENABLED", "false")
        from importlib import reload

        import fastsmtp.config

        reload(fastsmtp.config)
        settings = fastsmtp.config.Settings(root_api_key="test123")
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
        from sqlalchemy import select

        from fastsmtp.cleanup.service import DeliveryLogCleanupService

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
        from sqlalchemy import select

        from fastsmtp.cleanup.service import DeliveryLogCleanupService

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


from typer.testing import CliRunner

runner = CliRunner()


class TestCleanupCLI:
    """Tests for cleanup CLI command."""

    def test_cleanup_command_exists(self):
        """Test cleanup command is registered."""
        from fastsmtp.cli import app

        result = runner.invoke(app, ["cleanup", "--help"])
        assert result.exit_code == 0
        assert "delivery log" in result.stdout.lower() or "cleanup" in result.stdout.lower()

    def test_cleanup_dry_run_flag(self):
        """Test --dry-run flag is available."""
        from fastsmtp.cli import app

        result = runner.invoke(app, ["cleanup", "--help"])
        assert "--dry-run" in result.stdout

    def test_cleanup_older_than_flag(self):
        """Test --older-than flag is available."""
        from fastsmtp.cli import app

        result = runner.invoke(app, ["cleanup", "--help"])
        assert "--older-than" in result.stdout
