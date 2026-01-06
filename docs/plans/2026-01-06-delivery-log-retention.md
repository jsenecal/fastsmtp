# Delivery Log Retention Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add age-based retention cleanup for `delivery_log` records with both a background worker and CLI command.

**Architecture:** New `cleanup` module with `DeliveryLogCleanupService` that deletes records older than a configurable retention period. Background worker runs on a configurable interval. CLI command provides manual/dry-run execution.

**Tech Stack:** SQLAlchemy async, Typer CLI, asyncio background tasks

---

### Task 1: Add Configuration Settings

**Files:**
- Modify: `fastsmtp/src/fastsmtp/config.py:49-68`

**Step 1: Write the test**

Create `fastsmtp/tests/test_cleanup.py`:

```python
"""Tests for delivery log cleanup functionality."""

import os

import pytest

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
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupSettings -v`
Expected: FAIL with AttributeError (settings don't exist yet)

**Step 3: Write minimal implementation**

Add to `fastsmtp/src/fastsmtp/config.py` after line 68 (after `worker_batch_size`):

```python
    # Delivery log cleanup
    delivery_log_retention_days: int = 90
    delivery_log_cleanup_interval_hours: int = 24
    delivery_log_cleanup_enabled: bool = True
    delivery_log_cleanup_batch_size: int = 1000
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupSettings -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fastsmtp/src/fastsmtp/config.py fastsmtp/tests/test_cleanup.py
git commit -m "feat: add delivery log cleanup configuration settings"
```

---

### Task 2: Create CleanupResult Dataclass

**Files:**
- Create: `fastsmtp/src/fastsmtp/cleanup/__init__.py`
- Create: `fastsmtp/src/fastsmtp/cleanup/service.py`

**Step 1: Write the test**

Add to `fastsmtp/tests/test_cleanup.py`:

```python
from datetime import UTC, datetime


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
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupResult -v`
Expected: FAIL with ModuleNotFoundError (cleanup module doesn't exist)

**Step 3: Write minimal implementation**

Create `fastsmtp/src/fastsmtp/cleanup/__init__.py`:

```python
"""Delivery log cleanup module."""

from fastsmtp.cleanup.service import CleanupResult, DeliveryLogCleanupService

__all__ = [
    "CleanupResult",
    "DeliveryLogCleanupService",
]
```

Create `fastsmtp/src/fastsmtp/cleanup/service.py`:

```python
"""Delivery log cleanup service."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class CleanupResult:
    """Result of a cleanup operation."""

    deleted_count: int
    dry_run: bool
    cutoff_date: datetime


class DeliveryLogCleanupService:
    """Service for cleaning up old delivery log records."""

    pass
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupResult -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fastsmtp/src/fastsmtp/cleanup/
git commit -m "feat: add CleanupResult dataclass"
```

---

### Task 3: Implement DeliveryLogCleanupService.cleanup (dry-run mode)

**Files:**
- Modify: `fastsmtp/src/fastsmtp/cleanup/service.py`

**Step 1: Write the test**

Add to `fastsmtp/tests/test_cleanup.py`:

```python
import uuid
from datetime import timedelta

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.config import Settings
from fastsmtp.db.models import DeliveryLog, Domain


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
        from sqlalchemy import select

        from fastsmtp.cleanup.service import DeliveryLogCleanupService

        service = DeliveryLogCleanupService(test_settings, test_session)
        result = await service.cleanup(dry_run=True)

        assert result.dry_run is True
        assert result.deleted_count == 5  # Only old deliveries

        # Verify nothing was actually deleted
        stmt = select(DeliveryLog)
        db_result = await test_session.execute(stmt)
        all_deliveries = db_result.scalars().all()
        assert len(all_deliveries) == 8  # 5 old + 3 recent
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestDeliveryLogCleanupService::test_cleanup_dry_run_counts_without_deleting -v`
Expected: FAIL with TypeError (service doesn't accept parameters yet)

**Step 3: Write minimal implementation**

Update `fastsmtp/src/fastsmtp/cleanup/service.py`:

```python
"""Delivery log cleanup service."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.config import Settings
from fastsmtp.db.models import DeliveryLog

logger = logging.getLogger(__name__)


@dataclass
class CleanupResult:
    """Result of a cleanup operation."""

    deleted_count: int
    dry_run: bool
    cutoff_date: datetime


class DeliveryLogCleanupService:
    """Service for cleaning up old delivery log records."""

    def __init__(self, settings: Settings, session: AsyncSession):
        self.settings = settings
        self.session = session

    def _get_cutoff_date(self, retention_days: int | None = None) -> datetime:
        """Calculate the cutoff date for cleanup."""
        days = retention_days or self.settings.delivery_log_retention_days
        return datetime.now(UTC) - timedelta(days=days)

    async def cleanup(
        self,
        dry_run: bool = False,
        retention_days: int | None = None,
    ) -> CleanupResult:
        """Delete delivery logs older than the retention period.

        Args:
            dry_run: If True, only count records without deleting.
            retention_days: Override the configured retention period.

        Returns:
            CleanupResult with the number of deleted records.
        """
        cutoff_date = self._get_cutoff_date(retention_days)

        if dry_run:
            # Count records that would be deleted
            stmt = select(func.count()).select_from(DeliveryLog).where(
                DeliveryLog.created_at < cutoff_date
            )
            result = await self.session.execute(stmt)
            count = result.scalar() or 0

            logger.info(f"Dry run: would delete {count} delivery logs older than {cutoff_date}")

            return CleanupResult(
                deleted_count=count,
                dry_run=True,
                cutoff_date=cutoff_date,
            )

        # Actual deletion will be implemented in next task
        return CleanupResult(
            deleted_count=0,
            dry_run=False,
            cutoff_date=cutoff_date,
        )
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestDeliveryLogCleanupService::test_cleanup_dry_run_counts_without_deleting -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fastsmtp/src/fastsmtp/cleanup/service.py
git commit -m "feat: add dry-run mode for delivery log cleanup"
```

---

### Task 4: Implement Actual Deletion with Batching

**Files:**
- Modify: `fastsmtp/src/fastsmtp/cleanup/service.py`

**Step 1: Write the test**

Add to `fastsmtp/tests/test_cleanup.py` in `TestDeliveryLogCleanupService` class:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestDeliveryLogCleanupService::test_cleanup_deletes_old_records -v`
Expected: FAIL (deleted_count will be 0)

**Step 3: Write minimal implementation**

Update the `cleanup` method in `fastsmtp/src/fastsmtp/cleanup/service.py`:

```python
"""Delivery log cleanup service."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.config import Settings
from fastsmtp.db.models import DeliveryLog

logger = logging.getLogger(__name__)


@dataclass
class CleanupResult:
    """Result of a cleanup operation."""

    deleted_count: int
    dry_run: bool
    cutoff_date: datetime


class DeliveryLogCleanupService:
    """Service for cleaning up old delivery log records."""

    def __init__(self, settings: Settings, session: AsyncSession):
        self.settings = settings
        self.session = session

    def _get_cutoff_date(self, retention_days: int | None = None) -> datetime:
        """Calculate the cutoff date for cleanup."""
        days = retention_days or self.settings.delivery_log_retention_days
        return datetime.now(UTC) - timedelta(days=days)

    async def cleanup(
        self,
        dry_run: bool = False,
        retention_days: int | None = None,
    ) -> CleanupResult:
        """Delete delivery logs older than the retention period.

        Args:
            dry_run: If True, only count records without deleting.
            retention_days: Override the configured retention period.

        Returns:
            CleanupResult with the number of deleted records.
        """
        cutoff_date = self._get_cutoff_date(retention_days)
        batch_size = self.settings.delivery_log_cleanup_batch_size

        # Count total records to delete
        count_stmt = select(func.count()).select_from(DeliveryLog).where(
            DeliveryLog.created_at < cutoff_date
        )
        count_result = await self.session.execute(count_stmt)
        total_count = count_result.scalar() or 0

        if dry_run:
            logger.info(f"Dry run: would delete {total_count} delivery logs older than {cutoff_date}")
            return CleanupResult(
                deleted_count=total_count,
                dry_run=True,
                cutoff_date=cutoff_date,
            )

        # Delete in batches to avoid long locks
        total_deleted = 0
        while True:
            # Get IDs of records to delete in this batch
            select_stmt = (
                select(DeliveryLog.id)
                .where(DeliveryLog.created_at < cutoff_date)
                .limit(batch_size)
            )
            result = await self.session.execute(select_stmt)
            ids_to_delete = [row[0] for row in result.fetchall()]

            if not ids_to_delete:
                break

            # Delete the batch
            delete_stmt = delete(DeliveryLog).where(DeliveryLog.id.in_(ids_to_delete))
            await self.session.execute(delete_stmt)
            await self.session.commit()

            total_deleted += len(ids_to_delete)
            logger.debug(f"Deleted batch of {len(ids_to_delete)} delivery logs")

        logger.info(f"Deleted {total_deleted} delivery logs older than {cutoff_date}")

        return CleanupResult(
            deleted_count=total_deleted,
            dry_run=False,
            cutoff_date=cutoff_date,
        )
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestDeliveryLogCleanupService -v`
Expected: PASS (all tests in the class)

**Step 5: Commit**

```bash
git add fastsmtp/src/fastsmtp/cleanup/service.py
git commit -m "feat: implement batch deletion for delivery log cleanup"
```

---

### Task 5: Add CLI cleanup Command

**Files:**
- Modify: `fastsmtp/src/fastsmtp/cli.py`

**Step 1: Write the test**

Add to `fastsmtp/tests/test_cleanup.py`:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupCLI::test_cleanup_command_exists -v`
Expected: FAIL (no such command 'cleanup')

**Step 3: Write minimal implementation**

Add to `fastsmtp/src/fastsmtp/cli.py` before `if __name__ == "__main__":`:

```python
@app.command()
def cleanup(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be deleted without actually deleting"),
    older_than: str | None = typer.Option(None, "--older-than", help="Override retention period (e.g., '30d', '6h')"),
):
    """Clean up old delivery log records."""
    from datetime import timedelta

    from fastsmtp.cleanup.service import DeliveryLogCleanupService
    from fastsmtp.db.session import async_session

    settings = get_settings()

    # Parse older_than if provided
    retention_days: int | None = None
    if older_than:
        retention_days = _parse_duration_to_days(older_than)
        if retention_days is None:
            console.print(f"[red]Invalid duration format: {older_than}[/red]")
            console.print("Use format like '30d' (days) or '6h' (hours)")
            raise typer.Exit(1)

    async def run_cleanup():
        async with async_session() as session:
            service = DeliveryLogCleanupService(settings, session)
            result = await service.cleanup(dry_run=dry_run, retention_days=retention_days)
            return result

    result = run_async(run_cleanup())

    cutoff_str = result.cutoff_date.strftime("%Y-%m-%d %H:%M:%S UTC")

    if dry_run:
        console.print(f"[yellow]Would delete {result.deleted_count} delivery log records older than {cutoff_str}[/yellow]")
    else:
        console.print(f"[green]Deleted {result.deleted_count} delivery log records older than {cutoff_str}[/green]")


def _parse_duration_to_days(duration: str) -> int | None:
    """Parse a duration string like '30d' or '6h' to days.

    Returns None if the format is invalid.
    """
    import re

    match = re.match(r"^(\d+)([dhm])$", duration.lower())
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "d":
        return value
    elif unit == "h":
        # Convert hours to days (minimum 1 day if hours specified)
        return max(1, value // 24) if value >= 24 else 1
    elif unit == "m":
        # Minutes - minimum 1 day
        return 1

    return None
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupCLI -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fastsmtp/src/fastsmtp/cli.py
git commit -m "feat: add cleanup CLI command"
```

---

### Task 6: Add Background Cleanup Worker

**Files:**
- Create: `fastsmtp/src/fastsmtp/cleanup/worker.py`
- Modify: `fastsmtp/src/fastsmtp/cleanup/__init__.py`
- Modify: `fastsmtp/src/fastsmtp/cli.py`

**Step 1: Write the test**

Add to `fastsmtp/tests/test_cleanup.py`:

```python
import asyncio
from unittest.mock import AsyncMock, patch


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
        """Test worker doesn't start when disabled."""
        from fastsmtp.cleanup.worker import CleanupWorker

        settings = Settings(
            root_api_key="test123",
            delivery_log_cleanup_enabled=False,
        )

        worker = CleanupWorker(settings=settings)
        worker.start()

        # Worker should not have started a task
        assert worker._task is None
        assert worker._running is False
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupWorker -v`
Expected: FAIL with ModuleNotFoundError (worker module doesn't exist)

**Step 3: Write minimal implementation**

Create `fastsmtp/src/fastsmtp/cleanup/worker.py`:

```python
"""Background worker for delivery log cleanup."""

import asyncio
import contextlib
import logging

from fastsmtp.config import Settings, get_settings
from fastsmtp.cleanup.service import DeliveryLogCleanupService
from fastsmtp.db.session import async_session

logger = logging.getLogger(__name__)


class CleanupWorker:
    """Background worker that periodically cleans up old delivery logs."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._running = False
        self._task: asyncio.Task | None = None

    async def run_cleanup(self) -> int:
        """Run a single cleanup operation.

        Returns:
            Number of records deleted.
        """
        async with async_session() as session:
            service = DeliveryLogCleanupService(self.settings, session)
            result = await service.cleanup(dry_run=False)
            return result.deleted_count

    async def run(self) -> None:
        """Run the worker loop."""
        self._running = True
        interval_seconds = self.settings.delivery_log_cleanup_interval_hours * 3600

        logger.info(
            f"Cleanup worker started (interval: {self.settings.delivery_log_cleanup_interval_hours}h, "
            f"retention: {self.settings.delivery_log_retention_days}d)"
        )

        while self._running:
            try:
                # Wait first, then cleanup (don't cleanup immediately on startup)
                await asyncio.sleep(interval_seconds)

                if not self._running:
                    break

                deleted = await self.run_cleanup()
                if deleted > 0:
                    logger.info(f"Cleanup worker deleted {deleted} old delivery logs")

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in cleanup worker loop")
                # Wait before retrying on error
                await asyncio.sleep(60)

        logger.info("Cleanup worker stopped")

    def start(self) -> None:
        """Start the worker in the background."""
        if not self.settings.delivery_log_cleanup_enabled:
            logger.info("Cleanup worker disabled by configuration")
            return

        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        """Stop the worker."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def wait(self) -> None:
        """Wait for the worker to finish."""
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
```

Update `fastsmtp/src/fastsmtp/cleanup/__init__.py`:

```python
"""Delivery log cleanup module."""

from fastsmtp.cleanup.service import CleanupResult, DeliveryLogCleanupService
from fastsmtp.cleanup.worker import CleanupWorker

__all__ = [
    "CleanupResult",
    "CleanupWorker",
    "DeliveryLogCleanupService",
]
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py::TestCleanupWorker -v`
Expected: PASS

**Step 5: Commit**

```bash
git add fastsmtp/src/fastsmtp/cleanup/
git commit -m "feat: add background cleanup worker"
```

---

### Task 7: Integrate Cleanup Worker into Server

**Files:**
- Modify: `fastsmtp/src/fastsmtp/cli.py`

**Step 1: Write the test**

Add to `fastsmtp/tests/test_cleanup.py`:

```python
class TestCleanupIntegration:
    """Tests for cleanup integration with server."""

    def test_serve_command_has_no_cleanup_flag(self):
        """Test serve command doesn't have explicit cleanup flags (auto-enabled)."""
        from fastsmtp.cli import app

        result = runner.invoke(app, ["serve", "--help"])
        # Cleanup worker starts automatically based on config
        # No explicit flag needed
        assert result.exit_code == 0
```

**Step 2: Write implementation**

Update the `serve` command in `fastsmtp/src/fastsmtp/cli.py` to include the cleanup worker:

In the `serve` function, add after the webhook worker section:

```python
        if not smtp_only and not api_only:
            # Start webhook worker
            worker = WebhookWorker(settings)
            worker.start()
            console.print("[green]Webhook worker started[/green]")

            # Start cleanup worker (if enabled)
            from fastsmtp.cleanup import CleanupWorker

            cleanup_worker = CleanupWorker(settings)
            cleanup_worker.start()
            if settings.delivery_log_cleanup_enabled:
                console.print(
                    f"[green]Cleanup worker started (interval: {settings.delivery_log_cleanup_interval_hours}h)[/green]"
                )
```

**Step 3: Run all cleanup tests**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add fastsmtp/src/fastsmtp/cli.py
git commit -m "feat: integrate cleanup worker into server lifecycle"
```

---

### Task 8: Final Integration Test and Documentation Update

**Files:**
- Modify: `fastsmtp/tests/test_cleanup.py` (add integration test)

**Step 1: Write integration test**

Add to `fastsmtp/tests/test_cleanup.py`:

```python
class TestCleanupEndToEnd:
    """End-to-end tests for cleanup functionality."""

    @pytest.mark.asyncio
    async def test_full_cleanup_workflow(
        self,
        test_session: AsyncSession,
        test_settings: Settings,
    ):
        """Test complete cleanup workflow: create records, run cleanup, verify."""
        from sqlalchemy import select

        from fastsmtp.cleanup.service import DeliveryLogCleanupService

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
```

**Step 2: Run all tests**

Run: `uv run pytest fastsmtp/tests/test_cleanup.py -v`
Expected: All tests PASS

**Step 3: Run full test suite**

Run: `uv run pytest`
Expected: All existing tests still pass

**Step 4: Commit**

```bash
git add fastsmtp/tests/test_cleanup.py
git commit -m "test: add end-to-end cleanup integration test"
```

---

## Summary

After completing all tasks, you will have:

1. **Configuration** (`config.py`):
   - `FASTSMTP_DELIVERY_LOG_RETENTION_DAYS` (default: 90)
   - `FASTSMTP_DELIVERY_LOG_CLEANUP_INTERVAL_HOURS` (default: 24)
   - `FASTSMTP_DELIVERY_LOG_CLEANUP_ENABLED` (default: true)
   - `FASTSMTP_DELIVERY_LOG_CLEANUP_BATCH_SIZE` (default: 1000)

2. **Cleanup Service** (`cleanup/service.py`):
   - `DeliveryLogCleanupService` with `cleanup(dry_run, retention_days)` method
   - Batch deletion to avoid long DB locks
   - Proper logging

3. **Background Worker** (`cleanup/worker.py`):
   - `CleanupWorker` that runs on configurable interval
   - Auto-starts with server (if enabled)
   - Graceful shutdown

4. **CLI Command** (`cli.py`):
   - `fastsmtp cleanup` command
   - `--dry-run` flag
   - `--older-than` override (e.g., "30d")

5. **Tests** (`tests/test_cleanup.py`):
   - Settings tests
   - Service unit tests
   - Worker tests
   - CLI tests
   - End-to-end integration test
