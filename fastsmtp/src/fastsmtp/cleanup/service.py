"""Delivery log cleanup service."""

import asyncio
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
    has_more: bool = False  # True if max_per_run limit was reached


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

        Deletion is performed in batches with configurable delays to avoid
        overwhelming the database. A maximum per-run limit prevents any single
        cleanup run from taking too long.

        Args:
            dry_run: If True, only count records without deleting.
            retention_days: Override the configured retention period.

        Returns:
            CleanupResult with the number of deleted records.
        """
        cutoff_date = self._get_cutoff_date(retention_days)
        batch_size = self.settings.delivery_log_cleanup_batch_size
        max_per_run = self.settings.delivery_log_cleanup_max_per_run
        batch_delay_seconds = self.settings.delivery_log_cleanup_batch_delay_ms / 1000.0

        # Count total records to delete
        count_stmt = (
            select(func.count())
            .select_from(DeliveryLog)
            .where(DeliveryLog.created_at < cutoff_date)
        )
        count_result = await self.session.execute(count_stmt)
        total_count = count_result.scalar() or 0

        if dry_run:
            logger.info(
                f"Dry run: would delete {total_count} delivery logs older than {cutoff_date}"
            )
            return CleanupResult(
                deleted_count=total_count,
                dry_run=True,
                cutoff_date=cutoff_date,
                has_more=False,
            )

        # Delete in batches with delay to avoid overwhelming database
        total_deleted = 0
        first_batch = True
        while total_deleted < max_per_run:
            # Add delay between batches (skip delay for first batch)
            if not first_batch and batch_delay_seconds > 0:
                await asyncio.sleep(batch_delay_seconds)
            first_batch = False

            # Get IDs of records to delete in this batch
            remaining = max_per_run - total_deleted
            select_stmt = (
                select(DeliveryLog.id)
                .where(DeliveryLog.created_at < cutoff_date)
                .limit(min(batch_size, remaining))
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

        # Check if we hit the per-run limit (more records may remain)
        has_more = total_deleted >= max_per_run

        if has_more:
            logger.info(f"Deleted {total_deleted} delivery logs (limit reached, more remain)")
        else:
            logger.info(f"Deleted {total_deleted} delivery logs older than {cutoff_date}")

        return CleanupResult(
            deleted_count=total_deleted,
            dry_run=False,
            cutoff_date=cutoff_date,
            has_more=has_more,
        )
