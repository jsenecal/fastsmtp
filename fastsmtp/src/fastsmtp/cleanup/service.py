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
