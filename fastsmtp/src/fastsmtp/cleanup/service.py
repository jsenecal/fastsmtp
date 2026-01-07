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
