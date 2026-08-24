"""Background worker for the retention jobs: delivery-log cleanup and soft-delete purge."""

import asyncio
import contextlib
import logging
from dataclasses import dataclass

from fastsmtp.cleanup.purge import PurgeResult, SoftDeletePurgeService
from fastsmtp.cleanup.service import CleanupResult, DeliveryLogCleanupService
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.session import async_session

logger = logging.getLogger(__name__)

# Minimum interval between cleanup runs when catching up (5 minutes)
CATCHUP_INTERVAL_SECONDS = 300


@dataclass
class CleanupRunResult:
    """Outcome of one worker pass; a job that is disabled leaves its slot ``None``."""

    delivery_logs: CleanupResult | None = None
    purge: PurgeResult | None = None

    @property
    def has_more(self) -> bool:
        """Catch-up applies to delivery logs only; purge has no per-run limit."""
        return self.delivery_logs is not None and self.delivery_logs.has_more


class CleanupWorker:
    """Background worker that periodically runs the retention jobs.

    Two jobs share the schedule: delivery-log cleanup
    (``delivery_log_cleanup_enabled``) and the purge of soft-deleted rows
    (``soft_delete_retention_days``). The worker runs when either is enabled.
    When there are many delivery logs to delete (more than max_per_run), it
    runs more frequently to catch up gradually without overwhelming the
    database.
    """

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._running = False
        self._task: asyncio.Task | None = None

    @property
    def enabled(self) -> bool:
        return (
            self.settings.delivery_log_cleanup_enabled
            or self.settings.soft_delete_retention_days is not None
        )

    async def _cleanup_delivery_logs(self) -> CleanupResult:
        async with async_session() as session:
            return await DeliveryLogCleanupService(self.settings, session).cleanup(dry_run=False)

    async def _purge_soft_deleted(self) -> PurgeResult:
        async with async_session() as session:
            result = await SoftDeletePurgeService(self.settings, session).purge(dry_run=False)
        if result.total > 0:
            logger.info(f"Purged {result.total} soft-deleted rows ({result.breakdown})")
        return result

    async def run_cleanup(self) -> CleanupRunResult:
        """Run every enabled job once, each in its own session.

        A job that fails does not skip the other; the failures are re-raised
        together afterwards so the loop's error backoff still applies.
        """
        result = CleanupRunResult()
        errors: list[Exception] = []

        if self.settings.delivery_log_cleanup_enabled:
            try:
                result.delivery_logs = await self._cleanup_delivery_logs()
            except Exception as exc:
                errors.append(exc)

        if self.settings.soft_delete_retention_days is not None:
            try:
                result.purge = await self._purge_soft_deleted()
            except Exception as exc:
                errors.append(exc)

        if errors:
            raise ExceptionGroup("cleanup job failed", errors)
        return result

    async def run(self) -> None:
        """Run the worker loop."""
        self._running = True
        interval_seconds = self.settings.delivery_log_cleanup_interval_hours * 3600

        interval_hours = self.settings.delivery_log_cleanup_interval_hours
        retention_days = self.settings.delivery_log_retention_days
        soft_delete_days = self.settings.soft_delete_retention_days
        soft_delete_retention = f"{soft_delete_days}d" if soft_delete_days is not None else "never"
        logger.info(
            f"Cleanup worker started (interval: {interval_hours}h, retention: {retention_days}d, "
            f"soft-delete retention: {soft_delete_retention})"
        )

        # Wait before first cleanup (don't cleanup immediately on startup)
        await asyncio.sleep(interval_seconds)

        while self._running:
            try:
                if not self._running:
                    break

                result = await self.run_cleanup()
                if result.delivery_logs is not None and result.delivery_logs.deleted_count > 0:
                    logger.info(
                        f"Cleanup worker deleted {result.delivery_logs.deleted_count} "
                        "old delivery logs"
                    )

                # If there are more records to delete, run again sooner
                if result.has_more:
                    logger.info(f"More records to delete, next run in {CATCHUP_INTERVAL_SECONDS}s")
                    await asyncio.sleep(CATCHUP_INTERVAL_SECONDS)
                else:
                    # Normal interval
                    await asyncio.sleep(interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in cleanup worker loop")
                # Wait before retrying on error
                await asyncio.sleep(60)

        logger.info("Cleanup worker stopped")

    def start(self) -> None:
        """Start the worker in the background."""
        if not self.enabled:
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
