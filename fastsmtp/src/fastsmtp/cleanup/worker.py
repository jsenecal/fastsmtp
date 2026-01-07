"""Background worker for delivery log cleanup."""

import asyncio
import contextlib
import logging

from fastsmtp.cleanup.service import CleanupResult, DeliveryLogCleanupService
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.session import async_session

logger = logging.getLogger(__name__)

# Minimum interval between cleanup runs when catching up (5 minutes)
CATCHUP_INTERVAL_SECONDS = 300


class CleanupWorker:
    """Background worker that periodically cleans up old delivery logs.

    The worker runs cleanup at configurable intervals. When there are many
    records to delete (more than max_per_run), it will run more frequently
    to catch up gradually without overwhelming the database.
    """

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._running = False
        self._task: asyncio.Task | None = None

    async def run_cleanup(self) -> CleanupResult:
        """Run a single cleanup operation.

        Returns:
            CleanupResult with deletion details.
        """
        async with async_session() as session:
            service = DeliveryLogCleanupService(self.settings, session)
            return await service.cleanup(dry_run=False)

    async def run(self) -> None:
        """Run the worker loop."""
        self._running = True
        interval_seconds = self.settings.delivery_log_cleanup_interval_hours * 3600

        interval_hours = self.settings.delivery_log_cleanup_interval_hours
        retention_days = self.settings.delivery_log_retention_days
        logger.info(
            f"Cleanup worker started (interval: {interval_hours}h, retention: {retention_days}d)"
        )

        # Wait before first cleanup (don't cleanup immediately on startup)
        await asyncio.sleep(interval_seconds)

        while self._running:
            try:
                if not self._running:
                    break

                result = await self.run_cleanup()
                if result.deleted_count > 0:
                    logger.info(f"Cleanup worker deleted {result.deleted_count} old delivery logs")

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
