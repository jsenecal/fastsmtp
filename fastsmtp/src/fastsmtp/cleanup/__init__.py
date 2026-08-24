"""Retention jobs: delivery-log cleanup and purge of soft-deleted rows."""

from fastsmtp.cleanup.purge import PurgeResult, SoftDeletePurgeService
from fastsmtp.cleanup.service import CleanupResult, DeliveryLogCleanupService
from fastsmtp.cleanup.worker import CleanupRunResult, CleanupWorker

__all__ = [
    "CleanupResult",
    "CleanupRunResult",
    "CleanupWorker",
    "DeliveryLogCleanupService",
    "PurgeResult",
    "SoftDeletePurgeService",
]
