"""Delivery log cleanup module."""

from fastsmtp.cleanup.service import CleanupResult, DeliveryLogCleanupService
from fastsmtp.cleanup.worker import CleanupWorker

__all__ = [
    "CleanupResult",
    "CleanupWorker",
    "DeliveryLogCleanupService",
]
