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
