"""Retention purge of soft-deleted rows.

Tombstones (``deleted_at`` set) older than ``soft_delete_retention_days`` are
hard-deleted with bulk ``DELETE`` statements. Bulk deletes bypass the ORM
cascades, so the database ``ON DELETE`` rules do the work: every child FK is
``CASCADE`` (keys and memberships with a user; recipients, rulesets, rules and
members with a domain) and the delivery-log FKs are ``SET NULL``, which keeps
delivery history and severs its links -- exactly what ``session.delete()`` did
for a hard delete in v0.4.0.

Tables are purged children-first so the per-table counts are accurate; the
order is FK-safe either way. Each table runs on its own clock: a recipient
tombstoned independently before its domain has an older stamp and is purged
on that stamp even if the domain is restored later (its restore only clears
recipients carrying the domain's own stamp).

No batching: tombstones are configuration rows, not traffic. If a deployment
ever shows thousands, reuse the ``delivery_log_cleanup_batch_*`` knobs.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.config import Settings
from fastsmtp.db.models import APIKey, Domain, Recipient, SoftDeleteMixin, User

logger = logging.getLogger(__name__)


@dataclass
class PurgeResult:
    """Result of a purge run: rows removed (or, on a dry run, that would be) per table."""

    cutoff_date: datetime
    dry_run: bool
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def breakdown(self) -> str:
        """``recipients=1, api_keys=0, domains=1, users=1`` -- for the worker log and the CLI."""
        return ", ".join(f"{table}={count}" for table, count in self.counts.items())


class SoftDeletePurgeService:
    """Hard-delete tombstones older than the retention window."""

    # Children before parents so every row is counted under its own table
    # rather than disappearing through a parent's cascade.
    TABLES: tuple[tuple[type[SoftDeleteMixin], str], ...] = (
        (Recipient, "recipients"),
        (APIKey, "api_keys"),
        (Domain, "domains"),
        (User, "users"),
    )

    def __init__(self, settings: Settings, session: AsyncSession):
        self.settings = settings
        self.session = session

    def _get_cutoff_date(self, retention_days: int | None) -> datetime:
        days = (
            retention_days
            if retention_days is not None
            else self.settings.soft_delete_retention_days
        )
        if days is None:
            raise ValueError("soft-delete retention is not configured")
        if days < 1:
            # Settings enforce ge=1; the override must too. 0 would purge every
            # tombstone made before this instant, a negative one puts the
            # cutoff in the future and purges them all.
            raise ValueError("soft-delete retention must be at least 1 day")
        return datetime.now(UTC) - timedelta(days=days)

    async def purge(
        self,
        dry_run: bool = False,
        retention_days: int | None = None,
    ) -> PurgeResult:
        """Purge tombstones older than the retention period, one commit for all tables.

        Args:
            dry_run: Count what would be purged without deleting.
            retention_days: Override ``settings.soft_delete_retention_days``.

        Raises:
            ValueError: neither the override nor the setting is configured.
        """
        cutoff_date = self._get_cutoff_date(retention_days)
        counts: dict[str, int] = {}

        for model, name in self.TABLES:
            expired = model.deleted_at < cutoff_date
            if dry_run:
                counts[name] = (
                    await self.session.execute(
                        select(func.count()).select_from(model).where(expired)
                    )
                ).scalar_one()
            else:
                # No identity-map sync: the worker and the CLI open a fresh
                # session per run, so there is nothing loaded to keep in step,
                # and "fetch" would RETURNING every purged key for nothing.
                result = await self.session.execute(
                    delete(model).where(expired).execution_options(synchronize_session=False)
                )
                assert isinstance(result, CursorResult)  # execute() is typed as Result[Any]
                counts[name] = result.rowcount

        if not dry_run:
            await self.session.commit()

        purged = PurgeResult(cutoff_date=cutoff_date, dry_run=dry_run, counts=counts)
        # Callers (worker, CLI) report the outcome; this is the audit trail.
        logger.debug(
            f"{'Would purge' if dry_run else 'Purged'} {purged.total} soft-deleted rows "
            f"older than {cutoff_date} ({purged.breakdown})"
        )
        return purged
