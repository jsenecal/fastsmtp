"""Soft delete, restore and purge - the single module that writes ``deleted_at``.

The API routers and the server CLI call these; nothing else assigns
``deleted_at`` (grep for ``deleted_at =`` to audit). Read-side filtering is
``Model.live()`` on the mixin and :func:`visible` here.

Cascade rules
-------------
- A parent and the children it stamps receive the *same* timestamp, taken once
  per call (``datetime.now(UTC)`` unless ``now`` is given). ``timestamptz``
  round-trips microseconds, and the value is written and compared within one
  transaction, so equality is exact.
- ``Domain -> Recipient``: recipients are stamped and their queued deliveries
  cancelled. Rulesets, rules and members carry no tombstone; they are hidden
  through the parent and return unchanged on restore.
- ``User -> APIKey``: keys get the stamp *and* ``is_active = False``, so v0.4.0
  pods, which only check ``is_active``, reject them during a rolling deploy.
- Domain restore clears only recipients whose stamp equals the domain's; a
  recipient deleted independently earlier keeps its own tombstone.
- User restore never restores keys: credential revocation is one-way.
- Restore never touches ``is_enabled`` / ``is_active`` and never re-queues
  cancelled deliveries (that is the explicit retry endpoint's job).

Flushing
--------
``soft_delete_*`` flush, so counts and cancelled rows are visible to the rest
of the request. ``restore_*`` deliberately leave the parent row *unflushed*:
the caller's ``flush_or_http_conflict`` must be the flush that hits the
partial unique index when the name has been re-taken, so it can translate the
violation into the create route's 409. ``purge_*`` are ``session.delete`` -
ORM + FK cascades, exactly the v0.4.0 hard delete; callers guarantee the row
is already tombstoned (``api.validation.require_tombstoned``).
"""

from datetime import UTC, datetime

from sqlalchemy import ColumnElement, true, update
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.bulk import execute_counted
from fastsmtp.db.models import APIKey, Domain, Recipient, SoftDeleteMixin, User
from fastsmtp.webhook.queue import cancel_pending_deliveries


def visible(model: type[SoftDeleteMixin], include_deleted: bool) -> ColumnElement[bool]:
    """Read filter: everything when ``include_deleted``, else live rows only."""
    return true() if include_deleted else model.live()


def _stamp(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


async def soft_delete_user(
    session: AsyncSession, user: User, *, now: datetime | None = None
) -> int:
    """Tombstone ``user`` and revoke every key it still has. Returns the key count.

    Memberships are untouched; they are hidden by the member routes' user
    filter and come back with the user.
    """
    now = _stamp(now)
    user.deleted_at = now
    revoked = await execute_counted(
        session,
        update(APIKey)
        .where(APIKey.user_id == user.id, APIKey.live())
        .values(deleted_at=now, is_active=False),
    )
    await session.flush()
    return revoked


async def soft_delete_domain(
    session: AsyncSession, domain: Domain, *, now: datetime | None = None
) -> tuple[int, int]:
    """Tombstone ``domain``, its live recipients, and cancel their queued deliveries.

    Returns ``(recipients stamped, deliveries cancelled)``.
    """
    now = _stamp(now)
    domain.deleted_at = now
    stamped = await execute_counted(
        session,
        update(Recipient)
        .where(Recipient.domain_id == domain.id, Recipient.live())
        .values(deleted_at=now),
    )
    cancelled = await cancel_pending_deliveries(
        session, domain_id=domain.id, reason="Domain deleted", now=now
    )
    await session.flush()
    return stamped, cancelled


async def soft_delete_recipient(
    session: AsyncSession, recipient: Recipient, *, now: datetime | None = None
) -> int:
    """Tombstone ``recipient`` and cancel its queued deliveries. Returns the count."""
    now = _stamp(now)
    recipient.deleted_at = now
    cancelled = await cancel_pending_deliveries(
        session, recipient_ids=[recipient.id], reason="Recipient deleted", now=now
    )
    await session.flush()
    return cancelled


async def soft_delete_api_key(
    session: AsyncSession, api_key: APIKey, *, now: datetime | None = None
) -> None:
    """Tombstone ``api_key`` and deactivate it (the v0.4.0 pods' check)."""
    api_key.deleted_at = _stamp(now)
    api_key.is_active = False
    await session.flush()


async def restore_user(session: AsyncSession, user: User) -> None:
    """Clear the user's tombstone. Keys revoked at delete time stay revoked."""
    user.deleted_at = None


async def restore_domain(session: AsyncSession, domain: Domain) -> int:
    """Clear the domain's tombstone and those of the recipients stamped with it.

    Returns the number of recipients restored. The recipient UPDATE runs before
    the parent is cleared so that its autoflush cannot be the one to hit the
    name index (see module docstring).
    """
    stamp = domain.deleted_at
    if stamp is None:
        # Callers gate on require_tombstoned, but ``deleted_at == None`` would
        # compile to IS NULL and match every live recipient.
        return 0
    restored = await execute_counted(
        session,
        update(Recipient)
        .where(Recipient.domain_id == domain.id, Recipient.deleted_at == stamp)
        .values(deleted_at=None),
    )
    domain.deleted_at = None
    return restored


async def restore_recipient(session: AsyncSession, recipient: Recipient) -> None:
    """Clear the recipient's tombstone."""
    recipient.deleted_at = None


async def purge_user(session: AsyncSession, user: User) -> None:
    """Hard-delete a tombstoned user; keys and memberships cascade."""
    await session.delete(user)


async def purge_domain(session: AsyncSession, domain: Domain) -> None:
    """Hard-delete a tombstoned domain; recipients, rulesets, rules and members
    cascade, delivery-log rows keep their history with ``domain_id`` set NULL."""
    await session.delete(domain)


async def purge_recipient(session: AsyncSession, recipient: Recipient) -> None:
    """Hard-delete a tombstoned recipient; its delivery-log rows get ``recipient_id`` NULL."""
    await session.delete(recipient)
