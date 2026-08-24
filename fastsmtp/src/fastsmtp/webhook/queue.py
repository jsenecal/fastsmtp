"""Database-backed webhook delivery queue.

Soft delete and the ``cancelled`` status
----------------------------------------
A soft-deleted recipient keeps its row, so a queued delivery would otherwise
keep going out - with the recipient's authentication headers - for the whole
retry window. Three layers close that:

1. Delete-time cancellation: :func:`cancel_pending_deliveries` moves every
   pending/failed delivery of the tombstoned recipient(s) or domain to
   ``cancelled`` in the same transaction as the tombstone.
2. Claim-time exclusion: :func:`get_pending_deliveries` never hands out a
   delivery whose recipient or domain is tombstoned.
3. The dispatcher guard (``webhook.dispatcher``) re-checks the loaded
   recipient and its domain before building headers and calls
   :func:`mark_cancelled`.

``cancelled`` is sticky: :func:`mark_failed` and :func:`mark_delivered` refuse
to overwrite it, so a delivery claimed just before the tombstone landed cannot
resurrect itself as ``failed`` and be retried. Residual race: a delivery whose
HTTP call was already in flight when the tombstone committed completes once;
its status is then whatever the guards allow, never a retry. Only
:func:`retry_delivery` (the explicit operator endpoint) re-arms a cancelled
delivery.
"""

import asyncio
import hashlib
import json
import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import ColumnElement, exists, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.config import Settings, get_settings
from fastsmtp.db.bulk import execute_counted
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog, Domain, Recipient
from fastsmtp.smtp.validation import EmailAuthResult

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# The statuses the worker retries. ``cancelled`` is deliberately absent: it is
# terminal until an operator re-arms it through retry_delivery.
QUEUED_STATUSES = (DeliveryStatus.PENDING, DeliveryStatus.FAILED)

# The statuses the explicit retry endpoint re-arms. ``cancelled`` is here
# because that endpoint is the one path that revives a cancelled delivery, and
# only once its recipient and domain are live again (the UPDATE in
# retry_delivery enforces that). The API answers its 400 from this tuple.
RETRYABLE_STATUSES = (
    DeliveryStatus.FAILED,
    DeliveryStatus.EXHAUSTED,
    DeliveryStatus.CANCELLED,
)


def _not_cancelled() -> ColumnElement[bool]:
    """Guard for UPDATEs that must not overwrite a sticky ``cancelled`` status."""
    return DeliveryLog.status != DeliveryStatus.CANCELLED


def _recipient_and_domain_live() -> tuple[ColumnElement[bool], ColumnElement[bool]]:
    """Predicates that exclude deliveries whose recipient or domain is tombstoned.

    Shared by the claim query and the retry UPDATE, so a delivery the worker
    would refuse to send can never be re-armed either. Written as NOT EXISTS
    subqueries rather than outer joins: PostgreSQL rejects FOR UPDATE on the
    nullable side of an outer join, and the claim query's row lock must keep
    covering delivery_log only. Legacy rows with ``recipient_id`` NULL pass
    the recipient predicate and are judged on their domain alone.
    """
    return (
        ~exists().where(Recipient.id == DeliveryLog.recipient_id, ~Recipient.live()),
        ~exists().where(Domain.id == DeliveryLog.domain_id, ~Domain.live()),
    )


def _cancelled_values(reason: str, now: datetime) -> dict[str, Any]:
    """Column values that move a delivery to ``cancelled``; shared by both writers."""
    return {
        "status": DeliveryStatus.CANCELLED,
        "next_retry_at": None,
        "last_error": reason,
        "updated_at": now,  # Explicit update since onupdate doesn't trigger
    }


async def _send_dlq_notification(
    delivery: DeliveryLog,
    settings: Settings,
) -> None:
    """Send a dead letter queue notification for an exhausted delivery.

    This is fire-and-forget - failures are logged but don't affect the main flow.
    """
    if not settings.dlq_webhook_url:
        return

    # Import here to avoid circular imports
    from fastsmtp.webhook.dispatcher import send_webhook
    from fastsmtp.webhook.url_validator import create_ssrf_safe_client

    dlq_payload = {
        "event": "delivery.exhausted",
        "delivery_id": str(delivery.id),
        "message_id": delivery.message_id,
        "domain_id": str(delivery.domain_id) if delivery.domain_id else None,
        "webhook_url": delivery.webhook_url,
        "attempts": delivery.attempts,
        "last_error": delivery.last_error,
        "last_status_code": delivery.last_status_code,
        "created_at": delivery.created_at.isoformat() if delivery.created_at else None,
        "exhausted_at": datetime.now(UTC).isoformat(),
    }

    try:
        async with create_ssrf_safe_client(
            timeout=10.0,
            allowed_internal_domains=settings.webhook_allowed_internal_domains,
        ) as client:
            success, status_code, error = await send_webhook(
                url=settings.dlq_webhook_url,
                payload=dlq_payload,
                headers={"X-FastSMTP-Event": "dlq"},
                request_timeout=10.0,
                client=client,
                validate_url=True,
                allowed_internal_domains=settings.webhook_allowed_internal_domains,
            )
            if success:
                logger.info(f"DLQ notification sent for delivery {delivery.id}")
            else:
                logger.warning(
                    f"DLQ notification failed for delivery {delivery.id}: "
                    f"status={status_code}, error={error}"
                )
    except Exception:
        logger.exception(f"Failed to send DLQ notification for delivery {delivery.id}")


async def get_pending_count(session: AsyncSession) -> int:
    """Get the count of pending and failed (retry) deliveries.

    Used for backpressure checking.
    """
    from sqlalchemy import func

    stmt = select(func.count(DeliveryLog.id)).where(DeliveryLog.status.in_(QUEUED_STATUSES))
    result = await session.execute(stmt)
    return result.scalar() or 0


async def check_queue_backpressure(
    session: AsyncSession,
    settings: Settings | None = None,
) -> tuple[bool, int]:
    """Check if the delivery queue is under backpressure.

    Args:
        session: Database session
        settings: Application settings

    Returns:
        Tuple of (is_backpressured, current_count)
    """
    settings = settings or get_settings()

    # No limit configured = no backpressure
    if settings.queue_max_pending is None:
        return False, 0

    count = await get_pending_count(session)
    return count >= settings.queue_max_pending, count


def compute_payload_hash(payload: dict) -> str:
    """Compute a hash of the payload for deduplication."""
    payload_json = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(payload_json.encode()).hexdigest()


async def enqueue_delivery(
    session: AsyncSession,
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID | None,
    message_id: str,
    webhook_url: str,
    payload: dict,
    auth_result: EmailAuthResult | None = None,
    settings: Settings | None = None,
) -> DeliveryLog:
    """Enqueue a webhook delivery in the database.

    Args:
        session: Database session
        domain_id: Domain ID
        recipient_id: Recipient ID (optional)
        message_id: Email Message-ID
        webhook_url: URL to deliver to
        payload: Webhook payload
        auth_result: Email authentication result
        settings: Application settings

    Returns:
        Created DeliveryLog entry
    """
    settings = settings or get_settings()

    delivery = DeliveryLog(
        domain_id=domain_id,
        recipient_id=recipient_id,
        message_id=message_id,
        webhook_url=webhook_url,
        payload_hash=compute_payload_hash(payload),
        payload=payload,
        status=DeliveryStatus.PENDING,
        attempts=0,
        next_retry_at=datetime.now(UTC),
        instance_id=settings.instance_id,
        dkim_result=auth_result.dkim_result if auth_result else None,
        spf_result=auth_result.spf_result if auth_result else None,
    )
    session.add(delivery)
    await session.flush()
    await session.refresh(delivery)

    logger.debug(f"Enqueued delivery {delivery.id} for message {message_id}")
    return delivery


async def get_pending_deliveries(
    session: AsyncSession,
    batch_size: int = 10,
    instance_id: str | None = None,
) -> list[DeliveryLog]:
    """Get pending deliveries ready for processing.

    Uses SELECT FOR UPDATE SKIP LOCKED for safe concurrent processing
    in a multi-instance K8s environment.

    Args:
        session: Database session
        batch_size: Maximum number of deliveries to fetch
        instance_id: Instance ID to claim deliveries for

    Returns:
        List of DeliveryLog entries to process
    """
    settings = get_settings()
    instance_id = instance_id or settings.instance_id
    now = datetime.now(UTC)

    # Select pending deliveries that are due for retry. The recipient and its
    # domain are eagerly loaded (no N+1, and the dispatcher guard reads both
    # without a lazy load); tombstoned recipients and domains are excluded by
    # the shared predicates, shaped so the row lock below stays valid.
    stmt = (
        select(DeliveryLog)
        .options(selectinload(DeliveryLog.recipient).selectinload(Recipient.domain))
        .where(
            DeliveryLog.status.in_(QUEUED_STATUSES),
            DeliveryLog.next_retry_at <= now,
            *_recipient_and_domain_live(),
        )
        .order_by(DeliveryLog.next_retry_at)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    )

    result = await session.execute(stmt)
    deliveries = list(result.scalars().all())

    # Claim these deliveries for this instance by updating the locked rows directly
    # Using ORM objects ensures we update the exact same rows that are locked
    for delivery in deliveries:
        delivery.instance_id = instance_id

    # Flush to persist the changes while rows are still locked
    if deliveries:
        await session.flush()

    return deliveries


async def mark_delivered(
    session: AsyncSession,
    delivery_id: uuid.UUID,
) -> None:
    """Mark a delivery as successfully delivered.

    A delivery cancelled while its request was in flight stays cancelled.
    """
    stmt = (
        update(DeliveryLog)
        .where(DeliveryLog.id == delivery_id, _not_cancelled())
        .values(
            status=DeliveryStatus.DELIVERED,
            delivered_at=datetime.now(UTC),
            next_retry_at=None,
            last_error=None,
            updated_at=datetime.now(UTC),  # Explicit update since onupdate doesn't trigger
        )
    )
    await session.execute(stmt)
    await session.flush()
    logger.info(f"Delivery {delivery_id} marked as delivered")


async def mark_failed(
    session: AsyncSession,
    delivery_id: uuid.UUID,
    error: str,
    status_code: int | None = None,
    settings: Settings | None = None,
) -> None:
    """Mark a delivery as failed and schedule retry if applicable.

    A delivery cancelled while its request was in flight stays cancelled: no
    retry is scheduled and no DLQ notification goes out.
    """
    settings = settings or get_settings()

    # Get current delivery state
    stmt = select(DeliveryLog).where(DeliveryLog.id == delivery_id)
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if not delivery:
        logger.error(f"Delivery {delivery_id} not found")
        return

    if delivery.status == DeliveryStatus.CANCELLED:
        logger.info(f"Delivery {delivery_id} was cancelled; not recording the failure")
        return

    new_attempts = delivery.attempts + 1

    now = datetime.now(UTC)

    is_exhausted = new_attempts >= settings.webhook_max_retries

    if is_exhausted:
        # Exhausted all retries
        update_stmt = (
            update(DeliveryLog)
            .where(DeliveryLog.id == delivery_id, _not_cancelled())
            .values(
                status=DeliveryStatus.EXHAUSTED,
                attempts=new_attempts,
                last_error=error,
                last_status_code=status_code,
                next_retry_at=None,
                updated_at=now,  # Explicit update since onupdate doesn't trigger
            )
        )
        logger.warning(f"Delivery {delivery_id} exhausted after {new_attempts} attempts")
    else:
        # Calculate next retry with exponential backoff
        delay = settings.webhook_retry_base_delay * (2 ** (new_attempts - 1))
        next_retry = now + timedelta(seconds=delay)

        update_stmt = (
            update(DeliveryLog)
            .where(DeliveryLog.id == delivery_id, _not_cancelled())
            .values(
                status=DeliveryStatus.FAILED,
                attempts=new_attempts,
                last_error=error,
                last_status_code=status_code,
                next_retry_at=next_retry,
                updated_at=now,  # Explicit update since onupdate doesn't trigger
            )
        )
        logger.info(
            f"Delivery {delivery_id} failed (attempt {new_attempts}), next retry at {next_retry}"
        )

    # The loaded row can be stale: a select() does not refresh an object the
    # identity map already holds, so a cancellation committed by another
    # transaction after this delivery was claimed is only visible as the
    # guarded UPDATE matching nothing. That, not the early check above, is
    # what keeps the DLQ quiet for a cancelled delivery.
    matched = await execute_counted(session, update_stmt)
    await session.flush()
    if matched == 0:
        logger.info(f"Delivery {delivery_id} was cancelled under us; not recording the failure")
        return

    # Send DLQ notification for exhausted deliveries (fire-and-forget)
    if is_exhausted and settings.dlq_webhook_url:
        # Update delivery object with new values for notification
        delivery.attempts = new_attempts
        delivery.last_error = error
        delivery.last_status_code = status_code
        # Schedule as background task to not block the main flow
        asyncio.create_task(_send_dlq_notification(delivery, settings))


async def cancel_pending_deliveries(
    session: AsyncSession,
    *,
    recipient_ids: Sequence[uuid.UUID] = (),
    domain_id: uuid.UUID | None = None,
    reason: str,
    now: datetime,
) -> int:
    """Cancel every queued delivery of the given recipients and/or domain.

    Called by ``db.soft_delete`` in the same transaction as the tombstone, so
    nothing waits for the worker and backpressure drops immediately. Only
    ``pending`` and ``failed`` rows move; delivered and exhausted history is
    untouched. Targeting by ``domain_id`` also covers legacy rows whose
    ``recipient_id`` was nulled by a pre-0.5 hard delete.

    Args:
        session: Database session
        recipient_ids: Recipients whose deliveries to cancel
        domain_id: Domain whose deliveries to cancel
        reason: Stored in ``last_error`` ("Recipient deleted" / "Domain deleted")
        now: Timestamp written to ``updated_at`` (the tombstone's own)

    Returns:
        Number of deliveries cancelled
    """
    targets: list[ColumnElement[bool]] = []
    if recipient_ids:
        targets.append(DeliveryLog.recipient_id.in_(list(recipient_ids)))
    if domain_id is not None:
        targets.append(DeliveryLog.domain_id == domain_id)
    if not targets:
        return 0

    stmt = (
        update(DeliveryLog)
        .where(DeliveryLog.status.in_(QUEUED_STATUSES), or_(*targets))
        .values(**_cancelled_values(reason, now))
    )
    cancelled = await execute_counted(session, stmt)
    await session.flush()
    if cancelled:
        logger.info(f"Cancelled {cancelled} queued deliveries: {reason}")
    return cancelled


async def mark_cancelled(
    session: AsyncSession,
    delivery_id: uuid.UUID,
    reason: str,
) -> None:
    """Cancel a single claimed delivery; used by the dispatcher guard."""
    stmt = (
        update(DeliveryLog)
        .where(DeliveryLog.id == delivery_id)
        .values(**_cancelled_values(reason, datetime.now(UTC)))
    )
    await session.execute(stmt)
    await session.flush()
    logger.info(f"Delivery {delivery_id} cancelled: {reason}")


async def retry_delivery(
    session: AsyncSession,
    delivery_id: uuid.UUID,
) -> DeliveryLog | None:
    """Reset a delivery for immediate retry.

    The UPDATE decides: it matches only a row in ``RETRYABLE_STATUSES`` whose
    recipient and domain are live, by the claim query's own predicates. A
    tombstone that lands between a caller's checks and this statement still
    blocks the retry, so there is no check-then-act window to exploit, and the
    worker can never be handed a delivery the retry endpoint re-armed for a
    deleted endpoint.

    Args:
        session: Database session
        delivery_id: Delivery ID to retry

    Returns:
        The re-armed delivery, or ``None`` when nothing was re-armed: no such
        delivery, a status outside ``RETRYABLE_STATUSES``, or a tombstoned
        recipient or domain. The loaded row is not consulted for any of that,
        since it may be stale; the UPDATE's row count is the one answer.
    """
    stmt = select(DeliveryLog).where(DeliveryLog.id == delivery_id)
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if not delivery:
        return None

    now = datetime.now(UTC)
    update_stmt = (
        update(DeliveryLog)
        .where(
            DeliveryLog.id == delivery_id,
            DeliveryLog.status.in_(RETRYABLE_STATUSES),
            *_recipient_and_domain_live(),
        )
        .values(
            status=DeliveryStatus.PENDING,
            next_retry_at=now,
            updated_at=now,  # Explicit update since onupdate doesn't trigger
        )
    )
    # execute_counted synchronizes by "fetch", so the returned object already
    # carries the new state; no refresh round trip.
    matched = await execute_counted(session, update_stmt)
    await session.flush()
    if matched == 0:
        logger.info(
            f"Delivery {delivery_id} not re-armed: not in a retryable status, "
            "or its recipient or domain is deleted"
        )
        return None

    logger.info(f"Delivery {delivery_id} queued for retry")
    return delivery
