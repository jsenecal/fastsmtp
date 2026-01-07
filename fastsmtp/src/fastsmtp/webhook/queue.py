"""Database-backed webhook delivery queue."""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.config import Settings, get_settings
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog
from fastsmtp.smtp.validation import EmailAuthResult

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


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

    stmt = select(func.count(DeliveryLog.id)).where(
        DeliveryLog.status.in_([DeliveryStatus.PENDING, DeliveryStatus.FAILED])
    )
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

    # Select pending deliveries that are due for retry
    # Use selectinload to eagerly load recipients (fixes N+1 query issue)
    stmt = (
        select(DeliveryLog)
        .options(selectinload(DeliveryLog.recipient))
        .where(
            DeliveryLog.status.in_([DeliveryStatus.PENDING, DeliveryStatus.FAILED]),
            DeliveryLog.next_retry_at <= now,
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
    """Mark a delivery as successfully delivered."""
    stmt = (
        update(DeliveryLog)
        .where(DeliveryLog.id == delivery_id)
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
    """Mark a delivery as failed and schedule retry if applicable."""
    settings = settings or get_settings()

    # Get current delivery state
    stmt = select(DeliveryLog).where(DeliveryLog.id == delivery_id)
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if not delivery:
        logger.error(f"Delivery {delivery_id} not found")
        return

    new_attempts = delivery.attempts + 1

    now = datetime.now(UTC)

    is_exhausted = new_attempts >= settings.webhook_max_retries

    if is_exhausted:
        # Exhausted all retries
        update_stmt = (
            update(DeliveryLog)
            .where(DeliveryLog.id == delivery_id)
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
            .where(DeliveryLog.id == delivery_id)
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

    await session.execute(update_stmt)
    await session.flush()

    # Send DLQ notification for exhausted deliveries (fire-and-forget)
    if is_exhausted and settings.dlq_webhook_url:
        # Update delivery object with new values for notification
        delivery.attempts = new_attempts
        delivery.last_error = error
        delivery.last_status_code = status_code
        # Schedule as background task to not block the main flow
        asyncio.create_task(_send_dlq_notification(delivery, settings))


async def retry_delivery(
    session: AsyncSession,
    delivery_id: uuid.UUID,
) -> DeliveryLog | None:
    """Reset a delivery for immediate retry.

    Args:
        session: Database session
        delivery_id: Delivery ID to retry

    Returns:
        Updated DeliveryLog or None if not found
    """
    stmt = select(DeliveryLog).where(DeliveryLog.id == delivery_id)
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if not delivery:
        return None

    # Only allow retrying failed/exhausted deliveries
    if delivery.status not in (DeliveryStatus.FAILED, DeliveryStatus.EXHAUSTED):
        logger.warning(f"Cannot retry delivery {delivery_id} with status {delivery.status}")
        return delivery

    now = datetime.now(UTC)
    update_stmt = (
        update(DeliveryLog)
        .where(DeliveryLog.id == delivery_id)
        .values(
            status=DeliveryStatus.PENDING,
            next_retry_at=now,
            updated_at=now,  # Explicit update since onupdate doesn't trigger
        )
    )
    await session.execute(update_stmt)
    await session.flush()
    await session.refresh(delivery)

    logger.info(f"Delivery {delivery_id} queued for retry")
    return delivery
