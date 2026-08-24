"""Operations API endpoints (health, ready, delivery logs, test webhook)."""

import asyncio
import socket
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp import __version__
from fastsmtp.api.validation import IncludeDeleted
from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog, Domain, Recipient
from fastsmtp.db.session import get_session
from fastsmtp.schemas import (
    DeliveryLogDetailResponse,
    DeliveryLogResponse,
    HealthResponse,
    MessageResponse,
    QueueStats,
    ReadyResponse,
    TestWebhookRequest,
    TestWebhookResponse,
)
from fastsmtp.webhook import retry_delivery, send_webhook
from fastsmtp.webhook.queue import RETRYABLE_STATUSES

router = APIRouter(tags=["operations"])


@router.get("/health", response_model=HealthResponse)
async def health_check(
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Health check endpoint - returns server status."""
    return HealthResponse(
        status="ok",
        version=__version__,
        instance_id=settings.instance_id,
    )


async def _check_smtp_port(host: str, port: int, connect_timeout: float = 2.0) -> str:
    """Check if SMTP port is accepting connections.

    Returns 'ok' if accepting, 'unavailable' if not.
    """
    try:
        loop = asyncio.get_running_loop()
        # Use async socket check to avoid blocking
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (host, port)),
                timeout=connect_timeout,
            )
            return "ok"
        finally:
            sock.close()
    except (OSError, TimeoutError):
        return "unavailable"


async def _get_queue_stats(session: AsyncSession) -> QueueStats:
    """Get delivery queue statistics."""
    # Count by status in a single query
    stmt = select(DeliveryLog.status, func.count(DeliveryLog.id)).group_by(DeliveryLog.status)
    result = await session.execute(stmt)
    counts = {row[0]: row[1] for row in result.fetchall()}

    return QueueStats(
        pending=counts.get(DeliveryStatus.PENDING, 0),
        failed=counts.get(DeliveryStatus.FAILED, 0),
        exhausted=counts.get(DeliveryStatus.EXHAUSTED, 0),
    )


@router.get("/ready", response_model=ReadyResponse)
async def ready_check(
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    include_queue: bool = Query(False, description="Include queue statistics"),
    include_smtp: bool = Query(False, description="Include SMTP server check"),
) -> ReadyResponse:
    """Readiness check endpoint - verifies system health.

    Query parameters:
    - include_queue: Include delivery queue statistics (pending/failed/exhausted counts)
    - include_smtp: Check if SMTP server port is accepting connections
    """
    # Check database connectivity
    try:
        await session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not ready",
        ) from e

    response = ReadyResponse(
        status="ok",
        database=db_status,
    )

    # Optional: Check SMTP server
    if include_smtp:
        response.smtp = await _check_smtp_port(
            settings.smtp_host,
            settings.smtp_port,
        )

    # Optional: Get queue statistics
    if include_queue:
        response.queue = await _get_queue_stats(session)

    return response


# Delivery Log endpoints


async def _get_delivery_log_with_access(
    session: AsyncSession,
    log_id: uuid.UUID,
    auth: Auth,
    *,
    required_role: str,
    with_recipient: bool = False,
) -> tuple[DeliveryLog, Domain | None]:
    """Load a delivery log and check the caller's access to its domain.

    The domain is resolved with ``include_deleted=True`` so the history of a
    soft-deleted domain stays readable to its owners and superusers - a plain
    member gets the helper's 404, the same as for a domain that never existed.
    Rows orphaned by a purge (``domain_id`` NULL) are superuser-only, as they
    were for a hard delete. Returns the domain (possibly tombstoned) so
    callers can refuse mutations on it; ``with_recipient`` eager-loads the
    recipient (``lazy="raise"``) for callers that check its tombstone too.
    """
    stmt = select(DeliveryLog).where(DeliveryLog.id == log_id)
    if with_recipient:
        stmt = stmt.options(selectinload(DeliveryLog.recipient))
    result = await session.execute(stmt)
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Delivery log not found",
        )

    domain: Domain | None = None
    if log.domain_id:
        domain = await get_domain_with_access(
            log.domain_id,
            auth,
            session,
            required_role=required_role,
            include_deleted=True,
        )
    elif not auth.is_superuser():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    auth.require_scope("logs:read")
    return log, domain


async def _tombstoned_now(
    session: AsyncSession, model: type[Domain] | type[Recipient], row_id: uuid.UUID
) -> bool:
    """Fresh read of one row's tombstone, bypassing the identity map.

    A row that is gone counts as deleted: it was purged since this request
    loaded it, which is the one thing ``session.refresh`` cannot survive.
    """
    row = (await session.execute(select(model.deleted_at).where(model.id == row_id))).first()
    return row is None or row[0] is not None


async def _retry_refused_detail(
    session: AsyncSession, domain: Domain | None, recipient: Recipient | None
) -> str:
    """Why the guarded retry UPDATE matched nothing.

    The rows this request loaded may predate the tombstone that blocked the
    statement, so the answer is read fresh. When neither is tombstoned the
    status changed under us (a concurrent retry, or the worker).
    """
    if domain is not None and await _tombstoned_now(session, Domain, domain.id):
        return "Domain is deleted; restore it before retrying"
    if recipient is not None and await _tombstoned_now(session, Recipient, recipient.id):
        return "Recipient is deleted; restore it before retrying"
    return "Delivery is no longer retryable"


@router.get("/domains/{domain_id}/delivery-log", response_model=list[DeliveryLogResponse])
async def list_delivery_logs(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    status_filter: str | None = Query(None, alias="status"),
    message_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_deleted: IncludeDeleted = False,
) -> list[DeliveryLogResponse]:
    """List delivery logs for a domain.

    ``include_deleted`` also resolves a soft-deleted domain, so its history
    stays readable after the delete; it is owner-only, elevated before the
    lookup so a lesser role gets 403 whether or not a tombstone exists.
    """
    required_role = "owner" if include_deleted else "member"
    await get_domain_with_access(
        domain_id,
        auth,
        session,
        required_role=required_role,
        include_deleted=include_deleted,
    )
    auth.require_scope("logs:read")

    stmt = (
        select(DeliveryLog)
        .where(DeliveryLog.domain_id == domain_id)
        .order_by(DeliveryLog.created_at.desc())
    )

    if status_filter:
        stmt = stmt.where(DeliveryLog.status == status_filter)
    if message_id:
        stmt = stmt.where(DeliveryLog.message_id == message_id)

    stmt = stmt.limit(limit).offset(offset)

    result = await session.execute(stmt)
    logs = result.scalars().all()
    return [DeliveryLogResponse.model_validate(log) for log in logs]


@router.get("/delivery-log/{log_id}", response_model=DeliveryLogDetailResponse)
async def get_delivery_log(
    log_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> DeliveryLogDetailResponse:
    """Get a delivery log entry with full payload."""
    log, _ = await _get_delivery_log_with_access(session, log_id, auth, required_role="member")
    return DeliveryLogDetailResponse.model_validate(log)


@router.post("/delivery-log/{log_id}/retry", response_model=MessageResponse)
async def retry_delivery_endpoint(
    log_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Retry a failed, exhausted or cancelled delivery.

    A cancelled delivery is re-armed only once the recipient and domain it
    was cancelled for are live again; until then the answer is 409 and the
    operator restores them first. That decision is the queue's guarded
    UPDATE, not a check made earlier in the request, so a delete that lands
    mid-request still blocks the retry.
    """
    log, domain = await _get_delivery_log_with_access(
        session, log_id, auth, required_role="admin", with_recipient=True
    )

    if log.status not in RETRYABLE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot retry delivery with status '{log.status}'",
        )

    if await retry_delivery(session, log_id) is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=await _retry_refused_detail(session, domain, log.recipient),
        )

    return MessageResponse(message=f"Delivery {log_id} queued for retry")


# Test webhook endpoint


@router.post("/test-webhook", response_model=TestWebhookResponse)
async def test_webhook(
    data: TestWebhookRequest,
    auth: Auth,
    settings: Settings = Depends(get_settings),
) -> TestWebhookResponse:
    """Test a webhook URL by sending a test payload."""
    # Require authentication
    if not auth.is_superuser():
        auth.require_scope("recipients:write")

    # Build test payload
    payload = {
        "message_id": "<test@fastsmtp.local>",
        "from": data.from_address,
        "to": data.to_address,
        "subject": data.subject,
        "body_text": data.body,
        "body_html": "",
        "headers": {
            "From": data.from_address,
            "To": data.to_address,
            "Subject": data.subject,
        },
        "envelope_from": data.from_address,
        "envelope_to": [data.to_address],
        "attachments": [],
        "has_attachments": False,
        "dkim_result": "none",
        "spf_result": "none",
        "tags": ["test"],
        "_test": True,
    }

    # Send the webhook
    start_time = time.time()
    success, status_code, error = await send_webhook(
        url=str(data.webhook_url),
        payload=payload,
        request_timeout=30.0,
        allowed_internal_domains=settings.webhook_allowed_internal_domains,
    )
    elapsed_ms = (time.time() - start_time) * 1000

    return TestWebhookResponse(
        success=success,
        status_code=status_code,
        error=error,
        response_time_ms=round(elapsed_ms, 2),
    )
