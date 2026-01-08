"""Operations API endpoints (health, ready, delivery logs, test webhook)."""

import asyncio
import socket
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp import __version__
from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog
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


@router.get("/domains/{domain_id}/delivery-log", response_model=list[DeliveryLogResponse])
async def list_delivery_logs(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    status_filter: str | None = Query(None, alias="status"),
    message_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[DeliveryLogResponse]:
    """List delivery logs for a domain."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")
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
    stmt = select(DeliveryLog).where(DeliveryLog.id == log_id)
    result = await session.execute(stmt)
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Delivery log not found",
        )

    # Check access to the domain
    if log.domain_id:
        await get_domain_with_access(log.domain_id, auth, session, required_role="member")
    elif not auth.is_superuser():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    auth.require_scope("logs:read")
    return DeliveryLogDetailResponse.model_validate(log)


@router.post("/delivery-log/{log_id}/retry", response_model=MessageResponse)
async def retry_delivery_endpoint(
    log_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Retry a failed delivery."""
    # Get the log entry first
    stmt = select(DeliveryLog).where(DeliveryLog.id == log_id)
    result = await session.execute(stmt)
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Delivery log not found",
        )

    # Check access to the domain
    if log.domain_id:
        await get_domain_with_access(log.domain_id, auth, session, required_role="admin")
    elif not auth.is_superuser():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    auth.require_scope("logs:read")

    # Can only retry failed or exhausted deliveries
    if log.status not in ("failed", "exhausted"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot retry delivery with status '{log.status}'",
        )

    updated = await retry_delivery(session, log_id)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Delivery log not found",
        )

    return MessageResponse(message=f"Delivery {log_id} queued for retry")


# Test webhook endpoint


@router.post("/test-webhook", response_model=TestWebhookResponse)
async def test_webhook(
    data: TestWebhookRequest,
    auth: Auth,
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
    )
    elapsed_ms = (time.time() - start_time) * 1000

    return TestWebhookResponse(
        success=success,
        status_code=status_code,
        error=error,
        response_time_ms=round(elapsed_ms, 2),
    )
