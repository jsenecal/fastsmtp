"""Webhook dispatcher worker."""

import asyncio
import contextlib
import logging
from typing import Any

import httpx
from sqlalchemy import select

from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import DeliveryLog, Recipient
from fastsmtp.db.session import async_session
from fastsmtp.webhook.queue import get_pending_deliveries, mark_delivered, mark_failed

logger = logging.getLogger(__name__)


async def send_webhook(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    request_timeout: float = 30.0,
) -> tuple[bool, int | None, str | None]:
    """Send a webhook request.

    Args:
        url: Webhook URL
        payload: JSON payload to send
        headers: Additional headers
        request_timeout: Request timeout in seconds

    Returns:
        Tuple of (success, status_code, error_message)
    """
    all_headers = {
        "Content-Type": "application/json",
        "User-Agent": "FastSMTP/1.0",
    }
    if headers:
        all_headers.update(headers)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers=all_headers,
                timeout=request_timeout,
            )

            if response.is_success:
                return True, response.status_code, None
            else:
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                return False, response.status_code, error_msg

    except httpx.TimeoutException:
        return False, None, "Request timed out"
    except httpx.ConnectError as e:
        return False, None, f"Connection error: {e}"
    except httpx.HTTPError as e:
        return False, None, f"HTTP error: {e}"
    except Exception as e:
        logger.exception(f"Unexpected error sending webhook to {url}")
        return False, None, f"Unexpected error: {e}"


async def process_delivery(
    delivery: DeliveryLog,
    settings: Settings,
) -> None:
    """Process a single delivery.

    Args:
        delivery: DeliveryLog entry to process
        settings: Application settings
    """
    logger.debug(f"Processing delivery {delivery.id} to {delivery.webhook_url}")

    # Get recipient headers if available
    headers: dict[str, str] = {}
    if delivery.recipient_id:
        async with async_session() as session:
            stmt = select(Recipient).where(Recipient.id == delivery.recipient_id)
            result = await session.execute(stmt)
            recipient = result.scalar_one_or_none()
            if recipient and recipient.webhook_headers:
                headers = recipient.webhook_headers

    # Send the webhook
    success, status_code, error = await send_webhook(
        url=delivery.webhook_url,
        payload=delivery.payload,
        headers=headers,
        request_timeout=settings.webhook_timeout,
    )

    # Update delivery status
    async with async_session() as session:
        if success:
            await mark_delivered(session, delivery.id)
            await session.commit()
        else:
            await mark_failed(
                session,
                delivery.id,
                error or "Unknown error",
                status_code,
                settings,
            )
            await session.commit()


class WebhookWorker:
    """Background worker that processes the webhook delivery queue."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._running = False
        self._task: asyncio.Task | None = None

    async def process_batch(self) -> int:
        """Process a batch of pending deliveries.

        Returns:
            Number of deliveries processed
        """
        async with async_session() as session:
            deliveries = await get_pending_deliveries(
                session,
                batch_size=self.settings.worker_batch_size,
                instance_id=self.settings.instance_id,
            )
            await session.commit()

        if not deliveries:
            return 0

        logger.debug(f"Processing {len(deliveries)} deliveries")

        # Process deliveries concurrently
        tasks = [
            process_delivery(delivery, self.settings)
            for delivery in deliveries
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        return len(deliveries)

    async def run(self) -> None:
        """Run the worker loop."""
        self._running = True
        logger.info(f"Webhook worker started (instance: {self.settings.instance_id})")

        while self._running:
            try:
                processed = await self.process_batch()
                if processed == 0:
                    # No work available, wait before checking again
                    await asyncio.sleep(self.settings.worker_poll_interval)
            except Exception:
                logger.exception("Error in webhook worker loop")
                await asyncio.sleep(self.settings.worker_poll_interval)

        logger.info("Webhook worker stopped")

    def start(self) -> None:
        """Start the worker in the background."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run())

    def stop(self) -> None:
        """Stop the worker."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    async def wait(self) -> None:
        """Wait for the worker to finish."""
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
