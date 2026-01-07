"""Webhook dispatcher module."""

from fastsmtp.webhook.dispatcher import WebhookWorker, process_delivery, send_webhook
from fastsmtp.webhook.queue import (
    compute_payload_hash,
    enqueue_delivery,
    get_pending_deliveries,
    mark_delivered,
    mark_failed,
    retry_delivery,
)
from fastsmtp.webhook.url_validator import (
    SSRFError,
    is_url_safe,
    validate_webhook_url,
)

__all__ = [
    "SSRFError",
    "WebhookWorker",
    "compute_payload_hash",
    "enqueue_delivery",
    "get_pending_deliveries",
    "is_url_safe",
    "mark_delivered",
    "mark_failed",
    "process_delivery",
    "retry_delivery",
    "send_webhook",
    "validate_webhook_url",
]
