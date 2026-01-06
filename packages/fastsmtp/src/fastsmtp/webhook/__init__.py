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

__all__ = [
    "WebhookWorker",
    "compute_payload_hash",
    "enqueue_delivery",
    "get_pending_deliveries",
    "mark_delivered",
    "mark_failed",
    "process_delivery",
    "retry_delivery",
    "send_webhook",
]
