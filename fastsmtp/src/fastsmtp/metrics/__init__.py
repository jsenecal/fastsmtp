"""FastSMTP Prometheus metrics."""

from fastsmtp.metrics.definitions import (
    AUTH_RESULTS,
    QUEUE_DEPTH,
    REQUEST_DURATION,
    REQUEST_TOTAL,
    SMTP_MESSAGE_SIZE,
    SMTP_MESSAGES_TOTAL,
    WEBHOOK_DELIVERIES_TOTAL,
    WEBHOOK_DELIVERY_DURATION,
)
from fastsmtp.metrics.middleware import MetricsMiddleware

__all__ = [
    "MetricsMiddleware",
    "REQUEST_TOTAL",
    "REQUEST_DURATION",
    "WEBHOOK_DELIVERIES_TOTAL",
    "WEBHOOK_DELIVERY_DURATION",
    "SMTP_MESSAGES_TOTAL",
    "SMTP_MESSAGE_SIZE",
    "AUTH_RESULTS",
    "QUEUE_DEPTH",
]
