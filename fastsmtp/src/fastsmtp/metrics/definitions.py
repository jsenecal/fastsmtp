"""Prometheus metrics definitions for FastSMTP."""

from prometheus_client import Counter, Gauge, Histogram

# HTTP Request metrics
REQUEST_TOTAL = Counter(
    "fastsmtp_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

REQUEST_DURATION = Histogram(
    "fastsmtp_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Webhook delivery metrics
WEBHOOK_DELIVERIES_TOTAL = Counter(
    "fastsmtp_webhook_deliveries_total",
    "Total webhook deliveries",
    ["status"],  # delivered, failed, exhausted
)

WEBHOOK_DELIVERY_DURATION = Histogram(
    "fastsmtp_webhook_delivery_duration_seconds",
    "Webhook delivery duration in seconds",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

# SMTP message metrics
SMTP_MESSAGES_TOTAL = Counter(
    "fastsmtp_smtp_messages_total",
    "Total SMTP messages received",
    ["result"],  # accepted, rejected
)

SMTP_MESSAGE_SIZE = Histogram(
    "fastsmtp_smtp_message_size_bytes",
    "SMTP message size in bytes",
    buckets=(1024, 10240, 102400, 1048576, 10485760),  # 1KB, 10KB, 100KB, 1MB, 10MB
)

# Queue metrics
QUEUE_DEPTH = Gauge(
    "fastsmtp_queue_depth",
    "Number of pending webhook deliveries",
    ["status"],  # pending, failed
)

# Authentication metrics
AUTH_RESULTS = Counter(
    "fastsmtp_auth_results_total",
    "Email authentication results",
    ["type", "result"],  # type: dkim/spf, result: pass/fail/none
)
