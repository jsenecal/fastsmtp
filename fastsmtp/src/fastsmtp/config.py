"""FastSMTP configuration using pydantic-settings."""

import os
from functools import lru_cache
from pathlib import Path
from uuid import uuid4

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="FASTSMTP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # SMTP Server
    smtp_host: str = "0.0.0.0"
    smtp_port: int = 2525
    smtp_tls_port: int = 4650
    smtp_tls_cert: Path | None = None
    smtp_tls_key: Path | None = None
    smtp_require_starttls: bool = False
    smtp_max_message_size: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="Maximum email message size in bytes",
    )
    smtp_tls_hot_reload: bool = Field(
        default=False,
        description="Enable automatic TLS certificate reload when files change.",
    )
    smtp_tls_reload_interval: int = Field(
        default=300,
        description="Interval (seconds) to check for TLS certificate changes. Default 5 minutes.",
    )

    # Email authentication
    smtp_verify_dkim: bool = True
    smtp_verify_spf: bool = True
    smtp_reject_dkim_fail: bool = False
    smtp_reject_spf_fail: bool = False

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # CORS settings
    cors_origins: list[str] = Field(
        default_factory=list,
        description="Allowed CORS origins. Empty disables CORS. ['*'] for dev only.",
    )

    # Database (PostgreSQL)
    database_url: str = Field(
        default="postgresql+asyncpg://fastsmtp:fastsmtp@localhost:5432/fastsmtp",
        description="Database connection URL (postgresql+asyncpg://...)",
    )
    database_pool_size: int = 5
    database_pool_max_overflow: int = 10
    database_echo: bool = False

    # Webhook defaults
    webhook_timeout: int = 30
    webhook_max_retries: int = 5
    webhook_retry_base_delay: float = 1.0
    webhook_max_inline_attachment_size: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="Maximum attachment size to include inline in webhook payload (bytes). "
        "Only applies when attachment_storage='inline'. Larger attachments include metadata only.",
    )
    webhook_max_inline_payload_size: int = Field(
        default=50 * 1024 * 1024,  # 50MB
        description="Maximum total webhook payload size for inline storage (bytes). "
        "Payloads exceeding this will have body/attachments truncated.",
    )
    webhook_allowed_internal_domains: list[str] = Field(
        default_factory=list,
        description="Domains allowed to bypass SSRF protection (e.g., internal services). "
        "Use sparingly and only for trusted internal services.",
    )

    # Dead Letter Queue
    dlq_webhook_url: str | None = Field(
        default=None,
        description="Webhook URL to notify when deliveries are exhausted (dead letter queue). "
        "Receives JSON payload with delivery details for alerting/monitoring.",
    )

    # Queue Backpressure
    queue_max_pending: int | None = Field(
        default=None,
        description="Maximum pending deliveries before rejecting new emails. "
        "None = unlimited (default). Prevents unbounded queue growth.",
    )
    queue_backpressure_action: str = Field(
        default="reject",
        description="Action when queue is full: 'reject' (451 temp error) or "
        "'drop' (accept but don't queue). Reject allows sender to retry later.",
    )

    # Security
    root_api_key: SecretStr = Field(
        ...,
        description="Root API key for initial superuser access",
    )
    api_key_hash_algorithm: str = "sha256"
    encryption_key: str | None = Field(
        default=None,
        description="32-byte key for encrypting sensitive data at rest (e.g., webhook headers)",
    )

    # K8s/Operations
    instance_id: str = Field(default_factory=lambda: os.getenv("HOSTNAME", uuid4().hex[:8]))

    # Worker settings
    worker_poll_interval: float = 1.0
    worker_batch_size: int = 10

    # Delivery log cleanup
    delivery_log_retention_days: int = 90
    delivery_log_cleanup_interval_hours: int = 24
    delivery_log_cleanup_enabled: bool = True
    delivery_log_cleanup_batch_size: int = 1000
    delivery_log_cleanup_max_per_run: int = Field(
        default=100000,
        description="Maximum records to delete per cleanup run. Prevents long-running deletes.",
    )
    delivery_log_cleanup_batch_delay_ms: int = Field(
        default=100,
        description="Delay between batch deletes (ms) to reduce database load.",
    )

    # Rules engine
    regex_timeout_seconds: float = Field(
        default=1.0,
        description="Timeout for regex matching in rules engine (ReDoS protection)",
    )
    regex_thread_pool_size: int | None = Field(
        default=None,
        description="Thread pool size for regex operations (default: CPU count, min 2)",
    )
    rules_max_body_size: int = Field(
        default=1024 * 1024,  # 1MB
        description="Maximum body size (bytes) to evaluate in rules. Larger bodies are truncated.",
    )

    # Rate limiting (requires Redis for distributed)
    redis_url: str | None = Field(
        default=None,
        description="Redis/Valkey URL for rate limiting (e.g., redis://localhost:6379/0)",
    )
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting (requires redis_url to be set)",
    )
    rate_limit_requests_per_minute: int = Field(
        default=100,
        description="Maximum API requests per minute per API key",
    )
    rate_limit_auth_attempts_per_minute: int = Field(
        default=5,
        description="Maximum authentication attempts per minute per IP",
    )

    # SMTP Rate Limiting (in-memory, per-instance)
    smtp_rate_limit_enabled: bool = Field(
        default=True,
        description="Enable SMTP rate limiting per client IP",
    )
    smtp_rate_limit_connections_per_minute: int = Field(
        default=30,
        description="Maximum SMTP connections per minute per IP",
    )
    smtp_rate_limit_messages_per_minute: int = Field(
        default=60,
        description="Maximum SMTP messages per minute per IP",
    )
    smtp_rate_limit_recipients_per_message: int = Field(
        default=100,
        description="Maximum recipients per SMTP message",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached settings instance.

    Settings are cached after first load. Use clear_settings_cache()
    to reload settings (e.g., in tests or after environment changes).
    """
    # root_api_key is loaded from environment by pydantic-settings
    return Settings()  # type: ignore[call-arg]


def clear_settings_cache() -> None:
    """Clear the settings cache.

    Call this to force settings to be reloaded on the next get_settings() call.
    Useful in tests to ensure test isolation or when environment variables change.
    """
    get_settings.cache_clear()
