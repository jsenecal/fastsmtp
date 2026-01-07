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
        description="Allowed CORS origins. Empty list disables CORS. Use ['*'] for development only.",
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

    # Security
    root_api_key: SecretStr = Field(
        ...,
        description="Root API key for initial superuser access",
    )
    api_key_hash_algorithm: str = "sha256"

    # K8s/Operations
    instance_id: str = Field(
        default_factory=lambda: os.getenv("HOSTNAME", uuid4().hex[:8])
    )

    # Worker settings
    worker_poll_interval: float = 1.0
    worker_batch_size: int = 10

    # Delivery log cleanup
    delivery_log_retention_days: int = 90
    delivery_log_cleanup_interval_hours: int = 24
    delivery_log_cleanup_enabled: bool = True
    delivery_log_cleanup_batch_size: int = 1000


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
