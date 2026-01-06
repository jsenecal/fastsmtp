"""Tests for delivery log cleanup functionality."""

import os
from datetime import UTC, datetime

import pytest

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")


class TestCleanupSettings:
    """Tests for cleanup configuration settings."""

    def test_default_retention_days(self):
        """Test default retention is 90 days."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_retention_days == 90

    def test_default_cleanup_interval(self):
        """Test default cleanup interval is 24 hours."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_interval_hours == 24

    def test_default_cleanup_enabled(self):
        """Test cleanup is enabled by default."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_enabled is True

    def test_default_cleanup_batch_size(self):
        """Test default batch size is 1000."""
        from fastsmtp.config import Settings

        settings = Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_batch_size == 1000

    def test_retention_days_from_env(self, monkeypatch):
        """Test retention days can be set via environment."""
        monkeypatch.setenv("FASTSMTP_DELIVERY_LOG_RETENTION_DAYS", "30")
        from importlib import reload

        import fastsmtp.config

        reload(fastsmtp.config)
        settings = fastsmtp.config.Settings(root_api_key="test123")
        assert settings.delivery_log_retention_days == 30

    def test_cleanup_can_be_disabled(self, monkeypatch):
        """Test cleanup can be disabled via environment."""
        monkeypatch.setenv("FASTSMTP_DELIVERY_LOG_CLEANUP_ENABLED", "false")
        from importlib import reload

        import fastsmtp.config

        reload(fastsmtp.config)
        settings = fastsmtp.config.Settings(root_api_key="test123")
        assert settings.delivery_log_cleanup_enabled is False


class TestCleanupResult:
    """Tests for CleanupResult dataclass."""

    def test_cleanup_result_creation(self):
        """Test CleanupResult can be created with all fields."""
        from fastsmtp.cleanup.service import CleanupResult

        cutoff = datetime.now(UTC)
        result = CleanupResult(
            deleted_count=100,
            dry_run=False,
            cutoff_date=cutoff,
        )

        assert result.deleted_count == 100
        assert result.dry_run is False
        assert result.cutoff_date == cutoff

    def test_cleanup_result_dry_run(self):
        """Test CleanupResult with dry_run=True."""
        from fastsmtp.cleanup.service import CleanupResult

        result = CleanupResult(
            deleted_count=50,
            dry_run=True,
            cutoff_date=datetime.now(UTC),
        )

        assert result.dry_run is True
