"""Tests for delivery log cleanup functionality."""

import os

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
