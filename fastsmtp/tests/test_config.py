"""Tests for configuration settings."""

import pytest
from fastsmtp.config import Settings


class TestS3ConfigValidation:
    """Tests for S3 configuration validation."""

    def test_s3_storage_requires_bucket(self):
        """Test that S3 storage requires bucket."""
        with pytest.raises(ValueError, match="s3_bucket"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                attachment_storage="s3",
                s3_access_key="key",
                s3_secret_key="secret",
            )

    def test_s3_storage_requires_access_key(self):
        """Test that S3 storage requires access key."""
        with pytest.raises(ValueError, match="s3_access_key"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                attachment_storage="s3",
                s3_bucket="bucket",
                s3_secret_key="secret",
            )

    def test_s3_storage_requires_secret_key(self):
        """Test that S3 storage requires secret key."""
        with pytest.raises(ValueError, match="s3_secret_key"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                attachment_storage="s3",
                s3_bucket="bucket",
                s3_access_key="key",
            )

    def test_s3_storage_valid_config(self):
        """Test valid S3 configuration."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="s3",
            s3_bucket="my-bucket",
            s3_access_key="access-key",
            s3_secret_key="secret-key",
        )
        assert settings.attachment_storage == "s3"
        assert settings.s3_bucket == "my-bucket"

    def test_inline_storage_no_s3_required(self):
        """Test inline storage doesn't require S3 config."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="inline",
        )
        assert settings.attachment_storage == "inline"

    def test_default_attachment_storage_is_inline(self):
        """Test that default attachment storage is inline."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.attachment_storage == "inline"

    def test_s3_settings_have_defaults(self):
        """Test S3 settings have sensible defaults."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="s3",
            s3_bucket="bucket",
            s3_access_key="key",
            s3_secret_key="secret",
        )
        assert settings.s3_region == "us-east-1"
        assert settings.s3_prefix == "attachments"
        assert settings.s3_presigned_urls is False
        assert settings.s3_presigned_url_expiry == 3600
        assert settings.s3_endpoint_url is None


class TestRenamedWebhookSettings:
    """Tests for renamed webhook settings."""

    def test_max_inline_attachment_size_exists(self):
        """Test webhook_max_inline_attachment_size setting exists."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert hasattr(settings, "webhook_max_inline_attachment_size")
        assert settings.webhook_max_inline_attachment_size == 10 * 1024 * 1024  # 10MB

    def test_max_inline_payload_size_exists(self):
        """Test webhook_max_inline_payload_size setting exists."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert hasattr(settings, "webhook_max_inline_payload_size")
        assert settings.webhook_max_inline_payload_size == 50 * 1024 * 1024  # 50MB
