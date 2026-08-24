"""Tests for configuration settings."""

import pytest
from fastsmtp.config import DatabaseSettings, Settings
from pydantic import ValidationError


class TestSettingsScope:
    """The full model is for ``serve``; the migration tooling gets a narrower view.

    ``DatabaseSettings`` exists so ``alembic/env.py`` can resolve the database
    URL without being handed a root API key it never uses (issue #110). The
    root key stays required on ``Settings`` -- the point is scoping, not
    weakening.
    """

    def test_root_api_key_is_still_required_for_the_full_settings(self, monkeypatch):
        monkeypatch.delenv("FASTSMTP_ROOT_API_KEY", raising=False)
        with pytest.raises(ValidationError, match="root_api_key"):
            Settings(_env_file=None, database_url="sqlite+aiosqlite:///:memory:")

    def test_database_settings_need_only_the_url(self, monkeypatch):
        monkeypatch.delenv("FASTSMTP_ROOT_API_KEY", raising=False)
        monkeypatch.setenv("FASTSMTP_DATABASE_URL", "sqlite+aiosqlite:///scoped.db")
        settings = DatabaseSettings(_env_file=None)
        assert settings.database_url == "sqlite+aiosqlite:///scoped.db"

    def test_database_settings_ignore_the_s3_cross_field_rules(self, monkeypatch):
        """A config map shared with the serving pods must not break migrations."""
        monkeypatch.delenv("FASTSMTP_ROOT_API_KEY", raising=False)
        monkeypatch.setenv("FASTSMTP_DATABASE_URL", "sqlite+aiosqlite:///scoped.db")
        monkeypatch.setenv("FASTSMTP_ATTACHMENT_STORAGE", "s3")
        DatabaseSettings(_env_file=None)

    def test_database_settings_share_env_semantics_with_the_full_model(self):
        """Same prefix and .env handling, so the two views cannot drift apart."""
        assert issubclass(Settings, DatabaseSettings)
        assert Settings.model_config == DatabaseSettings.model_config
        assert (
            Settings.model_fields["database_url"].default
            == DatabaseSettings.model_fields["database_url"].default
        )


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


class TestRawMessagePreservationConfig:
    """Tests for raw message preservation settings."""

    def test_defaults_are_off(self):
        """Test raw preservation is disabled by default."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.preserve_raw_message is False
        assert settings.preserve_raw_required is False
        assert settings.s3_raw_prefix == "raw"

    def test_s3_configured_false_without_credentials(self):
        """Test s3_configured is False when credentials are absent."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.s3_configured is False

    def test_s3_configured_false_with_partial_credentials(self):
        """Test s3_configured is False when only some credentials are present."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            s3_bucket="bucket",
            s3_access_key="key",
        )
        assert settings.s3_configured is False

    def test_s3_configured_true_with_credentials(self):
        """Test s3_configured is True when bucket and credentials are present."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            s3_bucket="bucket",
            s3_access_key="key",
            s3_secret_key="secret",
        )
        assert settings.s3_configured is True

    def test_preserve_raw_message_requires_s3(self):
        """Test enabling raw preservation without S3 credentials is rejected."""
        with pytest.raises(ValueError, match="preserve_raw_message"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                preserve_raw_message=True,
            )

    def test_preserve_raw_required_requires_s3(self):
        """Test enabling required raw preservation without S3 credentials is rejected."""
        with pytest.raises(ValueError, match="preserve_raw_required"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                preserve_raw_required=True,
            )

    def test_preserve_raw_message_with_s3_is_valid(self):
        """Test raw preservation is accepted when S3 is configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            s3_bucket="bucket",
            s3_access_key="key",
            s3_secret_key="secret",
            preserve_raw_message=True,
            preserve_raw_required=True,
        )
        assert settings.preserve_raw_message is True
        assert settings.preserve_raw_required is True


class TestMetricsAccessConfig:
    """Tests for metrics endpoint access control settings."""

    def _settings(self, **overrides) -> Settings:
        base = {
            "database_url": "sqlite+aiosqlite:///:memory:",
            "root_api_key": "test_key_12345",
        }
        base.update(overrides)
        return Settings(**base)

    def test_defaults_are_unrestricted(self):
        """Test metrics access is unrestricted by default."""
        settings = self._settings()
        assert settings.metrics_allowed_ips == []
        assert settings.metrics_trusted_proxies == []

    def test_accepts_addresses_and_prefixes(self):
        """Test the allowlist accepts bare addresses and CIDR prefixes."""
        settings = self._settings(
            metrics_allowed_ips=["10.0.0.0/8", "192.0.2.5", "2001:db8::/32"],
        )
        assert len(settings.metrics_allowed_ips) == 3

    def test_rejects_malformed_allowlist_entry(self):
        """Test a malformed allowlist entry is rejected at startup.

        Failing open on a typo would leave metrics exposed while the operator
        believes they are restricted.
        """
        with pytest.raises(ValueError, match="metrics_allowed_ips"):
            self._settings(metrics_allowed_ips=["10.0.0.0/8", "nonsense"])

    def test_rejects_malformed_trusted_proxy_entry(self):
        """Test a malformed trusted-proxy entry is rejected at startup."""
        with pytest.raises(ValueError, match="metrics_trusted_proxies"):
            self._settings(metrics_trusted_proxies=["not-a-cidr"])

    def test_rejects_prefix_with_host_bits_set(self):
        """Test a prefix with host bits set is rejected rather than silently widened."""
        with pytest.raises(ValueError, match="metrics_allowed_ips"):
            self._settings(metrics_allowed_ips=["10.1.2.3/8"])
