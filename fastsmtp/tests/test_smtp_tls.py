"""Tests for SMTP TLS module to improve coverage."""

import ssl
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fastsmtp.config import Settings
from fastsmtp.smtp.tls import (
    create_tls_context,
    get_tls_context_from_settings,
    validate_tls_config,
)


class TestCreateTLSContext:
    """Tests for TLS context creation."""

    @pytest.fixture
    def temp_cert_files(self):
        """Create temporary certificate and key files."""
        # Create self-signed certificate for testing
        from subprocess import run, PIPE

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "cert.pem"
            key_path = Path(tmpdir) / "key.pem"

            # Generate a self-signed cert using openssl
            result = run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key_path),
                    "-out", str(cert_path),
                    "-days", "1",
                    "-nodes",
                    "-subj", "/CN=localhost",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                yield cert_path, key_path
            else:
                pytest.skip("openssl not available for TLS testing")

    def test_create_tls_context_success(self, temp_cert_files):
        """Test creating TLS context with valid cert/key."""
        cert_path, key_path = temp_cert_files

        context = create_tls_context(cert_path, key_path)

        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_NONE

    def test_create_tls_context_require_client_cert(self, temp_cert_files):
        """Test creating TLS context requiring client certificates."""
        cert_path, key_path = temp_cert_files

        context = create_tls_context(cert_path, key_path, require_client_cert=True)

        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_create_tls_context_invalid_cert(self):
        """Test creating TLS context with invalid certificate fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "invalid.pem"
            key_path = Path(tmpdir) / "invalid.key"

            cert_path.write_text("invalid cert")
            key_path.write_text("invalid key")

            with pytest.raises(ssl.SSLError):
                create_tls_context(cert_path, key_path)


class TestGetTLSContextFromSettings:
    """Tests for getting TLS context from settings."""

    def test_tls_not_configured(self):
        """Test when TLS is not configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            smtp_tls_cert=None,
            smtp_tls_key=None,
        )

        result = get_tls_context_from_settings(settings)
        assert result is None

    def test_tls_cert_missing(self):
        """Test when TLS certificate file doesn't exist."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            smtp_tls_cert=Path("/nonexistent/cert.pem"),
            smtp_tls_key=Path("/nonexistent/key.pem"),
        )

        result = get_tls_context_from_settings(settings)
        assert result is None

    def test_tls_key_missing(self):
        """Test when TLS key file doesn't exist."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            cert_path = Path(f.name)
            f.write(b"test cert")

        try:
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                secret_key="test-secret",
                smtp_tls_cert=cert_path,
                smtp_tls_key=Path("/nonexistent/key.pem"),
            )

            result = get_tls_context_from_settings(settings)
            assert result is None
        finally:
            cert_path.unlink()


class TestValidateTLSConfig:
    """Tests for TLS configuration validation."""

    def test_tls_not_configured_valid(self):
        """Test validation passes when TLS is not configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            smtp_tls_cert=None,
            smtp_tls_key=None,
        )

        is_valid, message = validate_tls_config(settings)
        assert is_valid is True
        assert "not configured" in message

    def test_tls_cert_without_key(self):
        """Test validation fails when cert provided without key."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            cert_path = Path(f.name)
            f.write(b"test cert")

        try:
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                secret_key="test-secret",
                smtp_tls_cert=cert_path,
                smtp_tls_key=None,
            )

            is_valid, message = validate_tls_config(settings)
            assert is_valid is False
            assert "no key" in message
        finally:
            cert_path.unlink()

    def test_tls_key_without_cert(self):
        """Test validation fails when key provided without cert."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            key_path = Path(f.name)
            f.write(b"test key")

        try:
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                secret_key="test-secret",
                smtp_tls_cert=None,
                smtp_tls_key=key_path,
            )

            is_valid, message = validate_tls_config(settings)
            assert is_valid is False
            assert "no certificate" in message
        finally:
            key_path.unlink()

    def test_tls_cert_not_found(self):
        """Test validation fails when cert file doesn't exist."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            smtp_tls_cert=Path("/nonexistent/cert.pem"),
            smtp_tls_key=Path("/tmp/test_key.pem"),
        )

        is_valid, message = validate_tls_config(settings)
        assert is_valid is False
        assert "not found" in message

    def test_tls_invalid_cert_key_pair(self):
        """Test validation fails with invalid cert/key pair."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "cert.pem"
            key_path = Path(tmpdir) / "key.pem"

            cert_path.write_text("invalid cert content")
            key_path.write_text("invalid key content")

            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                secret_key="test-secret",
                smtp_tls_cert=cert_path,
                smtp_tls_key=key_path,
            )

            is_valid, message = validate_tls_config(settings)
            assert is_valid is False
            assert "error" in message.lower()
