"""Tests for SMTP TLS module to improve coverage."""

import asyncio
import os
import ssl
import tempfile
import time
from pathlib import Path

import pytest

from fastsmtp.config import Settings
from fastsmtp.smtp.tls import (
    TLSContextManager,
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
        from subprocess import run

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "cert.pem"
            key_path = Path(tmpdir) / "key.pem"

            # Generate a self-signed cert using openssl
            result = run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
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


class TestTLSContextManager:
    """Tests for TLS hot-reload context manager."""

    @pytest.fixture
    def temp_cert_files(self):
        """Create temporary certificate and key files."""
        from subprocess import run

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "cert.pem"
            key_path = Path(tmpdir) / "key.pem"

            # Generate a self-signed cert using openssl
            result = run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                yield cert_path, key_path
            else:
                pytest.skip("openssl not available for TLS testing")

    def test_init_default_state(self):
        """Test TLSContextManager initializes with correct default state."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )

        manager = TLSContextManager(settings)

        assert manager.settings is settings
        assert manager._context is None
        assert manager._cert_mtime == 0
        assert manager._key_mtime == 0
        assert manager._running is False
        assert manager._task is None

    def test_context_property(self):
        """Test context property returns the stored context."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )

        manager = TLSContextManager(settings)
        assert manager.context is None

        # Simulate setting a context
        mock_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        manager._context = mock_context
        assert manager.context is mock_context

    def test_get_file_mtimes_no_files(self):
        """Test _get_file_mtimes returns 0 when no files configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=None,
            smtp_tls_key=None,
        )

        manager = TLSContextManager(settings)
        cert_mtime, key_mtime = manager._get_file_mtimes()

        assert cert_mtime == 0.0
        assert key_mtime == 0.0

    def test_get_file_mtimes_with_files(self, temp_cert_files):
        """Test _get_file_mtimes returns actual mtimes for existing files."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
        )

        manager = TLSContextManager(settings)
        cert_mtime, key_mtime = manager._get_file_mtimes()

        # Should return actual mtimes
        assert cert_mtime > 0
        assert key_mtime > 0
        assert cert_mtime == os.path.getmtime(cert_path)
        assert key_mtime == os.path.getmtime(key_path)

    def test_get_file_mtimes_nonexistent_files(self):
        """Test _get_file_mtimes returns 0 for non-existent files."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=Path("/nonexistent/cert.pem"),
            smtp_tls_key=Path("/nonexistent/key.pem"),
        )

        manager = TLSContextManager(settings)
        cert_mtime, key_mtime = manager._get_file_mtimes()

        assert cert_mtime == 0.0
        assert key_mtime == 0.0

    def test_files_changed_no_change(self, temp_cert_files):
        """Test _files_changed returns False when files haven't changed."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
        )

        manager = TLSContextManager(settings)
        # Set current mtimes
        manager._cert_mtime, manager._key_mtime = manager._get_file_mtimes()

        assert manager._files_changed() is False

    def test_files_changed_cert_modified(self, temp_cert_files):
        """Test _files_changed returns True when cert file is modified."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
        )

        manager = TLSContextManager(settings)
        # Set initial mtimes
        manager._cert_mtime, manager._key_mtime = manager._get_file_mtimes()

        # Modify the cert file (touch it to update mtime)
        time.sleep(0.01)  # Ensure mtime changes
        cert_path.touch()

        assert manager._files_changed() is True

    def test_files_changed_key_modified(self, temp_cert_files):
        """Test _files_changed returns True when key file is modified."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
        )

        manager = TLSContextManager(settings)
        # Set initial mtimes
        manager._cert_mtime, manager._key_mtime = manager._get_file_mtimes()

        # Modify the key file
        time.sleep(0.01)
        key_path.touch()

        assert manager._files_changed() is True

    def test_load_context_success(self, temp_cert_files):
        """Test load_context successfully loads TLS context."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
        )

        manager = TLSContextManager(settings)
        context = manager.load_context()

        assert context is not None
        assert isinstance(context, ssl.SSLContext)
        assert manager.context is context
        assert manager._cert_mtime > 0
        assert manager._key_mtime > 0

    def test_load_context_no_tls_configured(self):
        """Test load_context returns None when TLS not configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_cert=None,
            smtp_tls_key=None,
        )

        manager = TLSContextManager(settings)
        context = manager.load_context()

        assert context is None
        assert manager.context is None

    def test_load_context_invalid_files(self):
        """Test load_context returns None with invalid cert files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "invalid.pem"
            key_path = Path(tmpdir) / "invalid.key"
            cert_path.write_text("invalid")
            key_path.write_text("invalid")

            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                smtp_tls_cert=cert_path,
                smtp_tls_key=key_path,
            )

            manager = TLSContextManager(settings)
            context = manager.load_context()

            assert context is None

    @pytest.mark.asyncio
    async def test_start_hot_reload_disabled(self):
        """Test start_hot_reload does nothing when disabled."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=False,
        )

        manager = TLSContextManager(settings)
        manager.start_hot_reload()

        assert manager._running is False
        assert manager._task is None

    @pytest.mark.asyncio
    async def test_start_hot_reload_no_tls_configured(self):
        """Test start_hot_reload does nothing when TLS not configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=True,
            smtp_tls_cert=None,
            smtp_tls_key=None,
        )

        manager = TLSContextManager(settings)
        manager.start_hot_reload()

        assert manager._running is False
        assert manager._task is None

    @pytest.mark.asyncio
    async def test_start_hot_reload_enabled(self, temp_cert_files):
        """Test start_hot_reload starts monitor when enabled."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=True,
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
            smtp_tls_reload_interval=1,  # Short interval for testing
        )

        manager = TLSContextManager(settings)

        try:
            manager.start_hot_reload()

            assert manager._running is True
            assert manager._task is not None
            assert not manager._task.done()
        finally:
            await manager.stop_hot_reload()

    @pytest.mark.asyncio
    async def test_stop_hot_reload(self, temp_cert_files):
        """Test stop_hot_reload stops the monitor."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=True,
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
            smtp_tls_reload_interval=1,
        )

        manager = TLSContextManager(settings)
        manager.start_hot_reload()

        assert manager._running is True
        assert manager._task is not None

        await manager.stop_hot_reload()

        assert manager._running is False
        assert manager._task.done()

    @pytest.mark.asyncio
    async def test_stop_hot_reload_not_started(self):
        """Test stop_hot_reload handles case when not started."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )

        manager = TLSContextManager(settings)

        # Should not raise
        await manager.stop_hot_reload()

        assert manager._running is False

    @pytest.mark.asyncio
    async def test_monitor_loop_reloads_on_change(self, temp_cert_files):
        """Test monitor loop reloads context when files change."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=True,
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
            smtp_tls_reload_interval=1,  # 1 second for testing
        )

        manager = TLSContextManager(settings)
        manager.load_context()  # Initial load
        initial_cert_mtime = manager._cert_mtime

        try:
            manager.start_hot_reload()

            # Modify the cert file to trigger reload
            await asyncio.sleep(0.1)
            cert_path.touch()

            # Wait for monitor to detect and reload (> 1 second)
            await asyncio.sleep(1.5)

            # Context should have been reloaded (mtime updated)
            assert manager._cert_mtime > initial_cert_mtime
        finally:
            await manager.stop_hot_reload()

    @pytest.mark.asyncio
    async def test_monitor_loop_keeps_old_context_on_failure(self, temp_cert_files):
        """Test monitor keeps old context when reload fails."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=True,
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
            smtp_tls_reload_interval=1,
        )

        manager = TLSContextManager(settings)
        manager.load_context()
        original_context = manager.context

        try:
            manager.start_hot_reload()

            # Corrupt the cert file
            await asyncio.sleep(0.1)
            cert_path.write_text("invalid cert content")

            # Wait for monitor to detect change (> 1 second)
            await asyncio.sleep(1.5)

            # Should keep original context after failed reload
            assert manager.context is original_context
        finally:
            await manager.stop_hot_reload()

    @pytest.mark.asyncio
    async def test_monitor_loop_handles_exceptions(self, temp_cert_files):
        """Test monitor loop handles exceptions gracefully."""
        cert_path, key_path = temp_cert_files

        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_hot_reload=True,
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
            smtp_tls_reload_interval=1,
        )

        manager = TLSContextManager(settings)

        try:
            manager.start_hot_reload()

            # Wait a bit for the loop to start
            await asyncio.sleep(0.2)

            # Monitor should still be running
            assert manager._running is True
            assert not manager._task.done()
        finally:
            await manager.stop_hot_reload()

    def test_config_hot_reload_default_disabled(self):
        """Test that TLS hot-reload is disabled by default."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.smtp_tls_hot_reload is False

    def test_config_hot_reload_interval_default(self):
        """Test default reload interval is 300 seconds."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.smtp_tls_reload_interval == 300

    def test_config_hot_reload_interval_configurable(self):
        """Test reload interval is configurable."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            smtp_tls_reload_interval=60,
        )
        assert settings.smtp_tls_reload_interval == 60
