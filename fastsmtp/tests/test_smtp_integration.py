"""Integration tests for SMTP server.

Tests the complete email flow: SMTP -> parse -> database delivery queue.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import aiosmtplib
import pytest
import pytest_asyncio
from aiosmtpd.smtp import Envelope
from fastsmtp.config import Settings
from fastsmtp.db.models import DeliveryLog, Domain, Recipient
from fastsmtp.smtp.server import FastSMTPHandler, SMTPServer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class TestSMTPIntegration:
    """Integration tests for SMTP server."""

    @pytest.fixture
    def smtp_settings(self) -> Settings:
        """Create settings for integration testing with unique ports."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12525,  # High port to avoid conflicts
            smtp_tls_port=14650,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
            smtp_max_message_size=1024 * 1024,  # 1MB for testing
        )

    @pytest_asyncio.fixture
    async def smtp_server(self, smtp_settings: Settings):
        """Start an actual SMTP server for testing."""
        server = SMTPServer(settings=smtp_settings)
        server.start()
        yield server
        server.stop()

    @pytest_asyncio.fixture
    async def test_domain_setup(self, test_session: AsyncSession) -> Domain:
        """Create a domain and recipient for testing."""
        domain = Domain(
            domain_name="integration-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="test",
            webhook_url="https://webhook.example.com/integration",
            is_enabled=True,
        )
        test_session.add(recipient)

        # Also add a catch-all
        catchall = Recipient(
            domain_id=domain.id,
            local_part=None,
            webhook_url="https://webhook.example.com/catchall",
            is_enabled=True,
        )
        test_session.add(catchall)

        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_smtp_server_starts_and_accepts_connections(
        self, smtp_server, smtp_settings: Settings
    ):
        """Test that SMTP server starts and accepts connections."""
        server = smtp_server

        # Try to connect to the SMTP server
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        assert smtp.is_connected

        # Check EHLO response (aiosmtplib v5 doesn't take hostname argument)
        response = await smtp.ehlo()
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_ehlo_returns_capabilities(
        self, smtp_server, smtp_settings: Settings
    ):
        """Test that EHLO returns server capabilities."""
        server = smtp_server

        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.ehlo()
        assert response.code == 250

        # Should have SIZE capability
        assert smtp.supports_extension("SIZE")

        await smtp.quit()


class TestFastSMTPHandlerIntegration:
    """Test the handler directly for better control over database sessions."""

    @pytest.fixture
    def test_settings(self) -> Settings:
        """Create test settings."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
        )

    @pytest_asyncio.fixture
    async def test_domain_with_recipient(
        self, test_session: AsyncSession
    ) -> Domain:
        """Create a domain with recipient for handler testing."""
        domain = Domain(
            domain_name="handler-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="user",
            webhook_url="https://webhook.example.com/handler",
            is_enabled=True,
        )
        test_session.add(recipient)

        catchall = Recipient(
            domain_id=domain.id,
            local_part=None,
            webhook_url="https://webhook.example.com/catchall",
            is_enabled=True,
        )
        test_session.add(catchall)

        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_handle_rcpt_accepts_valid_recipient(
        self,
        test_settings: Settings,
        test_session: AsyncSession,
        test_domain_with_recipient: Domain,
    ):
        """Test that handle_RCPT accepts valid recipients."""
        handler = FastSMTPHandler(test_settings)

        # Create mock SMTP objects
        server = MagicMock()
        session = MagicMock()
        envelope = Envelope()
        envelope.rcpt_tos = []

        # Mock async_session to return our test session
        with patch("fastsmtp.smtp.server.async_session") as mock_async_session:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = test_session
            mock_ctx.__aexit__.return_value = None
            mock_async_session.return_value = mock_ctx

            result = await handler.handle_RCPT(
                server, session, envelope, "user@handler-test.com", []
            )

        assert result == "250 OK"
        assert "user@handler-test.com" in envelope.rcpt_tos

    @pytest.mark.asyncio
    async def test_handle_rcpt_rejects_unknown_domain(
        self,
        test_settings: Settings,
        test_session: AsyncSession,
    ):
        """Test that handle_RCPT rejects unknown domains."""
        handler = FastSMTPHandler(test_settings)

        server = MagicMock()
        session = MagicMock()
        envelope = Envelope()
        envelope.rcpt_tos = []

        with patch("fastsmtp.smtp.server.async_session") as mock_async_session:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = test_session
            mock_ctx.__aexit__.return_value = None
            mock_async_session.return_value = mock_ctx

            result = await handler.handle_RCPT(
                server, session, envelope, "user@unknown-domain.com", []
            )

        assert "550" in result
        assert "not configured" in result
        assert "user@unknown-domain.com" not in envelope.rcpt_tos

    @pytest.mark.asyncio
    async def test_handle_rcpt_rejects_invalid_address(
        self,
        test_settings: Settings,
        test_session: AsyncSession,
    ):
        """Test that handle_RCPT rejects malformed addresses."""
        handler = FastSMTPHandler(test_settings)

        server = MagicMock()
        session = MagicMock()
        envelope = Envelope()
        envelope.rcpt_tos = []

        with patch("fastsmtp.smtp.server.async_session") as mock_async_session:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = test_session
            mock_ctx.__aexit__.return_value = None
            mock_async_session.return_value = mock_ctx

            result = await handler.handle_RCPT(
                server, session, envelope, "invalid-no-at-sign", []
            )

        assert "550" in result
        assert "Invalid" in result

    @pytest.mark.asyncio
    async def test_handle_data_persists_to_database(
        self,
        test_settings: Settings,
        test_session: AsyncSession,
        test_domain_with_recipient: Domain,
    ):
        """Test that handle_DATA persists deliveries to database."""
        handler = FastSMTPHandler(test_settings)

        server = MagicMock()
        session = MagicMock()
        session.peer = ("127.0.0.1", 12345)
        session.host_name = "test-client"

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["user@handler-test.com"]
        envelope.content = b"""\
From: sender@example.com
To: user@handler-test.com
Subject: Test Email
Message-ID: <test-123@example.com>

This is a test message body.
"""

        with patch("fastsmtp.smtp.server.async_session") as mock_async_session:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = test_session
            mock_ctx.__aexit__.return_value = None
            mock_async_session.return_value = mock_ctx

            result = await handler.handle_DATA(server, session, envelope)

        assert result == "250 Message accepted for delivery"

        # Check that delivery was persisted
        stmt = select(DeliveryLog).where(
            DeliveryLog.message_id == "<test-123@example.com>"
        )
        db_result = await test_session.execute(stmt)
        delivery = db_result.scalar_one_or_none()
        assert delivery is not None
        assert delivery.webhook_url == "https://webhook.example.com/handler"
        assert delivery.status == "pending"

    @pytest.mark.asyncio
    async def test_handle_data_rejects_unparseable_message(
        self,
        test_settings: Settings,
    ):
        """Test that handle_DATA rejects unparseable messages."""
        handler = FastSMTPHandler(test_settings)

        server = MagicMock()
        session = MagicMock()
        session.peer = ("127.0.0.1", 12345)
        session.host_name = "test-client"

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@test.com"]
        # Use invalid byte sequences that can't be parsed as email
        envelope.content = b"\x80\x81\x82invalid"

        # Mock message_from_bytes to raise an exception
        with patch("fastsmtp.smtp.server.message_from_bytes") as mock_parse:
            mock_parse.side_effect = Exception("Parse error")
            result = await handler.handle_DATA(server, session, envelope)

        assert "550" in result
        assert "Failed to parse" in result


class TestSMTPLargeMessageHandling:
    """Tests for large message size limits."""

    @pytest.mark.asyncio
    async def test_smtp_server_advertises_size_limit(self):
        """Test that SMTP server advertises SIZE limit in EHLO."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12529,
            smtp_max_message_size=5 * 1024 * 1024,  # 5MB
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
        )

        server = SMTPServer(settings=settings)
        server.start()

        try:
            smtp = aiosmtplib.SMTP(
                hostname=settings.smtp_host,
                port=settings.smtp_port,
            )
            await smtp.connect()

            response = await smtp.ehlo()
            assert response.code == 250

            # Check SIZE extension is advertised
            assert smtp.supports_extension("SIZE")

            await smtp.quit()
        finally:
            server.stop()


class TestSMTPSTARTTLS:
    """Tests for STARTTLS functionality."""

    @pytest.fixture
    def tls_settings(self, tmp_path) -> Settings | None:
        """Create settings with TLS configured."""
        from subprocess import run

        # Generate self-signed certificate for testing
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"

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

        if result.returncode != 0:
            pytest.skip("openssl not available for TLS testing")
            return None

        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12527,
            smtp_tls_port=14651,
            smtp_tls_cert=cert_path,
            smtp_tls_key=key_path,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
        )

    @pytest.mark.asyncio
    async def test_tls_server_starts(self, tls_settings: Settings | None):
        """Test that TLS server starts when certificates are configured."""
        if tls_settings is None:
            pytest.skip("TLS settings not available")

        server = SMTPServer(settings=tls_settings)
        server.start()

        try:
            # Verify both controllers are started
            assert server.controller is not None
            assert server.tls_controller is not None
        finally:
            server.stop()

    @pytest.mark.asyncio
    async def test_starttls_plain_port_connects(
        self, tls_settings: Settings | None
    ):
        """Test connection to plain SMTP port when TLS is configured."""
        if tls_settings is None:
            pytest.skip("TLS settings not available")

        server = SMTPServer(settings=tls_settings)
        server.start()

        try:
            smtp = aiosmtplib.SMTP(
                hostname=tls_settings.smtp_host,
                port=tls_settings.smtp_port,
            )
            await smtp.connect()

            response = await smtp.ehlo()
            assert response.code == 250

            await smtp.quit()

        finally:
            server.stop()

    @pytest.mark.asyncio
    async def test_implicit_tls_connection(self, tls_settings: Settings | None):
        """Test connecting to implicit TLS port."""
        if tls_settings is None:
            pytest.skip("TLS settings not available")

        server = SMTPServer(settings=tls_settings)
        server.start()

        try:
            import ssl

            # Create SSL context that accepts self-signed certs
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            smtp = aiosmtplib.SMTP(
                hostname=tls_settings.smtp_host,
                port=tls_settings.smtp_tls_port,
                use_tls=True,
                tls_context=context,
            )
            await smtp.connect()
            assert smtp.is_connected

            response = await smtp.ehlo()
            assert response.code == 250

            await smtp.quit()

        finally:
            server.stop()


class TestSMTPAuthSettings:
    """Tests for SMTP authentication rejection settings."""

    @pytest.fixture
    def strict_auth_settings(self) -> Settings:
        """Create settings that reject on auth failure."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12528,
            smtp_verify_dkim=True,
            smtp_verify_spf=True,
            smtp_reject_dkim_fail=True,
            smtp_reject_spf_fail=True,
        )

    @pytest.mark.asyncio
    async def test_server_starts_with_strict_auth(
        self, strict_auth_settings: Settings
    ):
        """Test that server starts with strict auth settings."""
        server = SMTPServer(settings=strict_auth_settings)
        server.start()

        try:
            assert server.controller is not None

            smtp = aiosmtplib.SMTP(
                hostname=strict_auth_settings.smtp_host,
                port=strict_auth_settings.smtp_port,
            )
            await smtp.connect()
            assert smtp.is_connected
            await smtp.quit()

        finally:
            server.stop()

    @pytest.mark.asyncio
    async def test_handler_rejects_dkim_fail_when_configured(self):
        """Test handler rejects messages with DKIM failure when configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_verify_dkim=True,
            smtp_reject_dkim_fail=True,
        )

        handler = FastSMTPHandler(settings)

        server = MagicMock()
        session = MagicMock()
        session.peer = ("127.0.0.1", 12345)
        session.host_name = "test-client"

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@test.com"]
        envelope.content = b"""\
From: sender@example.com
To: recipient@test.com
Subject: Test

Body.
"""

        # Mock validate_email_auth to return DKIM failure
        with patch("fastsmtp.smtp.server.validate_email_auth") as mock_auth:
            from fastsmtp.smtp.validation import EmailAuthResult

            mock_auth.return_value = EmailAuthResult(
                dkim_result="fail",
                dkim_domain="example.com",
                dkim_selector=None,
                spf_result="none",
                spf_domain=None,
                client_ip="127.0.0.1",
            )

            result = await handler.handle_DATA(server, session, envelope)

        assert "550" in result
        assert "DKIM" in result

    @pytest.mark.asyncio
    async def test_handler_rejects_spf_fail_when_configured(self):
        """Test handler rejects messages with SPF failure when configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret-key",
            smtp_verify_spf=True,
            smtp_reject_spf_fail=True,
        )

        handler = FastSMTPHandler(settings)

        server = MagicMock()
        session = MagicMock()
        session.peer = ("127.0.0.1", 12345)
        session.host_name = "test-client"

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@test.com"]
        envelope.content = b"""\
From: sender@example.com
To: recipient@test.com
Subject: Test

Body.
"""

        with patch("fastsmtp.smtp.server.validate_email_auth") as mock_auth:
            from fastsmtp.smtp.validation import EmailAuthResult

            mock_auth.return_value = EmailAuthResult(
                dkim_result="none",
                dkim_domain=None,
                dkim_selector=None,
                spf_result="fail",
                spf_domain="example.com",
                client_ip="127.0.0.1",
            )

            result = await handler.handle_DATA(server, session, envelope)

        assert "550" in result
        assert "SPF" in result
