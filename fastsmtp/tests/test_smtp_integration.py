"""Integration tests for SMTP server.

Tests the complete email flow: SMTP -> parse -> database delivery queue.
"""

from collections.abc import Callable
from pathlib import Path
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
    def smtp_settings(self, make_smtp_settings: Callable[..., Settings]) -> Settings:
        """Create settings for integration testing (port 0 = OS-assigned)."""
        return make_smtp_settings(smtp_max_message_size=1024 * 1024)  # 1MB for testing

    @pytest_asyncio.fixture
    async def smtp_server(self, smtp_settings: Settings):
        """Start an actual SMTP server for testing."""
        server = SMTPServer(settings=smtp_settings)
        await server.start()
        yield server
        await server.stop()

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

        # Try to connect to the SMTP server
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_server.bound_smtp_port,
        )
        await smtp.connect()
        assert smtp.is_connected

        # Check EHLO response (aiosmtplib v5 doesn't take hostname argument)
        response = await smtp.ehlo()
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_ehlo_returns_capabilities(self, smtp_server, smtp_settings: Settings):
        """Test that EHLO returns server capabilities."""

        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_server.bound_smtp_port,
        )
        await smtp.connect()

        response = await smtp.ehlo()
        assert response.code == 250

        # Should have SIZE capability
        assert smtp.supports_extension("SIZE")

        await smtp.quit()


class TestMailFromAuthParam:
    """MAIL FROM must tolerate the RFC 4954 AUTH parameter.

    Once AUTH is advertised in EHLO, clients (notably Exchange Online) may add
    AUTH=<...> to MAIL FROM; the server may ignore it but must not reject it.
    """

    @pytest.fixture
    def smtp_settings(self, make_smtp_settings: Callable[..., Settings]) -> Settings:
        return make_smtp_settings()

    @pytest_asyncio.fixture
    async def smtp_server(self, smtp_settings: Settings):
        server = SMTPServer(settings=smtp_settings)
        await server.start()
        yield server
        await server.stop()

    @pytest_asyncio.fixture
    async def smtp_client(self, smtp_server, smtp_settings: Settings):
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_server.bound_smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()
        yield smtp
        await smtp.quit()

    @pytest.mark.asyncio
    async def test_mail_from_with_empty_auth_param(self, smtp_client):
        response = await smtp_client.execute_command(
            b"MAIL", b"FROM:<sender@example.com>", b"AUTH=<>"
        )
        assert response.code == 250

    @pytest.mark.asyncio
    async def test_mail_from_with_auth_address_param(self, smtp_client):
        response = await smtp_client.execute_command(
            b"MAIL", b"FROM:<sender@example.com>", b"AUTH=<user@example.com>"
        )
        assert response.code == 250

    @pytest.mark.asyncio
    async def test_mail_from_auth_combined_with_other_params(self, smtp_client):
        response = await smtp_client.execute_command(
            b"MAIL",
            b"FROM:<sender@example.com>",
            b"SIZE=5000",
            b"AUTH=<>",
            b"BODY=8BITMIME",
        )
        assert response.code == 250

    @pytest.mark.asyncio
    async def test_mail_from_unknown_param_still_rejected(self, smtp_client):
        response = await smtp_client.execute_command(
            b"MAIL", b"FROM:<sender@example.com>", b"RET=HDRS"
        )
        assert response.code == 555


class TestFastSMTPHandlerIntegration:
    """Test the handler directly for better control over database sessions."""

    @pytest.fixture
    def test_settings(self, make_smtp_settings: Callable[..., Settings]) -> Settings:
        """Create test settings."""
        return make_smtp_settings()

    @pytest_asyncio.fixture
    async def test_domain_with_recipient(self, test_session: AsyncSession) -> Domain:
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

            result = await handler.handle_RCPT(server, session, envelope, "invalid-no-at-sign", [])

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
        stmt = select(DeliveryLog).where(DeliveryLog.message_id == "<test-123@example.com>")
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
    async def test_smtp_server_advertises_size_limit(
        self, make_smtp_settings: Callable[..., Settings]
    ):
        """Test that SMTP server advertises SIZE limit in EHLO."""
        settings = make_smtp_settings(smtp_max_message_size=5 * 1024 * 1024)  # 5MB

        server = SMTPServer(settings=settings)
        try:
            await server.start()

            smtp = aiosmtplib.SMTP(
                hostname=settings.smtp_host,
                port=server.bound_smtp_port,
            )
            await smtp.connect()

            response = await smtp.ehlo()
            assert response.code == 250

            # Check SIZE extension is advertised
            assert smtp.supports_extension("SIZE")

            await smtp.quit()
        finally:
            await server.stop()


class TestSMTPSTARTTLS:
    """Tests for STARTTLS functionality."""

    @pytest.fixture(scope="class")
    def tls_cert_files(self, tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
        """Generate one self-signed certificate for the whole class.

        openssl is slow enough that generating per test is wasted work; the
        cert is only read, never mutated, so one class-scoped copy is safe.
        """
        from subprocess import run

        cert_dir = tmp_path_factory.mktemp("smtp-tls-certs")
        cert_path = cert_dir / "cert.pem"
        key_path = cert_dir / "key.pem"

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

        return cert_path, key_path

    @pytest.fixture
    def tls_settings(
        self,
        tls_cert_files: tuple[Path, Path],
        make_smtp_settings: Callable[..., Settings],
    ) -> Settings:
        """Create settings with TLS configured.

        Both listeners bind port 0, so the OS hands out two distinct free
        ports; read them back via bound_smtp_port / bound_smtp_tls_port.
        """
        cert_path, key_path = tls_cert_files
        return make_smtp_settings(smtp_tls_cert=cert_path, smtp_tls_key=key_path)

    @pytest.mark.asyncio
    async def test_tls_server_starts(self, tls_settings: Settings):
        """Test that TLS server starts when certificates are configured."""
        server = SMTPServer(settings=tls_settings)
        try:
            await server.start()

            # Verify both controllers are started
            assert server.controller is not None
            assert server.tls_controller is not None
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_starttls_plain_port_connects(self, tls_settings: Settings):
        """Test connection to plain SMTP port when TLS is configured."""
        server = SMTPServer(settings=tls_settings)
        try:
            await server.start()

            # Disable automatic STARTTLS - we're testing plain port connectivity
            # and that STARTTLS is advertised, not actual TLS upgrade
            smtp = aiosmtplib.SMTP(
                hostname=tls_settings.smtp_host,
                port=server.bound_smtp_port,
                start_tls=False,
            )
            await smtp.connect()

            response = await smtp.ehlo()
            assert response.code == 250

            # Verify STARTTLS is advertised
            assert smtp.supports_extension("STARTTLS")

            await smtp.quit()

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_starttls_upgrade(self, tls_settings: Settings):
        """Test STARTTLS upgrade with self-signed certificate."""
        import ssl

        server = SMTPServer(settings=tls_settings)
        try:
            await server.start()

            # Create SSL context that accepts self-signed certs
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            smtp = aiosmtplib.SMTP(
                hostname=tls_settings.smtp_host,
                port=server.bound_smtp_port,
                start_tls=False,  # Don't auto-upgrade, we'll do it manually
            )
            await smtp.connect()
            await smtp.ehlo()

            # Verify STARTTLS is available
            assert smtp.supports_extension("STARTTLS")

            # Manually upgrade to TLS
            await smtp.starttls(tls_context=context)

            # Verify we're now using TLS
            response = await smtp.ehlo()
            assert response.code == 250

            await smtp.quit()

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_implicit_tls_connection(self, tls_settings: Settings):
        """Test connecting to implicit TLS port."""
        server = SMTPServer(settings=tls_settings)
        try:
            await server.start()

            import ssl

            # Create SSL context that accepts self-signed certs
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            smtp = aiosmtplib.SMTP(
                hostname=tls_settings.smtp_host,
                port=server.bound_smtp_tls_port,
                use_tls=True,
                tls_context=context,
            )
            await smtp.connect()
            assert smtp.is_connected

            response = await smtp.ehlo()
            assert response.code == 250

            await smtp.quit()

        finally:
            await server.stop()


class TestSMTPAuthSettings:
    """Tests for SMTP authentication rejection settings."""

    @pytest.fixture
    def strict_auth_settings(self, make_smtp_settings: Callable[..., Settings]) -> Settings:
        """Create settings that reject on auth failure."""
        return make_smtp_settings(
            smtp_verify_dkim=True,
            smtp_verify_spf=True,
            smtp_reject_dkim_fail=True,
            smtp_reject_spf_fail=True,
        )

    @pytest.mark.asyncio
    async def test_server_starts_with_strict_auth(self, strict_auth_settings: Settings):
        """Test that server starts with strict auth settings."""
        server = SMTPServer(settings=strict_auth_settings)
        try:
            await server.start()

            assert server.controller is not None

            smtp = aiosmtplib.SMTP(
                hostname=strict_auth_settings.smtp_host,
                port=server.bound_smtp_port,
            )
            await smtp.connect()
            assert smtp.is_connected
            await smtp.quit()

        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_handler_rejects_dkim_fail_when_configured(
        self, make_smtp_settings: Callable[..., Settings], session_factory
    ):
        """Test handler rejects messages with DKIM failure when configured.

        ``recipient@test.com`` is on no configured domain, so the DATA path
        resolves it to the global policy - which is what this asserts. The
        session factory is patched because that resolution reads the database.
        """
        settings = make_smtp_settings(smtp_verify_dkim=True, smtp_reject_dkim_fail=True)

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
        with (
            patch("fastsmtp.smtp.server.async_session", session_factory),
            patch("fastsmtp.smtp.server.validate_email_auth") as mock_auth,
        ):
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
    async def test_handler_rejects_spf_fail_when_configured(
        self, make_smtp_settings: Callable[..., Settings], session_factory
    ):
        """Test handler rejects messages with SPF failure when configured.

        Same as the DKIM case above: an unconfigured recipient domain keeps
        the global policy, and resolving that reads the database.
        """
        settings = make_smtp_settings(smtp_verify_spf=True, smtp_reject_spf_fail=True)

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

        with (
            patch("fastsmtp.smtp.server.async_session", session_factory),
            patch("fastsmtp.smtp.server.validate_email_auth") as mock_auth,
        ):
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
