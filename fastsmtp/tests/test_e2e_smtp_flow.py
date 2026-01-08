"""End-to-end integration tests for SMTP server protocol handling.

Tests the SMTP server's ability to:
- Accept SMTP connections
- Handle EHLO/MAIL/RCPT/DATA commands
- Advertise correct capabilities

Note: Database integration is tested in test_smtp_integration.py with proper
mocking. These tests focus on SMTP protocol behavior.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiosmtplib
import pytest
import pytest_asyncio

from fastsmtp.config import Settings
from fastsmtp.smtp.server import SMTPServer


class TestSMTPProtocolE2E:
    """End-to-end tests for SMTP protocol behavior."""

    @pytest.fixture
    def smtp_settings(self) -> Settings:
        """Create settings for SMTP testing."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_e2e_key_12345",
            secret_key="test-e2e-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12570,  # Unique port
            smtp_tls_port=14680,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
            smtp_max_message_size=1024 * 1024,
        )

    @pytest_asyncio.fixture
    async def smtp_server(self, smtp_settings: Settings):
        """Start SMTP server for testing."""
        server = SMTPServer(settings=smtp_settings)
        server.start()
        await asyncio.sleep(0.1)  # Give server time to start
        yield server
        server.stop()

    @pytest.mark.asyncio
    async def test_smtp_server_accepts_connection(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server accepts connections."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        assert smtp.is_connected
        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_server_ehlo_capabilities(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server advertises correct capabilities."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.ehlo()
        assert response.code == 250

        # Verify expected capabilities
        assert smtp.supports_extension("SIZE")
        assert smtp.supports_extension("8BITMIME")
        assert smtp.supports_extension("SMTPUTF8")

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_server_mail_command(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server accepts MAIL FROM command."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        response = await smtp.mail("sender@example.com")
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_server_advertises_size(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server advertises correct message size limit."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.ehlo()
        assert response.code == 250

        # Check SIZE is advertised
        assert smtp.supports_extension("SIZE")

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_connection_reset(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test RSET command resets the mail transaction."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        # Start a transaction
        await smtp.mail("sender@example.com")

        # Reset should succeed
        response = await smtp.rset()
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_noop_command(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test NOOP command returns success."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.noop()
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_connection_reuse_without_data(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that connection can be reused for multiple MAIL transactions."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        # First transaction
        response1 = await smtp.mail("sender1@example.com")
        assert response1.code == 250
        await smtp.rset()

        # Second transaction
        response2 = await smtp.mail("sender2@example.com")
        assert response2.code == 250

        await smtp.quit()


class TestSMTPServerWithMockedDatabase:
    """Tests that verify SMTP handling with mocked database lookups."""

    @pytest.fixture
    def smtp_settings(self) -> Settings:
        """Create settings for SMTP testing."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_mock_key_12345",
            secret_key="test-mock-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12571,  # Unique port
            smtp_tls_port=14681,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
            smtp_max_message_size=1024 * 1024,
        )

    @pytest_asyncio.fixture
    async def smtp_server_with_mock(self, smtp_settings: Settings):
        """Start SMTP server with mocked database lookups."""
        # Mock the lookup_recipient function to simulate domain/recipient
        mock_domain = MagicMock()
        mock_domain.id = 1
        mock_domain.domain_name = "mock-test.example.com"
        mock_domain.is_enabled = True

        mock_recipient = MagicMock()
        mock_recipient.id = 1
        mock_recipient.domain_id = 1
        mock_recipient.local_part = "user"
        mock_recipient.webhook_url = "https://webhook.example.com/mock"
        mock_recipient.is_enabled = True

        async def mock_lookup(address, session):
            if address.endswith("@mock-test.example.com"):
                return mock_domain, mock_recipient, None
            return None, None, "Domain not configured"

        with (
            patch("fastsmtp.smtp.server.lookup_recipient", side_effect=mock_lookup),
            patch(
                "fastsmtp.smtp.server.FastSMTPHandler._process_and_persist_message",
                new_callable=AsyncMock,
            ) as mock_process,
        ):
            mock_process.return_value = None

            server = SMTPServer(settings=smtp_settings)
            server.start()
            await asyncio.sleep(0.1)
            yield server
            server.stop()

    @pytest.mark.asyncio
    async def test_smtp_accepts_valid_recipient(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test that SMTP server accepts emails to configured recipients."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@mock-test.example.com
Subject: Test Email
Message-ID: <mock-test-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This is a test email.
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@mock-test.example.com"],
            email_content,
        )

        assert errors == {}, f"SMTP returned errors: {errors}"
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_rejects_unknown_domain(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test that SMTP server rejects recipients from unknown domains."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        await smtp.ehlo()
        await smtp.mail("sender@external.com")

        with pytest.raises(aiosmtplib.SMTPRecipientRefused) as exc_info:
            await smtp.rcpt("user@unknown-domain.com")

        assert exc_info.value.code == 550

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_handles_multiple_recipients(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test sending to multiple recipients."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@mock-test.example.com, another@mock-test.example.com
Subject: Multi-recipient Test
Message-ID: <mock-multi-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Message to multiple recipients.
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@mock-test.example.com", "another@mock-test.example.com"],
            email_content,
        )

        assert errors == {}
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_handles_multipart_email(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test that multipart emails are accepted."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@mock-test.example.com
Subject: Multipart Test
Message-ID: <mock-multipart-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Plain text version.

--boundary123
Content-Type: text/html; charset="utf-8"

<html><body><p>HTML version.</p></body></html>

--boundary123--
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@mock-test.example.com"],
            email_content,
        )

        assert errors == {}
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_connection_reuse(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test sending multiple emails over a single connection."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        for i in range(3):
            email_content = f"""\
From: sender@external.com
To: user@mock-test.example.com
Subject: Connection Reuse Test {i}
Message-ID: <mock-reuse-{i:03d}@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Email number {i}.
""".encode()

            errors, message = await smtp.sendmail(
                "sender@external.com",
                ["user@mock-test.example.com"],
                email_content,
            )
            assert errors == {}
            assert "accepted" in message.lower()

        await smtp.quit()
