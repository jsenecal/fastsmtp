"""Extended tests for SMTP server module to improve coverage."""

import asyncio
from email.message import EmailMessage
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from aiosmtpd.smtp import Envelope, Session
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.config import Settings
from fastsmtp.db.models import Domain, Recipient
from fastsmtp.smtp.server import (
    FastSMTPHandler,
    SMTPServer,
    extract_email_payload,
    find_recipient_for_address,
    lookup_recipient,
)


class TestLookupRecipient:
    """Tests for recipient lookup function."""

    @pytest_asyncio.fixture
    async def test_domain_with_recipients(
        self, test_session: AsyncSession
    ) -> Domain:
        """Create a test domain with recipients."""
        domain = Domain(domain_name="smtp-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Specific recipient
        specific = Recipient(
            domain_id=domain.id,
            local_part="info",
            webhook_url="https://webhook.example.com/specific",
            is_enabled=True,
        )

        # Catch-all recipient
        catchall = Recipient(
            domain_id=domain.id,
            local_part=None,
            webhook_url="https://webhook.example.com/catchall",
            is_enabled=True,
        )

        # Disabled recipient
        disabled = Recipient(
            domain_id=domain.id,
            local_part="disabled",
            webhook_url="https://webhook.example.com/disabled",
            is_enabled=False,
        )

        test_session.add_all([specific, catchall, disabled])
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_lookup_invalid_address(self, test_session: AsyncSession):
        """Test lookup with invalid email address."""
        domain, recipient, error = await lookup_recipient("invalid", test_session)
        assert domain is None
        assert recipient is None
        assert "Invalid" in error

    @pytest.mark.asyncio
    async def test_lookup_unknown_domain(self, test_session: AsyncSession):
        """Test lookup with unknown domain."""
        domain, recipient, error = await lookup_recipient(
            "user@unknown.example.com", test_session
        )
        assert domain is None
        assert recipient is None
        assert "not configured" in error

    @pytest.mark.asyncio
    async def test_lookup_specific_recipient(
        self,
        test_session: AsyncSession,
        test_domain_with_recipients: Domain,
    ):
        """Test lookup finds specific recipient."""
        domain, recipient, error = await lookup_recipient(
            "info@smtp-test.com", test_session
        )
        assert domain is not None
        assert recipient is not None
        assert recipient.local_part == "info"
        assert error is None

    @pytest.mark.asyncio
    async def test_lookup_catchall_recipient(
        self,
        test_session: AsyncSession,
        test_domain_with_recipients: Domain,
    ):
        """Test lookup falls back to catch-all."""
        domain, recipient, error = await lookup_recipient(
            "unknown@smtp-test.com", test_session
        )
        assert domain is not None
        assert recipient is not None
        assert recipient.local_part is None  # Catch-all
        assert error is None

    @pytest.mark.asyncio
    async def test_lookup_disabled_recipient_uses_catchall(
        self,
        test_session: AsyncSession,
        test_domain_with_recipients: Domain,
    ):
        """Test disabled recipient falls back to catch-all."""
        domain, recipient, error = await lookup_recipient(
            "disabled@smtp-test.com", test_session
        )
        assert domain is not None
        assert recipient is not None
        # Should get catch-all since disabled recipient is skipped
        assert recipient.local_part is None
        assert error is None

    @pytest.mark.asyncio
    async def test_lookup_case_insensitive(
        self,
        test_session: AsyncSession,
        test_domain_with_recipients: Domain,
    ):
        """Test lookup is case-insensitive."""
        domain, recipient, error = await lookup_recipient(
            "INFO@SMTP-TEST.COM", test_session
        )
        assert domain is not None
        assert recipient is not None
        assert recipient.local_part == "info"
        assert error is None


class TestFindRecipientForAddress:
    """Tests for find_recipient_for_address function."""

    @pytest.mark.asyncio
    async def test_find_recipient_returns_tuple(self, test_session: AsyncSession):
        """Test that find_recipient_for_address returns domain and recipient."""
        domain, recipient = await find_recipient_for_address(
            "user@unknown.com", test_session
        )
        assert domain is None
        assert recipient is None


class TestExtractEmailPayload:
    """Tests for email payload extraction."""

    def test_extract_simple_text_email(self):
        """Test extracting payload from simple text email."""
        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.com"
        message["Subject"] = "Test Subject"
        message["Message-ID"] = "<test123@example.com>"
        message.set_content("This is the body")

        payload = extract_email_payload(message, envelope)

        assert payload["from"] == "sender@example.com"
        assert payload["to"] == "recipient@example.com"
        assert payload["subject"] == "Test Subject"
        assert payload["message_id"] == "<test123@example.com>"
        assert "This is the body" in payload["body_text"]
        assert payload["has_attachments"] is False

    def test_extract_html_email(self):
        """Test extracting payload from HTML email."""
        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.com"
        message["Subject"] = "HTML Email"
        message.set_content("<html><body><p>HTML content</p></body></html>", subtype="html")

        payload = extract_email_payload(message, envelope)

        assert "HTML content" in payload["body_html"]
        assert payload["body_text"] == ""

    def test_extract_multipart_email(self):
        """Test extracting payload from multipart email."""
        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.com"
        message["Subject"] = "Multipart Email"
        message.set_content("Plain text version")
        message.add_alternative("<html><body><p>HTML version</p></body></html>", subtype="html")

        payload = extract_email_payload(message, envelope)

        assert "Plain text" in payload["body_text"]
        assert "HTML version" in payload["body_html"]

    def test_extract_email_with_attachment(self):
        """Test extracting payload from email with attachment."""
        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.com"
        message["Subject"] = "Email with Attachment"
        message.set_content("Body text")
        message.add_attachment(
            b"file content",
            maintype="application",
            subtype="octet-stream",
            filename="test.txt",
        )

        payload = extract_email_payload(message, envelope)

        assert payload["has_attachments"] is True
        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["filename"] == "test.txt"


class TestFastSMTPHandler:
    """Tests for FastSMTPHandler."""

    @pytest.fixture
    def test_settings(self):
        """Create test settings."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
        )

    @pytest.fixture
    def handler(self, test_settings):
        """Create a test handler."""
        queue = asyncio.Queue()
        return FastSMTPHandler(test_settings, queue)

    @pytest.mark.asyncio
    async def test_handle_rcpt_invalid_address(self, handler):
        """Test RCPT with invalid address."""
        server = MagicMock()
        session = MagicMock()
        envelope = Envelope()

        with patch("fastsmtp.smtp.server.async_session") as mock_session:
            mock_db = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db

            with patch("fastsmtp.smtp.server.lookup_recipient") as mock_lookup:
                mock_lookup.return_value = (None, None, "Invalid address")

                result = await handler.handle_RCPT(
                    server, session, envelope, "invalid", []
                )

                assert "550" in result
                assert "Invalid" in result


class TestSMTPServer:
    """Tests for SMTPServer class."""

    @pytest.fixture
    def test_settings(self):
        """Create test settings."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            smtp_host="127.0.0.1",
            smtp_port=10025,
            smtp_tls_port=10465,
        )

    def test_smtp_server_init(self, test_settings):
        """Test SMTPServer initialization."""
        server = SMTPServer(settings=test_settings)

        assert server.settings == test_settings
        assert server.message_queue is not None
        assert server.handler is not None

    def test_smtp_server_init_default_queue(self, test_settings):
        """Test SMTPServer creates default queue."""
        server = SMTPServer(settings=test_settings)
        assert isinstance(server.message_queue, asyncio.Queue)

    def test_smtp_server_init_custom_queue(self, test_settings):
        """Test SMTPServer uses custom queue."""
        queue = asyncio.Queue()
        server = SMTPServer(settings=test_settings, message_queue=queue)
        assert server.message_queue is queue

    @pytest.mark.asyncio
    async def test_smtp_server_get_message(self, test_settings):
        """Test getting message from queue."""
        queue = asyncio.Queue()
        server = SMTPServer(settings=test_settings, message_queue=queue)

        test_message = {"test": True}
        await queue.put(test_message)

        result = await server.get_message()
        assert result == test_message
