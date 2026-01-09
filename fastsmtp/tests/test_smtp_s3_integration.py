"""Tests for SMTP server S3 attachment storage integration."""

from email.message import EmailMessage
from unittest.mock import AsyncMock

import pytest
from aiosmtpd.smtp import Envelope
from fastsmtp.config import Settings
from fastsmtp.smtp.server import extract_email_payload
from fastsmtp.storage.s3 import S3AttachmentInfo, S3Storage, S3UploadError


class TestExtractEmailPayloadWithS3:
    """Tests for extract_email_payload with S3 storage."""

    @pytest.fixture
    def s3_settings(self):
        """Create settings with S3 configured."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test123",
            attachment_storage="s3",
            s3_bucket="test-bucket",
            s3_access_key="key",
            s3_secret_key="secret",
        )

    @pytest.fixture
    def inline_settings(self):
        """Create settings with inline storage (default)."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test123",
            attachment_storage="inline",
        )

    @pytest.mark.asyncio
    async def test_s3_attachment_upload_success(self, s3_settings):
        """Test email payload extraction with successful S3 upload."""
        # Create email with attachment
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test with attachment"
        msg["Message-ID"] = "<test123@example.com>"
        msg.set_content("Body text")
        msg.add_attachment(
            b"PDF content here",
            maintype="application",
            subtype="pdf",
            filename="report.pdf",
        )

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        # Mock S3 storage
        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.return_value = S3AttachmentInfo(
            bucket="test-bucket",
            key="attachments/example.com/test123/report.pdf",
            url="https://s3.amazonaws.com/test-bucket/attachments/example.com/test123/report.pdf",
            presigned_url=None,
        )

        payload = await extract_email_payload(
            msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
        )

        assert len(payload["attachments"]) == 1
        att = payload["attachments"][0]
        assert att["storage"] == "s3"
        assert att["bucket"] == "test-bucket"
        assert "key" in att
        assert "url" in att
        assert "content" not in att  # No inline content

    @pytest.mark.asyncio
    async def test_s3_attachment_with_presigned_url(self, s3_settings):
        """Test email payload includes presigned URL when available."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"
        msg.set_content("Body")
        msg.add_attachment(b"content", maintype="application", subtype="pdf", filename="file.pdf")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.return_value = S3AttachmentInfo(
            bucket="test-bucket",
            key="attachments/file.pdf",
            url="https://s3.amazonaws.com/test-bucket/attachments/file.pdf",
            presigned_url="https://s3.amazonaws.com/test-bucket/attachments/file.pdf?X-Amz-Signature=...",
        )

        payload = await extract_email_payload(
            msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
        )

        att = payload["attachments"][0]
        assert att["presigned_url"] is not None
        assert "X-Amz-Signature" in att["presigned_url"]

    @pytest.mark.asyncio
    async def test_s3_fallback_on_upload_failure(self, s3_settings):
        """Test email payload falls back to inline when S3 fails."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"
        msg.set_content("Body")
        msg.add_attachment(b"content", maintype="application", subtype="pdf", filename="file.pdf")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        # Mock S3 storage to fail
        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.side_effect = S3UploadError("Failed", "file.pdf")

        payload = await extract_email_payload(
            msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
        )

        assert len(payload["attachments"]) == 1
        att = payload["attachments"][0]
        assert att["storage"] == "inline"
        assert att["storage_fallback"] is True
        assert "content" in att

    @pytest.mark.asyncio
    async def test_inline_storage_without_s3(self, inline_settings):
        """Test email payload uses inline storage when S3 not configured."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"
        msg.set_content("Body")
        msg.add_attachment(b"content", maintype="application", subtype="pdf", filename="file.pdf")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        # No S3 storage provided
        payload = await extract_email_payload(
            msg, envelope, inline_settings, s3_storage=None, domain=None
        )

        assert len(payload["attachments"]) == 1
        att = payload["attachments"][0]
        assert att["storage"] == "inline"
        assert "content" in att
        assert "bucket" not in att

    @pytest.mark.asyncio
    async def test_multiple_attachments_s3(self, s3_settings):
        """Test multiple attachments all uploaded to S3."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"
        msg.set_content("Body")
        msg.add_attachment(
            b"pdf content", maintype="application", subtype="pdf", filename="doc.pdf"
        )
        msg.add_attachment(b"image content", maintype="image", subtype="png", filename="image.png")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        # Mock S3 storage
        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.side_effect = [
            S3AttachmentInfo(
                bucket="test-bucket",
                key="attachments/doc.pdf",
                url="https://s3.amazonaws.com/test-bucket/attachments/doc.pdf",
                presigned_url=None,
            ),
            S3AttachmentInfo(
                bucket="test-bucket",
                key="attachments/image.png",
                url="https://s3.amazonaws.com/test-bucket/attachments/image.png",
                presigned_url=None,
            ),
        ]

        payload = await extract_email_payload(
            msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
        )

        assert len(payload["attachments"]) == 2
        for att in payload["attachments"]:
            assert att["storage"] == "s3"
            assert "bucket" in att
            assert "key" in att

    @pytest.mark.asyncio
    async def test_partial_s3_failure_mixed_storage(self, s3_settings):
        """Test partial S3 failure results in mixed storage types."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"
        msg.set_content("Body")
        msg.add_attachment(
            b"pdf content", maintype="application", subtype="pdf", filename="doc.pdf"
        )
        msg.add_attachment(b"image content", maintype="image", subtype="png", filename="image.png")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        # First upload succeeds, second fails
        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.side_effect = [
            S3AttachmentInfo(
                bucket="test-bucket",
                key="attachments/doc.pdf",
                url="https://s3.amazonaws.com/test-bucket/attachments/doc.pdf",
                presigned_url=None,
            ),
            S3UploadError("Network error", "image.png"),
        ]

        payload = await extract_email_payload(
            msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
        )

        assert len(payload["attachments"]) == 2
        # First attachment in S3
        assert payload["attachments"][0]["storage"] == "s3"
        # Second attachment fell back to inline
        assert payload["attachments"][1]["storage"] == "inline"
        assert payload["attachments"][1]["storage_fallback"] is True
