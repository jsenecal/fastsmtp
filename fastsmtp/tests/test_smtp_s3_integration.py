"""Tests for SMTP server S3 attachment storage integration."""

from datetime import UTC, datetime
from email import message_from_bytes
from email.message import EmailMessage
from unittest.mock import AsyncMock

import pytest
from aiosmtpd.smtp import Envelope
from fastsmtp.config import Settings
from fastsmtp.smtp.server import extract_email_payload, key_safe_message_id
from fastsmtp.storage.s3 import (
    S3AttachmentInfo,
    S3Storage,
    S3UploadError,
    sanitize_key_component,
)


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
    async def test_s3_upload_uses_provided_message_id(self, s3_settings):
        """The caller-provided message_id is used for the S3 key path."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<header-id@example.com>"
        msg.set_content("Body")
        msg.add_attachment(b"content", maintype="application", subtype="pdf", filename="file.pdf")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.return_value = S3AttachmentInfo(
            bucket="test-bucket",
            key="attachments/example.com/x/file.pdf",
            url="https://s3.amazonaws.com/test-bucket/attachments/example.com/x/file.pdf",
            presigned_url=None,
        )

        await extract_email_payload(
            msg,
            envelope,
            s3_settings,
            s3_storage=mock_s3,
            domain="example.com",
            message_id="<computed-id@fastsmtp>",
        )

        assert mock_s3.upload_attachment.call_args.kwargs["message_id"] == "<computed-id@fastsmtp>"

    @pytest.mark.asyncio
    async def test_s3_missing_message_id_generates_unique_ids(self, s3_settings):
        """Regression test for #44: messages without a Message-ID must not share
        the literal "unknown" S3 key path, or same-named attachments from
        different messages overwrite each other."""
        seen_message_ids = []

        for _ in range(2):
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "recipient@example.com"
            msg["Subject"] = "No message id"
            msg.set_content("Body")
            msg.add_attachment(
                b"content", maintype="application", subtype="pdf", filename="file.pdf"
            )

            envelope = Envelope()
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["recipient@example.com"]

            mock_s3 = AsyncMock(spec=S3Storage)
            mock_s3.upload_attachment.return_value = S3AttachmentInfo(
                bucket="test-bucket",
                key="attachments/example.com/x/file.pdf",
                url="https://s3.amazonaws.com/test-bucket/attachments/example.com/x/file.pdf",
                presigned_url=None,
            )

            await extract_email_payload(
                msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
            )
            seen_message_ids.append(mock_s3.upload_attachment.call_args.kwargs["message_id"])

        assert "unknown" not in seen_message_ids
        assert seen_message_ids[0] != seen_message_ids[1]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("degenerate", [b"<>", b"<  >", b'""'])
    async def test_s3_degenerate_message_id_generates_unique_ids(self, s3_settings, degenerate):
        """Regression test: a Message-ID that survives header parsing but not key
        sanitisation must not collapse to a shared S3 key path.

        #44 fixed the *absent* header by falling back to a UUID, but the guard
        tests truthiness. ``<>`` is truthy, so it reaches
        ``sanitize_key_component``, which strips it to the shared literal
        ``"unnamed"`` -- and every such message then overwrites the last.

        The message is parsed with ``message_from_bytes`` because that is what
        ``handle_DATA`` does. Its ``compat32`` policy hands the header back
        verbatim; assigning ``<>`` to an ``EmailMessage`` instead would raise in
        the stdlib's structured parser and never reach the code under test.
        """
        seen_message_ids = []

        for _ in range(2):
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "recipient@example.com"
            msg["Subject"] = "Degenerate message id"
            msg.set_content("Body")
            msg.add_attachment(
                b"content", maintype="application", subtype="pdf", filename="file.pdf"
            )
            on_the_wire = b"Message-ID: " + degenerate + b"\r\n" + msg.as_bytes()
            parsed = message_from_bytes(on_the_wire)
            assert parsed.get("Message-ID") == degenerate.decode()

            envelope = Envelope()
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["recipient@example.com"]

            mock_s3 = AsyncMock(spec=S3Storage)
            mock_s3.upload_attachment.return_value = S3AttachmentInfo(
                bucket="test-bucket",
                key="attachments/example.com/x/file.pdf",
                url="https://s3.amazonaws.com/test-bucket/attachments/example.com/x/file.pdf",
                presigned_url=None,
            )

            await extract_email_payload(
                parsed, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
            )
            seen_message_ids.append(mock_s3.upload_attachment.call_args.kwargs["message_id"])

        assert seen_message_ids[0] != seen_message_ids[1]
        # The point of the test: both must build usable, distinct key components.
        assert sanitize_key_component(seen_message_ids[0]) != "unnamed"
        assert sanitize_key_component(seen_message_ids[1]) != "unnamed"

    @pytest.mark.asyncio
    async def test_s3_usable_message_id_is_left_alone(self, s3_settings):
        """A Message-ID that sanitises to something identifying is used verbatim."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Subject"] = "Real message id"
        msg["Message-ID"] = "<real-id@example.com>"
        msg.set_content("Body")
        msg.add_attachment(b"content", maintype="application", subtype="pdf", filename="file.pdf")

        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@example.com"]

        mock_s3 = AsyncMock(spec=S3Storage)
        mock_s3.upload_attachment.return_value = S3AttachmentInfo(
            bucket="test-bucket",
            key="attachments/example.com/x/file.pdf",
            url="https://s3.amazonaws.com/test-bucket/attachments/example.com/x/file.pdf",
            presigned_url=None,
        )

        await extract_email_payload(
            msg, envelope, s3_settings, s3_storage=mock_s3, domain="example.com"
        )
        assert mock_s3.upload_attachment.call_args.kwargs["message_id"] == "<real-id@example.com>"

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


class TestKeySafeMessageId:
    """Tests for the single chokepoint both S3 key paths derive from."""

    @pytest.mark.parametrize("usable", ["<abc@example.com>", "abc@example.com", "plain-id"])
    def test_usable_ids_pass_through(self, usable):
        """Anything that survives sanitisation is returned verbatim."""
        assert key_safe_message_id(usable) == usable

    @pytest.mark.parametrize("unusable", [None, "", "   ", "<>", "<  >", '""', "<<>>"])
    def test_unusable_ids_are_replaced_with_something_unique(self, unusable):
        """Absent, empty and degenerate headers all get a generated id.

        Truthiness alone would let ``<>`` through -- it is a non-empty string
        that sanitises to nothing.
        """
        generated = key_safe_message_id(unusable)
        assert generated != unusable
        assert generated.endswith("@fastsmtp>")
        assert sanitize_key_component(generated) != "unnamed"
        assert key_safe_message_id(unusable) != generated, "must differ per call"

    def test_degenerate_ids_do_not_share_a_raw_archive_key(self):
        """Two ``<>`` messages to one domain on one day must not overwrite each other.

        This is the case ``preserve_raw_required`` cannot see: an overwrite is a
        *successful* PUT, so the "archive exists or roll back" promise is kept
        while the first message's bytes are gone.
        """
        storage = S3Storage(
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test123",
                s3_bucket="test-bucket",
                s3_access_key="key",
                s3_secret_key="secret",
            )
        )
        received_at = datetime(2026, 3, 7, 14, 30, tzinfo=UTC)

        keys = {
            storage._build_raw_key(
                domain="example.com",
                message_id=key_safe_message_id("<>"),
                received_at=received_at,
            )
            for _ in range(2)
        }
        assert len(keys) == 2
        assert not any(key.endswith("/unnamed.eml") for key in keys)
