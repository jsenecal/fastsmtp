"""Tests for SMTP server functionality."""

from email import message_from_bytes

from fastsmtp.smtp.server import extract_email_payload


class TestExtractEmailPayload:
    """Tests for email payload extraction."""

    def test_extract_simple_email(self, sample_email_content: bytes):
        """Test extracting payload from simple email."""
        message = message_from_bytes(sample_email_content)

        class MockEnvelope:
            mail_from = "sender@example.com"
            rcpt_tos = ["recipient@test.com"]

        payload = extract_email_payload(message, MockEnvelope())

        assert payload["message_id"] == "<test123@example.com>"
        assert payload["from"] == "sender@example.com"
        assert payload["to"] == "recipient@test.com"
        assert payload["subject"] == "Test Email"
        assert "This is a test email body" in payload["body_text"]
        assert payload["has_attachments"] is False

    def test_extract_multipart_email(self, sample_multipart_email: bytes):
        """Test extracting payload from multipart email."""
        message = message_from_bytes(sample_multipart_email)

        class MockEnvelope:
            mail_from = "sender@example.com"
            rcpt_tos = ["recipient@test.com"]

        payload = extract_email_payload(message, MockEnvelope())

        assert payload["message_id"] == "<test456@example.com>"
        assert payload["subject"] == "Test Multipart Email"
        assert "plain text version" in payload["body_text"]
        assert "HTML version" in payload["body_html"]
        assert payload["has_attachments"] is False

    def test_extract_envelope_data(self, sample_email_content: bytes):
        """Test that envelope data is included."""
        message = message_from_bytes(sample_email_content)

        class MockEnvelope:
            mail_from = "bounce@example.com"
            rcpt_tos = ["recipient1@test.com", "recipient2@test.com"]

        payload = extract_email_payload(message, MockEnvelope())

        assert payload["envelope_from"] == "bounce@example.com"
        assert "recipient1@test.com" in payload["envelope_to"]
        assert "recipient2@test.com" in payload["envelope_to"]

    def test_extract_headers(self, sample_email_content: bytes):
        """Test that headers are included."""
        message = message_from_bytes(sample_email_content)

        class MockEnvelope:
            mail_from = "sender@example.com"
            rcpt_tos = ["recipient@test.com"]

        payload = extract_email_payload(message, MockEnvelope())

        assert "headers" in payload
        assert payload["headers"]["From"] == "sender@example.com"
        assert payload["headers"]["Subject"] == "Test Email"
