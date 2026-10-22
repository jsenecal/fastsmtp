"""A message that is not multipart carries its one part as body or file (issue #175)."""

import base64
from email import message_from_bytes

import pytest
from fastsmtp.rules.engine import extract_field_values
from fastsmtp.smtp.server import extract_email_payload
from mime_helpers import PNG_BYTES, new_envelope

PDF_BYTES = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\nnot really a pdf\n"


def single_part(content: bytes, *header_lines: str) -> bytes:
    return (
        b"From: sender@example.com\r\nSubject: one part\r\n"
        + "".join(header_lines).encode()
        + b"\r\n"
        + content
    )


async def extract(raw: bytes) -> dict:
    return await extract_email_payload(message_from_bytes(raw), new_envelope())


class TestNonTextPartIsAnAttachment:
    @pytest.mark.asyncio
    async def test_pdf_with_attachment_disposition(self):
        payload = await extract(
            single_part(
                base64.b64encode(PDF_BYTES),
                'Content-Type: application/pdf; name="report.pdf"\r\n',
                'Content-Disposition: attachment; filename="report.pdf"\r\n',
                "Content-Transfer-Encoding: base64\r\n",
            )
        )
        [attachment] = payload["attachments"]
        assert attachment["filename"] == "report.pdf"
        assert attachment["content_type"] == "application/pdf"
        assert attachment["disposition"] == "attachment"
        assert base64.b64decode(attachment["content"]) == PDF_BYTES
        assert payload["body_text"] == ""
        assert payload["body_html"] == ""
        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_unnamed_image_without_disposition_gets_a_fallback_name(self):
        # Some scanners and scripts send a bare image as the whole message.
        payload = await extract(
            single_part(
                base64.b64encode(PNG_BYTES),
                "Content-Type: image/png\r\n",
                "Content-Transfer-Encoding: base64\r\n",
            )
        )
        [attachment] = payload["attachments"]
        assert attachment["content_type"] == "image/png"
        assert attachment["disposition"] == "attachment"
        assert attachment["filename"].endswith(".png")
        assert base64.b64decode(attachment["content"]) == PNG_BYTES
        assert payload["body_text"] == ""
        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_content_id_makes_it_inline(self):
        # Same as inside multipart mail: a Content-ID marks the part inline.
        payload = await extract(
            single_part(
                base64.b64encode(PNG_BYTES),
                "Content-Type: image/png\r\n",
                "Content-ID: <logo@example.com>\r\n",
                "Content-Transfer-Encoding: base64\r\n",
            )
        )
        [attachment] = payload["attachments"]
        assert attachment["disposition"] == "inline"
        assert attachment["content_id"] == "logo@example.com"
        # Nothing renders it, so it still counts.
        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_delivery_status_is_not_captured_as_an_empty_file(self):
        # message/delivery-status is report data, not a file. Capturing it would
        # put a zero-byte stub in a bounce and set has_attachments on mail that
        # carries nothing - see _classify_part.
        payload = await extract(
            single_part(
                b"Reporting-MTA: dns; mx.example.com\r\n",
                "Content-Type: message/delivery-status\r\n",
            )
        )
        assert payload["attachments"] == []
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_rules_see_the_lone_part(self):
        raw = single_part(
            base64.b64encode(PDF_BYTES),
            'Content-Type: application/pdf; name="report.pdf"\r\n',
            "Content-Transfer-Encoding: base64\r\n",
        )
        message = message_from_bytes(raw)
        payload = await extract_email_payload(message, new_envelope())
        assert extract_field_values("attachment_names", message, payload) == ["report.pdf"]
        assert extract_field_values("has_attachment", message, payload) == ["true"]


class TestTextPartIsTheBody:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "content_type, field",
        [
            ("text/plain", "body_text"),
            ("text/html", "body_html"),
            # Not plain or html, but the whole message: still the body, as before.
            ("text/calendar", "body_text"),
        ],
    )
    async def test_text_is_decoded_into_the_body(self, content_type, field):
        payload = await extract(
            single_part(
                "caf\u00e9".encode("latin-1"),
                f"Content-Type: {content_type}; charset=latin-1\r\n",
            )
        )
        assert payload[field] == "caf\u00e9"
        assert payload["attachments"] == []
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "charset, content, expected",
        [
            # An unknown charset, and bytes that are not valid in the one declared.
            ("x-no-such-charset", b"caf\xc3\xa9", "caf\u00e9"),
            ("utf-8", b"caf\xe9", "caf\ufffd"),
        ],
    )
    async def test_undecodable_charset_falls_back_to_utf8(self, charset, content, expected):
        payload = await extract(
            single_part(content, f"Content-Type: text/plain; charset={charset}\r\n")
        )
        assert payload["body_text"] == expected

    @pytest.mark.asyncio
    async def test_inline_disposition_without_a_filename_is_still_the_body(self):
        payload = await extract(
            single_part(
                b"hello",
                "Content-Type: text/plain\r\n",
                "Content-Disposition: inline\r\n",
            )
        )
        assert payload["body_text"] == "hello"
        assert payload["attachments"] == []

    @pytest.mark.asyncio
    async def test_text_marked_attachment_without_a_filename_is_a_file(self):
        payload = await extract(
            single_part(
                b"notes",
                "Content-Type: text/plain\r\n",
                "Content-Disposition: attachment\r\n",
            )
        )
        [attachment] = payload["attachments"]
        assert attachment["filename"].endswith(".txt")
        assert payload["body_text"] == ""

    @pytest.mark.asyncio
    async def test_text_with_a_disposition_filename_is_a_file(self):
        # The rule multipart mail already follows: a filename the sender put
        # on Content-Disposition marks a text part as a file.
        payload = await extract(
            single_part(
                b"a,b\r\n1,2\r\n",
                "Content-Type: text/csv\r\n",
                'Content-Disposition: attachment; filename="data.csv"\r\n',
            )
        )
        [attachment] = payload["attachments"]
        assert attachment["filename"] == "data.csv"
        assert base64.b64decode(attachment["content"]) == b"a,b\r\n1,2\r\n"
        assert payload["body_text"] == ""

    @pytest.mark.asyncio
    async def test_message_without_content_type_is_plain_text(self):
        payload = await extract(single_part(b"just text"))
        assert payload["body_text"] == "just text"
        assert payload["attachments"] == []

    @pytest.mark.asyncio
    async def test_multipart_without_a_boundary_stays_body_text(self):
        # The parser cannot split it, so there are no parts: the raw text is
        # still delivered as the body rather than dropped or captured as a file.
        payload = await extract(single_part(b"raw text", "Content-Type: multipart/mixed\r\n"))
        assert payload["body_text"] == "raw text"
        assert payload["attachments"] == []
