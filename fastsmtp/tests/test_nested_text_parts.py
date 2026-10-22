"""Text parts other than plain or html inside multipart mail are captured (issue #178)."""

import base64
from email import message_from_bytes

import pytest
from fastsmtp.smtp.server import extract_email_payload
from mime_helpers import new_envelope

INVITE = b"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n"


def multipart(subtype: str, *parts: bytes) -> bytes:
    body = b"".join(b"--b\r\n" + part + b"\r\n" for part in parts)
    return (
        b"From: organizer@example.com\r\nSubject: Meeting\r\n"
        + f"Content-Type: multipart/{subtype}; boundary=b\r\n\r\n".encode()
        + body
        + b"--b--\r\n"
    )


PLAIN = b"Content-Type: text/plain\r\n\r\nJoin us."
HTML = b"Content-Type: text/html\r\n\r\n<p>Join us.</p>"
CALENDAR = b"Content-Type: text/calendar; method=REQUEST\r\n\r\n" + INVITE


async def extract(raw: bytes) -> dict:
    return await extract_email_payload(message_from_bytes(raw), new_envelope())


class TestCalendarInvite:
    @pytest.mark.asyncio
    async def test_invite_without_disposition_in_mixed_is_an_attachment(self):
        # Dropped before: neither body nor attachment, so the invite was lost.
        payload = await extract(multipart("mixed", PLAIN, CALENDAR))
        assert payload["body_text"] == "Join us."
        [attachment] = payload["attachments"]
        assert attachment["content_type"] == "text/calendar"
        assert attachment["disposition"] == "attachment"
        assert attachment["filename"].endswith(".ics")
        assert base64.b64decode(attachment["content"]) == INVITE
        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_invite_as_an_alternative_is_an_attachment(self):
        # Outlook puts the invite beside the plain and html versions.
        payload = await extract(multipart("alternative", PLAIN, HTML, CALENDAR))
        assert payload["body_text"] == "Join us."
        assert payload["body_html"] == "<p>Join us.</p>"
        [attachment] = payload["attachments"]
        assert attachment["content_type"] == "text/calendar"

    @pytest.mark.asyncio
    async def test_inline_invite_is_captured_inline(self):
        calendar = b"Content-Type: text/calendar\r\nContent-Disposition: inline\r\n\r\n" + INVITE
        payload = await extract(multipart("mixed", PLAIN, calendar))
        [attachment] = payload["attachments"]
        assert attachment["disposition"] == "inline"
        # Not an image, so nothing renders it away: it counts.
        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_named_invite_keeps_its_name(self):
        calendar = b'Content-Type: text/calendar; name="invite.ics"\r\n\r\n' + INVITE
        payload = await extract(multipart("mixed", PLAIN, calendar))
        [attachment] = payload["attachments"]
        assert attachment["filename"] == "invite.ics"


class TestBodyPartsAreUnchanged:
    @pytest.mark.asyncio
    async def test_plain_and_html_are_still_the_body(self):
        payload = await extract(multipart("alternative", PLAIN, HTML))
        assert payload["body_text"] == "Join us."
        assert payload["body_html"] == "<p>Join us.</p>"
        assert payload["attachments"] == []

    @pytest.mark.asyncio
    async def test_named_html_body_is_still_the_body(self):
        # Some clients name the body part; a Content-Type name alone does not
        # make text/plain or text/html a file.
        html = b'Content-Type: text/html; name="message.html"\r\n\r\n<p>Hi</p>'
        payload = await extract(multipart("mixed", html))
        assert payload["body_html"] == "<p>Hi</p>"
        assert payload["attachments"] == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("subtype", ["x-amp-html", "watch-html", "enriched"])
    async def test_alternative_renderings_of_the_body_are_not_files(self, subtype):
        # RFC 2046 section 5.1.4: an alternative is another version of the same
        # content. Gmail AMP and Apple Watch renderings ride on ordinary mail;
        # capturing them would set has_attachments on every newsletter.
        alternative = f"Content-Type: text/{subtype}\r\n\r\n<p>Join us.</p>".encode()
        payload = await extract(multipart("alternative", PLAIN, alternative, HTML))
        assert payload["body_text"] == "Join us."
        assert payload["body_html"] == "<p>Join us.</p>"
        assert payload["attachments"] == []
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_delivery_report_data_is_not_captured(self):
        # multipart/report (RFC 6522): the human-readable part is the body, and
        # neither message/delivery-status nor the returned text/rfc822-headers
        # is a file - capturing them would set has_attachments on every bounce.
        report = (
            b"From: mailer-daemon@example.com\r\n"
            b"Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n"
            b"--b\r\nContent-Type: text/plain\r\n\r\nDelivery failed.\r\n"
            b"--b\r\nContent-Type: message/delivery-status\r\n\r\n"
            b"Reporting-MTA: dns; mx.example.com\r\n\r\n"
            b"Final-Recipient: rfc822; gone@example.com\r\nAction: failed\r\n"
            b"--b\r\nContent-Type: text/rfc822-headers\r\n\r\n"
            b"Subject: original\r\n"
            b"--b--\r\n"
        )
        payload = await extract(report)
        assert payload["body_text"] == "Delivery failed."
        assert payload["attachments"] == []
        assert payload["has_attachments"] is False
