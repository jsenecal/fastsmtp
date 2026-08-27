"""Payload extraction for inline parts and Content-ID.

HTML mail embeds images by reference: the body carries ``<img src="cid:x">``
and a sibling part carries ``Content-ID: <x>``. Historically the part walk in
``extract_email_payload`` kept a part only when its ``Content-Disposition``
contained ``attachment``, so those sibling parts matched no branch of the walk
and were discarded with neither their bytes nor their filename, and the parts
that did survive carried no ``content_id`` for the reference to resolve
against. See issue #146 and MetroOptic/portal#98.

The claims under test:

* **An inline part reaches the consumer.** Bytes, filename and content type,
  through the same storage path as any other attachment.
* **``content_id`` is emitted with the angle brackets stripped.** The header
  value is an addr-spec in brackets; the ``cid:`` URL in the HTML is the bare
  addr-spec (RFC 2392). Emitting the raw header would leave every consumer
  stripping brackets before it could match, which is the state that forced the
  downstream filename heuristic in the first place.
* **``content_id`` is independent of disposition.** Outlook marks
  cid-referenced images ``attachment`` as often as ``inline``; both need the
  field.
* **``has_attachments`` still counts only attachment-disposition parts.** It
  backs the ``has_attachment`` rule field, and corporate signature footers are
  inline logos - counting them would flip the field to true for a large share
  of ordinary mail and silently re-route existing rules on upgrade.
* **The message body is not mistaken for an inline part.** Outlook and Apple
  Mail both put ``Content-Disposition: inline`` on the ``text/plain`` and
  ``text/html`` body parts themselves. A rule that captured every inline
  disposition would empty ``body_text`` and turn the body into an attachment.
"""

import base64
from email import message_from_bytes
from email.message import EmailMessage

import pytest
from aiosmtpd.smtp import Envelope
from fastsmtp.smtp.server import extract_email_payload


def _envelope() -> Envelope:
    envelope = Envelope()
    envelope.mail_from = "sender@example.com"
    envelope.rcpt_tos = ["recipient@example.com"]
    return envelope


PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"fake image data"


def _outlook_style_message(disposition: str = "inline") -> bytes:
    """A multipart/related shaped the way Outlook emits a signature logo."""
    encoded = base64.b64encode(PNG_BYTES).decode("ascii")
    return f"""From: sender@example.com
To: recipient@example.com
Subject: Quarterly update
MIME-Version: 1.0
Content-Type: multipart/related; boundary="outer"

--outer
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable
Content-Disposition: inline

<html><body><p>Regards,</p><img src=3D"cid:image001.png@01DA1234.5678"></body=
></html>

--outer
Content-Type: image/png; name="image001.png"
Content-Transfer-Encoding: base64
Content-ID: <image001.png@01DA1234.5678>
Content-Disposition: {disposition}; filename="image001.png"

{encoded}

--outer--
""".encode()


class TestInlineParts:
    """Inline-disposition parts survive the walk and carry their Content-ID."""

    @pytest.mark.asyncio
    async def test_inline_image_is_captured(self):
        message = message_from_bytes(_outlook_style_message())

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert attachment["filename"] == "image001.png"
        assert attachment["content_type"] == "image/png"
        assert attachment["size"] == len(PNG_BYTES)
        assert base64.b64decode(attachment["content"]) == PNG_BYTES
        assert attachment["content_transfer_encoding"] == "base64"

    @pytest.mark.asyncio
    async def test_content_id_has_angle_brackets_stripped(self):
        message = message_from_bytes(_outlook_style_message())

        payload = await extract_email_payload(message, _envelope())

        assert payload["attachments"][0]["content_id"] == "image001.png@01DA1234.5678"

    @pytest.mark.asyncio
    async def test_inline_part_is_marked_inline(self):
        message = message_from_bytes(_outlook_style_message())

        payload = await extract_email_payload(message, _envelope())

        assert payload["attachments"][0]["disposition"] == "inline"

    @pytest.mark.asyncio
    async def test_content_id_survives_attachment_disposition(self):
        """Outlook marks cid-referenced images "attachment" as often as "inline"."""
        message = message_from_bytes(_outlook_style_message(disposition="attachment"))

        payload = await extract_email_payload(message, _envelope())

        attachment = payload["attachments"][0]
        assert attachment["content_id"] == "image001.png@01DA1234.5678"
        assert attachment["disposition"] == "attachment"

    @pytest.mark.asyncio
    async def test_html_body_is_still_extracted(self):
        """Capturing the sibling part must not consume the body it belongs to."""
        message = message_from_bytes(_outlook_style_message())

        payload = await extract_email_payload(message, _envelope())

        assert "cid:image001.png@01DA1234.5678" in payload["body_html"]

    @pytest.mark.asyncio
    async def test_part_with_name_but_no_disposition_is_captured(self):
        """Some clients emit a bare Content-Type name= and no disposition header."""
        encoded = base64.b64encode(PNG_BYTES).decode("ascii")
        raw = f"""From: sender@example.com
To: recipient@example.com
Subject: No disposition
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"

Body text

--outer
Content-Type: image/png; name="photo.png"
Content-Transfer-Encoding: base64

{encoded}

--outer--
""".encode()
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["filename"] == "photo.png"


class TestHasAttachmentsSemantics:
    """``has_attachments`` backs a routing rule field and must not drift."""

    @pytest.mark.asyncio
    async def test_inline_only_message_reports_no_attachments(self):
        message = message_from_bytes(_outlook_style_message())

        payload = await extract_email_payload(message, _envelope())

        assert payload["attachments"], "inline part should still be captured"
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_attachment_disposition_still_reports_attachments(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "recipient@example.com"
        message["Subject"] = "With attachment"
        message.set_content("Body text")
        message.add_attachment(
            b"file content",
            maintype="application",
            subtype="octet-stream",
            filename="test.txt",
        )

        payload = await extract_email_payload(message, _envelope())

        assert payload["has_attachments"] is True
        assert payload["attachments"][0]["disposition"] == "attachment"

    @pytest.mark.asyncio
    async def test_mixed_message_counts_only_the_attachment(self):
        encoded = base64.b64encode(PNG_BYTES).decode("ascii")
        raw = f"""From: sender@example.com
To: recipient@example.com
Subject: Logo and a real attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/html; charset="utf-8"
Content-Disposition: inline

<html><body><img src="cid:logo@example.com"></body></html>

--outer
Content-Type: image/png; name="logo.png"
Content-Transfer-Encoding: base64
Content-ID: <logo@example.com>
Content-Disposition: inline; filename="logo.png"

{encoded}

--outer
Content-Type: application/pdf; name="invoice.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.pdf"

{base64.b64encode(b"%PDF-1.4 fake").decode("ascii")}

--outer--
""".encode()
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 2
        by_name = {a["filename"]: a for a in payload["attachments"]}
        assert by_name["logo.png"]["disposition"] == "inline"
        assert by_name["invoice.pdf"]["disposition"] == "attachment"
        assert payload["has_attachments"] is True


class TestBodyPartsAreNotAttachments:
    """Body parts routinely carry ``Content-Disposition: inline``."""

    @pytest.mark.asyncio
    async def test_inline_body_parts_stay_bodies(self):
        raw = b"""From: sender@example.com
To: recipient@example.com
Subject: Apple Mail shape
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"
Content-Disposition: inline

Plain text body

--outer
Content-Type: text/html; charset="utf-8"
Content-Disposition: inline

<html><body><p>HTML body</p></body></html>

--outer--
"""
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert "Plain text body" in payload["body_text"]
        assert "HTML body" in payload["body_html"]
        assert payload["attachments"] == []
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_inline_text_part_with_filename_is_an_attachment(self):
        """A filename is what separates an inline text file from the body."""
        raw = b"""From: sender@example.com
To: recipient@example.com
Subject: Inline text file
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"
Content-Disposition: inline

Body text

--outer
Content-Type: text/plain; charset="utf-8"
Content-Disposition: inline; filename="notes.txt"

Note contents

--outer--
"""
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert "Body text" in payload["body_text"]
        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["filename"] == "notes.txt"


class TestRelatedRootPart:
    """The root part of a multipart/related carries its own Content-ID.

    RFC 2387 identifies the root part by the container's ``start`` parameter,
    whose value is that part's Content-ID. So an HTML body legitimately carries
    the header, and a Content-ID alone cannot be what marks a text part as a
    file - otherwise the body disappears from ``body_html`` and resurfaces as a
    nameless base64 blob in ``attachments``.
    """

    @staticmethod
    def _related_with_start() -> bytes:
        encoded = base64.b64encode(PNG_BYTES).decode("ascii")
        return f"""From: sender@example.com
To: recipient@example.com
Subject: Related with start
MIME-Version: 1.0
Content-Type: multipart/related; boundary="outer"; type="text/html"; start="<root@example.com>"

--outer
Content-Type: text/html; charset="utf-8"
Content-ID: <root@example.com>

<html><body><p>Real body</p><img src="cid:logo@example.com"></body></html>

--outer
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <logo@example.com>
Content-Disposition: inline

{encoded}

--outer--
""".encode()

    @pytest.mark.asyncio
    async def test_root_part_stays_the_body(self):
        message = message_from_bytes(self._related_with_start())

        payload = await extract_email_payload(message, _envelope())

        assert "Real body" in payload["body_html"]

    @pytest.mark.asyncio
    async def test_root_part_is_not_also_an_attachment(self):
        message = message_from_bytes(self._related_with_start())

        payload = await extract_email_payload(message, _envelope())

        assert [a["content_type"] for a in payload["attachments"]] == ["image/png"]

    @pytest.mark.asyncio
    async def test_empty_content_id_header_does_not_displace_the_body(self):
        """Some relays emit a bare ``Content-ID: <>`` on the body part."""
        raw = b"""From: sender@example.com
To: recipient@example.com
Subject: Empty content id
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"
Content-ID: <>

Plain body

--outer--
"""
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert "Plain body" in payload["body_text"]
        assert payload["attachments"] == []


class TestFilenamelessParts:
    """cid-referenced images routinely carry no filename at all.

    Every such part used to collapse to the literal name ``unnamed``, which is
    also what the S3 key is built from - so a message with two of them wrote
    both to one key and the second silently overwrote the first, leaving one
    ``cid:`` reference resolving to the wrong image and the other's bytes gone.
    """

    @staticmethod
    def _two_nameless_images() -> bytes:
        encoded = base64.b64encode(PNG_BYTES).decode("ascii")
        return f"""From: sender@example.com
To: recipient@example.com
Subject: Two nameless logos
MIME-Version: 1.0
Content-Type: multipart/related; boundary="outer"

--outer
Content-Type: text/html; charset="utf-8"

<html><body><img src="cid:one@example.com"><img src="cid:two@example.com"></body></html>

--outer
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <one@example.com>
Content-Disposition: inline

{encoded}

--outer
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <two@example.com>
Content-Disposition: inline

{encoded}

--outer--
""".encode()

    @pytest.mark.asyncio
    async def test_nameless_parts_get_distinct_filenames(self):
        message = message_from_bytes(self._two_nameless_images())

        payload = await extract_email_payload(message, _envelope())

        filenames = [a["filename"] for a in payload["attachments"]]
        assert len(filenames) == 2
        assert len(set(filenames)) == 2, f"S3 keys would collide: {filenames}"

    @pytest.mark.asyncio
    async def test_fallback_filename_carries_the_content_type_extension(self):
        message = message_from_bytes(self._two_nameless_images())

        payload = await extract_email_payload(message, _envelope())

        assert all(a["filename"].endswith(".png") for a in payload["attachments"])

    @pytest.mark.asyncio
    async def test_sender_supplied_filenames_are_left_alone(self):
        message = message_from_bytes(_outlook_style_message())

        payload = await extract_email_payload(message, _envelope())

        assert payload["attachments"][0]["filename"] == "image001.png"


class TestUnreferencedInlinePartsCount:
    """An inline part the body never renders is a file, not a decoration.

    Excusing a part from ``has_attachments`` purely because it said ``inline``
    hands the sender the exemption: ``Content-Disposition: inline;
    filename="invoice.exe"`` would be delivered to the webhook consumer while
    ``has_attachment`` stayed false, so a "quarantine anything with an
    attachment" rule never fired. What actually marks a decoration is that the
    HTML renders it - a ``cid:`` URL in the body pointing at the part. That is
    also how mail clients decide what to put behind the paperclip.
    """

    @staticmethod
    def _inline_file(headers: str, body_html: str = "<html><body>Hi</body></html>") -> bytes:
        encoded = base64.b64encode(b"MZ fake executable").decode("ascii")
        return f"""From: sender@example.com
To: recipient@example.com
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/html; charset="utf-8"

{body_html}

--outer
Content-Type: application/x-msdownload
Content-Transfer-Encoding: base64
{headers}

{encoded}

--outer--
""".encode()

    @pytest.mark.asyncio
    async def test_inline_file_without_a_content_id_counts(self):
        message = message_from_bytes(
            self._inline_file('Content-Disposition: inline; filename="invoice.exe"')
        )

        payload = await extract_email_payload(message, _envelope())

        assert payload["attachments"][0]["filename"] == "invoice.exe"
        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_unreferenced_content_id_does_not_buy_an_exemption(self):
        """The body has to actually reference the cid, not merely declare one."""
        message = message_from_bytes(
            self._inline_file(
                'Content-Disposition: inline; filename="invoice.exe"\n'
                "Content-ID: <never-referenced@evil.example>"
            )
        )

        payload = await extract_email_payload(message, _envelope())

        assert payload["has_attachments"] is True

    @pytest.mark.asyncio
    async def test_referenced_content_id_is_a_decoration(self):
        message = message_from_bytes(
            self._inline_file(
                'Content-Disposition: inline; filename="logo.png"\nContent-ID: <shown@example.com>',
                body_html='<html><body><img src="cid:shown@example.com"></body></html>',
            )
        )

        payload = await extract_email_payload(message, _envelope())

        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_attachment_disposition_counts_even_when_referenced(self):
        """Outlook marks cid images "attachment"; those already set the flag today."""
        message = message_from_bytes(
            self._inline_file(
                'Content-Disposition: attachment; filename="logo.png"\n'
                "Content-ID: <shown@example.com>",
                body_html='<html><body><img src="cid:shown@example.com"></body></html>',
            )
        )

        payload = await extract_email_payload(message, _envelope())

        assert payload["has_attachments"] is True


class TestContentIdIsUntrusted:
    """``Content-ID`` is sender-controlled and consumers interpolate it.

    The docs tell consumers to match it against the ``cid:`` URLs in
    ``body_html``, which invites putting it straight into an attribute. A
    well-formed value is an addr-spec, so anything carrying quotes, angle
    brackets, whitespace or control characters is malformed and is dropped
    rather than forwarded.
    """

    @staticmethod
    def _with_content_id(value: str) -> bytes:
        encoded = base64.b64encode(PNG_BYTES).decode("ascii")
        return f"""From: sender@example.com
To: recipient@example.com
Subject: Hostile content id
MIME-Version: 1.0
Content-Type: multipart/related; boundary="outer"

--outer
Content-Type: text/html; charset="utf-8"

<html><body>Hi</body></html>

--outer
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: {value}
Content-Disposition: inline

{encoded}

--outer--
""".encode()

    @pytest.mark.asyncio
    async def test_markup_bearing_content_id_is_dropped(self):
        message = message_from_bytes(self._with_content_id('<a"><script>alert(1)</script><b>'))

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        assert "content_id" not in payload["attachments"][0]

    @pytest.mark.asyncio
    async def test_overlong_content_id_is_dropped(self):
        message = message_from_bytes(self._with_content_id("<" + "a" * 600 + "@example.com>"))

        payload = await extract_email_payload(message, _envelope())

        assert "content_id" not in payload["attachments"][0]

    @pytest.mark.asyncio
    async def test_well_formed_content_id_survives(self):
        message = message_from_bytes(self._with_content_id("<image001.png@01DA1234.5678>"))

        payload = await extract_email_payload(message, _envelope())

        assert payload["attachments"][0]["content_id"] == "image001.png@01DA1234.5678"
