"""Payload extraction must not descend into an attached message/rfc822 part.

``Message.walk()`` recurses into a ``message/rfc822`` attachment the same way
it recurses into an ordinary ``multipart/*`` container - the attached message
is internally shaped as a one-element list holding the forwarded ``Message``,
which is enough to make ``is_multipart()`` true and pull ``walk()`` in. Nothing
in the part loop distinguished the forwarded message's own parts from the
outer message's, so forwarding an email used to:

* let the forwarded message's ``text/plain`` and ``text/html`` bodies
  overwrite the outer ``body_text`` and ``body_html`` - which also decides
  what the ``body`` rule condition matches on
* hoist the forwarded message's attachments into the outer ``attachments``
  array as if they belonged to the wrapper
* hoist the forwarded message's inline/cid parts the same way, carrying a
  ``content_id`` that only ever resolves against the forwarded HTML, never
  against the outer ``body_html``

See issue #148.

The claims under test:

* **The wrapper's own body survives.** A forward must not let the inner
  message's body text replace the outer message's.
* **The forwarded message's attachments do not leak to the top level.** Only
  the ``message/rfc822`` part itself appears in ``attachments``.
* **The forwarded message's inline/cid parts do not leak to the top level**
  either - same reasoning, they belong to the inner HTML, not the outer one.
* **The attached message carries its real bytes.** Before this fix,
  ``get_payload(decode=True)`` returns ``None`` for a ``message/*`` part, so
  the attachment entry existed with no content and ``size: 0``. After the fix
  the entry's ``content`` decodes back into the exact bytes of the forwarded
  message.
* **``has_attachments`` is true when the forwarded message is the only
  attachment.** It has ``Content-Disposition: attachment``, which always
  counts per ``_counts_as_attachment``.
* **A forward of a forward does not descend either.** Nesting two levels deep
  must still yield exactly one top-level attachment.
* **A message/rfc822 part with no disposition, Content-ID or filename is
  still captured, never dropped.** Every other rule that would classify such
  a part can be absent on a bare forward; falling through to "body" there
  would lose the whole forwarded message with no trace.
* **A pathologically deep forward-of-a-forward degrades instead of failing
  the whole message.** Serializing the innermost attachment can blow
  Python's recursion limit; that must not take down extraction for the rest
  of a perfectly deliverable message.
"""

import base64
from email import message_from_bytes

import pytest
from aiosmtpd.smtp import Envelope
from fastsmtp.smtp.server import extract_email_payload


def _envelope() -> Envelope:
    envelope = Envelope()
    envelope.mail_from = "sender@example.com"
    envelope.rcpt_tos = ["recipient@example.com"]
    return envelope


PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"fake image data"


def _forwarded_message_bytes(subject: str = "Original subject", boundary: str = "inner") -> bytes:
    """A forwarded message with its own body, its own attachment and its own
    inline cid image - everything issue #148 says must not leak into the
    outer payload.
    """
    encoded_logo = base64.b64encode(PNG_BYTES).decode("ascii")
    encoded_pdf = base64.b64encode(b"%PDF-1.4 fake").decode("ascii")
    return f"""From: original-sender@forwarded.example
To: original-recipient@forwarded.example
Subject: {subject}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: multipart/alternative; boundary="{boundary}alt"

--{boundary}alt
Content-Type: text/plain; charset="utf-8"

Forwarded plain text body

--{boundary}alt
Content-Type: text/html; charset="utf-8"

<html><body><p>Forwarded HTML body</p><img src="cid:innerlogo@forwarded.example"></body></html>

--{boundary}alt--

--{boundary}
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <innerlogo@forwarded.example>
Content-Disposition: inline

{encoded_logo}

--{boundary}
Content-Type: application/pdf; name="invoice.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.pdf"

{encoded_pdf}

--{boundary}--
""".encode()


def _wrapper_message(
    inner: bytes,
    filename: str | None = "forwarded.eml",
    boundary: str = "outer",
    body_text: str = "Wrapper's own body text.",
) -> bytes:
    """Wrap ``inner`` as a message/rfc822 attachment inside a new message that
    has its own, distinct body.
    """
    disposition = "Content-Disposition: attachment"
    if filename:
        disposition += f'; filename="{filename}"'
    return (
        f"""From: wrapper-sender@example.com
To: wrapper-recipient@example.com
Subject: Fwd: something
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset="utf-8"

{body_text}

--{boundary}
Content-Type: message/rfc822
{disposition}

""".encode()
        + inner
        + f"\n--{boundary}--\n".encode()
    )


class TestWrapperBodySurvives:
    """The forwarded message's body must not replace the wrapper's own."""

    @pytest.mark.asyncio
    async def test_wrapper_text_body_is_kept(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        assert "Wrapper's own body text." in payload["body_text"]
        assert "Forwarded plain text body" not in payload["body_text"]

    @pytest.mark.asyncio
    async def test_wrapper_has_no_html_body_of_its_own(self):
        """The wrapper carries no text/html part - the forwarded message's
        text/html must not fill body_html in its place.
        """
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        assert payload["body_html"] == ""


class TestForwardedAttachmentsDoNotLeak:
    """The forwarded message's own attachments stay inside the .eml bytes."""

    @pytest.mark.asyncio
    async def test_only_the_rfc822_part_is_a_top_level_attachment(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["content_type"] == "message/rfc822"

    @pytest.mark.asyncio
    async def test_inner_pdf_filename_does_not_appear(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        filenames = [a["filename"] for a in payload["attachments"]]
        assert "invoice.pdf" not in filenames


class TestForwardedInlinePartsDoNotLeak:
    """The forwarded message's cid-referenced image is not a top-level part."""

    @pytest.mark.asyncio
    async def test_inner_content_id_does_not_appear(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        content_ids = [a.get("content_id") for a in payload["attachments"]]
        assert "innerlogo@forwarded.example" not in content_ids

    @pytest.mark.asyncio
    async def test_attachment_count_excludes_the_inline_image(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        # Just the message/rfc822 part - not the inline image nor the pdf that
        # live inside it.
        assert len(payload["attachments"]) == 1


class TestRfc822AttachmentCarriesRealBytes:
    """The .eml entry must carry the forwarded message, not an empty stub."""

    @pytest.mark.asyncio
    async def test_content_decodes_back_into_the_forwarded_message(self):
        inner = _forwarded_message_bytes(subject="Quarterly numbers")
        message = message_from_bytes(_wrapper_message(inner))

        payload = await extract_email_payload(message, _envelope())

        attachment = payload["attachments"][0]
        assert attachment["size"] == len(inner)
        assert attachment["content_transfer_encoding"] == "base64"
        decoded = base64.b64decode(attachment["content"])
        assert decoded == inner

        reparsed = message_from_bytes(decoded)
        assert reparsed["Subject"] == "Quarterly numbers"
        assert reparsed["From"] == "original-sender@forwarded.example"
        assert reparsed.get_payload(0).get_payload(0).get_payload(decode=True) == (
            b"Forwarded plain text body\n"
        )

    @pytest.mark.asyncio
    async def test_nameless_forward_falls_back_to_an_eml_extension(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes(), filename=None))

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["filename"].endswith(".eml")


class TestHasAttachmentsForForwardedMessage:
    """A forwarded message is, by itself, an attachment."""

    @pytest.mark.asyncio
    async def test_forwarded_message_alone_sets_has_attachments(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, _envelope())

        assert payload["has_attachments"] is True


class TestNestedForwardDoesNotDescend:
    """A forward of a forward must not recurse past the first rfc822 part."""

    @pytest.mark.asyncio
    async def test_forward_of_a_forward_is_a_single_attachment(self):
        innermost = _forwarded_message_bytes(subject="Innermost subject", boundary="innermost")
        middle = _wrapper_message(
            innermost,
            filename="innermost.eml",
            boundary="middle",
            body_text="Middle forward body",
        )
        outer = _wrapper_message(
            middle,
            filename="middle.eml",
            boundary="outer",
            body_text="Outer forward body",
        )
        message = message_from_bytes(outer)

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert attachment["filename"] == "middle.eml"
        assert attachment["content_type"] == "message/rfc822"

        assert "Outer forward body" in payload["body_text"]
        assert "Middle forward body" not in payload["body_text"]
        assert "Innermost subject" not in payload["body_text"]

        decoded = base64.b64decode(attachment["content"])
        assert decoded == middle


class TestHeaderlessForwardIsNotDropped:
    """A message/rfc822 part is never body content, even with no
    Content-Disposition header and no filename of its own.

    Every other classification rule in ``_classify_part`` that would otherwise
    catch such a part (an explicit disposition, a Content-ID, a filename) can
    be absent on a bare forward. Falling through to ``None`` there would mean
    the whole forwarded message vanishes from the payload with no trace -
    worse than the pre-#148 bug, where its content at least leaked out
    (misattributed, but visible).
    """

    @pytest.mark.asyncio
    async def test_bare_rfc822_part_is_still_an_attachment(self):
        inner = _forwarded_message_bytes()
        raw = (
            b"""From: wrapper-sender@example.com
To: wrapper-recipient@example.com
Subject: Fwd: something
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"

Wrapper's own body text.

--outer
Content-Type: message/rfc822

"""
            + inner
            + b"\n--outer--\n"
        )
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert attachment["content_type"] == "message/rfc822"
        assert attachment["disposition"] == "attachment"
        assert payload["has_attachments"] is True
        decoded = base64.b64decode(attachment["content"])
        assert decoded == inner


def _minimal_wrap(inner: bytes, boundary: str) -> bytes:
    """A leaner message/rfc822 wrapper than ``_wrapper_message`` - just enough
    structure to cost stack frames when nested hundreds of levels deep.
    """
    return (
        f"""From: a@example.com
To: b@example.com
Subject: fwd
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain

body

--{boundary}
Content-Type: message/rfc822

""".encode()
        + inner
        + f"\n--{boundary}--\n".encode()
    )


class TestPathologicalNestingDegradesGracefully:
    """A forward nested deeply enough blows Python's recursion limit during
    ``.as_bytes()`` serialization, even though parsing it succeeded. That must
    degrade the one attachment, not raise out of ``extract_email_payload`` and
    fail the whole message for every recipient.
    """

    @pytest.mark.asyncio
    async def test_deeply_nested_forward_does_not_raise(self):
        raw = b"From: a@example.com\nTo: b@example.com\nSubject: leaf\n\nleaf body\n"
        for i in range(200):
            raw = _minimal_wrap(raw, f"b{i}")
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, _envelope())

        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert attachment["content_type"] == "message/rfc822"
        assert attachment["size"] == 0
        assert "content" not in attachment
