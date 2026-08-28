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
from fastsmtp.smtp.server import extract_email_payload
from mime_helpers import PNG_BYTES, envelope


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

        payload = await extract_email_payload(message, envelope())

        assert "Wrapper's own body text." in payload["body_text"]
        assert "Forwarded plain text body" not in payload["body_text"]

    @pytest.mark.asyncio
    async def test_wrapper_has_no_html_body_of_its_own(self):
        """The wrapper carries no text/html part - the forwarded message's
        text/html must not fill body_html in its place.
        """
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, envelope())

        assert payload["body_html"] == ""


class TestForwardedAttachmentsDoNotLeak:
    """The forwarded message's own attachments stay inside the .eml bytes."""

    @pytest.mark.asyncio
    async def test_only_the_rfc822_part_is_a_top_level_attachment(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, envelope())

        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["content_type"] == "message/rfc822"

    @pytest.mark.asyncio
    async def test_inner_pdf_filename_does_not_appear(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, envelope())

        filenames = [a["filename"] for a in payload["attachments"]]
        assert "invoice.pdf" not in filenames


class TestForwardedInlinePartsDoNotLeak:
    """The forwarded message's cid-referenced image is not a top-level part."""

    @pytest.mark.asyncio
    async def test_inner_content_id_does_not_appear(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, envelope())

        content_ids = [a.get("content_id") for a in payload["attachments"]]
        assert "innerlogo@forwarded.example" not in content_ids

    @pytest.mark.asyncio
    async def test_attachment_count_excludes_the_inline_image(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, envelope())

        # Just the message/rfc822 part - not the inline image nor the pdf that
        # live inside it.
        assert len(payload["attachments"]) == 1


class TestRfc822AttachmentCarriesRealBytes:
    """The .eml entry must carry the forwarded message, not an empty stub."""

    @pytest.mark.asyncio
    async def test_content_decodes_back_into_the_forwarded_message(self):
        inner = _forwarded_message_bytes(subject="Quarterly numbers")
        message = message_from_bytes(_wrapper_message(inner))

        payload = await extract_email_payload(message, envelope())

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

        payload = await extract_email_payload(message, envelope())

        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["filename"].endswith(".eml")


class TestHasAttachmentsForForwardedMessage:
    """A forwarded message is, by itself, an attachment."""

    @pytest.mark.asyncio
    async def test_forwarded_message_alone_sets_has_attachments(self):
        message = message_from_bytes(_wrapper_message(_forwarded_message_bytes()))

        payload = await extract_email_payload(message, envelope())

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

        payload = await extract_email_payload(message, envelope())

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

        payload = await extract_email_payload(message, envelope())

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

        payload = await extract_email_payload(message, envelope())

        assert len(payload["attachments"]) == 1
        attachment = payload["attachments"][0]
        assert attachment["content_type"] == "message/rfc822"
        assert attachment["size"] == 0
        assert "content" not in attachment


class TestOtherMessageSubtypes:
    """``message/*`` is not all forwarded mail.

    A DSN's ``message/delivery-status`` sits under the same maintype but is
    report data, not an encapsulated message. Capturing it would put a
    zero-byte stub in the payload of every bounce and, because an
    ``attachment`` disposition always counts, would set ``has_attachments`` on
    mail carrying nothing - firing every ``has_attachment`` rule on bounce
    traffic. Note the fixture carries no ``Content-Disposition``, which is what
    real DSNs send and what makes this reach the classifier's fallback at all.
    """

    @staticmethod
    def _bounce() -> bytes:
        return b"""From: MAILER-DAEMON@example.com
To: sender@example.com
Subject: Undelivered Mail Returned to Sender
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"

Delivery to the following recipient failed.

--outer
Content-Type: message/delivery-status

Reporting-MTA: dns; example.com

Final-Recipient: rfc822; one@example.com
Action: failed

Final-Recipient: rfc822; two@example.com
Action: failed

--outer--
"""

    @pytest.mark.asyncio
    async def test_bounce_carries_no_attachment_entry(self):
        message = message_from_bytes(self._bounce())

        payload = await extract_email_payload(message, envelope())

        assert "Delivery to the following recipient failed" in payload["body_text"]
        assert payload["attachments"] == []

    @pytest.mark.asyncio
    async def test_bounce_does_not_set_has_attachments(self):
        message = message_from_bytes(self._bounce())

        payload = await extract_email_payload(message, envelope())

        assert payload["has_attachments"] is False


class TestEncodedEncapsulatedMessage:
    """RFC 2045 restricts ``message/*`` to an identity transfer encoding.

    A client that base64s the forwarded message anyway leaves the parser
    holding the undecoded text as the submessage body. Serializing that gives
    a ``content`` which decodes to more base64 rather than to a message -
    plausible-looking bytes that are not the forwarded mail. Better to ship the
    metadata-only stub and say nothing false.
    """

    @pytest.mark.asyncio
    async def test_base64_encoded_forward_degrades_to_metadata(self):
        inner = b"From: original@example.com\nSubject: Original\n\nOriginal body\n"
        encoded = base64.b64encode(inner).decode("ascii")
        raw = f"""From: sender@example.com
To: recipient@example.com
Subject: Fwd, wrongly encoded
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"

See attached.

--outer
Content-Type: message/rfc822
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="forwarded.eml"

{encoded}

--outer--
""".encode()
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, envelope())

        entry = next(a for a in payload["attachments"] if a["content_type"] == "message/rfc822")
        assert entry["size"] == 0
        assert "content" not in entry
        assert payload["has_attachments"] is True


class TestMalformedContainers:
    """A multipart the parser cannot split has no parts to walk.

    A container declaring no boundary leaves ``get_payload()`` returning the
    raw string rather than a list of parts, so the iterator has nothing to
    descend into and must not treat the string as one.
    """

    @pytest.mark.asyncio
    async def test_nested_boundaryless_multipart_yields_no_parts(self):
        """The broken container has to be nested to reach the walk at all.

        A top-level container with no boundary never reports itself as
        multipart, so extraction takes the single-part path and the iterator is
        never entered. Nested inside a container that did split, it is reached.
        """
        raw = b"""From: sender@example.com
To: recipient@example.com
Subject: Broken nested container
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"

Body text

--outer
Content-Type: multipart/alternative

not actually split into parts

--outer--
"""
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, envelope())

        assert "Body text" in payload["body_text"]
        assert payload["attachments"] == []
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_unlabelled_binary_part_is_still_dropped(self):
        """A part with no disposition, no filename and no Content-ID.

        There is nothing to say it is a file and nothing to render it by, so it
        stays out of the payload, exactly as it did before inline capture.
        """
        raw = b"""From: sender@example.com
To: recipient@example.com
Subject: Anonymous part
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset="utf-8"

Body text

--outer
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

aGVsbG8gd29ybGQ=

--outer--
"""
        message = message_from_bytes(raw)

        payload = await extract_email_payload(message, envelope())

        assert "Body text" in payload["body_text"]
        assert payload["attachments"] == []
