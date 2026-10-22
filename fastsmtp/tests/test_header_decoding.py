"""Decoded convenience headers in the webhook payload and rules engine (issue #172)."""

from email import message_from_bytes
from email.header import Header
from email.message import Message
from types import SimpleNamespace

import pytest
from fastsmtp.rules.conditions import evaluate_condition
from fastsmtp.rules.engine import extract_field_value
from fastsmtp.smtp.headers import decoded_header
from fastsmtp.smtp.server import extract_email_payload

ENCODED_SUBJECT = (
    b"Subject: =?utf-8?B?Q291cHVyZSBkZSBzZXJ2aWNl?=\r\n =?utf-8?Q?_pr=C3=A9vue?= demain\r\n"
)


def parse(*header_lines: bytes) -> object:
    return message_from_bytes(b"".join(header_lines) + b"\r\nbody\r\n")


ENVELOPE = SimpleNamespace(mail_from="bounce@example.com", rcpt_tos=["rcpt@example.com"])


class TestDecodedHeader:
    def test_folded_b_and_q_encoded_subject_decodes_and_unfolds(self):
        message = parse(ENCODED_SUBJECT)
        assert decoded_header(message, "Subject") == "Coupure de service prévue demain"

    def test_encoded_display_name_keeps_address(self):
        message = parse(b"From: =?iso-8859-1?Q?J=E9r=F4me?= Dupont <jd@example.com>\r\n")
        assert decoded_header(message, "From") == "Jérôme Dupont <jd@example.com>"

    def test_address_list_decodes_each_display_name(self):
        message = parse(b'To: "Plain, Name" <a@x.com>, =?utf-8?B?w4lsb2RpZQ==?= <e@x.com>\r\n')
        assert decoded_header(message, "To") == '"Plain, Name" <a@x.com>, Élodie <e@x.com>'

    def test_decoded_display_name_with_specials_is_quoted(self):
        # Left bare, "Dupont, Jean" reads as two addresses to any consumer that
        # parses the list.
        message = parse(b"Cc: =?utf-8?B?RHVwb250LCBKZWFu?= <a@x.com>\r\n")
        assert decoded_header(message, "Cc") == '"Dupont, Jean" <a@x.com>'

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # Malformed addresses: a structured parser "repairs" these to "<>"
            # and "x", losing the address the consumer was sent.
            (b"<<garbage", "<<garbage"),
            (b"=?utf-8?q?x?= <bad@@x>", "x <bad@@x>"),
            # Comments, including the legacy "addr (Name)" form, survive.
            (b"a@x.com (=?utf-8?Q?J=C3=A9?=)", "a@x.com (J\u00e9)"),
            (b"John (work) <a@x.com>,  b@x.com", "John (work) <a@x.com>,  b@x.com"),
            # No space before "<" still gets the name quoted.
            (b"=?utf-8?B?RHVwb250LCBKZWFu?=<a@x.com>", '"Dupont, Jean"<a@x.com>'),
            # An encoded-word inside a quoted string is decoded but not re-quoted.
            (b'"=?utf-8?B?RHVwb250LCBKZWFu?=" <a@x.com>', '"Dupont, Jean" <a@x.com>'),
            # Quotes and backslashes in a decoded name are escaped when quoting.
            (b"=?utf-8?Q?A_=22B=22_=5C_C?= <a@x.com>", '"A \\"B\\" \\\\ C" <a@x.com>'),
            # Decoded text is escaped for the quoted-string or comment it lands in.
            (b'"=?utf-8?q?a=22b?=" <x@y>, c@d', '"a\\"b" <x@y>, c@d'),
            (b"(=?utf-8?q?a)b?=) x@y", "(a\\)b) x@y"),
            # A bare encoded address is not a display name, so it is not quoted.
            (b"=?utf-8?q?jd=40example.com?=", "jd@example.com"),
            (b"=?utf-8?q?jd=40x.com?=, Name <b@x.com>", "jd@x.com, Name <b@x.com>"),
            (
                b"=?utf-8?q?jd=40x.com?= Plain, =?utf-8?q?Name?= <b@x.com>",
                "jd@x.com Plain, Name <b@x.com>",
            ),
            # Obsolete syntax elsewhere in the list does not change the quoting.
            (
                b"a@x.com, , =?utf-8?B?RHVwb250LCBKZWFu?= <b@x.com>",
                'a@x.com, , "Dupont, Jean" <b@x.com>',
            ),
        ],
    )
    def test_address_header_changes_only_encoded_words(self, raw, expected):
        message = parse(b"Reply-To: " + raw + b"\r\n")
        assert decoded_header(message, "Reply-To") == expected

    def test_subject_is_never_quoted(self):
        message = parse(b"Subject: =?utf-8?B?RHVwb250LCBKZWFu?= <a@x.com>\r\n")
        assert decoded_header(message, "Subject") == "Dupont, Jean <a@x.com>"

    def test_multibyte_character_split_across_words(self):
        # "\u00e9" is C3 A9 in UTF-8; each encoded-word carries one byte.
        message = parse(b"Subject: =?utf-8?Q?caf=C3?= =?utf-8?Q?=A9?=\r\n")
        assert decoded_header(message, "Subject") == "caf\u00e9"

    def test_whitespace_between_encoded_and_plain_text_is_kept(self):
        message = parse(b"Subject: Re: =?utf-8?Q?caf=C3=A9?=  ok\r\n")
        assert decoded_header(message, "Subject") == "Re: caf\u00e9  ok"

    @pytest.mark.parametrize(
        "raw",
        [
            b"=?utf-8?B?not*base64!?=",
            b"=?utf-8?B?w4?=",
            b"=?base64?Q?abc?=",
            b"=?idna?Q?=FF?=",
            b"=?utf-8*en?X?abc?=",
            b"=??Q?abc?=",
            b"=?utf-8?Q??=",
            b"\xff\xfe =?utf-8?Q?=FF?= \x80",
        ],
    )
    def test_hostile_input_never_raises(self, raw):
        message = parse(b"Subject: " + raw + b"\r\n", b"From: " + raw + b"\r\n")
        assert isinstance(decoded_header(message, "Subject"), str)
        assert isinstance(decoded_header(message, "From"), str)

    def test_decoded_line_breaks_cannot_inject_lines(self):
        message = parse(b"Subject: =?utf-8?q?a=0D=0AX:_1=00?=\r\n")
        assert decoded_header(message, "Subject") == "a  X: 1 "

    def test_programmatic_header_object_is_tolerated(self):
        message = Message()
        message["Subject"] = Header("caf\u00e9", "utf-8")
        assert decoded_header(message, "Subject") == "caf\u00e9"

    def test_charset_language_suffix_is_ignored(self):
        # RFC 2231 section 5 lets an encoded-word carry "charset*language".
        message = parse(b"Subject: =?utf-8*fr?Q?caf=C3=A9?=\r\n")
        assert decoded_header(message, "Subject") == "caf\u00e9"

    def test_unknown_charset_falls_back_without_raising(self):
        message = parse(b"Subject: =?bogus-charset?Q?abc?= tail\r\n")
        assert decoded_header(message, "Subject") == "abc tail"

    def test_mislabelled_charset_uses_replacement_characters(self):
        message = parse(b"From: =?utf-8?Q?bad=FF?= <r@x.com>\r\n")
        assert decoded_header(message, "From") == "bad\ufffd <r@x.com>"

    def test_raw_utf8_header_decodes(self):
        # RFC 6532 headers arrive as 8-bit bytes; compat32 hands those back as
        # an email.header.Header, not a str.
        message = parse("Subject: caf\u00e9\r\n".encode())
        assert decoded_header(message, "Subject") == "caf\u00e9"

    def test_missing_header_is_empty_string(self):
        assert decoded_header(parse(b"X-Other: 1\r\n"), "Subject") == ""

    def test_lookup_is_case_insensitive(self):
        assert decoded_header(parse(b"SUBJECT: hi\r\n"), "Subject") == "hi"


class TestPayloadFields:
    @pytest.mark.asyncio
    async def test_convenience_fields_are_decoded(self):
        message = parse(
            b"From: =?iso-8859-1?Q?J=E9r=F4me?= <jd@example.com>\r\n",
            b"To: =?utf-8?B?w4lsb2RpZQ==?= <e@x.com>\r\n",
            b"Cc: =?utf-8?Q?Ren=C3=A9e?= <r@x.com>\r\n",
            b"Reply-To: =?utf-8?Q?Andr=C3=A9?= <a@x.com>\r\n",
            ENCODED_SUBJECT,
        )
        payload = await extract_email_payload(message, ENVELOPE)
        assert payload["from"] == "Jérôme <jd@example.com>"
        assert payload["to"] == "Élodie <e@x.com>"
        assert payload["cc"] == "Renée <r@x.com>"
        assert payload["reply_to"] == "André <a@x.com>"
        assert payload["subject"] == "Coupure de service prévue demain"

    @pytest.mark.asyncio
    async def test_headers_stay_raw(self):
        message = parse(ENCODED_SUBJECT)
        payload = await extract_email_payload(message, ENVELOPE)
        assert payload["headers"]["Subject"] == (
            "=?utf-8?B?Q291cHVyZSBkZSBzZXJ2aWNl?=\r\n =?utf-8?Q?_pr=C3=A9vue?= demain"
        )


class TestRulesUseDecodedValues:
    @pytest.mark.parametrize(
        "field_name, header_line, pattern",
        [
            ("subject", ENCODED_SUBJECT, "prévue"),
            ("from", b"From: =?iso-8859-1?Q?J=E9r=F4me?= <jd@example.com>\r\n", "Jérôme"),
            ("to", b"To: =?utf-8?B?w4lsb2RpZQ==?= <e@x.com>\r\n", "Élodie"),
        ],
    )
    def test_contains_matches_decoded_text(self, field_name, header_line, pattern):
        value = extract_field_value(field_name, parse(header_line), {})
        assert evaluate_condition("contains", value, pattern)

    def test_header_field_stays_raw(self):
        value = extract_field_value("header:Subject", parse(ENCODED_SUBJECT), {})
        assert value is not None
        assert value.startswith("=?utf-8?B?")
