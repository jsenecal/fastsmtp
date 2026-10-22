"""Decoded convenience headers in the webhook payload and rules engine (issue #172)."""

import time
from email import message_from_bytes
from email.header import Header
from email.message import Message
from email.utils import getaddresses

import pytest
from fastsmtp.rules.conditions import evaluate_condition
from fastsmtp.rules.engine import extract_field_value
from fastsmtp.smtp.headers import (
    PartFilename,
    decoded_header,
    part_filename,
    raw_header,
    raw_headers,
)
from fastsmtp.smtp.server import extract_email_payload
from mime_helpers import new_envelope

ENCODED_SUBJECT = (
    b"Subject: =?utf-8?B?Q291cHVyZSBkZSBzZXJ2aWNl?=\r\n =?utf-8?Q?_pr=C3=A9vue?= demain\r\n"
)
ENCODED_FROM = b"From: =?iso-8859-1?Q?J=E9r=F4me?= <jd@example.com>\r\n"
ENCODED_TO = b"To: =?utf-8?B?w4lsb2RpZQ==?= <e@x.com>\r\n"


def parse(*header_lines: bytes) -> Message:
    return message_from_bytes(b"".join(header_lines) + b"\r\nbody\r\n")


def addresses(value: str) -> list[list[str]]:
    """What a consumer's parser makes of an address header, in both modes."""
    return [[addr for _, addr in getaddresses([value], strict=strict)] for strict in (True, False)]


class TestDecodedHeader:
    def test_folded_b_and_q_encoded_subject_decodes_and_unfolds(self):
        message = parse(ENCODED_SUBJECT)
        assert decoded_header(message, "Subject") == "Coupure de service pr\u00e9vue demain"

    def test_encoded_display_name_keeps_address(self):
        message = parse(b"From: =?iso-8859-1?Q?J=E9r=F4me?= Dupont <jd@example.com>\r\n")
        assert decoded_header(message, "From") == "J\u00e9r\u00f4me Dupont <jd@example.com>"

    def test_address_list_decodes_each_display_name(self):
        message = parse(b'To: "Plain, Name" <a@x.com>, =?utf-8?B?w4lsb2RpZQ==?= <e@x.com>\r\n')
        assert decoded_header(message, "To") == '"Plain, Name" <a@x.com>, \u00c9lodie <e@x.com>'

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
            (b"(=?utf-8?q?a=29b?=) x@y", "(a\\)b) x@y"),
            # A display name whose encoded text holds a special is quoted.
            (b"=?utf-8?Q?boss=40corp.com?= <x@evil.com>", '"boss@corp.com" <x@evil.com>'),
            (
                b'=?utf-8?B?RHVwb250LCBKZWFu?= "Sr, Eng" <a@x>',
                '"Dupont, Jean" "Sr, Eng" <a@x>',
            ),
            # A group's display name is followed by ":" rather than "<".
            (b"=?utf-8?Q?Caf=C3=A9?=: a@x;", "Caf\u00e9: a@x;"),
            (b"J. =?utf-8?Q?Dupont?= <j@x>", "J. Dupont <j@x>"),
            # A period is allowed in a display name and is not quoted.
            (b"=?utf-8?Q?J=2E_Dupont?= <j@x>", "J. Dupont <j@x>"),
            # An unclosed "<" does not stop decoding in the next address.
            (b"a@x, <<bad, =?utf-8?Q?J=C3=A9?= <c@y>", "a@x, <<bad, J\u00e9 <c@y>"),
            # Obsolete syntax elsewhere in the list does not change the quoting.
            (
                b"a@x.com, , =?utf-8?B?RHVwb250LCBKZWFu?= <b@x.com>",
                'a@x.com, , "Dupont, Jean" <b@x.com>',
            ),
        ],
    )
    def test_address_header_decodes_only_names_and_comments(self, raw, expected):
        message = parse(b"Reply-To: " + raw + b"\r\n")
        decoded = decoded_header(message, "Reply-To")
        assert decoded == expected
        assert addresses(decoded) == addresses(raw_header(message, "Reply-To"))

    @pytest.mark.parametrize(
        "raw",
        [
            # RFC 2047 section 5 forbids encoded-words in an addr-spec, so
            # anything that is not a display name or comment stays as sent and
            # an encoded address can never pass for the sender.
            b"=?utf-8?q?jd=40example.com?=",
            b"=?utf-8?Q?boss=40corp.com=2C?= attacker@evil.com",
            b"=?utf-8?Q?Boss_=3Cboss=40corp.com=3E?=",
            b"<=?utf-8?Q?a=2Cb?=@x>",
            b'<"=?utf-8?Q?boss=40corp.com?="@evil.com>',
            # Touching another atom, or followed by "@" before any "<".
            b"=?utf-8?Q?admin?=@corp.com",
            b"admin@=?utf-8?Q?corp?=.com",
            b"=?utf-8?Q?a?= =?utf-8?Q?b?=@x",
            b"=?utf-8?Q?boss?= @corp.com",
            b"=?utf-8?Q?boss?= . x @corp.com",
            b"=?utf-8?q?ceo?= @corp.com <x@y>",
            b"=?utf-8?q?ceo?= @corp.com:x@y;",
            # A quoted-string that is the local-part, or the whole address.
            b'"=?utf-8?q?ceo?="@corp.com',
            b'"=?utf-8?q?ceo=40corp.com?="',
            # An unclosed quote: parsers read what follows as the addr-spec.
            b'x@y, "=?utf-8?q?evil=40corp.com?=',
        ],
    )
    def test_encoded_word_in_an_address_is_not_decoded(self, raw):
        message = parse(b"From: " + raw + b"\r\n")
        assert decoded_header(message, "From") == raw.decode()

    def test_only_the_address_part_stays_encoded(self):
        message = parse(b"To: =?utf-8?q?A?= <=?utf-8?Q?a?=@x>\r\n")
        assert decoded_header(message, "To") == "A <=?utf-8?Q?a?=@x>"

    @pytest.mark.parametrize(
        "raw",
        [b"Jane (=?utf-8?q?Doe=2C_Jane?=) <x@y>", b"x@y (=?utf-8?q?Doe=2C_Jane?=)"],
    )
    def test_decoding_that_changes_parsed_addresses_is_abandoned(self, raw):
        # Python's strict parser counts the decoded comma in the comment and
        # drops the address. Whatever the reason, a decode that changes what
        # the field parses to is not shipped.
        message = parse(b"Cc: " + raw + b"\r\n")
        assert decoded_header(message, "Cc") == raw.decode()

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("ceo\u2066@corp.com", "ceo\ufffd@corp.com"),
            ("Boss <ceo\u202e@corp.com>", "Boss <ceo\ufffd@corp.com>"),
            ("ceo\x01@corp.com", "ceo\ufffd@corp.com"),
        ],
    )
    def test_unsafe_characters_in_an_address_never_collapse_it(self, raw, expected):
        # Removed, or turned into a space, these would turn the address into
        # ceo@corp.com: a different mailbox.
        message = parse(f"From: {raw}\r\n".encode())
        assert decoded_header(message, "From") == expected

    def test_decoded_display_name_cannot_carry_bidi_or_line_breaks(self):
        message = parse(b"From: =?utf-8?Q?=E2=80=AEmoc.knab=0D=0A?= <a@x>\r\n")
        assert decoded_header(message, "From") == "\ufffdmoc.knab\ufffd\ufffd <a@x>"

    @pytest.mark.parametrize("name", ["To", "Subject"])
    def test_tab_folds_are_kept(self, name):
        # CRLF + HTAB is ordinary folding (Outlook and many MTAs emit it); the
        # TAB is whitespace, not a control character to neutralise.
        message = parse(f"{name}: =?utf-8?Q?Jean?= <a@x>,\r\n\tb@y.com\r\n".encode())
        assert decoded_header(message, name) == "Jean <a@x>,\tb@y.com"

    def test_many_same_charset_words_decode_in_linear_time(self):
        # Joining the bytes of a run with += on immutable bytes was quadratic.
        message = parse(b"Subject: " + b"=?utf-8?B?QUFBQUFBQUFBQUFB?= " * 40000 + b"\r\n")
        started = time.perf_counter()
        decoded_header(message, "Subject")
        assert time.perf_counter() - started < 2

    def test_many_encoded_words_decode_in_linear_time(self):
        # Rescanning the rest of the header for every encoded-word made this
        # take seconds, and a sender controls how many there are.
        message = parse(b"To: " + b"=?x?q?a?= " * 5000 + b"<a@x>\r\n")
        started = time.perf_counter()
        decoded_header(message, "To")
        assert time.perf_counter() - started < 2

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

    @pytest.mark.parametrize(
        "header_line, expected",
        [
            (b"Subject: =?utf-8\x00?q?hi?=\r\n", "hi"),
            (b"From: =?\x00?q?x?= <a@b>\r\n", "x <a@b>"),
        ],
    )
    def test_nul_in_charset_does_not_raise(self, header_line, expected):
        # codecs.lookup raises ValueError, not LookupError, for a name with a
        # NUL in it; uncaught, it failed delivery with a 451 on every retry.
        name = header_line.split(b":")[0].decode()
        assert decoded_header(parse(header_line), name) == expected

    def test_decoded_line_breaks_cannot_inject_lines(self):
        message = parse(b"Subject: =?utf-8?q?a=0D=0AX:_1=00?=\r\n")
        assert decoded_header(message, "Subject") == "a  X: 1 "

    @pytest.mark.parametrize(
        "raw",
        [b"=?iso-8859-1?Q?a=85b?=", b"=?utf-8?Q?a=E2=80=A8b?=", b"=?utf-8?Q?a=E2=80=A9b?="],
    )
    def test_unicode_line_separators_become_spaces(self, raw):
        assert decoded_header(parse(b"Subject: " + raw + b"\r\n"), "Subject") == "a b"

    def test_raw_utf8_line_separators_and_controls_become_spaces(self):
        message = parse("Subject: a\u2028b\u0085c\x00d\x1be\r\n".encode())
        assert decoded_header(message, "Subject") == "a b c d e"

    @pytest.mark.parametrize(
        "raw",
        [b"=?unicode_escape?Q?=5Cud800?=", b"=?raw_unicode_escape?Q?=5Cudfff?="],
    )
    def test_codecs_cannot_produce_lone_surrogates(self, raw):
        # Postgres rejects a lone surrogate in JSONB, so one in the payload
        # would fail the insert and the delivery with it.
        assert decoded_header(parse(b"Subject: " + raw + b"\r\n"), "Subject") == "\ufffd"

    def test_bidi_controls_are_removed_from_subject(self):
        message = parse(b"Subject: =?utf-8?Q?=E2=80=AEcba=E2=81=A6?=\r\n")
        assert decoded_header(message, "Subject") == "cba"

    def test_joiners_are_kept(self):
        # ZWNJ is part of ordinary Persian spelling; ZWJ builds emoji sequences.
        message = parse("Subject: \u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645\r\n".encode())
        assert "\u200c" in decoded_header(message, "Subject")

    def test_angle_brackets_mean_nothing_in_subject(self):
        message = parse(b"Subject: <=?utf-8?Q?caf=C3=A9?=>\r\n")
        assert decoded_header(message, "Subject") == "<caf\u00e9>"

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


class TestRawHeaders:
    """``headers`` and ``header:<name>`` keep the undecoded value, as text."""

    def test_raw_utf8_is_decoded_as_utf8(self):
        # compat32 hands RFC 6532 bytes back as an email.header.Header whose
        # str() turns each byte into its own U+FFFD.
        message = parse("X-A: \u00e9t\u00e9\r\n".encode())
        assert raw_header(message, "X-A") == "\u00e9t\u00e9"
        assert raw_headers(message) == {"X-A": "\u00e9t\u00e9"}

    def test_encoded_words_and_folds_are_kept(self):
        message = parse(ENCODED_SUBJECT)
        assert raw_header(message, "Subject") == (
            "=?utf-8?B?Q291cHVyZSBkZSBzZXJ2aWNl?=\r\n =?utf-8?Q?_pr=C3=A9vue?= demain"
        )

    def test_invalid_utf8_uses_replacement_characters(self):
        message = parse(b"X-A: caf\xe9\r\n")
        assert raw_header(message, "X-A") == "caf\ufffd"

    def test_first_occurrence_for_one_header_last_for_the_dict(self):
        # Matches what message.get() and dict(message.items()) did before.
        message = parse(b"X-A: one\r\n", b"X-A: two\r\n")
        assert raw_header(message, "x-a") == "one"
        assert raw_headers(message) == {"X-A": "two"}

    def test_lone_surrogate_does_not_raise(self):
        # Only reachable from a Message built from a str, never from the wire.
        message = Message()
        message["Subject"] = "a\ud800b"
        assert raw_header(message, "Subject") == "a\ufffdb"

    def test_missing_header_is_empty_string(self):
        assert raw_header(parse(b"X-Other: 1\r\n"), "X-A") == ""


def attachment_part(*header_lines: str) -> Message:
    return message_from_bytes(
        ("Content-Type: application/pdf\r\n" + "".join(header_lines) + "\r\nAAAA").encode()
    )


class TestPartFilename:
    @pytest.mark.parametrize(
        "disposition, expected",
        [
            # RFC 6532 raw UTF-8: compat32's get_filename() made this "caf\ufffd\ufffd.pdf".
            ('attachment; filename="caf\u00e9.pdf"', "caf\u00e9.pdf"),
            # RFC 2231, which get_filename() already handled.
            ("attachment; filename*=utf-8''caf%C3%A9.pdf", "caf\u00e9.pdf"),
            ("attachment; filename*0*=utf-8''caf%C3%A9; filename*1=\".pdf\"", "caf\u00e9.pdf"),
            # RFC 2047 inside quotes: forbidden by section 5 but sent by Outlook
            # and many libraries; get_filename() returned the encoded-word.
            ('attachment; filename="=?utf-8?Q?caf=C3=A9.pdf?="', "caf\u00e9.pdf"),
            ('attachment; filename="=?utf-8?B?w6k=?= =?utf-8?B?w6k=?=.txt"', "\u00e9\u00e9.txt"),
            # Plain names are unchanged.
            ('attachment; filename="a;b.pdf"', "a;b.pdf"),
            ("attachment; filename=plain.pdf", "plain.pdf"),
            # A bad charset degrades to U+FFFD rather than raising.
            ("attachment; filename*=bogus''%FF.pdf", "\ufffd.pdf"),
            # Control characters cannot put a line break into the name...
            ("attachment; filename*=utf-8''a%0D%0Ab.pdf", "a  b.pdf"),
            # ...nor a bidi override reverse how it displays.
            ("attachment; filename*=utf-8''a%E2%80%AEfdp.exe", "afdp.exe"),
        ],
    )
    def test_disposition_filename(self, disposition, expected):
        part = attachment_part(f"Content-Disposition: {disposition}\r\n")
        assert part_filename(part) == PartFilename(expected, on_disposition=True)

    def test_content_type_name_is_the_fallback(self):
        part = message_from_bytes(
            b'Content-Type: application/pdf; name="=?utf-8?Q?caf=C3=A9.pdf?="\r\n\r\nAAAA'
        )
        assert part_filename(part) == PartFilename("caf\u00e9.pdf", on_disposition=False)

    def test_falls_back_to_compat32_when_the_parse_finds_nothing(self):
        # The structured parser drops an unquoted encoded-word; a part that had
        # a filename before must not lose it, and the fallback is decoded too.
        part = attachment_part(
            "Content-Disposition: attachment; filename==?utf-8?Q?caf=C3=A9.pdf?=\r\n"
        )
        assert part_filename(part) == PartFilename("caf\u00e9.pdf", on_disposition=True)

    def test_compat32_disposition_filename_outranks_content_type_name(self):
        # The order get_filename() always used, and the flag that keeps a text
        # part carrying a disposition filename from being read as body.
        part = message_from_bytes(
            b'Content-Type: text/plain; name="body.txt"\r\n'
            b"Content-Disposition: inline; filename==?utf-8?Q?file.txt?=\r\n\r\nhi"
        )
        assert part_filename(part) == PartFilename("file.txt", on_disposition=True)

    def test_nul_in_rfc2231_charset_does_not_raise(self):
        part = attachment_part("Content-Disposition: attachment; filename*=utf\x00''abc\r\n")
        assert isinstance(part_filename(part), PartFilename)

    def test_no_filename(self):
        part = attachment_part("Content-Disposition: attachment\r\n")
        assert part_filename(part) == PartFilename(None, on_disposition=False)


class TestPayloadFields:
    @pytest.mark.asyncio
    async def test_convenience_fields_are_decoded(self):
        message = parse(
            ENCODED_FROM,
            ENCODED_TO,
            b"Cc: =?utf-8?Q?Ren=C3=A9e?= <r@x.com>\r\n",
            b"Reply-To: =?utf-8?Q?Andr=C3=A9?= <a@x.com>\r\n",
            ENCODED_SUBJECT,
        )
        payload = await extract_email_payload(message, new_envelope())
        assert payload["from"] == "J\u00e9r\u00f4me <jd@example.com>"
        assert payload["to"] == "\u00c9lodie <e@x.com>"
        assert payload["cc"] == "Ren\u00e9e <r@x.com>"
        assert payload["reply_to"] == "Andr\u00e9 <a@x.com>"
        assert payload["subject"] == "Coupure de service pr\u00e9vue demain"

    @pytest.mark.asyncio
    async def test_message_id_and_date_are_text(self):
        message = parse("Message-ID: <\u00e9@x>\r\nDate: lundi\u00e9\r\n".encode())
        payload = await extract_email_payload(message, new_envelope())
        assert payload["message_id"] == "<\u00e9@x>"
        assert payload["date"] == "lundi\u00e9"

    @pytest.mark.asyncio
    async def test_raw_utf8_part_headers_do_not_fail_extraction(self):
        # compat32 returns an email.header.Header for these, which has no
        # .split() or .strip(): extraction used to raise on any of them.
        message = message_from_bytes(
            (
                "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
                "--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
                "--b\r\nContent-Type: application/pdf\r\n"
                'Content-Disposition: attachment; filename="caf\u00e9.pdf"\r\n'
                "Content-Transfer-Encoding: base64 \u00e9\r\n"
                "Content-ID: <\u00e9@x>\r\n\r\nAAAA\r\n--b--\r\n"
            ).encode()
        )
        payload = await extract_email_payload(message, new_envelope())
        [attachment] = payload["attachments"]
        assert attachment["disposition"] == "attachment"
        assert attachment["content_id"] == "\u00e9@x"
        assert attachment["filename"] == "caf\u00e9.pdf"

    @pytest.mark.asyncio
    async def test_headers_carry_raw_utf8_as_text(self):
        message = parse("X-A: \u00e9t\u00e9\r\n".encode(), ENCODED_SUBJECT)
        payload = await extract_email_payload(message, new_envelope())
        assert payload["headers"]["X-A"] == "\u00e9t\u00e9"
        assert payload["headers"]["Subject"].startswith("=?utf-8?B?")


class TestRulesUseDecodedValues:
    @pytest.mark.parametrize(
        "field_name, header_line, pattern",
        [
            ("subject", ENCODED_SUBJECT, "pr\u00e9vue"),
            ("from", ENCODED_FROM, "J\u00e9r\u00f4me"),
            ("to", ENCODED_TO, "\u00c9lodie"),
        ],
    )
    def test_contains_matches_decoded_text(self, field_name, header_line, pattern):
        value = extract_field_value(field_name, parse(header_line), {})
        assert evaluate_condition("contains", value, pattern)

    def test_header_field_matches_raw_utf8(self):
        message = parse("X-A: \u00e9t\u00e9\r\n".encode())
        value = extract_field_value("header:X-A", message, {})
        assert evaluate_condition("equals", value, "\u00e9t\u00e9")

    def test_rules_read_the_decoded_payload_value(self):
        # extract_email_payload has already decoded these; re-decoding for
        # every rule condition multiplied what a crafted header costs.
        payload = {"from": "from payload", "to": "to payload", "subject": "subject payload"}
        message = parse(ENCODED_FROM, ENCODED_TO, ENCODED_SUBJECT)
        for field_name in ("from", "to", "subject"):
            assert extract_field_value(field_name, message, payload) == f"{field_name} payload"

    def test_header_field_stays_raw(self):
        value = extract_field_value("header:Subject", parse(ENCODED_SUBJECT), {})
        assert value is not None
        assert value.startswith("=?utf-8?B?")
