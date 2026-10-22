"""Decoded, human-readable header values for the webhook payload and rules engine."""

import base64
import binascii
import re
from email.message import Message

# RFC 2047 section 2: =?charset?encoding?encoded-text?=
_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([QqBb])\?([^?\s]*)\?=")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
# Decoded text may carry any byte, =0D=0A included. Left in, a CR/LF would put
# a line break back into a value consumers rightly treat as one line.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# What follows a display name: more phrase, then an angle-addr, before the next
# address. Without it, a decoded run is not a display name and is not quoted.
_DISPLAY_NAME_FOLLOWS = re.compile(r"[^,<]*<")

# Headers whose value is an address list, where a decoded display name may need
# quoting to keep parsing as the same list.
_ADDRESS_HEADERS = frozenset({"from", "sender", "reply-to", "to", "cc", "bcc"})
# RFC 5322 section 3.2.3 specials, which an atom-based display name cannot hold.
_SPECIALS = frozenset('()<>[]:;@\\,."')


def decoded_header(message: Message, name: str) -> str:
    """Return the first ``name`` header decoded and unfolded, or ``""`` if absent.

    ``message`` comes from ``message_from_bytes`` under compat32, whose ``get``
    hands back the value as it was on the wire: RFC 2047 encoded-words intact,
    CRLF folds intact, and raw 8-bit (RFC 6532) bytes wrapped in an
    ``email.header.Header`` rather than a str. The raw value is read from
    ``raw_items`` instead, unfolded, and has its encoded-words decoded.

    Nothing else about the value changes. ``email.policy.default`` would decode
    it too, but it re-renders an address list from its parse: it drops
    comments (the legacy ``addr (Name)`` form loses the name) and "repairs"
    what it cannot parse (``<<garbage`` becomes ``<>``). Here the consumer
    always gets the addresses it was sent.

    The one addition is escaping, so the decoded text cannot change the
    value's structure. In an address header, a decoded display name holding a
    special such as a comma is wrapped in a quoted-string, so
    ``=?utf-8?B?RHVwb250LCBKZWFu?= <a@x>`` becomes ``"Dupont, Jean" <a@x>``
    rather than something that reads as two addresses; decoded text already
    inside a quoted-string or comment is backslash-escaped for it instead. And
    control characters in decoded text, CR/LF included, become spaces.
    """
    raw = next((value for key, value in message.raw_items() if key.lower() == name.lower()), None)
    if raw is None:
        return ""
    if not isinstance(raw, str):
        # compat32 stores whatever was assigned, so a Message built in code can
        # hold an email.header.Header, whose str() is already decoded.
        raw = str(raw)
    return _decode(_LINE_BREAK.sub("", raw), quote_specials=name.lower() in _ADDRESS_HEADERS)


def _decode(value: str, quote_specials: bool) -> str:
    out: list[str] = []
    # Encoded-words decoded but not yet emitted, as (charset, bytes). RFC 2047
    # section 6.2 drops the whitespace between adjacent encoded-words, and a
    # multibyte character may be split across them, so a run is decoded as one.
    run: list[tuple[str, bytes]] = []
    scanner = _QuoteScanner()
    pos = 0

    def flush(rest: str) -> None:
        if not run:
            return
        text = _CONTROL.sub(" ", _decode_run(run))
        run.clear()
        if quote_specials:
            text = scanner.escape(text, display_name=bool(_DISPLAY_NAME_FOLLOWS.match(rest)))
        out.append(text)

    for match in _ENCODED_WORD.finditer(value):
        between = value[pos : match.start()]
        charset, encoding, encoded_text = match.groups()
        data = _decode_word(encoding, encoded_text)
        if data is not None and run and not between.strip(" \t"):
            run.append((charset, data))
        else:
            flush(value[pos:])
            out.append(scanner.feed(between))
            if data is None:
                # Not decodable: pass the word through as literal text.
                out.append(scanner.feed(match.group(0)))
            else:
                run.append((charset, data))
        pos = match.end()
    flush(value[pos:])
    out.append(scanner.feed(value[pos:]))
    return "".join(out)


def _decode_word(encoding: str, encoded_text: str) -> bytes | None:
    """Bytes an encoded-word's text stands for, or ``None`` if it is malformed."""
    try:
        if encoding in "Bb":
            padded = encoded_text + "=" * (-len(encoded_text) % 4)
            return base64.b64decode(padded, validate=True)
        return binascii.a2b_qp(encoded_text.encode("ascii"), header=True)
    except (binascii.Error, ValueError):
        return None


def _decode_run(run: list[tuple[str, bytes]]) -> str:
    """Decode adjacent encoded-words, joining the bytes of same-charset neighbours."""
    parts: list[str] = []
    charset, data = run[0]
    for next_charset, next_data in run[1:]:
        if next_charset.lower() == charset.lower():
            data += next_data
        else:
            parts.append(_to_text(data, charset))
            charset, data = next_charset, next_data
    parts.append(_to_text(data, charset))
    return "".join(parts)


def _to_text(data: bytes, charset: str) -> str:
    # RFC 2231 section 5 allows "charset*language" in an encoded-word.
    codec = charset.split("*", 1)[0]
    try:
        return data.decode(codec, "replace")
    except (LookupError, UnicodeError):
        # An unknown charset, or a non-text codec such as "base64".
        return data.decode("utf-8", "replace")


class _QuoteScanner:
    """Track whether literal header text leaves us inside a quoted-string or comment.

    Also turns raw 8-bit bytes, which compat32 carries as surrogate escapes,
    back into text, decoded as UTF-8 per RFC 6532.
    """

    def __init__(self) -> None:
        self._in_quotes = False
        self._comment_depth = 0
        self._escaped = False

    @property
    def at_top_level(self) -> bool:
        return not self._in_quotes and self._comment_depth == 0

    def escape(self, text: str, display_name: bool) -> str:
        """Make decoded ``text`` safe to emit at the current position."""
        if self._in_quotes:
            return _backslash(text, '\\"')
        if self._comment_depth:
            return _backslash(text, "\\()")
        if display_name and any(c in _SPECIALS for c in text):
            return '"' + _backslash(text, '\\"') + '"'
        return text

    def feed(self, text: str) -> str:
        for char in text:
            if self._escaped:
                self._escaped = False
            elif char == "\\" and not self.at_top_level:
                self._escaped = True
            elif char == '"' and self._comment_depth == 0:
                self._in_quotes = not self._in_quotes
            elif char == "(" and not self._in_quotes:
                self._comment_depth += 1
            elif char == ")" and self._comment_depth:
                self._comment_depth -= 1
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _backslash(text: str, chars: str) -> str:
    return "".join("\\" + c if c in chars else c for c in text)
