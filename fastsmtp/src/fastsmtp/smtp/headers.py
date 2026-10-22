"""Decoded, human-readable header values for the webhook payload and rules engine."""

import base64
import binascii
import bisect
import re
from email.message import Message
from email.policy import default
from email.utils import collapse_rfc2231_value, getaddresses
from typing import NamedTuple

# RFC 2047 section 2: =?charset?encoding?encoded-text?=
_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([QqBb])\?([^?\s]*)\?=")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
# Decoded text may carry any character, whether from an encoded-word or raw
# UTF-8. Three kinds are made safe before it reaches a consumer:
#
# - Controls. A CR/LF - or a C1 NEL or Unicode line/paragraph separator, which
#   str.splitlines() and many viewers also break on - would put a line break
#   back into a value consumers rightly treat as one line. TAB is left alone:
#   it is whitespace, and CRLF + HTAB is ordinary folding.
# - Bidi embeddings, overrides and isolates, which make a display name or
#   filename render reversed ("Trojan Source"). Joiners are kept: ZWNJ is
#   ordinary Persian spelling and ZWJ builds emoji sequences.
# - Lone surrogates. The *_escape codecs can produce them from an
#   encoded-word's charset, and Postgres rejects them in JSONB, which would
#   fail the delivery insert.
#
# In an address header all three become U+FFFD. Removing a character, or
# turning it into a space, can turn one mailbox into another - "ceo\u2066@x"
# into "ceo@x" - while U+FFFD keeps them distinct. Elsewhere controls become
# spaces and bidi characters are removed, which reads better.
_CONTROL = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_UNSAFE_IN_ADDRESS = re.compile(f"{_CONTROL.pattern}|{_BIDI.pattern}|{_SURROGATE.pattern}")

# Headers whose value is an address list, where decoded text must not be able
# to change which addresses the list holds.
_ADDRESS_HEADERS = frozenset({"from", "sender", "reply-to", "to", "cc", "bcc"})
# RFC 2047 section 5: in an address header an encoded-word may only stand as a
# whole word of a phrase or comment. One touching another atom is part of an
# addr-spec, and decoding it would rewrite the address.
_WORD_BEFORE = frozenset(' \t"(,:')
_WORD_AFTER = frozenset(' \t")<,:;')
# What may follow a display name at top level ("<" or a group's ":"), and what
# shows the text belongs to something else: the end of the address ("," or a
# group's ";") or an addr-spec ("@").
_DISPLAY_NAME_ENDS = frozenset("<:")
_TOP_LEVEL_MARKERS = frozenset("<:,;@")
# RFC 5322 section 3.2.3 specials, less ".", which obs-phrase allows in a display
# name and which changes nothing about how an address list parses.
_STRUCTURAL = frozenset('()<>[]:;@\\,"')


def raw_header(message: Message, name: str) -> str:
    """Return the first ``name`` header undecoded, or ``""`` if absent.

    Encoded-words and folds are left exactly as received. See :func:`_wire_text`
    for how raw 8-bit bytes become text.
    """
    raw = next((value for key, value in message.raw_items() if key.lower() == name.lower()), None)
    return "" if raw is None else _wire_text(raw)


def header_list(message: Message) -> list[list[str]]:
    """Every header undecoded, as ``[name, value]`` pairs in the order received."""
    return [[key, _wire_text(value)] for key, value in message.raw_items()]


def first_occurrences(pairs: list[list[str]]) -> dict[str, str]:
    """Collapse :func:`header_list` output to one value per name: the first.

    First, not last, because the headers that legitimately repeat are added at
    the top: trace fields (RFC 5321 section 4.4), Authentication-Results (RFC
    8601 section 4.1) and, by convention, filter verdicts such as X-Spam-*.
    Behind a relay that prepends them, the first is from the nearest hop and
    the last may be the sender's own forgery. :func:`raw_header`, behind
    ``header:<name>`` rules, agrees. Names are case-insensitive, so one that
    differs only in case is the same header and keeps the spelling it first
    arrived with.
    """
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in pairs:
        if key.lower() not in seen:
            seen.add(key.lower())
            headers[key] = value
    return headers


class PartFilename(NamedTuple):
    name: str | None
    """The part's filename as text, or ``None`` if it names none."""
    on_disposition: bool
    """Whether the sender put it on Content-Disposition, not the Content-Type."""


def part_filename(part: Message) -> PartFilename:
    """Return a MIME part's filename, read like ``Message.get_filename()``.

    That is the Content-Disposition ``filename`` parameter, else the
    Content-Type ``name``. But ``get_filename()`` parses the compat32 value, so
    a raw UTF-8 (RFC 6532) name loses every non-ASCII byte to U+FFFD, and an
    RFC 2047 encoded-word inside the quotes - forbidden by section 5 but sent
    by Outlook and many libraries - comes back undecoded.

    Here the parameters are parsed under ``email.policy.default`` from the
    text :func:`raw_header` gives, which handles both of those as well as RFC
    2231. Where that parse finds nothing (an unquoted encoded-word, say), the
    compat32 parse of the same parameter still answers, with its encoded-words
    decoded, so a part never loses a filename it had and the order
    ``get_filename()`` used is kept. The name is made safe the same way as
    :func:`decoded_header` output.
    """
    for header, param, on_disposition in (
        ("Content-Disposition", "filename", True),
        ("Content-Type", "name", False),
    ):
        if name := _mime_param(part, header, param):
            return PartFilename(_safe_text(name), on_disposition)
        if name := _compat32_param(part, header, param):
            return PartFilename(_safe_text(_decode(name, address=False)), on_disposition)
    return PartFilename(None, on_disposition=False)


def _mime_param(part: Message, header: str, param: str) -> str | None:
    raw = _unfolded(part, header)
    if not raw:
        return None
    try:
        parsed = default.header_factory(header, raw)
    except Exception:
        # The structured parser has a history of crashing on crafted input.
        # part_filename() falls back to the compat32 parse instead.
        return None
    value = parsed.params.get(param)
    return None if value is None else str(value)


def _compat32_param(part: Message, header: str, param: str) -> str | None:
    try:
        value = part.get_param(param, header=header.lower())
        return collapse_rfc2231_value(value) if value else None
    except (LookupError, ValueError):
        # A charset compat32 cannot even look up, such as one with a NUL in it.
        return None


def _unfolded(message: Message, name: str) -> str:
    return _LINE_BREAK.sub("", raw_header(message, name))


def _wire_text(value: object) -> str:
    """Turn a header value as compat32 stores it into text.

    Raw 8-bit (RFC 6532) bytes are carried as surrogate escapes, which are
    decoded as UTF-8 here, with U+FFFD for bytes that are not valid UTF-8.
    ``message.get`` would instead hand back an ``email.header.Header`` whose
    str() turns every one of those bytes into its own U+FFFD, valid UTF-8 or not.

    A Message built in code can hold an ``email.header.Header`` too, since
    compat32 stores whatever was assigned; its str() is already decoded.
    """
    if not isinstance(value, str):
        return str(value)
    try:
        return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        # A lone surrogate that is not an escaped byte. Only a Message built
        # from a str can hold one; message_from_bytes never produces it.
        return _SURROGATE.sub("\ufffd", value)


def decoded_header(message: Message, name: str) -> str:
    """Return the first ``name`` header decoded and unfolded, or ``""`` if absent.

    ``message`` comes from ``message_from_bytes`` under compat32, whose ``get``
    hands back the value as it was on the wire: RFC 2047 encoded-words intact,
    CRLF folds intact, and raw 8-bit (RFC 6532) bytes wrapped in an
    ``email.header.Header`` rather than a str. The value from
    :func:`raw_header` is unfolded instead, and has its encoded-words decoded.

    Nothing else about the value changes. ``email.policy.default`` would decode
    it too, but it re-renders an address list from its parse: it drops
    comments (the legacy ``addr (Name)`` form loses the name) and "repairs"
    what it cannot parse (``<<garbage`` becomes ``<>``). Here the consumer
    always gets the addresses it was sent.

    An address header is where decoding can do harm, so there:

    - Only display names and comments are decoded. RFC 2047 section 5 forbids
      encoded-words in an addr-spec, so an encoded-word is decoded only inside
      a comment, or as a whole word whose next top-level ``<``, ``:``, ``,``,
      ``;`` or ``@`` is a ``<`` (an angle-addr) or a group's ``:``. Anything
      else - inside ``<...>``, a quoted local-part, ``=?...?= @corp.com`` - is
      part of an address and stays as sent.
    - Decoded text is escaped for where it lands. At top level, text holding a
      special is wrapped in a quoted-string, so ``=?utf-8?B?RHVwb250LCBKZWFu?=
      <a@x>`` becomes ``"Dupont, Jean" <a@x>`` rather than two addresses;
      inside a quoted-string or comment it is backslash-escaped.
    - Finally, the decoded and undecoded values are both parsed with
      ``email.utils.getaddresses``. If the addresses differ in any way, the
      undecoded value is returned. The rules above are what make decoding
      safe; this catches any input where they and a real parser disagree.

    Control characters, line separators, bidi overrides and lone surrogates
    are neutralised whether they arrived encoded or as raw UTF-8 (see
    ``_CONTROL``), so the value is always a single line.
    """
    unfolded = _unfolded(message, name)
    if name.lower() not in _ADDRESS_HEADERS:
        return _safe_text(_decode(unfolded, address=False))
    undecoded = _UNSAFE_IN_ADDRESS.sub("\ufffd", unfolded)
    decoded = _UNSAFE_IN_ADDRESS.sub("\ufffd", _decode(unfolded, address=True))
    if decoded != undecoded and _addresses(decoded) != _addresses(undecoded):
        return undecoded
    return decoded


def _safe_text(text: str) -> str:
    """Neutralise the characters described at ``_CONTROL`` outside an address header."""
    text = _CONTROL.sub(" ", text)
    text = _BIDI.sub("", text)
    return _SURROGATE.sub("\ufffd", text)


def _addresses(value: str) -> list[list[str]] | None:
    """The addr-specs ``value`` parses to, under each parsing mode available."""
    try:
        try:
            pairs = [getaddresses([value], strict=True), getaddresses([value], strict=False)]
        except TypeError:
            # Pythons before the strict parameter (backported to 3.12.x and 3.13).
            pairs = [getaddresses([value])]
    except Exception:
        return None
    return [[addr for _, addr in mode] for mode in pairs]


def _decode(value: str, address: bool) -> str:
    matches = list(_ENCODED_WORD.finditer(value))
    if not matches:
        return value
    scan = _Scan(value, [match.start() for match in matches]) if address else None
    out: list[str] = []
    # Encoded-words decoded but not yet emitted, as (charset, bytes). RFC 2047
    # section 6.2 drops the whitespace between adjacent encoded-words, and a
    # multibyte character may be split across them, so a run is decoded as one.
    run: list[tuple[str, bytes]] = []
    run_state = _TOP
    pos = 0

    def flush() -> None:
        if run:
            text = _decode_run(run)
            out.append(_escape(text, run_state) if address else text)
            run.clear()

    for match in matches:
        between = value[pos : match.start()]
        charset, encoding, encoded_text = match.groups()
        data = _decode_word(encoding, encoded_text)
        in_address = scan is not None and scan.in_address(match)
        pos = match.end()
        if data is not None and not in_address and run and not between.strip(" \t"):
            run.append((charset, data))
            continue
        flush()
        out.append(between)
        if data is None or in_address:
            out.append(match.group(0))
        else:
            run.append((charset, data))
            run_state = scan.state_at(match.start()) if scan else _TOP
    flush()
    out.append(value[pos:])
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
    # Chunks collected and joined once: += on bytes copies the run so far each
    # time, which made a long run quadratic.
    parts: list[str] = []
    charset, chunks = run[0][0], [run[0][1]]
    for next_charset, next_data in run[1:]:
        if next_charset.lower() == charset.lower():
            chunks.append(next_data)
        else:
            parts.append(_to_text(b"".join(chunks), charset))
            charset, chunks = next_charset, [next_data]
    parts.append(_to_text(b"".join(chunks), charset))
    return "".join(parts)


def _to_text(data: bytes, charset: str) -> str:
    # RFC 2231 section 5 allows "charset*language" in an encoded-word.
    codec = charset.split("*", 1)[0]
    try:
        return data.decode(codec, "replace")
    except (LookupError, ValueError):
        # An unknown charset, a non-text codec such as "base64", or a name
        # the codec registry rejects outright, such as one holding a NUL.
        return data.decode("utf-8", "replace")


# Where a position sits in an address header, as the scan below records it.
_TOP, _QUOTED, _COMMENT, _ANGLE = range(4)


def _escape(text: str, state: int) -> str:
    """Make decoded ``text`` safe to emit where its encoded-words stood."""
    if state == _QUOTED:
        return _backslash(text, '\\"')
    if state == _COMMENT:
        return _backslash(text, "\\()")
    if any(c in _STRUCTURAL for c in text):
        return '"' + _backslash(text, '\\"') + '"'
    return text


def _backslash(text: str, chars: str) -> str:
    return "".join("\\" + c if c in chars else c for c in text)


class _Scan:
    """One linear pass over an address header's literal structure.

    Records the state (top level, quoted-string, comment, angle-addr) at each
    encoded-word, and every top-level marker that decides whether text is a
    display name. Deciding that by rescanning the rest of the header for each
    encoded-word made a header of many encoded-words quadratic, which a
    sender could use to stall the server.
    """

    def __init__(self, value: str, positions: list[int]) -> None:
        wanted = set(positions)
        self._states: dict[int, int] = {}
        self._marker_at: list[int] = []
        self._marker_char: list[str] = []
        in_quotes = in_angle = escaped = False
        comment_depth = 0
        for index, char in enumerate(value):
            if index in wanted:
                if in_angle:
                    self._states[index] = _ANGLE
                elif comment_depth:
                    self._states[index] = _COMMENT
                elif in_quotes:
                    self._states[index] = _QUOTED
            top_level = not in_quotes and comment_depth == 0
            if escaped:
                escaped = False
            elif char == "\\" and not top_level:
                escaped = True
            elif char == '"' and comment_depth == 0:
                in_quotes = not in_quotes
            elif char == "(" and not in_quotes:
                comment_depth += 1
            elif char == ")" and comment_depth:
                comment_depth -= 1
            elif top_level:
                if char in _TOP_LEVEL_MARKERS:
                    self._marker_at.append(index)
                    self._marker_char.append(char)
                if char == "<":
                    in_angle = True
                elif char in ">,":
                    # A comma ends the address too, so one unclosed "<" cannot
                    # swallow the rest of the list.
                    in_angle = False

    def state_at(self, position: int) -> int:
        return self._states.get(position, _TOP)

    def in_address(self, match: re.Match[str]) -> bool:
        """Whether an encoded-word is part of an addr-spec rather than a name or comment."""
        state = self.state_at(match.start())
        if state == _COMMENT:
            return False
        if state == _ANGLE:
            return True
        if state == _TOP:
            value = match.string
            before = value[match.start() - 1] if match.start() else " "
            after = value[match.end()] if match.end() < len(value) else " "
            if before not in _WORD_BEFORE or after not in _WORD_AFTER:
                return True
        # Top level or a quoted-string: a display name only if the next
        # top-level marker opens an angle-addr or a group. A quoted local-part
        # ("=?...?="@x) or an obs-local-part (=?...?= @x) reaches "@" first.
        nearest = bisect.bisect_left(self._marker_at, match.end())
        if nearest == len(self._marker_at):
            return True
        return self._marker_char[nearest] not in _DISPLAY_NAME_ENDS
