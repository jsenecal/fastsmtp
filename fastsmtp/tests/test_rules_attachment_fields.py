"""Rule matching on attachment names and content types.

Until now the only thing a rule knew about attachments was whether one
existed. The payload has carried a filename and a content type per part all
along, and neither was reachable from a rule, so an operator who wanted to
treat ``invoice.exe`` differently from ``invoice.pdf`` had to route every
attachment-bearing message somewhere else and decide there. See issue #154.

The claims under test:

* **A message offers one value per part, and any one of them can match.** This
  is the whole reason the field cannot be a single joined string: against
  ``"a.pdf\\nb.exe"`` an ``ends_with ".exe"`` would pass and against
  ``"b.exe\\na.pdf"`` it would fail, so the rule would silently test whichever
  attachment happened to sort last.
* **Every operator sees each value on its own.** ``starts_with``,
  ``ends_with`` and ``equals`` are the ones a joined string breaks; ``regex``
  and ``contains`` would appear to work and match across a boundary.
* **A message with no parts matches nothing**, including under ``exists``.
* **Inline images are included**, unlike ``has_attachment``. A rule is a policy
  surface, and a part that hides from it is worth more to a sender than a
  signature logo is to anyone else.
"""

import uuid
from email.message import EmailMessage

import pytest
from fastsmtp.db.models import Rule
from fastsmtp.rules.conditions import _compiled_pattern
from fastsmtp.rules.engine import evaluate_rule, extract_field_value, extract_field_values


def _rule(field: str, operator: str, value: str, case_sensitive: bool = False) -> Rule:
    return Rule(
        id=uuid.uuid4(),
        ruleset_id=uuid.uuid4(),
        order=0,
        field=field,
        operator=operator,
        value=value,
        case_sensitive=case_sensitive,
        action="forward",
    )


def _payload(*parts: tuple[str, str]) -> dict:
    """Build a payload from (filename, content_type) pairs."""
    return {
        "attachments": [
            {"filename": name, "content_type": ctype, "size": 1} for name, ctype in parts
        ]
    }


MESSAGE = EmailMessage()


class TestExtraction:
    def test_names_yield_one_value_per_part(self):
        payload = _payload(("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload"))

        assert extract_field_values("attachment_names", MESSAGE, payload) == ["a.pdf", "b.exe"]

    def test_types_yield_one_value_per_part(self):
        payload = _payload(("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload"))

        assert extract_field_values("attachment_types", MESSAGE, payload) == [
            "application/pdf",
            "application/x-msdownload",
        ]

    def test_a_message_with_no_parts_yields_nothing(self):
        assert extract_field_values("attachment_names", MESSAGE, {"attachments": []}) == []

    def test_single_valued_fields_still_yield_one_value(self):
        message = EmailMessage()
        message["Subject"] = "Hello"

        assert extract_field_values("subject", message, {}) == ["Hello"]

    def test_an_unknown_field_is_still_unknown(self):
        assert extract_field_values("nonsense", MESSAGE, {}) is None


class TestAnyValueMatches:
    """The ordering cases a single joined string would get wrong."""

    @pytest.mark.parametrize(
        "parts",
        [
            (("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload")),
            (("b.exe", "application/x-msdownload"), ("a.pdf", "application/pdf")),
        ],
        ids=["suspicious-last", "suspicious-first"],
    )
    def test_ends_with_matches_whichever_position(self, parts):
        assert evaluate_rule(
            _rule("attachment_names", "ends_with", ".exe"), MESSAGE, _payload(*parts)
        )

    @pytest.mark.parametrize(
        "parts",
        [
            (("a.pdf", "application/pdf"), ("invoice.exe", "application/x-msdownload")),
            (("invoice.exe", "application/x-msdownload"), ("a.pdf", "application/pdf")),
        ],
        ids=["suspicious-last", "suspicious-first"],
    )
    def test_starts_with_matches_whichever_position(self, parts):
        assert evaluate_rule(
            _rule("attachment_names", "starts_with", "invoice"), MESSAGE, _payload(*parts)
        )

    def test_equals_matches_one_value_not_the_concatenation(self):
        payload = _payload(("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload"))

        assert evaluate_rule(_rule("attachment_names", "equals", "b.exe"), MESSAGE, payload)

    def test_no_match_when_no_part_satisfies_it(self):
        payload = _payload(("a.pdf", "application/pdf"), ("b.docx", "application/msword"))

        assert not evaluate_rule(_rule("attachment_names", "ends_with", ".exe"), MESSAGE, payload)

    def test_a_pattern_cannot_match_across_two_parts(self):
        """Proof the values are never concatenated: "pdfb" spans the boundary."""
        payload = _payload(("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload"))

        assert not evaluate_rule(_rule("attachment_names", "contains", "pdfb"), MESSAGE, payload)

    def test_content_type_matching(self):
        payload = _payload(("a.pdf", "application/pdf"), ("logo.png", "image/png"))

        assert evaluate_rule(_rule("attachment_types", "starts_with", "image/"), MESSAGE, payload)

    def test_regex_applies_per_value(self):
        payload = _payload(("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload"))

        assert evaluate_rule(
            _rule("attachment_names", "regex", r"\.(exe|scr|vbs)$"), MESSAGE, payload
        )

    def test_case_insensitive_by_default(self):
        payload = _payload(("INVOICE.EXE", "application/x-msdownload"))

        assert evaluate_rule(_rule("attachment_names", "ends_with", ".exe"), MESSAGE, payload)

    def test_case_sensitive_when_asked(self):
        payload = _payload(("INVOICE.EXE", "application/x-msdownload"))

        assert not evaluate_rule(
            _rule("attachment_names", "ends_with", ".exe", case_sensitive=True), MESSAGE, payload
        )


class TestEmptyMessage:
    @pytest.mark.parametrize("field_name", ["attachment_names", "attachment_types"])
    def test_exists_is_false_with_no_parts(self, field_name):
        assert not evaluate_rule(_rule(field_name, "exists", ""), MESSAGE, {"attachments": []})

    @pytest.mark.parametrize("field_name", ["attachment_names", "attachment_types"])
    def test_exists_is_true_with_a_part(self, field_name):
        payload = _payload(("a.pdf", "application/pdf"))

        assert evaluate_rule(_rule(field_name, "exists", ""), MESSAGE, payload)

    def test_a_payload_with_no_attachments_key_does_not_raise(self):
        assert not evaluate_rule(_rule("attachment_names", "exists", ""), MESSAGE, {})


class TestInlineImagesAreVisible:
    """`has_attachment` excuses a rendered signature logo; these fields do not.

    A rule is where policy is expressed, so nothing the message carries should
    be invisible to it. The exemption exists to stop footer logos flipping a
    boolean, which is a different job from letting an operator write a rule
    about them - and a part that could hide from matching would be worth more
    to a sender than the convenience is to anyone else.
    """

    @pytest.mark.asyncio
    async def test_a_rendered_logo_is_matchable(self):
        payload = {
            "attachments": [
                {
                    "filename": "image001.png",
                    "content_type": "image/png",
                    "disposition": "inline",
                    "content_id": "image001.png@01DA",
                    "size": 1,
                }
            ],
            "has_attachments": False,
        }

        assert evaluate_rule(_rule("attachment_names", "equals", "image001.png"), MESSAGE, payload)
        assert extract_field_values("has_attachment", MESSAGE, payload) == ["false"]


class TestSingularHelper:
    """``extract_field_value`` stays the single-value view of the plural one.

    It is exported from ``fastsmtp.rules``, so its behaviour on the new fields
    is part of the surface whether or not anything in the tree calls it. On a
    multi-valued field it reports the first part only; rule evaluation uses
    ``extract_field_values`` and matches on any of them.
    """

    def test_returns_the_first_part_only(self):
        payload = _payload(("a.pdf", "application/pdf"), ("b.exe", "application/x-msdownload"))

        assert extract_field_value("attachment_names", MESSAGE, payload) == "a.pdf"

    def test_returns_empty_string_for_a_message_with_no_parts(self):
        assert extract_field_value("attachment_names", MESSAGE, {"attachments": []}) == ""

    def test_still_returns_none_for_an_unknown_field(self):
        assert extract_field_value("nonsense", MESSAGE, {}) is None

    def test_single_valued_fields_are_unchanged(self):
        message = EmailMessage()
        message["Subject"] = "Hello"

        assert extract_field_value("subject", message, {}) == "Hello"


class TestRegexCompilesOncePerPattern:
    """A regex rule must not pay a compile per attachment part.

    ``re2.search(pattern, text)`` compiles on every call, so evaluating a
    pattern against one value per part made compilation grow with what the
    sender chose to send - a message of many small parts, times each regex
    rule, times each recipient, on the event loop. The compile is cached, so
    the count is a property worth pinning rather than a timing test.
    """

    def test_one_compile_regardless_of_part_count(self):
        _compiled_pattern.cache_clear()
        payload = _payload(*[(f"f{i}.pdf", "application/pdf") for i in range(200)])

        evaluate_rule(_rule("attachment_names", "regex", r"\.(exe|scr)$"), MESSAGE, payload)

        assert _compiled_pattern.cache_info().misses == 1
        assert _compiled_pattern.cache_info().hits == 199

    def test_an_uncompilable_pattern_is_not_cached_and_does_not_match(self):
        """Backreferences are RE2-unsupported; it must keep failing loudly."""
        _compiled_pattern.cache_clear()
        payload = _payload(("a.pdf", "application/pdf"))

        assert not evaluate_rule(_rule("attachment_names", "regex", r"(a)\1"), MESSAGE, payload)
        assert _compiled_pattern.cache_info().currsize == 0
