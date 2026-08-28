"""Rule condition matchers."""

import logging
from functools import lru_cache
from typing import Any

import re2

logger = logging.getLogger(__name__)

# Rule patterns come from operators, not from mail, so the set is small and
# bounded - the cap is a backstop, not a working limit.
_PATTERN_CACHE_SIZE = 512


def _re2_options(case_sensitive: bool) -> re2.Options:
    """Build RE2 options for a match.

    log_errors is disabled because RE2 otherwise writes compile failures
    straight to stderr; we log them ourselves with context.
    """
    options = re2.Options()
    options.case_sensitive = case_sensitive
    options.log_errors = False
    return options


@lru_cache(maxsize=_PATTERN_CACHE_SIZE)
def _compiled_pattern(pattern: str, case_sensitive: bool) -> Any:
    """Compile a rule pattern once and reuse it.

    ``re2.search(pattern, text)`` compiles on every call - it has no cache of
    its own. A rule used to cost one compile per message, which was already
    waste; once a field can hold one value per attachment part, it became one
    compile per part, so the cost grew with what the sender chose to send.

    An invalid pattern raises out of here rather than being cached, so it keeps
    logging and failing to match exactly as before.
    """
    return re2.compile(pattern, options=_re2_options(case_sensitive))


def _re2_error_reason(exc: re2.error) -> str:
    """Extract a readable message from an re2.error (its args are bytes)."""
    reason = exc.args[0] if exc.args else str(exc)
    if isinstance(reason, bytes):
        return reason.decode("utf-8", errors="replace")
    return str(reason)


def validate_regex_pattern(pattern: str) -> None:
    """Raise ValueError if RE2 cannot compile the pattern.

    Rule regexes are evaluated with RE2 (linear-time by construction, so
    operator-supplied patterns cannot trigger catastrophic backtracking).
    RE2 does not support backreferences or lookaround; patterns using them
    are rejected here so they never reach match time. The error message is
    user-facing: both the rule schema and the rule update endpoint surface
    it verbatim in their 422 responses.
    """
    try:
        re2.compile(pattern, options=_re2_options(case_sensitive=True))
    except re2.error as exc:
        raise ValueError(
            f"Invalid regex pattern: {_re2_error_reason(exc)}. Rule regexes use "
            "RE2 syntax (https://github.com/google/re2/wiki/Syntax); "
            "backreferences and lookaround are not supported."
        ) from exc


def match_equals(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value equals pattern exactly."""
    if not case_sensitive:
        return value.lower() == pattern.lower()
    return value == pattern


def match_contains(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value contains pattern."""
    if not case_sensitive:
        return pattern.lower() in value.lower()
    return pattern in value


def match_starts_with(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value starts with pattern."""
    if not case_sensitive:
        return value.lower().startswith(pattern.lower())
    return value.startswith(pattern)


def match_ends_with(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value ends with pattern."""
    if not case_sensitive:
        return value.lower().endswith(pattern.lower())
    return value.endswith(pattern)


def match_regex(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value matches regex pattern.

    Evaluated with RE2, which matches in linear time by construction, so a
    crafted pattern cannot trigger catastrophic backtracking (ReDoS). A stored
    pattern RE2 cannot compile (backreferences, lookaround, plain syntax
    errors) logs a warning and does not match, never raises.

    RE2 requires valid UTF-8, and sender-controlled text can carry lone
    surrogates (a UTF-7 body part declaring an unpaired surrogate decodes
    successfully, so the errors="replace" fallback never runs). Those are
    replaced with U+FFFD before matching -- raising would tempfail the
    message, and refusing to match would let one crafted code point blind
    every regex rule.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        logger.debug("Regex value contains unencodable code points; sanitizing")
        value = value.encode("utf-8", errors="replace").decode("utf-8")
    try:
        return bool(_compiled_pattern(pattern, case_sensitive).search(value))
    except re2.error as e:
        # Invalid or RE2-unsupported pattern - log but don't match
        logger.warning(f"Invalid regex pattern '{pattern[:100]}': {_re2_error_reason(e)}")
        return False


def match_exists(value: Any, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value exists (is not None or empty)."""
    if value is None:
        return False
    if isinstance(value, str):
        return len(value.strip()) > 0
    if isinstance(value, list | dict):
        return len(value) > 0
    return True


# Operator to matcher function mapping
MATCHERS = {
    "equals": match_equals,
    "contains": match_contains,
    "starts_with": match_starts_with,
    "ends_with": match_ends_with,
    "regex": match_regex,
    "exists": match_exists,
}


def evaluate_condition(
    operator: str,
    value: Any,
    pattern: str,
    case_sensitive: bool = False,
) -> bool:
    """Evaluate a condition using the specified operator.

    Args:
        operator: Operator name (equals, contains, regex, etc.)
        value: Value to test
        pattern: Pattern to match against
        case_sensitive: Whether to use case-sensitive matching

    Returns:
        True if the condition matches
    """
    matcher = MATCHERS.get(operator)
    if not matcher:
        return False

    # Handle None values
    if value is None:
        if operator == "exists":
            return False
        return False

    # Convert value to string for string operations
    if not isinstance(value, str):
        value = str(value)

    return matcher(value, pattern, case_sensitive)
