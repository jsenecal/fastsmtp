"""Rule condition matchers."""

import re
from typing import Any


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
    """Match if value matches regex pattern."""
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return bool(re.search(pattern, value, flags))
    except re.error:
        return False


def match_exists(value: Any, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value exists (is not None or empty)."""
    if value is None:
        return False
    if isinstance(value, str):
        return len(value.strip()) > 0
    if isinstance(value, (list, dict)):
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
