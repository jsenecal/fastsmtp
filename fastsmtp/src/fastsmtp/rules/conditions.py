"""Rule condition matchers."""

import concurrent.futures
import logging
import os
import re
from typing import Any

from fastsmtp.config import get_settings
from fastsmtp.metrics.definitions import RULES_REGEX_TIMEOUTS

logger = logging.getLogger(__name__)

# Thread pool for regex timeout (ReDoS protection)
_regex_executor: concurrent.futures.ThreadPoolExecutor | None = None


class RegexTimeoutError(Exception):
    """Raised when a regex evaluation times out (potential ReDoS attack)."""

    def __init__(self, pattern: str, timeout: float):
        self.pattern = pattern
        self.timeout = timeout
        super().__init__(
            f"Regex evaluation timed out after {timeout}s (pattern: {pattern[:50]}...)"
        )


def _get_regex_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Get or create the regex thread pool executor.

    Pool size is determined by:
    1. Settings.regex_thread_pool_size if set
    2. CPU count (with minimum of 2)
    """
    global _regex_executor
    if _regex_executor is None:
        settings = get_settings()
        if settings.regex_thread_pool_size is not None:
            pool_size = max(1, settings.regex_thread_pool_size)
        else:
            pool_size = max(2, os.cpu_count() or 2)
        _regex_executor = concurrent.futures.ThreadPoolExecutor(max_workers=pool_size)
        logger.debug(f"Created regex thread pool with {pool_size} workers")
    return _regex_executor


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


def _regex_search(pattern: str, value: str, flags: int) -> bool:
    """Execute regex search (runs in thread for timeout support)."""
    return bool(re.search(pattern, value, flags))


def match_regex(value: str, pattern: str, case_sensitive: bool = False) -> bool:
    """Match if value matches regex pattern.

    Uses a thread-based timeout to protect against ReDoS attacks.

    Raises:
        RegexTimeoutError: If regex evaluation times out (potential ReDoS)
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    settings = get_settings()

    try:
        # Use thread pool with timeout for ReDoS protection
        executor = _get_regex_executor()
        future = executor.submit(_regex_search, pattern, value, flags)
        return future.result(timeout=settings.regex_timeout_seconds)
    except concurrent.futures.TimeoutError:
        # Regex took too long - potential ReDoS attack
        RULES_REGEX_TIMEOUTS.inc()
        logger.warning(
            f"SECURITY: Regex evaluation timed out after {settings.regex_timeout_seconds}s. "
            f"Pattern: {pattern[:100]}... Value length: {len(value)} chars. "
            "This may indicate a ReDoS attack."
        )
        raise RegexTimeoutError(pattern, settings.regex_timeout_seconds) from None
    except re.error as e:
        # Invalid regex pattern - log but don't match
        logger.warning(f"Invalid regex pattern '{pattern[:100]}': {e}")
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
