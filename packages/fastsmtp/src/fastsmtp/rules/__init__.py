"""Rules engine module."""

from fastsmtp.rules.conditions import (
    MATCHERS,
    evaluate_condition,
    match_contains,
    match_ends_with,
    match_equals,
    match_exists,
    match_regex,
    match_starts_with,
)
from fastsmtp.rules.engine import (
    RuleEvaluationResult,
    RuleMatch,
    evaluate_rule,
    evaluate_rules,
    extract_field_value,
    get_domain_auth_settings,
)

__all__ = [
    "MATCHERS",
    "RuleEvaluationResult",
    "RuleMatch",
    "evaluate_condition",
    "evaluate_rule",
    "evaluate_rules",
    "extract_field_value",
    "get_domain_auth_settings",
    "match_contains",
    "match_ends_with",
    "match_equals",
    "match_exists",
    "match_regex",
    "match_starts_with",
]
