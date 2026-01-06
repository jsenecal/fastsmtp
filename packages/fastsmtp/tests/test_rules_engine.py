"""Tests for the rules engine."""


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
from fastsmtp.rules.engine import RuleEvaluationResult


class TestMatchers:
    """Tests for individual matcher functions."""

    def test_match_equals(self):
        """Test equals matcher."""
        # Default is case-insensitive
        assert match_equals("test", "test") is True
        assert match_equals("test", "TEST") is True  # case-insensitive by default
        assert match_equals("test", "other") is False

    def test_match_equals_case_sensitive(self):
        """Test equals matcher with case sensitivity."""
        assert match_equals("test", "test", case_sensitive=True) is True
        assert match_equals("test", "TEST", case_sensitive=True) is False

    def test_match_contains(self):
        """Test contains matcher."""
        assert match_contains("hello world", "world") is True
        assert match_contains("hello world", "xyz") is False
        assert match_contains("", "test") is False

    def test_match_starts_with(self):
        """Test starts_with matcher."""
        assert match_starts_with("hello world", "hello") is True
        assert match_starts_with("hello world", "world") is False

    def test_match_ends_with(self):
        """Test ends_with matcher."""
        assert match_ends_with("hello world", "world") is True
        assert match_ends_with("hello world", "hello") is False

    def test_match_regex(self):
        """Test regex matcher."""
        assert match_regex("test@example.com", r".*@example\.com") is True
        assert match_regex("test@other.com", r".*@example\.com") is False
        # Invalid regex should return False
        assert match_regex("test", r"[invalid") is False

    def test_match_exists(self):
        """Test exists matcher."""
        assert match_exists("some value", "") is True
        assert match_exists("", "") is False
        assert match_exists(None, "") is False

    def test_matchers_dict(self):
        """Test MATCHERS dictionary has expected operators."""
        expected_operators = ["equals", "contains", "starts_with", "ends_with", "regex", "exists"]
        for op in expected_operators:
            assert op in MATCHERS


class TestEvaluateCondition:
    """Tests for the evaluate_condition function."""

    def test_evaluate_equals(self):
        """Test evaluating equals condition."""
        assert evaluate_condition("equals", "test", "test") is True
        assert evaluate_condition("equals", "test", "other") is False

    def test_evaluate_contains(self):
        """Test evaluating contains condition."""
        assert evaluate_condition("contains", "hello world", "world") is True
        assert evaluate_condition("contains", "hello", "world") is False

    def test_evaluate_regex(self):
        """Test evaluating regex condition."""
        assert evaluate_condition("regex", "test@example.com", r".*@example\.com") is True
        assert evaluate_condition("regex", "test@other.com", r".*@example\.com") is False

    def test_evaluate_invalid_operator(self):
        """Test evaluating with invalid operator."""
        assert evaluate_condition("invalid_operator", "value", "pattern") is False

    def test_evaluate_none_value(self):
        """Test evaluating with None value."""
        assert evaluate_condition("equals", None, "test") is False
        assert evaluate_condition("contains", None, "test") is False


class TestRuleEvaluationResult:
    """Tests for RuleEvaluationResult dataclass."""

    def test_result_defaults(self):
        """Test default result values."""
        result = RuleEvaluationResult()
        assert result.matches == []
        assert result.tags == []
        assert result.action == "forward"
        assert result.webhook_url_override is None

    def test_should_drop(self):
        """Test should_drop property."""
        result = RuleEvaluationResult(action="drop")
        assert result.should_drop is True

        result = RuleEvaluationResult(action="forward")
        assert result.should_drop is False

    def test_should_quarantine(self):
        """Test should_quarantine property."""
        result = RuleEvaluationResult(action="quarantine")
        assert result.should_quarantine is True

        result = RuleEvaluationResult(action="forward")
        assert result.should_quarantine is False
