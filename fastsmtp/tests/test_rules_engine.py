"""Tests for the rules engine."""

import uuid
from email.message import EmailMessage

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.models import Domain, Rule, RuleSet
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
from fastsmtp.smtp.validation import EmailAuthResult


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

    def test_match_regex_redos_protection(self, monkeypatch):
        """Test that regex matching times out on ReDoS patterns.

        This test uses a pattern known to cause catastrophic backtracking
        and verifies the timeout protection works correctly.
        """
        # Set a very short timeout for testing
        from fastsmtp.config import Settings

        def mock_settings():
            return Settings(
                root_api_key="test123",
                regex_timeout_seconds=0.1,  # 100ms timeout
            )

        monkeypatch.setattr("fastsmtp.rules.conditions.get_settings", mock_settings)

        # Clear the executor cache to use new settings
        import fastsmtp.rules.conditions as conditions

        conditions._regex_executor = None

        # A classic ReDoS pattern: catastrophic backtracking
        evil_pattern = r"(a+)+b"
        # Input that causes exponential backtracking
        evil_input = "a" * 30  # No 'b' at end causes backtracking

        # Should timeout and return False instead of hanging
        result = match_regex(evil_input, evil_pattern)
        assert result is False  # Times out or doesn't match


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


class TestRuleMatch:
    """Tests for RuleMatch dataclass."""

    def test_rule_match_creation(self):
        """Test creating a rule match."""
        rule_id = uuid.uuid4()
        ruleset_id = uuid.uuid4()
        match = RuleMatch(
            rule_id=rule_id,
            ruleset_id=ruleset_id,
            action="tag",
            tags=["important"],
            webhook_url_override="https://example.com/webhook",
        )
        assert match.rule_id == rule_id
        assert match.ruleset_id == ruleset_id
        assert match.action == "tag"
        assert match.tags == ["important"]
        assert match.webhook_url_override == "https://example.com/webhook"


class TestExtractFieldValue:
    """Tests for extract_field_value function."""

    def test_extract_from(self):
        """Test extracting From header."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        result = extract_field_value("from", msg, {})
        assert result == "sender@example.com"

    def test_extract_to(self):
        """Test extracting To header."""
        msg = EmailMessage()
        msg["To"] = "recipient@example.com"
        result = extract_field_value("to", msg, {})
        assert result == "recipient@example.com"

    def test_extract_subject(self):
        """Test extracting Subject header."""
        msg = EmailMessage()
        msg["Subject"] = "Test Subject"
        result = extract_field_value("subject", msg, {})
        assert result == "Test Subject"

    def test_extract_body(self):
        """Test extracting body from payload."""
        msg = EmailMessage()
        payload = {
            "body_text": "Plain text body",
            "body_html": "<p>HTML body</p>",
        }
        result = extract_field_value("body", msg, payload)
        assert "Plain text body" in result
        assert "<p>HTML body</p>" in result

    def test_extract_has_attachment_true(self):
        """Test has_attachment field when attachments exist."""
        msg = EmailMessage()
        payload = {"has_attachments": True}
        result = extract_field_value("has_attachment", msg, payload)
        assert result == "true"

    def test_extract_has_attachment_false(self):
        """Test has_attachment field when no attachments."""
        msg = EmailMessage()
        payload = {"has_attachments": False}
        result = extract_field_value("has_attachment", msg, payload)
        assert result == "false"

    def test_extract_dkim_result(self):
        """Test extracting DKIM result."""
        msg = EmailMessage()
        auth = EmailAuthResult(
            dkim_result="pass",
            dkim_domain="example.com",
            dkim_selector="default",
            spf_result="fail",
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        result = extract_field_value("dkim_result", msg, {}, auth)
        assert result == "pass"

    def test_extract_dkim_result_no_auth(self):
        """Test extracting DKIM result with no auth."""
        msg = EmailMessage()
        result = extract_field_value("dkim_result", msg, {}, None)
        assert result == "none"

    def test_extract_spf_result(self):
        """Test extracting SPF result."""
        msg = EmailMessage()
        auth = EmailAuthResult(
            dkim_result="pass",
            dkim_domain="example.com",
            dkim_selector="default",
            spf_result="softfail",
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        result = extract_field_value("spf_result", msg, {}, auth)
        assert result == "softfail"

    def test_extract_custom_header(self):
        """Test extracting custom header."""
        msg = EmailMessage()
        msg["X-Priority"] = "1"
        result = extract_field_value("header:X-Priority", msg, {})
        assert result == "1"

    def test_extract_unknown_field(self):
        """Test extracting unknown field returns None."""
        msg = EmailMessage()
        result = extract_field_value("unknown_field", msg, {})
        assert result is None


class TestEvaluateRule:
    """Tests for evaluate_rule function."""

    def test_evaluate_rule_match(self):
        """Test evaluating a matching rule."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"

        # Create a mock Rule-like object
        class MockRule:
            id = uuid.uuid4()
            field = "from"
            operator = "contains"
            value = "@example.com"
            case_sensitive = False

        result = evaluate_rule(MockRule(), msg, {})
        assert result is True

    def test_evaluate_rule_no_match(self):
        """Test evaluating a non-matching rule."""
        msg = EmailMessage()
        msg["From"] = "sender@other.com"

        class MockRule:
            id = uuid.uuid4()
            field = "from"
            operator = "contains"
            value = "@example.com"
            case_sensitive = False

        result = evaluate_rule(MockRule(), msg, {})
        assert result is False

    def test_evaluate_rule_field_not_found(self):
        """Test evaluating rule when field doesn't exist."""
        msg = EmailMessage()

        class MockRule:
            id = uuid.uuid4()
            field = "unknown_field"
            operator = "equals"
            value = "test"
            case_sensitive = False

        result = evaluate_rule(MockRule(), msg, {})
        assert result is False


class TestEvaluateRulesAsync:
    """Tests for the async evaluate_rules function."""

    @pytest_asyncio.fixture
    async def domain_with_rules(self, test_session: AsyncSession) -> Domain:
        """Create a domain with rulesets and rules."""
        domain = Domain(domain_name="rules-engine-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create a ruleset with rules
        ruleset = RuleSet(
            domain_id=domain.id,
            name="Test Rules",
            priority=10,
            is_enabled=True,
            stop_on_match=False,
        )
        test_session.add(ruleset)
        await test_session.flush()

        # Rule 1: Tag emails from example.com
        rule1 = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="contains",
            value="@example.com",
            action="tag",
            add_tags=["external"],
        )
        # Rule 2: Tag emails with "urgent" in subject
        rule2 = Rule(
            ruleset_id=ruleset.id,
            order=1,
            field="subject",
            operator="contains",
            value="urgent",
            action="tag",
            add_tags=["urgent"],
        )
        test_session.add_all([rule1, rule2])
        await test_session.commit()
        await test_session.refresh(domain)

        return domain

    @pytest.mark.asyncio
    async def test_evaluate_rules_matches(
        self, test_session: AsyncSession, domain_with_rules: Domain
    ):
        """Test evaluating rules with matching conditions."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["Subject"] = "This is urgent!"

        result = await evaluate_rules(
            session=test_session,
            domain_id=domain_with_rules.id,
            message=msg,
            payload={},
        )

        assert len(result.matches) == 2
        assert "external" in result.tags
        assert "urgent" in result.tags

    @pytest.mark.asyncio
    async def test_evaluate_rules_no_matches(
        self, test_session: AsyncSession, domain_with_rules: Domain
    ):
        """Test evaluating rules with no matches."""
        msg = EmailMessage()
        msg["From"] = "sender@other.com"
        msg["Subject"] = "Normal email"

        result = await evaluate_rules(
            session=test_session,
            domain_id=domain_with_rules.id,
            message=msg,
            payload={},
        )

        assert len(result.matches) == 0
        assert result.tags == []
        assert result.action == "forward"

    @pytest_asyncio.fixture
    async def domain_with_drop_rule(self, test_session: AsyncSession) -> Domain:
        """Create a domain with a drop rule."""
        domain = Domain(domain_name="drop-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(
            domain_id=domain.id,
            name="Drop Rules",
            priority=10,
            is_enabled=True,
        )
        test_session.add(ruleset)
        await test_session.flush()

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="contains",
            value="@spam.com",
            action="drop",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(domain)

        return domain

    @pytest.mark.asyncio
    async def test_evaluate_rules_drop_action(
        self, test_session: AsyncSession, domain_with_drop_rule: Domain
    ):
        """Test that drop action is correctly applied."""
        msg = EmailMessage()
        msg["From"] = "spammer@spam.com"

        result = await evaluate_rules(
            session=test_session,
            domain_id=domain_with_drop_rule.id,
            message=msg,
            payload={},
        )

        assert result.should_drop is True
        assert result.action == "drop"

    @pytest_asyncio.fixture
    async def domain_with_webhook_override(self, test_session: AsyncSession) -> Domain:
        """Create a domain with a webhook override rule."""
        domain = Domain(domain_name="webhook-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(
            domain_id=domain.id,
            name="Webhook Rules",
            priority=10,
            is_enabled=True,
        )
        test_session.add(ruleset)
        await test_session.flush()

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="contains",
            value="@vip.com",
            action="forward",
            webhook_url_override="https://vip.example.com/webhook",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(domain)

        return domain

    @pytest.mark.asyncio
    async def test_evaluate_rules_webhook_override(
        self, test_session: AsyncSession, domain_with_webhook_override: Domain
    ):
        """Test that webhook override is correctly applied."""
        msg = EmailMessage()
        msg["From"] = "important@vip.com"

        result = await evaluate_rules(
            session=test_session,
            domain_id=domain_with_webhook_override.id,
            message=msg,
            payload={},
        )

        assert result.webhook_url_override == "https://vip.example.com/webhook"

    @pytest_asyncio.fixture
    async def domain_with_stop_on_match(self, test_session: AsyncSession) -> Domain:
        """Create a domain with stop_on_match enabled."""
        domain = Domain(domain_name="stop-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(
            domain_id=domain.id,
            name="Stop Rules",
            priority=10,
            is_enabled=True,
            stop_on_match=True,
        )
        test_session.add(ruleset)
        await test_session.flush()

        # First rule will match
        rule1 = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="exists",
            value="",
            action="tag",
            add_tags=["first"],
        )
        # Second rule should not be evaluated
        rule2 = Rule(
            ruleset_id=ruleset.id,
            order=1,
            field="from",
            operator="exists",
            value="",
            action="tag",
            add_tags=["second"],
        )
        test_session.add_all([rule1, rule2])
        await test_session.commit()
        await test_session.refresh(domain)

        return domain

    @pytest.mark.asyncio
    async def test_evaluate_rules_stop_on_match(
        self, test_session: AsyncSession, domain_with_stop_on_match: Domain
    ):
        """Test that stop_on_match stops processing after first match."""
        msg = EmailMessage()
        msg["From"] = "anyone@example.com"

        result = await evaluate_rules(
            session=test_session,
            domain_id=domain_with_stop_on_match.id,
            message=msg,
            payload={},
        )

        # Only first rule should match due to stop_on_match
        assert len(result.matches) == 1
        assert "first" in result.tags
        assert "second" not in result.tags


class TestGetDomainAuthSettings:
    """Tests for get_domain_auth_settings function."""

    @pytest_asyncio.fixture
    async def domain_with_auth_settings(self, test_session: AsyncSession) -> Domain:
        """Create a domain with custom auth settings."""
        domain = Domain(
            domain_name="auth-settings-test.com",
            is_enabled=True,
            verify_dkim=True,
            verify_spf=False,
            reject_dkim_fail=True,
            reject_spf_fail=False,
        )
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_get_auth_settings(
        self, test_session: AsyncSession, domain_with_auth_settings: Domain
    ):
        """Test getting domain auth settings."""
        verify_dkim, verify_spf, reject_dkim, reject_spf = await get_domain_auth_settings(
            test_session, domain_with_auth_settings.id
        )
        assert verify_dkim is True
        assert verify_spf is False
        assert reject_dkim is True
        assert reject_spf is False

    @pytest.mark.asyncio
    async def test_get_auth_settings_not_found(self, test_session: AsyncSession):
        """Test getting auth settings for non-existent domain."""
        fake_id = uuid.uuid4()
        result = await get_domain_auth_settings(test_session, fake_id)
        assert result == (None, None, None, None)
