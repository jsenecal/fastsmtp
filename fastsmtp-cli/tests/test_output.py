"""Tests for CLI output formatting utilities."""

from datetime import UTC, datetime

from fastsmtp_cli.output import (
    format_datetime,
    print_api_key,
    print_api_keys_table,
    print_delivery_log,
    print_delivery_logs_table,
    print_domain,
    print_domains_table,
    print_error,
    print_health,
    print_info,
    print_json,
    print_members_table,
    print_profiles_table,
    print_ready,
    print_recipient,
    print_recipients_table,
    print_rule,
    print_rules_table,
    print_ruleset,
    print_rulesets_table,
    print_success,
    print_test_webhook_result,
    print_user,
    print_users_table,
    print_warning,
    print_whoami,
    status_style,
    truncate,
)


class TestFormatDateTime:
    """Tests for format_datetime function."""

    def test_format_none(self):
        """Test formatting None returns dash."""
        assert format_datetime(None) == "-"

    def test_format_datetime_object(self):
        """Test formatting datetime object."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC)
        result = format_datetime(dt)
        assert "2024-01-15" in result
        assert "10:30:45" in result

    def test_format_iso_string(self):
        """Test formatting ISO datetime string."""
        result = format_datetime("2024-01-15T10:30:45+00:00")
        assert "2024-01-15" in result
        assert "10:30:45" in result

    def test_format_iso_string_with_z(self):
        """Test formatting ISO string with Z suffix."""
        result = format_datetime("2024-01-15T10:30:45Z")
        assert "2024-01-15" in result

    def test_format_invalid_string(self):
        """Test formatting invalid string returns as-is."""
        result = format_datetime("not-a-date")
        assert result == "not-a-date"


class TestTruncate:
    """Tests for truncate function."""

    def test_truncate_none(self):
        """Test truncating None returns dash."""
        assert truncate(None) == "-"

    def test_truncate_short_text(self):
        """Test short text is not truncated."""
        assert truncate("short text") == "short text"

    def test_truncate_long_text(self):
        """Test long text is truncated with ellipsis."""
        long_text = "a" * 100
        result = truncate(long_text, max_length=50)
        assert len(result) == 50
        assert result.endswith("...")

    def test_truncate_exact_length(self):
        """Test text at exact max length is not truncated."""
        text = "a" * 50
        assert truncate(text, max_length=50) == text


class TestStatusStyle:
    """Tests for status_style function."""

    def test_success_statuses(self):
        """Test success statuses return green."""
        for status in ["ok", "pass", "success", "delivered", "active", "enabled"]:
            assert status_style(status) == "green"

    def test_failure_statuses(self):
        """Test failure statuses return red."""
        for status in ["fail", "failed", "error", "exhausted", "disabled"]:
            assert status_style(status) == "red"

    def test_warning_statuses(self):
        """Test warning statuses return yellow."""
        for status in ["pending", "queued", "retrying", "warning"]:
            assert status_style(status) == "yellow"

    def test_unknown_status(self):
        """Test unknown status returns white."""
        assert status_style("unknown") == "white"

    def test_case_insensitive(self):
        """Test status matching is case insensitive."""
        assert status_style("OK") == "green"
        assert status_style("FAIL") == "red"


class TestPrintFunctions:
    """Tests for print functions using Rich console."""

    def test_print_json(self, capsys):
        """Test print_json outputs valid JSON."""
        # We can't easily capture Rich output, but we can verify no exceptions
        print_json({"key": "value"})

    def test_print_error(self, capsys):
        """Test print_error outputs error message."""
        print_error("Something went wrong")
        # Rich output goes to internal console, but function should not raise

    def test_print_success(self, capsys):
        """Test print_success outputs success message."""
        print_success("Operation completed")

    def test_print_warning(self, capsys):
        """Test print_warning outputs warning message."""
        print_warning("Be careful")

    def test_print_info(self, capsys):
        """Test print_info outputs info message."""
        print_info("Information")


class TestHealthOutput:
    """Tests for health output formatting."""

    def test_print_health(self):
        """Test health output."""
        data = {
            "status": "ok",
            "version": "1.0.0",
            "instance_id": "test-instance",
        }
        # Should not raise
        print_health(data)

    def test_print_ready(self):
        """Test ready output."""
        data = {
            "status": "ok",
            "database": "ok",
        }
        print_ready(data)


class TestWhoamiOutput:
    """Tests for whoami output formatting."""

    def test_print_whoami(self):
        """Test whoami output."""
        data = {
            "user": {
                "id": "123",
                "username": "testuser",
                "email": "test@example.com",
                "is_superuser": True,
            },
            "api_key": {
                "id": "key-123",
                "name": "My Key",
                "scopes": ["read", "write"],
            },
        }
        print_whoami(data)


class TestUsersOutput:
    """Tests for users output formatting."""

    def test_print_users_table(self):
        """Test users table output."""
        users = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "user1",
                "email": "user1@example.com",
                "is_superuser": True,
                "is_active": True,
                "created_at": "2024-01-15T10:00:00Z",
            },
            {
                "id": "223e4567-e89b-12d3-a456-426614174000",
                "username": "user2",
                "email": "user2@example.com",
                "is_superuser": False,
                "is_active": False,
                "created_at": "2024-01-16T10:00:00Z",
            },
        ]
        print_users_table(users)

    def test_print_user(self):
        """Test single user output."""
        user = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "testuser",
            "email": "test@example.com",
            "is_superuser": False,
            "is_active": True,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-16T10:00:00Z",
        }
        print_user(user)


class TestAPIKeysOutput:
    """Tests for API keys output formatting."""

    def test_print_api_keys_table(self):
        """Test API keys table output."""
        keys = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Key 1",
                "scopes": ["read"],
                "expires_at": "2025-01-15T10:00:00Z",
                "last_used_at": "2024-01-10T10:00:00Z",
                "created_at": "2024-01-01T10:00:00Z",
            },
            {
                "id": "223e4567-e89b-12d3-a456-426614174000",
                "name": "Key 2",
                "scopes": [],
                "expires_at": None,
                "last_used_at": None,
                "created_at": "2024-01-02T10:00:00Z",
            },
        ]
        print_api_keys_table(keys)

    def test_print_api_keys_table_expired(self):
        """Test API keys table with expired key."""
        keys = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Expired Key",
                "scopes": [],
                "expires_at": "2020-01-15T10:00:00Z",  # Past date
                "last_used_at": None,
                "created_at": "2019-01-01T10:00:00Z",
            },
        ]
        print_api_keys_table(keys)

    def test_print_api_key_without_secret(self):
        """Test API key output without secret."""
        key = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "My Key",
            "scopes": ["read", "write"],
            "expires_at": "2025-01-15T10:00:00Z",
            "created_at": "2024-01-01T10:00:00Z",
        }
        print_api_key(key, show_secret=False)

    def test_print_api_key_with_secret(self):
        """Test API key output with secret."""
        key = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "My Key",
            "scopes": [],
            "expires_at": None,
            "created_at": "2024-01-01T10:00:00Z",
            "key": "fsmtp_test_secret_key_12345",
        }
        print_api_key(key, show_secret=True)


class TestDomainsOutput:
    """Tests for domains output formatting."""

    def test_print_domains_table(self):
        """Test domains table output."""
        domains = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "domain_name": "example.com",
                "description": "Example domain",
                "is_enabled": True,
                "role": "owner",
                "created_at": "2024-01-15T10:00:00Z",
            },
        ]
        print_domains_table(domains)

    def test_print_domain(self):
        """Test single domain output."""
        domain = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "domain_name": "example.com",
            "description": "Example domain",
            "is_enabled": True,
            "role": "owner",
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-16T10:00:00Z",
        }
        print_domain(domain)

    def test_print_domain_no_description(self):
        """Test domain output without description."""
        domain = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "domain_name": "example.com",
            "description": None,
            "is_enabled": False,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_domain(domain)


class TestMembersOutput:
    """Tests for members output formatting."""

    def test_print_members_table(self):
        """Test members table output."""
        members = [
            {
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": "owner_user",
                    "email": "owner@example.com",
                },
                "role": "owner",
                "created_at": "2024-01-15T10:00:00Z",
            },
            {
                "user": {
                    "id": "223e4567-e89b-12d3-a456-426614174000",
                    "username": "admin_user",
                    "email": "admin@example.com",
                },
                "role": "admin",
                "created_at": "2024-01-16T10:00:00Z",
            },
            {
                "user": {
                    "id": "323e4567-e89b-12d3-a456-426614174000",
                    "username": "member_user",
                    "email": "member@example.com",
                },
                "role": "member",
                "created_at": "2024-01-17T10:00:00Z",
            },
        ]
        print_members_table(members)


class TestRecipientsOutput:
    """Tests for recipients output formatting."""

    def test_print_recipients_table(self):
        """Test recipients table output."""
        recipients = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "local_part": "info",
                "webhook_url": "https://hook.example.com/webhook",
                "tags": ["important", "urgent"],
                "is_enabled": True,
            },
            {
                "id": "223e4567-e89b-12d3-a456-426614174000",
                "local_part": None,  # Catch-all
                "webhook_url": "https://hook.example.com/catchall",
                "tags": [],
                "is_enabled": False,
            },
        ]
        print_recipients_table(recipients)

    def test_print_recipient(self):
        """Test single recipient output."""
        recipient = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "local_part": "info",
            "webhook_url": "https://hook.example.com/webhook",
            "description": "Info email recipient",
            "tags": ["important"],
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_recipient(recipient)

    def test_print_recipient_catchall(self):
        """Test catch-all recipient output."""
        recipient = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "local_part": None,
            "webhook_url": "https://hook.example.com/catchall",
            "description": None,
            "tags": [],
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_recipient(recipient)


class TestRulesetsOutput:
    """Tests for rulesets output formatting."""

    def test_print_rulesets_table(self):
        """Test rulesets table output."""
        rulesets = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Spam Filter",
                "description": "Filter spam emails",
                "priority": 10,
                "rules": [{}, {}, {}],
                "is_enabled": True,
            },
        ]
        print_rulesets_table(rulesets)

    def test_print_ruleset(self):
        """Test single ruleset output."""
        ruleset = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Spam Filter",
            "description": "Filter spam emails",
            "priority": 10,
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
            "rules": [
                {
                    "id": "r1",
                    "name": "Block spam domain",
                    "field": "from",
                    "operator": "contains",
                    "value": "@spam.com",
                    "action": "drop",
                    "priority": 0,
                    "is_enabled": True,
                }
            ],
        }
        print_ruleset(ruleset)

    def test_print_ruleset_no_rules(self):
        """Test ruleset output without rules."""
        ruleset = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Empty Ruleset",
            "description": None,
            "priority": 0,
            "is_enabled": False,
            "created_at": "2024-01-15T10:00:00Z",
            "rules": [],
        }
        print_ruleset(ruleset)


class TestRulesOutput:
    """Tests for rules output formatting."""

    def test_print_rules_table(self):
        """Test rules table output."""
        rules = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Block spam",
                "field": "from",
                "operator": "contains",
                "value": "@spam.com",
                "action": "drop",
                "priority": 10,
                "is_enabled": True,
            },
        ]
        print_rules_table(rules)

    def test_print_rule(self):
        """Test single rule output."""
        rule = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Block spam",
            "field": "from",
            "operator": "contains",
            "value": "@spam.com",
            "action": "forward",
            "action_params": {"url": "https://backup.example.com"},
            "priority": 10,
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_rule(rule)

    def test_print_rule_no_action_params(self):
        """Test rule output without action params."""
        rule = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Tag email",
            "field": "subject",
            "operator": "starts_with",
            "value": "[URGENT]",
            "action": "tag",
            "action_params": None,
            "priority": 0,
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_rule(rule)


class TestDeliveryLogsOutput:
    """Tests for delivery logs output formatting."""

    def test_print_delivery_logs_table(self):
        """Test delivery logs table output."""
        logs = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "message_id": "<msg123@example.com>",
                "recipient_email": "user@example.com",
                "status": "delivered",
                "attempt_count": 1,
                "created_at": "2024-01-15T10:00:00Z",
            },
            {
                "id": "223e4567-e89b-12d3-a456-426614174000",
                "message_id": "<msg456@example.com>",
                "recipient_email": "user2@example.com",
                "status": "failed",
                "attempt_count": 3,
                "created_at": "2024-01-16T10:00:00Z",
            },
        ]
        print_delivery_logs_table(logs)

    def test_print_delivery_log(self):
        """Test single delivery log output."""
        log = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "message_id": "<msg123@example.com>",
            "recipient_email": "user@example.com",
            "webhook_url": "https://hook.example.com/webhook",
            "status": "delivered",
            "attempt_count": 1,
            "http_status_code": 200,
            "last_error": None,
            "created_at": "2024-01-15T10:00:00Z",
            "next_retry_at": None,
            "payload": {"subject": "Test email"},
        }
        print_delivery_log(log)

    def test_print_delivery_log_failed(self):
        """Test failed delivery log output."""
        log = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "message_id": "<msg123@example.com>",
            "recipient_email": "user@example.com",
            "webhook_url": "https://hook.example.com/webhook",
            "status": "failed",
            "attempt_count": 3,
            "http_status_code": 500,
            "last_error": "Server error",
            "created_at": "2024-01-15T10:00:00Z",
            "next_retry_at": "2024-01-15T11:00:00Z",
        }
        print_delivery_log(log)


class TestTestWebhookOutput:
    """Tests for test webhook output formatting."""

    def test_print_test_webhook_result_success(self):
        """Test successful webhook test output."""
        result = {
            "success": True,
            "status_code": 200,
            "response_time_ms": 150.5,
        }
        print_test_webhook_result(result)

    def test_print_test_webhook_result_failure(self):
        """Test failed webhook test output."""
        result = {
            "success": False,
            "status_code": 500,
            "error": "Internal server error",
            "response_time_ms": 1000.0,
        }
        print_test_webhook_result(result)

    def test_print_test_webhook_result_connection_error(self):
        """Test webhook test with connection error."""
        result = {
            "success": False,
            "status_code": None,
            "error": "Connection refused",
            "response_time_ms": 0,
        }
        print_test_webhook_result(result)


class TestProfilesOutput:
    """Tests for profiles output formatting."""

    def test_print_profiles_table(self):
        """Test profiles table output."""
        from fastsmtp_cli.config import Profile

        profiles = {
            "default": Profile(url="http://localhost:8000"),
            "prod": Profile(url="https://prod.example.com", api_key="prod_key"),
        }
        print_profiles_table(profiles, default_profile="default")

    def test_print_profiles_table_with_keys(self):
        """Test profiles table with API keys shown."""
        from fastsmtp_cli.config import Profile

        profiles = {
            "default": Profile(url="http://localhost:8000"),
            "prod": Profile(url="https://prod.example.com", api_key="prod_key_12345"),
        }
        print_profiles_table(profiles, default_profile="prod", show_keys=True)
