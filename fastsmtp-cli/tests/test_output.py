"""Tests for CLI output formatting utilities."""

from datetime import UTC, datetime

from fastsmtp_cli.output import (
    _format_expiry,
    console,
    field,
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
    short_id,
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


class TestField:
    """Tests for the field helper (escaped server text with a placeholder)."""

    def test_none_renders_placeholder(self):
        assert field(None) == "-"

    def test_empty_string_renders_placeholder(self):
        assert field("") == "-"

    def test_custom_placeholder(self):
        assert field(None, placeholder="all") == "all"

    def test_plain_text_passes_through(self):
        assert field("example.com") == "example.com"

    def test_non_string_is_stringified(self):
        assert field(42) == "42"

    def test_markup_is_escaped(self):
        assert field("[red]x[/red]") == r"\[red]x\[/red]"


class TestShortId:
    """Tests for the short_id helper (truncated, escaped identifiers)."""

    def test_none_renders_placeholder(self):
        assert short_id(None) == "-"

    def test_id_is_truncated_to_eight_chars(self):
        assert short_id("123e4567-e89b-12d3-a456-426614174000") == "123e4567..."

    def test_markup_in_id_is_escaped(self):
        assert short_id("[/x]bad-id") == r"\[/x]bad-..."


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
            "domains": ["example.com"],
            "is_root": False,
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

    def test_users_render_a_null_email_as_a_dash(self, capsys, monkeypatch):
        """`UserResponse.email` is nullable - both views must show a placeholder.

        The width is pinned so the assertions below cannot depend on rich's
        terminal-size detection: a narrower console truncates cells to an
        ellipsis and a wider one repads them. ``console`` reads ``COLUMNS`` once,
        when ``output`` is imported, so the size has to be set on the object.
        """
        monkeypatch.setattr(console, "_width", 100)
        user = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "testuser",
            "email": None,
            "is_superuser": False,
            "is_active": True,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-16T10:00:00Z",
        }

        print_users_table([user])
        assert "testuser │ - │" in " ".join(capsys.readouterr().out.split())

        print_user(user)
        assert "Email - " in " ".join(capsys.readouterr().out.split())


class TestFormatExpiry:
    """Tests for the _format_expiry helper shared by both API-key printers."""

    def test_none_renders_dim_never(self):
        assert _format_expiry(None) == "[dim]Never[/dim]"

    def test_future_timestamp_renders_plain(self):
        assert _format_expiry("2999-01-15T10:00:00Z") == "2999-01-15 10:00:00"

    def test_expired_timestamp_is_styled_red(self):
        assert _format_expiry("2020-01-15T10:00:00Z") == "[red]2020-01-15 10:00:00[/red]"

    def test_malformed_text_is_shown_literally_without_styling(self):
        assert _format_expiry("soon-ish") == "soon-ish"

    def test_malformed_text_with_markup_is_escaped(self):
        assert _format_expiry("[red]x[/red]") == r"\[red]x\[/red]"


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

    def test_table_survives_malformed_expiry_and_shows_it_literally(self, capsys, monkeypatch):
        """A non-ISO `expires_at` must not crash the table -- render it as-is.

        The expired-vs-not check used to parse the string before
        `format_datetime`'s literal-text fallback could run, so any server
        value `datetime.fromisoformat` rejects killed the whole command.
        """
        monkeypatch.setattr(console, "_width", 120)
        keys = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Odd Key",
                "scopes": [],
                "expires_at": "soon-ish",
                "last_used_at": None,
                "created_at": "2024-01-01T10:00:00Z",
            },
        ]
        print_api_keys_table(keys)
        output = capsys.readouterr().out
        assert "soon-ish" in output

    def test_expired_key_markup_parses_instead_of_leaking(self, capsys, monkeypatch):
        """The red styling on an expired key must parse, not print literally."""
        monkeypatch.setattr(console, "_width", 120)
        keys = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Expired Key",
                "scopes": [],
                "expires_at": "2020-01-15T10:00:00Z",
                "last_used_at": None,
                "created_at": "2019-01-01T10:00:00Z",
            },
        ]
        print_api_keys_table(keys)
        output = capsys.readouterr().out
        assert "2020-01-15" in output
        assert "[red]" not in output

    def test_no_expiry_renders_never_in_both_views(self, capsys, monkeypatch):
        """A key with no expiry must say "Never" in the table AND the detail view.

        The detail view used `format_datetime(...) or "Never"`, but
        `format_datetime(None)` returns a truthy "-", so the or-arm was dead
        and the two views disagreed.
        """
        monkeypatch.setattr(console, "_width", 120)
        key = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Eternal Key",
            "scopes": [],
            "expires_at": None,
            "last_used_at": None,
            "created_at": "2024-01-01T10:00:00Z",
        }

        print_api_keys_table([key])
        assert "Never" in capsys.readouterr().out

        print_api_key(key, show_secret=False)
        output = capsys.readouterr().out
        assert "Never" in output
        assert "[dim]" not in output


class TestDomainsOutput:
    """Tests for domains output formatting."""

    def test_print_domains_table(self):
        """Test domains table output."""
        domains = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "domain_name": "example.com",
                "is_enabled": True,
                "verify_dkim": True,
                "verify_spf": None,
                "preserve_raw_message": True,
                "created_at": "2024-01-15T10:00:00Z",
            },
        ]
        print_domains_table(domains)

    def test_print_domain(self):
        """Test single domain output."""
        domain = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "domain_name": "example.com",
            "is_enabled": True,
            "verify_dkim": True,
            "verify_spf": False,
            "reject_dkim_fail": None,
            "reject_spf_fail": None,
            "preserve_raw_message": True,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-16T10:00:00Z",
        }
        print_domain(domain)

    def test_print_domain_inheriting_every_flag(self):
        """A domain with every nullable flag unset inherits the server defaults."""
        domain = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "domain_name": "example.com",
            "is_enabled": False,
            "verify_dkim": None,
            "verify_spf": None,
            "reject_dkim_fail": None,
            "reject_spf_fail": None,
            "preserve_raw_message": None,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_domain(domain)


class TestMembersOutput:
    """Tests for members output formatting."""

    def test_print_members_table(self):
        """Test members table output."""
        members = [
            {
                "id": "a23e4567-e89b-12d3-a456-426614174000",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "owner_user",
                "role": "owner",
                "created_at": "2024-01-15T10:00:00Z",
            },
            {
                "id": "b23e4567-e89b-12d3-a456-426614174000",
                "user_id": "223e4567-e89b-12d3-a456-426614174000",
                "username": "admin_user",
                "role": "admin",
                "created_at": "2024-01-16T10:00:00Z",
            },
            {
                "id": "c23e4567-e89b-12d3-a456-426614174000",
                "user_id": "323e4567-e89b-12d3-a456-426614174000",
                "username": None,
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
                "webhook_headers": {"X-Token": "abc123"},
                "is_enabled": True,
            },
            {
                "id": "223e4567-e89b-12d3-a456-426614174000",
                "local_part": None,  # Catch-all
                "webhook_url": "https://hook.example.com/catchall",
                "webhook_headers": {},
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
            "webhook_headers": {"X-Token": "abc123"},
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
            "webhook_headers": {},
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
                "priority": 10,
                "stop_on_match": True,
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
            "priority": 10,
            "stop_on_match": True,
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
            "rules": [
                {
                    "id": "r1",
                    "ruleset_id": "123e4567-e89b-12d3-a456-426614174000",
                    "order": 0,
                    "field": "from",
                    "operator": "contains",
                    "value": "@spam.com",
                    "case_sensitive": False,
                    "action": "drop",
                    "add_tags": [],
                    "preserve_raw": False,
                }
            ],
        }
        print_ruleset(ruleset)

    def test_print_ruleset_no_rules(self):
        """Test ruleset output without rules."""
        ruleset = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "name": "Empty Ruleset",
            "priority": 0,
            "stop_on_match": False,
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
                "ruleset_id": "223e4567-e89b-12d3-a456-426614174000",
                "order": 10,
                "field": "from",
                "operator": "contains",
                "value": "@spam.com",
                "case_sensitive": False,
                "action": "drop",
                "add_tags": ["spam"],
                "preserve_raw": True,
            },
        ]
        print_rules_table(rules)

    def test_print_rule(self):
        """Test single rule output."""
        rule = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "ruleset_id": "223e4567-e89b-12d3-a456-426614174000",
            "order": 10,
            "field": "from",
            "operator": "contains",
            "value": "@spam.com",
            "case_sensitive": True,
            "action": "forward",
            "webhook_url_override": "https://backup.example.com",
            "add_tags": ["spam"],
            "preserve_raw": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_rule(rule)

    def test_print_rule_with_defaults(self):
        """Test rule output with every optional field left at its default."""
        rule = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "ruleset_id": "223e4567-e89b-12d3-a456-426614174000",
            "order": 0,
            "field": "subject",
            "operator": "starts_with",
            "value": "[URGENT]",
            "case_sensitive": False,
            "action": "tag",
            "webhook_url_override": None,
            "add_tags": [],
            "preserve_raw": False,
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
                "recipient_id": "323e4567-e89b-12d3-a456-426614174000",
                "status": "delivered",
                "attempts": 1,
                "created_at": "2024-01-15T10:00:00Z",
            },
            {
                "id": "223e4567-e89b-12d3-a456-426614174000",
                "message_id": "<msg456@example.com>",
                "recipient_id": None,
                "status": "failed",
                "attempts": 3,
                "created_at": "2024-01-16T10:00:00Z",
            },
        ]
        print_delivery_logs_table(logs)

    def test_print_delivery_log(self):
        """Test single delivery log output."""
        log = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "message_id": "<msg123@example.com>",
            "recipient_id": "323e4567-e89b-12d3-a456-426614174000",
            "webhook_url": "https://hook.example.com/webhook",
            "status": "delivered",
            "attempts": 1,
            "last_status_code": 200,
            "dkim_result": "pass",
            "spf_result": "pass",
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
            "recipient_id": "323e4567-e89b-12d3-a456-426614174000",
            "webhook_url": "https://hook.example.com/webhook",
            "status": "failed",
            "attempts": 3,
            "last_status_code": 500,
            "dkim_result": "fail",
            "spf_result": None,
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


class TestServerShapedOutput:
    """The formatters must read the fields the server actually returns.

    The smoke tests above only prove the formatters do not crash. These assert
    on the rendered text, so a field renamed on either side shows up here.
    """

    def test_domain_renders_nullable_flags_as_inherit(self, capsys):
        """A null flag means "inherit the server default", not "off"."""
        print_domain(
            {
                "id": "d1",
                "domain_name": "example.com",
                "is_enabled": True,
                "verify_dkim": True,
                "verify_spf": False,
                "reject_dkim_fail": None,
                "reject_spf_fail": None,
                "preserve_raw_message": None,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:00:00Z",
            }
        )
        output = capsys.readouterr().out

        assert "Verify DKIM" in output
        assert "Preserve Raw" in output
        assert "inherit" in output

    def test_domain_renders_preserve_raw_message_enabled(self, capsys):
        print_domain(
            {
                "id": "d1",
                "domain_name": "example.com",
                "is_enabled": True,
                "preserve_raw_message": True,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:00:00Z",
            }
        )
        output = capsys.readouterr().out

        assert "Preserve Raw" in output
        assert "inherit" not in output.split("Preserve Raw")[1].splitlines()[0]

    def test_rule_renders_order_tags_and_preserve_raw(self, capsys):
        print_rule(
            {
                "id": "r1",
                "ruleset_id": "rs1",
                "order": 3,
                "field": "subject",
                "operator": "contains",
                "value": "[SPAM]",
                "case_sensitive": True,
                "action": "tag",
                "webhook_url_override": None,
                "add_tags": ["spam", "review"],
                "preserve_raw": True,
                "created_at": "2024-01-15T10:00:00Z",
            }
        )
        output = capsys.readouterr().out

        assert "Order" in output
        assert "Preserve Raw" in output
        assert "spam, review" in output
        assert "Case Sensitive" in output

    def test_rules_table_reads_order_not_priority(self, capsys):
        print_rules_table(
            [
                {
                    "id": "11111111-2222-3333-4444-555555555555",
                    "order": 7,
                    "field": "from",
                    "operator": "equals",
                    "value": "a@b.test",
                    "action": "drop",
                    "add_tags": [],
                    "preserve_raw": False,
                }
            ]
        )
        output = capsys.readouterr().out

        assert "Order" in output
        assert "7" in output

    def test_member_table_reads_flat_user_fields(self, capsys):
        print_members_table(
            [
                {
                    "id": "m1",
                    "user_id": "abcdef12-3456-7890-abcd-ef1234567890",
                    "username": "alice",
                    "role": "admin",
                    "created_at": "2024-01-15T10:00:00Z",
                }
            ]
        )
        output = capsys.readouterr().out

        assert "alice" in output
        assert "admin" in output
        assert "abcdef12" in output

    def test_whoami_reads_domains_and_root_flag(self, capsys):
        print_whoami(
            {
                "user": {
                    "id": "u1",
                    "username": "alice",
                    "email": None,
                    "is_superuser": False,
                },
                "domains": ["example.com", "other.test"],
                "is_root": True,
            }
        )
        output = capsys.readouterr().out

        assert "alice" in output
        assert "example.com" in output
        assert "Root Key" in output

    def test_delivery_log_reads_attempts_and_status_code(self, capsys):
        print_delivery_log(
            {
                "id": "l1",
                "message_id": "<msg@example.com>",
                "recipient_id": "abcdef12-3456-7890-abcd-ef1234567890",
                "webhook_url": "https://hook.example.com",
                "status": "failed",
                "attempts": 4,
                "last_status_code": 503,
                "dkim_result": "pass",
                "last_error": "boom",
                "created_at": "2024-01-15T10:00:00Z",
                "next_retry_at": None,
            }
        )
        output = capsys.readouterr().out

        assert "4" in output
        assert "503" in output
        assert "pass" in output

    def test_recipient_renders_webhook_headers(self, capsys):
        print_recipient(
            {
                "id": "r1",
                "local_part": "support",
                "webhook_url": "https://hook.example.com",
                "webhook_headers": {"X-Token": "abc"},
                "is_enabled": True,
                "created_at": "2024-01-15T10:00:00Z",
            }
        )
        output = capsys.readouterr().out

        assert "Webhook Headers" in output
        assert "X-Token=abc" in output

    def test_error_detail_with_brackets_is_not_parsed_as_markup(self, capsys):
        """Server details list valid values in brackets; rich must not eat them."""
        print_error("Invalid field 'x'. Valid fields: [from, to, subject]")
        output = capsys.readouterr().err

        assert "[from, to, subject]" in output

    def test_webhook_result_without_response_time(self, capsys):
        """A failed webhook test reports a null response_time_ms."""
        print_test_webhook_result(
            {"success": False, "status_code": None, "error": "timeout", "response_time_ms": None}
        )
        output = capsys.readouterr().out

        assert "FAILED" in output
        assert "timeout" in output


class TestServerTextEscaping:
    """Server-supplied text must render literally, never parse as rich markup.

    Rich parses plain-string cells as markup, so a bracketed value could crash
    the command (``MarkupError`` on an unmatched closing tag) or inject styling
    and disguised links into another admin's terminal. Only the markup the
    formatters build deliberately (``yes_no``, ``tri_state``, the
    ``status_style`` wrappers) may parse.
    """

    # An unmatched closing tag: raises MarkupError if rich parses it.
    BAD = "ex[/x].com"

    def test_markup_in_username_renders_literally(self, capsys, monkeypatch):
        """Injected tags must appear as text, not be swallowed as styling."""
        monkeypatch.setattr(console, "_width", 200)
        payload = "[bold red on white]PWNED[/bold red on white]"
        print_users_table(
            [
                {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": payload,
                    "email": "user@example.com",
                    "is_superuser": False,
                    "is_active": True,
                    "created_at": "2024-01-15T10:00:00Z",
                }
            ]
        )
        output = " ".join(capsys.readouterr().out.split())
        assert payload in output

    def test_link_markup_is_not_rendered_as_link(self, capsys, monkeypatch):
        """A disguised [link=...] must not become a clickable link."""
        monkeypatch.setattr(console, "_width", 200)
        payload = "[link=file:///etc/passwd]click[/link]"
        print_user(
            {
                "id": "u1",
                "username": payload,
                "email": None,
                "is_superuser": False,
                "is_active": True,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:00:00Z",
            }
        )
        output = " ".join(capsys.readouterr().out.split())
        assert payload in output

    def test_domain_printers_survive_malformed_markup(self):
        domain = {
            "id": self.BAD,
            "domain_name": self.BAD,
            "is_enabled": True,
            "verify_dkim": None,
            "verify_spf": None,
            "reject_dkim_fail": None,
            "reject_spf_fail": None,
            "preserve_raw_message": None,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        }
        print_domains_table([domain])
        print_domain(domain)

    def test_user_printers_survive_malformed_markup(self):
        user = {
            "id": self.BAD,
            "username": self.BAD,
            "email": self.BAD,
            "is_superuser": False,
            "is_active": True,
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        }
        print_users_table([user])
        print_user(user)

    def test_member_printer_survives_malformed_markup(self):
        print_members_table(
            [
                {
                    "id": "m1",
                    "user_id": self.BAD,
                    "username": self.BAD,
                    "role": self.BAD,
                    "created_at": "2024-01-15T10:00:00Z",
                }
            ]
        )

    def test_recipient_printers_survive_malformed_markup(self):
        recipient = {
            "id": self.BAD,
            "local_part": self.BAD,
            "webhook_url": self.BAD,
            "webhook_headers": {self.BAD: self.BAD},
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_recipients_table([recipient])
        print_recipient(recipient)

    def test_ruleset_and_rule_printers_survive_malformed_markup(self):
        rule = {
            "id": self.BAD,
            "ruleset_id": self.BAD,
            "order": 1,
            "field": self.BAD,
            "operator": self.BAD,
            "value": self.BAD,
            "case_sensitive": False,
            "action": self.BAD,
            "webhook_url_override": self.BAD,
            "add_tags": [self.BAD],
            "preserve_raw": False,
            "created_at": "2024-01-15T10:00:00Z",
        }
        ruleset = {
            "id": self.BAD,
            "name": self.BAD,
            "priority": 0,
            "stop_on_match": False,
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
            "rules": [rule],
        }
        print_rulesets_table([ruleset])
        print_ruleset(ruleset)
        print_rules_table([rule])
        print_rule(rule)

    def test_delivery_log_printers_survive_malformed_markup(self):
        log = {
            "id": self.BAD,
            "message_id": self.BAD,
            "recipient_id": self.BAD,
            "webhook_url": self.BAD,
            "status": self.BAD,
            "attempts": 1,
            "last_status_code": 500,
            "dkim_result": self.BAD,
            "spf_result": self.BAD,
            "last_error": self.BAD,
            "created_at": "2024-01-15T10:00:00Z",
            "next_retry_at": None,
        }
        print_delivery_logs_table([log])
        print_delivery_log(log)

    def test_api_key_printers_survive_malformed_markup(self):
        key = {
            "id": self.BAD,
            "name": self.BAD,
            "scopes": [self.BAD],
            "expires_at": None,
            "last_used_at": None,
            "created_at": "2024-01-15T10:00:00Z",
            "key": self.BAD,
        }
        print_api_keys_table([key])
        print_api_key(key, show_secret=True)

    def test_whoami_and_health_survive_malformed_markup(self):
        print_whoami(
            {
                "user": {
                    "id": self.BAD,
                    "username": self.BAD,
                    "email": self.BAD,
                    "is_superuser": False,
                },
                "domains": [self.BAD],
                "is_root": False,
            }
        )
        print_health({"status": self.BAD, "version": self.BAD, "instance_id": self.BAD})
        print_ready({"status": self.BAD, "database": self.BAD})

    def test_profiles_table_survives_malformed_markup(self):
        from fastsmtp_cli.config import Profile

        profiles = {self.BAD: Profile(url=self.BAD, api_key=self.BAD)}
        print_profiles_table(profiles, default_profile=self.BAD, show_keys=True)

    def test_status_message_survives_malformed_markup(self):
        """A server-sent message routed through print_success must not parse."""
        print_success(self.BAD)
        print_warning(self.BAD)
        print_info(self.BAD)

    def test_status_text_inside_style_wrapper_renders_literally(self, capsys, monkeypatch):
        """The wrapper tags parse; the server status inside them must not."""
        monkeypatch.setattr(console, "_width", 200)
        print_delivery_logs_table(
            [
                {
                    "id": "l1",
                    "message_id": "<m@example.com>",
                    "recipient_id": None,
                    "status": "deliv[/x]ered",
                    "attempts": 1,
                    "created_at": "2024-01-15T10:00:00Z",
                }
            ]
        )
        output = " ".join(capsys.readouterr().out.split())
        assert "deliv[/x]ered" in output

    def test_deliberate_styling_still_parses(self, capsys, monkeypatch):
        """yes_no / tri_state / status wrappers must keep rendering as markup."""
        monkeypatch.setattr(console, "_width", 200)
        print_domain(
            {
                "id": "d1",
                "domain_name": "example.com",
                "is_enabled": True,
                "verify_dkim": None,
                "verify_spf": False,
                "reject_dkim_fail": None,
                "reject_spf_fail": None,
                "preserve_raw_message": None,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:00:00Z",
            }
        )
        output = capsys.readouterr().out
        assert "Yes" in output
        assert "inherit" in output
        assert "[green]" not in output
        assert "[dim]" not in output

    def test_catch_all_placeholder_still_parses(self, capsys, monkeypatch):
        monkeypatch.setattr(console, "_width", 200)
        recipient = {
            "id": "r1",
            "local_part": None,
            "webhook_url": "https://hook.example.com",
            "webhook_headers": {},
            "is_enabled": True,
            "created_at": "2024-01-15T10:00:00Z",
        }
        print_recipients_table([recipient])
        print_recipient(recipient)
        output = capsys.readouterr().out
        assert "(catch-all)" in output
        assert "[dim]" not in output
