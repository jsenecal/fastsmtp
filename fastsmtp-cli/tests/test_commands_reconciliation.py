"""Tests for the command signatures and payloads reconciled with the server API.

Companion to ``test_api_contract.py``: that file proves the client speaks to
routes the server serves, this one proves the ``fsmtp`` commands pass the right
arguments down to it - the nested domain IDs the server's routes require, and
the v0.2.0 raw-preservation flags.
"""

import json
import re
import tempfile
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import respx
from fastsmtp_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

BASE = "https://api.example.com"


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return ANSI_ESCAPE.sub("", text)


def body_of(route) -> dict:
    """JSON body of the first request made against a mocked route."""
    return json.loads(route.calls[0].request.content)


@pytest.fixture
def temp_config(monkeypatch):
    """Config pointing the CLI at the mocked API host."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.toml"
        monkeypatch.setenv("FSMTP_CONFIG", str(config_path))
        monkeypatch.setenv("FSMTP_URL", BASE)
        monkeypatch.setenv("FSMTP_API_KEY", "test_api_key")
        yield config_path


@pytest.fixture
def domain_id() -> str:
    return str(uuid4())


@pytest.fixture
def ruleset_id() -> str:
    return str(uuid4())


@pytest.fixture
def rule_id() -> str:
    return str(uuid4())


def domain_payload(domain_id: str, **overrides) -> dict:
    """A DomainResponse-shaped body."""
    payload = {
        "id": domain_id,
        "domain_name": "example.com",
        "is_enabled": True,
        "verify_dkim": None,
        "verify_spf": None,
        "reject_dkim_fail": None,
        "reject_spf_fail": None,
        "preserve_raw_message": None,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def rule_payload(rule_id: str, ruleset_id: str, **overrides) -> dict:
    """A RuleResponse-shaped body."""
    payload = {
        "id": rule_id,
        "ruleset_id": ruleset_id,
        "order": 0,
        "field": "subject",
        "operator": "contains",
        "value": "[SPAM]",
        "case_sensitive": False,
        "action": "tag",
        "webhook_url_override": None,
        "add_tags": ["spam"],
        "preserve_raw": False,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def ruleset_payload(ruleset_id: str, domain_id: str, rules: list[dict] | None = None) -> dict:
    """A RuleSetWithRulesResponse-shaped body."""
    return {
        "id": ruleset_id,
        "domain_id": domain_id,
        "name": "Spam Filter",
        "priority": 10,
        "stop_on_match": True,
        "is_enabled": True,
        "rules": rules if rules is not None else [],
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }


class TestDomainRawPreservation:
    """`fsmtp domain create|update --preserve-raw-message` (issue #46 item 5)."""

    @respx.mock
    def test_create_sends_preserve_raw_message_true(self, temp_config, domain_id):
        route = respx.post(f"{BASE}/api/v1/domains").mock(
            return_value=httpx.Response(201, json=domain_payload(domain_id))
        )

        result = runner.invoke(
            app, ["domain", "create", "example.com", "--preserve-raw-message", "true"]
        )

        assert result.exit_code == 0
        assert body_of(route)["preserve_raw_message"] is True

    @respx.mock
    def test_create_sends_preserve_raw_message_false(self, temp_config, domain_id):
        route = respx.post(f"{BASE}/api/v1/domains").mock(
            return_value=httpx.Response(201, json=domain_payload(domain_id))
        )

        result = runner.invoke(
            app, ["domain", "create", "example.com", "--preserve-raw-message", "false"]
        )

        assert result.exit_code == 0
        assert body_of(route)["preserve_raw_message"] is False

    @respx.mock
    def test_create_inherit_omits_the_field(self, temp_config, domain_id):
        route = respx.post(f"{BASE}/api/v1/domains").mock(
            return_value=httpx.Response(201, json=domain_payload(domain_id))
        )

        result = runner.invoke(
            app, ["domain", "create", "example.com", "--preserve-raw-message", "inherit"]
        )

        assert result.exit_code == 0
        assert "preserve_raw_message" not in body_of(route)

    @respx.mock
    def test_update_inherit_sends_explicit_null(self, temp_config, domain_id):
        """`inherit` must clear the column, which needs an explicit JSON null."""
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}").mock(
            return_value=httpx.Response(200, json=domain_payload(domain_id))
        )

        result = runner.invoke(
            app, ["domain", "update", domain_id, "--preserve-raw-message", "inherit"]
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert "preserve_raw_message" in body
        assert body["preserve_raw_message"] is None

    @respx.mock
    def test_update_without_the_flag_omits_the_field(self, temp_config, domain_id):
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}").mock(
            return_value=httpx.Response(200, json=domain_payload(domain_id))
        )

        result = runner.invoke(app, ["domain", "update", domain_id, "--disabled"])

        assert result.exit_code == 0
        assert "preserve_raw_message" not in body_of(route)

    @respx.mock
    def test_update_sends_verification_flags(self, temp_config, domain_id):
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}").mock(
            return_value=httpx.Response(200, json=domain_payload(domain_id))
        )

        result = runner.invoke(
            app,
            [
                "domain",
                "update",
                domain_id,
                "--verify-dkim",
                "true",
                "--reject-spf-fail",
                "false",
            ],
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert body["verify_dkim"] is True
        assert body["reject_spf_fail"] is False

    @respx.mock
    def test_create_reports_422_when_s3_missing(self, temp_config):
        """The server's 422 detail must reach the user, not a traceback."""
        detail = (
            "Raw message preservation requires S3 storage to be configured. "
            "Missing settings: s3_bucket, s3_endpoint_url"
        )
        respx.post(f"{BASE}/api/v1/domains").mock(
            return_value=httpx.Response(422, json={"detail": detail})
        )

        result = runner.invoke(
            app, ["domain", "create", "example.com", "--preserve-raw-message", "true"]
        )

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Raw message preservation requires S3" in strip_ansi(result.output)

    @respx.mock
    def test_shows_preserve_raw_message_in_output(self, temp_config, domain_id):
        respx.get(f"{BASE}/api/v1/domains/{domain_id}").mock(
            return_value=httpx.Response(
                200, json=domain_payload(domain_id, preserve_raw_message=True)
            )
        )

        result = runner.invoke(app, ["domain", "get", domain_id])

        assert result.exit_code == 0
        assert "Preserve Raw" in strip_ansi(result.output)


class TestRecipientDomainScoping:
    """Recipient commands need the domain ID the server's routes nest them under."""

    @respx.mock
    def test_get_uses_nested_route(self, temp_config, domain_id):
        recipient_id = str(uuid4())
        route = respx.get(f"{BASE}/api/v1/domains/{domain_id}/recipients/{recipient_id}").mock(
            return_value=httpx.Response(200, json={"id": recipient_id, "local_part": "info"})
        )

        result = runner.invoke(app, ["recipient", "get", domain_id, recipient_id])

        assert result.exit_code == 0
        assert route.called

    @respx.mock
    def test_update_uses_nested_put(self, temp_config, domain_id):
        recipient_id = str(uuid4())
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}/recipients/{recipient_id}").mock(
            return_value=httpx.Response(200, json={"id": recipient_id})
        )

        result = runner.invoke(
            app,
            [
                "recipient",
                "update",
                domain_id,
                recipient_id,
                "--webhook",
                "https://hook.example.com/new",
            ],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"webhook_url": "https://hook.example.com/new"}

    @respx.mock
    def test_delete_uses_nested_route(self, temp_config, domain_id):
        recipient_id = str(uuid4())
        route = respx.delete(f"{BASE}/api/v1/domains/{domain_id}/recipients/{recipient_id}").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(app, ["recipient", "delete", domain_id, recipient_id, "--force"])

        assert result.exit_code == 0
        assert route.called

    @respx.mock
    def test_create_sends_webhook_headers(self, temp_config, domain_id):
        route = respx.post(f"{BASE}/api/v1/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(201, json={"id": str(uuid4())})
        )

        result = runner.invoke(
            app,
            [
                "recipient",
                "create",
                domain_id,
                "https://hook.example.com",
                "--local",
                "support",
                "--header",
                "X-Token=abc123",
            ],
        )

        assert result.exit_code == 0
        assert body_of(route)["webhook_headers"] == {"X-Token": "abc123"}

    @respx.mock
    def test_create_rejects_malformed_header(self, temp_config, domain_id):
        result = runner.invoke(
            app,
            [
                "recipient",
                "create",
                domain_id,
                "https://hook.example.com",
                "--header",
                "not-a-pair",
            ],
        )

        assert result.exit_code == 1
        assert "KEY=VALUE" in strip_ansi(result.output)


class TestRuleSetDomainScoping:
    """Ruleset commands need the domain ID too."""

    @respx.mock
    def test_get_uses_nested_route(self, temp_config, domain_id, ruleset_id):
        route = respx.get(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(200, json=ruleset_payload(ruleset_id, domain_id))
        )

        result = runner.invoke(app, ["rules", "get", domain_id, ruleset_id])

        assert result.exit_code == 0
        assert route.called

    @respx.mock
    def test_update_uses_nested_put(self, temp_config, domain_id, ruleset_id):
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(200, json=ruleset_payload(ruleset_id, domain_id))
        )

        result = runner.invoke(app, ["rules", "update", domain_id, ruleset_id, "--priority", "20"])

        assert result.exit_code == 0
        assert body_of(route) == {"priority": 20}

    @respx.mock
    def test_update_sends_stop_on_match(self, temp_config, domain_id, ruleset_id):
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(200, json=ruleset_payload(ruleset_id, domain_id))
        )

        result = runner.invoke(
            app, ["rules", "update", domain_id, ruleset_id, "--no-stop-on-match"]
        )

        assert result.exit_code == 0
        assert body_of(route) == {"stop_on_match": False}

    @respx.mock
    def test_delete_uses_nested_route(self, temp_config, domain_id, ruleset_id):
        route = respx.delete(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(app, ["rules", "delete", domain_id, ruleset_id, "--force"])

        assert result.exit_code == 0
        assert route.called

    @respx.mock
    def test_create_sends_stop_on_match(self, temp_config, domain_id, ruleset_id):
        route = respx.post(f"{BASE}/api/v1/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(201, json=ruleset_payload(ruleset_id, domain_id))
        )

        result = runner.invoke(
            app, ["rules", "create", domain_id, "Spam Filter", "--priority", "10"]
        )

        assert result.exit_code == 0
        assert body_of(route) == {
            "name": "Spam Filter",
            "priority": 10,
            "stop_on_match": True,
        }


class TestRuleCommands:
    """Rules use the server's real fields and live under a domain."""

    @respx.mock
    def test_list_reads_rules_from_the_ruleset(self, temp_config, domain_id, ruleset_id, rule_id):
        """There is no rules collection endpoint; rules come with the ruleset."""
        route = respx.get(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(
                200,
                json=ruleset_payload(
                    ruleset_id, domain_id, rules=[rule_payload(rule_id, ruleset_id)]
                ),
            )
        )

        result = runner.invoke(app, ["rules", "rule", "list", domain_id, ruleset_id])

        assert result.exit_code == 0
        assert route.called
        assert "subject" in strip_ansi(result.output)

    @respx.mock
    def test_get_picks_the_rule_out_of_the_ruleset(
        self, temp_config, domain_id, ruleset_id, rule_id
    ):
        respx.get(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(
                200,
                json=ruleset_payload(
                    ruleset_id, domain_id, rules=[rule_payload(rule_id, ruleset_id)]
                ),
            )
        )

        result = runner.invoke(app, ["rules", "rule", "get", domain_id, ruleset_id, rule_id])

        assert result.exit_code == 0
        assert "[SPAM]" in strip_ansi(result.output)

    @respx.mock
    def test_get_reports_unknown_rule(self, temp_config, domain_id, ruleset_id, rule_id):
        respx.get(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(200, json=ruleset_payload(ruleset_id, domain_id))
        )

        result = runner.invoke(app, ["rules", "rule", "get", domain_id, ruleset_id, rule_id])

        assert result.exit_code == 1
        assert "not found" in strip_ansi(result.output).lower()

    @respx.mock
    def test_create_sends_only_server_fields(self, temp_config, domain_id, ruleset_id, rule_id):
        route = respx.post(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(201, json=rule_payload(rule_id, ruleset_id))
        )

        result = runner.invoke(
            app,
            [
                "rules",
                "rule",
                "create",
                domain_id,
                ruleset_id,
                "--field",
                "subject",
                "--operator",
                "contains",
                "--value",
                "[SPAM]",
                "--action",
                "tag",
                "--tag",
                "spam",
                "--case-sensitive",
                "--preserve-raw",
            ],
        )

        assert result.exit_code == 0
        assert body_of(route) == {
            "field": "subject",
            "operator": "contains",
            "value": "[SPAM]",
            "action": "tag",
            "case_sensitive": True,
            "preserve_raw": True,
            "add_tags": ["spam"],
        }

    @respx.mock
    def test_create_rejects_operators_the_server_rejects(self, temp_config, domain_id, ruleset_id):
        result = runner.invoke(
            app,
            [
                "rules",
                "rule",
                "create",
                domain_id,
                ruleset_id,
                "--field",
                "subject",
                "--operator",
                "not_equals",
                "--value",
                "x",
            ],
        )

        assert result.exit_code == 1
        assert "Invalid operator" in strip_ansi(result.output)

    @respx.mock
    def test_create_reports_422_when_s3_missing(self, temp_config, domain_id, ruleset_id):
        detail = (
            "Raw message preservation requires S3 storage to be configured. "
            "Missing settings: s3_bucket"
        )
        respx.post(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(422, json={"detail": detail})
        )

        result = runner.invoke(
            app,
            [
                "rules",
                "rule",
                "create",
                domain_id,
                ruleset_id,
                "--field",
                "subject",
                "--operator",
                "contains",
                "--value",
                "x",
                "--preserve-raw",
            ],
        )

        assert result.exit_code == 1
        assert "Raw message preservation requires S3" in strip_ansi(result.output)

    @respx.mock
    def test_update_uses_domain_scoped_put(self, temp_config, domain_id, rule_id, ruleset_id):
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}/rules/{rule_id}").mock(
            return_value=httpx.Response(200, json=rule_payload(rule_id, ruleset_id))
        )

        result = runner.invoke(
            app,
            ["rules", "rule", "update", domain_id, rule_id, "--action", "drop", "--preserve-raw"],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"action": "drop", "preserve_raw": True}

    @respx.mock
    def test_update_can_clear_preserve_raw(self, temp_config, domain_id, rule_id, ruleset_id):
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}/rules/{rule_id}").mock(
            return_value=httpx.Response(200, json=rule_payload(rule_id, ruleset_id))
        )

        result = runner.invoke(
            app, ["rules", "rule", "update", domain_id, rule_id, "--no-preserve-raw"]
        )

        assert result.exit_code == 0
        assert body_of(route) == {"preserve_raw": False}

    @respx.mock
    def test_delete_uses_domain_scoped_route(self, temp_config, domain_id, rule_id):
        route = respx.delete(f"{BASE}/api/v1/domains/{domain_id}/rules/{rule_id}").mock(
            return_value=httpx.Response(200, json={"message": "Rule deleted"})
        )

        result = runner.invoke(app, ["rules", "rule", "delete", domain_id, rule_id, "--force"])

        assert result.exit_code == 0
        assert route.called

    @respx.mock
    def test_reorder_sends_the_rule_ids(self, temp_config, domain_id, ruleset_id):
        first, second = str(uuid4()), str(uuid4())
        route = respx.post(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}/reorder").mock(
            return_value=httpx.Response(200, json={"message": "Rules reordered"})
        )

        result = runner.invoke(
            app, ["rules", "rule", "reorder", domain_id, ruleset_id, first, second]
        )

        assert result.exit_code == 0
        assert body_of(route) == {"rule_ids": [first, second]}

    @respx.mock
    def test_rule_output_shows_server_fields(self, temp_config, domain_id, ruleset_id, rule_id):
        respx.get(f"{BASE}/api/v1/domains/{domain_id}/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(
                200,
                json=ruleset_payload(
                    ruleset_id,
                    domain_id,
                    rules=[rule_payload(rule_id, ruleset_id, preserve_raw=True, order=3)],
                ),
            )
        )

        result = runner.invoke(app, ["rules", "rule", "get", domain_id, ruleset_id, rule_id])
        output = strip_ansi(result.output)

        assert result.exit_code == 0
        assert "Preserve Raw" in output
        assert "Order" in output


class TestMemberCommands:
    """Member role updates use PUT, which is what the server serves."""

    @respx.mock
    def test_update_member_uses_put(self, temp_config, domain_id):
        user_id = str(uuid4())
        route = respx.put(f"{BASE}/api/v1/domains/{domain_id}/members/{user_id}").mock(
            return_value=httpx.Response(200, json={"id": str(uuid4()), "role": "admin"})
        )

        result = runner.invoke(
            app, ["domain", "member", "update", domain_id, user_id, "--role", "admin"]
        )

        assert result.exit_code == 0
        assert body_of(route) == {"role": "admin"}


class TestApiKeyExpiry:
    """`auth create-key --expires <days>` must send the server's `expires_at`."""

    @respx.mock
    def test_expiry_is_sent_as_a_timestamp(self, temp_config):
        route = respx.post(f"{BASE}/api/v1/auth/keys").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": str(uuid4()),
                    "name": "ci",
                    "key": "secret",
                    "key_prefix": "fsk_",
                    "scopes": [],
                    "expires_at": None,
                    "last_used_at": None,
                    "is_active": True,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            )
        )

        result = runner.invoke(app, ["auth", "create-key", "ci", "--expires", "30"])

        assert result.exit_code == 0
        body = body_of(route)
        assert "expires_days" not in body
        assert body["expires_at"].startswith("20")
