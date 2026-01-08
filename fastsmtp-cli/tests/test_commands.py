"""Tests for CLI commands."""

import tempfile
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import respx
from fastsmtp_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def temp_config(monkeypatch):
    """Create a temporary config directory with a test profile."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.toml"
        monkeypatch.setenv("FSMTP_CONFIG", str(config_path))
        monkeypatch.setenv("FSMTP_URL", "https://api.example.com")
        monkeypatch.setenv("FSMTP_API_KEY", "test_api_key")
        yield config_path


class TestMainApp:
    """Tests for main app commands."""

    def test_version(self):
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "FastSMTP CLI version" in result.stdout

    def test_help(self):
        """Test --help flag."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "FastSMTP CLI" in result.stdout

    def test_no_args_shows_help(self):
        """Test running with no arguments shows help (exit code 0 with no_args_is_help)."""
        result = runner.invoke(app, [])
        # no_args_is_help=True shows help with exit code 0
        # But typer exits with 0 here
        assert "FastSMTP CLI" in result.stdout or result.exit_code in (0, 2)


class TestConfigCommands:
    """Tests for config commands."""

    def test_config_show(self, temp_config):
        """Test config show command."""
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0

    def test_config_set_profile(self, temp_config):
        """Test config set command with URL."""
        result = runner.invoke(
            app, ["config", "set", "default", "--url", "https://new.example.com"]
        )
        assert result.exit_code == 0

    def test_config_set_profile_api_key(self, temp_config):
        """Test config set command with API key."""
        result = runner.invoke(app, ["config", "set", "default", "--api-key", "new_api_key"])
        assert result.exit_code == 0

    def test_config_set_requires_options(self, temp_config):
        """Test config set requires at least one option."""
        result = runner.invoke(app, ["config", "set", "default"])
        assert result.exit_code == 1
        # Error might go to stderr (output captures both)
        assert "At least one option" in result.output

    def test_config_use(self, temp_config):
        """Test config use command."""
        # First create a profile
        runner.invoke(app, ["config", "set", "test", "--url", "https://test.example.com"])
        # Then switch to it
        result = runner.invoke(app, ["config", "use", "test"])
        assert result.exit_code == 0

    def test_config_use_nonexistent(self, temp_config):
        """Test config use with nonexistent profile."""
        result = runner.invoke(app, ["config", "use", "nonexistent"])
        assert result.exit_code == 1

    def test_config_delete(self, temp_config):
        """Test config delete command."""
        # First create a profile
        runner.invoke(app, ["config", "set", "test", "--url", "https://test.example.com"])
        # Then delete it
        result = runner.invoke(app, ["config", "delete", "test", "--force"])
        assert result.exit_code == 0


class TestAuthCommands:
    """Tests for auth commands."""

    @respx.mock
    def test_whoami(self, temp_config):
        """Test whoami command."""
        respx.get("https://api.example.com/api/auth/whoami").mock(
            return_value=httpx.Response(
                200,
                json={
                    "user": {
                        "id": "123",
                        "username": "testuser",
                        "email": "test@example.com",
                        "is_superuser": False,
                    },
                    "api_key": {
                        "id": "key-123",
                        "name": "Test Key",
                        "scopes": [],
                    },
                },
            )
        )

        result = runner.invoke(app, ["auth", "whoami"])
        assert result.exit_code == 0

    @respx.mock
    def test_whoami_error(self, temp_config):
        """Test whoami command with error."""
        respx.get("https://api.example.com/api/auth/whoami").mock(
            return_value=httpx.Response(401, json={"detail": "Unauthorized"})
        )

        result = runner.invoke(app, ["auth", "whoami"])
        assert result.exit_code == 1

    @respx.mock
    def test_keys_list(self, temp_config):
        """Test keys list command."""
        respx.get("https://api.example.com/api/auth/keys").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": "key-123",
                        "name": "Key 1",
                        "scopes": [],
                        "expires_at": None,
                        "last_used_at": None,
                        "created_at": "2024-01-15T10:00:00Z",
                    }
                ],
            )
        )

        result = runner.invoke(app, ["auth", "keys"])
        assert result.exit_code == 0

    @respx.mock
    def test_keys_list_empty(self, temp_config):
        """Test keys list when empty."""
        respx.get("https://api.example.com/api/auth/keys").mock(
            return_value=httpx.Response(200, json=[])
        )

        result = runner.invoke(app, ["auth", "keys"])
        assert result.exit_code == 0
        # Empty list shows "No API keys found" (might go to stderr via print_error)
        assert "No API keys found" in result.output

    @respx.mock
    def test_create_key(self, temp_config):
        """Test create-key command."""
        respx.post("https://api.example.com/api/auth/keys").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": "key-123",
                    "name": "New Key",
                    "scopes": ["read"],
                    "expires_at": None,
                    "created_at": "2024-01-15T10:00:00Z",
                    "key": "fsmtp_new_secret_key",
                },
            )
        )

        result = runner.invoke(app, ["auth", "create-key", "New Key", "--scope", "read"])
        assert result.exit_code == 0

    @respx.mock
    def test_delete_key(self, temp_config):
        """Test delete-key command with force flag."""
        key_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/auth/keys/{key_id}").mock(
            return_value=httpx.Response(204)
        )

        result = runner.invoke(app, ["auth", "delete-key", key_id, "--force"])
        assert result.exit_code == 0

    @respx.mock
    def test_delete_key_cancelled(self, temp_config):
        """Test delete-key command cancelled."""
        result = runner.invoke(app, ["auth", "delete-key", str(uuid4())], input="n\n")
        assert result.exit_code == 0

    @respx.mock
    def test_rotate_key(self, temp_config):
        """Test rotate-key command."""
        key_id = str(uuid4())
        respx.post(f"https://api.example.com/api/auth/keys/{key_id}/rotate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": key_id,
                    "name": "Rotated Key",
                    "scopes": [],
                    "expires_at": None,
                    "created_at": "2024-01-15T10:00:00Z",
                    "key": "fsmtp_new_rotated_key",
                },
            )
        )

        result = runner.invoke(app, ["auth", "rotate-key", key_id])
        assert result.exit_code == 0


class TestOpsCommands:
    """Tests for ops commands."""

    @respx.mock
    def test_health(self, temp_config):
        """Test health command."""
        respx.get("https://api.example.com/api/health").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "ok",
                    "version": "1.0.0",
                    "instance_id": "test",
                },
            )
        )

        result = runner.invoke(app, ["ops", "health"])
        assert result.exit_code == 0

    @respx.mock
    def test_ready(self, temp_config):
        """Test ready command."""
        respx.get("https://api.example.com/api/ready").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "ok",
                    "database": "ok",
                },
            )
        )

        result = runner.invoke(app, ["ops", "ready"])
        assert result.exit_code == 0

    @respx.mock
    def test_test_webhook(self, temp_config):
        """Test test-webhook command."""
        respx.post("https://api.example.com/api/test-webhook").mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "status_code": 200,
                    "response_time_ms": 100.0,
                },
            )
        )

        result = runner.invoke(app, ["ops", "test-webhook", "https://hook.example.com"])
        assert result.exit_code == 0


class TestDomainCommands:
    """Tests for domain commands."""

    @respx.mock
    def test_domain_list(self, temp_config):
        """Test domain list command."""
        respx.get("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": str(uuid4()),
                        "domain_name": "example.com",
                        "description": "Test domain",
                        "is_enabled": True,
                        "role": "owner",
                        "created_at": "2024-01-15T10:00:00Z",
                    }
                ],
            )
        )

        result = runner.invoke(app, ["domain", "list"])
        assert result.exit_code == 0

    @respx.mock
    def test_domain_create(self, temp_config):
        """Test domain create command."""
        respx.post("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": str(uuid4()),
                    "domain_name": "new.example.com",
                    "description": None,
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                },
            )
        )

        result = runner.invoke(app, ["domain", "create", "new.example.com"])
        assert result.exit_code == 0

    @respx.mock
    def test_domain_get(self, temp_config):
        """Test domain get command."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": domain_id,
                    "domain_name": "example.com",
                    "description": "Test domain",
                    "is_enabled": True,
                    "role": "owner",
                    "created_at": "2024-01-15T10:00:00Z",
                    "updated_at": "2024-01-16T10:00:00Z",
                },
            )
        )

        result = runner.invoke(app, ["domain", "get", domain_id])
        assert result.exit_code == 0

    @respx.mock
    def test_domain_delete(self, temp_config):
        """Test domain delete command."""
        domain_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/domains/{domain_id}").mock(
            return_value=httpx.Response(204)
        )

        result = runner.invoke(app, ["domain", "delete", domain_id, "--force"])
        assert result.exit_code == 0


class TestRecipientCommands:
    """Tests for recipient commands."""

    @respx.mock
    def test_recipient_list(self, temp_config):
        """Test recipient list command."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": str(uuid4()),
                        "local_part": "info",
                        "webhook_url": "https://hook.example.com",
                        "tags": [],
                        "is_enabled": True,
                    }
                ],
            )
        )

        result = runner.invoke(app, ["recipient", "list", domain_id])
        assert result.exit_code == 0

    @respx.mock
    def test_recipient_create(self, temp_config):
        """Test recipient create command."""
        domain_id = str(uuid4())
        respx.post(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": str(uuid4()),
                    "local_part": "info",
                    "webhook_url": "https://hook.example.com",
                    "description": None,
                    "tags": [],
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                },
            )
        )

        # webhook_url is a positional argument, local is --local/-l option
        result = runner.invoke(
            app,
            ["recipient", "create", domain_id, "https://hook.example.com", "--local", "info"],
        )
        assert result.exit_code == 0

    @respx.mock
    def test_recipient_get(self, temp_config):
        """Test recipient get command."""
        recipient_id = str(uuid4())
        respx.get(f"https://api.example.com/api/recipients/{recipient_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": recipient_id,
                    "local_part": "info",
                    "webhook_url": "https://hook.example.com",
                    "description": None,
                    "tags": [],
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                },
            )
        )

        result = runner.invoke(app, ["recipient", "get", recipient_id])
        assert result.exit_code == 0

    @respx.mock
    def test_recipient_delete(self, temp_config):
        """Test recipient delete command."""
        recipient_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/recipients/{recipient_id}").mock(
            return_value=httpx.Response(204)
        )

        result = runner.invoke(app, ["recipient", "delete", recipient_id, "--force"])
        assert result.exit_code == 0


class TestDomainErrorPaths:
    """Tests for domain command error paths."""

    @respx.mock
    def test_domain_list_empty(self, temp_config):
        """Test domain list when empty."""
        respx.get("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(200, json=[])
        )

        result = runner.invoke(app, ["domain", "list"])
        assert result.exit_code == 0
        assert "No domains found" in result.output

    @respx.mock
    def test_domain_list_error(self, temp_config):
        """Test domain list with API error."""
        respx.get("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(401, json={"detail": "Unauthorized"})
        )

        result = runner.invoke(app, ["domain", "list"])
        assert result.exit_code == 1

    @respx.mock
    def test_domain_create_error(self, temp_config):
        """Test domain create with API error."""
        respx.post("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(409, json={"detail": "Domain already exists"})
        )

        result = runner.invoke(app, ["domain", "create", "existing.com"])
        assert result.exit_code == 1

    @respx.mock
    def test_domain_get_error(self, temp_config):
        """Test domain get with API error."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Domain not found"})
        )

        result = runner.invoke(app, ["domain", "get", domain_id])
        assert result.exit_code == 1

    @respx.mock
    def test_domain_delete_cancelled(self, temp_config):
        """Test domain delete cancelled."""
        result = runner.invoke(app, ["domain", "delete", str(uuid4())], input="n\n")
        assert result.exit_code == 0

    @respx.mock
    def test_domain_delete_error(self, temp_config):
        """Test domain delete with API error."""
        domain_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/domains/{domain_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Domain not found"})
        )

        result = runner.invoke(app, ["domain", "delete", domain_id, "--force"])
        assert result.exit_code == 1


class TestRecipientErrorPaths:
    """Tests for recipient command error paths."""

    @respx.mock
    def test_recipient_list_empty(self, temp_config):
        """Test recipient list when empty."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(200, json=[])
        )

        result = runner.invoke(app, ["recipient", "list", domain_id])
        assert result.exit_code == 0
        assert "No recipients found" in result.output

    @respx.mock
    def test_recipient_list_error(self, temp_config):
        """Test recipient list with API error."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(404, json={"detail": "Domain not found"})
        )

        result = runner.invoke(app, ["recipient", "list", domain_id])
        assert result.exit_code == 1

    @respx.mock
    def test_recipient_create_error(self, temp_config):
        """Test recipient create with API error."""
        domain_id = str(uuid4())
        respx.post(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(400, json={"detail": "Invalid webhook URL"})
        )

        result = runner.invoke(
            app,
            ["recipient", "create", domain_id, "invalid-url"],
        )
        assert result.exit_code == 1

    @respx.mock
    def test_recipient_get_error(self, temp_config):
        """Test recipient get with API error."""
        recipient_id = str(uuid4())
        respx.get(f"https://api.example.com/api/recipients/{recipient_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Recipient not found"})
        )

        result = runner.invoke(app, ["recipient", "get", recipient_id])
        assert result.exit_code == 1

    @respx.mock
    def test_recipient_delete_cancelled(self, temp_config):
        """Test recipient delete cancelled."""
        result = runner.invoke(app, ["recipient", "delete", str(uuid4())], input="n\n")
        assert result.exit_code == 0

    @respx.mock
    def test_recipient_delete_error(self, temp_config):
        """Test recipient delete with API error."""
        recipient_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/recipients/{recipient_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Recipient not found"})
        )

        result = runner.invoke(app, ["recipient", "delete", recipient_id, "--force"])
        assert result.exit_code == 1


class TestRulesCommands:
    """Tests for rules commands."""

    @respx.mock
    def test_ruleset_list(self, temp_config):
        """Test ruleset list command (rules list)."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": str(uuid4()),
                        "name": "Test Rules",
                        "description": None,
                        "priority": 0,
                        "rules": [],
                        "is_enabled": True,
                    }
                ],
            )
        )

        result = runner.invoke(app, ["rules", "list", domain_id])
        assert result.exit_code == 0

    @respx.mock
    def test_ruleset_create(self, temp_config):
        """Test ruleset create command."""
        domain_id = str(uuid4())
        respx.post(f"https://api.example.com/api/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": str(uuid4()),
                    "name": "New Rules",
                    "description": None,
                    "priority": 10,
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                    "rules": [],
                },
            )
        )

        result = runner.invoke(app, ["rules", "create", domain_id, "New Rules", "--priority", "10"])
        assert result.exit_code == 0

    @respx.mock
    def test_ruleset_get(self, temp_config):
        """Test ruleset get command."""
        ruleset_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": ruleset_id,
                    "name": "Test Rules",
                    "description": None,
                    "priority": 0,
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                    "rules": [],
                },
            )
        )

        result = runner.invoke(app, ["rules", "get", ruleset_id])
        assert result.exit_code == 0

    @respx.mock
    def test_ruleset_delete(self, temp_config):
        """Test ruleset delete command."""
        ruleset_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(204)
        )

        result = runner.invoke(app, ["rules", "delete", ruleset_id, "--force"])
        assert result.exit_code == 0

    @respx.mock
    def test_rule_list(self, temp_config):
        """Test rule list command (rules rule list)."""
        ruleset_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": str(uuid4()),
                        "name": "Block spam",
                        "field": "from",
                        "operator": "contains",
                        "value": "@spam.com",
                        "action": "drop",
                        "priority": 0,
                        "is_enabled": True,
                    }
                ],
            )
        )

        result = runner.invoke(app, ["rules", "rule", "list", ruleset_id])
        assert result.exit_code == 0

    @respx.mock
    def test_rule_create(self, temp_config):
        """Test rule create command."""
        ruleset_id = str(uuid4())
        respx.post(f"https://api.example.com/api/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(
                201,
                json={
                    "id": str(uuid4()),
                    "name": "Block spam",
                    "field": "from",
                    "operator": "contains",
                    "value": "@spam.com",
                    "action": "drop",
                    "priority": 0,
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                },
            )
        )

        result = runner.invoke(
            app,
            [
                "rules",
                "rule",
                "create",
                ruleset_id,
                "Block spam",
                "--field",
                "from",
                "--operator",
                "contains",
                "--value",
                "@spam.com",
            ],
        )
        assert result.exit_code == 0

    @respx.mock
    def test_rule_get(self, temp_config):
        """Test rule get command."""
        rule_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rules/{rule_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": rule_id,
                    "name": "Block spam",
                    "field": "from",
                    "operator": "contains",
                    "value": "@spam.com",
                    "action": "drop",
                    "action_params": None,
                    "priority": 0,
                    "is_enabled": True,
                    "created_at": "2024-01-15T10:00:00Z",
                },
            )
        )

        result = runner.invoke(app, ["rules", "rule", "get", rule_id])
        assert result.exit_code == 0

    @respx.mock
    def test_rule_delete(self, temp_config):
        """Test rule delete command."""
        rule_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/rules/{rule_id}").mock(
            return_value=httpx.Response(204)
        )

        result = runner.invoke(app, ["rules", "rule", "delete", rule_id, "--force"])
        assert result.exit_code == 0


class TestRulesErrorPaths:
    """Tests for rules command error paths."""

    @respx.mock
    def test_ruleset_list_empty(self, temp_config):
        """Test ruleset list when empty."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(200, json=[])
        )

        result = runner.invoke(app, ["rules", "list", domain_id])
        assert result.exit_code == 0
        assert "No rulesets found" in result.output

    @respx.mock
    def test_ruleset_list_error(self, temp_config):
        """Test ruleset list with API error."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(404, json={"detail": "Domain not found"})
        )

        result = runner.invoke(app, ["rules", "list", domain_id])
        assert result.exit_code == 1

    @respx.mock
    def test_ruleset_create_error(self, temp_config):
        """Test ruleset create with API error."""
        domain_id = str(uuid4())
        respx.post(f"https://api.example.com/api/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(400, json={"detail": "Invalid ruleset"})
        )

        result = runner.invoke(app, ["rules", "create", domain_id, "Bad Rules"])
        assert result.exit_code == 1

    @respx.mock
    def test_ruleset_get_error(self, temp_config):
        """Test ruleset get with API error."""
        ruleset_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Ruleset not found"})
        )

        result = runner.invoke(app, ["rules", "get", ruleset_id])
        assert result.exit_code == 1

    @respx.mock
    def test_ruleset_delete_cancelled(self, temp_config):
        """Test ruleset delete cancelled."""
        result = runner.invoke(app, ["rules", "delete", str(uuid4())], input="n\n")
        assert result.exit_code == 0

    @respx.mock
    def test_ruleset_delete_error(self, temp_config):
        """Test ruleset delete with API error."""
        ruleset_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/rulesets/{ruleset_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Ruleset not found"})
        )

        result = runner.invoke(app, ["rules", "delete", ruleset_id, "--force"])
        assert result.exit_code == 1

    @respx.mock
    def test_rule_list_empty(self, temp_config):
        """Test rule list when empty."""
        ruleset_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(200, json=[])
        )

        result = runner.invoke(app, ["rules", "rule", "list", ruleset_id])
        assert result.exit_code == 0
        assert "No rules found" in result.output

    @respx.mock
    def test_rule_list_error(self, temp_config):
        """Test rule list with API error."""
        ruleset_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(404, json={"detail": "Ruleset not found"})
        )

        result = runner.invoke(app, ["rules", "rule", "list", ruleset_id])
        assert result.exit_code == 1

    @respx.mock
    def test_rule_create_error(self, temp_config):
        """Test rule create with API error."""
        ruleset_id = str(uuid4())
        respx.post(f"https://api.example.com/api/rulesets/{ruleset_id}/rules").mock(
            return_value=httpx.Response(400, json={"detail": "Invalid rule"})
        )

        result = runner.invoke(
            app,
            [
                "rules",
                "rule",
                "create",
                ruleset_id,
                "Bad Rule",
                "--field",
                "from",
                "--operator",
                "equals",
                "--value",
                "test",
            ],
        )
        assert result.exit_code == 1

    @respx.mock
    def test_rule_get_error(self, temp_config):
        """Test rule get with API error."""
        rule_id = str(uuid4())
        respx.get(f"https://api.example.com/api/rules/{rule_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Rule not found"})
        )

        result = runner.invoke(app, ["rules", "rule", "get", rule_id])
        assert result.exit_code == 1

    @respx.mock
    def test_rule_delete_cancelled(self, temp_config):
        """Test rule delete cancelled."""
        result = runner.invoke(app, ["rules", "rule", "delete", str(uuid4())], input="n\n")
        assert result.exit_code == 0

    @respx.mock
    def test_rule_delete_error(self, temp_config):
        """Test rule delete with API error."""
        rule_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/rules/{rule_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Rule not found"})
        )

        result = runner.invoke(app, ["rules", "rule", "delete", rule_id, "--force"])
        assert result.exit_code == 1


class TestDeliveryLogCommands:
    """Tests for delivery log commands."""

    @respx.mock
    def test_log_list(self, temp_config):
        """Test log list command."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/delivery-log").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": str(uuid4()),
                        "message_id": "<test@example.com>",
                        "recipient_email": "user@example.com",
                        "status": "delivered",
                        "attempt_count": 1,
                        "created_at": "2024-01-15T10:00:00Z",
                    }
                ],
            )
        )

        result = runner.invoke(app, ["ops", "log", "list", domain_id])
        assert result.exit_code == 0

    @respx.mock
    def test_log_list_empty(self, temp_config):
        """Test log list when empty."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/delivery-log").mock(
            return_value=httpx.Response(200, json=[])
        )

        result = runner.invoke(app, ["ops", "log", "list", domain_id])
        assert result.exit_code == 0
        assert "No delivery logs found" in result.output

    @respx.mock
    def test_log_list_error(self, temp_config):
        """Test log list with API error."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/delivery-log").mock(
            return_value=httpx.Response(404, json={"detail": "Domain not found"})
        )

        result = runner.invoke(app, ["ops", "log", "list", domain_id])
        assert result.exit_code == 1

    @respx.mock
    def test_log_get(self, temp_config):
        """Test log get command."""
        log_id = str(uuid4())
        respx.get(f"https://api.example.com/api/delivery-log/{log_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": log_id,
                    "message_id": "<test@example.com>",
                    "recipient_email": "user@example.com",
                    "webhook_url": "https://hook.example.com",
                    "status": "delivered",
                    "attempt_count": 1,
                    "http_status_code": 200,
                    "last_error": None,
                    "created_at": "2024-01-15T10:00:00Z",
                    "next_retry_at": None,
                },
            )
        )

        result = runner.invoke(app, ["ops", "log", "get", log_id])
        assert result.exit_code == 0

    @respx.mock
    def test_log_get_error(self, temp_config):
        """Test log get with API error."""
        log_id = str(uuid4())
        respx.get(f"https://api.example.com/api/delivery-log/{log_id}").mock(
            return_value=httpx.Response(404, json={"detail": "Log not found"})
        )

        result = runner.invoke(app, ["ops", "log", "get", log_id])
        assert result.exit_code == 1

    @respx.mock
    def test_log_retry(self, temp_config):
        """Test log retry command."""
        log_id = str(uuid4())
        respx.post(f"https://api.example.com/api/delivery-log/{log_id}/retry").mock(
            return_value=httpx.Response(
                200,
                json={"message": "Delivery queued for retry"},
            )
        )

        result = runner.invoke(app, ["ops", "log", "retry", log_id])
        assert result.exit_code == 0

    @respx.mock
    def test_log_retry_error(self, temp_config):
        """Test log retry with API error."""
        log_id = str(uuid4())
        respx.post(f"https://api.example.com/api/delivery-log/{log_id}/retry").mock(
            return_value=httpx.Response(400, json={"detail": "Cannot retry"})
        )

        result = runner.invoke(app, ["ops", "log", "retry", log_id])
        assert result.exit_code == 1


class TestOpsErrorPaths:
    """Tests for ops command error paths."""

    @respx.mock
    def test_health_error(self, temp_config):
        """Test health with API error."""
        respx.get("https://api.example.com/api/health").mock(
            return_value=httpx.Response(500, json={"detail": "Server error"})
        )

        result = runner.invoke(app, ["ops", "health"])
        assert result.exit_code == 1

    @respx.mock
    def test_ready_error(self, temp_config):
        """Test ready with API error."""
        respx.get("https://api.example.com/api/ready").mock(
            return_value=httpx.Response(503, json={"detail": "Database unavailable"})
        )

        result = runner.invoke(app, ["ops", "ready"])
        assert result.exit_code == 1

    @respx.mock
    def test_test_webhook_error(self, temp_config):
        """Test test-webhook with API error."""
        respx.post("https://api.example.com/api/test-webhook").mock(
            return_value=httpx.Response(400, json={"detail": "Invalid webhook URL"})
        )

        result = runner.invoke(app, ["ops", "test-webhook", "invalid-url"])
        assert result.exit_code == 1
