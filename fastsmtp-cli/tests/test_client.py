"""Tests for FastSMTP API client."""

import tempfile
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import respx
from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.config import Profile


@pytest.fixture
def temp_config(monkeypatch):
    """Create a temporary config directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.toml"
        monkeypatch.setenv("FSMTP_CONFIG", str(config_path))
        yield config_path


@pytest.fixture
def test_profile():
    """Create a test profile."""
    return Profile(
        url="https://api.example.com",
        api_key="test_api_key_12345",
        timeout=10.0,
        verify_ssl=True,
    )


class TestAPIError:
    """Tests for APIError exception."""

    def test_api_error_attributes(self):
        """Test APIError stores status code and detail."""
        error = APIError(404, "Not found")
        assert error.status_code == 404
        assert error.detail == "Not found"

    def test_api_error_message(self):
        """Test APIError string representation."""
        error = APIError(500, "Internal server error")
        assert "500" in str(error)
        assert "Internal server error" in str(error)


class TestFastSMTPClient:
    """Tests for FastSMTPClient."""

    def test_client_init_with_profile(self, test_profile):
        """Test client initialization with profile."""
        client = FastSMTPClient(profile=test_profile)
        assert client.profile == test_profile

    def test_client_init_with_profile_name(self, temp_config, monkeypatch):
        """Test client initialization with profile name."""
        from fastsmtp_cli.config import set_profile

        set_profile("test", url="https://test.example.com")

        client = FastSMTPClient(profile_name="test")
        assert client.profile.url == "https://test.example.com"

    def test_client_context_manager(self, test_profile):
        """Test client as context manager."""
        with FastSMTPClient(profile=test_profile) as client:
            assert client._client is None  # Not created until first request
        assert client._client is None  # Closed after exiting

    @respx.mock
    def test_client_get_request(self, test_profile):
        """Test GET request."""
        respx.get("https://api.example.com/api/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )

        with FastSMTPClient(profile=test_profile) as client:
            result = client.get("/api/health")
            assert result == {"status": "ok"}

    @respx.mock
    def test_client_post_request(self, test_profile):
        """Test POST request."""
        respx.post("https://api.example.com/api/test").mock(
            return_value=httpx.Response(201, json={"id": "123"})
        )

        with FastSMTPClient(profile=test_profile) as client:
            result = client.post("/api/test", json={"name": "test"})
            assert result == {"id": "123"}

    @respx.mock
    def test_client_put_request(self, test_profile):
        """Test PUT request."""
        respx.put("https://api.example.com/api/test/123").mock(
            return_value=httpx.Response(200, json={"updated": True})
        )

        with FastSMTPClient(profile=test_profile) as client:
            result = client.put("/api/test/123", json={"name": "updated"})
            assert result == {"updated": True}

    @respx.mock
    def test_client_patch_request(self, test_profile):
        """Test PATCH request."""
        respx.patch("https://api.example.com/api/test/123").mock(
            return_value=httpx.Response(200, json={"patched": True})
        )

        with FastSMTPClient(profile=test_profile) as client:
            result = client.patch("/api/test/123", json={"field": "value"})
            assert result == {"patched": True}

    @respx.mock
    def test_client_delete_request(self, test_profile):
        """Test DELETE request."""
        respx.delete("https://api.example.com/api/test/123").mock(return_value=httpx.Response(204))

        with FastSMTPClient(profile=test_profile) as client:
            result = client.delete("/api/test/123")
            assert result is None

    @respx.mock
    def test_client_error_response(self, test_profile):
        """Test handling of error responses."""
        respx.get("https://api.example.com/api/fail").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with FastSMTPClient(profile=test_profile) as client:
            with pytest.raises(APIError) as exc_info:
                client.get("/api/fail")
            assert exc_info.value.status_code == 404
            assert exc_info.value.detail == "Not found"

    @respx.mock
    def test_client_error_response_no_json(self, test_profile):
        """Test handling of error responses without JSON body."""
        respx.get("https://api.example.com/api/fail").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        with FastSMTPClient(profile=test_profile) as client:
            with pytest.raises(APIError) as exc_info:
                client.get("/api/fail")
            assert exc_info.value.status_code == 500
            assert "Internal Server Error" in exc_info.value.detail

    @respx.mock
    def test_client_authorization_header(self, test_profile):
        """Test that authorization header is set."""
        route = respx.get("https://api.example.com/api/test").mock(
            return_value=httpx.Response(200, json={})
        )

        with FastSMTPClient(profile=test_profile) as client:
            client.get("/api/test")

        assert route.calls[0].request.headers["Authorization"] == "Bearer test_api_key_12345"

    @respx.mock
    def test_client_no_auth_header_without_key(self, temp_config):
        """Test that no auth header is set when no API key."""
        profile = Profile(url="https://api.example.com")
        route = respx.get("https://api.example.com/api/test").mock(
            return_value=httpx.Response(200, json={})
        )

        with FastSMTPClient(profile=profile) as client:
            client.get("/api/test")

        assert "Authorization" not in route.calls[0].request.headers


class TestClientEndpoints:
    """Tests for API client endpoint methods."""

    @pytest.fixture
    def mock_client(self, test_profile):
        """Create a client for testing."""
        return FastSMTPClient(profile=test_profile)

    @respx.mock
    def test_health_endpoint(self, mock_client):
        """Test health endpoint."""
        respx.get("https://api.example.com/api/health").mock(
            return_value=httpx.Response(200, json={"status": "ok", "version": "1.0"})
        )

        with mock_client as client:
            result = client.health()
            assert result["status"] == "ok"

    @respx.mock
    def test_ready_endpoint(self, mock_client):
        """Test ready endpoint."""
        respx.get("https://api.example.com/api/ready").mock(
            return_value=httpx.Response(200, json={"status": "ok", "database": "ok"})
        )

        with mock_client as client:
            result = client.ready()
            assert result["status"] == "ok"

    @respx.mock
    def test_whoami_endpoint(self, mock_client):
        """Test whoami endpoint."""
        respx.get("https://api.example.com/api/auth/whoami").mock(
            return_value=httpx.Response(200, json={"user": {"id": "123"}})
        )

        with mock_client as client:
            result = client.whoami()
            assert result["user"]["id"] == "123"

    @respx.mock
    def test_list_api_keys_endpoint(self, mock_client):
        """Test list API keys endpoint."""
        respx.get("https://api.example.com/api/auth/keys").mock(
            return_value=httpx.Response(200, json=[{"id": "123", "name": "key1"}])
        )

        with mock_client as client:
            result = client.list_api_keys()
            assert len(result) == 1
            assert result[0]["name"] == "key1"

    @respx.mock
    def test_create_api_key_endpoint(self, mock_client):
        """Test create API key endpoint."""
        respx.post("https://api.example.com/api/auth/keys").mock(
            return_value=httpx.Response(201, json={"id": "123", "name": "new-key", "key": "secret"})
        )

        with mock_client as client:
            result = client.create_api_key("new-key", scopes=["read"], expires_days=30)
            assert result["name"] == "new-key"

    @respx.mock
    def test_delete_api_key_endpoint(self, mock_client):
        """Test delete API key endpoint."""
        key_id = str(uuid4())
        respx.delete(f"https://api.example.com/api/auth/keys/{key_id}").mock(
            return_value=httpx.Response(204)
        )

        with mock_client as client:
            client.delete_api_key(key_id)

    @respx.mock
    def test_list_domains_endpoint(self, mock_client):
        """Test list domains endpoint."""
        respx.get("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(200, json=[{"id": "123", "domain_name": "example.com"}])
        )

        with mock_client as client:
            result = client.list_domains()
            assert len(result) == 1
            assert result[0]["domain_name"] == "example.com"

    @respx.mock
    def test_create_domain_endpoint(self, mock_client):
        """Test create domain endpoint."""
        respx.post("https://api.example.com/api/domains").mock(
            return_value=httpx.Response(201, json={"id": "123", "domain_name": "new.example.com"})
        )

        with mock_client as client:
            result = client.create_domain("new.example.com", description="Test domain")
            assert result["domain_name"] == "new.example.com"

    @respx.mock
    def test_list_recipients_endpoint(self, mock_client):
        """Test list recipients endpoint."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(200, json=[{"id": "r1", "local_part": "info"}])
        )

        with mock_client as client:
            result = client.list_recipients(domain_id)
            assert len(result) == 1
            assert result[0]["local_part"] == "info"

    @respx.mock
    def test_create_recipient_endpoint(self, mock_client):
        """Test create recipient endpoint."""
        domain_id = str(uuid4())
        respx.post(f"https://api.example.com/api/domains/{domain_id}/recipients").mock(
            return_value=httpx.Response(
                201, json={"id": "r1", "webhook_url": "https://hook.example.com"}
            )
        )

        with mock_client as client:
            result = client.create_recipient(
                domain_id,
                webhook_url="https://hook.example.com",
                local_part="info",
                tags=["important"],
            )
            assert result["webhook_url"] == "https://hook.example.com"

    @respx.mock
    def test_list_rulesets_endpoint(self, mock_client):
        """Test list rulesets endpoint."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/rulesets").mock(
            return_value=httpx.Response(200, json=[{"id": "rs1", "name": "Test Rules"}])
        )

        with mock_client as client:
            result = client.list_rulesets(domain_id)
            assert len(result) == 1
            assert result[0]["name"] == "Test Rules"

    @respx.mock
    def test_test_webhook_endpoint(self, mock_client):
        """Test test webhook endpoint."""
        respx.post("https://api.example.com/api/test-webhook").mock(
            return_value=httpx.Response(200, json={"success": True, "status_code": 200})
        )

        with mock_client as client:
            result = client.test_webhook(
                webhook_url="https://hook.example.com",
                from_address="test@example.com",
                to_address="user@example.com",
                subject="Test",
                body="Test body",
            )
            assert result["success"] is True

    @respx.mock
    def test_list_delivery_logs_endpoint(self, mock_client):
        """Test list delivery logs endpoint."""
        domain_id = str(uuid4())
        respx.get(f"https://api.example.com/api/domains/{domain_id}/delivery-log").mock(
            return_value=httpx.Response(200, json=[{"id": "log1", "status": "delivered"}])
        )

        with mock_client as client:
            result = client.list_delivery_logs(domain_id, status="delivered")
            assert len(result) == 1
            assert result[0]["status"] == "delivered"
