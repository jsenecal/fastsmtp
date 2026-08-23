"""Tests for webhook URL validation (SSRF protection)."""

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import httpcore
import pytest
from fastsmtp.webhook.url_validator import (
    SSRFError,
    SSRFSafeAsyncConnectionPool,
    is_host_in_allowlist,
    is_ip_blocked,
    is_url_safe,
    validate_webhook_url,
)


class TestIsIpBlocked:
    """Tests for is_ip_blocked function."""

    def test_localhost_ipv4_blocked(self):
        """Test that localhost IPv4 is blocked."""
        assert is_ip_blocked("127.0.0.1") is True
        assert is_ip_blocked("127.0.0.255") is True
        assert is_ip_blocked("127.255.255.255") is True

    def test_localhost_ipv6_blocked(self):
        """Test that localhost IPv6 is blocked."""
        assert is_ip_blocked("::1") is True

    def test_private_class_a_blocked(self):
        """Test that 10.x.x.x range is blocked."""
        assert is_ip_blocked("10.0.0.1") is True
        assert is_ip_blocked("10.255.255.255") is True

    def test_private_class_b_blocked(self):
        """Test that 172.16-31.x.x range is blocked."""
        assert is_ip_blocked("172.16.0.1") is True
        assert is_ip_blocked("172.31.255.255") is True
        # 172.32.x.x is NOT private
        assert is_ip_blocked("172.32.0.1") is False

    def test_private_class_c_blocked(self):
        """Test that 192.168.x.x range is blocked."""
        assert is_ip_blocked("192.168.0.1") is True
        assert is_ip_blocked("192.168.255.255") is True

    def test_link_local_blocked(self):
        """Test that link-local addresses are blocked."""
        assert is_ip_blocked("169.254.0.1") is True
        assert is_ip_blocked("169.254.169.254") is True  # AWS metadata

    def test_public_ip_allowed(self):
        """Test that public IPs are allowed."""
        assert is_ip_blocked("8.8.8.8") is False
        assert is_ip_blocked("1.1.1.1") is False
        assert is_ip_blocked("93.184.216.34") is False  # example.com

    def test_invalid_ip_not_blocked(self):
        """Test that invalid IPs return False."""
        assert is_ip_blocked("not-an-ip") is False
        assert is_ip_blocked("") is False


class TestValidateWebhookUrl:
    """Tests for validate_webhook_url function."""

    def test_valid_https_url(self):
        """Test that valid HTTPS URLs pass validation."""
        # Should not raise
        validate_webhook_url("https://example.com/webhook", resolve_dns=False)
        validate_webhook_url("https://api.example.com:8080/hook", resolve_dns=False)

    def test_valid_http_url(self):
        """Test that valid HTTP URLs pass validation."""
        validate_webhook_url("http://example.com/webhook", resolve_dns=False)

    def test_invalid_scheme_rejected(self):
        """Test that non-HTTP(S) schemes are rejected."""
        with pytest.raises(SSRFError, match="scheme must be http or https"):
            validate_webhook_url("ftp://example.com/file")

        with pytest.raises(SSRFError, match="scheme must be http or https"):
            validate_webhook_url("file:///etc/passwd")

    def test_localhost_blocked(self):
        """Test that localhost is blocked."""
        with pytest.raises(SSRFError, match="blocked"):
            validate_webhook_url("http://localhost/webhook", resolve_dns=False)

        with pytest.raises(SSRFError, match="blocked"):
            validate_webhook_url("http://localhost.localdomain/webhook", resolve_dns=False)

    def test_localhost_ip_blocked(self):
        """Test that localhost IP is blocked."""
        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://127.0.0.1/webhook", resolve_dns=False)

        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://127.0.0.1:8080/webhook", resolve_dns=False)

    def test_private_ip_blocked(self):
        """Test that private IPs are blocked."""
        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://10.0.0.1/webhook", resolve_dns=False)

        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://192.168.1.1/webhook", resolve_dns=False)

        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://172.16.0.1/webhook", resolve_dns=False)

    def test_metadata_ip_blocked(self):
        """Test that cloud metadata IP is blocked."""
        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)

    def test_metadata_hostname_blocked(self):
        """Test that metadata hostnames are blocked."""
        with pytest.raises(SSRFError, match="blocked"):
            validate_webhook_url("http://metadata.google.internal/", resolve_dns=False)

    def test_missing_hostname_rejected(self):
        """Test that URLs without hostname are rejected."""
        with pytest.raises(SSRFError, match="must have a hostname"):
            validate_webhook_url("http:///path")

    def test_public_ip_allowed(self):
        """Test that public IPs are allowed."""
        validate_webhook_url("http://93.184.216.34/webhook", resolve_dns=False)

    def test_ipv6_localhost_blocked(self):
        """Test that IPv6 localhost is blocked."""
        with pytest.raises(SSRFError, match="blocked range"):
            validate_webhook_url("http://[::1]/webhook", resolve_dns=False)


class TestAllowedInternalDomains:
    """Tests for the allowed_internal_domains bypass."""

    def test_exact_match_bypasses_dns_block(self):
        """An allowlisted hostname resolving to a private IP is permitted."""

        def fake_getaddrinfo(host, port, **kwargs):
            return [(2, 1, 6, "", ("10.6.8.8", port))]

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            # Without allowlist: blocked
            with pytest.raises(SSRFError, match="blocked IP"):
                validate_webhook_url("https://n8n.internal.example.com/hook")
            # With allowlist: permitted
            validate_webhook_url(
                "https://n8n.internal.example.com/hook",
                allowed_internal_domains=["n8n.internal.example.com"],
            )

    def test_subdomain_match_bypasses_dns_block(self):
        """A host that is a subdomain of an allowed entry is permitted."""

        def fake_getaddrinfo(host, port, **kwargs):
            return [(2, 1, 6, "", ("10.0.0.5", port))]

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            validate_webhook_url(
                "https://api.internal.example/hook",
                allowed_internal_domains=["internal.example"],
            )

    def test_match_is_case_insensitive(self):
        """Allowlist matching ignores case on both sides."""

        def fake_getaddrinfo(host, port, **kwargs):
            return [(2, 1, 6, "", ("10.0.0.5", port))]

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            validate_webhook_url(
                "https://N8N.Internal.Example.COM/hook",
                allowed_internal_domains=["n8n.internal.example.com"],
            )

    def test_partial_suffix_does_not_match(self):
        """A hostname that merely shares a suffix substring is not allowed."""
        assert is_host_in_allowlist("evilexample.com", ["example.com"]) is False
        assert is_host_in_allowlist("example.com.evil", ["example.com"]) is False

    def test_blocked_hostname_still_blocked_when_not_allowlisted(self):
        """Allowlist does not match, so a blocked literal hostname is still blocked."""
        with pytest.raises(SSRFError, match="blocked"):
            validate_webhook_url(
                "http://localhost/hook",
                resolve_dns=False,
                allowed_internal_domains=["other.example"],
            )

    def test_allowlisted_localhost_is_permitted(self):
        """An explicitly allowlisted hostname bypasses the BLOCKED_HOSTNAMES set."""
        # Skip DNS resolution by using a hostname that will be allowlisted before
        # the IP lookup runs.
        validate_webhook_url(
            "http://localhost/hook",
            resolve_dns=False,
            allowed_internal_domains=["localhost"],
        )

    def test_cluster_local_hostname_via_settings_env(self, monkeypatch):
        """A k8s service hostname is permitted only when allowlisted via env settings."""
        from fastsmtp.config import Settings

        def fake_getaddrinfo(host, port, **kwargs):
            return [(2, 1, 6, "", ("10.43.0.15", port))]

        url = "http://myapp-api.myns.svc.cluster.local:8000/x"

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            # Empty allowlist (default): refused
            monkeypatch.delenv("FASTSMTP_WEBHOOK_ALLOWED_INTERNAL_DOMAINS", raising=False)
            settings = Settings(root_api_key="test_key_12345", secret_key="test-secret")
            assert settings.webhook_allowed_internal_domains == []
            with pytest.raises(SSRFError, match="blocked IP"):
                validate_webhook_url(
                    url,
                    allowed_internal_domains=settings.webhook_allowed_internal_domains,
                )

            # Allowlisted via env var: permitted
            monkeypatch.setenv(
                "FASTSMTP_WEBHOOK_ALLOWED_INTERNAL_DOMAINS",
                '["myapp-api.myns.svc.cluster.local"]',
            )
            settings = Settings(root_api_key="test_key_12345", secret_key="test-secret")
            assert settings.webhook_allowed_internal_domains == ["myapp-api.myns.svc.cluster.local"]
            validate_webhook_url(
                url,
                allowed_internal_domains=settings.webhook_allowed_internal_domains,
            )

    def test_is_url_safe_threads_allowlist(self):
        """is_url_safe forwards the allowlist to validate_webhook_url."""

        def fake_getaddrinfo(host, port, **kwargs):
            return [(2, 1, 6, "", ("10.6.8.8", port))]

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            ok, err = is_url_safe(
                "https://n8n.internal.example.com/hook",
                allowed_internal_domains=["n8n.internal.example.com"],
            )
            assert ok is True
            assert err is None

    def test_entry_with_leading_dot_matches(self):
        """Entries written with a leading dot (".example.com") are accepted."""
        assert is_host_in_allowlist("api.example.com", [".example.com"]) is True
        assert is_host_in_allowlist("example.com", [".example.com"]) is True

    def test_entry_with_whitespace_matches(self):
        """Entries with surrounding whitespace are tolerated."""
        assert is_host_in_allowlist("api.example.com", ["  example.com  "]) is True
        assert is_host_in_allowlist("example.com", ["\texample.com\n"]) is True

    def test_empty_or_whitespace_only_entry_does_not_match(self):
        """Empty or whitespace-only entries do not silently match every host."""
        assert is_host_in_allowlist("anything.com", [""]) is False
        assert is_host_in_allowlist("anything.com", ["   "]) is False
        assert is_host_in_allowlist("anything.com", ["."]) is False


class TestIsUrlSafe:
    """Tests for is_url_safe helper function."""

    def test_safe_url_returns_true(self):
        """Test that safe URLs return (True, None)."""
        is_safe, error = is_url_safe("https://example.com/hook", resolve_dns=False)
        assert is_safe is True
        assert error is None

    def test_unsafe_url_returns_false_with_error(self):
        """Test that unsafe URLs return (False, error_message)."""
        is_safe, error = is_url_safe("http://127.0.0.1/hook", resolve_dns=False)
        assert is_safe is False
        assert error is not None
        assert "blocked" in error.lower()

    def test_invalid_url_returns_false_with_error(self):
        """Test that invalid URLs return (False, error_message)."""
        is_safe, error = is_url_safe("not-a-url", resolve_dns=False)
        assert is_safe is False
        assert error is not None


class TestSSRFSafeAsyncConnectionPool:
    """Tests for the connect-time (DNS-rebinding) half of SSRF protection."""

    @staticmethod
    def _request(url: str) -> httpcore.Request:
        return httpcore.Request("POST", url)

    @pytest.mark.asyncio
    async def test_blocked_hostname_rejected(self):
        """A blocked hostname is refused before the connection is made."""
        pool = SSRFSafeAsyncConnectionPool()
        with pytest.raises(SSRFError) as exc_info:
            await pool.handle_async_request(self._request("http://localhost/hook"))
        # httpcore stores the host as bytes; the message must not read b'localhost'.
        assert str(exc_info.value) == "Hostname 'localhost' is blocked"

    @pytest.mark.asyncio
    async def test_blocked_ip_literal_rejected(self):
        """An IP literal in a blocked range is refused, rendered as text."""
        pool = SSRFSafeAsyncConnectionPool()
        with pytest.raises(SSRFError) as exc_info:
            await pool.handle_async_request(self._request("http://169.254.169.254/latest"))
        assert str(exc_info.value) == "IP address '169.254.169.254' is in a blocked range"

    @pytest.mark.asyncio
    async def test_resolved_blocked_ip_rejected(self):
        """A hostname resolving to a blocked IP is refused, rendered as text."""
        pool = SSRFSafeAsyncConnectionPool()

        async def fake_getaddrinfo(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

        with (
            patch.object(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo),
            pytest.raises(SSRFError) as exc_info,
        ):
            await pool.handle_async_request(self._request("http://rebind.example.com/hook"))
        assert str(exc_info.value) == (
            "Hostname 'rebind.example.com' resolves to blocked IP '127.0.0.1'"
        )

    @pytest.mark.asyncio
    async def test_empty_host_rejected(self):
        """A request with no host is refused rather than reaching the socket."""
        pool = SSRFSafeAsyncConnectionPool()
        request = httpcore.Request("POST", httpcore.URL(scheme=b"http", host=b"", target=b"/hook"))
        with pytest.raises(SSRFError, match="Request has no host"):
            await pool.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_allowlisted_host_bypasses_checks(self):
        """An allowlisted internal domain skips the blocklist and reaches the pool."""
        pool = SSRFSafeAsyncConnectionPool(allowed_internal_domains=["internal.test"])
        sentinel = object()

        with patch.object(
            httpcore.AsyncConnectionPool,
            "handle_async_request",
            new=AsyncMock(return_value=sentinel),
        ) as mock_super:
            result = await pool.handle_async_request(self._request("http://internal.test/hook"))

        assert result is sentinel
        # The allowlist check must run on decoded text, not on b'internal.test'.
        assert mock_super.await_count == 1
