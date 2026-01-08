"""Tests for webhook URL validation (SSRF protection)."""

import pytest

from fastsmtp.webhook.url_validator import (
    SSRFError,
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
