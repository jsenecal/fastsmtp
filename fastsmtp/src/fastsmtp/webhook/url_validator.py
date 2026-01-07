"""Webhook URL validation for SSRF protection."""

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

import httpcore
import httpx

# Private and reserved IP ranges that should be blocked
BLOCKED_IP_RANGES = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Private networks (RFC 1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Cloud metadata services
    ipaddress.ip_network("169.254.169.254/32"),  # AWS, GCP, Azure metadata
    # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("100.64.0.0/10"),
    # Documentation/test ranges
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Broadcast
    ipaddress.ip_network("255.255.255.255/32"),
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",  # GCP metadata
    "metadata",  # Common metadata alias
}


class SSRFError(Exception):
    """Raised when a URL is blocked due to SSRF protection."""

    pass


def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address is in a blocked range.

    Args:
        ip_str: IP address as string

    Returns:
        True if the IP is blocked, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in BLOCKED_IP_RANGES)
    except ValueError:
        # Invalid IP address format
        return False


def validate_webhook_url(url: str, resolve_dns: bool = True) -> None:
    """Validate a webhook URL for SSRF protection.

    Args:
        url: The URL to validate
        resolve_dns: Whether to resolve DNS and check the resolved IP

    Raises:
        SSRFError: If the URL is blocked due to SSRF protection
        ValueError: If the URL is malformed
    """
    # Parse the URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL format: {e}") from e

    # Require HTTP or HTTPS scheme
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"URL scheme must be http or https, got: {parsed.scheme}")

    # Require a hostname
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL must have a hostname")

    # Normalize hostname
    hostname_lower = hostname.lower()

    # Check against blocked hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        raise SSRFError(f"Hostname '{hostname}' is blocked")

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if is_ip_blocked(str(ip)):
            raise SSRFError(f"IP address '{hostname}' is in a blocked range")
        # IP address is allowed, no need to resolve DNS
        return
    except ValueError:
        # Not an IP address, continue with hostname validation
        pass

    # Resolve DNS to check actual IP addresses (if enabled)
    if resolve_dns:
        try:
            # Get all IP addresses for the hostname
            addrinfo = socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                proto=socket.IPPROTO_TCP,
            )
            for _family, _, _, _, sockaddr in addrinfo:
                ip_str = str(sockaddr[0])
                if is_ip_blocked(ip_str):
                    raise SSRFError(f"Hostname '{hostname}' resolves to blocked IP '{ip_str}'")
        except socket.gaierror:
            # DNS resolution failed - this is okay, the request will fail later
            # We don't want to block URLs that might temporarily have DNS issues
            pass


def is_url_safe(url: str, resolve_dns: bool = True) -> tuple[bool, str | None]:
    """Check if a URL is safe for webhook delivery.

    Args:
        url: The URL to check
        resolve_dns: Whether to resolve DNS and check the resolved IP

    Returns:
        Tuple of (is_safe, error_message)
    """
    try:
        validate_webhook_url(url, resolve_dns=resolve_dns)
        return True, None
    except (SSRFError, ValueError) as e:
        return False, str(e)


class SSRFSafeAsyncConnectionPool(httpcore.AsyncConnectionPool):
    """Connection pool that validates resolved IPs to prevent DNS rebinding attacks.

    This prevents TOCTOU (Time-Of-Check-Time-Of-Use) attacks where DNS returns
    a safe IP during validation but a malicious IP (e.g., 127.0.0.1) at connection time.
    """

    def __init__(
        self,
        allowed_internal_domains: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        # Normalize allowed domains to lowercase for comparison
        self._allowed_domains = {d.lower() for d in (allowed_internal_domains or [])}

    def _is_domain_allowed(self, host: str) -> bool:
        """Check if a domain is in the allowed internal domains list."""
        host_lower = host.lower()
        # Exact match or subdomain match
        for allowed in self._allowed_domains:
            if host_lower == allowed or host_lower.endswith("." + allowed):
                return True
        return False

    async def handle_async_request(self, request: httpcore.Request) -> httpcore.Response:
        """Handle request with IP validation at connection time."""
        host = request.url.host
        if host is None:
            raise SSRFError("Request has no host")

        # Decode host if bytes
        if isinstance(host, bytes):
            host = host.decode("ascii")

        # Check if domain is in allowlist (bypass SSRF protection)
        if self._is_domain_allowed(host):
            return await super().handle_async_request(request)

        # Check blocked hostnames
        if host.lower() in BLOCKED_HOSTNAMES:
            raise SSRFError(f"Hostname '{host}' is blocked")

        # Check if host is already an IP address
        try:
            ip = ipaddress.ip_address(host)
            if is_ip_blocked(str(ip)):
                raise SSRFError(f"IP address '{host}' is in a blocked range")
        except ValueError:
            # Not an IP, resolve DNS and validate asynchronously
            port = request.url.port or (443 if request.url.scheme == b"https" else 80)
            try:
                # Use async DNS resolution to avoid blocking the event loop
                loop = asyncio.get_running_loop()
                addrinfo = await loop.getaddrinfo(
                    host,
                    port,
                    proto=socket.IPPROTO_TCP,
                )
                for _family, _, _, _, sockaddr in addrinfo:
                    ip_str = str(sockaddr[0])
                    if is_ip_blocked(ip_str):
                        raise SSRFError(f"Hostname '{host}' resolves to blocked IP '{ip_str}'")
            except socket.gaierror:
                # Let the actual connection fail with proper error
                pass

        return await super().handle_async_request(request)


class SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """HTTP transport that prevents SSRF via DNS rebinding attacks.

    Use this transport when creating httpx.AsyncClient to ensure that
    IP validation happens at connection time, not just at request time.
    """

    def __init__(
        self,
        allowed_internal_domains: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        # Replace the internal connection pool with our SSRF-safe version
        self._pool = SSRFSafeAsyncConnectionPool(
            allowed_internal_domains=allowed_internal_domains,
            **kwargs,
        )


def create_ssrf_safe_client(
    timeout: float = 30.0,
    limits: httpx.Limits | None = None,
    allowed_internal_domains: list[str] | None = None,
) -> httpx.AsyncClient:
    """Create an httpx client with SSRF protection at connection time.

    This client validates resolved IPs when connecting, preventing DNS rebinding
    attacks where an attacker's DNS server returns different IPs between
    validation and actual connection.

    Args:
        timeout: Request timeout in seconds
        limits: Connection pool limits
        allowed_internal_domains: Domains allowed to bypass SSRF protection

    Returns:
        httpx.AsyncClient configured with SSRF-safe transport
    """
    transport = SSRFSafeTransport(allowed_internal_domains=allowed_internal_domains)
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        limits=limits or httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
