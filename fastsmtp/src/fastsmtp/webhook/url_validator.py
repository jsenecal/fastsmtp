"""Webhook URL validation for SSRF protection."""

import ipaddress
import socket
from urllib.parse import urlparse

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
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return True
        return False
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
            for family, _, _, _, sockaddr in addrinfo:
                ip_str = sockaddr[0]
                if is_ip_blocked(ip_str):
                    raise SSRFError(
                        f"Hostname '{hostname}' resolves to blocked IP '{ip_str}'"
                    )
        except socket.gaierror as e:
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
