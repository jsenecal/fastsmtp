"""Shared IP address and network helpers.

Several parts of the application match an address against a list of networks:
SSRF protection blocks webhook targets in private ranges, and the metrics
endpoint restricts scraping to an operator-supplied allowlist. They share these
helpers so the parsing and matching rules stay identical.
"""

import ipaddress
from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(entries: Iterable[str] | None) -> list[IPNetwork]:
    """Parse IP addresses and CIDR prefixes into networks.

    A bare address is treated as a single-host network, so callers can accept
    ``10.0.0.0/8`` and ``192.0.2.5`` in the same setting.

    Args:
        entries: Addresses or prefixes, in either address family

    Returns:
        The parsed networks, in the order given

    Raises:
        ValueError: If an entry is not a valid address or prefix. Malformed
            entries are rejected rather than skipped: silently dropping a typo
            would leave an allowlist wider than the operator believes.
    """
    networks: list[IPNetwork] = []
    for entry in entries or []:
        try:
            networks.append(ipaddress.ip_network(entry, strict=True))
        except ValueError as e:
            raise ValueError(f"Invalid IP address or CIDR prefix {entry!r}: {e}") from e
    return networks


def ip_in_networks(ip_str: str, networks: Iterable[IPNetwork]) -> bool:
    """Check whether an address falls inside any of the given networks.

    Args:
        ip_str: Address to test
        networks: Networks to test against

    Returns:
        True if the address is a member of any network. IPv4-mapped IPv6
        addresses are compared as their IPv4 form. An address that cannot be
        parsed is not a member; matching happens on a request path, so an
        unusable peer address must not raise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # A dual-stack socket reports IPv4 peers as ::ffff:10.1.2.3. Without
    # unwrapping those, an IPv4 entry would never match a real IPv4 client.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return any(ip in network for network in networks)
