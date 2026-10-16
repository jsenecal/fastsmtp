"""Shared IP address and network helpers.

Several parts of the application match an address against a list of networks:
SSRF protection blocks webhook targets in private ranges, and the metrics
endpoint restricts scraping to an operator-supplied allowlist. They share these
helpers so the parsing and matching rules stay identical.
"""

import ipaddress
from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _unmapped(ip: IPAddress) -> IPAddress:
    # A dual-stack socket reports IPv4 peers as ::ffff:10.1.2.3.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def unmap_ipv4(ip_str: str) -> str:
    """Return an IPv4-mapped IPv6 address in its IPv4 form.

    A listener bound dual-stack (see ``bind_dualstack``) reports IPv4 peers as
    ``::ffff:a.b.c.d``. Anything else, including a value that is not an
    address at all, is returned unchanged.
    """
    try:
        return str(_unmapped(ipaddress.ip_address(ip_str)))
    except ValueError:
        return ip_str


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

    # Without unwrapping IPv4-mapped peers, an IPv4 entry would never match a
    # real IPv4 client on a dual-stack socket.
    ip = _unmapped(ip)
    return any(ip in network for network in networks)
