"""Tests for shared IP address and network helpers."""

import pytest
from fastsmtp.net import ip_in_networks, parse_networks


class TestParseNetworks:
    """Tests for parsing IP/CIDR entries into networks."""

    def test_parses_cidr_prefix(self):
        """Test a CIDR prefix is parsed as a network."""
        networks = parse_networks(["10.0.0.0/8"])
        assert len(networks) == 1
        assert str(networks[0]) == "10.0.0.0/8"

    def test_parses_bare_ipv4_as_single_host(self):
        """Test a bare address becomes a single-host network."""
        networks = parse_networks(["192.0.2.5"])
        assert str(networks[0]) == "192.0.2.5/32"

    def test_parses_bare_ipv6_as_single_host(self):
        """Test a bare IPv6 address becomes a single-host network."""
        networks = parse_networks(["2001:db8::1"])
        assert str(networks[0]) == "2001:db8::1/128"

    def test_parses_ipv6_prefix(self):
        """Test an IPv6 prefix is parsed as a network."""
        networks = parse_networks(["2001:db8::/32"])
        assert str(networks[0]) == "2001:db8::/32"

    def test_parses_mixed_entries(self):
        """Test a list may mix bare addresses and prefixes."""
        assert len(parse_networks(["10.0.0.0/8", "192.0.2.5", "2001:db8::/32"])) == 3

    def test_empty_list_yields_no_networks(self):
        """Test an empty list parses to no networks."""
        assert parse_networks([]) == []

    def test_none_yields_no_networks(self):
        """Test None parses to no networks."""
        assert parse_networks(None) == []

    def test_rejects_malformed_entry(self):
        """Test a malformed entry raises rather than being skipped.

        Silently dropping a typo would fail open, leaving an allowlist wider
        than the operator believes it to be.
        """
        with pytest.raises(ValueError, match="not-an-ip"):
            parse_networks(["10.0.0.0/8", "not-an-ip"])

    def test_rejects_host_bits_set(self):
        """Test a prefix with host bits set is reported clearly."""
        with pytest.raises(ValueError, match="10.1.2.3/8"):
            parse_networks(["10.1.2.3/8"])


class TestIpInNetworks:
    """Tests for membership checks."""

    def test_matches_address_inside_prefix(self):
        """Test an address inside a prefix matches."""
        assert ip_in_networks("10.1.2.3", parse_networks(["10.0.0.0/8"])) is True

    def test_rejects_address_outside_prefix(self):
        """Test an address outside every prefix does not match."""
        assert ip_in_networks("192.0.2.1", parse_networks(["10.0.0.0/8"])) is False

    def test_matches_exact_host_entry(self):
        """Test a bare host entry matches only that address."""
        networks = parse_networks(["192.0.2.5"])
        assert ip_in_networks("192.0.2.5", networks) is True
        assert ip_in_networks("192.0.2.6", networks) is False

    def test_matches_ipv6(self):
        """Test IPv6 membership works."""
        assert ip_in_networks("2001:db8::1", parse_networks(["2001:db8::/32"])) is True

    def test_ipv4_does_not_match_ipv6_network(self):
        """Test address families do not cross-match."""
        assert ip_in_networks("10.1.2.3", parse_networks(["2001:db8::/32"])) is False

    def test_empty_networks_never_match(self):
        """Test an empty network list matches nothing."""
        assert ip_in_networks("10.1.2.3", []) is False

    def test_ipv4_mapped_address_matches_ipv4_network(self):
        """Test an IPv4-mapped IPv6 address matches IPv4 entries.

        A socket bound dual-stack reports IPv4 peers as ::ffff:10.1.2.3, so
        without normalising them an IPv4 allowlist would silently reject every
        legitimate IPv4 client.
        """
        assert ip_in_networks("::ffff:10.1.2.3", parse_networks(["10.0.0.0/8"])) is True

    def test_ipv4_mapped_address_still_respects_bounds(self):
        """Test normalisation does not widen the match."""
        assert ip_in_networks("::ffff:203.0.113.9", parse_networks(["10.0.0.0/8"])) is False

    def test_malformed_address_does_not_match(self):
        """Test an unparseable address is simply not a member.

        Callers decide what to do about unknown peers; this must not raise
        in the middle of a request.
        """
        assert ip_in_networks("unknown", parse_networks(["10.0.0.0/8"])) is False
