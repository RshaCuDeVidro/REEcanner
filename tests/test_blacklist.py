"""BlacklistManager.is_ip_int_public edge case tests."""
import ipaddress

from reecanner.utils import BlacklistManager


def ip(s):
    return int(ipaddress.IPv4Address(s))


def make(networks):
    return BlacklistManager(include_recommended=False, allow_private=True,
                            custom_networks=networks)


def test_empty_ranges_all_public(empty_blacklist):
    assert empty_blacklist._flat_ranges == []
    assert empty_blacklist.is_ip_int_public(ip("0.0.0.0"))
    assert empty_blacklist.is_ip_int_public(ip("10.0.0.1"))
    assert empty_blacklist.is_ip_int_public(ip("255.255.255.255"))


def test_single_range_boundaries():
    bl = make(["10.0.0.0/8"])
    # inside the range
    assert not bl.is_ip_int_public(ip("10.0.0.0"))        # first address
    assert not bl.is_ip_int_public(ip("10.255.255.255"))  # last address
    assert not bl.is_ip_int_public(ip("10.1.2.3"))
    # just outside
    assert bl.is_ip_int_public(ip("9.255.255.255"))
    assert bl.is_ip_int_public(ip("11.0.0.0"))


def test_adjacent_ranges_merge():
    bl = make(["10.0.0.0/8", "11.0.0.0/8"])
    assert not bl.is_ip_int_public(ip("10.255.255.255"))
    assert not bl.is_ip_int_public(ip("11.0.0.0"))       # merge must not leak
    assert not bl.is_ip_int_public(ip("11.255.255.255"))
    assert bl.is_ip_int_public(ip("12.0.0.0"))


def test_overlapping_ranges():
    bl = make(["10.0.0.0/8", "10.1.0.0/16"])
    assert not bl.is_ip_int_public(ip("10.1.0.5"))
    assert bl.is_ip_int_public(ip("11.0.0.0"))


def test_unsorted_input():
    bl = make(["192.168.0.0/16", "10.0.0.0/8"])
    assert not bl.is_ip_int_public(ip("192.168.1.1"))
    assert not bl.is_ip_int_public(ip("10.0.0.1"))
    assert bl.is_ip_int_public(ip("172.20.0.1"))


def test_single_host_range():
    bl = make(["203.0.113.7/32"])
    assert not bl.is_ip_int_public(ip("203.0.113.7"))
    assert bl.is_ip_int_public(ip("203.0.113.6"))
    assert bl.is_ip_int_public(ip("203.0.113.8"))


def test_default_blacklist_blocks_private():
    bl = BlacklistManager(include_recommended=False, allow_private=False)
    assert not bl.is_ip_int_public(ip("192.168.1.1"))
    assert not bl.is_ip_int_public(ip("127.0.0.1"))
    assert not bl.is_ip_int_public(ip("224.0.0.1"))
    assert bl.is_ip_int_public(ip("203.0.113.7"))


def test_invalid_network_ignored():
    bl = make(["not-a-network", "10.0.0.0/8"])
    assert not bl.is_ip_int_public(ip("10.0.0.1"))
    assert bl.is_ip_int_public(ip("1.2.3.4"))
