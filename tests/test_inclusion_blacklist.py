"""InclusionManager blacklist subtraction (keeps blacklisted ranges out of the
target index space so a mostly-blacklisted target cannot abort the scan)."""
import ipaddress

import pytest

from reecanner.utils import BlacklistManager, InclusionManager


def _ip(s):
    return int(ipaddress.IPv4Address(s))


def test_mostly_private_target_keeps_only_public_slice():
    bl = BlacklistManager(include_recommended=False, allow_private=False)
    inc = InclusionManager(["10.0.0.0/8", "1.2.3.0/24"], seed=1, blacklist=bl)
    # the whole 10/8 is blacklisted (private); only the /24 survives
    assert inc.total_ips == 256
    produced = {inc.get_random_ip_int(i)[0] for i in range(inc.total_ips)}
    assert produced == {_ip(f"1.2.3.{h}") for h in range(256)}


def test_all_blacklisted_raises():
    bl = BlacklistManager(include_recommended=False, allow_private=False)
    with pytest.raises(ValueError):
        InclusionManager(["192.168.0.0/16"], seed=1, blacklist=bl)


def test_no_blacklist_arg_is_unchanged():
    inc = InclusionManager(["1.2.3.0/24"], seed=1)
    assert inc.total_ips == 256


def test_partial_overlap_carves_correctly():
    bl = BlacklistManager(include_recommended=False, allow_private=True,
                          custom_networks=["1.2.3.128/25"])
    inc = InclusionManager(["1.2.3.0/24"], seed=1, blacklist=bl)
    assert inc.total_ips == 128
    produced = {inc.get_random_ip_int(i)[0] for i in range(inc.total_ips)}
    assert produced == {_ip(f"1.2.3.{h}") for h in range(128)}
