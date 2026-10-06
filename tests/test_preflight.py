"""Preflight reachability check + firewall diagnostics tests."""
import struct

import pytest

from reecanner import preflight


def _synack(src_port: int, dst_port: int, flags: int = 0x12) -> bytes:
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack("!H", 40)
    ip[9] = 6
    tcp = bytearray(20)
    tcp[0:2] = struct.pack("!H", src_port)
    tcp[2:4] = struct.pack("!H", dst_port)
    tcp[12] = 0x50
    tcp[13] = flags
    return bytes(ip + tcp)


class TestParseTarget:
    def test_valid(self):
        assert preflight.parse_target("1.1.1.1:443") == ("1.1.1.1", 443)

    @pytest.mark.parametrize("bad", ["", "1.1.1.1", "1.1.1.1:", ":443", "1.1.1.1:0",
                                     "1.1.1.1:70000", "not-an-ip:443", "1.1.1.1:abc"])
    def test_invalid(self, bad):
        assert preflight.parse_target(bad) is None


class TestSynAckParse:
    def test_matches_our_source_port(self):
        assert preflight._parse_synack(_synack(22, 61000), 61000) is True

    def test_ignores_other_ports_and_flags(self):
        assert preflight._parse_synack(_synack(22, 61000), 40000) is False
        assert preflight._parse_synack(_synack(22, 61000, flags=0x02), 61000) is False
        assert preflight._parse_synack(b"", 61000) is False


class TestNetInfo:
    def test_afpacket_requires_all_three(self):
        assert preflight.net_info_supports_afpacket(("eth0", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"))
        assert not preflight.net_info_supports_afpacket(("eth0", "aa:bb:cc:dd:ee:ff", None))
        assert not preflight.net_info_supports_afpacket((None, None, None))


class TestFirewallHint:
    def test_detects_iptables_drop_policy(self, monkeypatch):
        sample = ("-P INPUT DROP\n"
                  "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                  "-A INPUT -j REJECT --reject-with icmp-host-prohibited\n")

        class R:
            stdout = sample

        monkeypatch.setattr(preflight.shutil, "which",
                            lambda name: "/usr/sbin/iptables" if name == "iptables" else None)
        monkeypatch.setattr(preflight.subprocess, "run", lambda *a, **k: R())
        hint = preflight.firewall_hint()
        assert hint is not None and "DROP" in hint

    def test_none_when_no_firewall(self, monkeypatch):
        monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
        assert preflight.firewall_hint() is None


class TestMessages:
    def test_warning_mentions_fix_and_flags(self):
        msg = preflight.format_warning(61000, afpacket_only=True, static_hint="iptables INPUT policy is DROP")
        assert preflight.SRC_PORT_RANGE in msg
        assert "--no-afpacket" in msg
        assert "SOCK_RAW" in msg
        assert "iptables INPUT policy is DROP" in msg

    def test_zero_hits_hint(self):
        msg = preflight.format_zero_hits_hint(61000)
        assert "0 hosts" in msg
        assert preflight.SRC_PORT_RANGE in msg


class TestRunPreflight:
    def test_returns_none_when_probe_succeeds(self, monkeypatch):
        monkeypatch.setattr(preflight, "_send_syn", lambda *a, **k: True)
        assert preflight.run_preflight(b"\x0a\x00\x00\x01", 61000, (None, None, None)) is None

    def test_returns_warning_when_probe_fails(self, monkeypatch):
        monkeypatch.setattr(preflight, "_send_syn", lambda *a, **k: False)
        monkeypatch.setattr(preflight, "firewall_hint", lambda: None)
        msg = preflight.run_preflight(b"\x0a\x00\x00\x01", 61000, (None, None, None))
        assert msg is not None and "--no-afpacket" in msg

    def test_afpacket_only_detected(self, monkeypatch):
        calls = {"n": 0}

        def fake_send(local_ip_bytes, src_port, dst_ip, dst_port, net_info, timeout):
            calls["n"] += 1
            # first pass (AF_PACKET) always fails, SOCK_RAW pass succeeds
            return net_info is None

        monkeypatch.setattr(preflight, "_send_syn", fake_send)
        monkeypatch.setattr(preflight, "firewall_hint", lambda: None)
        net = ("eth0", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        msg = preflight.run_preflight(b"\x0a\x00\x00\x01", 61000, net)
        assert msg is not None and "SOCK_RAW" in msg and "AF_PACKET" in msg
