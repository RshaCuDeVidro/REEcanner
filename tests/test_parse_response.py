"""parse_response() tests with synthetic raw packets (IP headers built in-test)."""
import struct

from reecanner.scanner import parse_response

SRC_PORT = 42424


def build_ip(proto: int, src: bytes, dst: bytes, ttl: int = 64, payload: bytes = b"") -> bytes:
    """Minimal IPv4 header (checksum zeroed; parse_response does not verify it)."""
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1234, 0, ttl, proto, 0, src, dst)
    return hdr + payload


def build_tcp(sport: int, dport: int, flags: int, window: int = 5840,
              options: bytes = b"") -> bytes:
    """TCP header with optional option bytes (padded to a 4-byte boundary)."""
    pad = (-len(options)) % 4
    options = options + b"\x01" * pad  # NOP padding
    doff = (5 + len(options) // 4) << 4
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, doff, flags,
                       window, 0, 0) + options


def build_udp(sport: int, dport: int, payload: bytes = b"\x00" * 4) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


SRC_IP = bytes([203, 0, 113, 7])
DST_IP = bytes([198, 51, 100, 2])


def test_syn_ack_basic():
    pkt = build_ip(6, SRC_IP, DST_IP, ttl=64, payload=build_tcp(80, SRC_PORT, 0x12, window=29200))
    r = parse_response(pkt, SRC_PORT)
    assert r is not None
    assert r.ip == "203.0.113.7"
    assert r.ip_int == (203 << 24) | (113 << 8) | 7
    assert r.port == 80
    assert r.proto == "tcp"
    assert r.ttl == 64
    assert r.window == 29200
    assert r.mss is None
    assert r.window_scale is None
    assert r.timestamp is None


def test_syn_ack_with_options():
    # MSS=1460, NOP, WS=7, TS val=0x01020304
    opts = (b"\x02\x04\x05\xb4" + b"\x01" + b"\x03\x03\x07"
            + b"\x08\x0a\x01\x02\x03\x04\x00\x00\x00\x00")
    pkt = build_ip(6, SRC_IP, DST_IP, payload=build_tcp(443, SRC_PORT, 0x12, options=opts))
    r = parse_response(pkt, SRC_PORT)
    assert r is not None
    assert r.mss == 1460
    assert r.window_scale == 7
    assert r.timestamp == 0x01020304


def test_syn_only_rejected():
    pkt = build_ip(6, SRC_IP, DST_IP, payload=build_tcp(80, SRC_PORT, 0x02))
    assert parse_response(pkt, SRC_PORT) is None


def test_wrong_dst_port_rejected():
    pkt = build_ip(6, SRC_IP, DST_IP, payload=build_tcp(80, SRC_PORT + 1, 0x12))
    assert parse_response(pkt, SRC_PORT) is None


def test_truncated_rejected():
    assert parse_response(b"\x45\x00\x00", SRC_PORT) is None


def test_udp_response():
    pkt = build_ip(17, SRC_IP, DST_IP, ttl=128, payload=build_udp(53, SRC_PORT))
    r = parse_response(pkt, SRC_PORT, udp=True)
    assert r is not None
    assert r.proto == "udp"
    assert r.port == 53
    assert r.ttl == 128


def test_udp_wrong_port_rejected():
    pkt = build_ip(17, SRC_IP, DST_IP, payload=build_udp(53, SRC_PORT + 1))
    assert parse_response(pkt, SRC_PORT, udp=True) is None


def test_icmp_echo_reply():
    icmp = struct.pack("!BBHHH", 0, 0, 0, 0x1337, 1) + b"abcdefghijklmnop"
    pkt = build_ip(1, SRC_IP, DST_IP, ttl=64, payload=icmp)
    r = parse_response(pkt, SRC_PORT, icmp=True)
    assert r is not None
    assert r.proto == "icmp"
    assert r.port == 0
    assert r.ip == "203.0.113.7"


def test_icmp_non_reply_rejected():
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1337, 1) + b"abcdefghijklmnop"
    pkt = build_ip(1, SRC_IP, DST_IP, payload=icmp)
    assert parse_response(pkt, SRC_PORT, icmp=True) is None
