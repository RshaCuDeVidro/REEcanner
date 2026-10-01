"""Template/patch packet bytes: checksums must self-verify and the
template path must agree byte-for-byte with the legacy create_*_fast helpers."""
import socket
import struct

from reecanner.packet import (
    ICMP_PAYLOAD_LEN,
    PSEUDO_HEADER_STRUCT,
    build_icmp_template,
    build_syn_template,
    build_udp_template,
    checksum,
    create_ipv4_header_fast,
    create_tcp_header_fast,
    patch_icmp,
    patch_syn,
    patch_udp,
)

LOCAL = socket.inet_aton("192.0.2.1")
TARGET = 0xCB007105  # 203.0.113.5


def test_syn_ip_checksum_self_verifies():
    for macs in (None, (b"\xaa" * 6, b"\xbb" * 6)):
        buf, ip_static, tcp_static = build_syn_template(LOCAL, 40000, macs=macs)
        off = 14 if macs else 0
        patch_syn(buf, off, TARGET, 443, ip_static, tcp_static)
        assert checksum(bytes(buf[off:off + 20])) == 0


def test_syn_tcp_checksum_self_verifies():
    buf, ip_static, tcp_static = build_syn_template(LOCAL, 40000)
    patch_syn(buf, 0, TARGET, 443, ip_static, tcp_static)
    tcp_seg = bytes(buf[20:40])
    pseudo = PSEUDO_HEADER_STRUCT.pack(LOCAL, struct.pack("!I", TARGET),
                                       0, socket.IPPROTO_TCP, 20)
    assert checksum(pseudo + tcp_seg) == 0


def test_syn_template_matches_fast_helpers():
    buf, ip_static, tcp_static = build_syn_template(LOCAL, 40000)
    patch_syn(buf, 0, TARGET, 443, ip_static, tcp_static)
    dst = struct.pack("!I", TARGET)
    assert bytes(buf[0:20]) == create_ipv4_header_fast(LOCAL, dst, socket.IPPROTO_TCP)
    assert bytes(buf[20:40]) == create_tcp_header_fast(LOCAL, dst, 40000, 443, flags=2)


def test_udp_ip_checksum_self_verifies():
    buf, ip_static = build_udp_template(LOCAL, 40000, b"\x00" * 12)
    patch_udp(buf, 0, TARGET, 53, ip_static)
    assert checksum(bytes(buf[0:20])) == 0
    # UDP checksum is optional in IPv4 and intentionally left at 0
    assert buf[26] == 0 and buf[27] == 0
    # dst port patched into the UDP header
    assert struct.unpack("!H", buf[22:24])[0] == 53


def test_icmp_checksums_self_verify():
    buf, ip_static = build_icmp_template(LOCAL)
    patch_icmp(buf, 0, TARGET, ip_static)
    assert checksum(bytes(buf[0:20])) == 0
    icmp_end = 20 + 8 + ICMP_PAYLOAD_LEN
    assert checksum(bytes(buf[20:icmp_end])) == 0
    # echo id/seq are static across targets
    assert struct.unpack("!H", buf[24:26])[0] == 0x1337
