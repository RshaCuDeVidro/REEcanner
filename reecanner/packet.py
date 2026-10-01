"""Raw IPv4/TCP/UDP/ICMP packet construction and parsing helpers.

The template/patch API (build_*_template / patch_*) mirrors the layout used
by the C worker so the pure-Python fallback in scanner.py shares one source
of truth for packet bytes: a fully-built template is created once and only
the per-target fields (dst IP, dst port, checksums) are patched per packet.
"""
from __future__ import annotations

import socket
import struct
from typing import Optional, Tuple


def checksum(msg: bytes) -> int:
    if len(msg) % 2 == 1:
        msg += b'\0'
    s = sum(struct.unpack(f"!{len(msg)//2}H", msg))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


IP_HEADER_STRUCT = struct.Struct('!BBHHHBBH4s4s')
TCP_HEADER_STRUCT = struct.Struct('!HHLLBBHHH')
PSEUDO_HEADER_STRUCT = struct.Struct('!4s4sBBH')

IP_ID = 54321
DEFAULT_TTL = 64
SYN_WINDOW = 5840
ICMP_PAYLOAD_LEN = 16
ICMP_ECHO_ID = 0x1337

_pack_into = struct.pack_into


def _fold(sum32: int) -> int:
    """Fold a 32-bit accumulator into a 16-bit one's-complement checksum."""
    sum32 = (sum32 >> 16) + (sum32 & 0xFFFF)
    sum32 = (sum32 >> 16) + (sum32 & 0xFFFF)
    return ~sum32 & 0xFFFF


def _write_eth(buf: bytearray, macs: Tuple[bytes, bytes]) -> None:
    """Write the ethernet header (dst gateway MAC, src local MAC)."""
    _pack_into('!6s6sH', buf, 0, macs[0], macs[1], 0x0800)


def _write_ip_header(buf: bytearray, off: int, total_len: int, proto: int,
                     local_ip_bytes: bytes) -> None:
    _pack_into('!BBHHHBB', buf, off, 0x45, 0, total_len, IP_ID, 0,
               DEFAULT_TTL, proto)
    _pack_into('!4s', buf, off + 12, local_ip_bytes)


def build_syn_template(local_ip_bytes: bytes, src_port: int,
                       macs: Optional[Tuple[bytes, bytes]] = None
                       ) -> Tuple[bytearray, int, int]:
    """Build a SYN packet template.

    Returns (buffer, ip_static_sum, tcp_static_sum). Per-packet patching is
    done by patch_syn(). ``macs`` is (gateway_mac_bytes, local_mac_bytes);
    when given, a 14-byte ethernet header is prepended.
    """
    off = 14 if macs else 0
    buf = bytearray(off + 40)
    if macs:
        _write_eth(buf, macs)
    _write_ip_header(buf, off, 40, socket.IPPROTO_TCP, local_ip_bytes)
    _pack_into('!H', buf, off + 20, src_port)
    _pack_into('!BBH', buf, off + 32, 0x50, 0x02, SYN_WINDOW)  # doff=5, SYN

    w0, w1 = struct.unpack("!HH", local_ip_bytes)
    ip_static = 0x4500 + 40 + IP_ID + 0 + (DEFAULT_TTL << 8 | 6) + w0 + w1
    # pseudo-header: src(4) + dst(4, per-pkt) + proto(6) + len(20)
    tcp_static = w0 + w1 + 6 + 20 + src_port + 0x5002 + SYN_WINDOW
    return buf, ip_static, tcp_static


def patch_syn(buf: bytearray, off: int, ip_int: int, port: int,
              ip_static_sum: int, tcp_static_sum: int) -> None:
    """Patch a SYN template for one target: dst IP, dst port, checksums."""
    ip_hi, ip_lo = ip_int >> 16, ip_int & 0xFFFF

    cs_ip = _fold(ip_static_sum + ip_hi + ip_lo)
    buf[off + 10] = cs_ip >> 8
    buf[off + 11] = cs_ip & 0xFF

    buf[off + 16] = (ip_int >> 24) & 0xFF
    buf[off + 17] = (ip_int >> 16) & 0xFF
    buf[off + 18] = (ip_int >> 8) & 0xFF
    buf[off + 19] = ip_int & 0xFF

    buf[off + 22] = port >> 8
    buf[off + 23] = port & 0xFF

    cs_tcp = _fold(tcp_static_sum + ip_hi + ip_lo + port)
    buf[off + 36] = cs_tcp >> 8
    buf[off + 37] = cs_tcp & 0xFF


def build_udp_template(local_ip_bytes: bytes, src_port: int, payload: bytes,
                       macs: Optional[Tuple[bytes, bytes]] = None
                       ) -> Tuple[bytearray, int]:
    """Build a UDP packet template for one probe payload.

    Returns (buffer, ip_static_sum). The UDP checksum is left at 0
    (optional in IPv4). Patch per target with patch_udp().
    """
    off = 14 if macs else 0
    total_len = 28 + len(payload)
    buf = bytearray(off + total_len)
    if macs:
        _write_eth(buf, macs)
    _write_ip_header(buf, off, total_len, socket.IPPROTO_UDP, local_ip_bytes)
    _pack_into('!H', buf, off + 20, src_port)
    _pack_into('!HH', buf, off + 24, 8 + len(payload), 0)
    buf[off + 28:off + 28 + len(payload)] = payload

    w0, w1 = struct.unpack("!HH", local_ip_bytes)
    ip_static = 0x4500 + total_len + IP_ID + 0 + (DEFAULT_TTL << 8 | 17) + w0 + w1
    return buf, ip_static


def patch_udp(buf: bytearray, off: int, ip_int: int, port: int,
              ip_static_sum: int) -> None:
    """Patch a UDP template for one target: dst IP, dst port, IP checksum."""
    ip_hi, ip_lo = ip_int >> 16, ip_int & 0xFFFF

    cs_ip = _fold(ip_static_sum + ip_hi + ip_lo)
    buf[off + 10] = cs_ip >> 8
    buf[off + 11] = cs_ip & 0xFF

    buf[off + 16] = (ip_int >> 24) & 0xFF
    buf[off + 17] = (ip_int >> 16) & 0xFF
    buf[off + 18] = (ip_int >> 8) & 0xFF
    buf[off + 19] = ip_int & 0xFF

    buf[off + 22] = port >> 8
    buf[off + 23] = port & 0xFF


def build_icmp_template(local_ip_bytes: bytes,
                        macs: Optional[Tuple[bytes, bytes]] = None
                        ) -> Tuple[bytearray, int]:
    """Build an ICMP echo-request (ping) template.

    Returns (buffer, ip_static_sum). The ICMP checksum is fully static
    (identifier/sequence do not change per target).
    """
    off = 14 if macs else 0
    total_len = 20 + 8 + ICMP_PAYLOAD_LEN
    buf = bytearray(off + total_len)
    if macs:
        _write_eth(buf, macs)
    _write_ip_header(buf, off, total_len, socket.IPPROTO_ICMP, local_ip_bytes)
    # ICMP echo request: type 8, code 0, id, seq, then padding payload
    _pack_into('!BBHHH', buf, off + 20, 8, 0, 0, ICMP_ECHO_ID, 1)
    for i in range(ICMP_PAYLOAD_LEN):
        buf[off + 28 + i] = 0x61 + (i % 26)  # 'abc...' padding
    icmp_sum = checksum(bytes(buf[off + 20:off + total_len]))
    _pack_into('!H', buf, off + 22, icmp_sum)

    w0, w1 = struct.unpack("!HH", local_ip_bytes)
    ip_static = 0x4500 + total_len + IP_ID + 0 + (DEFAULT_TTL << 8 | 1) + w0 + w1
    return buf, ip_static


def patch_icmp(buf: bytearray, off: int, ip_int: int,
               ip_static_sum: int) -> None:
    """Patch an ICMP template for one target: dst IP and IP checksum."""
    ip_hi, ip_lo = ip_int >> 16, ip_int & 0xFFFF

    cs_ip = _fold(ip_static_sum + ip_hi + ip_lo)
    buf[off + 10] = cs_ip >> 8
    buf[off + 11] = cs_ip & 0xFF

    buf[off + 16] = (ip_int >> 24) & 0xFF
    buf[off + 17] = (ip_int >> 16) & 0xFF
    buf[off + 18] = (ip_int >> 8) & 0xFF
    buf[off + 19] = ip_int & 0xFF


def create_ipv4_header_fast(src_addr_bytes: bytes, dst_addr_bytes: bytes, proto: int = socket.IPPROTO_TCP) -> bytes:
    version_ihl = 0x45
    tos = 0
    tot_len = 40
    ip_id = IP_ID
    frag_off = 0
    ttl = DEFAULT_TTL
    check = 0
    header = IP_HEADER_STRUCT.pack(version_ihl, tos, tot_len, ip_id, frag_off, ttl, proto, check, src_addr_bytes, dst_addr_bytes)
    check = checksum(header)
    return IP_HEADER_STRUCT.pack(version_ihl, tos, tot_len, ip_id, frag_off, ttl, proto, check, src_addr_bytes, dst_addr_bytes)


def create_tcp_header_fast(src_addr_bytes: bytes, dst_addr_bytes: bytes, src_port: int, dst_port: int, flags: int = 2) -> bytes:
    seq = 0
    ack_seq = 0
    doff_res = (5 << 4)
    window = SYN_WINDOW
    check = 0
    urg_ptr = 0
    tcp_header = TCP_HEADER_STRUCT.pack(src_port, dst_port, seq, ack_seq, doff_res, flags, window, check, urg_ptr)
    psh = PSEUDO_HEADER_STRUCT.pack(src_addr_bytes, dst_addr_bytes, 0, socket.IPPROTO_TCP, 20)
    tcp_checksum = checksum(psh + tcp_header)
    return TCP_HEADER_STRUCT.pack(src_port, dst_port, seq, ack_seq, doff_res, flags, window, tcp_checksum, urg_ptr)


def parse_tcp_header(data: bytes):
    res = struct.unpack('!HHLLBBHHH', data[:20])
    return {'src_port': res[0], 'dst_port': res[1], 'seq': res[2], 'ack': res[3], 'flags': res[5]}


def parse_ipv4_header(data: bytes):
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return {'ihl': ihl, 'length': iph_length, 'src': src_ip, 'dst': dst_ip, 'proto': iph[6]}
