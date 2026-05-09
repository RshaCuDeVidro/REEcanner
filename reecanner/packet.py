import struct
import socket

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

def create_ipv4_header_fast(src_addr_bytes: bytes, dst_addr_bytes: bytes, proto: int = socket.IPPROTO_TCP) -> bytes:
    version_ihl = 0x45
    tos = 0
    tot_len = 40
    ip_id = 54321
    frag_off = 0
    ttl = 64
    check = 0
    header = IP_HEADER_STRUCT.pack(version_ihl, tos, tot_len, ip_id, frag_off, ttl, proto, check, src_addr_bytes, dst_addr_bytes)
    check = checksum(header)
    return IP_HEADER_STRUCT.pack(version_ihl, tos, tot_len, ip_id, frag_off, ttl, proto, check, src_addr_bytes, dst_addr_bytes)

def create_tcp_header_fast(src_addr_bytes: bytes, dst_addr_bytes: bytes, src_port: int, dst_port: int, flags: int = 2) -> bytes:
    seq = 0
    ack_seq = 0
    doff_res = (5 << 4)
    window = 5840
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
