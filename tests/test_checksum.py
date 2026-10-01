"""packet.checksum tests against RFC 1071 reference values."""
import struct

from reecanner.packet import checksum


def rfc1071_reference(data: bytes) -> int:
    """Independent, deliberately literal RFC 1071 one's-complement sum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def test_rfc1071_known_vector():
    # RFC 1071 example octets: 00 01 f2 03 f4 f5 f6 f7 -> checksum 0x220d
    msg = bytes([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])
    assert checksum(msg) == 0x220d
    assert checksum(msg) == rfc1071_reference(msg)


def test_matches_reference_various():
    msgs = [
        b"",
        b"\x00",
        b"\xff" * 7,
        bytes(range(256)),
        b"\x45\x00\x00\x28\xd4\x31\x00\x00\x40\x06\x00\x00" + b"\x0a\x00\x00\x01" + b"\x0a\x00\x00\x02",
    ]
    for msg in msgs:
        assert checksum(msg) == rfc1071_reference(msg), msg.hex()


def test_odd_length_padding():
    # b'\x01' pads to 0x0100 -> ~0x0100 = 0xfeff
    assert checksum(b"\x01") == 0xFEFF


def test_self_verifying_property():
    # A message with its own checksum appended must checksum to 0.
    for msg in (b"hello world", bytes(range(100)), b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"):
        cs = checksum(msg)
        if len(msg) % 2:
            padded = msg + b"\x00" + struct.pack("!H", cs)
        else:
            padded = msg + struct.pack("!H", cs)
        assert checksum(padded) == 0, msg.hex()


def test_all_zeros():
    assert checksum(b"\x00\x00") == 0xFFFF


def test_all_ones():
    # 0xffff + 0xffff folds back to 0xffff -> checksum 0x0000
    assert checksum(b"\xff\xff\xff\xff") == 0x0000
