"""Classic BPF program construction tests.

Regression coverage for the filter that keeps unrelated traffic out of the
Python sniffer. The old code packed instructions with the wrong ``sock_filter``
layout and could never obtain the program pointer, so the kernel filter was
never actually installed.
"""
import ctypes
import os

import pytest

from reecanner.scanner import _bpf_insn, _SockFilter, _SockFprog, build_bpf_program


def test_sock_filter_layout_is_8_bytes():
    assert ctypes.sizeof(_SockFilter) == 8


def test_sock_fprog_layout_is_native_pointer_size():
    # u16 + padding + pointer
    assert ctypes.sizeof(_SockFprog) == 8 + ctypes.sizeof(ctypes.c_void_p)


def test_tcp_program_filters_on_source_port():
    src_port = 61000  # > 255: the old 'HHIB' packing raised struct.error here
    prog = build_bpf_program(src_port)
    assert prog
    assert all(isinstance(i, _SockFilter) for i in prog)
    # second instruction is "jeq src_port"
    assert prog[1].code == 0x15
    assert prog[1].k == src_port


def test_udp_and_icmp_programs_build():
    assert build_bpf_program(1234, udp=True)
    icmp = build_bpf_program(0, icmp=True)
    assert icmp
    assert all(i.code in (0x30, 0x15, 0x06) for i in icmp)


def test_instruction_keeps_full_32bit_k():
    insn = _bpf_insn(0x06, 0, 0, 0x00040000)
    assert insn.k == 0x00040000
    assert insn.jt == 0 and insn.jf == 0


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="attaching a BPF filter needs root")
def test_attach_real_filter():
    import socket

    from reecanner.scanner import _attach_bpf

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    try:
        _attach_bpf(sock, build_bpf_program(61000))
    finally:
        sock.close()
