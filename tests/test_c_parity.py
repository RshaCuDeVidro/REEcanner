"""C worker vs Python FeistelShuffler parity tests (via ctypes)."""
import ctypes
import os

import pytest

from reecanner.utils import FeistelShuffler

WORKER_SO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reecanner", "worker.so",
)

worker = None
if os.path.exists(WORKER_SO):
    try:
        worker = ctypes.CDLL(WORKER_SO)
        worker.reecanner_fget.restype = ctypes.c_uint32
        worker.reecanner_fget.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
    except (OSError, AttributeError):
        worker = None

pytestmark = pytest.mark.skipif(
    worker is None,
    reason="worker.so with reecanner_fget not available (run `make` first)",
)


def c_fget(idx, keys, max_val, half_bits, mask):
    c_keys = (ctypes.c_uint32 * 4)(*keys)
    return worker.reecanner_fget(idx, c_keys, max_val, half_bits, mask)


@pytest.mark.parametrize("max_val", [1, 2, 255, 256, 1000, 65535])
def test_fget_parity(max_val):
    """C fget and Python FeistelShuffler.get must agree exactly."""
    fs = FeistelShuffler(key=0xDEADBEEF, max_val=max_val)
    for i in range(max_val):
        expected = fs.get(i)
        got = c_fget(i, fs.keys, max_val, fs.half_bits, fs.mask)
        assert got == expected, f"idx={i}: C={got} python={expected}"


@pytest.mark.parametrize("key", [0, 1, 0x12345678, 0xFFFFFFFF])
def test_fget_parity_keys(key):
    max_val = 4096
    fs = FeistelShuffler(key=key, max_val=max_val)
    for i in range(max_val):
        assert c_fget(i, fs.keys, max_val, fs.half_bits, fs.mask) == fs.get(i)
