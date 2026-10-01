"""p0f-style passive OS fingerprinting from SYN-ACK TTL, window and TCP options.

The heuristics below combine the observed TTL (normalized to the probable
initial TTL), the advertised TCP window, and the MSS / window-scale /
timestamp options when they are available. Signatures are ordered from most
to least specific; the first one whose constraints all match wins.
"""
from __future__ import annotations

from typing import Optional


def _initial_ttl(ttl: int) -> int:
    """Map an observed TTL to the most likely initial TTL."""
    if ttl <= 32:
        return 32
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


# Each signature: (label, initial_ttl, windows, mss, wscales, has_ts)
# A value of None means "do not constrain on this attribute".
_SIGNATURES = [
    # --- network infrastructure (initial TTL 255) ---
    ("Cisco IOS",        255, {4128, 8192},      1460, None, None),
    ("Cisco/Network",    255, {4128, 8192, 16384}, None, None, None),
    ("Juniper/Network",  255, {16384, 32768, 65535}, None, None, None),
    ("Network printer",  255, {2920, 4096, 8760}, None, None, None),
    ("Solaris",          255, {32850, 64240, 24616}, None, None, None),
    # --- Windows family (initial TTL 128) ---
    ("Windows 11",       128, {64240},           1460, {8}, False),
    ("Windows 10",       128, {64240, 65535},    1460, {2, 4, 8}, False),
    ("Windows 10/11",    128, {64240, 65535},    None, None, None),
    ("Windows 7/2008",   128, {8192},            1460, {2, 8}, False),
    ("Windows 7/2008",   128, {8192, 65392},     None, None, None),
    ("Windows XP/2003",  128, {65535, 16384, 64240}, 1460, {0}, False),
    ("Windows",          128, None,              None, None, None),
    # --- macOS / iOS (initial TTL 64, big windows) ---
    ("macOS 14/iOS 17",  64,  {65535},           1460, {6, 7}, True),
    ("macOS 12/iOS",     64,  {65535},           1460, {4, 5}, True),
    ("macOS/iOS",        64,  {65535},           None, None, None),
    # --- Linux family (initial TTL 64) ---
    ("Android",          64,  {64240, 65535},    {1380, 1400, 1440}, {6, 7, 8}, True),
    ("Linux 5.x/6.x",    64,  {64240, 65160, 32120}, 1460, {6, 7, 8}, True),
    ("Linux 3.x/4.x",    64,  {26883, 28960, 29200}, 1460, {5, 6, 7}, True),
    ("ChromeOS",         64,  {26883, 29200},    {1370, 1460}, {6, 7}, True),
    ("Linux 3.x+",       64,  {26883, 28960, 29200, 32120, 64240, 65160}, None, None, None),
    ("Linux 2.6",        64,  {5840, 5720},      {1440, 1460}, {0, 1, 2}, None),
    ("Linux 2.4",        64,  {5840},            1460, {0}, False),
    # --- BSD / embedded ---
    ("FreeBSD",          64,  {16384, 32768, 65535}, 1460, {3, 6}, True),
    ("FreeBSD",          64,  {16384, 32768},    None, None, None),
    ("Network printer",  64,  {2920, 8760},      {1380, 1460}, None, None),
    ("Embedded/IoT",     64,  {1460, 2190, 2920, 4096, 8760}, None, {0, 1}, None),
    ("Embedded/IoT",     32,  None,              None, None, None),
    ("Linux",            64,  None,              None, None, None),
]


def guess_os(ttl: int, window: int, mss: Optional[int] = None,
             wscale: Optional[int] = None, has_ts: Optional[bool] = None) -> str:
    """Guess the remote OS from a SYN-ACK's TTL, window size and TCP options.

    ``mss``/``wscale``/``has_ts`` may be None when the options were not
    parsed (or absent); unconstrained attributes are treated as wildcards.
    """
    itl = _initial_ttl(ttl)
    for label, s_itl, s_win, s_mss, s_wscale, s_ts in _SIGNATURES:
        if itl != s_itl:
            continue
        if s_win is not None and window not in s_win:
            continue
        if s_mss is not None and mss is not None:
            allowed = s_mss if isinstance(s_mss, (set, frozenset)) else {s_mss}
            if mss not in allowed:
                continue
        if s_wscale is not None and wscale is not None and wscale not in s_wscale:
            continue
        if s_ts is not None and has_ts is not None and has_ts != s_ts:
            continue
        return label
    # generic fallback by initial TTL
    if itl == 64:
        return "Linux/Unix"
    if itl == 128:
        return "Windows"
    if itl == 255:
        return "Network device"
    return "?"
