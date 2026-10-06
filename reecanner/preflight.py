"""Preflight reachability check + firewall diagnostics.

A raw SYN scanner sends packets that bypass the kernel connection tracker when
it uses the AF_PACKET fast path. On a host with a stateful firewall (e.g.
``INPUT policy DROP`` plus a ``RELATED,ESTABLISHED`` accept), every reply --
which has no conntrack entry -- is dropped, and the scan silently reports
0 hosts. That looks exactly like a scanner bug.

This module detects the condition up front: it sends one SYN through the same
send path the scan will use and watches for the SYN-ACK. If nothing comes back
it retries over SOCK_RAW to tell "the AF_PACKET replies are being dropped" apart
from "no route / cloud security list". On failure it returns a human-readable
warning with the concrete fix.

All of it is best-effort and non-fatal: the scan always proceeds.
"""
from __future__ import annotations

import logging
import re
import shutil
import socket
import struct
import subprocess
import time
from typing import Optional

from reecanner import packet as packet_mod

logger = logging.getLogger(__name__)

#: Source-port range the scanner picks from (see Scanner.__init__:
#: ``int(time.time()) % 29000 + 10000``). Used for the suggested iptables rule.
SRC_PORT_RANGE = "10000:38999"

#: Stable public echo targets used as canaries. One SYN each, no data.
CANARY_TARGETS: list[tuple[str, int]] = [("1.1.1.1", 443), ("8.8.8.8", 443)]

#: How long to wait for a SYN-ACK per probe.
PROBE_TIMEOUT = 1.2


def net_info_supports_afpacket(net_info) -> bool:
    """True when we have everything needed for the AF_PACKET send path."""
    return bool(net_info and net_info[0] and net_info[1] and net_info[2])


def parse_target(value: str) -> Optional[tuple[str, int]]:
    """Parse an ``IP:PORT`` preflight target. Returns None when malformed."""
    if not value or ":" not in value:
        return None
    host, _, port_s = value.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not host or not (0 < port < 65536):
        return None
    try:
        socket.inet_aton(host)
    except OSError:
        return None
    return host, port


def _parse_synack(data: bytes, src_port: int) -> bool:
    """True when *data* is a TCP SYN-ACK addressed to our source port."""
    if len(data) < 20 or data[0] >> 4 != 4:
        return False
    ihl = (data[0] & 0x0F) << 2
    if len(data) < ihl + 20:
        return False
    dp = (data[ihl + 2] << 8) | data[ihl + 3]
    if dp != src_port:
        return False
    return (data[ihl + 13] & 0x12) == 0x12


def _send_syn(local_ip_bytes: bytes, src_port: int, dst_ip: str, dst_port: int,
              net_info, timeout: float) -> bool:
    """Send one SYN via the requested path; return True if a SYN-ACK comes back."""
    macs = None
    if net_info_supports_afpacket(net_info):
        iface, l_mac, g_mac = net_info
        macs = (bytes.fromhex(g_mac.replace(":", "")),
                bytes.fromhex(l_mac.replace(":", "")))
    else:
        iface = None

    buf, ip_static, tcp_static = packet_mod.build_syn_template(local_ip_bytes, src_port, macs)
    off = 14 if macs else 0
    packet_mod.patch_syn(buf, off, struct.unpack("!I", socket.inet_aton(dst_ip))[0],
                         dst_port, ip_static, tcp_static)

    listener = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    listener.settimeout(0.2)

    sender = None
    try:
        if macs:
            sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sender.bind((iface, 0))
            sender.send(buf)
        else:
            sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sender.sendto(bytes(buf), (dst_ip, 0))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = listener.recvfrom(65535)
            except (socket.timeout, BlockingIOError, InterruptedError):
                continue
            if _parse_synack(data, src_port):
                return True
        return False
    except OSError as e:
        logger.debug("preflight probe to %s:%d failed: %s", dst_ip, dst_port, e)
        return False
    finally:
        if sender is not None:
            sender.close()
        listener.close()


def firewall_hint() -> Optional[str]:
    """Best-effort static look at the host firewall. Returns a hint or None.

    Heuristic only -- the active probe is the source of truth. Handles both
    iptables and nftables; never raises.
    """
    iptables = shutil.which("iptables")
    if iptables:
        try:
            out = subprocess.run([iptables, "-S", "INPUT"], capture_output=True,
                                 text=True, timeout=3).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        if out:
            policy_drop = bool(re.search(r"^-P INPUT DROP", out, re.M))
            has_reject = bool(re.search(r"-j (REJECT|DROP)\b", out))
            has_related = bool(re.search(r"RELATED,ESTABLISHED|ESTABLISHED,RELATED", out))
            if policy_drop or has_reject:
                note = "iptables INPUT policy is DROP" if policy_drop else \
                    "iptables INPUT has a REJECT/DROP rule"
                if has_related:
                    note += " (its RELATED,ESTABLISHED accept never matches AF_PACKET replies)"
                return note
            return None

    nft = shutil.which("nft")
    if nft:
        try:
            out = subprocess.run([nft, "list", "ruleset"], capture_output=True,
                                 text=True, timeout=3).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        if out and re.search(r"policy drop", out) and re.search(r"\b(reject|drop)\b", out):
            return "nftables has a drop policy; AF_PACKET replies may be dropped"
    return None


def _fix_block(src_port: int) -> str:
    return (
        "What to check:\n"
        "  - inspect the rules:    sudo iptables -S INPUT\n"
        "  - allow the replies:    sudo iptables -I INPUT -p tcp -m tcp "
        f"--dport {SRC_PORT_RANGE} "
        "--tcp-flags SYN,ACK SYN,ACK -j ACCEPT\n"
        "  - or skip AF_PACKET:    reecanner ... --no-afpacket\n"
        "  - cloud hosts:          allow inbound TCP SYN-ACK to the source-port range\n"
        "                          in the security list / security group\n"
    )


def format_warning(src_port: int, afpacket_only: bool = False,
                   static_hint: Optional[str] = None) -> str:
    """Build the user-facing warning shown when the preflight probe fails."""
    lines = [
        "[!] preflight: no SYN-ACK came back from the probe target(s).",
        "    This usually means replies are being dropped before they reach the",
        "    scanner -- not that every target is down.",
        "",
    ]
    if afpacket_only:
        lines += [
            "    A SOCK_RAW probe to the same target succeeded, which confirms the",
            "    drop is specific to the AF_PACKET path: it bypasses the kernel",
            "    connection tracker, so a stateful firewall (INPUT policy DROP plus",
            "    a RELATED,ESTABLISHED accept) drops every reply and scans silently",
            "    return 0 hosts.",
        ]
    else:
        lines += [
            "    Both the AF_PACKET and SOCK_RAW probes failed, which points at a",
            "    missing route, a cloud security list, or a firewall that drops the",
            "    outgoing SYN itself.",
        ]
    lines.append("")
    lines.append("    " + _fix_block(src_port).replace("\n", "\n    ").rstrip())
    if static_hint:
        lines.append("")
        lines.append("    detected: " + static_hint)
    lines.append("")
    lines.append("    Disable this check with --no-preflight.")
    return "\n".join(lines)


def format_zero_hits_hint(src_port: int, static_hint: Optional[str] = None) -> str:
    """Concise hint appended after a scan that sent packets but found nothing."""
    lines = [
        "[!] scan finished with 0 hosts. If you expected results, the replies may",
        "    be dropped by a stateful firewall (AF_PACKET bypasses conntrack).",
        "    " + _fix_block(src_port).strip().replace("\n", "\n    "),
    ]
    if static_hint:
        lines.append("    detected: " + static_hint)
    return "\n".join(lines)


def run_preflight(local_ip_bytes: bytes, src_port: int, net_info,
                  target: Optional[str] = None, timeout: float = PROBE_TIMEOUT) -> Optional[str]:
    """Probe reachability through the real send path.

    Returns None when a SYN-ACK is seen (all good), otherwise a warning string
    ready to print. Never raises.
    """
    if target:
        parsed = parse_target(target)
        targets = [parsed] if parsed else list(CANARY_TARGETS)
        if parsed is None:
            logger.warning("ignoring malformed preflight target %r", target)
    else:
        targets = list(CANARY_TARGETS)

    use_afp = net_info_supports_afpacket(net_info)

    try:
        for ip, port in targets:
            if _send_syn(local_ip_bytes, src_port, ip, port, net_info, timeout):
                return None

        afpacket_only = False
        if use_afp:
            # Distinguish "AF_PACKET replies dropped" from "nothing is reachable".
            for ip, port in targets:
                if _send_syn(local_ip_bytes, src_port, ip, port, (None, None, None), timeout):
                    afpacket_only = True
                    break

        return format_warning(src_port, afpacket_only=afpacket_only,
                              static_hint=firewall_hint())
    except Exception as e:  # never let a diagnostic kill the scan
        logger.debug("preflight aborted: %s", e)
        return None
