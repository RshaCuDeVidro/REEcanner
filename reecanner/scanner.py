"""Core scanning engine: packet workers, sniffer and the Scanner orchestrator."""
from __future__ import annotations

import ctypes
import dataclasses
import json
import logging
import multiprocessing
import os
import queue
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from reecanner import packet as packet_mod
from reecanner.fingerprint import guess_os
from reecanner.ports import get_service_name

if TYPE_CHECKING:
    from reecanner.utils import BlacklistManager, InclusionManager

logger = logging.getLogger(__name__)

# UDP probe payloads for --udp-payload. 'auto' rotates through all of them
# in round-robin across target IPs.
UDP_PAYLOADS = {
    'dns': b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01",
    'ntp': b"\x17\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # monlist, mode 7 v2
    'snmp': (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04qBig"
             b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    'ssdp': (b'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n'
             b'Man:"ssdp:discover"\r\nST:upnp:rootdevice\r\nMX:1\r\n\r\n'),
    'memcached': b"stats\r\n",
}
UDP_PAYLOAD_ORDER = ('dns', 'ntp', 'snmp', 'ssdp', 'memcached')

try:
    _lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'worker.so'))
    _lib.run_worker.restype = None
    _lib.run_worker.argtypes = [                         # keep in sync with worker.c run_worker
        ctypes.c_int,                                    # worker_id
        ctypes.POINTER(ctypes.c_uint8),                  # src_ip (4 bytes)
        ctypes.POINTER(ctypes.c_uint16), ctypes.c_int,   # ports, ports_len
        ctypes.c_uint16,                                 # src_port
        ctypes.POINTER(ctypes.c_int),                    # rate_limit_ptr
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,   # bl_ranges, bl_len
        ctypes.POINTER(ctypes.c_uint32),                 # feistel_keys (4)
        ctypes.c_uint64,                                 # total_ips
        ctypes.POINTER(ctypes.c_uint32),                 # net_bases
        ctypes.POINTER(ctypes.c_uint32),                 # net_starts
        ctypes.c_int, ctypes.c_int,                      # nets_len, single_net
        ctypes.POINTER(ctypes.c_int),                    # run_flag
        ctypes.POINTER(ctypes.c_uint64),                 # pps_ptr
        ctypes.POINTER(ctypes.c_uint64),                 # sent_ptr
        ctypes.c_char_p,                                 # iface
        ctypes.POINTER(ctypes.c_uint8),                  # lmac (6 bytes)
        ctypes.POINTER(ctypes.c_uint8),                  # gmac (6 bytes)
        ctypes.c_int,                                    # total_workers
        ctypes.c_int64,                                  # start_index
        ctypes.c_int, ctypes.c_int,                      # shards, shard_id
        ctypes.c_int,                                    # batch_size
        ctypes.c_int,                                    # half_bits
        ctypes.c_uint32,                                 # feistel_mask
        ctypes.c_int,                                    # retries
        ctypes.c_int,                                    # is_udp
        ctypes.c_int,                                    # adaptive
        ctypes.POINTER(ctypes.c_uint64),                 # fail_ptr
        ctypes.POINTER(ctypes.c_uint8),                  # payloads (concatenated)
        ctypes.POINTER(ctypes.c_int),                    # payload_lens
        ctypes.c_int,                                    # num_payloads
        ctypes.c_int,                                    # is_icmp
    ]
    HAS_C_WORKER = True
except (OSError, AttributeError) as e:
    logger.warning("C worker (worker.so) not available, Python fallback will be used: %s", e)
    HAS_C_WORKER = False

# Linux capability bit for CAP_NET_RAW
_CAP_NET_RAW_BIT = 13

# consecutive blacklisted candidates a worker tolerates before assuming the
# blacklist covers the whole target space (kept in sync with worker.c)
MAX_BLACKLIST_ATTEMPTS = 10000

# SOL_PACKET level + PACKET_QDISC_BYPASS option: skip the qdisc layer so send
# buffers fill (and fail) instead of silently queueing — this is also what
# makes send failures a usable congestion signal for adaptive mode.
_SOL_PACKET = 263
_PACKET_QDISC_BYPASS = 21


def has_raw_socket_permission() -> bool:
    """Return True if the process can open raw sockets (root or CAP_NET_RAW)."""
    geteuid = getattr(os, 'geteuid', None)
    if geteuid is not None and geteuid() == 0:
        return True
    try:
        with open('/proc/self/status', 'r') as f:
            for line in f:
                if line.startswith('CapEff:'):
                    cap_eff = int(line.split()[1], 16)
                    return bool(cap_eff & (1 << _CAP_NET_RAW_BIT))
    except (OSError, ValueError, IndexError) as e:
        logger.debug("could not inspect capabilities: %s", e)
    return False


def ensure_raw_permissions() -> None:
    """Raise PermissionError unless raw socket access is available.

    reecanner cannot scan without raw sockets; failing fast with a clear
    message is better than silently sending zero packets.
    """
    if not has_raw_socket_permission():
        raise PermissionError(
            "reecanner requires raw socket access. Run as root or grant "
            "CAP_NET_RAW to the interpreter, e.g.: "
            "sudo setcap cap_net_raw+ep \"$(readlink -f \"$(which python3)\")\""
        )


def _read_iface_mac(iface: str) -> Optional[str]:
    try:
        with open(f"/sys/class/net/{iface}/address", 'r') as f:
            return f.read().strip()
    except OSError as e:
        logger.warning("could not read MAC address for %s: %s", iface, e)
        return None


def get_net_info() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Discover (iface, local_mac, gateway_mac) via iproute2, without a shell."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=5)
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("could not query default route: %s", e)
        return None, None, None

    parts = out.split()
    try:
        gw_ip = parts[parts.index("via") + 1]
        iface = parts[parts.index("dev") + 1]
    except (ValueError, IndexError):
        logger.warning("unexpected 'ip route show default' output: %r", out)
        return None, None, None

    local_mac = _read_iface_mac(iface)

    gw_mac: Optional[str] = None
    try:
        out = subprocess.check_output(["ip", "-j", "neigh", "show", gw_ip], text=True, timeout=5)
        for entry in json.loads(out):
            if entry.get("dst") == gw_ip and entry.get("lladdr"):
                gw_mac = entry["lladdr"]
                break
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as e:
        logger.warning("could not resolve gateway MAC for %s: %s", gw_ip, e)

    return iface, local_mac, gw_mac


def get_iface_net_info(iface: str) -> tuple[str, Optional[str], Optional[str]]:
    """Build net_info for an explicitly requested interface (--interface).

    Reads the MAC from sysfs and resolves a neighbor MAC (preferring the
    default gateway) via ``ip neigh`` on that interface.
    """
    local_mac = _read_iface_mac(iface)

    gw_mac: Optional[str] = None
    try:
        out = subprocess.check_output(["ip", "route", "show", "default", "dev", iface],
                                      text=True, timeout=5)
        parts = out.split()
        gw_ip = parts[parts.index("via") + 1] if "via" in parts else None
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("could not query default route for %s: %s", iface, e)
        gw_ip = None

    try:
        out = subprocess.check_output(["ip", "-j", "neigh", "show", "dev", iface],
                                      text=True, timeout=5)
        entries = json.loads(out)
        # prefer the default gateway's entry, then any entry with a MAC
        for entry in entries:
            if gw_ip and entry.get("dst") == gw_ip and entry.get("lladdr"):
                gw_mac = entry["lladdr"]
                break
        if gw_mac is None:
            for entry in entries:
                if entry.get("lladdr"):
                    gw_mac = entry["lladdr"]
                    break
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as e:
        logger.warning("could not resolve gateway MAC on %s: %s", iface, e)

    return iface, local_mac, gw_mac


def _check_raw_socket() -> Optional[str]:
    """Probe raw socket creation; return an error string or None on success."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return None
    except OSError as e:
        return str(e)


@dataclass
class WorkerConfig:
    """Everything a packet-sending worker needs, in one picklable bundle."""
    worker_id: int = 0
    local_ip_bytes: bytes = b'\x00' * 4
    ports: list = field(default_factory=lambda: [80])
    src_port: int = 61000
    rate_limit_array: object = None
    bl_mgr: Optional['BlacklistManager'] = None
    inc_mgr: Optional['InclusionManager'] = None
    run_event: object = None
    run_flag: object = None
    pps_array: object = None
    sent_array: object = None
    fail_array: object = None
    net_info: tuple = (None, None, None)
    total_workers: int = 1
    start_index: int = 0
    shards: int = 1
    shard_id: int = 0
    batch_size: int = 4096
    retries: int = 1
    is_udp: bool = False
    adaptive: bool = False
    is_icmp: bool = False
    udp_payloads: list = field(default_factory=lambda: [UDP_PAYLOADS['dns']])
    idx_array: object = None
    error_queue: object = None


def c_packet_worker(cfg: WorkerConfig) -> None:
    """Thin wrapper: extract Python data → call C run_worker"""
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    err = _check_raw_socket()
    if err is not None:
        if cfg.error_queue is not None:
            cfg.error_queue.put(f"worker {cfg.worker_id}: cannot open raw socket: {err}")
        return

    lip = (ctypes.c_uint8 * 4)(*cfg.local_ip_bytes)
    c_ports = (ctypes.c_uint16 * len(cfg.ports))(*cfg.ports)

    bl = cfg.bl_mgr._flat_ranges
    c_bl = (ctypes.c_uint32 * len(bl))(*bl) if bl else (ctypes.c_uint32 * 0)()

    c_keys = (ctypes.c_uint32 * 4)(*cfg.inc_mgr.shuffler.keys)
    total_ips = cfg.inc_mgr.total_ips
    nets = cfg.inc_mgr.networks
    c_bases = (ctypes.c_uint32 * len(nets))(*[n['net'] for n in nets])
    c_starts = (ctypes.c_uint32 * len(nets))(*[n['start'] for n in nets])

    iface, l_mac, g_mac = cfg.net_info
    c_iface = iface.encode() if iface else None
    c_lmac = c_gmac = None
    if iface and l_mac and g_mac:
        c_lmac = (ctypes.c_uint8 * 6)(*bytes.fromhex(l_mac.replace(':', '')))
        c_gmac = (ctypes.c_uint8 * 6)(*bytes.fromhex(g_mac.replace(':', '')))

    payloads = cfg.udp_payloads or [UDP_PAYLOADS['dns']]
    payload_blob = b''.join(payloads)
    c_payloads = (ctypes.c_uint8 * len(payload_blob))(*payload_blob)
    c_payload_lens = (ctypes.c_int * len(payloads))(*[len(p) for p in payloads])

    rate_limit_ptr = ctypes.cast(ctypes.addressof(cfg.rate_limit_array) + cfg.worker_id * 4,
                                 ctypes.POINTER(ctypes.c_int))

    _lib.run_worker(
        cfg.worker_id,
        lip,
        c_ports, len(cfg.ports),
        cfg.src_port,
        rate_limit_ptr,
        c_bl, len(bl),
        c_keys,
        total_ips,
        c_bases, c_starts, len(nets), 1 if cfg.inc_mgr.single_net else 0,
        ctypes.cast(ctypes.addressof(cfg.run_flag), ctypes.POINTER(ctypes.c_int)),
        ctypes.cast(ctypes.addressof(cfg.pps_array) + cfg.worker_id * 8, ctypes.POINTER(ctypes.c_uint64)),
        ctypes.cast(ctypes.addressof(cfg.sent_array) + cfg.worker_id * 8, ctypes.POINTER(ctypes.c_uint64)),
        c_iface, c_lmac, c_gmac,
        cfg.total_workers,
        cfg.start_index,
        cfg.shards, cfg.shard_id,
        cfg.batch_size,
        cfg.inc_mgr.shuffler.half_bits,
        cfg.inc_mgr.shuffler.mask,
        cfg.retries,
        1 if cfg.is_udp else 0,
        1 if cfg.adaptive else 0,
        ctypes.cast(ctypes.addressof(cfg.fail_array) + cfg.worker_id * 8, ctypes.POINTER(ctypes.c_uint64)),
        c_payloads, c_payload_lens, len(payloads),
        1 if cfg.is_icmp else 0,
    )


def packet_worker(cfg: WorkerConfig) -> None:
    """Pure-Python packet sending worker (fallback when worker.so is unavailable).

    Packet bytes come from reecanner.packet template builders; only the
    per-target fields are patched in the hot loop.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(os, 'sched_setaffinity'):
        try:
            os.sched_setaffinity(0, {cfg.worker_id % (os.cpu_count() or 1)})
        except OSError as e:
            logger.debug("sched_setaffinity failed for worker %d: %s", cfg.worker_id, e)
    iface, l_mac, g_mac = cfg.net_info
    try:
        if iface:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32*1024*1024)
            try:
                sock.setsockopt(_SOL_PACKET, _PACKET_QDISC_BYPASS, 1)
            except OSError as e:
                logger.debug("PACKET_QDISC_BYPASS not available: %s", e)
            sock.bind((iface, 0))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32*1024*1024)
        # non-blocking: a full send buffer must fail (congestion signal for
        # adaptive mode), not stall the worker inside the kernel
        sock.setblocking(False)
    except OSError as e:
        logger.error("worker %d failed to create send socket: %s", cfg.worker_id, e)
        if cfg.error_queue is not None:
            cfg.error_queue.put(f"worker {cfg.worker_id}: cannot open raw socket: {e}")
        return
    _send = sock.send
    _sendto = sock.sendto

    macs = None
    if iface:
        macs = (bytes.fromhex(g_mac.replace(':', '')), bytes.fromhex(l_mac.replace(':', '')))
    off = 14 if iface else 0

    if cfg.is_icmp:
        templates = [packet_mod.build_icmp_template(cfg.local_ip_bytes, macs)]
    elif cfg.is_udp:
        templates = [packet_mod.build_udp_template(cfg.local_ip_bytes, cfg.src_port, p, macs)
                     for p in (cfg.udp_payloads or [UDP_PAYLOADS['dns']])]
    else:
        templates = [packet_mod.build_syn_template(cfg.local_ip_bytes, cfg.src_port, macs)]
    single_template = len(templates) == 1

    run_event = cfg.run_event
    inc_mgr = cfg.inc_mgr
    bl_mgr = cfg.bl_mgr
    ports = cfg.ports
    total_workers = cfg.total_workers
    retries = cfg.retries
    batch_size = cfg.batch_size
    shards = cfg.shards
    shard_id = cfg.shard_id
    worker_id = cfg.worker_id
    pps_array = cfg.pps_array
    sent_array = cfg.sent_array
    fail_array = cfg.fail_array
    idx_array = cfg.idx_array

    current_index = cfg.start_index + worker_id
    get_ip = inc_mgr.get_random_ip_int
    is_pub = bl_mgr.is_ip_int_public
    ports_len = len(ports)
    total_work = inc_mgr.total_ips * ports_len * retries
    last_rate_limit = -1
    eff_batch = batch_size
    interval = 0
    if single_template:
        batch_msgs = [[bytearray(templates[0][0]), None if iface else (None, 0)]
                      for _ in range(batch_size)]
    else:
        batch_msgs = [[None, None if iface else (None, 0)] for _ in range(batch_size)]

    while run_event.is_set():
        start_time = time.perf_counter()
        rate_limit = cfg.rate_limit_array[worker_id]
        if rate_limit != last_rate_limit:
            last_rate_limit = rate_limit
            eff_batch = batch_size
            if rate_limit > 0:
                max_for_rate = max(1, (rate_limit + 9) // 10)
                eff_batch = min(eff_batch, max_for_rate)
                interval = eff_batch / rate_limit
            else:
                interval = 0
        batch_count = 0
        scan_done = False
        ip_idx = 0
        for i in range(eff_batch):
            if current_index >= total_work:
                scan_done = True
                break
            attempts = 0
            while True:
                if current_index >= total_work:
                    scan_done = True
                    break
                if shards > 1 and (current_index % shards) != shard_id:
                    current_index += total_workers
                    continue

                ip_idx = current_index // ports_len
                ip_int, _ = get_ip(ip_idx)
                current_index += total_workers
                if is_pub(ip_int): break
                attempts += 1
                if attempts > MAX_BLACKLIST_ATTEMPTS:
                    logger.warning("worker %d: blacklist covers target space, stopping", worker_id)
                    run_event.clear()
                    return
                if not run_event.is_set(): return
            if scan_done: break

            port_idx = (current_index - total_workers) % ports_len
            port = ports[port_idx]

            # probe payload: round-robin across target IPs (UDP multi-payload)
            tidx = 0 if single_template else ip_idx % len(templates)
            tmpl = templates[tidx]
            if single_template:
                buf = batch_msgs[i][0]
            else:
                buf = bytearray(tmpl[0])
                batch_msgs[i][0] = buf

            if cfg.is_icmp:
                packet_mod.patch_icmp(buf, off, ip_int, tmpl[1])
            elif cfg.is_udp:
                packet_mod.patch_udp(buf, off, ip_int, port, tmpl[1])
            else:
                packet_mod.patch_syn(buf, off, ip_int, port, tmpl[1], tmpl[2])

            if not iface:
                batch_msgs[i][1] = (f"{(ip_int>>24)&255}.{(ip_int>>16)&255}.{(ip_int>>8)&255}.{ip_int&255}", 0)
            batch_count += 1
        if batch_count > 0:
            sent_ok = 0
            for m in batch_msgs[:batch_count]:
                try:
                    if iface: _send(m[0])
                    else: _sendto(m[0], m[1])
                    sent_ok += 1
                except OSError as e:
                    # send failure (e.g. EAGAIN on a full buffer): primary
                    # congestion signal for adaptive mode
                    if fail_array is not None:
                        fail_array[worker_id] += 1
                    logger.debug("worker %d send failed: %s", worker_id, e)
            pps_array[worker_id] += sent_ok
            sent_array[worker_id] += sent_ok

        if idx_array is not None:
            idx_array[worker_id] = current_index

        # rate limit sleep with transmission compensation
        if interval > 0:
            duration = time.perf_counter() - start_time
            if duration < interval:
                w = interval - duration
                if w > 0.001:
                    time.sleep(w)
                else:
                    end_t = time.perf_counter() + w
                    while time.perf_counter() < end_t:
                        pass

        if scan_done: return


@dataclass
class Response:
    """A parsed response packet from a scanned host."""
    ip: str
    ip_int: int
    port: int
    proto: str  # 'tcp', 'udp' or 'icmp'
    ttl: int = 0
    window: int = 0
    mss: Optional[int] = None
    window_scale: Optional[int] = None
    timestamp: Optional[int] = None


def _parse_tcp_options(opts: bytes) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Extract (mss, window_scale, tsval) from raw TCP option bytes."""
    mss: Optional[int] = None
    wscale: Optional[int] = None
    tsval: Optional[int] = None
    i = 0
    n = len(opts)
    while i < n:
        kind = opts[i]
        if kind == 0:  # end of option list
            break
        if kind == 1:  # NOP
            i += 1
            continue
        if i + 1 >= n:
            break
        length = opts[i + 1]
        if length < 2 or i + length > n:
            break
        if kind == 2 and length == 4:
            mss = (opts[i + 2] << 8) | opts[i + 3]
        elif kind == 3 and length == 3:
            wscale = opts[i + 2]
        elif kind == 8 and length == 10:
            tsval = struct.unpack('!I', opts[i + 2:i + 6])[0]
        i += length
    return mss, wscale, tsval


def parse_response(data: bytes, src_port: int, udp: bool = False,
                   icmp: bool = False,
                   local_ip_int: Optional[int] = None) -> Optional[Response]:
    """Pure packet parsing: return a Response for a relevant reply, else None.

    TCP: only SYN-ACK packets whose destination port is our source port;
    MSS/window-scale/timestamp are extracted from the TCP options.
    UDP: any datagram whose destination port is our source port (covers all
    UDP probe types — DNS, NTP, SNMP, SSDP, memcached).
    ICMP: echo replies (type 0).

    When ``local_ip_int`` is given, packets not addressed to us are rejected
    (filters unrelated backscatter that happens to hit our source port).
    """
    if len(data) < 20:
        return None
    if data[0] >> 4 != 4:
        return None
    iph_len = (data[0] & 0x0F) << 2
    if iph_len < 20:
        return None
    if local_ip_int is not None:
        dst = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19]
        if dst != local_ip_int:
            return None
    ip_int = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]
    ip_str = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
    if icmp:
        if len(data) < iph_len + 8:
            return None
        if data[iph_len] != 0:  # echo reply only
            return None
        return Response(ip=ip_str, ip_int=ip_int, port=0, proto='icmp', ttl=data[8])
    if udp:
        if len(data) < iph_len + 8:
            return None
        dp = (data[iph_len + 2] << 8) | data[iph_len + 3]
        if dp != src_port:
            return None
        sp = (data[iph_len] << 8) | data[iph_len + 1]
        return Response(ip=ip_str, ip_int=ip_int, port=sp, proto='udp', ttl=data[8])
    if len(data) < iph_len + 20:
        return None
    dp = (data[iph_len + 2] << 8) | data[iph_len + 3]
    if dp != src_port:
        return None
    if (data[iph_len + 13] & 0x12) != 0x12:  # SYN+ACK
        return None
    sp = (data[iph_len] << 8) | data[iph_len + 1]
    window = (data[iph_len + 14] << 8) | data[iph_len + 15]
    mss = wscale = tsval = None
    tcp_hdr_len = ((data[iph_len + 12] >> 4) & 0xF) << 2
    if tcp_hdr_len > 20 and len(data) >= iph_len + tcp_hdr_len:
        mss, wscale, tsval = _parse_tcp_options(data[iph_len + 20:iph_len + tcp_hdr_len])
    return Response(
        ip=ip_str, ip_int=ip_int, port=sp, proto='tcp', ttl=data[8], window=window,
        mss=mss, window_scale=wscale, timestamp=tsval,
    )


class ResultSink:
    """Handles all per-hit output: buffered stdout, result queue, streaming JSONL, probe queue.

    stdout lines are buffered and flushed every FLUSH_LINES lines or
    FLUSH_INTERVAL seconds, whichever comes first.
    """

    FLUSH_LINES = 50
    FLUSH_INTERVAL = 0.1

    def __init__(self, quiet: bool = False, simple: bool = False, no_port: bool = False,
                 use_color: bool = False, results_queue=None, probe_queue=None,
                 stream_path: Optional[str] = None):
        self.quiet = quiet
        self.simple = simple
        self.no_port = no_port
        self.results_queue = results_queue
        self.probe_queue = probe_queue
        self._buf: list = []
        self._last_flush = time.monotonic()
        self._stream = None
        if stream_path:
            try:
                self._stream = open(stream_path, 'a', buffering=1)  # line buffered
            except OSError as e:
                logger.warning("could not open streaming output %s: %s", stream_path, e)

    def _queue_out(self, text: str) -> None:
        self._buf.append(text)
        if len(self._buf) >= self.FLUSH_LINES:
            self.flush_pending(force=True)

    def flush_pending(self, force: bool = False) -> None:
        """Flush buffered stdout lines when the batch is full, stale, or forced."""
        if not self._buf:
            self._last_flush = time.monotonic()
            return
        if force or (time.monotonic() - self._last_flush) >= self.FLUSH_INTERVAL:
            try:
                sys.stdout.write(''.join(self._buf))
                sys.stdout.flush()
            except OSError as e:
                logger.debug("stdout flush failed: %s", e)
            self._buf.clear()
            self._last_flush = time.monotonic()

    def emit(self, resp: Response) -> None:
        """Record and display one newly discovered host."""
        record: dict = {'ip': resp.ip, 'port': resp.port, 'proto': resp.proto}
        svc = ""
        if resp.proto in ('tcp', 'udp'):
            if resp.proto == 'tcp':
                try:
                    os_guess = guess_os(resp.ttl, resp.window, resp.mss,
                                        resp.window_scale, resp.timestamp is not None)
                except (ValueError, KeyError, AttributeError) as e:
                    logger.debug("OS fingerprint failed: %s", e)
                    os_guess = ""
                if os_guess:
                    record['os'] = os_guess
            try:
                svc = get_service_name(resp.port)
            except (ValueError, KeyError, AttributeError) as e:
                logger.debug("service lookup failed for port %d: %s", resp.port, e)
                svc = ""
        if svc:
            record['service'] = svc

        if not self.quiet:
            if self.simple:
                out = f"{resp.ip}\n" if (self.no_port or resp.proto == 'icmp') else f"{resp.ip}:{resp.port}\n"
                if sys.stderr.isatty():
                    self._queue_out(f"\r\033[K{out}")
                else:
                    self._queue_out(out)
            else:
                if resp.proto == 'icmp':
                    self._queue_out(f"\r\033[K{resp.ip:<16}  icmp echo\n")
                elif resp.proto == 'udp':
                    port_str = f":{resp.port}/udp" if not self.no_port else ""
                    self._queue_out(f"\r\033[K{resp.ip:<16}{port_str}\n")
                else:
                    port_str = f":{resp.port:<6}" if not self.no_port else ""
                    parts = [f"{resp.ip:<16}{port_str}"]
                    if svc:
                        parts.append(svc)
                    self._queue_out(f"\r\033[K{'  '.join(parts)}\n")
            self.flush_pending()

        if self.results_queue is not None:
            try:
                self.results_queue.put_nowait(record)
            except (queue.Full, OSError):
                logger.debug("results queue unavailable, dropping %s:%d", resp.ip, resp.port)

        if self.probe_queue is not None and resp.port > 0:
            try:
                self.probe_queue.put_nowait((resp.ip, resp.port))
            except (queue.Full, OSError):
                logger.debug("probe queue full, dropping probe for %s:%d", resp.ip, resp.port)

        if self._stream is not None:
            try:
                self._stream.write(json.dumps(record) + "\n")
            except OSError as e:
                logger.warning("streaming output write failed: %s", e)

    def close(self) -> None:
        self.flush_pending(force=True)
        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                pass
            self._stream = None


def _register_hit(resp: Response, seen_hosts: set, found_count, limit: int,
                  run_event, run_flag) -> str:
    """Dedupe and count a response. Returns 'new', 'dup' or 'limit'."""
    host_key = (resp.ip_int << 16) | (resp.port & 0xFFFF)
    if host_key in seen_hosts:
        return 'dup'
    seen_hosts.add(host_key)
    hit_limit = False
    with found_count.get_lock():
        found_count.value += 1
        if limit > 0 and found_count.value >= limit:
            hit_limit = True
    if hit_limit:
        run_event.clear()
        if run_flag is not None:
            run_flag.value = 0
        return 'limit'
    return 'new'


def process_packet(data: bytes, src_port: int, seen_hosts: set, found_count,
                   sink: ResultSink, run_event, limit: int, udp: bool = False,
                   run_flag=None, icmp: bool = False,
                   local_ip_int: Optional[int] = None) -> None:
    """Handle one captured packet: parse, dedupe, count, emit to the sink."""
    if not run_event.is_set():
        return
    # Extra safety: check limit again before processing
    if limit > 0 and found_count.value >= limit:
        run_event.clear()
        if run_flag is not None:
            run_flag.value = 0
        return
    resp = parse_response(data, src_port, udp=udp, icmp=icmp,
                          local_ip_int=local_ip_int)
    if resp is None:
        return
    status = _register_hit(resp, seen_hosts, found_count, limit, run_event, run_flag)
    if status == 'dup':
        return
    sink.emit(resp)


def _attach_bpf(sock: socket.socket, insns: list) -> None:
    """Attach a classic BPF program (list of packed sock_filter structs)."""
    bpf_program = b''.join(insns)
    fprog = struct.pack('HL', len(insns), struct.unpack('L', struct.pack('P', bpf_program))[0])
    # SO_ATTACH_FILTER = 26
    sock.setsockopt(socket.SOL_SOCKET, 26, fprog)


def sniffer_process(src_port, run_event, found_count, quiet, use_color, limit, simple=False,
                    run_flag=None, sniffer_ready=None, resolve=False, results_queue=None,
                    probe_queue=None, udp=False, no_port=False, error_queue=None,
                    stream_path=None, icmp=False, local_ip_int=None):
    """Raw-socket sniffer process. Filters replies and emits hits.

    Reports socket creation failures to the parent via error_queue and always
    sets sniffer_ready so the parent never blocks forever waiting on startup.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        if icmp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        elif udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64*1024*1024)

        # BPF Filter: kernel-level filtering so Python never sees unrelated traffic.
        try:
            if icmp:
                # ICMP type at offset 20 (IPv4 header without options): echo reply = 0
                bpf_insns = [
                    struct.pack('HHIB', 0x30, 0, 0, 20),          # ldb [20]
                    struct.pack('HHIB', 0x15, 0, 1, 0),           # jeq 0, KEEP, DROP
                    struct.pack('HHIB', 0x06, 0, 0, 0x00040000),  # KEEP: ret 0x40000
                    struct.pack('HHIB', 0x06, 0, 0, 0)            # DROP: ret 0
                ]
            elif udp:
                # UDP: dst port at offset 22
                bpf_insns = [
                    struct.pack('HHIB', 0x28, 0, 0, 22),       # ldh [22]
                    struct.pack('HHIB', 0x15, 0, 1, src_port), # jeq src_port, K, D
                    struct.pack('HHIB', 0x06, 0, 0, 0x00040000), # K: ret 0x40000
                    struct.pack('HHIB', 0x06, 0, 0, 0)          # D: ret 0
                ]
            else:
                # TCP: dst port at offset 22, flags at offset 33
                bpf_insns = [
                    struct.pack('HHIB', 0x28, 0, 0, 22),       # ldh [22]
                    struct.pack('HHIB', 0x15, 0, 4, src_port), # jeq src_port, NEXT, DROP
                    struct.pack('HHIB', 0x30, 0, 0, 33),       # ldb [33]
                    struct.pack('HHIB', 0x54, 0, 0, 0x12),     # and 0x12
                    struct.pack('HHIB', 0x15, 0, 1, 0x12),     # jeq 0x12, KEEP, DROP
                    struct.pack('HHIB', 0x06, 0, 0, 0x00040000), # KEEP: ret 0x40000
                    struct.pack('HHIB', 0x06, 0, 0, 0)          # DROP: ret 0
                ]
            _attach_bpf(sock, bpf_insns)
        except (OSError, struct.error) as e:
            logger.debug("BPF attach failed, falling back to software filtering: %s", e)

    except OSError as e:
        logger.error("sniffer failed to create raw socket: %s", e)
        if error_queue is not None:
            error_queue.put(f"sniffer: cannot open raw socket: {e}")
        if sniffer_ready:
            sniffer_ready.set()
        return

    if sniffer_ready:
        sniffer_ready.set()

    sink = ResultSink(quiet=quiet, simple=simple, no_port=no_port, use_color=use_color,
                      results_queue=results_queue, probe_queue=probe_queue,
                      stream_path=stream_path)
    seen_hosts = set()

    def _handle(data: bytes) -> None:
        process_packet(data, src_port, seen_hosts, found_count, sink,
                       run_event, limit, udp=udp, run_flag=run_flag, icmp=icmp,
                       local_ip_int=local_ip_int)

    sock.settimeout(0.1)
    try:
        while run_event.is_set():
            try:
                data, _ = sock.recvfrom(65535)
                _handle(data)
                # drain the burst without returning to the timeout wait:
                # after the first packet of a burst arrives, keep pulling
                # with MSG_DONTWAIT until the kernel queue is empty
                while run_event.is_set():
                    try:
                        data, _ = sock.recvfrom(65535, socket.MSG_DONTWAIT)
                    except (BlockingIOError, InterruptedError):
                        break
                    _handle(data)
                sink.flush_pending()
            except socket.timeout:
                sink.flush_pending()
                continue
            except OSError as e:
                logger.debug("sniffer recv error: %s", e)
                continue
    finally:
        sink.close()
        sock.close()


@dataclass
class ScannerConfig:
    """Configuration for a Scanner run."""
    ports: list = field(default_factory=lambda: [80])
    rate_limit: int = 1000
    blacklist_manager: Optional['BlacklistManager'] = None
    inclusion_manager: Optional['InclusionManager'] = None
    source_port: Optional[int] = None
    workers: Optional[int] = None
    limit: int = 0
    quiet: bool = False
    start_index: int = 0
    shards: int = 1
    shard_id: int = 0
    checkpoint_file: Optional[str] = None
    simple: bool = False
    batch_size: int = 4096
    retries: int = 1
    resolve: bool = False
    banners: bool = False
    http_probe: bool = False
    vulns: bool = False
    udp: bool = False
    adaptive: bool = False
    adaptive_grace: float = 10.0
    udp_payload: str = 'auto'
    ping_sweep: bool = False
    net_info: Optional[tuple] = None
    user_agent: str = 'reecanner/1.0'
    no_port: bool = False
    redis_url: Optional[str] = None
    wait: float = 3.0
    output_append: Optional[str] = None
    status_json: Optional[str] = None


class Scanner:
    """High-speed SYN/UDP/ICMP scanner orchestrating send workers, a sniffer and probes.

    Accepts a ScannerConfig or plain keyword arguments matching its fields,
    e.g. ``Scanner(ports=[80, 443], rate_limit=5000, inclusion_manager=inc,
    blacklist_manager=bl)``.

    Checkpoint imprecision: the resume index is the minimum of the per-worker
    frontier indices (pure Python worker), i.e. conservative — a tail slice
    of targets may be rescanned but none are skipped. The C worker does not
    report its internal index, so in that case the checkpoint falls back to
    ``start_index + total_sent``, which is likewise conservative (blacklisted
    and shard-skipped indices are not counted as sent).
    """

    # adaptive rate controller constants
    ADAPT_INTERVAL = 5.0       # seconds between rate decisions
    ADAPT_CLEAR_WINDOWS = 2    # consecutive clear windows (10s) before ramping up
    ADAPT_MIN_RATE = 100

    def __init__(self, config: Optional[ScannerConfig] = None, **kwargs):
        if config is None:
            config = ScannerConfig()
        if kwargs:
            unknown = set(kwargs) - {f.name for f in dataclasses.fields(ScannerConfig)}
            if unknown:
                raise TypeError(f"unknown Scanner arguments: {sorted(unknown)}")
            config = dataclasses.replace(config, **kwargs)
        self.config = config
        self.ports = [0] if config.ping_sweep else config.ports
        self.rate_limit = config.rate_limit
        self.bl_mgr = config.blacklist_manager
        self.inc_mgr = config.inclusion_manager
        if self.inc_mgr is None or self.bl_mgr is None:
            raise ValueError(
                "Scanner requires inclusion_manager and blacklist_manager; "
                "build them with reecanner.utils.InclusionManager / BlacklistManager"
            )
        self.src_port = config.source_port or (int(time.time()) % 29000 + 10000)
        self.local_ip = self._get_local_ip()
        self.local_ip_bytes = socket.inet_aton(self.local_ip)
        self.workers_count = config.workers or multiprocessing.cpu_count()
        self.limit = config.limit
        self.quiet = config.quiet
        self.simple = config.simple
        self.wait = config.wait
        self.output_append = config.output_append
        self.status_json = config.status_json
        self.user_agent = config.user_agent
        self.run_event = multiprocessing.Event()
        self.run_event.set()
        self.run_flag = multiprocessing.RawValue(ctypes.c_int, 1)
        self.found_count = multiprocessing.Value('i', 0)

        self.pps_array = multiprocessing.RawArray(ctypes.c_uint64, self.workers_count)
        self.sent_array = multiprocessing.RawArray(ctypes.c_uint64, self.workers_count)
        self.fail_array = multiprocessing.RawArray(ctypes.c_uint64, self.workers_count)
        self.cur_idx_array = multiprocessing.RawArray(ctypes.c_uint64, self.workers_count)
        self.error_queue = multiprocessing.Queue()

        self.net_info = config.net_info or get_net_info()
        self.seed = self.inc_mgr.shuffler.seed
        self.start_index = config.start_index
        self.shards = config.shards
        self.shard_id = config.shard_id
        self.checkpoint_file = config.checkpoint_file
        self.batch_size = config.batch_size
        self.retries = config.retries
        self.resolve = config.resolve
        self.banners = config.banners
        self.http_probe = config.http_probe
        self.vulns = config.vulns
        self.udp = config.udp
        self.ping_sweep = config.ping_sweep
        if config.udp_payload == 'auto':
            self.udp_payloads = [UDP_PAYLOADS[k] for k in UDP_PAYLOAD_ORDER]
        else:
            self.udp_payloads = [UDP_PAYLOADS[config.udp_payload]]
        # the C worker supports at most 16 payloads; cap here so both engines agree
        if len(self.udp_payloads) > 16:
            logger.warning("too many UDP payloads (%d); using only the first 16",
                           len(self.udp_payloads))
            self.udp_payloads = self.udp_payloads[:16]
        self.adaptive = config.adaptive
        self.adaptive_grace = config.adaptive_grace
        self.initial_rate_limit = config.rate_limit
        self.rate_limit_array = multiprocessing.RawArray(ctypes.c_int, self.workers_count)
        self.no_port = config.no_port
        self.redis_url = config.redis_url
        self.total_work = self.inc_mgr.total_ips * len(self.ports) * self.retries
        self.use_c = HAS_C_WORKER
        # results flow: sniffer -> multiprocessing.Queue -> drainer thread -> local list
        self._results: list = []
        self._results_queue = multiprocessing.Queue()
        self._results_stop = threading.Event()
        self._drain_thread: Optional[threading.Thread] = None
        self._probe_queue = multiprocessing.Queue() if (config.banners or config.http_probe or config.vulns or config.resolve or config.redis_url) else None
        # adaptive controller state
        self._adapt_last = 0.0
        self._adapt_clear_streak = 0
        self._last_fail_total = 0
        self._last_pps_sum = 0

    def _get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def _drain_errors(self) -> list:
        errors = []
        while True:
            try:
                errors.append(self.error_queue.get_nowait())
            except queue.Empty:
                break
        return errors

    def _drain_results(self) -> None:
        """Drainer thread body: move records from the results queue to the local list."""
        while not self._results_stop.is_set():
            try:
                self._results.append(self._results_queue.get(timeout=0.2))
            except queue.Empty:
                continue
            except (EOFError, OSError):
                break
        # final drain once the sniffer has exited
        while True:
            try:
                self._results.append(self._results_queue.get_nowait())
            except queue.Empty:
                break
            except (EOFError, OSError):
                break

    def _start_drainer(self) -> None:
        self._results_stop.clear()
        self._drain_thread = threading.Thread(target=self._drain_results, daemon=True)
        self._drain_thread.start()

    def _stop_drainer(self) -> None:
        self._results_stop.set()
        if self._drain_thread is not None:
            self._drain_thread.join(timeout=2.0)
            self._drain_thread = None

    def _checkpoint_index(self) -> int:
        """Conservative resume index (see Scanner docstring for imprecision).

        Uses the minimum of the per-worker frontier indices: slow workers are
        never leapfrogged, so a tail slice may be rescanned but no target is
        skipped.
        """
        idxs = [i for i in self.cur_idx_array if i > 0]
        if idxs:
            return min(idxs)
        return self.start_index + sum(self.sent_array)

    def _save_checkpoint(self) -> None:
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump({"index": self._checkpoint_index(), "seed": self.seed}, f)
        except OSError as e:
            logger.warning("could not write checkpoint file %s: %s", self.checkpoint_file, e)

    def _write_status_json(self, sent_total: int, found_total: int,
                           curr_pps: float, start_time: float) -> None:
        """Atomically write the --status-json monitoring file (temp + rename)."""
        pct = min(100.0, sent_total / self.total_work * 100) if self.total_work > 0 else 0.0
        remaining = max(0, self.total_work - sent_total)
        eta = remaining / curr_pps if curr_pps > 0 else None
        payload = {
            "sent": sent_total,
            "found": found_total,
            "pps": round(curr_pps, 1),
            "eta": round(eta, 1) if eta is not None else None,
            "progress_pct": round(pct, 2),
            "elapsed": round(time.time() - start_time, 1),
            "rate_limit": self.rate_limit,
        }
        tmp_path = self.status_json + ".tmp"
        try:
            with open(tmp_path, 'w') as f:
                json.dump(payload, f)
            os.replace(tmp_path, self.status_json)
        except OSError as e:
            logger.warning("could not write status json %s: %s", self.status_json, e)

    def _per_worker_rate(self) -> int:
        """Per-worker pps. 0 means unlimited; any positive target rate maps to
        at least 1 pps per worker so small rates can never collapse to 0
        (which the workers interpret as unlimited)."""
        if self.rate_limit <= 0:
            return 0
        return max(1, self.rate_limit // self.workers_count)

    def _set_rate_limit(self, new_limit: int) -> None:
        """Update the total target rate and fan it out to per-worker slots."""
        self.rate_limit = new_limit
        rpw = self._per_worker_rate()
        for idx in range(self.workers_count):
            self.rate_limit_array[idx] = rpw

    def _adaptive_tick(self, now: float, start_time: float, curr_pps: float,
                       last_warning_time: float) -> float:
        """One adaptive-rate step. Returns the updated last_warning_time.

        Congestion signal: send failures reported by the workers (send
        returning EAGAIN/ENOBUFS on the non-blocking sockets), not raw
        throughput. Decisions are made every ADAPT_INTERVAL seconds with
        hysteresis: -20% on congestion, +10% only after ADAPT_CLEAR_WINDOWS
        consecutive clear windows.
        """
        if now - start_time <= self.adaptive_grace:
            return last_warning_time
        if now - self._adapt_last < self.ADAPT_INTERVAL:
            return last_warning_time
        self._adapt_last = now

        fail_total = sum(self.fail_array)
        fails = fail_total - self._last_fail_total
        self._last_fail_total = fail_total

        if fails > 0:
            new_limit = max(self.ADAPT_MIN_RATE, int(self.rate_limit * 0.8))
            if new_limit < self.rate_limit:
                self._set_rate_limit(new_limit)
                self._adapt_clear_streak = 0
                logger.info("adaptive: %d send failures in window; reducing rate to %d pps",
                            fails, self.rate_limit)
                if now - last_warning_time > 10.0:
                    sys.stderr.write(f"\n[!] adaptive: send errors detected. Adapting target rate to {self.rate_limit} pps\033[K\n")
                    sys.stderr.flush()
                    last_warning_time = now
        else:
            self._adapt_clear_streak += 1
            if (self._adapt_clear_streak >= self.ADAPT_CLEAR_WINDOWS
                    and self.rate_limit < self.initial_rate_limit):
                new_limit = min(self.initial_rate_limit,
                                max(int(self.rate_limit * 1.1), self.rate_limit + 1))
                if new_limit > self.rate_limit:
                    self._set_rate_limit(new_limit)
                    logger.info("adaptive: path clear for %ds; increasing rate to %d pps",
                                self._adapt_clear_streak * int(self.ADAPT_INTERVAL),
                                self.rate_limit)
                    if now - last_warning_time > 10.0:
                        sys.stderr.write(f"\n[*] adaptive: path clear. Adapting target rate to {self.rate_limit} pps\033[K\n")
                        sys.stderr.flush()
                        last_warning_time = now
        return last_warning_time

    def _render_progress(self, sent_total: int, found_total: int,
                         curr_pps: float, pct: float, final: bool = False) -> None:
        """Render the one-line progress bar to stderr."""
        sent_fmt = f"{sent_total:,}".replace(',', '.')
        filled = int(pct / 5)
        bar = '█' * filled + '░' * (20 - filled)
        if final:
            sys.stderr.write(f"\r[{bar}] {pct:5.1f}% | {sent_fmt} sent | found: {found_total}\033[K\n")
        else:
            pps_fmt = f"{curr_pps:,.0f}".replace(',', '.')
            if curr_pps > 0 and sent_total < self.total_work:
                eta_s = (self.total_work - sent_total) / curr_pps
                eta_str = f" | eta: {eta_s/60:.1f}m" if eta_s >= 60 else f" | eta: {eta_s:.0f}s"
            else:
                eta_str = ""
            sys.stderr.write(f"\r[{bar}] {pct:5.1f}% | {sent_fmt} sent @ {pps_fmt} pps | found: {found_total}{eta_str}\033[K")
        sys.stderr.flush()

    def run(self, console=None):
        """Run the scan. Requires root or CAP_NET_RAW (see ensure_raw_permissions).

        Returns the list of result dicts (same as calling get_results());
        returns an empty list on startup failure.
        """
        ensure_raw_permissions()

        if console is None:
            class DummyConsole:
                no_color = True
                def print(self, *args, **kwargs): pass
            console = DummyConsole()

        # start probe engine if needed
        probe_engine = None
        if self.banners or self.http_probe or self.vulns or self.resolve:
            from reecanner.probes import ProbeEngine
            probe_engine = ProbeEngine(do_banners=self.banners, do_http=self.http_probe, do_vulns=self.vulns, do_resolve=self.resolve, use_color=not console.no_color, quiet=self.quiet, simple=self.simple, user_agent=self.user_agent)
            probe_engine.start()

        redis_client = None
        if self.redis_url:
            try:
                import redis
            except ImportError:
                console.print("[bold red][!][/bold red] redis package not installed. install with: pip install reecanner[redis]")
                logger.error("redis support requested but the redis package is not installed")
                if probe_engine:
                    probe_engine.stop()
                return []
            try:
                redis_client = redis.Redis.from_url(self.redis_url)
                redis_client.ping()
                console.print(f"[bold green][*][/bold green] connected to redis: [cyan]{self.redis_url}[/cyan]")
            except Exception as e:
                console.print(f"[bold red][!][/bold red] failed to connect to redis: {e}")
                if probe_engine:
                    probe_engine.stop()
                return []

        self._start_drainer()

        sniffer_ready = multiprocessing.Event()
        sniff_p = multiprocessing.Process(target=sniffer_process, args=(
            self.src_port, self.run_event, self.found_count,
            self.quiet, not console.no_color, self.limit, self.simple,
            self.run_flag, sniffer_ready, self.resolve, self._results_queue,
            self._probe_queue, self.udp, self.no_port, self.error_queue,
            self.output_append, self.ping_sweep,
            struct.unpack('!I', self.local_ip_bytes)[0],
        ))
        sniff_p.start()
        sniffer_ready.wait(timeout=5.0)  # wait for the sniffer to be ready
        if not sniff_p.is_alive():
            errors = self._drain_errors()
            detail = f": {'; '.join(errors)}" if errors else ""
            console.print(f"[bold red][!][/bold red] sniffer process failed to start{detail}")
            logger.error("sniffer process died during startup%s", detail)
            if probe_engine:
                probe_engine.stop()
            self._stop_drainer()
            return []

        rpw = self._per_worker_rate()
        for i in range(self.workers_count):
            self.rate_limit_array[i] = rpw
        procs = []
        if self.use_c:
            for i in range(self.workers_count):
                wcfg = WorkerConfig(
                    worker_id=i, local_ip_bytes=self.local_ip_bytes, ports=self.ports,
                    src_port=self.src_port, rate_limit_array=self.rate_limit_array,
                    bl_mgr=self.bl_mgr, inc_mgr=self.inc_mgr, run_flag=self.run_flag,
                    pps_array=self.pps_array, sent_array=self.sent_array,
                    fail_array=self.fail_array, net_info=self.net_info,
                    total_workers=self.workers_count, start_index=self.start_index,
                    shards=self.shards, shard_id=self.shard_id, batch_size=self.batch_size,
                    retries=self.retries, is_udp=self.udp, adaptive=self.adaptive,
                    is_icmp=self.ping_sweep, udp_payloads=self.udp_payloads,
                    error_queue=self.error_queue,
                )
                p = multiprocessing.Process(target=c_packet_worker, args=(wcfg,))
                p.start()
                procs.append(p)
        else:
            console.print("[bold yellow][*][/bold yellow] C worker not available, using Python fallback")
            for i in range(self.workers_count):
                wcfg = WorkerConfig(
                    worker_id=i, local_ip_bytes=self.local_ip_bytes, ports=self.ports,
                    src_port=self.src_port, rate_limit_array=self.rate_limit_array,
                    bl_mgr=self.bl_mgr, inc_mgr=self.inc_mgr, run_event=self.run_event,
                    pps_array=self.pps_array, sent_array=self.sent_array,
                    fail_array=self.fail_array, net_info=self.net_info,
                    total_workers=self.workers_count, start_index=self.start_index,
                    shards=self.shards, shard_id=self.shard_id, batch_size=self.batch_size,
                    retries=self.retries, is_udp=self.udp, adaptive=self.adaptive,
                    is_icmp=self.ping_sweep, udp_payloads=self.udp_payloads,
                    idx_array=self.cur_idx_array, error_queue=self.error_queue,
                )
                p = multiprocessing.Process(target=packet_worker, args=(wcfg,))
                p.start()
                procs.append(p)

        # give workers a moment to fail fast on socket errors
        time.sleep(0.3)
        errors = self._drain_errors()
        if errors:
            for e in errors:
                console.print(f"[bold red][!][/bold red] {e}")
                logger.error("worker startup failure: %s", e)
            self.run_flag.value = 0
            self.run_event.clear()
            for p in procs + [sniff_p]:
                p.join(timeout=0.5)
                if p.is_alive():
                    p.terminate()
            if probe_engine:
                probe_engine.stop()
            self._stop_drainer()
            return []

        start_time = time.time()
        self._adapt_last = start_time
        last_pps_check = start_time
        sys.stderr.write("\n")

        last_checkpoint_time = time.time()
        last_status_time = time.time()
        grace_period = self.wait  # masscan-style: linger for late responses after sending ends
        grace_start = None
        curr_pps = 0.0
        interrupted = False
        last_warning_time = 0
        try:
            while self.run_event.is_set() and self.run_flag.value:
                time.sleep(0.1)

                errors = self._drain_errors()
                if errors:
                    for e in errors:
                        console.print(f"[bold red][!][/bold red] {e}")
                        logger.error("worker failure during scan: %s", e)
                    interrupted = True
                    break

                if self._probe_queue:
                    pending_redis = []
                    while not self._probe_queue.empty():
                        try:
                            ip, port = self._probe_queue.get_nowait()
                        except queue.Empty:
                            break
                        if redis_client:
                            pending_redis.append(f"{ip}:{port}")
                        elif probe_engine:
                            probe_engine.submit(ip, port)
                    # one round-trip per tick instead of one per host —
                    # a slow redis must not stall the monitor loop
                    if pending_redis:
                        try:
                            redis_client.rpush("reecanner:queue", *pending_redis)
                        except Exception as e:
                            logger.warning("failed to push %d hosts to redis: %s",
                                           len(pending_redis), e)

                # check whether all send workers have finished
                if grace_start is None and all(not p.is_alive() for p in procs):
                    grace_start = time.time()
                    # final progress update
                    sent_total = sum(self.sent_array)
                    found_total = self.found_count.value
                    pct = min(100.0, sent_total / self.total_work * 100) if self.total_work > 0 else 100.0
                    if not self.simple and not self.quiet:
                        self._render_progress(sent_total, found_total, 0, pct, final=True)
                        sys.stderr.write(f"[*] scan complete, waiting {grace_period:.0f}s for responses...\n")
                        sys.stderr.flush()

                if grace_start and (time.time() - grace_start >= grace_period):
                    break

                # pps calculation: pps_array is cumulative (never reset) so
                # there is no lost-increment race with the workers
                now = time.time()
                elapsed = now - last_pps_check
                if elapsed >= 1.0:
                    pps_sum = sum(self.pps_array)
                    curr_pps = (pps_sum - self._last_pps_sum) / elapsed
                    self._last_pps_sum = pps_sum
                    last_pps_check = now

                    if self.checkpoint_file and (now - last_checkpoint_time > 10.0):
                        self._save_checkpoint()
                        last_checkpoint_time = now

                    if self.status_json and (now - last_status_time >= 10.0):
                        self._write_status_json(sum(self.sent_array), self.found_count.value,
                                                curr_pps, start_time)
                        last_status_time = now

                    if self.adaptive:
                        last_warning_time = self._adaptive_tick(now, start_time, curr_pps,
                                                                last_warning_time)

                # progress bar every tick
                if grace_start is None:
                    sent_total = sum(self.sent_array)
                    found_total = self.found_count.value
                    pct = min(100.0, sent_total / self.total_work * 100) if self.total_work > 0 else 0
                    if not self.simple and not self.quiet:
                        self._render_progress(sent_total, found_total, curr_pps, pct)
        except KeyboardInterrupt:
            interrupted = True
            self.run_flag.value = 0
            self.run_event.clear()
        except Exception:
            logger.exception("scan monitor loop failed")
            interrupted = True
            self.run_flag.value = 0
            self.run_event.clear()

        # drain probe queue and shut the probe engine down (always — even
        # when the queue was never created, e.g. vulns-only library configs)
        if probe_engine:
            if self._probe_queue:
                while not self._probe_queue.empty():
                    try:
                        ip, port = self._probe_queue.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        probe_engine.submit(ip, port)
                    except Exception as e:
                        logger.warning("failed to drain probe queue: %s", e)
                        break
            if not interrupted and not probe_engine.queue.empty():
                if not self.simple and not self.quiet:
                    sys.stderr.write(f"\r[*] waiting for {probe_engine.queue.qsize()} pending probes to finish...\033[K\n")
                    sys.stderr.flush()
            probe_engine.stop(force=interrupted)
            self._probe_engine_results = list(probe_engine.results)

        total_duration = time.time() - start_time
        sent_total = sum(self.sent_array)
        avg_pps = sent_total / total_duration if total_duration > 0 else 0
        sent_fmt = f"{sent_total:,}".replace(',', '.')
        pps_fmt = f"{avg_pps:,.0f}".replace(',', '.')
        if not self.simple and not self.quiet:
            sys.stderr.write(f"\r[*] sent: {sent_fmt} | rate: {pps_fmt} pps | found: {self.found_count.value} | next index: {self._checkpoint_index()}\033[K\n")
            sys.stderr.flush()

        if self.checkpoint_file:
            self._save_checkpoint()

        if self.status_json:
            self._write_status_json(sent_total, self.found_count.value, avg_pps, start_time)

        self.run_flag.value = 0
        self.run_event.clear()
        try:
            for p in procs + [sniff_p]:
                p.join(timeout=0.2)

            # force-terminate any remaining processes
            for p in procs + [sniff_p]:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=0.1)
        except KeyboardInterrupt:
            for p in procs + [sniff_p]:
                if p.is_alive():
                    p.terminate()
        except Exception as e:
            logger.debug("error while joining worker processes: %s", e)

        self._stop_drainer()

        # rich summary table
        if not self.quiet and not self.simple:
            try:
                self._print_summary_table(console, probe_engine)
            except KeyboardInterrupt:
                pass

        return self.get_results()

    def _print_summary_table(self, console, probe_engine=None):
        results = list(self._results)
        if self.limit > 0:
            results = results[:self.limit]
        if not results:
            return
        probe_results = list(probe_engine.results) if probe_engine and probe_engine.results else []
        from reecanner.output import RichTableWriter
        RichTableWriter(console).write(results, probe_results=probe_results, show_vulns=self.vulns)

    def get_results(self) -> list:
        """Return scan results merged with any probe (banner/http/resolve) data."""
        results = list(self._results)
        if self.limit > 0:
            results = results[:self.limit]

        # merge probe results if available
        if hasattr(self, '_probe_engine_results'):
            probe_map = {}
            for pr in self._probe_engine_results:
                key = (pr['ip'], pr['port'])
                probe_map[key] = pr
            for r in results:
                key = (r['ip'], r['port'])
                if key in probe_map:
                    r.update(probe_map[key])
        return results

    @property
    def found_total(self) -> int:
        return self.found_count.value
