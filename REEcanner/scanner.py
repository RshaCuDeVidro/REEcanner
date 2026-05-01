import socket
import threading
import multiprocessing
import ctypes
import time
import json
import sys
import struct
import subprocess
import os
import queue
import signal
from datetime import datetime

try:
    _lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'worker.so'))
    _lib.run_worker.restype = None
    _lib.run_worker.argtypes = [                         # trabalhar com worker.c : ->
        ctypes.c_int,                                    # worker_id
        ctypes.POINTER(ctypes.c_uint8),                  # src_ip (4 bytes)
        ctypes.POINTER(ctypes.c_uint16), ctypes.c_int,   # ports, ports_len
        ctypes.c_uint16,                                 # src_port
        ctypes.c_int,                                    # rate_limit
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
    ]
    HAS_C_WORKER = True
except:
    HAS_C_WORKER = False

def get_net_info():
    try:
        gw_info = subprocess.check_output("ip route show default", shell=True).decode()
        gw_ip = gw_info.split()[2]
        iface = gw_info.split()[4]
        local_mac = subprocess.check_output(f"cat /sys/class/net/{iface}/address", shell=True).decode().strip()
        arp_info = subprocess.check_output(f"arp -n {gw_ip}", shell=True).decode()
        gw_mac = next(line.split()[2] for line in arp_info.splitlines() if gw_ip in line)
        return iface, local_mac, gw_mac
    except: return None, None, None
def c_packet_worker(worker_id, local_ip_bytes, ports, src_port, rate_limit, bl_mgr, inc_mgr, run_flag, pps_array, sent_array, net_info, total_workers, start_index=0, shards=1, shard_id=0, batch_size=4096, retries=1, is_udp=0):
    """Thin wrapper: extract Python data → call C run_worker"""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    lip = (ctypes.c_uint8 * 4)(*local_ip_bytes)
    c_ports = (ctypes.c_uint16 * len(ports))(*ports)
    
    bl = bl_mgr._flat_ranges
    c_bl = (ctypes.c_uint32 * len(bl))(*bl) if bl else (ctypes.c_uint32 * 0)()
    
    c_keys = (ctypes.c_uint32 * 4)(*inc_mgr.shuffler.keys)
    total_ips = inc_mgr.total_ips
    nets = inc_mgr.networks
    c_bases = (ctypes.c_uint32 * len(nets))(*[n['net'] for n in nets])
    c_starts = (ctypes.c_uint32 * len(nets))(*[n['start'] for n in nets])
    
    iface, l_mac, g_mac = net_info
    c_iface = iface.encode() if iface else None
    c_lmac = c_gmac = None
    if iface and l_mac and g_mac:
        c_lmac = (ctypes.c_uint8 * 6)(*bytes.fromhex(l_mac.replace(':', '')))
        c_gmac = (ctypes.c_uint8 * 6)(*bytes.fromhex(g_mac.replace(':', '')))

    _lib.run_worker(
        worker_id,
        lip,
        c_ports, len(ports),
        src_port,
        rate_limit,
        c_bl, len(bl),
        c_keys,
        total_ips,
        c_bases, c_starts, len(nets), 1 if inc_mgr.single_net else 0,
        ctypes.cast(ctypes.addressof(run_flag), ctypes.POINTER(ctypes.c_int)),
        ctypes.cast(ctypes.addressof(pps_array) + worker_id * 8, ctypes.POINTER(ctypes.c_uint64)),
        ctypes.cast(ctypes.addressof(sent_array) + worker_id * 8, ctypes.POINTER(ctypes.c_uint64)),
        c_iface, c_lmac, c_gmac,
        total_workers,
        start_index,
        shards, shard_id,
        batch_size,
        inc_mgr.shuffler.half_bits,
        inc_mgr.shuffler.mask,
        retries,
        is_udp
    )

def packet_worker(worker_id, local_ip_bytes, ports, src_port, rate_limit, bl_mgr, inc_mgr, run_event, pps_array, sent_array, net_info, total_workers, start_index=0, shards=1, shard_id=0, batch_size=4096, retries=1, is_udp=0):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(os, 'sched_setaffinity'):
        try: os.sched_setaffinity(0, {worker_id % (os.cpu_count() or 1)})
        except: pass
    iface, l_mac, g_mac = net_info
    try:
        if iface:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32*1024*1024)
            try: sock.setsockopt(socket.SOL_SOCKET, 46, 50)
            except: pass
            sock.bind((iface, 0))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32*1024*1024)
    except: return
    _sendmmsg = sock.sendmmsg if hasattr(sock, 'sendmmsg') else None
    _send = sock.send
    _sendto = sock.sendto
    _pack_into = struct.pack_into
    _unpack = struct.unpack
    src_ip_words = _unpack("!HH", local_ip_bytes)
    ip_static_sum = 0x4500 + 40 + 54321 + 0 + (64 << 8 | 6) + src_ip_words[0] + src_ip_words[1]
    
    current_index = start_index + worker_id
    rng_state = ((worker_id + 1) * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    
    get_ip = inc_mgr.get_random_ip_int
    is_pub = bl_mgr.is_ip_int_public
    total_ips = inc_mgr.total_ips
    total_work = total_ips * retries
    ports_len = len(ports)
    # dynamic eff_batch pra manter intervalo ~100ms
    eff_batch = batch_size
    if rate_limit > 0:
        max_for_rate = max(1, (rate_limit + 9) // 10)
        eff_batch = min(eff_batch, max_for_rate)
    interval = (eff_batch / rate_limit) if rate_limit > 0 else 0
    next_t = time.perf_counter()
    batch_msgs = []
    off = 14 if iface else 0
    pkt_len = 54 if iface else 40
    if iface:
        g_mac_bytes = bytes.fromhex(g_mac.replace(':',''))
        l_mac_bytes = bytes.fromhex(l_mac.replace(':',''))
    for _ in range(eff_batch):
        buf = bytearray(pkt_len)
        if iface: _pack_into('!6s6sH', buf, 0, g_mac_bytes, l_mac_bytes, 0x0800)
        _pack_into('!BBHHHBB', buf, off, 0x45, 0, 40, 54321, 0, 64, 6)
        _pack_into('!4s', buf, off+12, local_ip_bytes)
        _pack_into('!H', buf, off+20, src_port)
        _pack_into('!BBH', buf, off+32, 0x50, 2, 5840)
        batch_msgs.append([buf, 0, None if iface else (None, 0)])
    while run_event.is_set():
        if interval > 0:
            c = time.perf_counter()
            if c < next_t:
                w = next_t - c
                if w > 0.001: time.sleep(w)
                else: 
                    while time.perf_counter() < next_t: pass
            next_t += interval
        batch_count = 0
        scan_done = False
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
                    
                ip_int, _ = get_ip(current_index)
                current_index += total_workers
                if is_pub(ip_int): break
                attempts += 1
                if attempts > 2000:
                    run_event.clear()
                    return
                if not run_event.is_set(): return
            if scan_done: break

            rng_state = (rng_state ^ (rng_state << 13)) & 0xFFFFFFFFFFFFFFFF
            rng_state = (rng_state ^ (rng_state >> 7)) & 0xFFFFFFFFFFFFFFFF
            rng_state = (rng_state ^ (rng_state << 17)) & 0xFFFFFFFFFFFFFFFF
            port = ports[rng_state % ports_len]
            
            buf = batch_msgs[i][0]
            ip_hi, ip_lo = ip_int >> 16, ip_int & 0xFFFF
            s_ip = ip_static_sum + ip_hi + ip_lo
            s_ip = (s_ip >> 16) + (s_ip & 0xFFFF)
            s_ip = (s_ip >> 16) + (s_ip & 0xFFFF)
            s_tcp = src_ip_words[0] + src_ip_words[1] + ip_hi + ip_lo + 26 + src_port + port + 0x5002 + 5840
            s_tcp = (s_tcp >> 16) + (s_tcp & 0xFFFF)
            s_tcp = (s_tcp >> 16) + (s_tcp & 0xFFFF)
            
            cs_ip = ~s_ip & 0xFFFF
            buf[off+10] = cs_ip >> 8
            buf[off+11] = cs_ip & 0xFF
            
            buf[off+16] = (ip_int >> 24) & 0xFF
            buf[off+17] = (ip_int >> 16) & 0xFF
            buf[off+18] = (ip_int >> 8) & 0xFF
            buf[off+19] = ip_int & 0xFF
            
            buf[off+22] = port >> 8
            buf[off+23] = port & 0xFF
            
            cs_tcp = ~s_tcp & 0xFFFF
            buf[off+36] = cs_tcp >> 8
            buf[off+37] = cs_tcp & 0xFF
            
            if not iface: 
                batch_msgs[i][2] = (f"{(ip_int>>24)&255}.{(ip_int>>16)&255}.{(ip_int>>8)&255}.{ip_int&255}", 0)
            batch_count += 1
        try:
            if batch_count > 0:
                if _sendmmsg: _sendmmsg(batch_msgs[:batch_count])
                else:
                    for m in batch_msgs[:batch_count]: 
                        if iface: _send(m[0])
                        else: _sendto(m[0], m[2])
                pps_array[worker_id] += batch_count
                sent_array[worker_id] += batch_count
        except: pass
        if scan_done: return

def output_writer(q: queue.Queue, filepath: str):
    buffer = []
    with open(filepath, 'a') as f:
        while True:
            item = q.get()
            if item is None:
                break
            
            buffer.append(item)
            if len(buffer) >= 1000:
                f.write("".join(buffer))
                f.flush()
                buffer.clear()
                
        if buffer:
            f.write("".join(buffer))
            f.flush()

def sniffer_process(src_port, run_event, found_count, output_file, quiet, use_color, limit, simple=False, run_flag=None, sniffer_ready=None, resolve=False, results_list=None, probe_queue=None, udp=False):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64*1024*1024)
    except:
        if sniffer_ready: sniffer_ready.set()
        return
    
    if sniffer_ready: sniffer_ready.set()
    
    _recvmmsg = getattr(sock, 'recvmmsg', None)
    G, B, E = ("\033[92m", "\033[1m", "\033[0m") if use_color else ("", "", "")
    seen_hosts = set()
    vlen = 256
    
    q = queue.Queue(maxsize=100_000)
    writer_thread = None
    if output_file:
        writer_thread = threading.Thread(target=output_writer, args=(q, output_file), daemon=True)
        writer_thread.start()
    
    while run_event.is_set():
        try:
            if _recvmmsg:
                msgs = _recvmmsg(vlen, socket.MSG_DONTWAIT)
                for data, _, _, _ in msgs:
                    process_packet(data, src_port, seen_hosts, found_count, quiet, q if output_file else None, G, B, E, run_event, limit, simple=simple, resolve=resolve, results_list=results_list, probe_queue=probe_queue, udp=udp)
            else:
                sock.settimeout(0.1)
                data, _ = sock.recvfrom(65535)
                process_packet(data, src_port, seen_hosts, found_count, quiet, q if output_file else None, G, B, E, run_event, limit, simple=simple, resolve=resolve, results_list=results_list, probe_queue=probe_queue, udp=udp)
        except (socket.timeout, BlockingIOError): continue
        except: continue
        
    if writer_thread:
        q.put(None)
        writer_thread.join()

def process_packet(data, src_port, seen_hosts, found_count, quiet, log_queue, G, B, E, run_event, limit, simple=False, resolve=False, results_list=None, probe_queue=None, udp=False):
    iph_len = (data[0] & 0x0F) << 2
    if len(data) < iph_len + 8: return
    
    if udp:
        # UDP response: dst port must match our src_port
        dp = (data[iph_len + 2] << 8) | data[iph_len + 3]
        if dp != src_port: return
        sp = (data[iph_len] << 8) | data[iph_len + 1]  # remote source port = the open port
        ip_int = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]
        host_key = (ip_int << 16) | sp
        if host_key in seen_hosts: return
        seen_hosts.add(host_key)
        with found_count.get_lock():
            found_count.value += 1
            if limit > 0 and found_count.value >= limit:
                run_event.clear()
        ip_str = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
        if not quiet:
            if simple:
                sys.stdout.write(f"{ip_str}:{sp}\n")
            else:
                sys.stdout.write(f"\r\033[K{B}{G}found{E} {ip_str}:{sp}/udp\n")
            sys.stdout.flush()
        if results_list is not None:
            results_list.append({'ip': ip_str, 'port': sp, 'proto': 'udp'})
        return
    
    if len(data) < iph_len + 20: return
    dp = (data[iph_len + 2] << 8) | data[iph_len + 3]
    if dp == src_port:
        if (data[iph_len + 13] & 0x12) == 0x12:
            ip_int = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]
            sp = (data[iph_len] << 8) | data[iph_len + 1]
            host_key = (ip_int << 16) | sp
            
            if host_key in seen_hosts: return
            seen_hosts.add(host_key)
            
            with found_count.get_lock():
                found_count.value += 1
                if limit > 0 and found_count.value >= limit:
                    run_event.clear()
                    if run_flag is not None:
                        run_flag.value = 0
            
            ip_str = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
            # OS fingerprint from TTL + window
            ttl = data[8]
            window = (data[iph_len + 14] << 8) | data[iph_len + 15]
            try:
                from REEcanner.fingerprint import guess_os
                os_guess = guess_os(ttl, window)
            except: os_guess = ""
            # reverse DNS
            hostname = ""
            if resolve:
                try: hostname = socket.gethostbyaddr(ip_str)[0]
                except: pass
            # service name
            try:
                from REEcanner.ports import get_service_name
                svc = get_service_name(sp)
            except: svc = ""
            
            if not quiet:
                if simple:
                    if sp in (80, 443):
                        sys.stdout.write(f"{ip_str}\n")
                    else:
                        sys.stdout.write(f"{ip_str}:{sp}\n")
                else:
                    extra = ""
                    if os_guess: extra += f" {os_guess}"
                    if hostname: extra += f" ({hostname})"
                    if svc: extra += f" [{svc}]"
                    sys.stdout.write(f"\r\033[K{B}{G}found{E} {ip_str}:{sp}{extra}\n")
                sys.stdout.flush()
            if log_queue is not None:
                entry = {"ip":ip_str,"port":sp,"time":datetime.now().isoformat()}
                if hostname: entry["hostname"] = hostname
                if svc: entry["service"] = svc
                if os_guess: entry["os"] = os_guess
                log_queue.put(json.dumps(entry)+"\n")
            # collect for output formats
            if results_list is not None:
                r = {'ip': ip_str, 'port': sp, 'proto': 'tcp'}
                if os_guess: r['os'] = os_guess
                if hostname: r['hostname'] = hostname
                if svc: r['service'] = svc
                results_list.append(r)
            # submit for probing
            if probe_queue is not None:
                try: probe_queue.put_nowait((ip_str, sp))
                except: pass

class Scanner:
    def __init__(self, ports, rate_limit=1000, blacklist_manager=None, inclusion_manager=None, source_port=None, workers=None, limit=0, output_file=None, quiet=False, seed=None, start_index=0, shards=1, shard_id=0, checkpoint_file=None, simple=False, batch_size=4096, retries=1, resolve=False, banners=False, http_probe=False, vulns=False, udp=False, adaptive=False):
        self.ports = ports
        self.rate_limit = rate_limit
        self.bl_mgr = blacklist_manager
        self.inc_mgr = inclusion_manager
        self.src_port = source_port or (int(time.time()) % 29000 + 10000)
        self.local_ip = self._get_local_ip()
        self.local_ip_bytes = socket.inet_aton(self.local_ip)
        self.workers_count = workers or multiprocessing.cpu_count()
        self.limit = limit
        self.output_file = output_file
        self.quiet = quiet
        self.simple = simple
        self.run_event = multiprocessing.Event()
        self.run_event.set()
        self.run_flag = multiprocessing.RawValue(ctypes.c_int, 1)
        self.found_count = multiprocessing.Value('i', 0)
        
        self.pps_array = multiprocessing.RawArray(ctypes.c_uint64, self.workers_count)
        self.sent_array = multiprocessing.RawArray(ctypes.c_uint64, self.workers_count)
        
        self.net_info = get_net_info()
        self.seed = self.inc_mgr.shuffler.seed
        self.start_index = start_index
        self.shards = shards
        self.shard_id = shard_id
        self.checkpoint_file = checkpoint_file
        self.batch_size = batch_size
        self.retries = retries
        self.resolve = resolve
        self.banners = banners
        self.http_probe = http_probe
        self.vulns = vulns
        self.udp = udp
        self.adaptive = adaptive
        self.total_work = self.inc_mgr.total_ips * self.retries
        self.use_c = HAS_C_WORKER
        # shared results list for output formats
        self._results_manager = multiprocessing.Manager()
        self._results_list = self._results_manager.list()
        self._probe_queue = self._results_manager.Queue() if (banners or http_probe) else None

    def _get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally: s.close()

    def run(self, console):
        # start probe engine if needed
        probe_engine = None
        if self.banners or self.http_probe or self.vulns:
            from REEcanner.probes import ProbeEngine
            probe_engine = ProbeEngine(do_banners=self.banners, do_http=self.http_probe, do_vulns=self.vulns, use_color=not console.no_color, quiet=self.quiet, simple=self.simple)
            probe_engine.start()
        
        sniffer_ready = multiprocessing.Event()
        sniff_p = multiprocessing.Process(target=sniffer_process, args=(
            self.src_port, self.run_event, self.found_count, self.output_file,
            self.quiet, not console.no_color, self.limit, self.simple,
            self.run_flag, sniffer_ready, self.resolve, self._results_list,
            self._probe_queue, self.udp
        ))
        sniff_p.start()
        sniffer_ready.wait(timeout=5.0)  # esperar sniffer ficar pronto
        rpw = self.rate_limit // self.workers_count
        procs = []
        if self.use_c:
            #console.print(f"[bold green][*][/bold green] using [cyan]C worker[/cyan] (worker.so)")
            for i in range(self.workers_count):
                p = multiprocessing.Process(target=c_packet_worker, args=(i, self.local_ip_bytes, self.ports, self.src_port, rpw, self.bl_mgr, self.inc_mgr, self.run_flag, self.pps_array, self.sent_array, self.net_info, self.workers_count, self.start_index, self.shards, self.shard_id, self.batch_size, self.retries, 1 if self.udp else 0))
                p.start()
                procs.append(p)
        else:
            console.print(f"[bold yellow][*][/bold yellow] C worker not available, using Python fallback")
            for i in range(self.workers_count):
                p = multiprocessing.Process(target=packet_worker, args=(i, self.local_ip_bytes, self.ports, self.src_port, rpw, self.bl_mgr, self.inc_mgr, self.run_event, self.pps_array, self.sent_array, self.net_info, self.workers_count, self.start_index, self.shards, self.shard_id, self.batch_size, self.retries, 1 if self.udp else 0))
                p.start()
                procs.append(p)
        
        start_time = time.time()
        last_pps_check = start_time
        sys.stderr.write("\n")
        
        last_checkpoint_time = time.time()
        grace_period = 3.0  # imitando masscan, demorar um tico pro scan terminar 
        grace_start = None
        curr_pps = 0.0
        try:
            while self.run_event.is_set() and self.run_flag.value:
                time.sleep(0.1)
                
                # ver se terminou
                if grace_start is None and all(not p.is_alive() for p in procs):
                    grace_start = time.time()
                    # final progress update
                    sent_total = sum(self.sent_array)
                    found_total = self.found_count.value
                    sent_fmt = f"{sent_total:,}".replace(',', '.')
                    pct = min(100.0, sent_total / self.total_work * 100) if self.total_work > 0 else 100.0
                    filled = int(pct / 5)
                    bar = '█' * filled + '░' * (20 - filled)
                    sys.stderr.write(f"\r[{bar}] {pct:5.1f}% | {sent_fmt} sent | found: {found_total}\033[K\n")
                    sys.stderr.write(f"[*] scan complete, waiting {grace_period:.0f}s for responses...\n")
                    sys.stderr.flush()
                
                if grace_start and (time.time() - grace_start >= grace_period):
                    break
                
                # pps calculo
                now = time.time()
                elapsed = now - last_pps_check
                if elapsed >= 1.0:
                    curr_pps = sum(self.pps_array) / elapsed
                    for i in range(self.workers_count): self.pps_array[i] = 0
                    last_pps_check = now
                    
                    if self.checkpoint_file and (now - last_checkpoint_time > 10.0):
                        sent_total = sum(self.sent_array)
                        current_idx = self.start_index + sent_total
                        with open(self.checkpoint_file, 'w') as f:
                            json.dump({"index": current_idx}, f)
                        last_checkpoint_time = now
                
                # progress bar todo tick
                if grace_start is None:
                    sent_total = sum(self.sent_array)
                    found_total = self.found_count.value
                    sent_fmt = f"{sent_total:,}".replace(',', '.')
                    pps_fmt = f"{curr_pps:,.0f}".replace(',', '.')
                    pct = min(100.0, sent_total / self.total_work * 100) if self.total_work > 0 else 0
                    filled = int(pct / 5)
                    bar = '█' * filled + '░' * (20 - filled) #<- peguei de uma dotfile do waybar kkkkkk
                    # ETA
                    if curr_pps > 0 and sent_total < self.total_work:
                        remaining = self.total_work - sent_total
                        eta_s = remaining / curr_pps
                        if eta_s >= 60:
                            eta_str = f" | eta: {eta_s/60:.1f}m"
                        else:
                            eta_str = f" | eta: {eta_s:.0f}s"
                    else:
                        eta_str = ""
                    sys.stderr.write(f"\r[{bar}] {pct:5.1f}% | {sent_fmt} sent @ {pps_fmt} pps | found: {found_total}{eta_str}\033[K")
                    sys.stderr.flush()
                
                # adaptive rate: adjust if actual << target
                if self.adaptive and curr_pps > 0:
                    ratio = curr_pps / self.rate_limit if self.rate_limit > 0 else 1.0
                    if ratio < 0.5:
                        sys.stderr.write(f"\n[!] adaptive: actual rate {curr_pps:.0f} << target {self.rate_limit}, possible congestion\033[K\n")
                        sys.stderr.flush()
        except KeyboardInterrupt:
            self.run_flag.value = 0
            self.run_event.clear()
        except:
            self.run_flag.value = 0
            self.run_event.clear()
        
        # drain probe queue
        if probe_engine and self._probe_queue:
            while not self._probe_queue.empty():
                try:
                    ip, port = self._probe_queue.get_nowait()
                    probe_engine.submit(ip, port)
                except: break
            # wait for probes to finish
            import time as _t
            _t.sleep(1)
            probe_engine.stop()
        
        total_duration = time.time() - start_time
        sent_total = sum(self.sent_array)
        avg_pps = sent_total / total_duration if total_duration > 0 else 0
        sent_fmt = f"{sent_total:,}".replace(',', '.')
        pps_fmt = f"{avg_pps:,.0f}".replace(',', '.')
        sys.stderr.write(f"\r[*] sent: {sent_fmt} | rate: {pps_fmt} pps | found: {self.found_count.value} | next index: {self.start_index + sent_total}\033[K\n")
        sys.stderr.flush()

        if self.checkpoint_file:
            try:
                with open(self.checkpoint_file, 'w') as f:
                    json.dump({"index": self.start_index + sent_total}, f)
            except: pass

        self.run_flag.value = 0
        self.run_event.clear()
        try:
        
            for p in procs + [sniff_p]:
                p.join(timeout=0.2)
            
            for p in procs + [sniff_p]:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=0.1)
        except KeyboardInterrupt:
            # gepeto: pra terminar tudo
            for p in procs + [sniff_p]:
                if p.is_alive():
                    p.terminate()
        except: pass

    def get_results(self):
        """get collected scan results for output formats"""
        results = list(self._results_list)
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
    def found_total(self):
        return self.found_count.value
