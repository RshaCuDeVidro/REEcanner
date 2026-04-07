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

def packet_worker(worker_id, local_ip_bytes, ports, src_port, rate_limit, bl_mgr, inc_mgr, run_event, pps_array, sent_array, net_info, total_workers, start_index=0, shards=1, shard_id=0, batch_size=4096):
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
    ports_len = len(ports)
    # batch_size comes from function parameter
    interval = (batch_size / rate_limit) if rate_limit > 0 else 0
    next_t = time.perf_counter()
    batch_msgs = []
    off = 14 if iface else 0
    pkt_len = 54 if iface else 40
    if iface:
        g_mac_bytes = bytes.fromhex(g_mac.replace(':',''))
        l_mac_bytes = bytes.fromhex(l_mac.replace(':',''))
    for _ in range(batch_size):
        buf = bytearray(pkt_len)
        if iface: _pack_into('!6s6sH', buf, 0, g_mac_bytes, l_mac_bytes, 0x0800)
        _pack_into('!BBHHHBB', buf, off, 0x45, 0, 40, 54321, 0, 64, 6)
        _pack_into('!4s', buf, off+12, local_ip_bytes)
        _pack_into('!H', buf, off+20, src_port)
        _pack_into('!BBH', buf, off+32, 0x50, 2, 5840)
        batch_msgs.append([buf, 0, None if iface else (None, 0)])
    local_sent = 0
    while run_event.is_set():
        if interval > 0:
            c = time.perf_counter()
            if c < next_t:
                w = next_t - c
                if w > 0.001: time.sleep(w)
                else: 
                    while time.perf_counter() < next_t: pass
            next_t += interval
        for i in range(batch_size):
            attempts = 0
            while True:
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
        try:
            if _sendmmsg: _sendmmsg(batch_msgs)
            else:
                for m in batch_msgs: 
                    if iface: _send(m[0])
                    else: _sendto(m[0], m[2])
            local_sent += batch_size
            if local_sent >= 4096:
                pps_array[worker_id] += local_sent
                sent_array[worker_id] += local_sent
                local_sent = 0
        except: pass

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

def sniffer_process(src_port, run_event, found_count, output_file, quiet, use_color, limit, simple=False):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64*1024*1024)
    except: return
    
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
                    process_packet(data, src_port, seen_hosts, found_count, quiet, q if output_file else None, G, B, E, run_event, limit, simple=simple)
            else:
                sock.settimeout(0.1)
                data, _ = sock.recvfrom(65535)
                process_packet(data, src_port, seen_hosts, found_count, quiet, q if output_file else None, G, B, E, run_event, limit, simple=simple)
        except (socket.timeout, BlockingIOError): continue
        except: continue
        
    if writer_thread:
        q.put(None)
        writer_thread.join()

def process_packet(data, src_port, seen_hosts, found_count, quiet, log_queue, G, B, E, run_event, limit, simple=False):
    iph_len = (data[0] & 0x0F) << 2
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
            
            ip_str = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
            if not quiet:
                if simple:
                    if sp == 443:
                        sys.stdout.write(f"{ip_str}\n")
                    elif sp == 80:
                        sys.stdout.write(f"{ip_str}\n")
                    else:
                        sys.stdout.write(f"{ip_str}:{sp}\n")
                else:
                    # \r mv pro inicio
                    sys.stdout.write(f"\r\033[K{B}{G}found{E} {ip_str}:{sp}\n")
                sys.stdout.flush()
            if log_queue is not None:
                log_queue.put(json.dumps({"ip":ip_str,"port":sp,"time":datetime.now().isoformat()})+"\n")

class Scanner:
    def __init__(self, ports, rate_limit=1000, blacklist_manager=None, inclusion_manager=None, source_port=None, workers=None, limit=0, output_file=None, quiet=False, seed=None, start_index=0, shards=1, shard_id=0, checkpoint_file=None, simple=False, batch_size=4096):
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
        self.found_count = multiprocessing.Value('i', 0)
        
        self.pps_array = multiprocessing.Array(ctypes.c_ulonglong, self.workers_count)
        self.sent_array = multiprocessing.Array(ctypes.c_ulonglong, self.workers_count)
        
        self.net_info = get_net_info()
        self.seed = self.inc_mgr.shuffler.seed
        self.start_index = start_index
        self.shards = shards
        self.shard_id = shard_id
        self.checkpoint_file = checkpoint_file
        self.batch_size = batch_size

    def _get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally: s.close()

    def run(self, console):
        sniff_p = multiprocessing.Process(target=sniffer_process, args=(self.src_port, self.run_event, self.found_count, self.output_file, self.quiet, not console.no_color, self.limit, self.simple))
        sniff_p.start()
        rpw = self.rate_limit // self.workers_count
        procs = []
        for i in range(self.workers_count):
            p = multiprocessing.Process(target=packet_worker, args=(i, self.local_ip_bytes, self.ports, self.src_port, rpw, self.bl_mgr, self.inc_mgr, self.run_event, self.pps_array, self.sent_array, self.net_info, self.workers_count, self.start_index, self.shards, self.shard_id, self.batch_size))
            p.start()
            procs.append(p)
        
        start_time = time.time()
        last_pps_check = start_time
        sys.stderr.write("\n")
        
        last_checkpoint_time = time.time()
        
        try:
            while self.run_event.is_set():
                time.sleep(0.1)
                now = time.time()
                elapsed = now - last_pps_check
                if elapsed >= 1.0:
                    curr_pps = sum(self.pps_array) / elapsed
                    for i in range(self.workers_count): self.pps_array[i] = 0
                    last_pps_check = now
                    
                    sent_total = sum(self.sent_array)
                    found_total = self.found_count.value
                    sent_fmt = f"{sent_total:,}".replace(',', '.')
                    pps_fmt = f"{curr_pps:,.0f}".replace(',', '.')
                    current_idx = self.start_index + sent_total
                    #-> pipe linux
                    sys.stderr.write(f"\r[*] sent: {sent_fmt} | rate: {pps_fmt} pps | found: {found_total} | index: {current_idx}\033[K")
                    sys.stderr.flush()
                    
                    if self.checkpoint_file and (now - last_checkpoint_time > 10.0):
                        with open(self.checkpoint_file, 'w') as f:
                            json.dump({"index": current_idx}, f)
                        last_checkpoint_time = now
        except KeyboardInterrupt:
            self.run_event.clear()
        except:
            self.run_event.clear()
        
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


        self.run_event.clear()
        try:
        
            for p in procs + [sniff_p]:
                p.join(timeout=0.2)
            
            # gepetot: força terminar se tiver is_alive true
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

    @property
    def found_total(self):
        return self.found_count.value
