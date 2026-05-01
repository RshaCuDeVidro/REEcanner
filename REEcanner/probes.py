"""Banner grabbing and HTTP probing for discovered services"""
import socket
import ssl
import re
import threading
import queue
import sys
from datetime import datetime

def banner_grab(ip, port, timeout=3):
    """Connect and grab banner/response from a service"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # HTTP-like ports: send GET
        if port in (80, 8080, 8000, 8888, 8008, 8081, 3000, 5000, 9090):
            sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port in (443, 8443, 4443, 9443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
            sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        # otherwise just wait for server to send first
        data = sock.recv(4096)
        sock.close()
        return data.decode('utf-8', errors='replace').strip()[:512]
    except:
        return None

def http_probe(ip, port, timeout=5):
    """Full HTTP probe — status, title, server, redirect"""
    try:
        use_ssl = port in (443, 8443, 4443, 9443)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        sock.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
                if len(data) > 32768: break
            except: break
        sock.close()
        text = data.decode('utf-8', errors='replace')
        r = {}
        lines = text.split('\r\n')
        if lines and 'HTTP/' in lines[0]:
            parts = lines[0].split(' ', 2)
            if len(parts) >= 2:
                try: r['status'] = int(parts[1])
                except: pass
                if len(parts) >= 3: r['status_text'] = parts[2]
        for line in lines[1:]:
            if not line: break
            if ':' in line:
                k, v = line.split(':', 1)
                k = k.strip().lower()
                if k == 'server': r['server'] = v.strip()
                elif k == 'location': r['redirect'] = v.strip()
                elif k == 'content-type': r['content_type'] = v.strip()
        m = re.search(r'<title[^>]*>(.*?)</title>', text, re.I | re.S)
        if m: r['title'] = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]
        return r if r else None
    except:
        return None

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000, 5000, 4443, 9443, 9090, 3001, 9000, 8001}

class ProbeEngine:
    """Runs banner/HTTP probes in background threads"""
    def __init__(self, do_banners=False, do_http=False, do_vulns=False, use_color=True, quiet=False, simple=False, timeout=3):
        self.do_banners = do_banners
        self.do_http = do_http
        self.do_vulns = do_vulns
        self.quiet = quiet
        self.simple = simple
        self.timeout = timeout
        self.G = "\033[92m" if use_color else ""
        self.C = "\033[96m" if use_color else ""
        self.R = "\033[91m" if use_color else ""
        self.Y = "\033[93m" if use_color else ""
        self.B = "\033[1m" if use_color else ""
        self.D = "\033[2m" if use_color else ""
        self.E = "\033[0m" if use_color else ""
        self.queue = queue.Queue(maxsize=10000)
        self.results = []
        self._workers = []
        self._stop = False

    def start(self, num_threads=8):
        for _ in range(num_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._workers.append(t)

    def submit(self, ip, port):
        if not self.do_banners and not self.do_http and not self.do_vulns: return
        try: self.queue.put_nowait((ip, port))
        except: pass

    def stop(self):
        self._stop = True
        for _ in self._workers:
            try: self.queue.put_nowait(None)
            except: pass
        for t in self._workers:
            t.join(timeout=5)

    def _worker(self):
        while not self._stop:
            try:
                item = self.queue.get(timeout=0.5)
            except: continue
            if item is None: break
            ip, port = item
            result = {'ip': ip, 'port': port}
            banner_text = None
            server_header = None
            
            # HTTP probe for web ports
            if self.do_http and port in HTTP_PORTS:
                hr = http_probe(ip, port, self.timeout)
                if hr:
                    result.update(hr)
                    server_header = hr.get('server', '')
                    if not self.quiet and not self.simple:
                        parts = []
                        if 'status' in hr: parts.append(f"{hr['status']}")
                        if 'title' in hr: parts.append(f"\"{hr['title']}\"")
                        if 'server' in hr: parts.append(hr['server'])
                        if 'redirect' in hr: parts.append(f"→ {hr['redirect']}")
                        if parts:
                            info = ' | '.join(parts)
                            sys.stdout.write(f"\r\033[K  {self.C}http{self.E} {ip}:{port} — {info}\n")
                            sys.stdout.flush()
            # Banner grab for non-HTTP or if HTTP probe wasn't done
            elif self.do_banners:
                banner = banner_grab(ip, port, self.timeout)
                if banner:
                    first_line = banner.split('\n')[0].strip()[:200]
                    result['banner'] = first_line
                    banner_text = banner
                    if not self.quiet and not self.simple:
                        sys.stdout.write(f"\r\033[K  {self.C}banner{self.E} {ip}:{port} — {first_line}\n")
                        sys.stdout.flush()
            
            # vuln lookup via searchsploit
            if self.do_vulns and (banner_text or server_header):
                try:
                    from REEcanner.vulns import lookup_vulns
                    exploits = lookup_vulns(banner_text, port=port, server=server_header)
                    if exploits:
                        result['exploits'] = exploits
                        if not self.quiet and not self.simple:
                            sys.stdout.write(f"\r\033[K  {self.R}\u2500\u2500 vulns{self.E} {self.B}{ip}:{port}{self.E}\n")
                            for ex in exploits:
                                cve = f" {self.Y}{ex['cve']}{self.E}" if 'cve' in ex else ""
                                sys.stdout.write(f"\r\033[K     {self.R}\u2022{self.E} {ex['id']}{cve} {self.D}{ex['title']}{self.E}\n")
                            sys.stdout.flush()
                except: pass
            
            self.results.append(result)

