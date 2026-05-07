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
        tls_domains = []
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
            try:
                der = sock.getpeercert(binary_form=True)
                if der:
                    import cryptography.x509 as x509
                    from cryptography.x509.oid import ExtensionOID, NameOID
                    cert = x509.load_der_x509_certificate(der)
                    try:
                        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        tls_domains.extend(ext.value.get_values_for_type(x509.DNSName))
                    except: pass
                    
                    if not tls_domains:
                        try:
                            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                            if cn: tls_domains.append(cn[0].value)
                        except: pass
                        
                    if tls_domains:
                        tls_domains = list(set(d.replace('*.', '') for d in tls_domains if d and isinstance(d, str)))
            except: pass
            
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
        if tls_domains: r['tls_domains'] = tls_domains
        return r if r else None
    except:
        return None

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000, 5000, 4443, 9443, 9090, 3001, 9000, 8001}

class ProbeEngine:
    """Runs banner/HTTP probes and DNS resolution in background threads"""
    def __init__(self, do_banners=False, do_http=False, do_vulns=False, do_resolve=False, use_color=True, quiet=False, simple=False, timeout=3):
        self.do_banners = do_banners
        self.do_http = do_http
        self.do_vulns = do_vulns
        self.do_resolve = do_resolve
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
        if not self.do_banners and not self.do_http and not self.do_vulns and not self.do_resolve: return
        try: self.queue.put_nowait((ip, port))
        except: pass

    def stop(self, force=False):
        if force:
            self._stop = True
        
        for _ in self._workers:
            try: self.queue.put(None)
            except: pass
            
        for t in self._workers:
            t.join(timeout=10 if force else None)

    def _worker(self):
        while True:
            try:
                item = self.queue.get(timeout=0.5)
            except queue.Empty:
                if self._stop: break
                continue
            if item is None: break
            ip, port = item
            result = {'ip': ip, 'port': port}
            banner_text = None
            server_header = None
            
            # DNS reverse resolution
            if self.do_resolve:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    result['hostname'] = hostname
                    if not self.quiet and not self.simple:
                        sys.stdout.write(f"\r\033[K  {self.G}resolve{self.E} {ip} — {hostname}\n")
                        sys.stdout.flush()
                except: pass

            if (self.do_http or self.do_resolve) and port in HTTP_PORTS:
                hr = http_probe(ip, port, self.timeout)
                if hr:
                    result.update(hr)
                    server_header = hr.get('server', '')
                    if not self.quiet and not self.simple:
                        parts = []
                        if 'status' in hr: parts.append(f"{hr['status']}")
                        if 'title' in hr: parts.append(f"\"{hr['title']}\"")
                        if 'server' in hr: parts.append(hr['server'])
                        if 'tls_domains' in hr: parts.append(f"certs: {','.join(hr['tls_domains'])}")
                        if 'redirect' in hr: parts.append(f"→ {hr['redirect']}")
                        if parts:
                            info = ' | '.join(parts)
                            sys.stdout.write(f"\r\033[K  {self.C}http{self.E} {ip}:{port} — {info}\n")
                            sys.stdout.flush()
            # Banner grab for non-HTTP or if HTTP probe wasn't done
            elif self.do_banners:
                banner = banner_grab(ip, port, self.timeout)
                if banner:
                    banner_text = banner
                    first_line = banner.split('\n')[0].strip()[:200]
                    # extract Server header from HTTP-like responses
                    server_match = re.search(r'^[Ss]erver:\s*(.+)$', banner, re.M)
                    if server_match:
                        server_header = server_match.group(1).strip()
                        display = f"{first_line} ({server_header})"
                    else:
                        display = first_line
                    result['banner'] = display
                    if not self.quiet and not self.simple:
                        sys.stdout.write(f"\r\033[K  {self.C}banner{self.E} {ip}:{port} — {display}\n")
                        sys.stdout.flush()
            
            # vuln lookup via searchsploit
            if self.do_vulns and (banner_text or server_header):
                try:
                    from REEcanner.vulns import lookup_vulns, parse_banner
                    parsed_name = None
                    if server_header:
                        parsed_name = parse_banner(server_header, port)
                    if not parsed_name and banner_text:
                        parsed_name = parse_banner(banner_text, port)
                    
                    exploits = lookup_vulns(banner_text, port=port, server=server_header)
                    if exploits:
                        result['exploits'] = exploits
                        if not self.quiet and not self.simple:
                            label = f" ({parsed_name})" if parsed_name else ""
                            ids = ", ".join(ex.get('id', '') for ex in exploits[:3])
                            extra = f" +{len(exploits)-3} more" if len(exploits) > 3 else ""
                            sys.stdout.write(f"\r\033[K  {self.R}vulns{self.E} {ip}:{port}{label} -> {ids}{extra}\n")
                            sys.stdout.flush()
                except: pass
            
            self.results.append(result)

