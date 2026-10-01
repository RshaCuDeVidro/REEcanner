"""banner_grab / http_probe against a real local TCP server (127.0.0.1)."""
import socket
import threading

from reecanner import probes


class _OneShotServer:
    """Accept one connection, optionally read the request, reply, close."""

    def __init__(self, reply: bytes, read_first: bool = False):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.request = b""
        self._reply = reply
        self._read_first = read_first
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(5)
            if self._read_first:
                while b"\r\n\r\n" not in self.request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    self.request += chunk
            conn.sendall(self._reply)
            conn.close()
        except OSError:
            pass
        finally:
            self.sock.close()

    def join(self):
        self._t.join(timeout=5)


def test_banner_grab_server_speaks_first():
    srv = _OneShotServer(b"SSH-2.0-OpenSSH_8.9p1\r\n")
    banner = probes.banner_grab("127.0.0.1", srv.port, timeout=5)
    srv.join()
    assert banner is not None and "OpenSSH_8.9p1" in banner


def test_banner_grab_http_port_sends_get(monkeypatch):
    srv = _OneShotServer(b"HTTP/1.0 200 OK\r\n\r\nhi", read_first=True)
    monkeypatch.setattr(probes, "HTTP_GET_PORTS", {srv.port})
    banner = probes.banner_grab("127.0.0.1", srv.port, timeout=5)
    srv.join()
    assert banner is not None and "200 OK" in banner
    assert srv.request.startswith(b"GET / HTTP/1.0")
    assert b"User-Agent: reecanner/1.0" in srv.request


def test_http_probe_parses_response():
    body = b"<html><head><title>  Hello   World </title></head></html>"
    reply = (b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\n"
             b"Content-Type: text/html; charset=utf-8\r\n\r\n") + body
    srv = _OneShotServer(reply, read_first=True)
    r = probes.http_probe("127.0.0.1", srv.port, timeout=5)
    srv.join()
    assert r is not None
    assert r["status"] == 200
    assert r["server"] == "TestServer/1.0"
    assert r["content_type"] == "text/html; charset=utf-8"
    assert r["title"] == "Hello World"
    assert srv.request.startswith(b"GET / HTTP/1.1")


def test_http_probe_redirect():
    reply = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n"
    srv = _OneShotServer(reply, read_first=True)
    r = probes.http_probe("127.0.0.1", srv.port, timeout=5)
    srv.join()
    assert r["status"] == 301
    assert r["redirect"] == "https://example.com/"


def test_banner_grab_connection_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert probes.banner_grab("127.0.0.1", port, timeout=2) is None
