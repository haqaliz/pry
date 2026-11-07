"""Shared test fixtures: an offline network guard and a loopback HTTP server."""

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.resolver
import pytest

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture(autouse=True)
def isolated_corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    real_connect = socket.socket.connect

    def guarded_connect(sock, address):
        if isinstance(address, tuple) and address[0] not in _LOOPBACK_HOSTS:
            raise AssertionError("network access to %r blocked in tests" % (address,))
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    def no_dns(*args, **kwargs):
        raise AssertionError("real DNS lookup blocked in tests")

    monkeypatch.setattr(dns.resolver, "resolve", no_dns)


@pytest.fixture
def http_server():
    routes = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = routes.get(self.path, (404, {}, b""))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port, routes
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
