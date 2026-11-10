"""Loopback integration for the live rate-limit observation (AT2/AT3/AT7).

No third-party target and no Docker; the server is on 127.0.0.1 only.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.live import scan_live
from pry.probe.rate_limit import OBSERVED, THROTTLED, RateLimitConfig


class Handler(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        if self.path == "/login":
            Handler.hits += 1
            if Handler.hits > 2:
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(b"slow down\n")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found\n")

    def log_message(self, format, *args):
        pass


@pytest.fixture
def live_server():
    Handler.hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def isolated_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def test_live_rate_limit_stops_on_the_first_throttle(live_server, tmp_path):
    token = TokenSigner().issue(normalize_target(live_server), "dns_txt")

    outcome = scan_live(
        live_server,
        token,
        out=tmp_path / "run",
        rate_limit_config=RateLimitConfig(endpoint="/login", count=5),
    )

    observation = outcome.observations[0]
    assert observation["probe"] == "rate_limit"
    assert observation["status"] == THROTTLED
    assert observation["count"] == 3
    assert observation["statuses"] == [200, 200, 429]
    assert "request 3/5" in observation["evidence"]
    assert "verdict" not in observation
    assert "proof" not in observation
    assert all(result.probe != "rate_limit" for result in outcome.results)
    assert Handler.hits == 3


def test_live_rate_limit_observes_all_accepted_requests(live_server, tmp_path):
    token = TokenSigner().issue(normalize_target(live_server), "dns_txt")

    outcome = scan_live(
        live_server,
        token,
        out=tmp_path / "run",
        rate_limit_config=RateLimitConfig(endpoint="/login", count=2),
    )

    observation = outcome.observations[0]
    assert observation["status"] == OBSERVED
    assert observation["count"] == 2
    assert observation["statuses"] == [200, 200]
    assert Handler.hits == 2
