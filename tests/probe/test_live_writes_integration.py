"""Loopback integration for a live Level 2 write (AT1/AT8).

No third-party target and no Docker; the server is on 127.0.0.1 only.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.live import scan_live
from pry.probe.results import EXPOSED
from pry.probe.write import WriteConfig
from pry.proof import load_bundle, verify_bundle


class Handler(BaseHTTPRequestHandler):
    stored = ""

    def do_POST(self):
        if self.path != "/api/write":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        Handler.stored = self.rfile.read(length).decode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"created":true}')

    def do_GET(self):
        if self.path != "/api/write":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write((Handler.stored or "{}").encode("utf-8"))

    def log_message(self, format, *args):
        pass


@pytest.fixture
def live_server():
    Handler.stored = ""
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


def test_a_live_write_is_reproduced_and_signed(live_server, tmp_path):
    token = TokenSigner().issue(normalize_target(live_server), "dns_txt")
    config = WriteConfig(
        method="POST",
        endpoint="/api/write",
        body='{"name":"{{marker}}"}',
        verify_endpoint="/api/write",
        verify_contains="{{marker}}",
    )

    outcome = scan_live(
        live_server,
        token,
        out=tmp_path / "run",
        write_config=config,
    )

    write = next(result for result in outcome.results if result.probe == "write")
    assert write.verdict == EXPOSED
    assert write.proof is not None
    assert write.response["status"] == 201
    verification = write.response["verification"]
    assert verification["response"]["status"] == 200
    assert "pry-" in verification["response"]["body"]
    assert "pry-" in Handler.stored

    payload, fingerprint = verify_bundle(load_bundle(write.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["probe"] == "write"
    assert (
        payload["finding"]["response"]["verification"]["response"]["status"]
        == 200
    )
    assert fingerprint.startswith("sha256:")
