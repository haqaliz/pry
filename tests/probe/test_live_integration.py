"""Loopback integration for the live read-only scan (AT4/AT5/AT8).

No third-party target and no Docker; the server is on 127.0.0.1 only.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.live import scan_live
from pry.probe.results import EXPOSED
from pry.proof import load_bundle, verify_bundle
from pry.report import load_run, write_report


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            origin = self.headers.get("Origin")
            self.send_response(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"ok\n")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(
                b"DATABASE_URL=postgres://user:pass@db.local/app\n"
                b"SECRET_KEY=live-secret-value\n"
            )
        elif self.path.startswith("/__pry_missing__"):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(
                b'Traceback (most recent call last):\n'
                b'  File "/app/server.py", line 1, in handler\n'
            )
        elif self.path == "/api/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users":[{"id":1}]}')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")

    def log_message(self, format, *args):
        pass


@pytest.fixture
def live_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def isolated_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def test_live_scan_reproduces_and_signs(live_server, isolated_keys, tmp_path):
    token = TokenSigner().issue(normalize_target(live_server), "dns_txt")

    outcome = scan_live(
        live_server,
        token,
        endpoints=["/api/users"],
        out=tmp_path / "run",
    )

    exposed = [result for result in outcome.results if result.verdict == EXPOSED]
    assert len(exposed) == 4
    for result in exposed:
        assert result.proof is not None
        payload, fingerprint = verify_bundle(load_bundle(result.proof))
        assert payload["finding"]["verdict"] == EXPOSED
        assert fingerprint.startswith("sha256:")

    report_path = write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] == 4

    report_text = report_path.read_text(encoding="utf-8")
    assert "127.0.0.1" in report_text
    assert "live-secret-value" not in report_text
    assert "user:pass" not in report_text

    for path in Path(tmp_path / "run").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert token not in text
