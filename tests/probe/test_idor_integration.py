"""Loopback integration for configured live IDOR (AT8).

Two identities, two objects, a real P1 token, and no third-party target.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.idor import load_idor_config
from pry.probe.live import scan_live
from pry.probe.results import EXPOSED
from pry.proof import load_bundle, verify_bundle
from pry.report import load_run, write_report


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if self.path == "/api/items/1" and "session=a" in cookie:
            self._send(200, '{"id":1,"owner":"a"}')
        elif self.path == "/api/items/2" and "session=b" in cookie:
            self._send(200, '{"id":2,"owner":"b"}')
        elif self.path == "/api/items/2" and "session=a" in cookie:
            # The IDOR: identity A can read identity B's object.
            self._send(200, '{"id":2,"owner":"b"}')
        elif self.path.startswith("/api/items/"):
            self._send(403, '{"error":"forbidden"}')
        else:
            self._send(404, '{"error":"not found"}')

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
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


def test_configured_idor_is_reproduced_and_redacted(
    live_server, isolated_state, tmp_path
):
    config_path = tmp_path / "idor.json"
    config_path.write_text(
        json.dumps(
            {
                "identity_a": {"headers": {"Cookie": "session=a"}},
                "identity_b": {"headers": {"Cookie": "session=b"}},
                "object_a": "/api/items/1",
                "object_b": "/api/items/2",
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    token = TokenSigner().issue(normalize_target(live_server), "dns_txt")

    outcome = scan_live(
        live_server,
        token,
        idor_config=load_idor_config(config_path),
        out=tmp_path / "run",
    )

    idor = next(result for result in outcome.results if result.probe == "idor")
    assert idor.verdict == EXPOSED
    assert idor.proof is not None
    assert idor.request["headers"].get("cookie") == "[redacted]"
    payload, fingerprint = verify_bundle(load_bundle(idor.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert fingerprint.startswith("sha256:")

    report_path = write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] == 1

    report_text = report_path.read_text(encoding="utf-8")
    assert "127.0.0.1" in report_text
    for secret in ("session=a", "session=b", token, str(config_path)):
        assert secret not in report_text

    for path in Path(tmp_path / "run").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            for secret in ("session=a", "session=b", token, str(config_path)):
                assert secret not in text
