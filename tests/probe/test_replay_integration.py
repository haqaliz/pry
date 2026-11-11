"""Loopback integration for live proof replay (AT1/AT2/AT7).

No third-party target and no Docker; the server is on 127.0.0.1 only.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.replay import MATCH, MISMATCH, replay_bundle
from pry.proof import build_bundle


class Handler(BaseHTTPRequestHandler):
    status = 200
    seen_headers = {}

    def do_GET(self):
        Handler.seen_headers = dict(self.headers)
        self.send_response(Handler.status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, format, *args):
        pass


@pytest.fixture
def live_server():
    Handler.status = 200
    Handler.seen_headers = {}
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


def _payload(origin):
    target = {
        "sandbox_id": "live-0123456789ab",
        "path": origin,
        "kind": "live",
        "url": origin,
        "ownership_proof": "dns_txt",
        "git_commit": None,
        "git_dirty": None,
        "tree_sha256": None,
        "image": None,
        "image_digest": None,
        "port": None,
    }
    finding = {
        "probe": "cors",
        "verdict": "EXPOSED",
        "cause": None,
        "evidence": "CORS reflects the origin with credentials",
        "request": {
            "method": "GET",
            "url": origin + "/",
            "headers": {
                "origin": "https://pry.invalid",
                "user-agent": "pry/0.1",
                "authorization": "[redacted]",
                "cookie": "[redacted]",
            },
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
    }
    return build_bundle(target, finding)["payload"]


def _token(origin):
    return TokenSigner().issue(normalize_target(origin), "dns_txt")


def test_a_live_replay_matches_and_sends_no_credentials(live_server):
    result = replay_bundle(_payload(live_server), _token(live_server))

    assert result["status"] == MATCH
    assert result["recorded_status"] == 200
    assert result["replay_status"] == 200
    assert "authorization" not in {
        name.lower() for name in Handler.seen_headers
    }
    assert "cookie" not in {name.lower() for name in Handler.seen_headers}


def test_a_changed_status_is_a_mismatch(live_server):
    Handler.status = 403

    result = replay_bundle(_payload(live_server), _token(live_server))

    assert result["status"] == MISMATCH
    assert result["recorded_status"] == 200
    assert result["replay_status"] == 403
