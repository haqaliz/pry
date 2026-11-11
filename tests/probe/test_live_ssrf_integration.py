"""Loopback end-to-end for live SSRF with a user callback (AT9).

No third-party target and no Docker; both servers are on 127.0.0.1 only.
"""

import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.live import scan_live
from pry.probe.live_ssrf import LiveSsrfConfig
from pry.probe.results import EXPOSED, NOT_REPRODUCED
from pry.proof import load_bundle, verify_bundle


class Loopback:
    def __init__(self, handler):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.url = "http://127.0.0.1:%d" % self.server.server_port

    def __enter__(self):
        self.thread.start()
        return self.url

    def __exit__(self, *exc_info):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _callback_handler():
    hits = set()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # The app's own fetch records the path; Pry's polls only read it.
            if self.headers.get("User-Agent", "").startswith("pry/"):
                status = 200 if self.path in hits else 404
            else:
                hits.add(self.path)
                status = 200
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"hit\n" if status == 200 else b"no hit\n")

        def log_message(self, format, *args):
            pass

    return Handler


def _target_handler(follow):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = urllib.parse.urlsplit(self.path)
            if parts.path == "/fetch":
                url = urllib.parse.parse_qs(parts.query).get("url", [""])[0]
                if follow and url:
                    threading.Thread(
                        target=_fetch, args=(url,), daemon=True
                    ).start()
                self.send_response(200)
            else:
                self.send_response(404)
            self.end_headers()
            self.wfile.write(b"ok\n")

        def log_message(self, format, *args):
            pass

    return Handler


def _fetch(url):
    try:
        urllib.request.urlopen(url, timeout=5).read()
    except Exception:
        pass


def _scan(target, callback, tmp_path):
    token = TokenSigner().issue(normalize_target(target), "dns_txt")
    return scan_live(
        target,
        token,
        ssrf_config=LiveSsrfConfig(
            endpoint="/fetch", parameter="url", callback_url=callback
        ),
        out=tmp_path / "run",
    )


@pytest.fixture(autouse=True)
def isolated_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


def test_live_ssrf_reproduces_a_callback_hit_and_signs_it(tmp_path):
    with Loopback(_callback_handler()) as callback, Loopback(
        _target_handler(follow=True)
    ) as target:
        outcome = _scan(target, callback, tmp_path)

    ssrf = next(result for result in outcome.results if result.probe == "ssrf")
    assert ssrf.verdict == EXPOSED
    assert ssrf.proof is not None

    payload, fingerprint = verify_bundle(load_bundle(ssrf.proof))
    finding = payload["finding"]
    assert finding["probe"] == "ssrf"
    assert finding["verdict"] == EXPOSED
    pair = finding["response"]["callback"]
    assert pair["attempts"] >= 1
    assert pair["response"]["status"] == 200
    assert pair["request"]["url"].startswith(callback + "/")
    nonce = pair["request"]["url"].rsplit("/", 1)[1]
    assert nonce in finding["evidence"]
    assert finding["request"]["url"].startswith(target + "/fetch?url=")
    assert fingerprint.startswith("sha256:")


def test_live_ssrf_without_a_fetch_is_not_reproduced(tmp_path):
    with Loopback(_callback_handler()) as callback, Loopback(
        _target_handler(follow=False)
    ) as target:
        outcome = _scan(target, callback, tmp_path)

    ssrf = next(result for result in outcome.results if result.probe == "ssrf")
    assert ssrf.verdict == NOT_REPRODUCED
    assert ssrf.proof is None
    assert ssrf.response["callback"]["attempts"] == 3
    assert ssrf.response["callback"]["response"]["status"] == 404
