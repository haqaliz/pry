"""Local SSRF scripts: callback server and probe against loopback HTTP.

Nothing here starts Docker or touches a third-party target.
"""

import ast
import json
import socket
import threading
import urllib.parse
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import pry.probe.callback_server as callback_server
import pry.probe.ssrf_probe as ssrf_probe

NONCE = "0123456789abcdef0123456789abcdef"
ENDPOINT = "/api/fetch"
PARAMETER = "url"


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class _AppHandler(_QuietHandler):
    def _respond(self, status, body, headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        mode = self.server.mode
        if mode == "fetch":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            with urllib.request.urlopen(query["url"][0], timeout=5) as response:
                response.read()
            self._respond(200, b"fetched")
        elif mode == "large":
            self._respond(200, b"x" * 10000)
        elif mode == "redirect":
            self._respond(302, b"", {"Location": self.server.redirect_to})
        else:
            self._respond(200, b"ignored")


@contextmanager
def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _app(mode, **attributes):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    server.mode = mode
    for name, value in attributes.items():
        setattr(server, name, value)
    with _serve(server) as base:
        yield base


@contextmanager
def _callback(tmp_path):
    hits = tmp_path / "hits.jsonl"
    server = callback_server.create_server("127.0.0.1", 0, hits)
    with _serve(server) as base:
        yield base, hits


def _closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_callback_server_logs_each_get_as_jsonl_and_returns_200(tmp_path):
    hits = tmp_path / "nested" / "hits.jsonl"
    hits.parent.mkdir()
    server = callback_server.create_server("127.0.0.1", 0, hits)

    with _serve(server) as base:
        request = urllib.request.Request(
            base + "/" + NONCE, headers={"X-Test": "one"}
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            response.read()

    lines = hits.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert set(entry) == {"method", "path", "headers"}
    assert entry["method"] == "GET"
    assert entry["path"] == "/" + NONCE
    assert entry["headers"]["x-test"] == "one"


def test_callback_server_defaults():
    assert callback_server.DEFAULT_PORT == 9000
    assert callback_server.DEFAULT_HOST == "0.0.0.0"
    assert callback_server.DEFAULT_HITS == "/tmp/pry-callback-hits.jsonl"


def test_probe_hit_records_the_app_request_and_the_callback_request(tmp_path):
    with _app("fetch") as app_base, _callback(tmp_path) as (callback_base, hits):
        result = ssrf_probe.run_probe(
            app_base, ENDPOINT, PARAMETER, NONCE, callback_base, hits
        )

    assert result["hit"] is True
    assert result["cause"] is None
    assert result["app_response"]["status"] == 200
    assert result["app_response"]["body"] == "fetched"
    assert result["callback_hit"]["method"] == "GET"
    assert result["callback_hit"]["path"] == "/" + NONCE
    assert result["request"]["method"] == "GET"
    assert result["request"]["headers"] == {"user-agent": ssrf_probe.USER_AGENT}

    callback_url = callback_base + "/" + NONCE
    parts = urllib.parse.urlsplit(result["request"]["url"])
    assert parts.path == ENDPOINT
    assert urllib.parse.parse_qs(parts.query) == {PARAMETER: [callback_url]}


def test_probe_url_encodes_the_callback_url(tmp_path):
    with _app("ignore") as app_base, _callback(tmp_path) as (callback_base, hits):
        result = ssrf_probe.run_probe(
            app_base, ENDPOINT, PARAMETER, NONCE, callback_base, hits
        )

    callback_url = callback_base + "/" + NONCE
    url = result["request"]["url"]
    assert url.startswith(app_base + ENDPOINT + "?url=")
    assert "url=" + urllib.parse.quote_plus(callback_url) in url
    assert callback_url not in url


def test_probe_ignored_url_is_no_hit_after_the_poll(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(ssrf_probe, "HIT_TIMEOUT", 0.2)
    monkeypatch.setattr(ssrf_probe, "POLL_INTERVAL", 0.01)
    with _app("ignore") as app_base, _callback(tmp_path) as (callback_base, hits):
        result = ssrf_probe.run_probe(
            app_base, ENDPOINT, PARAMETER, NONCE, callback_base, hits
        )

    assert result["hit"] is False
    assert result["cause"] is None
    assert result["app_response"]["status"] == 200
    assert result["app_response"]["body"] == "ignored"
    assert result["callback_hit"] is None


def test_probe_app_request_failure_is_a_named_cause(tmp_path):
    with _callback(tmp_path) as (callback_base, hits):
        result = ssrf_probe.run_probe(
            "http://127.0.0.1:%d" % _closed_port(),
            ENDPOINT,
            PARAMETER,
            NONCE,
            callback_base,
            hits,
        )

    assert result["hit"] is False
    assert result["cause"] == ssrf_probe.SSRF_APP_REQUEST_FAILED
    assert result["app_response"] is None
    assert result["callback_hit"] is None


def test_probe_unreadable_hit_log_is_a_named_cause(tmp_path):
    hits = tmp_path / "hits-as-directory"
    hits.mkdir()
    with _app("ignore") as app_base, _callback(tmp_path) as (callback_base, _):
        result = ssrf_probe.run_probe(
            app_base, ENDPOINT, PARAMETER, NONCE, callback_base, hits
        )

    assert result["hit"] is False
    assert result["cause"] == ssrf_probe.SSRF_HIT_READ_FAILED
    assert result["app_response"]["status"] == 200
    assert result["callback_hit"] is None


def test_probe_caps_the_app_body_at_4_kib(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf_probe, "HIT_TIMEOUT", 0.2)
    monkeypatch.setattr(ssrf_probe, "POLL_INTERVAL", 0.01)
    with _app("large") as app_base, _callback(tmp_path) as (callback_base, hits):
        result = ssrf_probe.run_probe(
            app_base, ENDPOINT, PARAMETER, NONCE, callback_base, hits
        )

    assert result["app_response"]["status"] == 200
    assert len(result["app_response"]["body"]) == ssrf_probe.BODY_LIMIT
    assert ssrf_probe.BODY_LIMIT == 4096


def test_probe_does_not_follow_an_app_redirect(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf_probe, "HIT_TIMEOUT", 0.2)
    monkeypatch.setattr(ssrf_probe, "POLL_INTERVAL", 0.01)
    with _callback(tmp_path) as (callback_base, hits):
        with _app("redirect", redirect_to=callback_base + "/" + NONCE) as app_base:
            result = ssrf_probe.run_probe(
                app_base, ENDPOINT, PARAMETER, NONCE, callback_base, hits
            )

    assert result["hit"] is False
    assert result["cause"] is None
    assert result["app_response"]["status"] == 302
    assert not hits.exists()


def test_probe_uses_a_ten_second_app_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(ssrf_probe, "HIT_TIMEOUT", 0.2)
    monkeypatch.setattr(ssrf_probe, "POLL_INTERVAL", 0.01)
    calls = []

    def fetch(url, timeout):
        calls.append((url, timeout))
        return ssrf_probe.AppResponse(200, {}, "ok")

    result = ssrf_probe.run_probe(
        "http://app:8000",
        ENDPOINT,
        PARAMETER,
        NONCE,
        "http://pry-callback:9000",
        tmp_path / "missing.jsonl",
        fetch=fetch,
    )

    assert calls[0][1] == ssrf_probe.APP_TIMEOUT == 10
    assert result["hit"] is False
    assert result["cause"] is None


def test_probe_main_prints_json_and_exits_zero(tmp_path, capsys):
    with _app("fetch") as app_base, _callback(tmp_path) as (callback_base, hits):
        code = ssrf_probe.main(
            [app_base, ENDPOINT, PARAMETER, NONCE, callback_base, str(hits)]
        )

    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["hit"] is True
    assert payload["callback_hit"]["path"] == "/" + NONCE


def test_probe_main_defaults_the_hit_log_to_the_sandbox_tmp():
    assert ssrf_probe.DEFAULT_HITS == "/tmp/pry-callback-hits.jsonl"


@pytest.mark.parametrize(
    "module", [callback_server, ssrf_probe]
)
def test_ssrf_scripts_are_standard_library_only(module):
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")

    assert imported
    assert not any(
        name == "pry" or name.startswith("pry.") for name in imported
    ), imported
