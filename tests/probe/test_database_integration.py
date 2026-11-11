"""Database integration checks.

Served database files are opt-in Docker tests. Provider database rules use a
loopback HTTP server only; no third-party target and no Docker.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from pry.cli import main
from pry.probe.results import EXPOSED, NOT_REPRODUCED
from pry.probe.scan import scan_local
from pry.proof import load_bundle, verify_bundle
from pry.report import load_run, write_report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FAKE_ROW = "fixture-row@example.invalid"

_requires_docker = pytest.mark.skipif(
    os.environ.get("PRY_DOCKER_TESTS") != "1",
    reason="set PRY_DOCKER_TESTS=1 to run Docker integration tests",
)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "corpus.jsonl"))


@pytest.mark.docker
@_requires_docker
def test_served_sql_dump_is_exposed_and_rows_are_not_stored(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "vulnerable-app"), out=tmp_path / "run", timeout=60
    )

    database = next(
        result for result in outcome.results if result.probe == "database"
    )
    assert database.verdict == EXPOSED
    assert database.proof is not None
    assert "SQL dump content withheld" in database.response["body"]
    assert FAKE_ROW not in str(outcome.results)

    payload, fingerprint = verify_bundle(load_bundle(database.proof))
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["probe"] == "database"
    assert fingerprint.startswith("sha256:")

    write_report(tmp_path / "run")
    report = load_run(tmp_path / "run")
    assert report.counts[EXPOSED] >= 1
    report_text = (tmp_path / "run" / "report.html").read_text(encoding="utf-8")
    assert "database" in report_text
    assert FAKE_ROW not in report_text

    for path in Path(tmp_path / "run").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert FAKE_ROW not in text


@pytest.mark.docker
@_requires_docker
def test_safe_fixture_has_no_database_exposure(tmp_path):
    outcome = scan_local(
        str(FIXTURES / "safe-app"), out=tmp_path / "run", timeout=60
    )

    database = next(
        result for result in outcome.results if result.probe == "database"
    )
    assert database.verdict == NOT_REPRODUCED
    assert database.proof is None


PROVIDER_MARKER = "pry-test-marker-abc123"
SUPABASE_ANON_KEY = "pry-anon-key-1234567890"
SUPABASE_MARKER_PATH = "/rest/v1/pry_ownership?select=marker"
SUPABASE_DATA_PATH = "/rest/v1/users?select=*"


class ProviderHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get("apikey")))
        routes = {
            "/marker.json": json.dumps(PROVIDER_MARKER),
            "/data.json": '{"users":[{"id":1}]}',
            SUPABASE_MARKER_PATH: json.dumps([{"marker": PROVIDER_MARKER}]),
            SUPABASE_DATA_PATH: '[{"id":1}]',
        }
        body = routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def provider_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port, server.requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _write_config(tmp_path, data):
    path = tmp_path / "db.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(str(path), 0o600)
    return path


def _database_argv(config_path, run_dir):
    return [
        "database",
        "--config",
        str(config_path),
        "--confirm-marker",
        "--out",
        str(run_dir),
        "--json",
    ]


def test_firebase_database_check_exposes_signs_and_reports(
    provider_server, tmp_path, capsys
):
    base, requests = provider_server
    config_path = _write_config(
        tmp_path,
        {
            "provider": "firebase-rtdb",
            "url": base,
            "marker_path": "/marker.json",
            "marker": PROVIDER_MARKER,
            "read_path": "/data.json",
        },
    )
    run_dir = tmp_path / "run"

    assert main(_database_argv(config_path, run_dir)) == 1

    data = json.loads(capsys.readouterr().out)
    assert data["summary"][EXPOSED] == 1
    assert [path for path, _apikey in requests] == [
        "/marker.json",
        "/data.json",
    ]
    assert all(apikey is None for _path, apikey in requests)

    payload, fingerprint = verify_bundle(load_bundle(data["proof"]))
    assert payload["finding"]["verdict"] == EXPOSED
    assert payload["finding"]["probe"] == "database_rules"
    assert fingerprint.startswith("sha256:")

    report_path = write_report(run_dir)
    report = load_run(run_dir)
    assert report.counts[EXPOSED] == 1
    html = report_path.read_text(encoding="utf-8")
    assert "database" in html
    assert "Ownership proof" in html
    assert "database_marker" in html
    assert base in html


def test_supabase_database_check_sends_and_redacts_the_anon_key(
    provider_server, tmp_path, capsys
):
    base, requests = provider_server
    config_path = _write_config(
        tmp_path,
        {
            "provider": "supabase",
            "url": base,
            "marker_path": SUPABASE_MARKER_PATH,
            "marker": PROVIDER_MARKER,
            "read_path": SUPABASE_DATA_PATH,
            "anon_key": SUPABASE_ANON_KEY,
        },
    )
    run_dir = tmp_path / "run"

    assert main(_database_argv(config_path, run_dir)) == 1

    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert data["summary"][EXPOSED] == 1
    assert [path for path, _apikey in requests] == [
        SUPABASE_MARKER_PATH,
        SUPABASE_DATA_PATH,
    ]
    assert [apikey for _path, apikey in requests] == [
        SUPABASE_ANON_KEY,
        SUPABASE_ANON_KEY,
    ]

    payload, _fingerprint = verify_bundle(load_bundle(data["proof"]))
    assert payload["finding"]["verdict"] == EXPOSED
    assert (
        payload["finding"]["request"]["headers"]["apikey"] == "[redacted]"
    )

    write_report(run_dir)
    texts = [raw]
    for path in Path(run_dir).rglob("*"):
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    for text in texts:
        assert SUPABASE_ANON_KEY not in text
    assert str(config_path) not in raw
