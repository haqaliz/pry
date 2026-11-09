"""Live read-only scan tests (AT1-AT3, AT8).

Every probe is faked here: nothing in this file sends a request.
"""

import json
from pathlib import Path

import pytest

import pry.probe.live as live
from pry.own.errors import OwnershipError
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.idor import IdorConfig
from pry.probe.results import (
    EXPOSED,
    NOT_REPRODUCED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
    summarize,
)
from pry.probe.scan import ScanOutcome
from pry.proof import load_bundle, verify_bundle
from pry.report import write_report
from pry.report.corpus import read_findings

ORIGIN = "https://app.example.com"
OTHER = "https://other.example"
PROBES = ("cors", "errors", "secrets")


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    path = tmp_path / "ownership.key"
    monkeypatch.setenv("PRY_KEY_FILE", str(path))
    return path


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    path = tmp_path / "proof.key"
    monkeypatch.setenv("PRY_PROOF_KEY", str(path))
    return path


@pytest.fixture
def corpus_file(tmp_path):
    return tmp_path / "corpus.jsonl"


def _token(target=ORIGIN, proof="dns_txt"):
    return TokenSigner().issue(normalize_target(target), proof)


def _idor_config():
    return IdorConfig(
        headers_a={"Cookie": "sid=alice"},
        headers_b={"Cookie": "sid=bob"},
        object_a="/api/orders/1",
        object_b="/api/orders/2",
    )


def _payload(probe, verdict=NOT_REPRODUCED, url=ORIGIN + "/"):
    return {
        "probe": probe,
        "verdict": verdict,
        "cause": None,
        "evidence": "%s checked" % probe,
        "request": {
            "method": "GET",
            "url": url,
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
    }


class Sentinel:
    """A probe/fetch that must never run before ownership validation."""

    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("probe ran before ownership validation")


@pytest.fixture
def sentinel(monkeypatch):
    guard = Sentinel()
    for name in (
        "probe_cors",
        "probe_errors",
        "probe_secrets",
        "probe_unauth",
        "probe_idor",
    ):
        monkeypatch.setattr(live, name, guard)
    return guard


@pytest.fixture
def fake_probes(monkeypatch):
    calls = []

    def cors(base_url):
        calls.append(("cors", base_url))
        return _payload("cors", EXPOSED)

    def errors(base_url):
        calls.append(("errors", base_url))
        return _payload("errors", NOT_REPRODUCED, base_url + "/__pry_missing__")

    def secrets(base_url):
        calls.append(("secrets", base_url))
        return _payload("secrets", UNVERIFIED, base_url + "/.env")

    def unauth(base_url, path):
        calls.append(("unauth", base_url, path))
        return _payload("unauth", EXPOSED, base_url + path)

    monkeypatch.setattr(live, "probe_cors", cors)
    monkeypatch.setattr(live, "probe_errors", errors)
    monkeypatch.setattr(live, "probe_secrets", secrets)
    monkeypatch.setattr(live, "probe_unauth", unauth)
    return calls


@pytest.mark.parametrize(
    "token",
    [None, "", "garbage"],
)
def test_scan_live_rejects_a_missing_or_malformed_token_before_any_probe(
    tmp_path, sentinel, token
):
    with pytest.raises(OwnershipError):
        live.scan_live(ORIGIN, token, out=tmp_path / "run")

    assert sentinel.calls == []
    assert not (tmp_path / "run").exists()


def test_scan_live_rejects_a_token_for_another_target_before_any_probe(
    tmp_path, sentinel
):
    with pytest.raises(OwnershipError) as exc:
        live.scan_live(ORIGIN, _token(OTHER), out=tmp_path / "run")

    assert exc.value.cause == "TOKEN_TARGET_MISMATCH"
    assert sentinel.calls == []
    assert not (tmp_path / "run").exists()


def test_scan_live_rejects_an_invalid_endpoint_before_any_probe(
    tmp_path, sentinel
):
    with pytest.raises(ProbeError) as exc:
        live.scan_live(
            ORIGIN, _token(), endpoints=["http://evil.invalid"], out=tmp_path / "run"
        )

    assert exc.value.cause == "INVALID_ENDPOINT"
    assert sentinel.calls == []
    assert not (tmp_path / "run").exists()


def test_scan_live_runs_the_shared_probes_and_signs_exposed_findings(
    tmp_path, fake_probes
):
    token = _token()
    run_dir = tmp_path / "run"

    outcome = live.scan_live(ORIGIN + "/ignored?q=1", token, out=run_dir)

    assert isinstance(outcome, ScanOutcome)
    assert fake_probes == [
        ("cors", ORIGIN),
        ("errors", ORIGIN),
        ("secrets", ORIGIN),
    ]
    assert [result.probe for result in outcome.results] == list(PROBES)
    assert all(isinstance(result, ProbeResult) for result in outcome.results)
    assert [result.verdict for result in outcome.results] == [
        EXPOSED,
        NOT_REPRODUCED,
        UNVERIFIED,
    ]
    assert outcome.summary == summarize(outcome.results)
    assert outcome.summary == {EXPOSED: 1, NOT_REPRODUCED: 1, UNVERIFIED: 1}
    assert outcome.results_path == run_dir / "results.json"
    assert outcome.snapshot == json.loads(
        (run_dir / "snapshot.json").read_text(encoding="utf-8")
    )

    exposed = outcome.results[0]
    assert exposed.proof is not None
    assert Path(exposed.proof).is_file()
    assert outcome.results[1].proof is None
    assert outcome.results[2].proof is None
    payload, _fingerprint = verify_bundle(load_bundle(exposed.proof))
    assert payload["target"]["sandbox_id"] == outcome.snapshot["sandbox_id"]
    assert payload["target"]["kind"] == "live"
    assert payload["target"]["path"] == ORIGIN
    assert payload["finding"]["probe"] == "cors"
    assert payload["finding"]["verdict"] == EXPOSED

    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert set(data) == {
        "version",
        "target",
        "results",
        "summary",
        "observations",
        "created_at",
    }
    assert data["target"] == {
        "sandbox_id": outcome.snapshot["sandbox_id"],
        "path": ORIGIN,
        "kind": "live",
    }
    assert [entry["probe"] for entry in data["results"]] == list(PROBES)
    assert data["summary"] == outcome.summary


def test_scan_live_writes_a_live_snapshot(tmp_path, fake_probes):
    token = _token(proof="well_known")

    outcome = live.scan_live(ORIGIN + "/app", token, out=tmp_path / "run")
    snapshot = json.loads(
        (tmp_path / "run" / "snapshot.json").read_text(encoding="utf-8")
    )

    assert outcome.snapshot == snapshot
    assert snapshot["version"] == 1
    assert snapshot["sandbox_id"].startswith("live-")
    assert snapshot["created_at"].endswith("Z")
    assert snapshot["target"] == {
        "path": ORIGIN,
        "kind": "live",
        "url": ORIGIN,
        "ownership_proof": "well_known",
        "git_commit": None,
        "git_dirty": None,
        "tree_sha256": None,
    }
    assert snapshot["project"] == {
        "package_manager": None,
        "lockfile": None,
        "lockfile_sha256": None,
        "image": None,
        "image_digest": None,
        "install": None,
        "build": None,
        "start": None,
        "port": None,
    }
    assert snapshot["sandbox"] == {
        "network": "live",
        "container_id": None,
        "workspace": None,
        "internal_url": ORIGIN,
    }
    assert snapshot["result"] == {"status": "ready"}


def test_scan_live_runs_unauth_for_each_declared_endpoint(tmp_path, fake_probes):
    outcome = live.scan_live(
        ORIGIN,
        _token(),
        endpoints=["/api/users", "/api/admin"],
        out=tmp_path / "run",
    )

    assert fake_probes == [
        ("cors", ORIGIN),
        ("errors", ORIGIN),
        ("secrets", ORIGIN),
        ("unauth", ORIGIN, "/api/users"),
        ("unauth", ORIGIN, "/api/admin"),
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "unauth",
        "unauth",
    ]
    assert outcome.summary == {EXPOSED: 3, NOT_REPRODUCED: 1, UNVERIFIED: 1}


def test_scan_live_appends_the_configured_idor_result(
    tmp_path, fake_probes, monkeypatch
):
    calls = []

    def idor(base_url, config):
        calls.append((base_url, config))
        return _payload("idor", EXPOSED, base_url + config.object_b)

    monkeypatch.setattr(live, "probe_idor", idor)
    config = _idor_config()
    run_dir = tmp_path / "run"

    outcome = live.scan_live(
        ORIGIN,
        _token(),
        endpoints=["/api/users"],
        idor_config=config,
        out=run_dir,
    )

    assert calls == [(ORIGIN, config)]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "unauth",
        "idor",
    ]
    idor_result = outcome.results[-1]
    assert idor_result.verdict == EXPOSED
    assert idor_result.proof is not None
    payload, _fingerprint = verify_bundle(load_bundle(idor_result.proof))
    assert payload["finding"]["probe"] == "idor"
    assert payload["finding"]["verdict"] == EXPOSED
    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert data["results"][-1]["probe"] == "idor"
    assert outcome.summary == summarize(outcome.results)
    assert outcome.summary[EXPOSED] == 3


def test_scan_live_report_includes_the_idor_result(
    tmp_path, fake_probes, monkeypatch
):
    monkeypatch.setattr(
        live,
        "probe_idor",
        lambda base_url, config: _payload(
            "idor", NOT_REPRODUCED, base_url + config.object_b
        ),
    )

    outcome = live.scan_live(
        ORIGIN, _token(), idor_config=_idor_config(), out=tmp_path / "run"
    )
    report_path = write_report(Path(outcome.results_path).parent)
    rendered = report_path.read_text(encoding="utf-8")

    assert "idor" in rendered
    assert "NOT_REPRODUCED" in rendered


def test_scan_live_without_an_idor_config_does_not_run_it(
    tmp_path, fake_probes, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        live, "probe_idor", lambda *args, **kwargs: calls.append((args, kwargs))
    )

    outcome = live.scan_live(ORIGIN, _token(), out=tmp_path / "run")

    assert calls == []
    assert [result.probe for result in outcome.results] == list(PROBES)


def test_scan_live_validates_the_token_before_the_idor_probe(tmp_path, sentinel):
    with pytest.raises(OwnershipError):
        live.scan_live(
            ORIGIN,
            "garbage",
            idor_config=_idor_config(),
            out=tmp_path / "run",
        )

    assert sentinel.calls == []
    assert not (tmp_path / "run").exists()


def test_scan_live_appends_one_corpus_record_per_finding(
    tmp_path, fake_probes, corpus_file
):
    token = _token()
    outcome = live.scan_live(ORIGIN, token, out=tmp_path / "run")

    records = read_findings()

    assert outcome.corpus_error is None
    assert [record["probe"] for record in records] == list(PROBES)
    assert [record["verdict"] for record in records] == [
        EXPOSED,
        NOT_REPRODUCED,
        UNVERIFIED,
    ]
    assert all(record["kind"] == "live" for record in records)
    assert all(record["target"] == ORIGIN for record in records)
    assert all(
        record["sandbox_id"] == outcome.snapshot["sandbox_id"] for record in records
    )
    exposed = [record for record in records if record["verdict"] == EXPOSED]
    assert all(Path(record["proof"]).is_file() for record in exposed)
    for record in exposed:
        _payload, fingerprint = verify_bundle(load_bundle(record["proof"]))
        assert record["fingerprint"] == fingerprint


def test_scan_live_never_writes_the_token(tmp_path, fake_probes, corpus_file):
    token = _token()

    live.scan_live(ORIGIN, token, out=tmp_path / "run")

    texts = [
        (tmp_path / "run" / "snapshot.json").read_text(encoding="utf-8"),
        (tmp_path / "run" / "results.json").read_text(encoding="utf-8"),
        corpus_file.read_text(encoding="utf-8"),
    ]
    texts.extend(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "run" / "proofs").glob("*.json")
    )
    assert all(token not in text for text in texts)
