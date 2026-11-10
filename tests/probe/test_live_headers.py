"""Live header-observation scan tests (AT2, AT4, AT5).

Every probe is faked here: nothing in this file sends a request.
"""

import json

import pytest

import pry.probe.live as live
from pry.own.errors import OwnershipError
from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe.headers import OBSERVED
from pry.probe.results import EXPOSED, NOT_REPRODUCED, UNVERIFIED

ORIGIN = "https://app.example.com"


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


@pytest.fixture(autouse=True)
def proof_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_PROOF_KEY", str(tmp_path / "proof.key"))


def _token():
    return TokenSigner().issue(normalize_target(ORIGIN), "dns_txt")


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


@pytest.fixture
def fake_probes(monkeypatch):
    calls = []

    def probe(name):
        def run(base_url):
            calls.append((name, base_url))
            return _payload(name)

        return run

    monkeypatch.setattr(live, "probe_cors", probe("cors"))
    monkeypatch.setattr(live, "probe_errors", probe("errors"))
    monkeypatch.setattr(live, "probe_secrets", probe("secrets"))
    monkeypatch.setattr(live, "probe_database", probe("database"))
    return calls


def _observation(status=OBSERVED):
    return {
        "probe": "headers",
        "status": status,
        "evidence": "6 recommended response headers checked on /: 1 present, "
        "5 missing (hardening observation)",
        "request": {
            "method": "GET",
            "url": ORIGIN + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": {"status": 200, "headers": {}, "body": "ok"},
        "missing": ["content-security-policy"],
        "present": ["x-frame-options"],
    }


def _unverified_observation():
    return {
        "probe": "headers",
        "status": UNVERIFIED,
        "evidence": "TARGET_UNREACHABLE: transport failure: connection refused",
        "request": {
            "method": "GET",
            "url": ORIGIN + "/",
            "headers": {"User-Agent": "pry/0.1"},
        },
        "response": None,
        "missing": [],
        "present": [],
    }


def test_scan_live_with_headers_appends_the_in_process_observation(
    tmp_path, fake_probes, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        live,
        "probe_headers",
        lambda base_url: calls.append(base_url) or _observation(),
    )

    outcome = live.scan_live(
        ORIGIN, _token(), headers=True, out=tmp_path / "run"
    )

    assert calls == [ORIGIN]
    assert fake_probes == [
        ("cors", ORIGIN),
        ("errors", ORIGIN),
        ("secrets", ORIGIN),
        ("database", ORIGIN),
    ]
    assert [result.probe for result in outcome.results] == [
        "cors",
        "errors",
        "secrets",
        "database",
    ]
    assert [observation["probe"] for observation in outcome.observations] == [
        "headers"
    ]
    observation = outcome.observations[0]
    assert observation["status"] == OBSERVED
    assert observation["missing"] == ["content-security-policy"]
    assert observation["present"] == ["x-frame-options"]
    assert "proof" not in observation
    assert "verdict" not in observation
    assert outcome.summary == {
        EXPOSED: 0,
        NOT_REPRODUCED: 4,
        UNVERIFIED: 0,
    }

    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert data["observations"][0]["probe"] == "headers"
    assert "proof" not in data["observations"][0]
    assert "verdict" not in data["observations"][0]
    assert not (tmp_path / "run" / "proofs").exists()


def test_scan_live_without_headers_does_not_run_the_header_probe(
    tmp_path, fake_probes, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        live, "probe_headers", lambda base_url: calls.append(base_url)
    )

    outcome = live.scan_live(ORIGIN, _token(), out=tmp_path / "run")

    assert calls == []
    assert outcome.observations == []
    data = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert data["observations"] == []


def test_scan_live_validates_ownership_before_the_header_probe(
    tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        live, "probe_headers", lambda base_url: calls.append(base_url)
    )

    with pytest.raises(OwnershipError):
        live.scan_live(
            ORIGIN, "garbage", headers=True, out=tmp_path / "run"
        )

    assert calls == []
    assert not (tmp_path / "run").exists()


def test_scan_live_records_a_transport_failure_as_unverified(
    tmp_path, fake_probes, monkeypatch
):
    monkeypatch.setattr(
        live, "probe_headers", lambda base_url: _unverified_observation()
    )

    outcome = live.scan_live(
        ORIGIN, _token(), headers=True, out=tmp_path / "run"
    )

    observation = outcome.observations[0]
    assert observation["status"] == UNVERIFIED
    assert observation["response"] is None
    assert observation["missing"] == []
    assert observation["present"] == []
    assert "TARGET_UNREACHABLE" in observation["evidence"]
    assert outcome.summary[EXPOSED] == 0
