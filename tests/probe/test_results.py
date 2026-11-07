"""Probe result, redaction, and results.json tests (AT13).

The result model is the host-side contract: an unknown verdict must never be
serialized, secret values must never reach results.json, and headers are
always lowercase.
"""

import json
import stat
from dataclasses import fields

import pytest

from pry.probe.results import (
    BODY_LIMIT,
    EXPOSED,
    NOT_REPRODUCED,
    RESULTS_FAILED,
    UNVERIFIED,
    ProbeError,
    ProbeResult,
    ScanResult,
    normalize_headers,
    redact_secret,
    redact_urls,
    summarize,
    write_results,
)


def _result(verdict=EXPOSED, probe="cors"):
    return ProbeResult(
        probe=probe,
        verdict=verdict,
        cause=None,
        evidence="Access-Control-Allow-Origin reflects https://pry.invalid",
        request={
            "method": "GET",
            "url": "http://app:3000/",
            "headers": {"Origin": "https://pry.invalid", "User-Agent": "pry/0.1"},
        },
        response={
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "https://pry.invalid",
                "Access-Control-Allow-Credentials": "true",
            },
            "body": "ok",
        },
    )


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_probe_result_has_exactly_the_contract_fields():
    assert [field.name for field in fields(ProbeResult)] == [
        "probe",
        "verdict",
        "cause",
        "evidence",
        "request",
        "response",
        "proof",
    ]


def test_probe_result_proof_defaults_to_none():
    assert _result().proof is None


def test_probe_result_accepts_a_proof_path():
    result = ProbeResult(
        probe="cors",
        verdict=EXPOSED,
        cause=None,
        evidence="reflected",
        request={"method": "GET", "url": "http://app/", "headers": {}},
        response={"status": 200, "headers": {}, "body": "ok"},
        proof="/run/proofs/" + "a" * 64 + ".json",
    )

    assert result.proof == "/run/proofs/" + "a" * 64 + ".json"


def test_probe_result_parses_a_sidecar_payload_without_proof():
    payload = {
        "probe": "cors",
        "verdict": NOT_REPRODUCED,
        "cause": None,
        "evidence": "cors checked",
        "request": {"method": "GET", "url": "http://app/", "headers": {}},
        "response": {"status": 200, "headers": {}, "body": "ok"},
    }

    assert ProbeResult(**payload).proof is None


def test_probe_result_requires_every_field():
    complete = {
        "probe": "cors",
        "verdict": EXPOSED,
        "cause": None,
        "evidence": "reflected",
        "request": {"method": "GET", "url": "http://app/", "headers": {}},
        "response": {"status": 200, "headers": {}, "body": ""},
    }
    for name in list(complete):
        missing = dict(complete)
        del missing[name]
        with pytest.raises(TypeError):
            ProbeResult(**missing)


@pytest.mark.parametrize("verdict", [EXPOSED, NOT_REPRODUCED, UNVERIFIED])
def test_probe_result_accepts_the_three_verdicts(verdict):
    assert _result(verdict).verdict == verdict


@pytest.mark.parametrize("verdict", ["SAFE", "SECURE", "", "exposed"])
def test_probe_result_rejects_any_other_verdict(verdict):
    with pytest.raises(ValueError):
        _result(verdict)


def test_probe_result_lowercases_request_and_response_headers():
    result = _result()

    assert result.request["headers"] == {
        "origin": "https://pry.invalid",
        "user-agent": "pry/0.1",
    }
    assert result.response["headers"] == {
        "access-control-allow-origin": "https://pry.invalid",
        "access-control-allow-credentials": "true",
    }
    assert result.request["method"] == "GET"


def test_probe_result_caps_the_response_body():
    result = ProbeResult(
        probe="secrets",
        verdict=EXPOSED,
        cause=None,
        evidence="DATABASE_URL found",
        request={"method": "GET", "url": "http://app/.env", "headers": {}},
        response={"status": 200, "headers": {}, "body": "x" * (BODY_LIMIT + 100)},
    )

    assert len(result.response["body"]) == BODY_LIMIT
    assert BODY_LIMIT == 4096


def test_normalize_headers_lowercases_keys_and_strings_values():
    assert normalize_headers(
        {"Content-Type": "text/plain", "X-Count": 3}
    ) == {"content-type": "text/plain", "x-count": "3"}


def test_normalize_headers_turns_none_into_an_empty_dict():
    assert normalize_headers(None) == {}


def test_scan_result_has_exactly_the_contract_fields():
    scan = ScanResult(
        version=1,
        target={"sandbox_id": "pry-0123456789ab", "path": "/tmp/app", "kind": "static"},
        results=[_result(EXPOSED), _result(NOT_REPRODUCED, "errors")],
        summary={EXPOSED: 1, NOT_REPRODUCED: 1, UNVERIFIED: 0},
        created_at="2026-11-07T00:00:00Z",
    )

    assert [field.name for field in fields(ScanResult)] == [
        "version",
        "target",
        "results",
        "summary",
        "created_at",
    ]
    assert scan.version == 1
    assert scan.target["sandbox_id"] == "pry-0123456789ab"
    assert len(scan.results) == 2
    assert scan.summary[EXPOSED] == 1
    assert scan.created_at.endswith("Z")


def test_summarize_counts_every_verdict():
    results = [
        _result(EXPOSED),
        _result(EXPOSED),
        _result(NOT_REPRODUCED),
        _result(UNVERIFIED),
    ]

    assert summarize(results) == {EXPOSED: 2, NOT_REPRODUCED: 1, UNVERIFIED: 1}


def test_summarize_of_no_results_has_zero_counts():
    assert summarize([]) == {EXPOSED: 0, NOT_REPRODUCED: 0, UNVERIFIED: 0}


def test_redact_secret_replaces_the_value_and_keeps_the_key():
    text = (
        "APP_ENV=production\n"
        "DATABASE_URL=postgres://user:pass@db.local/app\n"
        "DEBUG=false\n"
    )

    redacted = redact_secret(text, "DATABASE_URL")

    assert "DATABASE_URL=[redacted]" in redacted
    assert "user:pass" not in redacted
    assert "postgres://" not in redacted
    assert "APP_ENV=production" in redacted
    assert "DEBUG=false" in redacted


def test_redact_secret_handles_aws_credentials_and_leaves_other_keys():
    text = (
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    redacted = redact_secret(text, "aws_secret_access_key")

    assert "aws_secret_access_key = [redacted]" in redacted
    assert "wJalr" not in redacted
    assert "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" in redacted


def test_redact_urls_hides_userinfo_and_keeps_the_host():
    redacted = redact_urls("DSN=postgres://user:pass@db.local:5432/app")

    assert "user:pass" not in redacted
    assert "postgres://[redacted]@db.local:5432/app" in redacted


def test_write_results_is_atomic_sorted_and_0600(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    data = {"version": 1, "summary": {UNVERIFIED: 0, EXPOSED: 1}, "target": {}}

    path = write_results(run_dir, data)

    assert path == run_dir / "results.json"
    assert _mode(path) == 0o600
    assert not (run_dir / "results.json.tmp").exists()
    assert path.read_text() == json.dumps(data, sort_keys=True, indent=2) + "\n"


def test_write_results_is_byte_identical_for_the_same_data(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    data = {"results": [], "version": 1}

    first = write_results(run_dir, data).read_bytes()
    second = write_results(run_dir, data).read_bytes()

    assert first == second


def test_write_results_maps_a_missing_directory_to_a_named_failure(tmp_path):
    with pytest.raises(ProbeError) as exc:
        write_results(tmp_path / "missing", {"version": 1})

    assert exc.value.cause == RESULTS_FAILED
