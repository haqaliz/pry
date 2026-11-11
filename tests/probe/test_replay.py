"""Live proof replay tests (AT1-AT7).

Every replay uses an injected fetch; nothing here opens a socket.
"""

import pytest

from pry.own.target import normalize_target
from pry.own.tokens import TokenSigner
from pry.probe import replay
from pry.probe.sidecar import Response, TransportError

TARGET_URL = "https://app.example.com"
TARGET = {
    "sandbox_id": "live-0123456789ab",
    "path": TARGET_URL,
    "kind": "live",
    "url": TARGET_URL,
    "ownership_proof": "dns_txt",
    "git_commit": None,
    "git_dirty": None,
    "tree_sha256": None,
    "image": None,
    "image_digest": None,
    "port": None,
}
FINDING = {
    "probe": "cors",
    "verdict": "EXPOSED",
    "cause": None,
    "evidence": "CORS reflects the origin with credentials",
    "request": {
        "method": "GET",
        "url": TARGET_URL + "/",
        "headers": {
            "origin": "https://pry.invalid",
            "user-agent": "pry/0.1",
            "accept": "application/json",
            "authorization": "[redacted]",
            "cookie": "[redacted]",
        },
    },
    "response": {
        "status": 200,
        "headers": {"access-control-allow-origin": "https://pry.invalid"},
        "body": "ok",
    },
}


@pytest.fixture(autouse=True)
def ownership_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_KEY_FILE", str(tmp_path / "ownership.key"))


def _token(target=TARGET_URL):
    return TokenSigner().issue(normalize_target(target), "dns_txt")


def _payload(**overrides):
    payload = {"target": dict(TARGET), "finding": dict(FINDING)}
    payload.update(overrides)
    return payload


class FakeFetch:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    def __call__(self, method, url, headers):
        self.calls.append((method, url, dict(headers)))
        if self.exc is not None:
            raise self.exc
        return self.response


def _response(status=200, body="ok"):
    return Response(status, {"content-type": "text/plain"}, body, TARGET_URL + "/")


def test_a_matching_status_is_a_match_and_sends_only_safe_headers():
    fetch = FakeFetch(_response(200))

    result = replay.replay_bundle(_payload(), _token(), fetch=fetch)

    assert result["status"] == replay.MATCH
    assert result["probe"] == "cors"
    assert result["target"] == TARGET_URL
    assert result["recorded_status"] == 200
    assert result["replay_status"] == 200
    assert "status match only" in result["message"]
    assert fetch.calls == [
        ("GET", TARGET_URL + "/", {"user-agent": "pry/0.1", "accept": "application/json"})
    ]
    assert "authorization" not in fetch.calls[0][2]
    assert "cookie" not in fetch.calls[0][2]


def test_a_different_status_is_a_mismatch():
    fetch = FakeFetch(_response(403, "denied"))

    result = replay.replay_bundle(_payload(), _token(), fetch=fetch)

    assert result["status"] == replay.MISMATCH
    assert result["recorded_status"] == 200
    assert result["replay_status"] == 403
    assert "403" in result["message"]


def test_a_transport_failure_is_unverified():
    fetch = FakeFetch(
        exc=TransportError(replay.TARGET_UNREACHABLE, "connection refused")
    )

    result = replay.replay_bundle(_payload(), _token(), fetch=fetch)

    assert result["status"] == replay.UNVERIFIED
    assert result["cause"] == replay.TARGET_UNREACHABLE
    assert "connection refused" in result["message"]
    assert "replay_status" not in result


def test_a_local_bundle_is_refused_before_any_request():
    fetch = FakeFetch(_response())
    payload = _payload(target=dict(TARGET, kind="static", path="/repo"))

    with pytest.raises(replay.ReplayError) as exc:
        replay.replay_bundle(payload, _token(), fetch=fetch)

    assert exc.value.cause == replay.REPLAY_LIVE_ONLY
    assert fetch.calls == []


def test_a_write_finding_is_refused_before_any_request():
    fetch = FakeFetch(_response())
    finding = dict(FINDING, request=dict(FINDING["request"], method="POST"))

    with pytest.raises(replay.ReplayError) as exc:
        replay.replay_bundle(_payload(finding=finding), _token(), fetch=fetch)

    assert exc.value.cause == replay.REPLAY_READ_ONLY_ONLY
    assert fetch.calls == []


def test_a_foreign_request_url_is_refused_before_any_request():
    fetch = FakeFetch(_response())
    finding = dict(
        FINDING,
        request=dict(FINDING["request"], url="https://other.example/steal"),
    )

    with pytest.raises(replay.ReplayError) as exc:
        replay.replay_bundle(_payload(finding=finding), _token(), fetch=fetch)

    assert exc.value.cause == replay.REPLAY_TARGET_MISMATCH
    assert fetch.calls == []


def test_a_token_for_another_target_is_refused_before_any_request():
    fetch = FakeFetch(_response())

    with pytest.raises(Exception) as exc:
        replay.replay_bundle(
            _payload(), _token("https://other.example"), fetch=fetch
        )

    assert getattr(exc.value, "cause", "") in (
        "TOKEN_TARGET_MISMATCH",
        "TOKEN_INVALID",
    )
    assert fetch.calls == []


def test_a_malformed_recorded_status_is_refused():
    fetch = FakeFetch(_response())
    finding = dict(FINDING, response={"status": "200", "headers": {}, "body": ""})

    with pytest.raises(replay.ReplayError) as exc:
        replay.replay_bundle(_payload(finding=finding), _token(), fetch=fetch)

    assert exc.value.cause == replay.REPLAY_INVALID
    assert fetch.calls == []


def test_a_missing_user_agent_falls_back_to_pry():
    fetch = FakeFetch(_response())
    finding = dict(
        FINDING,
        request={"method": "GET", "url": TARGET_URL + "/", "headers": {}},
    )

    replay.replay_bundle(_payload(finding=finding), _token(), fetch=fetch)

    assert fetch.calls[0][2] == {"user-agent": "pry/0.1"}
