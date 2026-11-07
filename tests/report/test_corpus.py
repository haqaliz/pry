"""Corpus append/read tests (AT1)."""

import json
import stat

import pytest

from pry.report.corpus import (
    REPORT_FAILED,
    REPORT_MALFORMED,
    ReportError,
    append_findings,
    corpus_path,
    read_findings,
)


@pytest.fixture(autouse=True)
def corpus_home(tmp_path, monkeypatch):
    path = tmp_path / "home" / ".pry" / "corpus.jsonl"
    monkeypatch.setenv("PRY_CORPUS", str(path))
    return path


def _record(**overrides):
    record = {
        "created_at": "2026-11-08T00:00:00Z",
        "sandbox_id": "pry-0123456789ab",
        "target": "/repos/acme-app",
        "kind": "node",
        "probe": "cors",
        "verdict": "EXPOSED",
        "cause": None,
        "proof": "proofs/" + "a" * 64 + ".json",
        "fingerprint": "sha256:" + "b" * 64,
    }
    record.update(overrides)
    return record


def test_append_writes_one_sorted_json_line_per_record(corpus_home):
    first = _record(probe="cors")
    second = _record(probe="secrets")

    append_findings([first, second])

    lines = corpus_home.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert lines[0] == json.dumps(first, sort_keys=True)
    assert lines[1] == json.dumps(second, sort_keys=True)
    assert read_findings() == [first, second]


def test_append_is_additive(corpus_home):
    append_findings([_record(probe="cors")])
    append_findings([_record(probe="secrets")])

    assert [record["probe"] for record in read_findings()] == ["cors", "secrets"]


def test_append_creates_the_directory_at_0700_and_file_at_0600(corpus_home):
    append_findings([_record()])

    assert stat.S_IMODE(corpus_home.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(corpus_home.stat().st_mode) == 0o600


def test_corpus_path_defaults_to_home_and_expands_user(monkeypatch, tmp_path):
    monkeypatch.delenv("PRY_CORPUS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    assert corpus_path() == tmp_path / ".pry" / "corpus.jsonl"


def test_corpus_path_uses_the_pry_corpus_override(monkeypatch, tmp_path):
    monkeypatch.setenv("PRY_CORPUS", "~/custom/bank.jsonl")
    monkeypatch.setenv("HOME", str(tmp_path))

    assert corpus_path() == tmp_path / "custom" / "bank.jsonl"


def test_read_missing_corpus_returns_an_empty_list(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_CORPUS", str(tmp_path / "missing" / "corpus.jsonl"))

    assert read_findings() == []


def test_write_failure_raises_report_failed(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("PRY_CORPUS", str(blocker / "corpus.jsonl"))

    with pytest.raises(ReportError) as exc:
        append_findings([_record()])

    assert exc.value.cause == REPORT_FAILED


def test_read_malformed_corpus_raises_report_malformed(tmp_path, monkeypatch):
    path = tmp_path / "corpus.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    monkeypatch.setenv("PRY_CORPUS", str(path))

    with pytest.raises(ReportError) as exc:
        read_findings()

    assert exc.value.cause == REPORT_MALFORMED
