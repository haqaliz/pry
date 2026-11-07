"""Append-only JSONL bank of findings for local reports."""

import json
import os
from pathlib import Path
from typing import List

REPORT_MISSING = "REPORT_MISSING"
REPORT_MALFORMED = "REPORT_MALFORMED"
REPORT_FAILED = "REPORT_FAILED"

CORPUS_ENV = "PRY_CORPUS"
DEFAULT_CORPUS = "~/.pry/corpus.jsonl"


class ReportError(Exception):
    """A report failure with a stable, machine-readable cause."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self) -> str:
        return "%s: %s" % (self.cause, self.message)


def corpus_path() -> Path:
    """Return the local corpus path, honoring the ``PRY_CORPUS`` override."""
    return Path(os.environ.get(CORPUS_ENV) or DEFAULT_CORPUS).expanduser()


def append_findings(records) -> Path:
    """Append one sorted JSON line per record at 0600, creating the dir 0700."""
    path = corpus_path()
    directory = path.parent
    try:
        created = not directory.exists()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if created:
            os.chmod(str(directory), 0o700)
        fd = os.open(
            str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.chmod(str(path), 0o600)
    except (OSError, TypeError, ValueError) as exc:
        raise ReportError(
            REPORT_FAILED, "cannot append corpus: %s" % exc
        ) from exc
    return path


def read_findings() -> List[dict]:
    """Read every banked record; a missing corpus is empty, not an error."""
    path = corpus_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ReportError(
            REPORT_FAILED, "cannot read corpus: %s" % exc
        ) from exc

    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError as exc:
            raise ReportError(
                REPORT_MALFORMED, "corpus line is not valid JSON"
            ) from exc
    return records
