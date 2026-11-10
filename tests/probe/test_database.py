"""Exposed database file probe tests (AT1-AT6).

Every probe takes an injected ``fetch``; nothing here opens a socket.
"""

import json

import pytest

import pry.probe.sidecar as sidecar
from pry.probe.results import ProbeResult

BASE = "http://app:3000"
SQLITE_EXCERPT = "SQLite format 3\\x00 [binary database content withheld]"
SQLITE_BODY = "SQLite format 3\x00" + "fake-row-secret" + "\x00" * 16
DUMP_BODY = (
    "-- pry fixture dump\n"
    "-- generated for tests\n"
    "CREATE TABLE users (id INTEGER, email TEXT);\n"
    "INSERT INTO users VALUES (1, 'fake-row-secret@example.invalid');\n"
)


class FakeFetch:
    """Records each request and returns scripted responses or raises."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers):
        self.calls.append((method, url, dict(headers)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _response(status=404, body="", path="/", final_url=None):
    return sidecar.Response(
        status, {}, body, BASE + path if final_url is None else final_url
    )


def _all(status=404, body="", headers=None):
    return [
        sidecar.Response(status, headers or {}, body, BASE + path)
        for path in sidecar.DATABASE_PATHS
    ]


def test_database_paths_are_the_four_conventional_names():
    assert sidecar.DATABASE_PATHS == (
        "/data.db",
        "/app.db",
        "/db.sqlite",
        "/dump.sql",
    )


def test_a_sqlite_header_at_data_db_is_exposed_with_a_binary_excerpt():
    fetch = FakeFetch(_response(200, SQLITE_BODY, "/data.db"), *_all()[1:])

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["probe"] == "database"
    assert result["verdict"] == sidecar.EXPOSED
    assert result["cause"] is None
    assert "/data.db" in result["evidence"]
    assert "sqlite" in result["evidence"].lower()
    assert result["response"]["body"] == SQLITE_EXCERPT
    assert result["response"]["status"] == 200
    assert "fake-row-secret" not in json.dumps(result)
    assert fetch.calls == [
        (
            "GET",
            BASE + path,
            {"User-Agent": sidecar.USER_AGENT},
        )
        for path in sidecar.DATABASE_PATHS[:1]
    ]


def test_a_sql_dump_at_dump_sql_is_exposed_with_only_the_keyword():
    fetch = FakeFetch(*_all()[:3], _response(200, DUMP_BODY, "/dump.sql"))

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.EXPOSED
    assert "/dump.sql" in result["evidence"]
    assert "CREATE TABLE" in result["evidence"]
    assert result["response"]["body"] == (
        "CREATE TABLE [SQL dump content withheld]"
    )
    assert "fake-row-secret" not in json.dumps(result)
    assert "INSERT INTO" not in result["response"]["body"]
    assert len(fetch.calls) == len(sidecar.DATABASE_PATHS)


@pytest.mark.parametrize(
    "prefix,keyword",
    [
        ("PRAGMA foreign_keys=OFF;\n", "PRAGMA"),
        ("create table users (id integer);\n", "create table"),
        ("insert into users values (1);\n", "insert into"),
        ("BEGIN TRANSACTION;\n", "BEGIN TRANSACTION"),
        ("drop table users;\n", "drop table"),
    ],
)
def test_each_sql_dump_signature_is_exposed_after_comments(prefix, keyword):
    body = "\n-- generated dump\n  -- second comment\n \n" + prefix
    fetch = FakeFetch(_response(200, body, "/dump.sql"), *_all()[1:])

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.EXPOSED
    assert result["response"]["body"] == (
        keyword + " [SQL dump content withheld]"
    )


def test_a_sql_keyword_after_other_content_is_not_a_signature():
    body = "<html><body>learn to CREATE TABLE safely</body></html>"
    fetch = FakeFetch(*_all(200, body, {"Content-Type": "text/html"}))

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert result["response"]["body"] == body


@pytest.mark.parametrize("status", [401, 403, 404])
def test_rejected_statuses_are_not_reproduced(status):
    fetch = FakeFetch(*_all(status))

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert result["cause"] is None
    assert result["evidence"] == (
        "checked 4 database paths; no SQLite/SQL dump signature found in a "
        "same-origin 200 response"
    )
    assert result["response"]["status"] == status
    assert len(fetch.calls) == len(sidecar.DATABASE_PATHS)


def test_an_html_200_fallback_is_not_reproduced():
    body = "<!doctype html><html><body>app shell</body></html>"
    fetch = FakeFetch(*_all(200, body, {"Content-Type": "text/html"}))

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert "checked 4 database paths" in result["evidence"]
    assert len(fetch.calls) == len(sidecar.DATABASE_PATHS)


def test_a_foreign_origin_200_signature_is_not_reproduced():
    foreign = sidecar.Response(
        200, {}, SQLITE_BODY, "https://evil.invalid/data.db"
    )
    fetch = FakeFetch(foreign, *_all()[1:])

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.NOT_REPRODUCED
    assert result["response"]["body"] == SQLITE_EXCERPT
    assert "fake-row-secret" not in json.dumps(result)


def test_transport_failure_is_unverified_with_a_named_cause():
    fetch = FakeFetch(
        sidecar.TransportError(sidecar.TARGET_UNREACHABLE, "connection refused")
    )

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert result["verdict"] == sidecar.UNVERIFIED
    assert result["cause"] == sidecar.TARGET_UNREACHABLE
    assert result["response"] is None
    assert "Traceback" not in result["evidence"]


def test_the_database_result_loads_as_the_host_probe_result():
    fetch = FakeFetch(_response(200, SQLITE_BODY, "/data.db"), *_all()[1:])

    result = sidecar.probe_database(BASE, fetch=fetch)

    assert set(result) == {
        "probe",
        "verdict",
        "cause",
        "evidence",
        "request",
        "response",
    }
    assert set(result["request"]) == {"method", "url", "headers"}
    assert set(result["response"]) == {"status", "headers", "body"}
    host = ProbeResult(**result)
    assert host.probe == "database"
    assert host.verdict == sidecar.EXPOSED
