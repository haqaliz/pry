"""Local SSRF probe script. Standard library only; mounted in the sidecar.

Run as ``python /pry/ssrf_probe.py APP_BASE ENDPOINT PARAMETER NONCE
CALLBACK_BASE [HITS_PATH]``. It GETs the declared app endpoint with the
callback URL as a query value, then polls the callback hit log for the nonce.
It prints one JSON object and exits 0; failures are named causes, not crashes.
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

BODY_LIMIT = 4096
APP_TIMEOUT = 10
HIT_TIMEOUT = 5.0
POLL_INTERVAL = 0.05
USER_AGENT = "pry/0.1"
DEFAULT_HITS = "/tmp/pry-callback-hits.jsonl"

SSRF_APP_REQUEST_FAILED = "SSRF_APP_REQUEST_FAILED"
SSRF_HIT_READ_FAILED = "SSRF_HIT_READ_FAILED"


@dataclass(frozen=True)
class AppResponse:
    status: int
    headers: dict
    body: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _headers(headers) -> dict:
    return {
        str(name).lower(): str(value) for name, value in (headers or {}).items()
    }


def _read_text(response) -> str:
    raw = response.read(BODY_LIMIT)
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")[:BODY_LIMIT]
    return str(raw)[:BODY_LIMIT]


def fetch_url(url: str, timeout: float = APP_TIMEOUT) -> AppResponse:
    """GET with no credentials, no redirects, and a capped body."""
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT}, method="GET"
    )
    try:
        response = _OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return AppResponse(exc.code, _headers(exc.headers), _read_text(exc))
    try:
        return AppResponse(
            int(response.status), _headers(response.headers), _read_text(response)
        )
    finally:
        close = getattr(response, "close", None)
        if close is not None:
            close()


def _find_hit(hits_path, nonce):
    """Return (hit, cause): the recorded request for /<nonce>, or a failure."""
    target = "/" + nonce
    deadline = time.monotonic() + HIT_TIMEOUT
    while True:
        try:
            with open(hits_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(entry, dict) and entry.get("path") == target:
                        return entry, None
        except FileNotFoundError:
            pass
        except OSError:
            return None, SSRF_HIT_READ_FAILED
        if time.monotonic() >= deadline:
            return None, None
        time.sleep(POLL_INTERVAL)


def run_probe(
    app_base,
    endpoint,
    parameter,
    nonce,
    callback_base,
    hits_path,
    fetch=None,
):
    """Try the declared fetch endpoint and look for the nonce in the hit log."""
    fetch = fetch if fetch is not None else fetch_url
    callback_url = callback_base.rstrip("/") + "/" + nonce
    url = (
        app_base.rstrip("/")
        + endpoint
        + "?"
        + urllib.parse.urlencode({parameter: callback_url})
    )
    request = {
        "method": "GET",
        "url": url,
        "headers": {"user-agent": USER_AGENT},
    }

    try:
        response = fetch(url, APP_TIMEOUT)
        app_response = {
            "status": int(response.status),
            "headers": _headers(response.headers),
            "body": str(response.body or "")[:BODY_LIMIT],
        }
    except Exception:
        return {
            "hit": False,
            "cause": SSRF_APP_REQUEST_FAILED,
            "request": request,
            "app_response": None,
            "callback_hit": None,
        }

    hit, cause = _find_hit(hits_path, nonce)
    return {
        "hit": hit is not None,
        "cause": cause,
        "request": request,
        "app_response": app_response,
        "callback_hit": hit,
    }


def main(argv=None, fetch=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    usage = (
        "usage: ssrf_probe.py APP_BASE ENDPOINT PARAMETER NONCE CALLBACK_BASE "
        "[HITS_PATH]\n"
    )
    if len(args) not in (5, 6):
        sys.stderr.write(usage)
        return 2
    app_base, endpoint, parameter, nonce, callback_base = args[:5]
    hits_path = args[5] if len(args) == 6 else DEFAULT_HITS
    payload = run_probe(
        app_base, endpoint, parameter, nonce, callback_base, hits_path, fetch=fetch
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
