"""Local SSRF callback server. Standard library only; mounted in a sidecar.

Run as ``python /pry/callback_server.py --port 9000 --hits PATH``. Every GET is
appended to the hit log as one JSON object per line; the response is always 200.
"""

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9000
DEFAULT_HITS = "/tmp/pry-callback-hits.jsonl"


def _headers(headers) -> dict:
    return {
        str(name).lower(): str(value) for name, value in (headers or {}).items()
    }


class _Handler(BaseHTTPRequestHandler):
    def _log_hit(self) -> None:
        entry = {
            "method": self.command,
            "path": self.path,
            "headers": _headers(self.headers),
        }
        with self.server.hits_lock:
            with open(self.server.hits_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
                handle.flush()

    def _ok(self) -> None:
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._log_hit()
        self._ok()

    def do_POST(self):
        self._ok()

    def do_HEAD(self):
        self._ok()

    def log_message(self, format, *args):
        pass


def create_server(host: str, port: int, hits_path) -> ThreadingHTTPServer:
    """Return a started-but-not-serving server for tests and ``main``."""
    server = ThreadingHTTPServer((host, port), _Handler)
    server.hits_path = str(hits_path)
    server.hits_lock = threading.Lock()
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="callback_server.py")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--hits", default=DEFAULT_HITS)
    args = parser.parse_args(argv)
    server = create_server(DEFAULT_HOST, args.port, args.hits)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
