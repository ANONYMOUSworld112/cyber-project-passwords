from __future__ import annotations

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Optional
from urllib.parse import urlparse

from csp.web import api
from csp.web.session import cleanup_expired, wipe_all

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".svg": "image/svg+xml",
}


class CSPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[csp] {args[0]} {args[1]} {args[2]}\n")

    def _send_json(self, data: Any, status: int = 200, headers: Optional[dict] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode("utf-8"))

    def _read_file(self, rel_path: str) -> Optional[bytes]:
        """Read a file from STATIC_DIR, return bytes or None."""
        if ".." in rel_path.replace("\\", "/"):
            return None
        abspath = os.path.normpath(os.path.join(STATIC_DIR, rel_path))
        norm_static = os.path.normpath(STATIC_DIR)
        if os.path.commonpath([abspath, norm_static]) != norm_static:
            return None
        try:
            with open(abspath, "rb") as f:
                return f.read()
        except OSError:
            return None

    def _respond_file(self, content: bytes, mime: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(content)

    def _handle_api(self, method: str) -> None:
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        cleanup_expired()
        handled = api.dispatch(self, method, parts)
        if not handled:
            self._send_json({"error": "not found"}, 404)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path.startswith("/api/"):
            self._handle_api("GET")
            return

        if path == "/" or path == "/index.html":
            data = self._read_file("index.html")
            if data:
                self._respond_file(data, "text/html; charset=utf-8")
            else:
                self.send_error(404)
            return

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            ext = os.path.splitext(rel)[1].lower()
            mime = MIME_TYPES.get(ext, "application/octet-stream")
            data = self._read_file(rel)
            if data:
                self._respond_file(data, mime)
            else:
                data = self._read_file("index.html")
                if data:
                    self._respond_file(data, "text/html; charset=utf-8")
                else:
                    self.send_error(404)
            return

        data = self._read_file("index.html")
        if data:
            self._respond_file(data, "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if not self.path.startswith("/api/"):
            self.send_error(405)
            return
        self._handle_api("POST")

    def do_PUT(self) -> None:
        if not self.path.startswith("/api/"):
            self.send_error(405)
            return
        self._handle_api("PUT")

    def do_DELETE(self) -> None:
        if not self.path.startswith("/api/"):
            self.send_error(405)
            return
        self._handle_api("DELETE")


def run_server(host: str = "127.0.0.1", port: int = 8899) -> None:
    server = HTTPServer((host, port), CSPRequestHandler)
    print(f"[csp] web interface at http://{host}:{port}")
    print(f"[csp] press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        print("[csp] wiping sessions...")
        wipe_all()
        server.server_close()
        print("[csp] stopped.")
