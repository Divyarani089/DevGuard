"""DevGuard zero-dependency web dashboard."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .scan import scan_project


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"

HOST = "127.0.0.1"
PORT = 8000


class DevGuardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the DevGuard dashboard."""

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(data)),
        )
        self.end_headers()

        self.wfile.write(data)

    def _send_file(self, file_path: Path) -> None:
        if not file_path.exists() or not file_path.is_file():
            self.send_error(404, "File not found")
            return

        data = file_path.read_bytes()

        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }

        content_type = content_types.get(
            file_path.suffix.lower(),
            "application/octet-stream",
        )

        self.send_response(200)
        self.send_header(
            "Content-Type",
            content_type,
        )
        self.send_header(
            "Content-Length",
            str(len(data)),
        )
        self.end_headers()

        self.wfile.write(data)

    def do_GET(self) -> None:
        """Serve dashboard files."""

        if self.path in ("/", "/index.html"):
            self._send_file(FRONTEND_DIR / "index.html")
            return

        if self.path == "/style.css":
            self._send_file(FRONTEND_DIR / "style.css")
            return

        if self.path == "/app.js":
            self._send_file(FRONTEND_DIR / "app.js")
            return

        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        """Run a DevGuard project scan."""

        if self.path != "/api/scan":
            self.send_error(404, "Not found")
            return

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )

            raw_body = self.rfile.read(content_length)

            payload = json.loads(
                raw_body.decode("utf-8")
            )

            project_path = str(
                payload.get("path", "")
            ).strip()

            if not project_path:
                self._send_json(
                    {"error": "Project path is required."},
                    status=400,
                )
                return

            findings = scan_project(project_path)

            serialized_findings = [
                finding.to_dict()
                for finding in findings
            ]

            self._send_json(
                {
                    "success": True,
                    "findings": serialized_findings,
                    "total": len(serialized_findings),
                }
            )

        except FileNotFoundError as exc:
            self._send_json(
                {"error": str(exc)},
                status=400,
            )

        except NotADirectoryError as exc:
            self._send_json(
                {"error": str(exc)},
                status=400,
            )

        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            self._send_json(
                {"error": "Invalid request data."},
                status=400,
            )

        except Exception as exc:
            self._send_json(
                {"error": f"Scan failed: {exc}"},
                status=500,
            )

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        """Keep terminal output simple."""

        print(f"[DevGuard] {format % args}")


def run_server() -> None:
    """Start the local DevGuard dashboard server."""

    if not FRONTEND_DIR.is_dir():
        raise FileNotFoundError(
            f"Frontend directory not found: {FRONTEND_DIR}"
        )

    server = ThreadingHTTPServer(
        (HOST, PORT),
        DevGuardHandler,
    )

    print(
        f"DevGuard dashboard running at "
        f"http://{HOST}:{PORT}"
    )
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nStopping DevGuard dashboard...")

    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()