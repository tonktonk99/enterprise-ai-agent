import json
import os
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .agent import create_proposal
from .audit import AuditLog
from .local_model import model_name, model_ready
from .organization_qa import OrganizationDataStore, answer_question, parse_import_payload
from .security import scan_proposed_files
from .workspace import apply_proposal

ROOT = Path(os.environ.get("AGENT_WORKSPACE_ROOT", os.getcwd())).resolve()
WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
TASKS: dict[str, dict[str, Any]] = {}
TASKS_LOCK = threading.RLock()
MAX_BODY_BYTES = 32 * 1024
MAX_IMPORT_BODY_BYTES = 2_000_000


AUDIT = AuditLog()
ORG_DATA = OrganizationDataStore()


class Handler(BaseHTTPRequestHandler):
    server_version = "EnterpriseAgent/0.1"

    def _headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
        self.send_header("Cache-Control", "no-store")

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self, max_bytes: int = MAX_BODY_BYTES) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > max_bytes:
            raise ValueError(f"Request body must be between 1 byte and {max_bytes} bytes.")
        try:
            content = json.loads(self.rfile.read(length))
        except UnicodeDecodeError as error:
            raise ValueError("Request body must be UTF-8 JSON.") from error
        if not isinstance(content, dict):
            raise ValueError("Request body must be a JSON object.")
        return content

    def _host_is_local(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            parsed_host = urlparse(f"http://{host}")
            host_port = parsed_host.port
        except ValueError:
            return False
        if parsed_host.hostname not in {"localhost", "127.0.0.1", "::1"}:
            return False
        if host_port not in (None, self.server.server_port):
            return False
        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed_origin = urlparse(origin)
                origin_port = parsed_origin.port
            except ValueError:
                return False
            if parsed_origin.scheme not in {"http", "https"} or parsed_origin.hostname not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                return False
            if origin_port not in (None, self.server.server_port):
                return False
        return self.headers.get("Sec-Fetch-Site", "").lower() not in {
            "cross-site",
            "same-site",
        }

    def do_GET(self) -> None:
        if not self._host_is_local():
            self._json(403, {"error": "Only localhost requests are allowed."})
            return
        path = urlparse(self.path).path
        if path == "/api/health":
            try:
                configured_model = model_name()
            except ValueError:
                configured_model = "model configuration blocked"
            self._json(
                200,
                {
                    "status": "ok",
                    "workspace": ROOT.name,
                    "local_model_ready": model_ready(),
                    "model": configured_model,
                    "local_only": True,
                    "approval_required": True,
                },
            )
            return
        if path == "/api/data/status":
            self._json(200, ORG_DATA.status())
            return
        if path == "/api/audit/verify":
            self._json(200, {"valid": AUDIT.verify()})
            return
        if path == "/":
            target = WEB_ROOT / "index.html"
        elif path in {"/assets/app.js", "/assets/style.css"}:
            target = WEB_ROOT / path.removeprefix("/assets/")
        else:
            self._json(404, {"error": "Not found."})
            return
        try:
            body = target.read_bytes()
        except OSError:
            self._json(500, {"error": "The web UI asset could not be read."})
            return
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
        }[target.suffix]
        self.send_response(200)
        self._headers(content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._host_is_local():
            self._json(403, {"error": "Only localhost requests are allowed."})
            return
        path = urlparse(self.path).path
        try:
            body = self._body(
                MAX_IMPORT_BODY_BYTES
                if path == "/api/data/import"
                else MAX_BODY_BYTES
            )
            if path == "/api/data/import":
                filename, content = parse_import_payload(body)
                status = ORG_DATA.import_csv(filename, content)
                AUDIT.record(
                    {
                        "event": "organization_csv_imported",
                        "record_count": status["record_count"],
                    }
                )
                self._json(
                    200,
                    {
                        "loaded": status["loaded"],
                        "record_count": status["record_count"],
                        "headers": status["headers"],
                        "imported_at": status["imported_at"],
                    },
                )
                return
            if path == "/api/data/clear":
                if body.get("approved") is not True:
                    self._json(400, {"error": "Explicit approval is required to clear local data."})
                    return
                ORG_DATA.clear()
                AUDIT.record({"event": "organization_dataset_cleared"})
                self._json(200, {"loaded": False, "record_count": 0})
                return
            if path == "/api/ask":
                result = answer_question(ORG_DATA, body.get("question"))
                AUDIT.record(
                    {
                        "event": "organization_question_answered",
                        "source_count": len(result["sources"]),
                    }
                )
                self._json(200, result)
                return
            if path == "/api/tasks":
                task_id = str(uuid.uuid4())
                proposal = create_proposal(ROOT, body.get("task"))
                proposal["id"] = task_id
                proposal["approved"] = False
                with TASKS_LOCK:
                    if len(TASKS) >= 100:
                        TASKS.pop(next(iter(TASKS)))
                    TASKS[task_id] = proposal
                AUDIT.record(
                    {
                        "event": "proposal_created",
                        "task_id": task_id,
                        "status": proposal["status"],
                        "file_count": len(proposal["files"]),
                    }
                )
                self._json(201, proposal)
                return
            prefix = "/api/tasks/"
            if path.startswith(prefix) and path.endswith("/apply"):
                task_id = path[len(prefix) : -len("/apply")].strip("/")
                if not body.get("approved") is True:
                    self._json(400, {"error": "Explicit approval is required."})
                    return
                with TASKS_LOCK:
                    proposal = TASKS.get(task_id)
                    if proposal is None:
                        self._json(404, {"error": "Proposal not found or expired."})
                        return
                    if proposal["status"] != "ready" or not proposal["files"]:
                        self._json(409, {"error": "This proposal is blocked or has no changes."})
                        return
                    findings = scan_proposed_files(proposal["files"])
                    if any(item["severity"] in {"high", "critical"} for item in findings):
                        self._json(409, {"error": "Edited proposal failed the local secret scan."})
                        return
                    changed = apply_proposal(ROOT, proposal["files"])
                    proposal["status"] = "applied"
                    proposal["approved"] = True
                AUDIT.record(
                    {
                        "event": "proposal_applied",
                        "task_id": task_id,
                        "status": "applied",
                        "file_count": len(changed),
                    }
                )
                self._json(200, {"status": "applied", "files_changed": len(changed)})
                return
            self._json(404, {"error": "Not found."})
        except json.JSONDecodeError:
            self._json(400, {"error": "Request body must contain valid JSON."})
        except (ValueError, RuntimeError) as error:
            self._json(422, {"error": str(error)})
        except (sqlite3.Error, OSError) as error:
            self._json(500, {"error": f"Local storage operation failed: {error}"})

    def log_message(self, format: str, *args: object) -> None:
        super().log_message(format, *args)


def main() -> None:
    host = os.environ.get("AGENT_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeError("The development server only supports loopback binding.")
    port = int(os.environ.get("AGENT_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Enterprise AI Agent UI: http://127.0.0.1:{port}")
    print(f"Workspace: {ROOT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
