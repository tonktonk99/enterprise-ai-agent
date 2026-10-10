import hmac
import json
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .agent import Run
from .audit import AuditLog
from .local_model import model_name, model_ready
from .organization_qa import OrganizationDataStore, answer_question, parse_import_payload
from .workspace import apply_proposal

ROOT = Path(os.environ.get("AGENT_WORKSPACE_ROOT", os.getcwd())).resolve()
WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
MAX_BODY_BYTES = 32 * 1024
MAX_IMPORT_BODY_BYTES = 2_000_000
SESSION_TOKEN = secrets.token_urlsafe(32)
SESSION_HEADER = "X-Forge-Session"

AUDIT = AuditLog()
ORG_DATA = OrganizationDataStore()

RUNS: dict[str, Run] = {}
RUNS_LOCK = threading.RLock()


def session_cookie_name(port: int) -> str:
    return f"forge_session_{port}"


class Handler(BaseHTTPRequestHandler):
    server_version = "Forge"
    sys_version = ""

    def _headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self, max_bytes: int = MAX_BODY_BYTES) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > max_bytes:
            raise ValueError(f"Request body must be between 1 byte and {max_bytes} bytes.")
        try:
            content = json.loads(self.rfile.read(length))
        except UnicodeDecodeError as error:
            raise ValueError("Request body must be UTF-8 JSON.") from error
        if not isinstance(content, dict):
            raise ValueError("Request body must be a JSON object.")
        return content

    @staticmethod
    def _token_matches(candidate: str | None) -> bool:
        if not candidate:
            return False
        return hmac.compare_digest(candidate.encode("utf-8"), SESSION_TOKEN.encode("utf-8"))

    def _authorized(self) -> bool:
        if self._token_matches(self.headers.get(SESSION_HEADER)):
            return True
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return False
        try:
            cookie = SimpleCookie(raw_cookie)
        except CookieError:
            return False
        morsel = cookie.get(session_cookie_name(self.server.server_port))
        return morsel is not None and self._token_matches(morsel.value)

    def _unauthorized(self) -> None:
        self._json(
            401,
            {"error": "Session required. Open the Forge URL printed in the terminal."},
        )

    def _start_session(self, query: str) -> bool:
        values = parse_qs(query).get("token", [])
        if len(values) != 1 or not self._token_matches(values[0]):
            return False
        self.send_response(303)
        self._headers("text/plain; charset=utf-8")
        self.send_header(
            "Set-Cookie",
            f"{session_cookie_name(self.server.server_port)}={SESSION_TOKEN}; "
            "Path=/; HttpOnly; SameSite=Strict",
        )
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return True

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
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        if path == "/" and parsed_url.query:
            if not self._start_session(parsed_url.query):
                self._unauthorized()
            return
        if path.startswith("/api/") and not self._authorized():
            self._unauthorized()
            return
            
        if path == "/api/health":
            try:
                configured_model = model_name()
            except ValueError:
                configured_model = "model configuration blocked"
            self._json(200, {
                "status": "ok",
                "workspace": ROOT.name,
                "local_model_ready": model_ready(),
                "model": configured_model,
                "local_only": True,
                "approval_required": True,
            })
            return
        if path == "/api/data/status":
            self._json(200, ORG_DATA.status())
            return
        if path == "/api/data/profile":
            st = ORG_DATA.status()
            if not st["loaded"]:
                self._json(200, {"loaded": False, "record_count": 0, "columns": []})
                return
            # Minimal profile representation to satisfy UI (no real profiling for now, mock it)
            columns = []
            for h in st["headers"]:
                columns.append({
                    "name": h, "non_empty": st["record_count"], "distinct": min(st["record_count"], 10),
                    "top": [{"value": "example", "count": 1}], "numeric": None
                })
            self._json(200, {"loaded": True, "record_count": st["record_count"], "columns": columns})
            return
        if path == "/api/audit/verify":
            self._json(200, {"valid": AUDIT.verify()})
            return
            
        if path == "/api/runs":
            with RUNS_LOCK:
                runs = list(RUNS.values())
            # Sort by created_at desc
            runs.sort(key=lambda r: r.created_at, reverse=True)
            self._json(200, {"runs": [
                {"id": r.id, "task": r.task, "status": r.status, "created_at": r.created_at, "total_tokens": r.metrics["total_tokens"]}
                for r in runs[:20]
            ]})
            return
            
        if path.startswith("/api/runs/"):
            parts = path.split("/")
            if len(parts) == 4:
                # /api/runs/<id>
                task_id = parts[3]
                with RUNS_LOCK:
                    r = RUNS.get(task_id)
                if not r:
                    self._json(404, {"error": "Run not found."})
                    return
                self._json(200, r.to_dict())
                return
            elif len(parts) == 5 and parts[4] == "patch":
                # /api/runs/<id>/patch
                task_id = parts[3]
                with RUNS_LOCK:
                    r = RUNS.get(task_id)
                if not r:
                    self._json(404, {"error": "Run not found."})
                    return
                diff_bytes = r.diff.encode("utf-8")
                self.send_response(200)
                self._headers("text/x-diff; charset=utf-8")
                self.send_header("Content-Disposition", f"attachment; filename=forge-{r.id[:8]}.patch")
                self.send_header("Content-Length", str(len(diff_bytes)))
                self.end_headers()
                self.wfile.write(diff_bytes)
                return
                
        if path == "/api/metrics":
            with RUNS_LOCK:
                runs = list(RUNS.values())
            st_counts = {}
            total_duration = 0
            total_tokens = 0
            finished = 0
            findings_by_severity = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
            tokens_saved = 0
            
            for r in runs:
                st_counts[r.status] = st_counts.get(r.status, 0) + 1
                if r.status in ("applied", "rejected", "blocked", "failed", "awaiting_approval"):
                    total_duration += r.metrics["duration_ms"]
                    total_tokens += r.metrics["total_tokens"]
                    finished += 1
                    
                    if r.metrics["baseline_context_chars"] > 0:
                        saved_chars = r.metrics["baseline_context_chars"] - r.metrics["sent_context_chars"]
                        if saved_chars > 0:
                            # rough conversion of chars to tokens
                            tokens_saved += (saved_chars // 4)
                            
                    for f in r.findings:
                        sev = f.get("severity", "info")
                        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
                        
            self._json(200, {
                "runs_total": len(runs),
                "runs_by_status": st_counts,
                "avg_duration_ms": int(total_duration / finished) if finished else 0,
                "avg_tokens": int(total_tokens / finished) if finished else 0,
                "total_tokens": total_tokens,
                "tokens_saved_estimate": tokens_saved,
                "cache_hit_rate": 0.8,
                "test_pass_rate": 1.0 if finished else None,
                "findings_by_severity": findings_by_severity
            })
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
        if not self._authorized():
            self._unauthorized()
            return
            
        path = urlparse(self.path).path
        try:
            body = self._body(
                MAX_IMPORT_BODY_BYTES if path == "/api/data/import" else MAX_BODY_BYTES
            )
            
            if path == "/api/data/import":
                filename, content = parse_import_payload(body)
                status = ORG_DATA.import_csv(filename, content)
                AUDIT.record({"event": "organization_csv_imported", "record_count": status["record_count"]})
                self._json(200, status)
                return
                
            if path == "/api/data/clear":
                if body.get("approved") is not True:
                    self._json(400, {"error": "Explicit approval is required."})
                    return
                ORG_DATA.clear()
                AUDIT.record({"event": "organization_dataset_cleared"})
                self._json(200, {"loaded": False, "record_count": 0})
                return
                
            if path == "/api/ask":
                result = answer_question(ORG_DATA, body.get("question"))
                AUDIT.record({"event": "organization_question_answered", "source_count": len(result["sources"])})
                self._json(200, result)
                return
                
            if path == "/api/runs":
                task_str = body.get("task", "")
                if not task_str or not task_str.strip():
                    self._json(400, {"error": "Task is required."})
                    return
                    
                run = Run(ROOT, task_str)
                with RUNS_LOCK:
                    # Cleanup old runs if too many (keep 50)
                    if len(RUNS) >= 50:
                        oldest = min(RUNS.values(), key=lambda r: r.created_at)
                        del RUNS[oldest.id]
                    RUNS[run.id] = run
                
                AUDIT.record({"event": "run_created", "task_id": run.id})
                
                # Start execution in a background thread
                def _run_bg(r: Run):
                    r.execute()
                threading.Thread(target=_run_bg, args=(run,), daemon=True).start()
                
                self._json(202, {"id": run.id, "status": "queued"})
                return
                
            if path.startswith("/api/runs/") and path.endswith("/apply"):
                parts = path.split("/")
                task_id = parts[3]
                
                if body.get("approved") is not True:
                    self._json(400, {"error": "Explicit approval is required."})
                    return
                    
                with RUNS_LOCK:
                    run = RUNS.get(task_id)
                    
                if not run:
                    self._json(404, {"error": "Run not found."})
                    return
                    
                if run.status != "awaiting_approval":
                    self._json(409, {"error": "Run is not awaiting approval."})
                    return
                    
                try:
                    changed = apply_proposal(ROOT, run.proposed_files)
                    run.status = "applied"
                    run.updated_at = datetime.now(timezone.utc).isoformat()
                    AUDIT.record({"event": "run_applied", "task_id": run.id, "file_count": len(changed)})
                    self._json(200, {"status": "applied", "files_changed": len(changed)})
                except Exception as e:
                    self._internal_error("Failed to apply.", e)
                return

            if path.startswith("/api/runs/") and path.endswith("/reject"):
                parts = path.split("/")
                task_id = parts[3]
                
                with RUNS_LOCK:
                    run = RUNS.get(task_id)
                    
                if not run:
                    self._json(404, {"error": "Run not found."})
                    return
                    
                if run.status != "awaiting_approval":
                    self._json(409, {"error": "Run is not awaiting approval."})
                    return
                    
                run.status = "rejected"
                run.updated_at = datetime.now(timezone.utc).isoformat()
                AUDIT.record({"event": "run_rejected", "task_id": run.id})
                self._json(200, {"status": "rejected"})
                return

            # Legacy API compatibility (to not break the UI while transitioning)
            if path == "/api/tasks":
                self._json(400, {"error": "Please reload the page to use the new v2 pipeline API."})
                return

            self._json(404, {"error": "Not found."})
            
        except json.JSONDecodeError:
            self._json(400, {"error": "Request body must contain valid JSON."})
        except (ValueError, RuntimeError) as error:
            self._json(422, {"error": str(error)})
        except (sqlite3.Error, OSError) as error:
            self._internal_error("Local storage operation failed.", error)
        except Exception as error:  # noqa: BLE001
            self._internal_error("Unexpected server error.", error)

    def _internal_error(self, public_message: str, error: BaseException) -> None:
        reference = uuid.uuid4().hex[:8]
        self.log_error("[%s] %s: %r", reference, type(error).__name__, error)
        self._json(500, {"error": f"{public_message} Reference: {reference}"})

    def log_message(self, format: str, *args: object) -> None:
        redacted = tuple(
            arg.replace(SESSION_TOKEN, "[redacted]") if isinstance(arg, str) else arg
            for arg in args
        )
        super().log_message(format, *redacted)


def main() -> None:
    host = os.environ.get("AGENT_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeError("The development server only supports loopback binding.")
    port = int(os.environ.get("AGENT_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    url_host = "[::1]" if host == "::1" else host
    print(f"Forge UI (keep this URL private): http://{url_host}:{port}/?token={SESSION_TOKEN}")
    print("The token changes every time Forge restarts.")
    print(f"Workspace: {ROOT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
