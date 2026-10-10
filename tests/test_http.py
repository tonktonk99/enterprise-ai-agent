import atexit
import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_platform import organization_qa
_temp = tempfile.TemporaryDirectory()
atexit.register(_temp.cleanup)
_root = Path(_temp.name) / "workspace"
_root.mkdir()
_target = _root / "target.py"
_target.write_text("before\n", encoding="utf-8")
_audit_path = Path(_temp.name) / "audit.sqlite3"

with patch.dict(
    "os.environ",
    {
        "AGENT_AUDIT_DB": str(_audit_path),
        "AGENT_WORKSPACE_ROOT": str(_root),
        "ORG_DATA_DB": str(Path(_temp.name) / "org-data.sqlite3"),
    },
):
    from agent_platform import server as server_module


class AgentHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server_module.ThreadingHTTPServer(
            ("127.0.0.1", 0), server_module.Handler
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, payload=None, headers=None, authenticated=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request_headers = {"Content-Type": "application/json"}
        if authenticated:
            cookie_name = server_module.session_cookie_name(self.httpd.server_port)
            request_headers["Cookie"] = f"{cookie_name}={server_module.SESSION_TOKEN}"
        request_headers.update(headers or {})
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        result = response.status, response.read()
        self.last_headers = response.headers
        connection.close()
        return result

    def test_api_requires_session_token(self):
        for method, path, payload in (
            ("GET", "/api/health", None),
            ("GET", "/api/data/status", None),
            ("POST", "/api/tasks", {"task": "x"}),
            ("POST", "/api/data/clear", {"approved": True}),
        ):
            status, _ = self.request(method, path, payload, authenticated=False)
            self.assertEqual(status, 401, path)
            status, _ = self.request(
                method,
                path,
                payload,
                {"Cookie": f"forge_session_{self.httpd.server_port}=wrong"},
                authenticated=False,
            )
            self.assertEqual(status, 401, path)
        status, _ = self.request(
            "GET",
            "/api/health",
            headers={server_module.SESSION_HEADER: server_module.SESSION_TOKEN},
            authenticated=False,
        )
        self.assertEqual(status, 200)
        # Static UI assets stay reachable so the page can explain how to log in.
        status, _ = self.request("GET", "/", authenticated=False)
        self.assertEqual(status, 200)

    def test_startup_url_sets_strict_http_only_cookie(self):
        status, _ = self.request("GET", "/?token=wrong", authenticated=False)
        self.assertEqual(status, 401)
        status, _ = self.request(
            "GET", f"/?token={server_module.SESSION_TOKEN}", authenticated=False
        )
        self.assertEqual(status, 303)
        self.assertEqual(self.last_headers["Location"], "/")
        cookie = self.last_headers["Set-Cookie"]
        self.assertIn(server_module.SESSION_TOKEN, cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_storage_errors_do_not_leak_details(self):
        with patch.object(
            server_module.ORG_DATA,
            "clear",
            side_effect=OSError("/Users/secret/path/org-data.sqlite3 is locked"),
        ):
            status, body = self.request("POST", "/api/data/clear", {"approved": True})
        self.assertEqual(status, 500)
        self.assertNotIn(b"/Users/secret", body)
        self.assertIn(b"Reference:", body)
        self.assertNotIn("Python", self.last_headers.get("Server", ""))

    def test_writes_require_approval_and_reject_cross_origin_requests(self):
        server_module.TASKS.clear()
        before_hash = hashlib.sha256(b"before\n").hexdigest()
        proposal = {
            "summary": "Update target.",
            "plan": ["Update one file."],
            "files": [
                {
                    "path": "target.py",
                    "content": "after\n",
                    "before_hash": before_hash,
                    "reason": "Test proposal",
                }
            ],
            "tests": [],
            "review": {"status": "pass", "notes": []},
            "security_findings": [],
            "deployment_notes": [],
            "context": {
                "files_scanned": 1,
                "files_included": 1,
                "files_skipped_for_secrets": 0,
                "context_chars": 7,
            },
            "status": "ready",
        }
        with patch.object(server_module, "create_proposal", return_value=proposal):
            status, body = self.request("POST", "/api/tasks", {"task": "change target"})
        self.assertEqual(status, 201)
        task_id = json.loads(body)["id"]

        status, _ = self.request(
            "POST", f"/api/tasks/{task_id}/apply", {"approved": False}
        )
        self.assertEqual(status, 400)
        self.assertEqual(_target.read_text(encoding="utf-8"), "before\n")

        status, _ = self.request(
            "POST",
            "/api/tasks",
            {"task": "attack"},
            {"Origin": "https://attacker.example"},
        )
        self.assertEqual(status, 403)

        status, body = self.request(
            "POST", f"/api/tasks/{task_id}/apply", {"approved": True}
        )
        self.assertEqual(status, 200, body.decode("utf-8"))
        self.assertEqual(_target.read_text(encoding="utf-8"), "after\n")
        self.assertTrue(server_module.AUDIT.verify())

    def test_local_csv_import_q_and_a_and_clear(self):
        server_module.ORG_DATA.clear()
        status, body = self.request(
            "POST",
            "/api/data/import",
            {
                "filename": "directory.csv",
                "content": "employee_id,name,team\nE-1,Alex,Support\n",
            },
        )
        self.assertEqual(status, 200, body.decode("utf-8"))
        self.assertEqual(json.loads(body)["record_count"], 1)

        with patch.object(
            organization_qa,
            "completion",
            return_value=json.dumps(
                {"answer": "Alex is on Support [R1]", "citations": ["R1"]}
            ),
        ):
            status, body = self.request(
                "POST", "/api/ask", {"question": "Who is on Support?"}
            )
        self.assertEqual(status, 200, body.decode("utf-8"))
        answer = json.loads(body)
        self.assertEqual(answer["sources"], [{"source_id": "R1", "csv_row": 2}])
        self.assertNotIn("record", answer["sources"][0])

        status, _ = self.request("POST", "/api/data/clear", {"approved": False})
        self.assertEqual(status, 400)
        status, body = self.request("POST", "/api/data/clear", {"approved": True})
        self.assertEqual(status, 200)
        self.assertFalse(server_module.ORG_DATA.status()["loaded"])


if __name__ == "__main__":
    unittest.main()
