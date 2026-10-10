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

    def request(self, method, path, payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers or {})
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

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
