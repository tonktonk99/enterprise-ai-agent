import tempfile
import unittest
import hashlib
from pathlib import Path
from unittest.mock import patch
import json
import os

from agent_platform.agent import create_proposal
from agent_platform.security import find_secrets, validate_relative_path
from agent_platform.workspace import apply_proposal, gather_context, validate_proposal


class SecurityTests(unittest.TestCase):
    def test_detects_secret_without_returning_secret_value(self):
        value = "api_key = 'super-secret-value-123'"
        self.assertEqual(find_secrets(value), ["credential"])

    def test_rejects_traversal_and_credentials_files(self):
        for path in ("../outside.py", "/tmp/outside.py", ".env", "nested/.env.local"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_relative_path(path)

    def test_context_excludes_secret_files_and_secret_bearing_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.py").write_text("print('safe')\n", encoding="utf-8")
            (root / "credentials.py").write_text(
                "API_KEY = 'very-secret-value-123'\n", encoding="utf-8"
            )
            (root / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
            context = gather_context(root, "update main.py")
            paths = [item["path"] for item in context["files"]]
            self.assertEqual(paths, ["main.py"])
            self.assertEqual(context["files_skipped_for_secrets"], 1)

    def test_stale_proposal_cannot_be_applied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text("old\n", encoding="utf-8")
            proposal = {
                "path": "app.py",
                "content": "new\n",
                "before_hash": "0" * 64,
            }
            with self.assertRaisesRegex(ValueError, "changed after proposal"):
                validate_proposal(root, [proposal])
            with self.assertRaisesRegex(ValueError, "changed after proposal"):
                apply_proposal(root, [proposal])
            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")

    def test_applies_approved_proposal_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text("old\n", encoding="utf-8")
            target.chmod(0o640)
            before_hash = hashlib.sha256(b"old\n").hexdigest()
            changed = apply_proposal(
                root,
                [{"path": "app.py", "content": "new\n", "before_hash": before_hash}],
            )
            self.assertEqual(changed, ["app.py"])
            self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_model_proposal_gets_server_verified_base_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "app.py"
            target.write_text("old\n", encoding="utf-8")
            model_content = {
                "summary": "Update application output.",
                "plan": ["Update the app."],
                "files": [{"path": "app.py", "content": "new\n", "reason": "Fix"}],
                "tests": ["Run the unit tests."],
                "review": {"status": "pass", "notes": []},
                "security_findings": [],
                "deployment_notes": ["Deploy manually after review."],
            }
            with patch.dict(
                os.environ,
                {"AI_API_KEY": "test-key", "AI_BASE_URL": "http://localhost:8001/v1"},
            ), patch(
                "agent_platform.agent.completion",
                return_value=json.dumps(model_content),
            ):
                proposal = create_proposal(root, "Update app.py output")

            self.assertEqual(proposal["status"], "ready")
            self.assertEqual(
                proposal["files"][0]["before_hash"], hashlib.sha256(b"old\n").hexdigest()
            )


if __name__ == "__main__":
    unittest.main()
