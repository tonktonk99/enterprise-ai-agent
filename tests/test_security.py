import tempfile
import unittest
import hashlib
from pathlib import Path
from unittest.mock import patch
import json
import os

from agent_platform.agent import Run
from agent_platform.security import find_secrets, validate_relative_path
from agent_platform.workspace import apply_proposal, gather_context, validate_proposal


class SecurityTests(unittest.TestCase):
    def test_detects_secret_without_returning_secret_value(self):
        value = "api_key = 'super-secret-value-123'"
        self.assertEqual(find_secrets(value), ["credential"])

    def test_detects_common_credential_formats(self):
        # Synthetic, non-functional values assembled at runtime.
        samples = {
            "private_key": "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
            "aws_access_key": "ASIA" + "A" * 16,
            "aws_secret_key": "aws_secret_access_key = " + "a" * 40,
            "github_token": "github_pat_" + "a" * 70,
            "gitlab_token": "glpat-" + "a" * 20,
            "stripe_key": "sk_" + "live_" + "a" * 24,
            "google_api_key": "AIza" + "a" * 35,
            "slack_token": "xoxb-" + "1" * 12,
            "npm_token": "npm_" + "a" * 36,
            "jwt": "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
            "azure_storage_key": "AccountKey=" + "a" * 44,
            "url_credential": "postgres://admin:" + "hunter22" + "@db.internal",
        }
        for label, sample in samples.items():
            with self.subTest(label=label):
                self.assertIn(label, find_secrets(sample))

    def test_ordinary_code_is_not_flagged(self):
        code = (
            "password = request.form['password']\n"
            "url = 'https://example.com/path'\n"
            "token_count = len(tokens)\n"
        )
        self.assertEqual(find_secrets(code), [])

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
            
            def mock_completion(*args, **kwargs):
                prompt = kwargs.get("prompt", args[0] if args else "")
                usage = {"prompt": 10, "completion": 10}
                if "Planner" in str(prompt):
                    return json.dumps({"goal": "g", "steps": ["s"], "files_to_read": ["app.py"], "files_to_create": [], "risk": "low", "acceptance": []}), usage
                elif "Coder" in str(prompt):
                    return json.dumps({"files": [{"path": "app.py", "content": "new\n", "reason": "Fix"}]}), usage
                elif "Reviewer" in str(prompt):
                    return json.dumps({"status": "pass", "notes": []}), usage
                return "{}", {"prompt": 0, "completion": 0}

            run = Run(root, "Update app.py output")
            with patch.dict(os.environ, {"AI_API_KEY": "test-key"}), \
                 patch("agent_platform.agent.completion_with_usage", side_effect=mock_completion):
                run.execute()

            self.assertEqual(run.status, "awaiting_approval", run.error)
            self.assertEqual(
                run.proposed_files[0]["before_hash"], hashlib.sha256(b"old\n").hexdigest()
            )

if __name__ == "__main__":
    unittest.main()
