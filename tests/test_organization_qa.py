import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_platform import organization_qa
from agent_platform.local_model import completion, model_ready
from agent_platform.organization_qa import OrganizationDataStore, answer_question


class OrganizationDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = OrganizationDataStore(Path(self.temp.name) / "org.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_imports_utf8_csv_and_retrieves_matching_records(self):
        result = self.store.import_csv(
            "directory.csv",
            "\ufeffemployee_id,name,team,role\n"
            "E-1,สมชาย,Support,Engineer\n"
            "E-2,สมหญิง,Finance,Analyst\n"
            "E-3,มานะ,การเงิน,ผู้จัดการ\n",
        )
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["headers"][0], "employee_id")
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        rows = self.store.retrieve("ใครทำงานทีม Support")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record"]["employee_id"], "E-1")
        self.assertEqual(rows[0]["csv_row"], 2)
        thai_rows = self.store.retrieve("ใครอยู่ฝ่ายการเงิน")
        self.assertEqual(len(thai_rows), 1)
        self.assertEqual(thai_rows[0]["record"]["employee_id"], "E-3")

    def test_rejects_sensitive_columns_and_preserves_previous_import(self):
        self.store.import_csv("directory.csv", "employee_id,team\nE-1,Support\n")
        with self.assertRaisesRegex(ValueError, "highly sensitive"):
            self.store.import_csv(
                "directory.csv", "employee_id,salary\nE-1,100000\n"
            )
        self.assertEqual(self.store.status()["record_count"], 1)

    def test_rejects_non_csv_oversize_duplicate_or_malformed_input(self):
        for filename, content in (
            ("directory.xlsx", "id,name\n1,A\n"),
            ("directory.csv", "id,id\n1,2\n"),
            ("directory.csv", "id,name\n1,A,extra\n"),
        ):
            with self.subTest(filename=filename, content=content), self.assertRaises(ValueError):
                self.store.import_csv(filename, content)
        with self.assertRaisesRegex(ValueError, "1.5 MB"):
            self.store.import_csv(
                "large.csv", "team\n" + ("x" * organization_qa.MAX_CSV_BYTES)
            )

    def test_answers_include_only_validated_citations_not_personal_rows(self):
        self.store.import_csv(
            "directory.csv",
            "employee_id,name,team,role\nE-1,สมชาย,Support,Engineer\n"
            "E-2,สมหญิง,Finance,Analyst\n",
        )

        def fake_completion(messages, *, max_tokens, json_mode):
            prompt = json.loads(messages[1]["content"])
            self.assertEqual(prompt["retrieved_records"][0]["record"]["team"], "Support")
            self.assertTrue(json_mode)
            return json.dumps(
                {"answer": "ทีม Support มีวิศวกรหนึ่งคน [R1]", "citations": ["R1", "R99"]},
                ensure_ascii=False,
            )

        with patch.object(organization_qa, "completion", side_effect=fake_completion):
            result = answer_question(self.store, "ใครทำงานทีม Support")
        self.assertEqual(result["sources"], [{"source_id": "R1", "csv_row": 2}])
        self.assertFalse(result["retrieval_complete"])
        self.assertNotIn("สมชาย", json.dumps(result["sources"], ensure_ascii=False))

    def test_no_matching_data_does_not_call_local_model(self):
        self.store.import_csv(
            "directory.csv", "employee_id,name,team\nE-1,Somchai,Support\n"
        )
        with patch.object(organization_qa, "completion") as model:
            result = answer_question(self.store, "Who is in Legal?")
        model.assert_not_called()
        self.assertEqual(result["sources"], [])

    def test_external_model_endpoint_is_rejected_before_any_request(self):
        with patch.dict(
            os.environ,
            {"AI_BASE_URL": "https://example.com/v1", "AI_API_KEY": "must-not-leave"},
        ), patch("urllib.request.build_opener") as build_opener:
            with self.assertRaisesRegex(ValueError, "external model services are blocked"):
                completion([{"role": "user", "content": "private"}], max_tokens=200)
        build_opener.assert_not_called()

    def test_cloud_or_remote_model_names_are_rejected(self):
        for model in ("qwen2.5:3b-cloud", "remote-model"):
            with self.subTest(model=model), patch.dict(
                os.environ,
                {"AI_BASE_URL": "http://127.0.0.1:11434/v1", "AI_MODEL": model},
            ), patch("urllib.request.build_opener") as build_opener:
                with self.assertRaisesRegex(ValueError, "Cloud/remote"):
                    completion([{"role": "user", "content": "private"}], max_tokens=200)
                build_opener.assert_not_called()

    def test_ollama_model_readiness_probes_loopback_only(self):
        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b'{"models":[{"name":"qwen2.5:3b"}]}'

        with patch.dict(os.environ, {"AI_BASE_URL": "http://localhost:11434/v1", "AI_MODEL": "qwen2.5:3b"}), patch(
            "urllib.request.build_opener"
        ) as build_opener:
            build_opener.return_value.open.return_value = FakeResponse()
            self.assertTrue(model_ready())
            request = build_opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, "http://localhost:11434/api/tags")


if __name__ == "__main__":
    unittest.main()
