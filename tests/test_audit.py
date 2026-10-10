import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from agent_platform.audit import AuditLog


class AuditLogTests(unittest.TestCase):
    def test_hash_chain_verifies_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "audit.sqlite3"
            with patch.dict("os.environ", {"AGENT_AUDIT_DB": str(db_path)}):
                audit = AuditLog()
            audit.record({"event": "proposal_created", "task_id": "test-id"})
            audit.record({"event": "proposal_applied", "task_id": "test-id"})
            self.assertTrue(audit.verify())

            with closing(sqlite3.connect(db_path)) as db:
                with db:
                    db.execute("UPDATE events SET event_json='{}' WHERE sequence=1")
            self.assertFalse(audit.verify())


if __name__ == "__main__":
    unittest.main()
