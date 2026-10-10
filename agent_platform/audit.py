import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


class AuditLog:
    def __init__(self) -> None:
        configured_path = os.environ.get("AGENT_AUDIT_DB")
        path = Path(
            configured_path
            if configured_path
            else Path.home() / ".local" / "share" / "enterprise-ai-agent" / "audit.sqlite3"
        ).expanduser()
        if not path.is_absolute():
            raise RuntimeError("AGENT_AUDIT_DB must be an absolute path.")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise RuntimeError("The audit database must not be a symbolic link.")
        if not configured_path:
            path.parent.chmod(0o700)
        self.path = path
        self.lock = threading.Lock()
        with self._session() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )"""
            )
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def record(self, event: dict[str, Any]) -> None:
        with self.lock, self._session() as db:
            row = db.execute(
                "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous = row[0] if row else "0" * 64
            created_at = datetime.now(timezone.utc).isoformat()
            event_json = json.dumps(event, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(
                f"{previous}\n{created_at}\n{event_json}".encode("utf-8")
            ).hexdigest()
            db.execute(
                "INSERT INTO events(created_at,event_json,previous_hash,event_hash) VALUES(?,?,?,?)",
                (created_at, event_json, previous, event_hash),
            )

    def verify(self) -> bool:
        previous = "0" * 64
        with self.lock, self._session() as db:
            rows = db.execute(
                "SELECT created_at,event_json,previous_hash,event_hash "
                "FROM events ORDER BY sequence"
            )
            for created_at, event_json, stored_previous, stored_hash in rows:
                expected = hashlib.sha256(
                    f"{previous}\n{created_at}\n{event_json}".encode("utf-8")
                ).hexdigest()
                if not hmac.compare_digest(stored_previous, previous):
                    return False
                if not hmac.compare_digest(stored_hash, expected):
                    return False
                previous = stored_hash
        return True
