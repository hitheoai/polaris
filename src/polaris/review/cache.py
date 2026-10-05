"""Local result cache: unchanged code under the same model is never assessed twice."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from polaris.jsonio import digest_json


class ReviewCache:
    """A small SQLite key/value store. Values are serialized assessment envelopes."""

    def __init__(self, path: Path, *, max_entries: int = 200_000) -> None:
        if path.is_symlink():
            raise ValueError("refusing a symlinked cache path")
        path.parent.mkdir(parents=True, exist_ok=True)
        marker = path.parent / ".gitignore"
        if not marker.exists() and not marker.is_symlink():
            marker.write_text("# Polaris review cache; safe to delete.\n*\n", encoding="utf-8")
        self.path = path
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), timeout=5, check_same_thread=False)
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS results (key TEXT PRIMARY KEY, value TEXT NOT NULL, used REAL NOT NULL)"
            )

    @staticmethod
    def key(request: dict[str, object], identity: dict[str, object]) -> str:
        return digest_json({"request": request, "identity": identity})

    def get(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM results WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            with self._db:
                self._db.execute("UPDATE results SET used = ? WHERE key = ?", (time.time(), key))
            return str(row[0])

    def put(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO results (key, value, used) VALUES (?, ?, ?)", (key, value, time.time())
            )
            count = self._db.execute("SELECT COUNT(*) FROM results").fetchone()[0]
            if count > self.max_entries:
                self._db.execute(
                    "DELETE FROM results WHERE key IN (SELECT key FROM results ORDER BY used LIMIT ?)",
                    (count - self.max_entries,),
                )

    def close(self) -> None:
        with self._lock:
            self._db.close()
