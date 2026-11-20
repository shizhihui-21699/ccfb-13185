"""SQLite 存储：检测会话与探针事件。多线程安全（DNS / API / Streamlit 共用）。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time


class DB:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    token      TEXT PRIMARY KEY,
                    created    REAL NOT NULL,
                    user_agent TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS events (
                    id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL,
                    kind  TEXT NOT NULL,
                    ts    REAL NOT NULL,
                    ip    TEXT NOT NULL DEFAULT '',
                    extra TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_events_token ON events(token);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=15, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def create_session(self, token: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sessions(token, created) VALUES (?, ?)",
                (token, time.time()),
            )

    def set_user_agent(self, token: str, ua: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET user_agent = ? WHERE token = ?", (ua, token)
            )

    def add_event(self, token: str, kind: str, ip: str = "", extra: dict | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO events(token, kind, ts, ip, extra) VALUES (?, ?, ?, ?, ?)",
                (token, kind, time.time(), ip, json.dumps(extra or {}, ensure_ascii=False)),
            )

    def get_session(self, token: str) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token = ?", (token,)
            ).fetchone()
        return dict(row) if row else None

    def get_events(self, token: str) -> list[dict]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT kind, ts, ip, extra FROM events WHERE token = ? ORDER BY id",
                (token,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["extra"] = json.loads(d["extra"])
            except Exception:
                d["extra"] = {}
            out.append(d)
        return out

    def purge_old(self, max_age_seconds: float) -> int:
        cutoff = time.time() - max_age_seconds
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE created < ?", (cutoff,))
            conn.execute(
                "DELETE FROM events WHERE token NOT IN (SELECT token FROM sessions)"
            )
            return cur.rowcount
