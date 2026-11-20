"""SQLite-backed observation store shared by the web, DNS and STUN collectors.

One file, WAL mode, short-lived connections: three processes (Streamlit web
app, DNS listener, STUN listener) write to it concurrently, so every write
uses ``BEGIN IMMEDIATE`` plus a generous busy timeout and retries on
``database is locked``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    peer_ip      TEXT,
    user_agent   TEXT,
    client_hint  TEXT,
    stun_port    INTEGER,
    stage        TEXT,
    meta_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_stun_port ON sessions(stun_port, created_at);

CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token        TEXT NOT NULL,
    channel      TEXT NOT NULL,          -- http | dns | stun | webrtc
    observed_at  REAL NOT NULL,
    source_ip    TEXT NOT NULL,
    source_port  INTEGER,
    transport    TEXT,                   -- udp | tcp | tls | https
    detail_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_token ON observations(token, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_time ON observations(observed_at);

CREATE TABLE IF NOT EXISTS audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   REAL NOT NULL,
    event        TEXT NOT NULL,
    client_ip    TEXT,
    detail_json  TEXT
);
"""

CHANNELS = ("http", "dns", "stun", "webrtc")


@dataclass(slots=True)
class Session:
    token: str
    created_at: float
    expires_at: float
    peer_ip: str | None
    user_agent: str | None
    client_hint: str | None
    meta: dict[str, Any]
    stun_port: int | None = None
    stage: str | None = None

    @property
    def expires_in(self) -> float:
        return self.expires_at - time.time()


@dataclass(slots=True)
class Observation:
    channel: str
    observed_at: float
    source_ip: str
    source_port: int | None
    transport: str | None
    detail: dict[str, Any]


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ low level
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            timeout=15.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        last_error: Exception | None = None
        for attempt in range(5):
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(sql, params)
                conn.execute("COMMIT")
                return cur
            except sqlite3.OperationalError as exc:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
                last_error = exc
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                time.sleep(0.05 * (attempt + 1))
            finally:
                conn.close()
        raise RuntimeError(f"写入数据库失败: {last_error}")

    def _read(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        conn = self._connect()
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    # ------------------------------------------------------------------ sessions
    def create_session(self, token: str, ttl_seconds: int, peer_ip: str | None,
                       user_agent: str | None, client_hint: str | None,
                       meta: dict[str, Any] | None = None,
                       stun_port: int | None = None) -> Session:
        now = time.time()
        expires = now + ttl_seconds
        self._write(
            "INSERT OR REPLACE INTO sessions"
            "(token, created_at, expires_at, peer_ip, user_agent, client_hint, stun_port,"
            " meta_json) VALUES (?,?,?,?,?,?,?,?)",
            (token, now, expires, peer_ip, user_agent, client_hint, stun_port,
             json.dumps(meta or {}, ensure_ascii=False)),
        )
        return Session(token, now, expires, peer_ip, user_agent, client_hint, meta or {},
                       stun_port)

    def set_stage(self, token: str, stage: str) -> bool:
        cur = self._write("UPDATE sessions SET stage = ? WHERE token = ?", (stage[:40], token))
        return cur.rowcount > 0

    def assign_stun_port(self, token: str, ports: list[int], ttl_seconds: int) -> int | None:
        """Pick a STUN port for this session, avoiding sessions that are still live.

        STUN messages carry no identity, so a port is the only attribution key.
        We prefer a port no other unexpired session holds; if all are busy we
        fall back to the least recently created one (attribution still works
        because the browser probes within seconds of the page loading).
        """
        now = time.time()
        rows = self._read(
            "SELECT token, stun_port FROM sessions WHERE expires_at > ? AND stun_port IS NOT NULL",
            (now,),
        )
        taken = {int(r["stun_port"]): r["token"] for r in rows if r["token"] != token}
        candidate = next((port for port in ports if port not in taken), None)
        if candidate is None:
            ordered = self._read(
                "SELECT stun_port, MAX(created_at) AS newest FROM sessions"
                " WHERE expires_at > ? AND stun_port IS NOT NULL AND token != ?"
                " GROUP BY stun_port ORDER BY newest",
                (now, token),
            )
            if ordered:
                candidate = int(ordered[0]["stun_port"])
        if candidate is None:
            return None
        self._write(
            "UPDATE sessions SET stun_port = ?, expires_at = MAX(expires_at, ?) WHERE token = ?",
            (candidate, now + ttl_seconds, token),
        )
        return candidate

    def lookup_stun_port(self, port: int) -> str | None:
        """Which live session owns this STUN port (newest session wins)."""
        rows = self._read(
            "SELECT token FROM sessions WHERE stun_port = ? AND expires_at > ?"
            " ORDER BY created_at DESC LIMIT 1",
            (port, time.time()),
        )
        return rows[0]["token"] if rows else None

    def get_session(self, token: str) -> Session | None:
        rows = self._read("SELECT * FROM sessions WHERE token = ?", (token,))
        if not rows:
            return None
        row = rows[0]
        try:
            meta = json.loads(row["meta_json"] or "{}")
        except json.JSONDecodeError:
            meta = {}
        return Session(
            token=row["token"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            peer_ip=row["peer_ip"],
            user_agent=row["user_agent"],
            client_hint=row["client_hint"],
            meta=meta,
            stun_port=row["stun_port"],
            stage=row["stage"],
        )

    def touch_session(self, token: str, ttl_seconds: int) -> bool:
        """Slide the expiry forward; returns False when the session is unknown."""
        cur = self._write(
            "UPDATE sessions SET expires_at = MAX(expires_at, ?) WHERE token = ?",
            (time.time() + ttl_seconds, token),
        )
        return cur.rowcount > 0

    # -------------------------------------------------------------- observations
    def add_observation(self, token: str, channel: str, source_ip: str,
                        source_port: int | None = None, transport: str | None = None,
                        detail: dict[str, Any] | None = None,
                        observed_at: float | None = None) -> int:
        if channel not in CHANNELS:
            raise ValueError(f"未知通道 {channel!r}")
        cur = self._write(
            "INSERT INTO observations(token, channel, observed_at, source_ip, source_port,"
            " transport, detail_json) VALUES (?,?,?,?,?,?,?)",
            (token, channel, observed_at or time.time(), source_ip, source_port,
             transport, json.dumps(detail or {}, ensure_ascii=False)),
        )
        return int(cur.lastrowid or 0)

    def observations(self, token: str) -> list[Observation]:
        rows = self._read(
            "SELECT channel, observed_at, source_ip, source_port, transport, detail_json"
            " FROM observations WHERE token = ? ORDER BY observed_at",
            (token,),
        )
        out: list[Observation] = []
        for row in rows:
            try:
                detail = json.loads(row["detail_json"] or "{}")
            except json.JSONDecodeError:
                detail = {}
            out.append(
                Observation(
                    channel=row["channel"],
                    observed_at=row["observed_at"],
                    source_ip=row["source_ip"],
                    source_port=row["source_port"],
                    transport=row["transport"],
                    detail=detail,
                )
            )
        return out

    def counts(self, token: str) -> dict[str, int]:
        rows = self._read(
            "SELECT channel, COUNT(*) AS n FROM observations WHERE token = ? GROUP BY channel",
            (token,),
        )
        out = {channel: 0 for channel in CHANNELS}
        for row in rows:
            out[row["channel"]] = int(row["n"])
        return out

    # ------------------------------------------------------------------- ops
    def audit(self, event: str, client_ip: str | None = None,
              detail: dict[str, Any] | None = None) -> None:
        self._write(
            "INSERT INTO audit(created_at, event, client_ip, detail_json) VALUES (?,?,?,?)",
            (time.time(), event, client_ip, json.dumps(detail or {}, ensure_ascii=False)),
        )

    def purge(self, keep_seconds: int = 7 * 86400, now: float | None = None) -> int:
        """Delete observations, sessions and audit rows older than the window.

        Expired sessions are removed even inside the keep window — a session whose
        expiry has passed can never produce a new observation, and its STUN port
        should go back into the pool immediately.
        """
        cutoff = (now if now is not None else time.time()) - keep_seconds
        current = now if now is not None else time.time()
        removed = 0
        removed += self._write("DELETE FROM observations WHERE observed_at < ?", (cutoff,)).rowcount
        removed += self._write(
            "DELETE FROM sessions WHERE expires_at < ? OR expires_at < ?", (cutoff, current)
        ).rowcount
        removed += self._write("DELETE FROM audit WHERE created_at < ?", (cutoff,)).rowcount
        return removed

    def health(self) -> dict[str, Any]:
        row = self._read(
            "SELECT COUNT(*) AS sessions,"
            " SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) AS active FROM sessions",
            (time.time(),),
        )[0]
        totals = self._read(
            "SELECT channel, COUNT(*) AS n FROM observations WHERE observed_at > ? GROUP BY channel",
            (time.time() - 3600,),
        )
        return {
            "sessions": int(row["sessions"] or 0),
            "active_sessions": int(row["active"] or 0),
            "observations_last_hour": {r["channel"]: int(r["n"]) for r in totals},
        }


def iter_json(value: str | None) -> Iterator[Any]:
    """Small helper used by tests and CLI tools."""
    try:
        yield json.loads(value or "null")
    except json.JSONDecodeError:
        yield None
