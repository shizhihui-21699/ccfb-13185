"""会话与观测数据存储。

采集端（HTTP/DNS/STUN）和 Streamlit 页面是两个进程，通过 SQLite
共享数据。库很小，开启 WAL，所有写入都在毫秒级完成。

只保存判定所需的最小字段：来源地址、作业类型、简短明细。会话过期后
连同其全部观测一起删除。
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

SESSION_TTL_DEFAULT = 900
_MAX_JSON = 4000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    user_agent    TEXT NOT NULL DEFAULT '',
    app_ip        TEXT NOT NULL DEFAULT '',
    app_ip_family INTEGER
);

CREATE TABLE IF NOT EXISTS observations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    kind          TEXT NOT NULL,
    ts            REAL NOT NULL,
    source_ip     TEXT NOT NULL DEFAULT '',
    source_family INTEGER,
    transport     TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_obs_session_kind ON observations(session_id, kind);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS stun_ports (
    port          INTEGER PRIMARY KEY,
    session_id    TEXT NOT NULL UNIQUE,
    claimed_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    kind          TEXT NOT NULL,
    ts            REAL NOT NULL,
    payload       TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_reports_session ON browser_reports(session_id, kind);
"""


def new_session_id() -> str:
    """128 位随机会话标识，只含十六进制字符。"""
    return secrets.token_hex(16)


def valid_session_id(value: str | None) -> bool:
    if not isinstance(value, str) or len(value) != 32:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _json(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return text[:_MAX_JSON]


@dataclass(frozen=True)
class Observation:
    kind: str
    ts: float
    source_ip: str
    source_family: int | None
    transport: str
    detail: dict[str, Any]


@dataclass(frozen=True)
class Session:
    id: str
    created_at: float
    expires_at: float
    user_agent: str
    app_ip: str
    app_ip_family: int | None

    @property
    def expired(self) -> bool:
        return self.expires_at < time.time()


class Store:
    """线程安全（每线程独立连接）的轻量存储。"""

    def __init__(self, path: str | Path, *, ttl_seconds: int = SESSION_TTL_DEFAULT):
        self.path = str(path)
        self.ttl_seconds = ttl_seconds
        self._uri = False
        self._anchor: sqlite3.Connection | None = None
        if self.path == ":memory:":
            # 普通 :memory: 每个连接都是独立库；用共享缓存 + 一个常驻连接
            # 让测试里的多线程读写看到同一个库。
            token = secrets.token_hex(8)
            self.path = f"file:vpncheck-{token}?mode=memory&cache=shared"
            self._uri = True
            self._anchor = sqlite3.connect(self.path, uri=True, check_same_thread=False)
        else:
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # -- 连接管理 ---------------------------------------------------------
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(
            self.path, timeout=5.0, isolation_level=None, uri=self._uri
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            if not self._uri:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
        finally:
            conn.close()

    def close(self) -> None:
        if self._anchor is not None:
            try:
                self._anchor.close()
            finally:
                self._anchor = None

    # -- 会话 -------------------------------------------------------------
    def create_session(
        self,
        session_id: str | None = None,
        *,
        user_agent: str = "",
        app_ip: str = "",
        app_ip_family: int | None = None,
        ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> Session:
        sid = session_id or new_session_id()
        if not valid_session_id(sid):
            raise ValueError("会话标识必须是 32 位十六进制字符串")
        now = time.time() if now is None else now
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        expires = now + ttl
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions"
                " (id, created_at, expires_at, user_agent, app_ip, app_ip_family)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (sid, now, expires, (user_agent or "")[:400], app_ip or "", app_ip_family),
            )
        return Session(
            id=sid,
            created_at=now,
            expires_at=expires,
            user_agent=(user_agent or "")[:400],
            app_ip=app_ip or "",
            app_ip_family=app_ip_family,
        )

    def get_session(self, session_id: str | None) -> Session | None:
        if not valid_session_id(session_id):
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        return Session(
            id=row["id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            user_agent=row["user_agent"],
            app_ip=row["app_ip"],
            app_ip_family=row["app_ip_family"],
        )

    def session_alive(self, session_id: str | None, *, now: float | None = None) -> bool:
        session = self.get_session(session_id)
        if session is None:
            return False
        now = time.time() if now is None else now
        return session.expires_at >= now

    def touch(self, session_id: str, *, now: float | None = None) -> None:
        """续期：员工停留在页面上时不至于中途过期。"""
        if not valid_session_id(session_id):
            return
        now = time.time() if now is None else now
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET expires_at = MAX(expires_at, ?) WHERE id = ?",
                (now + self.ttl_seconds, session_id),
            )

    def sessions_for_address(
        self, ip: str, *, now: float | None = None, limit: int = 8
    ) -> list[str]:
        """找出与该地址关联、且仍活跃的会话。

        关联依据：会话在页面上登记过的应用访问地址（``app_ip``）或已有观测
        的来源地址。用于把无法携带会话标识的 STUN 请求归并到会话上。
        """
        if not ip:
            return []
        now = time.time() if now is None else now
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT s.id AS id, s.created_at AS created_at
                FROM sessions AS s
                LEFT JOIN observations AS o ON o.session_id = s.id
                WHERE s.expires_at >= ?
                  AND (s.app_ip = ? OR o.source_ip = ?)
                ORDER BY s.created_at DESC
                LIMIT ?
                """,
                (now, ip, ip, limit),
            ).fetchall()
        return [row["id"] for row in rows]

    # -- 观测 -------------------------------------------------------------
    def add_observation(
        self,
        session_id: str,
        kind: str,
        *,
        source_ip: str = "",
        source_family: int | None = None,
        transport: str = "",
        detail: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> bool:
        if not valid_session_id(session_id):
            return False
        now = time.time() if now is None else now
        with self._connect() as conn:
            alive = conn.execute(
                "SELECT 1 FROM sessions WHERE id = ? AND expires_at >= ?",
                (session_id, now),
            ).fetchone()
            if alive is None:
                return False
            conn.execute(
                "INSERT INTO observations"
                " (session_id, kind, ts, source_ip, source_family, transport, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    kind[:32],
                    now,
                    source_ip or "",
                    source_family,
                    transport[:16],
                    _json(detail or {}),
                ),
            )
        return True

    def observations(self, session_id: str, kind: str | None = None) -> list[Observation]:
        if not valid_session_id(session_id):
            return []
        query = "SELECT * FROM observations WHERE session_id = ?"
        params: list[Any] = [session_id]
        if kind is not None:
            query += " AND kind = ?"
            params.append(kind)
        query += " ORDER BY ts ASC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            Observation(
                kind=row["kind"],
                ts=row["ts"],
                source_ip=row["source_ip"],
                source_family=row["source_family"],
                transport=row["transport"],
                detail=json.loads(row["detail"] or "{}"),
            )
            for row in rows
        ]

    # -- 浏览器上报 -------------------------------------------------------
    def add_browser_report(
        self,
        session_id: str,
        kind: str,
        payload: dict[str, Any],
        *,
        now: float | None = None,
    ) -> bool:
        if not valid_session_id(session_id):
            return False
        now = time.time() if now is None else now
        with self._connect() as conn:
            alive = conn.execute(
                "SELECT 1 FROM sessions WHERE id = ? AND expires_at >= ?",
                (session_id, now),
            ).fetchone()
            if alive is None:
                return False
            conn.execute(
                "INSERT INTO browser_reports (session_id, kind, ts, payload)"
                " VALUES (?, ?, ?, ?)",
                (session_id, kind[:32], now, _json(payload)),
            )
        return True

    def browser_reports(self, session_id: str, kind: str | None = None) -> list[dict[str, Any]]:
        if not valid_session_id(session_id):
            return []
        query = "SELECT kind, ts, payload FROM browser_reports WHERE session_id = ?"
        params: list[Any] = [session_id]
        if kind is not None:
            query += " AND kind = ?"
            params.append(kind)
        query += " ORDER BY ts ASC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        out = []
        for row in rows:
            try:
                payload = json.loads(row["payload"] or "{}")
            except json.JSONDecodeError:
                payload = {}
            out.append({"kind": row["kind"], "ts": row["ts"], "payload": payload})
        return out

    # -- STUN 端口认领 ----------------------------------------------------
    def claim_stun_port(
        self,
        session_id: str,
        base: int,
        size: int,
        *,
        now: float | None = None,
    ) -> int | None:
        """为会话认领一个端口池端口；池满或认领失败返回 ``None``。

        ``port`` 是主键、``session_id`` 唯一：并发认领时由 SQLite 保证同一
        端口不会被两个会话同时占用，页面与探针分进程部署也一致。
        """
        if not valid_session_id(session_id) or size <= 0:
            return None
        now = time.time() if now is None else now
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT port FROM stun_ports WHERE session_id = ?", (session_id,)
            ).fetchone()
            if existing is not None:
                return int(existing["port"])
            used = {
                row["port"]
                for row in conn.execute(
                    "SELECT port FROM stun_ports WHERE port BETWEEN ? AND ?",
                    (base, base + size - 1),
                )
            }
            for offset in range(size):
                port = base + offset
                if port in used:
                    continue
                try:
                    conn.execute(
                        "INSERT INTO stun_ports (port, session_id, claimed_at) VALUES (?, ?, ?)",
                        (port, session_id, now),
                    )
                except sqlite3.IntegrityError:
                    # 另一个进程刚抢到同一个端口，或该会话已认领，重新读一次。
                    existing = conn.execute(
                        "SELECT port FROM stun_ports WHERE session_id = ?", (session_id,)
                    ).fetchone()
                    if existing is not None:
                        return int(existing["port"])
                    continue
                return port
        return None

    def stun_port_of(self, session_id: str) -> int | None:
        if not valid_session_id(session_id):
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT port FROM stun_ports WHERE session_id = ?", (session_id,)
            ).fetchone()
        return int(row["port"]) if row is not None else None

    def session_for_stun_port(self, port: int) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT session_id FROM stun_ports WHERE port = ?", (port,)
            ).fetchone()
        return row["session_id"] if row is not None else None

    def release_stun_port(self, session_id: str) -> None:
        if not valid_session_id(session_id):
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM stun_ports WHERE session_id = ?", (session_id,))

    def expire_stun_ports(self, *, now: float | None = None) -> int:
        """回收已过期会话的端口。"""
        now = time.time() if now is None else now
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM stun_ports WHERE session_id NOT IN"
                " (SELECT id FROM sessions WHERE expires_at >= ?)",
                (now,),
            )
            return cursor.rowcount or 0

    # -- 维护 -------------------------------------------------------------
    def cleanup(self, *, now: float | None = None) -> int:
        """删除过期会话及其全部数据，返回删除的会话数。"""
        now = time.time() if now is None else now
        with self._connect() as conn:
            ids = [
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM sessions WHERE expires_at < ?", (now,)
                ).fetchall()
            ]
            for sid in ids:
                conn.execute("DELETE FROM observations WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM browser_reports WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM stun_ports WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        return len(ids)

    def purge_session(self, session_id: str) -> None:
        if not valid_session_id(session_id):
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM observations WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM browser_reports WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM stun_ports WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
