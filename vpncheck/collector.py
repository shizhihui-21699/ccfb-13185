"""HTTP 采集端。

职责很小：记录“浏览器从这个地址、这个协议族访问了我”，并接收页面提交的
WebRTC/网络能力上报。它不返回任何业务数据，也不做重定向。

端点
----
``GET /probe/ip``
    返回本次请求的对端地址（JSON）。页面在 IPv4 专用域名和 IPv6 专用域名上
    各请求一次，用来观察两种协议族的**实际 TCP 出口**。
``GET /probe/pixel.gif``
    同上，但返回 1×1 透明图，供 ``<img>`` 降级探测使用。
``GET /probe/client.js``
    浏览器端探测脚本。以静态文件形式提供，供页面用 ``<script src>`` 加载；
    见 :mod:`vpncheck.probe_page` 中关于 ``st.html`` 净化限制的说明。
``POST /probe/report``
    页面提交的检测结果（WebRTC 候选、超时与错误），只接受本服务
    ``allowed_origins`` 中的来源。
``GET /healthz``
    健康检查。

安全约束
--------
* 默认不信任 ``X-Forwarded-For``；只有对端属于 ``trusted_proxies`` 才读取。
* 会话标识必须是 32 位十六进制，且必须存在且未过期。
* 请求体上限 64 KiB，按来源地址做令牌桶限流。
* 响应统一 ``Cache-Control: no-store``，避免缓存探测结果。
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .client_js import CLIENT_JS
from .clientip import resolve_client_ip
from .config import AppConfig, CollectorConfig
from .store import Store, valid_session_id

LOGGER = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
PIXEL = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)

_ALLOWED_REPORT_KINDS = {"webrtc", "netinfo", "timing", "error"}


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class _Limiter:
    capacity: float = 240.0
    rate: float = 8.0
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_cleanup: float = 0.0

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self.capacity, now)
                self._buckets[key] = bucket
            else:
                bucket.tokens = min(
                    self.capacity, bucket.tokens + (now - bucket.last) * self.rate
                )
                bucket.last = now
            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            if now - self._last_cleanup > 60.0:
                cutoff = now - 300.0
                for stale in [k for k, b in self._buckets.items() if b.last < cutoff]:
                    self._buckets.pop(stale, None)
                self._last_cleanup = now
            return True


class Collector:
    """把配置、存储和限流器封装起来，便于测试与嵌入。"""

    def __init__(
        self,
        config: CollectorConfig,
        app_config: AppConfig,
        store: Store,
    ):
        self.config = config
        self.app = app_config
        self.store = store
        self.limiter = _Limiter()
        origins = {origin.rstrip("/").lower() for origin in app_config.allowed_origins}
        self.allowed_origins = origins

    # -- 工具 -------------------------------------------------------------
    def client_ip(self, peer_ip: str | None, headers: dict[str, str]):
        return resolve_client_ip(
            peer_ip,
            headers,
            trust_forwarded_for=self.config.trust_forwarded_for,
            trusted_proxies=self.config.trusted_proxies,
        )

    def cors_origin(self, headers: dict[str, str]) -> str | None:
        origin = None
        for key, value in headers.items():
            if key.lower() == "origin":
                origin = value.strip().rstrip("/")
                break
        if origin and origin.lower() in self.allowed_origins:
            return origin
        return None

    def record_http(
        self,
        session_id: str | None,
        ip: str,
        family: int,
        transport: str,
        *,
        path: str = "/probe/ip",
        host: str = "",
    ) -> bool:
        if not session_id:
            return False
        return self.store.add_observation(
            session_id,
            "http",
            source_ip=ip,
            source_family=family,
            transport=transport,
            detail={"path": path, "host": host.lower()},
        )


class _Handler(BaseHTTPRequestHandler):
    server_version = "vpncheck-collector/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # 注入字段
    collector: Collector

    # -- 基础 -------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102
        LOGGER.debug("%s - %s", self.address_string(), fmt % args)

    def _headers_dict(self) -> dict[str, str]:
        return {key: value for key, value in self.headers.items()}

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        extra: dict[str, str] | None = None,
    ) -> None:
        collector = self.collector
        origin = collector.cors_origin(self._headers_dict())
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Vary", "Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _peer_ip(self) -> str | None:
        return self.client_address[0] if self.client_address else None

    # -- 路由 -------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(HTTPStatus.NO_CONTENT, b"", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)

        if path == "/healthz":
            self._json(HTTPStatus.OK, {"ok": True})
            return

        if path == "/probe/client.js":
            self._handle_script()
            return

        if path in {"/probe/ip", "/probe/pixel.gif"}:
            self._handle_probe(path, query)
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        if path != "/probe/report":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self._handle_report()

    # -- 处理 -------------------------------------------------------------
    def _handle_probe(self, path: str, query: dict[str, list[str]]) -> None:
        collector = self.collector
        ip = collector.client_ip(self._peer_ip(), self._headers_dict())
        if ip is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "无法确定来源地址"})
            return
        if not collector.limiter.allow(str(ip)):
            self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "请求过于频繁"})
            return

        sid = (query.get("s") or [None])[0]
        if sid is not None and not valid_session_id(sid):
            sid = None

        transport = "ipv6" if ip.version == 6 else "ipv4"
        host = self.headers.get("Host", "") or ""
        recorded = collector.record_http(
            sid, str(ip), ip.version, transport, path=path, host=host
        )

        if path.endswith("pixel.gif"):
            self._send(
                HTTPStatus.OK,
                PIXEL,
                "image/gif",
                extra={"Cross-Origin-Resource-Policy": "cross-origin"},
            )
            return

        self._json(
            HTTPStatus.OK,
            {
                "ip": str(ip),
                "family": ip.version,
                "is_public": bool(ip.is_global),
                "transport": transport,
                "recorded": recorded,
            },
        )

    def _handle_script(self) -> None:
        # 脚本需要被 st.html 所在页面跨域加载，因此允许任意来源读取，但
        # 明确禁止被当作模块使用（避免第三方页面 import 后拿到配置）。
        self._send(
            HTTPStatus.OK,
            CLIENT_JS.encode("utf-8"),
            "application/javascript; charset=utf-8",
            extra={
                "Cross-Origin-Resource-Policy": "cross-origin",
                "Cache-Control": "public, max-age=300, must-revalidate",
            },
        )

    def _handle_report(self) -> None:
        collector = self.collector
        headers = self._headers_dict()

        # 跨站来源直接拒绝：上报只允许自检页面本身发起。
        origin_header = next(
            (v for k, v in headers.items() if k.lower() == "origin"), None
        )
        if origin_header is not None and collector.cors_origin(headers) is None:
            self._json(HTTPStatus.FORBIDDEN, {"error": "来源不被允许"})
            return

        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "缺少或非法的 Content-Length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "请求体大小不合法"})
            return
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "只接受 application/json"})
            return

        ip = collector.client_ip(self._peer_ip(), headers)
        if ip is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "无法确定来源地址"})
            return
        if not collector.limiter.allow(str(ip)):
            self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "请求过于频繁"})
            return

        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "JSON 解析失败"})
            return
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "上报内容必须是对象"})
            return

        sid = payload.get("sid")
        if not valid_session_id(sid if isinstance(sid, str) else None):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "会话标识不合法"})
            return
        kind = payload.get("kind")
        if not isinstance(kind, str) or kind not in _ALLOWED_REPORT_KINDS:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "上报类型不合法"})
            return
        data = payload.get("data")
        if not isinstance(data, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "缺少 data 对象"})
            return

        ok = collector.store.add_browser_report(sid, kind, data)
        if not ok:
            self._json(HTTPStatus.GONE, {"error": "会话不存在或已过期"})
            return
        self._json(HTTPStatus.OK, {"ok": True})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, collector: Collector):
        self.collector = collector
        handler = type("BoundHandler", (handler,), {"collector": collector})
        super().__init__(addr, handler)


class _Server6(_Server):
    import socket as _socket

    address_family = _socket.AF_INET6


class CollectorService:
    """启动 HTTP 采集端（IPv4，可选 IPv6）。"""

    def __init__(self, config: CollectorConfig, app: AppConfig, store: Store):
        self.config = config
        self.app = app
        self.store = store
        self.collector = Collector(config, app, store)
        self._servers: list[_Server] = []
        self._threads: list[threading.Thread] = []
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        for host, port in self.config.listeners:
            cls = _Server6 if ":" in host else _Server
            srv = cls((host, port), _Handler, self.collector)
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            self._servers.append(srv)
            self._threads.append(thread)
            LOGGER.info("采集端已监听 %s:%s (HTTP)", host, port)
        self._started = True

    def stop(self) -> None:
        for srv in self._servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:  # noqa: BLE001
                LOGGER.debug("停止采集端失败", exc_info=True)
        self._servers.clear()
        self._threads.clear()
        self._started = False

    def run_forever(self) -> None:
        self.start()
        for thread in self._threads:
            thread.join()
