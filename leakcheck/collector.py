"""HTTP collector: session bootstrap, browser beacons, pixel probes, health.

Deployment shape (see ``deploy/``): the collector and the Streamlit app sit
behind one reverse proxy.  The browser component inside the Streamlit page calls
this API cross-origin, so CORS is explicit; in the recommended deployment both
are served from the same site and the allowlist stays narrow.

Trust model: the client IP is taken from the TCP peer unless the peer is a
configured trusted proxy, in which case ``X-Forwarded-For`` is walked.  Nothing
the page sends is trusted as an address — every address in the report comes from
what the kernel told us (peer address) or from the DNS/STUN listeners.
"""

from __future__ import annotations

import base64
import logging
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import AppConfig, load_config
from .netutil import IPAddress, client_ip_from_forwarded, parse_ip
from .storage import Store
from .tokens import is_valid, new_token

log = logging.getLogger("leakcheck.collector")

# 1x1 transparent GIF, kept as bytes so the beacon never touches the disk.
PIXEL_GIF = base64.b64decode(b"R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

MAX_BEACON_BYTES = 16 * 1024
MAX_CANDIDATES = 64


class RateLimiter:
    """Per-client sliding window; small and in-process on purpose."""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, cost: int = 1) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) + cost > self.limit:
            return False
        bucket.extend([now] * cost)
        if len(self._hits) > 50_000:
            self._hits.clear()
        return True


def create_app(config: AppConfig | None = None) -> FastAPI:
    config = config or load_config()
    store = Store(config.server.database_path)
    limiter = RateLimiter(config.server.rate_limit_per_minute)

    app = FastAPI(
        title="VPN 泄露自检采集端",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config
    app.state.store = store

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.server.allowed_origins or ["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
        max_age=600,
    )

    def peer_ip(request: Request) -> IPAddress | None:
        forwarded = {k.lower(): v for k, v in request.headers.items()}
        raw_peer = request.client.host if request.client else None
        return client_ip_from_forwarded(
            forwarded, config.server.trusted_proxies, parse_ip(raw_peer)
        )

    def require_known_session(token: str, ip: IPAddress | None) -> None:
        if not is_valid(config.server.hmac_secret, token,
                        max_age=config.server.session_ttl_seconds):
            raise HTTPException(status_code=403, detail="令牌无效或已过期")
        if not store.touch_session(token, config.server.session_ttl_seconds):
            raise HTTPException(status_code=404, detail="会话不存在，请刷新页面")

    # ------------------------------------------------------------------ meta
    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "store": store.health()}

    @app.get("/api/v1/meta")
    def meta() -> dict[str, Any]:
        """Public, unauthenticated information the browser needs to probe."""
        return {
            "probe_domain": config.probe_domain,
            "site_title": config.site_title,
            "stun_ports": config.stun.ports,
            "stun_host": _public_host(config),
            "stun_targets": [f"{ip}:{config.stun.ports[0]}" for ip in config.stun.public_ips]
            if config.stun.public_ips and config.stun.ports else [],
            "max_probes": config.server.max_probes,
            "session_ttl": config.server.session_ttl_seconds,
        }

    # --------------------------------------------------------------- sessions
    @app.post("/api/v1/session")
    async def create_session(request: Request,
                             x_client_hint: str | None = Header(default=None)) -> dict[str, Any]:
        ip = peer_ip(request)
        key = str(ip) if ip else "unknown"
        if not limiter.allow(f"session:{key}", cost=1):
            raise HTTPException(status_code=429, detail="请求过于频繁，请稍候再试")
        token = new_token(config.server.hmac_secret)
        stun_port = None
        store.create_session(
            token,
            config.server.session_ttl_seconds,
            str(ip) if ip else None,
            request.headers.get("user-agent"),
            x_client_hint,
        )
        if config.stun.enabled and config.stun.ports:
            # Claim a UDP port now, not when the browser asks: STUN messages carry
            # no identity, so the port is the only thing tying them to a session.
            stun_port = store.assign_stun_port(
                token, config.stun.ports, config.server.session_ttl_seconds
            )
        if ip is not None:
            store.add_observation(
                token, "http", str(ip), None,
                "https" if request.url.scheme == "https" else "http",
                {"path": "/api/v1/session", "method": "POST", "kind": "session-bootstrap"},
            )
        store.audit("session_created", str(ip) if ip else None, {"token_prefix": token[:8]})
        return {
            "token": token,
            "expires_in": config.server.session_ttl_seconds,
            "probe_domain": config.probe_domain,
            "stun_port": stun_port,
            "stun_ports": config.stun.ports,
            "stun_host": _public_host(config),
        }

    # ---------------------------------------------------------------- beacons
    @app.get("/px.gif")
    def pixel(request: Request, t: str = Query(default=""), k: str = Query(default="")) -> Response:
        return _record_pixel(t, k, request, "px.gif")

    @app.get("/px.png")
    def pixel_png(request: Request, t: str = Query(default=""), k: str = Query(default="")) -> Response:
        return _record_pixel(t, k, request, "px.png")

    def _record_pixel(token: str, kind: str, request: Request, path: str) -> Response:
        headers = {
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Access-Control-Allow-Origin": "*",
        }
        if is_valid(
            config.server.hmac_secret, token, max_age=config.server.session_ttl_seconds
        ):
            ip = peer_ip(request)
            if ip is not None:
                try:
                    store.add_observation(
                        token, "http", str(ip), None,
                        "https" if request.url.scheme == "https" else "http",
                        {"path": path, "kind": kind or "pixel", "method": "GET",
                         "referer": request.headers.get("referer", "")[:300]},
                    )
                except Exception:  # noqa: BLE001
                    log.exception("记录像素探针失败")
        return Response(content=PIXEL_GIF, media_type="image/gif", headers=headers)

    @app.post("/api/v1/observe/http")
    async def observe_http(request: Request) -> dict[str, Any]:
        payload = await _json_body(request)
        token = str(payload.get("token") or "")
        require_known_session(token, peer_ip(request))
        ip = peer_ip(request)
        if ip is None:
            raise HTTPException(status_code=400, detail="无法确定来源地址")
        key = f"http:{ip}"
        if not limiter.allow(key, cost=1):
            raise HTTPException(status_code=429, detail="请求过于频繁")
        detail = {
            "path": str(payload.get("path") or "/api/v1/observe/http")[:200],
            "kind": str(payload.get("kind") or "beacon")[:60],
            "method": "POST",
            "referer": request.headers.get("referer", "")[:300],
            "round": payload.get("round"),
        }
        store.add_observation(
            token, "http", str(ip), None,
            "https" if request.url.scheme == "https" else "http", detail,
        )
        return {"ok": True, "observed": str(ip)}

    @app.post("/api/v1/observe/webrtc")
    async def observe_webrtc(request: Request) -> dict[str, Any]:
        payload = await _json_body(request)
        token = str(payload.get("token") or "")
        require_known_session(token, peer_ip(request))
        ip = peer_ip(request)
        if ip is None:
            raise HTTPException(status_code=400, detail="无法确定来源地址")
        key = f"webrtc:{ip}"
        if not limiter.allow(key, cost=1):
            raise HTTPException(status_code=429, detail="请求过于频繁")
        candidates = _clean_candidates(payload.get("candidates"))
        detail = {
            "kind": "webrtc-candidates",
            "candidates": candidates,
            "error": str(payload.get("error") or "")[:300] or None,
            "elapsed_ms": int(payload.get("elapsed_ms") or 0),
            "browser": str(payload.get("browser") or "")[:120],
            "mdns": bool(payload.get("mdns")),
            "ua": request.headers.get("user-agent", "")[:300],
        }
        store.add_observation(token, "webrtc", str(ip), None, "https", detail)
        return {"ok": True, "accepted": len(candidates)}

    @app.post("/api/v1/stage")
    async def stage_update(request: Request) -> dict[str, Any]:
        payload = await _json_body(request)
        token = str(payload.get("token") or "")
        require_known_session(token, peer_ip(request))
        store.set_stage(token, str(payload.get("stage") or ""))
        return {"ok": True}

    @app.get("/api/v1/observations/{token}")
    def observations(token: str) -> dict[str, Any]:
        """Compact view of what the server has seen, for the standalone page."""
        if not is_valid(config.server.hmac_secret, token,
                        max_age=config.server.session_ttl_seconds):
            raise HTTPException(status_code=403, detail="令牌无效或已过期")
        session = store.get_session(token)
        if session is None:
            raise HTTPException(status_code=404, detail="会话不存在")
        rows = []
        for obs in store.observations(token):
            rows.append(
                {
                    "channel": obs.channel,
                    "address": obs.source_ip,
                    "port": obs.source_port,
                    "transport": obs.transport,
                    "kind": obs.detail.get("kind"),
                }
            )
        return {"stage": session.stage or "running", "rows": rows,
                "counts": store.counts(token)}

    @app.get("/api/v1/status/{token}")
    def status(token: str) -> dict[str, Any]:
        if not is_valid(config.server.hmac_secret, token,
                        max_age=config.server.session_ttl_seconds):
            raise HTTPException(status_code=403, detail="令牌无效或已过期")
        session = store.get_session(token)
        if session is None:
            raise HTTPException(status_code=404, detail="会话不存在")
        return {
            "counts": store.counts(token),
            "expires_in": max(0.0, session.expires_in),
            "stun_port": session.stun_port,
        }

    # -------------------------------------------------------- standalone page
    @app.get("/probe.html")
    def probe_page() -> Response:
        """A dependency-free copy of the browser probe, for when Streamlit is down."""
        from .frontend import standalone_page

        return Response(content=standalone_page(config), media_type="text/html; charset=utf-8")

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"ok": False, "detail": exc.detail})

    async def _json_body(request: Request) -> dict[str, Any]:
        raw = await request.body()
        if len(raw) > MAX_BEACON_BYTES:
            raise HTTPException(status_code=413, detail="上报数据过大")
        try:
            import json

            payload = json.loads(raw or b"{}")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="JSON 解析失败") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="JSON 顶层必须是对象")
        return payload

    return app


def _public_host(config: AppConfig) -> str:
    host = config.server.public_base_url.split("//")[-1].split("/")[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _clean_candidates(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw[:MAX_CANDIDATES]:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address") or "").strip()[:128]
        # A candidate without an address tells us nothing; drop it rather than
        # storing rows that would render as empty evidence.
        if not address:
            continue
        out.append(
            {
                "type": str(item.get("type") or "")[:16],
                "protocol": str(item.get("protocol") or "")[:16],
                "address": address,
                "port": item.get("port") if isinstance(item.get("port"), int) else None,
                "foundation": str(item.get("foundation") or "")[:32],
            }
        )
    return out


def main() -> None:  # pragma: no cover - entry point
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load_config()
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.server.collector_bind,
        port=config.server.collector_port,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips=",".join(str(n) for n in config.server.trusted_proxies) or None,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
