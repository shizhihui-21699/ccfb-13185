"""探针回调 API（FastAPI）。

浏览器里的探针 JS 调用这些接口，服务端记录的 TCP 对端 IP 就是该流量的真实出口：
  GET  /api/probe/web     —— 普通 HTTPS 流量的出口 IP
  GET  /api/probe/ipv6    —— 通过 ipv6.<zone>（仅 AAAA）访问，成功即说明有 IPv6 出口
  GET  /api/probe/ipv4    —— 对照组
  GET  /api/probe/dns-hit —— 经 <token>.dns.<zone> 解析后的回源，确认 DNS 链路完整
  POST /api/report/{token} —— 浏览器上报 WebRTC 收集到的候选地址
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

log = logging.getLogger("leakcheck.api")


class WebRTCReport(BaseModel):
    webrtc: list[dict] = []  # [{"ip": "1.2.3.4", "type": "host|srflx|relay"}, ...]


def create_app(db, cfg: dict) -> FastAPI:
    app = FastAPI(title="vpn-leak-check API", docs_url=None, redoc_url=None)
    # 探针接口按 token 隔离、不含敏感数据，放开 CORS 便于跨端口/跨域调用
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def client_ip(request: Request) -> str:
        if cfg.get("trust_proxy_headers"):
            xff = request.headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()
        return request.client.host if request.client else ""

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/probe/web")
    def probe_web(token: str, request: Request):
        ip = client_ip(request)
        db.set_user_agent(token, request.headers.get("user-agent", ""))
        db.add_event(token, "web", ip)
        return {"ip": ip}

    @app.get("/api/probe/ipv6")
    def probe_ipv6(token: str, request: Request):
        ip = client_ip(request)
        db.add_event(token, "ipv6", ip)
        return {"ip": ip}

    @app.get("/api/probe/ipv4")
    def probe_ipv4(token: str, request: Request):
        ip = client_ip(request)
        db.add_event(token, "ipv4", ip)
        return {"ip": ip}

    @app.get("/api/probe/dns-hit")
    def probe_dns_hit(token: str, request: Request):
        ip = client_ip(request)
        db.add_event(token, "dns-hit", ip, {"host": request.headers.get("host", "")})
        return {"ip": ip}

    @app.post("/api/report/{token}")
    def report(token: str, body: WebRTCReport, request: Request):
        for item in body.webrtc[:50]:
            ip = str(item.get("ip", ""))[:64]
            if ip:
                db.add_event(token, "webrtc", ip, {"type": str(item.get("type", ""))[:16]})
        db.add_event(token, "report_done", client_ip(request))
        return {"ok": True, "received": len(body.webrtc)}

    return app
