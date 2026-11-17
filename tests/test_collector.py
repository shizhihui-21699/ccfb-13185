"""采集端与客户端地址解析。"""

from __future__ import annotations

import ipaddress
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import make_config  # noqa: E402

from vpncheck.clientip import resolve_client_ip  # noqa: E402
from vpncheck.collector import CollectorService  # noqa: E402
from vpncheck.store import Store  # noqa: E402


# --------------------------------------------------------------------------
# 地址解析
# --------------------------------------------------------------------------
def _net(value):
    return (ipaddress.ip_network(value),)


def test_direct_peer_used_when_not_trusting_headers():
    assert str(resolve_client_ip("198.51.100.9", {"X-Forwarded-For": "1.2.3.4"})) == "198.51.100.9"


def test_forwarded_ignored_from_untrusted_peer():
    ip = resolve_client_ip(
        "198.51.100.9",
        {"X-Forwarded-For": "1.2.3.4"},
        trust_forwarded_for=True,
        trusted_proxies=_net("10.0.0.0/8"),
    )
    assert str(ip) == "198.51.100.9"


def test_forwarded_used_behind_trusted_proxy():
    ip = resolve_client_ip(
        "10.1.2.3",
        {"X-Forwarded-For": "203.0.113.5, 10.9.9.9"},
        trust_forwarded_for=True,
        trusted_proxies=_net("10.0.0.0/8"),
    )
    assert str(ip) == "203.0.113.5"


def test_forwarded_skips_spoofed_left_entries():
    # 客户端自己塞了 8.8.8.8，但真正的右侧链路是可信代理
    ip = resolve_client_ip(
        "10.1.2.3",
        {"X-Forwarded-For": "8.8.8.8, 198.51.100.77, 10.1.2.3"},
        trust_forwarded_for=True,
        trusted_proxies=_net("10.0.0.0/8"),
    )
    assert str(ip) == "198.51.100.77"


def test_ipv4_mapped_normalized():
    ip = resolve_client_ip("::ffff:203.0.113.7")
    assert str(ip) == "203.0.113.7" and ip.version == 4


def test_garbage_peer_returns_none():
    assert resolve_client_ip("not-an-ip") is None


# --------------------------------------------------------------------------
# 采集端
# --------------------------------------------------------------------------
@pytest.fixture()
def collector_env():
    config = make_config(
        app={"allowed_origins": ["https://vpncheck.example.com"]},
        collector={"public_url_v4": "http://127.0.0.1:9"},
        dns={"enabled": False},
        stun={"enabled": False},
    )
    store = Store(":memory:")
    sid = "e" * 32
    store.create_session(sid, ttl_seconds=300)
    service = CollectorService(config.collector, config.app, store)
    service.start()
    port = service._servers[0].server_address[1]
    yield f"http://127.0.0.1:{port}", store, sid
    service.stop()


def _get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def _post(url: str, payload: dict, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    merged = {"Content-Type": "application/json"}
    merged.update(headers or {})
    request = urllib.request.Request(url, data=body, headers=merged, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_probe_records_source(collector_env):
    base, store, sid = collector_env
    status, body = _get(f"{base}/probe/ip?s={sid}")
    assert status == 200
    assert body["ip"] == "127.0.0.1"
    assert body["family"] == 4
    assert body["recorded"] is True
    obs = store.observations(sid, "http")
    assert len(obs) == 1 and obs[0].source_ip == "127.0.0.1"


def test_probe_without_session_does_not_record(collector_env):
    base, store, sid = collector_env
    status, body = _get(f"{base}/probe/ip")
    assert status == 200 and body["recorded"] is False
    assert store.observations(sid, "http") == []


def test_probe_rejects_bad_session(collector_env):
    base, store, sid = collector_env
    status, body = _get(f"{base}/probe/ip?s=not-a-session")
    assert status == 200 and body["recorded"] is False


def test_pixel_probe(collector_env):
    base, store, sid = collector_env
    request = urllib.request.Request(f"{base}/probe/pixel.gif?s={sid}")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.headers["Content-Type"] == "image/gif"
        assert response.read(3) == b"GIF"
    assert len(store.observations(sid, "http")) == 1


def test_report_requires_allowed_origin(collector_env):
    base, store, sid = collector_env
    status, _ = _post(
        f"{base}/probe/report",
        {"sid": sid, "kind": "webrtc", "data": {"candidates": []}},
        {"Origin": "https://evil.example.net"},
    )
    assert status == 403
    status, body = _post(
        f"{base}/probe/report",
        {"sid": sid, "kind": "webrtc", "data": {"candidates": []}},
        {"Origin": "https://vpncheck.example.com"},
    )
    assert status == 200 and body["ok"] is True
    assert len(store.browser_reports(sid, "webrtc")) == 1


def test_report_rejects_bad_kind_and_session(collector_env):
    base, store, sid = collector_env
    status, _ = _post(f"{base}/probe/report", {"sid": sid, "kind": "nope", "data": {}})
    assert status == 400
    status, _ = _post(f"{base}/probe/report", {"sid": "f" * 32, "kind": "webrtc", "data": {}})
    assert status == 410


def test_report_rejects_oversized_body(collector_env):
    base, store, sid = collector_env
    status, _ = _post(
        f"{base}/probe/report", {"sid": sid, "kind": "webrtc", "data": {"x": "A" * 80000}}
    )
    assert status == 413


def test_healthz(collector_env):
    base, store, sid = collector_env
    status, body = _get(f"{base}/healthz")
    assert status == 200 and body == {"ok": True}


def test_unknown_path_404(collector_env):
    base, store, sid = collector_env
    status, _ = _get(f"{base}/nope")
    assert status == 404


def test_cors_preflight(collector_env):
    base, store, sid = collector_env
    request = urllib.request.Request(
        f"{base}/probe/report",
        method="OPTIONS",
        headers={"Origin": "https://vpncheck.example.com"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 204
        assert response.headers["Access-Control-Allow-Origin"] == "https://vpncheck.example.com"


def test_expired_session_not_recorded(collector_env):
    base, store, sid = collector_env
    store.create_session("0" * 32, ttl_seconds=1, now=time.time() - 100)
    status, body = _get(f"{base}/probe/ip?s={'0' * 32}")
    assert status == 200 and body["recorded"] is False
