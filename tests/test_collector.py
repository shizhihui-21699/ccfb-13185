"""Collector API tests (FastAPI TestClient): sessions, beacons, CORS, limits."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from leakcheck.collector import PIXEL_GIF, create_app


@pytest.fixture()
def client(config, store):
    app = create_app(config)
    # A real peer address: the collector attributes observations to the TCP peer,
    # so the default "testclient" hostname would (correctly) be rejected.
    with TestClient(app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def _new_session(client) -> dict:
    response = client.post("/api/v1/session")
    assert response.status_code == 200, response.text
    return response.json()


def test_healthz(client):
    body = client.get("/healthz").json()
    assert body["ok"] is True


def test_session_bootstrap_records_http_observation(client, config, store):
    data = _new_session(client)
    assert len(data["token"]) == 28
    assert data["probe_domain"] == config.probe_domain
    assert data["stun_ports"] == config.stun.ports

    observations = store.observations(data["token"])
    assert [o.channel for o in observations] == ["http"]
    assert observations[0].source_ip == "127.0.0.1"


def test_meta_is_public(client, config):
    body = client.get("/api/v1/meta").json()
    assert body["probe_domain"] == config.probe_domain
    assert body["max_probes"] == config.server.max_probes


def test_pixel_records_observation_and_returns_gif(client, store):
    token = _new_session(client)["token"]
    response = client.get(f"/px.gif?t={token}&k=round1")
    assert response.status_code == 200
    assert response.content == PIXEL_GIF
    assert response.headers["cache-control"].startswith("no-store")
    assert any(o.detail.get("kind") == "round1" for o in store.observations(token))


def test_pixel_without_valid_token_is_still_served(client, store):
    response = client.get("/px.gif?t=invalid")
    assert response.status_code == 200
    assert response.content == PIXEL_GIF


def test_http_beacon_requires_valid_token(client, store):
    token = _new_session(client)["token"]
    ok = client.post("/api/v1/observe/http", json={"token": token, "kind": "round2"})
    assert ok.status_code == 200
    assert any(o.detail.get("kind") == "round2" for o in store.observations(token))

    bad = client.post("/api/v1/observe/http", json={"token": "x" * 28})
    assert bad.status_code == 403


def test_beacon_rejects_oversized_body(client):
    token = _new_session(client)["token"]
    response = client.post(
        "/api/v1/observe/http",
        content=b'{"token":"' + token.encode() + b'","pad":"' + b"a" * 20000 + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_beacon_rejects_non_object_json(client):
    _new_session(client)  # a live session, so rejection is about the body shape
    response = client.post("/api/v1/observe/http", content=b"[1,2,3]",
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400


def test_webrtc_report_is_sanitised(client, store):
    token = _new_session(client)["token"]
    payload = {
        "token": token,
        "candidates": [
            {"type": "srflx", "address": "198.51.100.7", "port": 61000, "protocol": "udp"},
            {"type": "host", "address": "10.0.0.5", "port": 52000, "protocol": "udp"},
            {"junk": True},
            "not-a-dict",
        ],
        "error": None,
        "elapsed_ms": 1234,
        "mdns": False,
        "browser": "pytest",
    }
    response = client.post("/api/v1/observe/webrtc", json=payload)
    assert response.status_code == 200
    assert response.json()["accepted"] == 2

    webrtc = [o for o in store.observations(token) if o.channel == "webrtc"][0]
    assert len(webrtc.detail["candidates"]) == 2
    assert webrtc.detail["elapsed_ms"] == 1234


def test_stage_and_observations_endpoints(client, store):
    token = _new_session(client)["token"]
    assert client.post("/api/v1/stage", json={"token": token, "stage": "dns"}).status_code == 200
    body = client.get(f"/api/v1/observations/{token}").json()
    assert body["stage"] == "dns"
    assert body["rows"]


def test_cors_allows_probe_origin(client):
    response = client.options(
        "/api/v1/observe/http",
        headers={
            "Origin": "https://leakcheck.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") in {"*", "https://leakcheck.example.com"}


def test_rate_limit_returns_429(config):
    config.server.rate_limit_per_minute = 2
    app = create_app(config)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        assert client.post("/api/v1/session").status_code == 200
        # Each session creation costs one; the third must be throttled.
        codes = [client.post("/api/v1/session").status_code for _ in range(3)]
        assert 429 in codes


def test_probe_page_served(client, config):
    response = client.get("/probe.html")
    assert response.status_code == 200
    # The standalone page creates its own session and reads the probe domain
    # from the API response, so it must reference that endpoint and the WebRTC API.
    assert "/api/v1/session" in response.text
    assert "RTCPeerConnection" in response.text


def test_token_without_session_row_returns_404(client, config):
    """A correctly signed token for a session that was purged must not be accepted."""
    from leakcheck.tokens import new_token

    orphan = new_token(config.server.hmac_secret)
    response = client.post("/api/v1/observe/http", json={"token": orphan})
    assert response.status_code == 404
