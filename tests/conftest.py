"""Shared fixtures: a config that models a small company's exit inventory."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from leakcheck.config import AppConfig, config_from_dict  # noqa: E402
from leakcheck.storage import Observation, Store  # noqa: E402
from leakcheck.tokens import new_token  # noqa: E402

RAW_CONFIG: dict[str, Any] = {
    "site": {"title": "测试自检", "probe_domain": "probe.test.invalid"},
    "server": {
        "public_base_url": "http://127.0.0.1:8081",
        "collector_bind": "127.0.0.1",
        "collector_port": 8081,
        "hmac_secret": "unit-test-secret",
        "session_ttl_seconds": 900,
        "rate_limit_per_minute": 600,
    },
    "dns": {
        "enabled": True,
        "bind_host": "127.0.0.1",
        "bind_port": 15353,
        "zone": "probe.test.invalid",
        "answer_ipv4": ["203.0.113.10"],
        "answer_ipv6": ["2001:db8::10"],
    },
    "stun": {"enabled": True, "bind_host": "127.0.0.1", "ports": [3478], "bind_ipv6": False},
    "exit_inventory": {
        "vpn_egress": {"addresses": ["198.51.100.0/24", "2001:db8:100::/48"]},
        "corp_resolvers": {"addresses": ["198.51.100.21/32"]},
        "office_egress": {"addresses": ["203.0.113.0/24"]},
        "known_third_party_resolvers": {"Cloudflare": ["1.1.1.1/32", "1.0.0.1/32"]},
    },
    "remediation": {"support_contact": "IT 服务台", "internal_dns_servers": ["10.10.0.53"]},
}


@pytest.fixture()
def config(tmp_path: Path) -> AppConfig:
    raw = dict(RAW_CONFIG)
    raw["server"] = dict(RAW_CONFIG["server"])
    raw["server"]["database_path"] = str(tmp_path / "leakcheck.db")
    return config_from_dict(raw)


@pytest.fixture()
def store(config: AppConfig) -> Store:
    return Store(config.server.database_path)


@pytest.fixture()
def session(store: Store, config: AppConfig):
    token = new_token(config.server.hmac_secret)
    return store.create_session(
        token, config.server.session_ttl_seconds, "198.51.100.7",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "pytest",
    )


def obs(channel: str, ip: str, **detail: Any) -> Observation:
    from leakcheck.storage import Observation as Obs

    return Obs(
        channel=channel,
        observed_at=0.0,
        source_ip=ip,
        source_port=detail.pop("port", 50000),
        transport=detail.pop("transport", "udp"),
        detail=detail,
    )
