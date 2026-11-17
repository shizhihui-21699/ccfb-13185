"""测试用的临时环境：随机端口、临时数据库、示例出口表。"""

from __future__ import annotations

import socket
import tempfile
from pathlib import Path
from typing import Any

from vpncheck.config import Config, parse_config


def free_port(kind: int = socket.SOCK_DGRAM) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_tcp_port() -> int:
    return free_port(socket.SOCK_STREAM)


BASE_CONFIG: dict[str, Any] = {
    "app": {
        "title": "测试自检",
        "public_url": "http://127.0.0.1",
        "allowed_origins": ["http://127.0.0.1"],
        "session_ttl_seconds": 300,
        "poll_interval_seconds": 1.0,
    },
    "collector": {
        "listen_host": "127.0.0.1",
        "listen_port": 0,
        "public_url_v4": "http://127.0.0.1",
        "trust_forwarded_for": False,
        "trusted_proxies": [],
    },
    "dns": {
        "enabled": True,
        "zone": "probe.test.invalid",
        "listen_host": "127.0.0.1",
        "listen_port": 0,
        "answer_ipv4": ["192.0.2.1"],
        "answer_ipv6": [],
        "ttl": 0,
        "wait_seconds": 2.0,
    },
    "stun": {
        "enabled": True,
        "listen_host": "127.0.0.1",
        "listen_port": 0,
        "public_host_v4": "127.0.0.1",
        "public_port_v4": 3478,
        "port_range": {"base": 40000, "size": 8},
    },
    "policy": {"app_requires_tunnel": False},
    "egress": [
        {"name": "测试公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"},
    ],
}


def make_config(**overrides: Any) -> Config:
    import copy

    data = copy.deepcopy(BASE_CONFIG)
    for section, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(section), dict):
            data[section].update(value)
        else:
            data[section] = value
    tmp = Path(tempfile.mkdtemp(prefix="vpncheck-test-"))
    return parse_config(data, source_path=tmp / "config.toml")
