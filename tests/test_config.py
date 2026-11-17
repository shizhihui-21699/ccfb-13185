"""配置解析的边界条件。"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import BASE_CONFIG  # noqa: E402

from vpncheck.config import ConfigError, parse_config  # noqa: E402


def _parse(**overrides):
    data = copy.deepcopy(BASE_CONFIG)
    for section, value in overrides.items():
        data[section] = value
    return parse_config(data, source_path=Path("/tmp/config.toml"))


def test_minimal_config_ok():
    config = _parse()
    assert config.dns.zone == "probe.test.invalid"
    assert config.stun.port_range == (40000, 40007)
    assert config.table.is_corporate(_ip("203.0.113.9"))


def _ip(value):
    import ipaddress

    return ipaddress.ip_address(value)


def test_rejects_zero_prefix():
    with pytest.raises(ConfigError, match="0.0.0.0/0"):
        _parse(egress=[{"name": "坏规则", "cidr": ["0.0.0.0/0"]}])


def test_requires_corporate_entry():
    with pytest.raises(ConfigError, match="corporate"):
        _parse(egress=[{"name": "只有 DNS", "cidr": ["192.0.2.0/24"], "kind": "dns"}])


def test_rejects_unknown_kind():
    with pytest.raises(ConfigError, match="kind"):
        _parse(egress=[{"name": "x", "cidr": ["192.0.2.0/24"], "kind": "whatever"}])


def test_rejects_bad_cidr():
    with pytest.raises(ConfigError, match="不是合法 CIDR"):
        _parse(egress=[{"name": "x", "cidr": ["192.0.2.0/33"]}])


def test_rejects_bad_zone():
    with pytest.raises(ConfigError, match="域名"):
        _parse(dns={**BASE_CONFIG["dns"], "zone": "not a domain!"})


def test_dns_answers_validated():
    with pytest.raises(ConfigError, match="answer_ipv4"):
        _parse(dns={**BASE_CONFIG["dns"], "answer_ipv4": ["2001:db8::1"]})


def test_allowed_origins_required():
    with pytest.raises(ConfigError, match="allowed_origins"):
        _parse(app={"title": "x", "allowed_origins": []})


def test_stun_disabled_skips_host_requirement():
    config = _parse(
        stun={"enabled": False, "port_range": {"base": 40000, "size": 0}}
    )
    assert not config.stun.can_probe
    assert config.stun.full_uris == ("stun:invalid.invalid:3478",)


def test_documentation_addresses_detected():
    config = _parse()
    assert config.uses_documentation_addresses


def test_real_addresses_not_flagged():
    config = _parse(
        egress=[{"name": "真实出口", "cidr": ["49.234.11.0/24"], "kind": "corporate"}]
    )
    assert not config.uses_documentation_addresses


def test_policy_flag():
    config = _parse(policy={"app_requires_tunnel": True})
    assert config.policy.app_requires_tunnel


def test_invalid_boolean_rejected():
    with pytest.raises(ConfigError, match="true 或 false"):
        _parse(policy={"app_requires_tunnel": "yes"})
