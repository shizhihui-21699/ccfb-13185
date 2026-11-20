"""Token, config and storage tests."""

from __future__ import annotations

import time

import pytest
import yaml

from conftest import RAW_CONFIG

from leakcheck.config import ConfigError, config_from_dict, load_config, parse_networks
from leakcheck.netutil import (
    address_scope, client_ip_from_forwarded, parse_ip,
)
from leakcheck.storage import Store
from leakcheck.tokens import is_valid, new_token, normalise


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def test_token_is_dns_label_safe():
    token = new_token(b"secret")
    assert len(token) == 28
    assert token.isalnum() and token == token.lower()
    assert len(token) <= 63


def test_tokens_are_unique_and_verify():
    secret = b"secret"
    tokens = {new_token(secret) for _ in range(200)}
    assert len(tokens) == 200
    for token in tokens:
        assert is_valid(secret, token, max_age=600)


def test_token_rejects_forgery():
    good = new_token(b"secret")
    tampered = ("a" if good[0] != "a" else "b") + good[1:]
    assert not is_valid(b"secret", tampered)
    assert not is_valid(b"other-secret", good)
    assert not is_valid(b"secret", "not-a-token")
    assert not is_valid(b"secret", "")
    assert not is_valid(b"secret", good[:-3])


def test_token_expiry():
    issued = time.time() - 3600
    token = new_token(b"secret", issued_at=issued)
    assert is_valid(b"secret", token, max_age=900) is False
    assert is_valid(b"secret", token, max_age=7200) is True


def test_normalise_case():
    token = new_token(b"secret")
    assert normalise(token.upper()) == token


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_config_requires_probe_domain():
    with pytest.raises(ConfigError, match="probe_domain"):
        config_from_dict({**RAW_CONFIG, "site": {"probe_domain": "not a domain"}})


def test_config_rejects_empty_vpn_egress():
    raw = {**RAW_CONFIG, "exit_inventory": {**RAW_CONFIG["exit_inventory"],
                                            "vpn_egress": {"addresses": []}}}
    with pytest.raises(ConfigError, match="vpn_egress"):
        config_from_dict(raw)


def test_config_zone_must_match_probe_domain():
    raw = {**RAW_CONFIG, "dns": {**RAW_CONFIG["dns"], "zone": "other.invalid"}}
    with pytest.raises(ConfigError, match="zone"):
        config_from_dict(raw)


def test_config_rejects_bad_network():
    raw = {**RAW_CONFIG, "exit_inventory": {**RAW_CONFIG["exit_inventory"],
                                            "vpn_egress": {"addresses": ["999.1.1.1/24"]}}}
    with pytest.raises(ConfigError, match="非法地址"):
        config_from_dict(raw)


def test_config_requires_existing_file(tmp_path):
    with pytest.raises(ConfigError, match="找不到配置文件"):
        load_config(tmp_path / "missing.yaml")


def test_config_loads_from_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    raw = {**RAW_CONFIG, "server": {**RAW_CONFIG["server"],
                                    "database_path": str(tmp_path / "x.db")}}
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    config = load_config(path)
    assert config.probe_domain == "probe.test.invalid"
    assert config.exits.in_vpn_egress(parse_ip("198.51.100.5"))


def test_default_third_party_resolvers_when_unset():
    raw = {**RAW_CONFIG, "exit_inventory": {
        "vpn_egress": RAW_CONFIG["exit_inventory"]["vpn_egress"],
        "corp_resolvers": RAW_CONFIG["exit_inventory"]["corp_resolvers"],
    }}
    config = config_from_dict(raw)
    assert config.exits.public_resolver_name(parse_ip("8.8.8.8")) == "Google"
    assert config.exits.public_resolver_name(parse_ip("1.1.1.1")) == "Cloudflare"


# ---------------------------------------------------------------------------
# netutil
# ---------------------------------------------------------------------------

def test_parse_ip_forms():
    assert str(parse_ip("203.0.113.9")) == "203.0.113.9"
    assert str(parse_ip("[2001:db8::1]")) == "2001:db8::1"
    assert str(parse_ip("203.0.113.9:443")) == "203.0.113.9"
    assert str(parse_ip("::ffff:203.0.113.9")) == "203.0.113.9"
    assert parse_ip("not-an-ip") is None
    assert parse_ip(None) is None


def test_address_scope_is_stable():
    assert address_scope(parse_ip("10.0.0.1")) == "private"
    assert address_scope(parse_ip("100.64.0.1")) == "private"
    assert address_scope(parse_ip("127.0.0.1")) == "loopback"
    assert address_scope(parse_ip("169.254.1.1")) == "link_local"
    assert address_scope(parse_ip("224.0.0.1")) == "multicast"
    assert address_scope(parse_ip("203.0.113.5")) == "public"
    assert address_scope(parse_ip("2001:db8::1")) == "public"
    assert address_scope(parse_ip("fd00::1")) == "private"


def test_forwarded_header_ignored_from_untrusted_peer():
    trusted = parse_networks(["127.0.0.0/8"])
    headers = {"x-forwarded-for": "1.2.3.4"}
    assert str(client_ip_from_forwarded(headers, trusted, parse_ip("9.9.9.9"))) == "9.9.9.9"


def test_forwarded_header_walked_from_trusted_peer():
    trusted = parse_networks(["127.0.0.0/8", "10.0.0.0/8"])
    headers = {"x-forwarded-for": "1.2.3.4, 10.1.1.1"}
    result = client_ip_from_forwarded(headers, trusted, parse_ip("127.0.0.1"))
    assert str(result) == "1.2.3.4"


def test_forwarded_all_trusted_falls_back_to_peer():
    trusted = parse_networks(["127.0.0.0/8"])
    headers = {"x-forwarded-for": "127.0.0.5"}
    assert str(client_ip_from_forwarded(headers, trusted, parse_ip("127.0.0.1"))) == "127.0.0.1"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def test_session_roundtrip(store: Store):
    token = new_token(b"k")
    store.create_session(token, 60, "1.2.3.4", "UA", "hint", {"a": 1})
    fetched = store.get_session(token)
    assert fetched is not None
    assert fetched.meta == {"a": 1}
    assert fetched.expires_in > 0
    assert store.touch_session(token, 120)
    assert not store.touch_session("missing-token-value", 60)


def test_observation_dedup_counting(store: Store):
    token = new_token(b"k")
    store.create_session(token, 60, "1.2.3.4", "UA", None)
    for _ in range(3):
        store.add_observation(token, "http", "1.2.3.4", None, "https", {"kind": "round1"})
    counts = store.counts(token)
    assert counts["http"] == 3
    assert counts["dns"] == 0
    assert len(store.observations(token)) == 3


def test_observation_rejects_unknown_channel(store: Store):
    with pytest.raises(ValueError):
        store.add_observation("t", "carrier-pigeon", "1.1.1.1")


def test_stun_port_allocation_avoids_collisions(store: Store):
    ports = [5000, 5001]
    tokens = []
    for _ in range(2):
        token = new_token(b"k")
        store.create_session(token, 60, "1.2.3.4", "UA", None)
        tokens.append(token)
        store.assign_stun_port(token, ports, 60)
    assigned = {store.get_session(t).stun_port for t in tokens}
    assert assigned == set(ports)
    # Every port maps back to a live session.
    for port in ports:
        assert store.lookup_stun_port(port) in tokens


def test_stun_port_reuse_when_pool_exhausted(store: Store):
    token_a, token_b = new_token(b"k"), new_token(b"k2")
    store.create_session(token_a, 60, "1.2.3.4", "UA", None)
    store.create_session(token_b, 60, "1.2.3.4", "UA", None)
    assert store.assign_stun_port(token_a, [5000], 60) == 5000
    assert store.assign_stun_port(token_b, [5000], 60) == 5000


def test_stage_and_purge(store: Store):
    token = new_token(b"k")
    store.create_session(token, -1, "1.2.3.4", "UA", None)  # already expired
    assert store.set_stage(token, "dns")
    assert store.get_session(token).stage == "dns"
    store.add_observation(token, "http", "1.2.3.4")
    store.purge(keep_seconds=0)
    assert store.get_session(token) is None
    assert store.observations(token) == []
    # An expired session is dropped even when everything is inside the window.
    fresh = new_token(b"k3")
    store.create_session(fresh, -5, "1.2.3.4", "UA", None)
    store.purge(keep_seconds=7 * 86400)
    assert store.get_session(fresh) is None


def test_health_shape(store: Store):
    token = new_token(b"k")
    store.create_session(token, 60, "1.2.3.4", "UA", None)
    health = store.health()
    assert health["sessions"] >= 1
    assert "observations_last_hour" in health
