"""Verdict engine tests: every severity path, and the "no data" trap."""

from __future__ import annotations

from conftest import obs

from leakcheck.verdict import Category, Severity, classify, detect_os, evaluate


def checks_by_key(report):
    return {check.key: check for check in report.checks}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def test_classify_prefers_vpn_over_office(config):
    from leakcheck.netutil import parse_ip

    cls = classify(config.exits, parse_ip("198.51.100.42"))
    assert cls.category is Category.VPN
    assert cls.network == "198.51.100.0/24"


def test_classify_corp_resolver_before_public(config):
    from leakcheck.netutil import parse_ip

    # 198.51.100.21 sits inside both the VPN and resolver prefixes; the channel
    # decides which attribution is useful.
    assert classify(config.exits, parse_ip("198.51.100.21"), "dns").category is Category.CORP_RESOLVER
    assert classify(config.exits, parse_ip("198.51.100.21"), "http").category is Category.VPN
    assert classify(config.exits, parse_ip("1.1.1.1"), "dns").category is Category.THIRD_PARTY
    assert classify(config.exits, parse_ip("203.0.113.5"), "http").category is Category.OFFICE


def test_classify_private_and_loopback(config):
    from leakcheck.netutil import parse_ip

    assert classify(config.exits, parse_ip("10.1.2.3")).category is Category.PRIVATE
    assert classify(config.exits, parse_ip("127.0.0.1")).category is Category.LOOPBACK
    assert classify(config.exits, parse_ip("2001:db8::1")).category is Category.GLOBAL_UNKNOWN
    assert classify(config.exits, parse_ip("224.0.0.1")).category is Category.SPECIAL


def test_operator_listed_public_resolver_is_trusted_first(config):
    """A resolver the operator lists as corporate must not be flagged as public."""
    from leakcheck.config import config_from_dict
    from conftest import RAW_CONFIG

    raw = {**RAW_CONFIG, "exit_inventory": {**RAW_CONFIG["exit_inventory"],
                                            "corp_resolvers": {"addresses": ["1.1.1.1/32"]}}}
    cfg = config_from_dict(raw)
    from leakcheck.netutil import parse_ip

    assert classify(cfg.exits, parse_ip("1.1.1.1")).category is Category.CORP_RESOLVER


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_all_channels_on_vpn_exit_pass(config, session):
    observations = [
        obs("http", "198.51.100.7", path="/px.gif", kind="round1"),
        obs("http", "198.51.100.7", path="/api/v1/observe/http", kind="round2"),
        obs("dns", "198.51.100.21", qtype="A", edns=True, ecs=None),
        obs("dns", "198.51.100.21", qtype="AAAA", edns=True, ecs=None),
        obs("stun", "198.51.100.7", kind="stun-binding", local_port=3478),
        obs("webrtc", "198.51.100.7", kind="webrtc-candidates",
            candidates=[{"type": "srflx", "address": "198.51.100.7", "port": 61000, "protocol": "udp"}]),
    ]
    report = evaluate(config, session, observations)
    by_key = checks_by_key(report)
    assert report.severity is Severity.PASS
    assert by_key["http_egress"].severity is Severity.PASS
    assert by_key["dns_egress"].severity is Severity.PASS
    assert by_key["udp_egress"].severity is Severity.PASS
    assert by_key["egress_consistency"].severity is Severity.PASS


# ---------------------------------------------------------------------------
# Leaks
# ---------------------------------------------------------------------------

def test_http_direct_egress_is_fail(config, session):
    report = evaluate(config, session, [obs("http", "45.33.12.9", kind="round1")])
    check = checks_by_key(report)["http_egress"]
    assert check.severity is Severity.FAIL
    assert "45.33.12.9" in check.summary
    assert report.severity is Severity.FAIL


def test_dns_public_resolver_is_fail(config, session):
    report = evaluate(config, session, [obs("dns", "1.1.1.1", qtype="A", edns=True, ecs=None)])
    check = checks_by_key(report)["dns_egress"]
    assert check.severity is Severity.FAIL
    assert "公共解析器" in check.summary


def test_dns_ecs_is_fail_even_when_resolver_is_corporate(config, session):
    report = evaluate(
        config, session,
        [obs("dns", "198.51.100.21", qtype="A", edns=True, ecs="203.0.113.0/24")],
    )
    check = checks_by_key(report)["dns_egress"]
    assert check.severity is Severity.FAIL
    assert any("ECS" in d for d in check.details)


def test_missing_dns_is_unknown_not_pass(config, session):
    """The critical anti-pattern: no evidence must never read as "safe"."""
    report = evaluate(config, session, [obs("http", "198.51.100.7", kind="round1")])
    check = checks_by_key(report)["dns_egress"]
    assert check.severity is Severity.UNKNOWN
    assert "加密 DNS" in check.summary or "split-horizon" in check.summary


def test_udp_bypass_is_fail(config, session):
    report = evaluate(
        config, session,
        [obs("stun", "45.33.12.9", kind="stun-binding", local_port=3478),
         obs("webrtc", "45.33.12.9", kind="webrtc-candidates", candidates=[])],
    )
    assert checks_by_key(report)["udp_egress"].severity is Severity.FAIL


def test_webrtc_exposed_public_address_fails_udp(config, session):
    report = evaluate(
        config, session,
        [obs("stun", "198.51.100.7", kind="stun-binding", local_port=3478),
         obs("webrtc", "198.51.100.7", kind="webrtc-candidates", candidates=[
             {"type": "srflx", "address": "45.33.12.9", "port": 61000, "protocol": "udp"},
         ])],
    )
    check = checks_by_key(report)["udp_egress"]
    assert check.severity is Severity.FAIL
    assert any("45.33.12.9" in d for d in check.details)


def test_webrtc_private_host_candidate_is_warn(config, session):
    report = evaluate(
        config, session,
        [obs("stun", "198.51.100.7", kind="stun-binding", local_port=3478),
         obs("webrtc", "198.51.100.7", kind="webrtc-candidates", candidates=[
             {"type": "host", "address": "10.8.0.44", "port": 52000, "protocol": "udp"},
         ])],
    )
    assert checks_by_key(report)["webrtc_disclosure"].severity is Severity.WARN


def test_webrtc_mdns_only_is_pass():
    from leakcheck.config import config_from_dict
    from conftest import RAW_CONFIG

    cfg = config_from_dict(RAW_CONFIG)
    report = evaluate(
        cfg, _fake_session(cfg),
        [obs("stun", "198.51.100.7", kind="stun-binding", local_port=3478),
         obs("webrtc", "198.51.100.7", kind="webrtc-candidates", candidates=[
             {"type": "host", "address": "a1b2c3d4-0000.local", "port": 52000, "protocol": "udp"},
         ])],
    )
    check = checks_by_key(report)["webrtc_disclosure"]
    assert check.severity is Severity.PASS


def test_ipv6_global_outside_inventory_is_fail(config, session):
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1"),
         obs("http", "2a00:1450:4001::1", kind="round1", transport="https")],
    )
    check = checks_by_key(report)["ipv6_bypass"]
    assert check.severity is Severity.FAIL
    assert "IPv6" in check.summary


def test_ipv6_inside_vpn_range_passes(config, session):
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1"),
         obs("http", "2001:db8:100::5", kind="round1", transport="https")],
    )
    assert checks_by_key(report)["ipv6_bypass"].severity is Severity.PASS


def test_ipv6_no_observations_and_no_candidates_is_unknown(config, session):
    report = evaluate(config, session, [obs("http", "198.51.100.7", kind="round1")])
    check = checks_by_key(report)["ipv6_bypass"]
    assert check.severity is Severity.UNKNOWN
    assert "没有观测到公网 IPv6" in check.summary


def test_ipv6_link_local_only_is_not_reported_as_tunnel(config, session):
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1"),
         obs("stun", "fe80::1", kind="stun-binding", local_port=3478)],
    )
    check = checks_by_key(report)["ipv6_bypass"]
    assert check.severity is Severity.PASS
    assert "链路本地" in check.summary


def test_ipv6_vpn_prefix_requires_match_before_claiming_tunnel(config, session):
    """An empty IPv6 exit list must not produce "IPv6 goes through the company"."""
    report = evaluate(
        config, session,
        [obs("http", "2001:db8:100::5", kind="round1", transport="https")],
    )
    check = checks_by_key(report)["ipv6_bypass"]
    assert check.severity is Severity.PASS
    assert "2001:db8:100::5" in check.summary


def test_consistency_flags_split_brain(config, session):
    """Some channels through the VPN and some not: a split-tunnel gap."""
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1"),
         obs("dns", "45.33.12.9", qtype="A"),
         obs("stun", "198.51.100.7", kind="stun-binding", local_port=3478)],
    )
    check = checks_by_key(report)["egress_consistency"]
    assert check.severity is Severity.FAIL
    assert "dns" in check.summary
    assert "不一致" in check.summary


def test_consistency_all_channels_same_foreign_exit_is_not_split_brain(config, session):
    """Every channel leaving through one foreign address is "not connected", not
    a misconfigured split tunnel — the fix for the user is completely different."""
    report = evaluate(
        config, session,
        [obs("http", "45.33.12.9", kind="round1"),
         obs("dns", "45.33.12.9", qtype="A"),
         obs("stun", "45.33.12.9", kind="stun-binding", local_port=3478)],
    )
    check = checks_by_key(report)["egress_consistency"]
    assert check.severity is Severity.WARN
    assert "未使用公司 VPN" in check.summary
    assert any("未连接" in d or "没有进入" in d for d in check.details)


def test_consistency_ignores_webrtc_report_channel(config, session):
    """A webrtc row only says what the page was told; it must not be counted as a
    separate egress and make a clean result look inconsistent."""
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1"),
         obs("dns", "198.51.100.21", qtype="A"),
         obs("webrtc", "198.51.100.7", kind="webrtc-candidates",
             candidates=[{"type": "srflx", "address": "198.51.100.7", "port": 1,
                          "protocol": "udp"}])],
    )
    check = checks_by_key(report)["egress_consistency"]
    assert check.severity is Severity.PASS


def test_removed_duplicates_do_not_inflate_evidence(config, session):
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1") for _ in range(5)],
    )
    check = checks_by_key(report)["http_egress"]
    assert len(check.evidence) == 1


def test_dns_observations_with_distinct_names_are_all_counted(config, session):
    """Six real lookups must not collapse into one: the count is evidence."""
    observations = [
        obs("dns", "198.51.100.21", qtype="A", qname=f"tok-abc{i}.probe.test.invalid")
        for i in range(6)
    ]
    report = evaluate(config, session, observations)
    check = checks_by_key(report)["dns_egress"]
    assert "6 次查询" in check.evidence[0].value


# ---------------------------------------------------------------------------
# Remediation wiring
# ---------------------------------------------------------------------------

def test_fail_checks_carry_os_specific_remediation(config, session):
    session.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    report = evaluate(config, session, [obs("dns", "1.1.1.1", qtype="A")])
    check = checks_by_key(report)["dns_egress"]
    assert check.remediation, "失败项必须给出修复步骤"
    titles = " ".join(step.title for step in check.remediation)
    # macOS must receive macOS instructions, not the Windows recipe.
    assert "/etc/resolv.conf" in titles
    assert "Clear-DnsClientCache" not in titles


def test_pass_checks_carry_no_remediation_noise(config, session):
    report = evaluate(
        config, session,
        [obs("http", "198.51.100.7", kind="round1"),
         obs("dns", "198.51.100.21", qtype="A")],
    )
    assert checks_by_key(report)["http_egress"].remediation == []


def test_unknown_os_falls_back_to_generic_steps(config, session):
    session.user_agent = "curl/8.0"
    report = evaluate(config, session, [obs("dns", "1.1.1.1", qtype="A")])
    check = checks_by_key(report)["dns_egress"]
    assert any("加密 DNS" in step.title for step in check.remediation)


def test_detect_os():
    assert detect_os("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") == "windows"
    assert detect_os("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4)") == "macos"
    assert detect_os("Mozilla/5.0 (X11; Linux x86_64)") == "linux"
    assert detect_os("Mozilla/5.0 (Linux; Android 14)") == "android"
    assert detect_os("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)") == "ios"
    assert detect_os("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)") == "chromeos"
    assert detect_os(None) == "unknown"


# ---------------------------------------------------------------------------

def _fake_session(config):
    from leakcheck.storage import Session

    return Session(
        token="x" * 28, created_at=0.0, expires_at=1e18, peer_ip="198.51.100.7",
        user_agent="Mozilla/5.0 (Windows NT 10.0)", client_hint=None, meta={},
    )
