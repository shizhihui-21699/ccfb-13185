"""判定逻辑：覆盖正常、DNS 泄露、IPv6 泄露、WebRTC 泄露与证据不足。"""

from __future__ import annotations

import ipaddress
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import make_config  # noqa: E402

from vpncheck.analysis import (  # noqa: E402
    LEAK,
    OK,
    SKIPPED,
    UNKNOWN,
    WARN,
    build_report,
    check_dns_egress,
    check_webrtc,
)
from vpncheck.store import Observation  # noqa: E402

CORP = "203.0.113.10"
CORP_DNS = "203.0.113.53"
HOME = "49.234.11.66"  # 真实公网地址，用于验证 is_public 分支


def _config(**overrides):
    return make_config(**overrides)


def _obs(kind: str, ip: str, family: int | None = None, transport: str = "udp", **detail) -> Observation:
    return Observation(
        kind=kind,
        ts=time.time(),
        source_ip=ip,
        source_family=family or (6 if ":" in ip else 4),
        transport=transport,
        detail=detail,
    )


def _report(config, observations, reports=(), app_ip=None):
    return build_report(
        config,
        observations=list(observations),
        reports=list(reports),
        app_ip=ipaddress.ip_address(app_ip) if app_ip else None,
    )


# --------------------------------------------------------------------------
# 整体判定
# --------------------------------------------------------------------------
def test_all_inside_is_ok():
    config = _config(
        collector={"public_url_v6": "http://[::1]:9", "public_url_v4": "http://127.0.0.1:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    report = _report(
        config,
        [_obs("http", CORP), _obs("dns", CORP_DNS)],
        reports=[{"payload": {"candidates": [{"type": "srflx", "address": CORP}]}}],
        app_ip=CORP,
    )
    assert report.overall == OK, [f"{f.key}:{f.status}" for f in report.findings]
    assert report.by_key("dns").status == OK
    assert report.by_key("webrtc").status == OK


def test_public_dns_resolver_is_leak():
    config = _config(
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
        collector={"public_url_v4": "http://127.0.0.1:9"},
    )
    report = _report(config, [_obs("dns", "8.8.8.8")])
    finding = report.by_key("dns")
    assert finding.status == LEAK
    assert "8.8.8.8" in " ".join(finding.evidence)
    assert "公共递归解析器" in finding.summary


def test_mixed_dns_is_leak_with_split_hint():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    findings = check_dns_egress(
        config, [_obs("dns", CORP_DNS), _obs("dns", "1.1.1.1")]
    )
    assert findings.status == LEAK
    assert "split_dns" in findings.fix_keys
    assert "分流" in findings.summary


def test_no_dns_observation_is_unknown_not_ok():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    finding = check_dns_egress(config, [])
    assert finding.status == UNKNOWN
    assert "DoH" in " ".join(finding.detail)


def test_private_resolver_is_warn():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    finding = check_dns_egress(config, [_obs("dns", "10.20.30.40")])
    assert finding.status == WARN


def test_ipv6_egress_bypassing_tunnel_is_leak():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9", "public_url_v6": "http://[::1]:9"},
        egress=[
            {"name": "公司出口", "cidr": ["203.0.113.0/24", "2001:db8:1234::/48"], "kind": "corporate"}
        ],
    )
    report = _report(config, [_obs("http", "2408:8207:1234::1")])
    finding = report.by_key("ipv6")
    assert finding.status == LEAK
    assert "IPv6" in finding.title


def test_ipv6_inside_tunnel_ok():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9", "public_url_v6": "http://[::1]:9"},
        egress=[
            {"name": "公司出口", "cidr": ["203.0.113.0/24", "2001:db8:1234::/48"], "kind": "corporate"}
        ],
    )
    finding = _report(config, [_obs("http", "2001:db8:1234::9")]).by_key("ipv6")
    assert finding.status == OK


def test_ipv6_without_v6_probe_is_skipped():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    finding = _report(config, []).by_key("ipv6")
    assert finding.status == SKIPPED


def test_webrtc_public_srflx_is_leak():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    reports = [
        {
            "payload": {
                "candidates": [
                    {"type": "srflx", "address": HOME, "port": 5000},
                    {"type": "host", "address": "192.168.1.9"},
                ]
            }
        }
    ]
    finding = check_webrtc(config, reports, stun_enabled=True)
    assert finding.status == LEAK
    assert HOME in finding.evidence
    assert "webrtc" in finding.fix_keys


def test_webrtc_private_candidate_is_warn():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    reports = [{"payload": {"candidates": [{"type": "host", "address": "192.168.1.9"}]}}]
    finding = check_webrtc(config, reports, stun_enabled=True)
    assert finding.status == WARN


def test_webrtc_mdns_host_candidate_not_flagged():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    reports = [
        {"payload": {"candidates": [{"type": "host", "address": "1a2b3c4d-0000.local"}]}}
    ]
    finding = check_webrtc(config, reports, stun_enabled=True)
    assert finding.status == UNKNOWN
    assert "mDNS" in " ".join(finding.detail)


def test_webrtc_corporate_srflx_ok():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    reports = [{"payload": {"candidates": [{"type": "srflx", "address": CORP}]}}]
    assert check_webrtc(config, reports, stun_enabled=True).status == OK


def test_webrtc_missing_report_is_unknown():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    assert check_webrtc(config, [], stun_enabled=True).status == UNKNOWN


def test_webrtc_error_is_warn():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    reports = [{"payload": {"error": "RTCPeerConnection 初始化失败"}}]
    assert check_webrtc(config, reports, stun_enabled=True).status == WARN


def test_inconsistent_http_egress_flagged():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    report = _report(config, [_obs("http", CORP), _obs("http", HOME)])
    finding = report.by_key("consistency")
    assert finding.status == LEAK
    assert "分流" in finding.summary


def test_app_requires_tunnel_turns_missing_egress_into_leak():
    strict = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        policy={"app_requires_tunnel": True},
    )
    finding = _report(strict, [], app_ip=HOME).by_key("app")
    assert finding.status == LEAK

    relaxed = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    assert _report(relaxed, [], app_ip=HOME).by_key("app").status == WARN


def test_unknown_app_ip_is_unknown():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    assert _report(config, []).by_key("app").status == UNKNOWN


def test_report_orders_worst_first():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    report = _report(config, [_obs("dns", "8.8.8.8")], app_ip=CORP)
    first = report.sorted_findings()[0]
    assert first.status == LEAK


def test_resolver_table_can_cover_corporate_dns():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        egress=[
            {"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"},
            {"name": "公司 DNS 出口", "cidr": ["192.0.2.0/24"], "kind": "dns"},
        ],
    )
    finding = check_dns_egress(config, [_obs("dns", "192.0.2.53")])
    assert finding.status == OK


def test_ipv6_leak_detected_from_webrtc_when_http_missing():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9", "public_url_v6": "http://[::1]:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    reports = [
        {"payload": {"candidates": [{"type": "srflx", "address": "2408:8207:abcd::1"}]}}
    ]
    finding = _report(config, [], reports=reports).by_key("ipv6")
    assert finding.status == LEAK
    assert "WebRTC" in finding.summary


def test_ipv6_ok_when_webrtc_only_shows_tunnel_v6():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9", "public_url_v6": "http://[::1]:9"},
        egress=[
            {"name": "公司出口", "cidr": ["203.0.113.0/24", "2001:db8:1234::/48"], "kind": "corporate"}
        ],
    )
    reports = [
        {"payload": {"candidates": [{"type": "srflx", "address": "2001:db8:1234::5"}]}}
    ]
    finding = _report(config, [], reports=reports).by_key("ipv6")
    assert finding.status == OK


def test_dns_observation_without_source_is_unknown():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    finding = check_dns_egress(config, [_obs("dns", "")])
    assert finding.status == UNKNOWN
    assert "没有记录到来源地址" in finding.summary


def test_dns_missing_but_browser_tried_is_explained():
    config = _config(collector={"public_url_v4": "http://127.0.0.1:9"})
    reports = [{"kind": "timing", "payload": {"dns": 3}}]
    finding = check_dns_egress(config, [], reports)
    assert finding.status == UNKNOWN
    assert "3 次" in finding.detail[0]
    assert any("委派" in line for line in finding.detail)


def test_webrtc_uses_only_latest_report():
    config = _config(
        collector={"public_url_v4": "http://127.0.0.1:9"},
        egress=[{"name": "公司出口", "cidr": ["203.0.113.0/24"], "kind": "corporate"}],
    )
    stale = {"payload": {"candidates": [{"type": "srflx", "address": HOME}]}}
    fresh = {"payload": {"candidates": [{"type": "srflx", "address": CORP}]}}
    finding = check_webrtc(config, [stale, fresh], stun_enabled=True)
    assert finding.status == OK, finding.summary
