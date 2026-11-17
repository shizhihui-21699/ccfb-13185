"""存储层、修复建议与页面脚本渲染。"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vpncheck.analysis import LEAK, OK, Finding  # noqa: E402
from vpncheck.guidance import (  # noqa: E402
    ANDROID,
    IOS,
    LINUX,
    MACOS,
    WINDOWS,
    detect_platform,
    fix_markdown,
    fixes_for,
    render_steps,
)
from vpncheck.probe_page import ProbePlan, render  # noqa: E402
from vpncheck.store import Store, valid_session_id  # noqa: E402


# --------------------------------------------------------------------------
# 存储
# --------------------------------------------------------------------------
def test_session_lifecycle():
    store = Store(":memory:", ttl_seconds=60)
    session = store.create_session(user_agent="UA/1.0", app_ip="203.0.113.2", app_ip_family=4)
    assert valid_session_id(session.id)
    assert store.session_alive(session.id)
    assert store.get_session(session.id).app_ip == "203.0.113.2"


def test_expired_session_rejected_and_cleaned():
    store = Store(":memory:", ttl_seconds=1)
    session = store.create_session(now=time.time() - 100)
    assert not store.session_alive(session.id)
    assert store.add_observation(session.id, "http", source_ip="1.2.3.4") is False
    assert store.cleanup() == 1
    assert store.get_session(session.id) is None


def test_invalid_session_id_rejected():
    store = Store(":memory:")
    with pytest.raises(ValueError):
        store.create_session("not-hex")
    assert store.get_session("nope") is None
    assert store.add_observation("../etc/passwd", "http") is False


def test_observations_and_reports_roundtrip():
    store = Store(":memory:")
    session = store.create_session()
    store.add_observation(
        session.id, "dns", source_ip="203.0.113.5", source_family=4, detail={"seq": 2}
    )
    store.add_browser_report(session.id, "webrtc", {"candidates": [{"type": "srflx"}]})
    obs = store.observations(session.id, "dns")
    assert len(obs) == 1 and obs[0].detail["seq"] == 2
    reports = store.browser_reports(session.id)
    assert len(reports) == 1 and reports[0]["payload"]["candidates"][0]["type"] == "srflx"


def test_purge_removes_everything():
    store = Store(":memory:")
    session = store.create_session()
    store.add_observation(session.id, "http", source_ip="1.2.3.4")
    store.purge_session(session.id)
    assert store.get_session(session.id) is None
    assert store.observations(session.id) == []


def test_touch_extends_expiry():
    store = Store(":memory:", ttl_seconds=60)
    session = store.create_session(now=time.time() - 50)
    store.touch(session.id)
    assert store.get_session(session.id).expires_at > session.expires_at


def test_sessions_for_address(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    a = store.create_session(app_ip="203.0.113.9", app_ip_family=4)
    b = store.create_session(app_ip="203.0.113.10", app_ip_family=4)
    store.add_observation(b.id, "http", source_ip="203.0.113.10")
    assert store.sessions_for_address("203.0.113.9") == [a.id]
    assert store.sessions_for_address("203.0.113.10") == [b.id]
    assert store.sessions_for_address("203.0.113.99") == []


# --------------------------------------------------------------------------
# 修复建议
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("ua", "expected"),
    [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", WINDOWS),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1)", MACOS),
        ("Mozilla/5.0 (X11; Linux x86_64)", LINUX),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", IOS),
        ("Mozilla/5.0 (Linux; Android 14; Pixel 8)", ANDROID),
    ],
)
def test_detect_platform(ua, expected):
    assert detect_platform(ua) == (expected,)


def test_detect_platform_empty_lists_all_desktops():
    assert set(detect_platform("")) == {WINDOWS, MACOS, LINUX}


def test_fixes_collected_by_severity():
    findings = [
        Finding("dns", "DNS", LEAK, "x", fix_keys=("dns", "doh")),
        Finding("app", "页面", OK, "ok", fix_keys=("tunnel",)),
    ]
    keys = [item.key for item in fixes_for(findings)]
    assert keys == ["dns", "doh"]


def test_render_steps_prefers_platform():
    finding = Finding("ipv6", "IPv6", LEAK, "x", fix_keys=("ipv6",))
    items = fixes_for([finding])
    macos_steps = render_steps(items[0], (MACOS,))
    assert all(line.startswith("macOS") for line in macos_steps)


def test_markdown_report_contains_evidence_and_contact():
    finding = Finding(
        "dns", "DNS 解析出口", LEAK, "解析绕过隧道", evidence=["8.8.8.8"], fix_keys=("dns", "doh")
    )
    text = fix_markdown([finding], "Mozilla/5.0 (Windows NT 10.0)", helpdesk="IT 服务台")
    assert "DNS 解析出口（泄露）" in text
    assert "`8.8.8.8`" in text
    assert "Windows" in text
    assert "IT 服务台" in text


def test_markdown_report_when_clean():
    text = fix_markdown([Finding("dns", "DNS", OK, "fine")], "")
    assert "没有发现需要处理的项目" in text


# --------------------------------------------------------------------------
# 浏览器脚本
# --------------------------------------------------------------------------
def _plan(**overrides) -> ProbePlan:
    values = {
        "session_id": "a" * 32,
        "ipv4_base": "https://probe.example.com",
        "ipv6_base": "https://probe6.example.com",
        "dns_zone": "probe.example.com",
        "dns_rounds": 3,
        "dns_wait": 8.0,
        "stun_uris": ("stun:stun.example.com:35000",),
        "report_url": "https://probe.example.com/probe/report",
        "ipv4_probe_url": "https://probe.example.com/probe/ip",
        "ipv6_probe_url": "https://probe6.example.com/probe/ip",
        "script_url": "https://probe.example.com/probe/client.js",
    }
    values.update(overrides)
    return ProbePlan(**values)


def test_probe_plan_serialized_into_page():
    plan = _plan()
    page = render(plan)
    assert "vpncheck-cfg" in page
    assert plan.session_id in page
    start = page.index('data-cfg="') + len('data-cfg="')
    end = page.index('"', start)
    raw = page[start:end].replace("&quot;", '"')
    cfg = json.loads(raw)
    assert cfg["sid"] == plan.session_id
    assert cfg["dnsZone"] == "probe.example.com"
    assert cfg["stunUris"] == ["stun:stun.example.com:35000"]
    assert cfg["ipv6Probe"] == "https://probe6.example.com/probe/ip"
    # 探测脚本以外部文件形式加载，避免 st.html 净化截断内联脚本
    assert 'data-script="https://probe.example.com/probe/client.js"' in page
    assert "function ()" not in page  # 页面里不再内联大段 JS


def test_probe_plan_escapes_html_injection():
    plan = _plan(dns_zone='</script><img src=x onerror="alert(1)">')
    page = render(plan)
    assert "<img src=x" not in page
    assert "</script><img" not in page


def test_probe_bootstrap_avoids_angle_bracket_sequences():
    page = render(_plan())
    bootstrap = page[page.rindex("<script>") + len("<script>") : page.rindex("</script>")]
    import re

    assert not re.search(r"<[A-Za-z/!]", bootstrap), bootstrap


def test_client_script_has_no_closing_script_tag():
    from vpncheck.client_js import client_js

    assert "</script" not in client_js().lower()


def test_probe_plan_without_optional_transports():
    plan = _plan(
        ipv6_base=None, ipv6_probe_url=None, dns_zone=None, stun_uris=()
    )
    page = render(plan)
    assert "null" in page
    cfg_start = page.index('data-cfg="') + len('data-cfg="')
    cfg_end = page.index('"', cfg_start)
    cfg = json.loads(page[cfg_start:cfg_end].replace("&quot;", '"'))
    assert cfg["ipv6Probe"] is None and cfg["dnsZone"] is None


# --------------------------------------------------------------------------
# STUN 端口池
# --------------------------------------------------------------------------
def test_stun_port_claim_is_stable_and_unique():
    store = Store(":memory:")
    a = store.create_session()
    b = store.create_session()
    pa = store.claim_stun_port(a.id, 40000, 4)
    pb = store.claim_stun_port(b.id, 40000, 4)
    assert pa == 40000 and pb == 40001
    assert store.claim_stun_port(a.id, 40000, 4) == pa  # 重复认领返回同一个
    assert store.session_for_stun_port(pa) == a.id
    assert store.stun_port_of(b.id) == pb


def test_stun_port_pool_exhaustion():
    store = Store(":memory:")
    ids = [store.create_session().id for _ in range(3)]
    ports = {store.claim_stun_port(sid, 41000, 2) for sid in ids}
    assert ports == {41000, 41001, None}


def test_release_and_expire_stun_ports():
    store = Store(":memory:", ttl_seconds=1)
    sid = store.create_session(now=time.time() - 10).id
    assert store.claim_stun_port(sid, 42000, 2) == 42000
    assert store.expire_stun_ports() == 1
    assert store.session_for_stun_port(42000) is None

    live = store.create_session()
    store.claim_stun_port(live.id, 42000, 2)
    store.release_stun_port(live.id)
    assert store.stun_port_of(live.id) is None
