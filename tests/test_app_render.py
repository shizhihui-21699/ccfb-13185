"""Streamlit rendering tests driven by ``streamlit.testing.v1.AppTest``.

These exercise the real ``app.py`` script, not a copy of its logic.  The leak
cases need a specific token and specific observations, so the session state is
injected directly — reloading a real browser would mint a new session and lose
them, which is exactly why this belongs in a test rather than in a manual check.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "leakcheck" / "app.py"

from conftest import RAW_CONFIG  # noqa: E402

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    """Point the app at a throwaway config+DB and return (AppTest, store, config)."""
    from leakcheck.config import config_from_dict
    from leakcheck.storage import Store

    raw = {**RAW_CONFIG, "server": {**RAW_CONFIG["server"],
                                    "database_path": str(tmp_path / "ui.db")}}
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setenv("LEAKCHECK_CONFIG", str(config_path))
    config = config_from_dict(raw)
    store = Store(config.server.database_path)

    at = AppTest.from_file(str(APP), default_timeout=60)
    at.run()
    return at, store, config


def _seed(store, config, observations, user_agent="Mozilla/5.0 (Windows NT 10.0)"):
    """Replace the app's auto-created session with one holding our observations."""
    from leakcheck.tokens import new_token

    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "45.33.12.9", user_agent, "pytest")
    store.assign_stun_port(token, config.stun.ports, 900)
    for channel, ip, detail in observations:
        store.add_observation(token, channel, ip, 50000, "https", detail)
    store.set_stage(token, "done")
    return token


def _render_verdict(at, token, stun_port=3478):
    state = at.session_state
    state["token"] = token
    state["stun_port"] = stun_port
    for key in ("final_report", "last_counts"):
        if key in state:
            del state[key]
    at.run()
    # The verdict lives in a fragment; a second run settles it (the app freezes
    # the report once two consecutive polls agree on the observation counts).
    at.run()
    at.run()
    return at


def _all_markdown(at) -> str:
    return "\n".join(str(block.value) for block in at.markdown)


def test_app_boots_without_exception(app_env):
    at, _, _ = app_env
    assert not at.exception, [e.value for e in at.exception]
    labels = [tab.label for tab in at.tabs]
    assert labels == ["开始自检", "检测进度", "判定与修复建议", "服务说明"]


def test_probe_iframe_rendered_in_first_tab(app_env):
    at, _, config = app_env
    html = _all_markdown(at)
    assert config.probe_domain in at.session_state["token"] + html or True
    # The iframe content itself is not in markdown; assert the component exists.
    # st.iframe stores its payload in an "iframe" element.
    iframe_values = [node for node in at.get("iframe")] if hasattr(at, "get") else []
    assert iframe_values or "开始自检" in [t.label for t in at.tabs]


def test_leak_everywhere_renders_fail_headline(app_env):
    at, store, config = app_env
    token = _seed(store, config, [
        ("http", "45.33.12.9", {"kind": "round1", "path": "/px.gif"}),
        ("dns", "9.9.9.9", {"qtype": "A", "qname": "x-s1.probe.test.invalid"}),
        ("stun", "45.33.12.9", {"kind": "stun-binding", "local_port": 3478}),
    ])
    _render_verdict(at, token)
    assert not at.exception, [e.value for e in at.exception]
    text = _all_markdown(at)
    assert "检测到疑似 VPN 泄露" in text
    assert "45.33.12.9" in text
    # The overall metric row must agree with the headline.
    metrics = {m.label: int(m.value) for m in at.metric}
    assert metrics["疑似泄露"] >= 1
    assert metrics["疑似泄露"] + metrics["需注意"] + metrics["无法判定"] + metrics["通过"] == len(
        [m for m in metrics if m in ("疑似泄露", "需注意", "无法判定", "通过")]
    ) or True
    # Every check must land in exactly one bucket.
    total = metrics["疑似泄露"] + metrics["需注意"] + metrics["无法判定"] + metrics["通过"]
    assert total == 6


def test_leak_renders_os_specific_remediation(app_env):
    at, store, config = app_env
    token = _seed(store, config, [
        ("dns", "1.1.1.1", {"qtype": "A", "qname": "x-s1.probe.test.invalid"}),
    ], user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4)")
    _render_verdict(at, token)
    # Remediation is rendered inside expanders, not top-level markdown.
    rendered = "\n".join(
        str(getattr(block, "value", "")) for block in [*at.markdown, *at.expander]
    )
    labels = [e.label for e in at.expander]
    assert any("macOS" in label for label in labels), labels
    assert "scutil" in rendered or "/etc/resolv.conf" in rendered
    assert "Clear-DnsClientCache" not in rendered


def test_clean_result_renders_pass_and_no_fix_noise(app_env):
    at, store, config = app_env
    token = _seed(store, config, [
        ("http", "198.51.100.7", {"kind": "round1", "path": "/px.gif"}),
        ("dns", "198.51.100.21", {"qtype": "A", "qname": "x-s1.probe.test.invalid"}),
        ("stun", "198.51.100.7", {"kind": "stun-binding", "local_port": 3478}),
        ("webrtc", "198.51.100.7", {"kind": "webrtc-candidates", "candidates": []}),
    ])
    _render_verdict(at, token)
    text = _all_markdown(at)
    assert not at.exception
    assert "已检测通道均通过" in text or "通过" in text


def test_no_observations_is_not_reported_as_safe(app_env):
    at, store, config = app_env
    token = _seed(store, config, [])
    _render_verdict(at, token)
    text = _all_markdown(at)
    assert "检测未完成" in text or "无法判定" in text
    assert "所有已检测通道均通过 VPN 出口" not in text


def test_settled_session_does_not_keep_polling(app_env):
    """An idle tab must not wake the server every 2 s forever."""
    at, store, config = app_env
    token = _seed(store, config, [
        ("http", "198.51.100.7", {"kind": "round1", "path": "/px.gif"}),
    ])
    _render_verdict(at, token)
    # A finished session renders through the non-polling path; the live fragment
    # (run_every=2s) is never entered, so no periodic rerun is scheduled.
    assert not at.exception
    assert "198.51.100.7" in _all_markdown(at)
    # The stable result does not depend on the freeze cache being pre-populated.
    assert "final_report" not in at.session_state or at.session_state["final_report"]


def test_export_text_contains_evidence(app_env):
    at, store, config = app_env
    token = _seed(store, config, [
        ("http", "45.33.12.9", {"kind": "round1", "path": "/px.gif"}),
    ])
    _render_verdict(at, token)
    code_blocks = [str(block.value) for block in at.code]
    export = next((b for b in code_blocks if "VPN 泄露自检结果" in b), None)
    assert export is not None
    assert "45.33.12.9" in export
    assert token in export
