"""Streamlit interface: the page employees open after connecting to the VPN.

Flow
----
1. On load we mint a session (server-side) and render three things in one
   scroll: the embedded browser probe, the live status, and the verdict.  The
   probe posts to the collector's API directly, so observations accumulate in
   SQLite while Streamlit re-renders.
2. While the probe runs, the progress and verdict render inside
   ``st.fragment(run_every=2.0)`` so they update without a page reload.  Once the
   browser reports ``stage=done`` the fragments are left for non-polling
   variants — an idle tab must not wake the server every two seconds forever.
3. Operator diagnostics (listener health, effective inventory) are shown only
   with ``?admin=<LEAKCHECK_ADMIN_TOKEN>``, because that view belongs to IT.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import streamlit as st

# ``streamlit run leakcheck/app.py`` executes this file as a top-level script, so
# relative imports would fail and the project root is not necessarily on
# sys.path.  Bootstrapping it here keeps both invocation styles working.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from leakcheck.config import AppConfig, ConfigError, load_config  # noqa: E402
from leakcheck.frontend import build_probe_html  # noqa: E402
from leakcheck.remediation import os_label, steps_to_html  # noqa: E402
from leakcheck.storage import Store  # noqa: E402
from leakcheck.tokens import new_token  # noqa: E402
from leakcheck.verdict import Check, Report, Severity, evaluate  # noqa: E402

STAGE_SEQUENCE = ["http", "dns", "webrtc", "done"]
STAGE_LABEL = {
    "boot": "准备中",
    "http": "正在检测网页出口",
    "dns": "正在检测 DNS 解析出口",
    "webrtc": "正在检测实时通信与 UDP",
    "done": "采集完成",
    "error": "探针执行出错",
    "running": "等待浏览器上报",
}
SEVERITY_ICON = {
    Severity.PASS: "🟢",
    Severity.INFO: "🔵",
    Severity.UNKNOWN: "⚪",
    Severity.WARN: "🟠",
    Severity.FAIL: "🔴",
}

CSS = """
<style>
  .lc-hero { padding: 18px 20px; border-radius: 12px; border: 1px solid var(--lc-line);
             background: var(--lc-card); margin-bottom: 14px; }
  .lc-hero h1 { font-size: 1.35rem; margin: 0 0 6px; }
  .lc-hero p { margin: 0; opacity: .78; font-size: .92rem; }
  .lc-chip { display: inline-block; font-size: .76rem; padding: 2px 9px; border-radius: 999px;
             border: 1px solid var(--lc-line); margin-right: 6px; opacity: .9; }
  .lc-card { border: 1px solid var(--lc-line); border-radius: 10px; padding: 12px 14px;
             margin: 8px 0; background: var(--lc-card); }
  .lc-card h3 { margin: 0 0 4px; font-size: 1rem; }
  .lc-card p { margin: 4px 0; font-size: .9rem; }
  .lc-evidence { width: 100%; border-collapse: collapse; font-size: .82rem; margin-top: 6px; }
  .lc-evidence th, .lc-evidence td { text-align: left; padding: 4px 6px;
             border-bottom: 1px solid var(--lc-line); vertical-align: top; }
  .lc-evidence th { opacity: .6; font-weight: 600; }
  .lc-steps { padding-left: 1.2rem; font-size: .9rem; }
  .lc-steps li { margin-bottom: .85rem; }
  .lc-steps p { margin: .3rem 0; }
  .lc-cmd { background: var(--lc-code); padding: 8px 10px; border-radius: 6px; overflow-x: auto;
            font-size: .78rem; margin: .35rem 0; }
  .lc-verify { opacity: .8; }
  .lc-mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .lc-big { font-size: 1.6rem; font-weight: 700; }
</style>
"""


def _theme_style() -> str:
    """Theme-neutral design tokens, so the page works in light and dark mode.

    Streamlit does not expose the active theme's palette to scripts, so every
    colour here is expressed as a translucent overlay on whatever background the
    viewer has.
    """
    return (
        "<style>:root { --lc-line: rgba(127,127,127,.28);"
        " --lc-card: rgba(127,127,127,.06); --lc-code: rgba(127,127,127,.14); }</style>"
    )


@dataclass(slots=True)
class AppState:
    config: AppConfig
    store: Store


@st.cache_resource(show_spinner=False)
def _boot(config_path: str) -> AppState:
    """Load config and open the store once per process.

    The cache key is the config path: with a single argument-less cache, an
    in-process caller that switches ``LEAKCHECK_CONFIG`` (a test harness, or an
    operator restarting with a different file) would silently keep serving the
    first database and exit inventory it ever saw.
    """
    config = load_config(config_path)
    store = Store(config.server.database_path)
    return AppState(config=config, store=store)


def _ensure_session(state: AppState) -> tuple[str, int | None]:
    """One session per browser tab, kept in Streamlit session state."""
    if "token" not in st.session_state:
        token = new_token(state.config.server.hmac_secret)
        peer = st.context.headers.get("X-Forwarded-For") or st.context.ip_address
        ua = st.context.headers.get("User-Agent", "")
        port = None
        try:
            session = state.store.create_session(
                token,
                state.config.server.session_ttl_seconds,
                str(peer or "").strip() or None,
                ua,
                "streamlit",
            )
            port = state.store.assign_stun_port(
                token, state.config.stun.ports, state.config.server.session_ttl_seconds
            )
            session.stun_port = port
        except Exception:  # noqa: BLE001 - the page must still render
            st.session_state["store_error"] = True
        st.session_state["token"] = token
        st.session_state["stun_port"] = port
        st.session_state["started_at"] = time.time()
    return st.session_state["token"], st.session_state.get("stun_port")


def _interesting_ports(state: AppState) -> list[int]:
    return state.config.stun.ports or []


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _severity_pill(severity: Severity) -> str:
    color = {
        Severity.PASS: "var(--lc-ok, #1a7f37)",
        Severity.INFO: "#0a5cc7",
        Severity.UNKNOWN: "#7d8590",
        Severity.WARN: "#9a6700",
        Severity.FAIL: "#cf222e",
    }[severity]
    return (
        f'<span class="lc-chip" style="border-color:{color};color:{color}">'
        f"{SEVERITY_ICON[severity]} {severity.label}</span>"
    )


def _evidence_table(check: Check) -> str:
    if not check.evidence:
        return ""
    rows = "".join(
        f"<tr><td>{_esc(ev.label)}</td><td class='lc-mono'>{_esc(ev.value)}</td>"
        f"<td>{_esc(ev.extra)}</td></tr>"
        for ev in check.evidence
    )
    return (
        "<table class='lc-evidence'><thead><tr><th>通道/来源</th><th>观测值</th>"
        f"<th>说明</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _esc(text: Any) -> str:
    import html

    return html.escape(str(text or ""))


def _render_check(check: Check, os_family: str) -> None:
    body = [
        f"<div class='lc-card'><h3>{SEVERITY_ICON[check.severity]} {_esc(check.title)}"
        f" {_severity_pill(check.severity)}</h3>",
        f"<p>{_esc(check.summary)}</p>",
        _evidence_table(check),
    ]
    if check.details:
        body.append(
            "<ul style='font-size:.86rem;margin:.5rem 0 0;padding-left:1.1rem'>"
            + "".join(f"<li>{_esc(d)}</li>" for d in check.details)
            + "</ul>"
        )
    body.append("</div>")
    st.markdown("".join(body), unsafe_allow_html=True)
    if check.remediation and check.severity.rank >= Severity.WARN.rank:
        with st.expander(f"修复建议（{os_label(os_family)}）", expanded=check.severity is Severity.FAIL):
            st.markdown(steps_to_html(check.remediation), unsafe_allow_html=True)


def _render_report(report: Report) -> None:
    severity = report.severity
    hero_tone = {
        Severity.PASS: "#1a7f37",
        Severity.INFO: "#0a5cc7",
        Severity.UNKNOWN: "#7d8590",
        Severity.WARN: "#9a6700",
        Severity.FAIL: "#cf222e",
    }[severity]
    st.markdown(
        f"<div class='lc-hero' style='border-left:5px solid {hero_tone}'>"
        f"<h1>{SEVERITY_ICON[severity]} {_esc(report.headline())}</h1>"
        f"<p>{_esc(_summary_line(report))}</p></div>",
        unsafe_allow_html=True,
    )

    cols = st.columns(4)
    counts = {
        "疑似泄露": len(report.failed),
        "需注意": len(report.warnings),
        "无法判定": len(report.unknown),
        "通过": len([c for c in report.checks if c.severity is Severity.PASS]),
    }
    for col, (label, value) in zip(cols, counts.items()):
        col.metric(label, value)

    st.caption(
        f"检测时间 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}"
        f" · 浏览器 {os_label(report.os_family)} · 会话 {report.session.token[:10]}…"
        f"（令牌仅用于关联本次观测，不含身份信息）"
    )

    for check in report.checks:
        _render_check(check, report.os_family)

    with st.expander("导出结果（发给 IT）"):
        st.code(_export_text(report), language="text")
    st.download_button(
        "下载结果文本",
        data=_export_text(report).encode("utf-8"),
        file_name=f"vpn-leak-check-{report.session.token[:8]}.txt",
        mime="text/plain",
        help="文本中只包含本次的出口地址与判定，不含姓名、账号或内网 URL。",
    )


def _summary_line(report: Report) -> str:
    measured = [c for c in report.checks if c.measured]
    parts = [f"完成 {len(measured)}/{len(report.checks)} 项可观测检查"]
    if report.client_class:
        parts.append(f"页面请求来源被归类为「{report.client_class.label}」")
    if not report.observations:
        parts.append("尚未收到任何浏览器上报")
    return "；".join(parts)


def _export_text(report: Report) -> str:
    lines = [
        f"VPN 泄露自检结果  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}",
        f"总体判定：{report.severity.label} — {report.headline()}",
        f"浏览器：{os_label(report.os_family)}（{report.session.user_agent or '未知'}）",
        f"会话令牌：{report.session.token}",
        "",
    ]
    for check in report.checks:
        lines.append(f"[{check.severity.label}] {check.title}")
        lines.append(f"  结论：{check.summary}")
        for ev in check.evidence:
            lines.append(f"  - {ev.label}: {ev.value} {ev.extra}".rstrip())
        for detail in check.details:
            lines.append(f"  · {detail}")
        lines.append("")
    lines.append("— 本结果由公司 VPN 泄露自检服务生成，仅包含出口地址观测值。")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def _render_probe_panel(state: AppState, token: str, stun_port: int | None) -> None:
    if stun_port is None and state.config.stun.enabled:
        port = state.store.assign_stun_port(
            token, state.config.stun.ports, state.config.server.session_ttl_seconds
        )
        st.session_state["stun_port"] = port
        stun_port = port
    html = build_probe_html(
        state.config,
        token,
        stun_port or (state.config.stun.ports[0] if state.config.stun.ports else 3478),
    )
    st.iframe(html, height=132)


def _live_state(state: AppState, token: str) -> tuple[str, dict[str, int], float]:
    session = state.store.get_session(token)
    counts = state.store.counts(token)
    stage = (session.stage if session else None) or "running"
    remaining = session.expires_in if session else 0.0
    return stage, counts, remaining


def main() -> None:
    st.set_page_config(
        page_title="VPN 流量泄露自检",
        page_icon="🛰️",
        layout="centered",
        initial_sidebar_state="collapsed",
    )
    st.markdown(CSS + _theme_style(), unsafe_allow_html=True)

    try:
        state = _boot(os.environ.get("LEAKCHECK_CONFIG", "config.yaml"))
    except ConfigError as exc:
        st.error(f"服务配置不可用：{exc}")
        st.stop()

    token, stun_port = _ensure_session(state)

    st.markdown(
        f"<div class='lc-hero'><h1>🛰️ {_esc(state.config.site_title)}</h1>"
        "<p>请先连上公司 VPN，再打开本页。页面会自动从四个通道检查流量是否真的走了隧道："
        "网页请求出口、DNS 解析出口、实时通信（WebRTC/UDP）出口、IPv6 路径。"
        "整个过程约 10 秒，无需安装任何软件。</p></div>",
        unsafe_allow_html=True,
    )

    tabs = st.tabs(["开始自检", "检测进度", "判定与修复建议", "服务说明"])
    with tabs[0]:
        st.markdown("#### 第 1 步：浏览器自动探测")
        _render_probe_panel(state, token, stun_port)
        st.caption(
            "探针只做三件事：请求一张 1×1 像素图、解析几个随机子域名、收集一次 WebRTC 候选。"
            "它不读取文件、不发起连接你的内网服务。"
        )
        if st.button("重新开始一次检测", type="primary"):
            for key in ("token", "stun_port", "started_at", "final_report",
                        "last_counts"):
                st.session_state.pop(key, None)
            st.rerun()

    with tabs[1]:
        _render_progress(state, token)

    with tabs[2]:
        session = state.store.get_session(token)
        if _settled(state, token, session):
            _render_verdict_settled(state, token)
        else:
            _render_verdict_live(state, token, stun_port)

    with tabs[3]:
        _render_about(state)


def _settled(state: AppState, token: str, session=None) -> bool:
    """True once no further observation can arrive for this session."""
    session = session or state.store.get_session(token)
    return session is not None and session.stage in ("done", "error")


def _render_progress(state: AppState, token: str) -> None:
    if _settled(state, token):
        _render_progress_body(state, token)
    else:
        _render_progress_live(state, token)


@st.fragment(run_every=2.0)
def _render_progress_live(state: AppState, token: str) -> None:
    if _settled(state, token):
        # A fragment's run_every cannot be changed at runtime, so the way to stop
        # polling is to leave the fragment: a full rerun re-executes the script,
        # which then renders the non-polling variant. Without this the employee's
        # idle tab would keep waking the server every two seconds forever.
        st.rerun()
    _render_progress_body(state, token)


def _render_progress_body(state: AppState, token: str) -> None:
    stage, counts, remaining = _live_state(state, token)
    st.markdown(f"#### 当前阶段：{STAGE_LABEL.get(stage, stage)}")
    st.progress(
        min(1.0, (STAGE_SEQUENCE.index(stage) + 1) / len(STAGE_SEQUENCE))
        if stage in STAGE_SEQUENCE else 0.15
    )
    cols = st.columns(4)
    for col, (label, n) in zip(
        cols,
        [
            ("网页请求", counts.get("http", 0)),
            ("DNS 查询", counts.get("dns", 0)),
            ("UDP/STUN", counts.get("stun", 0)),
            ("WebRTC 上报", counts.get("webrtc", 0)),
        ],
    ):
        col.metric(label, n)
    st.caption(f"会话剩余有效时间 {int(max(0, remaining))} 秒。数值会自动刷新，无需手动重载。")
    if stage == "done":
        st.success("采集完成，请切换到「判定与修复建议」查看结果。")
    elif stage == "error":
        st.warning("探针执行过程中出错，请查看下方说明或手动复测。")
    with st.expander("没有数据？"):
        st.markdown(
            "- **网页请求为 0**：浏览器可能没加载到探针（被拦截器或 CSP 挡住）。换用独立标签页打开本页。\n"
            "- **DNS 查询为 0**：浏览器可能启用了加密 DNS（DoH），或内网 DNS 对探针域名做了本地应答。"
            "这本身不一定是泄露，但会让我们无法判定。\n"
            "- **UDP/STUN 为 0**：浏览器策略禁用了 WebRTC，或防火墙挡住了检测服务的 UDP 端口。\n"
            "- 如果页面显示多项为 0，请把本页地址发给 IT，并附上你使用的浏览器与 VPN 客户端版本。"
        )


@st.fragment()
def _render_verdict_settled(state: AppState, token: str) -> None:
    """Frozen result: no polling, no recomputation, stable while being read."""
    final = st.session_state.get("final_report")
    if final is not None and final.get("token") == token:
        _render_report(final["report"])
        return
    session = state.store.get_session(token)
    if session is None:
        st.warning("会话已过期，请回到「开始自检」重新开始。")
        return
    _render_report(evaluate(state.config, session, state.store.observations(token)))


@st.fragment(run_every=2.0)
def _render_verdict_live(state: AppState, token: str, stun_port: int | None) -> None:
    # While the probe is still running the numbers move; once it reports done and
    # two consecutive polls agree, the report is frozen and the polling fragment
    # is left (see the note in _render_progress_live).
    final = st.session_state.get("final_report")
    if final is not None and final.get("token") == token:
        _render_report(final["report"])
        return

    session = state.store.get_session(token)
    if session is None:
        st.warning("会话已过期，请回到「开始自检」重新开始。")
        return
    observations = state.store.observations(token)
    report = evaluate(state.config, session, observations)
    counts = state.store.counts(token)

    settled = session.stage in ("done", "error")
    previous = st.session_state.get("last_counts")
    if settled and observations:
        if previous == counts:
            st.session_state["final_report"] = {"token": token, "report": report}
            st.session_state["last_counts"] = counts
            st.rerun()  # switch to the non-polling variant
    st.session_state["last_counts"] = counts

    if not observations:
        st.info("正在等待浏览器探针上报，通常 2–10 秒内完成。")
    _render_report(report)


def _render_about(state: AppState) -> None:
    config = state.config
    st.markdown("#### 这个页面在看什么")
    st.markdown(
        f"""
| 通道 | 怎么观测 | 能发现什么 |
| --- | --- | --- |
| 网页请求 | 浏览器向 `{config.server.public_base_url}` 请求像素图与上报接口，服务端记录 TCP 对端地址 | TCP/HTTPS 是否走了隧道 |
| DNS 解析 | 浏览器解析随机子域 `*.{config.probe_domain}`，该域的权威服务器由本服务运营，记录**递归解析器**的出口地址 | DNS 是否走公司解析器、是否带 ECS 泄露客户端网段 |
| 实时通信 | 浏览器用 WebRTC 向本服务的 STUN 端口发 UDP，服务端记录 UDP 对端地址；同时页面报告它看到的候选地址 | UDP 是否绕过隧道、页面是否被暴露真实地址 |
| IPv6 | 在上面的观测里单独筛出 IPv6 地址，并结合浏览器报告的 IPv6 候选 | IPv6 是否走了隧道之外的路径 |

**为什么需要权威 DNS 探针**：网页自身无法知道"是谁替我解析的域名"。只有当解析请求真正到达由我们运营的权威服务器，
服务端才能看到递归解析器的出口地址——这正是判断 DNS 是否绕过隧道所需的证据。

**判定依据**：所有观测地址都会与公司下发的出口地址清单（VPN 出口、解析器出口、办公网出口）比对。
不在清单内且为公网地址 → 疑似泄露；属于内网/回环 → 正常；没有任何数据 → 记为"无法判定"而不是"通过"。

**隐私**：本服务不记录姓名、账号或内网 URL；会话令牌是签名随机值，观测数据默认保留 7 天后删除。
"""
    )
    st.markdown("#### 浏览器兼容性")
    st.markdown(
        "Chrome / Edge / Firefox / Safari 均可。WebRTC 检测需要 **HTTPS 安全上下文**，"
        "若通过 `http://` 访问，该通道会显示为「无法判定」。"
    )
    if config.remediation.support_url or config.remediation.support_contact:
        st.markdown(
            f"#### 需要帮助\n遇到反复判定为泄露，请联系 **{config.remediation.support_contact}**"
            + (f"，或访问 {config.remediation.support_url}" if config.remediation.support_url else "")
            + "，并附上「导出结果」的文本。"
        )
    with st.expander("运维：服务自检信息"):
        st.markdown(
            f"- 采集端：`{config.server.public_base_url}`\n"
            f"- 探针域：`{config.probe_domain}`\n"
            f"- 出口清单：VPN {len(config.exits.vpn_egress.networks)} 段 / "
            f"解析器 {len(config.exits.corp_resolvers.networks)} 段 / "
            f"办公网 {len(config.exits.office_egress.networks)} 段\n"
            f"- STUN 端口：{config.stun.ports}\n"
        )
        if _diagnostics_allowed():
            st.code(
                json.dumps(state.store.health(), ensure_ascii=False, indent=2),
                language="json",
            )
        else:
            st.caption("设置环境变量 LEAKCHECK_ADMIN_TOKEN 并访问 ?admin=<token> 可查看运行状态。")


def _diagnostics_allowed() -> bool:
    expected = os.environ.get("LEAKCHECK_ADMIN_TOKEN")
    if not expected:
        return False
    supplied = st.query_params.get("admin", "")
    if not supplied:
        return False
    return hashlib.sha256(supplied.encode()).hexdigest() == hashlib.sha256(expected.encode()).hexdigest()


main()
