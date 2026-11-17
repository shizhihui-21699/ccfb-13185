"""Streamlit 自检页面。

默认在同一进程内启动三个探针（HTTP 采集端、DNS 探针、STUN）；把
``probes.mode`` 设为 ``external`` 时改由 ``scripts/run_probes.py`` 常驻，
页面只读共享 SQLite。启动方式见 README：``streamlit run app.py``。

页面流程
--------
1. 为本次浏览器会话创建会话标识（只存在服务端数据库，不写 Cookie）。
2. 注入探测器：唯一子域解析、IPv4/IPv6 出口探测、WebRTC 候选收集。
3. 轮询本会话的观测结果，逐项判定并给出修复建议。
"""

from __future__ import annotations

import ipaddress
import logging
import os
import sys
import threading
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vpncheck.analysis import (  # noqa: E402
    LEAK,
    OK,
    SKIPPED,
    UNKNOWN,
    WARN,
    Report,
    build_report,
)
from vpncheck.clientip import resolve_client_ip  # noqa: E402
from vpncheck.collector import CollectorService  # noqa: E402
from vpncheck.config import Config, ConfigError, load_config  # noqa: E402
from vpncheck.dns_probe import DnsProbeService  # noqa: E402
from vpncheck.guidance import (  # noqa: E402
    browser_hint,
    detect_platform,
    fix_markdown,
    fixes_for,
)
from vpncheck.probe_page import ProbePlan  # noqa: E402
from vpncheck.probe_page import render as render_probe
from vpncheck.store import Store  # noqa: E402
from vpncheck.stun import StunService  # noqa: E402

LOGGER = logging.getLogger("vpncheck.app")
logging.basicConfig(
    level=os.environ.get("VPNCHECK_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

IPV4_PROBE_PATH = "/probe/ip"
DNS_ROUNDS = 3


class Services:
    """进程内单例：配置、存储与三个探针服务。

    ``probes.mode = "external"`` 时不启动任何监听器，只共享 SQLite，页面读取
    由 ``scripts/run_probes.py`` 写入的观测。这样 53/3478 端口的规划、扩缩容
    和 Streamlit 重启互不影响。
    """

    def __init__(self, config: Config):
        self.config = config
        self.store = Store(_db_path(config), ttl_seconds=config.app.session_ttl_seconds)
        self.collector = CollectorService(config.collector, config.app, self.store)
        self.dns = DnsProbeService(config.dns, self.store)
        self.stun = StunService(config.stun, self.store)
        self._started = False
        self._lock = threading.Lock()
        # 启动失败的服务名 -> 原因。页面据此显示「服务端未就绪」，而不是崩溃。
        self.failures: dict[str, str] = {}

    @property
    def embedded(self) -> bool:
        return self.config.probes.embedded

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            if not self.config.probes.embedded:
                LOGGER.info("probes.mode=external，页面不启动探针，使用 %s", self.store.path)
                self._started = True
                return
            for name, service in (
                ("采集端", self.collector),
                ("DNS 探针", self.dns),
                ("STUN 探针", self.stun),
            ):
                try:
                    service.start()
                except Exception as exc:  # noqa: BLE001
                    # 单个探针起不来（端口被占、无权限绑 53 等）只降级对应检测项，
                    # 不能因此让整个自检页打不开。
                    self.failures[name] = f"{type(exc).__name__}: {exc}"
                    LOGGER.error("启动%s失败：%s", name, exc, exc_info=True)
            self._started = True
            if self.failures:
                LOGGER.warning("以下探针未能启动：%s", "，".join(self.failures))
            else:
                LOGGER.info("探针服务已启动")


def _db_path(config: Config) -> str:
    raw = os.environ.get("VPNCHECK_DB")
    if raw:
        return str(Path(raw).expanduser().resolve())
    return str(Path(config.source_path).parent / "data" / "vpncheck.sqlite3")


@st.cache_resource(show_spinner=False)
def get_services() -> Services:
    config = load_config(os.environ.get("VPNCHECK_CONFIG") or None)
    services = Services(config)
    services.start()
    return services


def _app_client_ip(config: Config) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Streamlit 自身看到的访问地址，仅用于交叉核对。

    本地部署（127.0.0.1）或前置代理剥离地址时这里会是 ``None``；此时判定会
    回退到采集端观测到的 HTTP 出口，见 :func:`_effective_app_ip`。
    """
    peer = getattr(st.context, "ip_address", None)
    return resolve_client_ip(
        peer,
        _request_headers(),
        trust_forwarded_for=config.collector.trust_forwarded_for,
        trusted_proxies=config.collector.trusted_proxies,
    )


def _effective_app_ip(services: Services, sid: str):
    """页面出口地址：优先 Streamlit 连接地址，否则用采集端看到的 HTTP 出口。"""
    direct = _app_client_ip(services.config)
    if direct is not None:
        return direct
    for obs in services.store.observations(sid, "http"):
        ip = ipaddress.ip_address(obs.source_ip) if obs.source_ip else None
        if ip is not None:
            return ip
    return None


def _request_headers() -> dict[str, str]:
    try:
        return dict(st.context.headers)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        return {}


def _user_agent() -> str:
    headers = _request_headers()
    for key, value in headers.items():
        if key.lower() == "user-agent":
            return value
    return ""


def _session_id(services: Services) -> str:
    sid = st.session_state.get("vpncheck_sid")
    if isinstance(sid, str) and services.store.session_alive(sid):
        services.store.touch(sid)
        return sid
    app_ip = _app_client_ip(services.config)
    session = services.store.create_session(
        user_agent=_user_agent(),
        app_ip=str(app_ip or ""),
        app_ip_family=app_ip.version if app_ip else None,
    )
    st.session_state["vpncheck_sid"] = session.id
    return session.id


def _plan(services: Services, sid: str) -> ProbePlan:
    config = services.config
    ipv4_base = config.collector.public_url_v4
    ipv6_base = config.collector.public_url_v6
    # 外置探针模式下端口由 run_probes.py 分配并记录在配置里，页面无从得知；
    # 这里只对内置模式分配端口，外置模式退化为在配置的固定端口上探测。
    stun_uris = services.stun.uris(sid) if config.stun.can_probe else ()
    return ProbePlan(
        session_id=sid,
        ipv4_base=ipv4_base,
        ipv6_base=ipv6_base,
        dns_zone=config.dns.zone if config.dns.enabled else None,
        dns_rounds=DNS_ROUNDS,
        dns_wait=config.dns.wait_seconds,
        stun_uris=stun_uris,
        report_url=ipv4_base + "/probe/report",
        ipv4_probe_url=ipv4_base + IPV4_PROBE_PATH,
        ipv6_probe_url=(ipv6_base + IPV4_PROBE_PATH) if ipv6_base else None,
        script_url=config.collector.script_url,
    )


def _build(services: Services, sid: str, user_agent: str) -> Report:
    return build_report(
        services.config,
        observations=services.store.observations(sid),
        reports=services.store.browser_reports(sid, "webrtc"),
        app_ip=_effective_app_ip(services, sid),
        user_agent=user_agent,
    )


def _status_icon(status: str) -> str:
    return {OK: "✅", WARN: "⚠️", LEAK: "❌", UNKNOWN: "❔", SKIPPED: "➖"}.get(status, "•")


def _render_summary(report: Report) -> None:
    overall = report.overall
    if overall == LEAK:
        st.error("**检测到泄露。** 下面标红的部分需要按建议处理，处理完请重新检测。")
    elif overall == WARN:
        st.warning("**未发现明确泄露，但有项目需要确认。** 请逐条查看说明。")
    elif overall == OK:
        st.success("**未发现泄露。** 你的 DNS、IPv4/IPv6 与 WebRTC 流量都在公司出口内。")
    else:
        st.info("**检测尚未完成。** 页面还在等待浏览器/探针回报，请稍候…")


def _render_service_health(services: Services) -> None:
    if not services.failures:
        return
    st.warning("**部分探针未能启动，对应检测项不完整。**")
    for name, reason in services.failures.items():
        st.caption(f"· {name}：{reason}")


def _render_findings(report: Report) -> None:
    for finding in report.sorted_findings():
        icon = _status_icon(finding.status)
        with st.expander(f"{icon} {finding.title} — {finding.label}", expanded=finding.status in {LEAK, WARN}):
            st.markdown(finding.summary)
            if finding.evidence:
                st.markdown("**证据**")
                for item in finding.evidence:
                    st.code(item, language=None)
            if finding.detail:
                st.markdown("**说明**")
                for line in finding.detail:
                    st.markdown(f"- {line}")


def _render_fixes(report: Report, user_agent: str) -> None:
    items = fixes_for(report.findings)
    if not items:
        return
    platforms = detect_platform(user_agent)
    st.subheader("修复建议")
    hint = browser_hint(user_agent)
    if hint:
        st.caption(hint)
    for item in items:
        with st.container(border=True):
            st.markdown(f"**{item.title}**")
            for platform, steps in item.steps_for(platforms):
                st.markdown(f"*{_platform_label(platform)}*")
                for index, step in enumerate(steps, start=1):
                    st.markdown(f"{index}. {step}")
            if item.note:
                st.caption(item.note)


def _platform_label(platform: str) -> str:
    from vpncheck.guidance import PLATFORM_LABELS

    return PLATFORM_LABELS.get(platform, platform)


def _render_details(report: Report, services: Services, sid: str) -> None:
    with st.expander("原始观测（排障用）", expanded=False):
        st.write("采到的地址：")
        if report.addresses:
            st.table(
                [{"项目": k, "地址": v} for k, v in report.addresses.items()]
            )
        else:
            st.caption("暂无。")
        st.write(
            f"HTTP 探测 {report.meta.get('http_probes', 0)} 次 · "
            f"DNS 查询 {report.meta.get('dns_queries', 0)} 次 · "
            f"WebRTC 上报 {report.meta.get('webrtc_reports', 0)} 次"
        )
        observations = services.store.observations(sid)
        if observations:
            st.dataframe(
                [
                    {
                        "时间": _ts(o.ts),
                        "类型": o.kind,
                        "来源地址": o.source_ip,
                        "协议": {4: "IPv4", 6: "IPv6"}.get(o.source_family or 0, ""),
                        "传输": o.transport,
                    }
                    for o in observations[-40:]
                ],
                width="stretch",
                hide_index=True,
            )
        st.caption(
            "会话仅保存判定所需的地址与计数，"
            f"{services.config.app.session_ttl_seconds // 60} 分钟后自动删除。"
        )


def _ts(value: float) -> str:
    import datetime as _dt

    return _dt.datetime.fromtimestamp(value).strftime("%H:%M:%S")


def _sidebar(services: Services, report: Report) -> None:
    config = services.config
    with st.sidebar:
        st.header("说明")
        st.markdown(
            "本页会做四项检查，全部只读取**你自己的**网络路径：\n\n"
            "1. 访问本页的流量从哪个出口发出\n"
            "2. DNS 查询由哪个解析器代你发出\n"
            "3. IPv6 流量是否绕过隧道\n"
            "4. 浏览器 WebRTC 是否暴露真实地址\n\n"
            "不会读取文件、Cookie 或浏览记录。"
        )
        if config.app.privacy_notice_url:
            st.markdown(f"[隐私说明]({config.app.privacy_notice_url})")
        if config.uses_documentation_addresses:
            st.warning(
                "服务端出口表仍是示例地址（RFC 5737/3849），检测结果不能当真。"
                "请让网络组把真实出口地址填进 config.toml。"
            )
        st.divider()
        st.caption("公司出口表")
        st.code(config.summary(), language=None)
        if report.meta.get("user_agent"):
            st.divider()
            st.caption(f"浏览器：{report.meta['user_agent'][:120]}")


def main() -> None:
    try:
        services = get_services()
    except ConfigError as exc:
        st.error("配置有误，服务无法启动。")
        st.code(str(exc), language=None)
        st.stop()
        return

    config = services.config
    st.set_page_config(page_title=config.app.title, page_icon="🛡️", layout="centered")
    st.title(config.app.title)
    st.caption("连上公司 VPN 后打开本页。检测在你自己的浏览器里运行，结果只属于本次会话。")

    sid = _session_id(services)
    user_agent = _user_agent() or st.session_state.get("vpncheck_ua", "")
    st.session_state["vpncheck_ua"] = user_agent

    plan = _plan(services, sid)
    st.html(render_probe(plan), unsafe_allow_javascript=True)

    if st.button("重新检测", type="secondary"):
        services.store.purge_session(sid)
        services.stun.release(sid)
        st.session_state.pop("vpncheck_sid", None)
        st.rerun()

    poll = st.fragment(_poll_fragment, run_every=config.app.poll_interval_seconds)
    poll(services, user_agent)


_CLEANUP_INTERVAL = 30.0


def _maybe_cleanup(services: Services) -> None:
    """过期数据清理按 30 秒节流，避免每个轮询周期都扫一次库。"""
    last = st.session_state.get("vpncheck_cleanup_at", 0.0)
    now = time.time()
    if now - last < _CLEANUP_INTERVAL:
        return
    st.session_state["vpncheck_cleanup_at"] = now
    services.store.cleanup()


def _poll_fragment(services: Services, user_agent: str) -> None:
    sid = st.session_state.get("vpncheck_sid")
    if not isinstance(sid, str):
        st.info("会话已失效，请刷新页面。")
        return
    _maybe_cleanup(services)
    report = _build(services, sid, user_agent)

    _render_summary(report)
    _render_service_health(services)

    cols = st.columns(5)
    for col, finding in zip(cols, report.findings, strict=False):
        with col:
            st.metric(finding.title, finding.label)

    _render_findings(report)
    _render_fixes(report, user_agent)

    st.download_button(
        "下载检测结果（Markdown）",
        data=fix_markdown(
            report.findings,
            user_agent,
            helpdesk=services.config.app.helpdesk_contact,
        ).encode("utf-8"),
        file_name="vpn-leak-report.md",
        mime="text/markdown",
    )

    with st.expander("判定依据与局限", expanded=False):
        st.markdown(
            "- 「页面访问出口」「DNS 解析出口」「IPv6 出口」来自**服务端看到的连接地址**，"
            "无法被页面脚本伪造。\n"
            "- DNS 项看到的是**递归解析器**的出口，不是你的电脑地址；因此公司 DNS 的对外"
            "出口必须写进出口表。\n"
            "- WebRTC 项来自浏览器的候选地址，属自报数据，但地址由浏览器在真实网络交互中"
            "取得，仍具参考价值。\n"
            "- 加密 DNS（DoH/DoT）会让 DNS 探测看不到任何查询，此时该项会显示“无法判定”，"
            "而不是“正常”。"
        )

    _render_details(report, services, sid)
    _sidebar(services, report)


main()
