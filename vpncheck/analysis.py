"""结果关联与判定。

输入是该会话在采集端、DNS 探针和 STUN 上留下的全部观测，输出一组
:class:`Finding`。判定只做一件事：把观测到的地址与公司出口表比对，并把
"为什么这么判"写清楚，包括证据和局限。
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .config import Config
from .nets import (
    IPAddress,
    classify_address,
    is_public,
    known_resolver_name,
    parse_ip,
)
from .store import Observation

OK = "ok"
WARN = "warn"
LEAK = "leak"
UNKNOWN = "unknown"
SKIPPED = "skipped"

STATUS_LABELS = {
    OK: "正常",
    WARN: "需注意",
    LEAK: "泄露",
    UNKNOWN: "无法判定",
    SKIPPED: "未执行",
}

STATUS_ORDER = {LEAK: 0, WARN: 1, UNKNOWN: 2, SKIPPED: 3, OK: 4}


@dataclass
class Finding:
    key: str
    title: str
    status: str
    summary: str
    detail: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    fix_keys: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


@dataclass
class Report:
    findings: list[Finding]
    addresses: dict[str, str]
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def overall(self) -> str:
        statuses = {f.status for f in self.findings}
        if LEAK in statuses:
            return LEAK
        if WARN in statuses:
            return WARN
        if UNKNOWN in statuses:
            return UNKNOWN
        if statuses and statuses <= {OK, SKIPPED}:
            return OK
        return UNKNOWN

    @property
    def overall_label(self) -> str:
        return STATUS_LABELS.get(self.overall, self.overall)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: STATUS_ORDER.get(f.status, 9))

    def by_key(self, key: str) -> Finding | None:
        return next((f for f in self.findings if f.key == key), None)


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------
def _fmt(ip: IPAddress | None, config: Config) -> str:
    if ip is None:
        return "—"
    return f"{ip}（{config.table.describe(ip)}）"


def _resolver_note(ip: IPAddress) -> str:
    name = known_resolver_name(ip)
    return f"，常见公共解析器：{name}" if name else ""


def _unique(ips: Iterable[IPAddress]) -> list[IPAddress]:
    seen: OrderedDict[str, IPAddress] = OrderedDict()
    for ip in ips:
        seen.setdefault(str(ip), ip)
    return list(seen.values())


def _family_label(family: int | None) -> str:
    return {4: "IPv4", 6: "IPv6"}.get(family or 0, "未知协议族")


# --------------------------------------------------------------------------
# 各项检测
# --------------------------------------------------------------------------
def check_app_egress(config: Config, app_ip: IPAddress | None) -> Finding:
    if app_ip is None:
        return Finding(
            key="app",
            title="访问自检页的出口",
            status=UNKNOWN,
            summary="未能从连接信息中读到你的地址（本地访问或代理剥离了地址）。",
            detail=["如果你是从公司内网直接打开的页面，这一项可能为空，不影响其他检测。"],
        )
    in_table = config.table.is_corporate(app_ip)
    detail = [f"采集端看到的连接地址：{_fmt(app_ip, config)}"]
    if in_table:
        return Finding(
            key="app",
            title="访问自检页的出口",
            status=OK,
            summary="你访问自检页的流量从公司出口发出，隧道对这部分流量生效。",
            detail=detail,
        )
    status = LEAK if config.policy.app_requires_tunnel else WARN
    summary = (
        "访问自检页的流量没有走公司出口，说明你当前的网络路径不在隧道内。"
        if config.policy.app_requires_tunnel
        else "访问自检页的流量不在公司出口表内；如果自检站本身部署在公网，这是预期结果。"
    )
    detail.append(
        "注意：自检站若部署在公网，员工不走 VPN 也能打开本页，"
        "因此这一项只反映“打开页面”这条路径，不能单独证明隧道失效。"
    )
    return Finding(
        key="app",
        title="访问自检页的出口",
        status=status,
        summary=summary,
        detail=detail,
        evidence=[str(app_ip)],
        fix_keys=("tunnel",),
    )


def check_dns_egress(
    config: Config,
    observations: list[Observation],
    reports: list[dict[str, Any]] | None = None,
) -> Finding:
    dns_obs = [o for o in observations if o.kind == "dns"]
    if not config.dns.enabled:
        return Finding(
            key="dns",
            title="DNS 解析出口",
            status=SKIPPED,
            summary="服务端未启用 DNS 探针，未检测解析出口。",
        )
    if not dns_obs:
        attempted = _dns_attempts(reports or [])
        detail = [
            "可能是浏览器启用了加密 DNS（DoH/DoT）导致探测域名没有被本地解析，",
            "也可能是网络屏蔽了到探针区域 53 端口的查询。",
            "可以关闭浏览器的“安全 DNS”，或在系统里临时换回公司 DNS 后重试。",
        ]
        if attempted:
            detail.insert(
                0,
                f"浏览器确实发起了 {attempted} 次探测域名的解析请求，但探针一次也没收到——"
                "这说明查询在中途被别的解析器接走了（加密 DNS 最可能）。",
            )
            detail.append(
                "另一种可能是服务端漏配委派：请确认上联解析器把探针区域指向了本服务，"
                "否则查询会被拒绝而根本到不了探针。"
            )
        return Finding(
            key="dns",
            title="DNS 解析出口",
            status=UNKNOWN,
            summary=(
                "浏览器发出过解析请求，但探针没收到，无法判定 DNS 出口。"
                if attempted
                else "没有观察到任何解析请求。"
            ),
            detail=detail,
            fix_keys=("doh",),
        )

    counts = Counter(o.source_ip for o in dns_obs if o.source_ip)
    resolvers = [ip for ip in (_unique(parse_ip(value) for value in counts) if counts else []) if ip]
    if not resolvers:
        # 观测存在但没有可用来源地址（例如前置代理把地址剥离了）：宁可说
        # 无法判定，也不能因为"没有外部地址"就判成正常。
        return Finding(
            key="dns",
            title="DNS 解析出口",
            status=UNKNOWN,
            summary="观察到了解析请求，但没有记录到来源地址，无法判定。",
            detail=[
                f"共 {len(dns_obs)} 次解析请求的来源地址为空。",
                "常见原因：探针前面有反向代理/NAT 设备剥离了源地址，或采集端配置的",
                "信任代理列表不正确。请让部署方检查采集端与 DNS 探针的地址可见性。",
            ],
        )
    corporate = [ip for ip in resolvers if config.table.is_expected_dns(ip)]
    outside = [ip for ip in resolvers if not config.table.is_expected_dns(ip)]

    evidence = [f"{ip} × {counts[str(ip)]}" for ip in resolvers]
    detail = [
        f"共观察到 {len(dns_obs)} 次解析请求，来自 {len(resolvers)} 个出口地址。",
        "这里看到的是**递归解析器**的出口地址，不是你的电脑地址：",
        "公司 DNS 会用自己的出口去查询，公共 DNS（如 8.8.8.8）用自己的地址查询。",
    ]
    for ip in resolvers:
        role = "公司出口" if config.table.is_expected_dns(ip) else "不在公司出口表内"
        detail.append(f"· {ip} —— {role}{_resolver_note(ip)}（{_family_label(ip.version)}）")

    if not outside:
        return Finding(
            key="dns",
            title="DNS 解析出口",
            status=OK,
            summary="你的解析请求全部由公司出口的 DNS 发出，DNS 走隧道。",
            detail=detail,
            evidence=evidence,
        )

    if corporate:
        summary = "解析请求同时来自公司出口和外部地址，说明存在分流：部分域名没走公司 DNS。"
        status = LEAK
        fix_keys = ("dns", "split_dns")
    else:
        publicish = [ip for ip in outside if is_public(ip)]
        if publicish:
            summary = "解析请求全部由公司出口以外的公共递归解析器发出，DNS 查询绕过了隧道。"
            status = LEAK
            fix_keys = ("dns", "doh")
        else:
            summary = "解析请求的来源不在公司出口表内，需要确认这是公司 DNS 还是本地/运营商 DNS。"
            status = WARN
            fix_keys = ("dns",)
        detail.append(
            "如果公司 DNS 的出站地址有 NAT、且没有写进 config.toml 的出口表，"
            "这里可能误报。请让网络组补全公司 DNS 的对外出口地址段。"
        )
    detail.append(
        "同时留意：部分厂商 VPN 默认把 DNS 查询交给本机运营商，"
        "或浏览器开启了“安全 DNS”（DoH）直接连公共解析器，这两种都会命中本项。"
    )
    return Finding(
        key="dns",
        title="DNS 解析出口",
        status=status,
        summary=summary,
        detail=detail,
        evidence=evidence,
        fix_keys=fix_keys,
    )


def check_ipv6(
    config: Config,
    observations: list[Observation],
    reports: list[dict[str, Any]] | None = None,
) -> Finding:
    v6_http = [o for o in observations if o.kind == "http" and o.source_family == 6]
    v6_dns = [o for o in observations if o.kind == "dns" and o.source_family == 6]

    if not config.collector.public_url_v6:
        return Finding(
            key="ipv6",
            title="IPv6 是否绕过隧道",
            status=SKIPPED,
            summary="服务端没有为 IPv6 配置独立探测地址，未检测 IPv6 路径。",
            detail=[
                "要检测 IPv6 泄露，请给采集端一个 AAAA 记录（public_url_v6），",
                "页面会单独用 IPv6 访问它，从而看出 IPv6 流量走的是隧道还是本机运营商。",
            ],
        )

    if not v6_http:
        # 没有 HTTP 观测时，仍可用 WebRTC 的 IPv6 srflx 候选作为旁证。
        rtc_v6 = _webrtc_ipv6_candidates(reports or [])
        outside_rtc = [ip for ip in rtc_v6 if not config.table.is_corporate(ip)]
        if outside_rtc and any(is_public(ip) for ip in outside_rtc):
            return Finding(
                key="ipv6",
                title="IPv6 是否绕过隧道",
                status=LEAK,
                summary="页面没能用 IPv6 连上采集端，但 WebRTC 拿到了隧道外的公网 IPv6 地址。",
                detail=[
                    "采集端没有收到 IPv6 连接，可能是 IPv6 回程或探测域名未放通；",
                    "但 WebRTC 的 STUN 反射地址显示，本机确有可用的公网 IPv6 并直接出网。",
                    *[f"· {ip} —— 不在公司出口表内" for ip in outside_rtc],
                ],
                evidence=[str(ip) for ip in outside_rtc],
                fix_keys=("ipv6", "webrtc"),
            )
        return Finding(
            key="ipv6",
            title="IPv6 是否绕过隧道",
            status=OK,
            summary="未观察到可用的 IPv6 出网路径，IPv6 不会绕过隧道。",
            detail=[
                "页面尝试用 IPv6 地址访问采集端但没有收到连接；",
                "通常说明本机没有可路由的公网 IPv6，或隧道已把 IPv6 全部接管/禁用。",
                *([f"WebRTC 也只看到隧道内的 IPv6 地址：{', '.join(map(str, rtc_v6))}"] if rtc_v6 else []),
            ],
        )

    ips = [ip for ip in (_unique(parse_ip(o.source_ip) for o in v6_http)) if ip]
    outside = [ip for ip in ips if not config.table.is_corporate(ip)]
    detail = [
        "页面通过只解析到 IPv6 的域名访问了采集端，下面是采集端看到的地址：",
        *[
            f"· {ip} —— {'公司出口' if config.table.is_corporate(ip) else '不在公司出口表内'}"
            for ip in ips
        ],
    ]
    if v6_dns and not any(o.source_ip for o in v6_dns):
        detail.append("此外还观察到经 IPv6 到达的 DNS 查询，IPv6 路径确实在承载流量。")
    if not outside:
        return Finding(
            key="ipv6",
            title="IPv6 是否绕过隧道",
            status=OK,
            summary="IPv6 流量从公司出口发出，没有绕过隧道。",
            detail=detail,
            evidence=[str(ip) for ip in ips],
        )
    detail.append(
        "典型的“IPv6 泄露”：电脑同时具备公网 IPv6，而 VPN 只接管了 IPv4。"
        "这种配置下访问支持 IPv6 的网站会直接走本地运营商。"
    )
    if not config.has_corporate_v6:
        detail.append(
            "另外，公司出口表里没有配置任何 IPv6 网段。如果公司确实有 IPv6 出口，"
            "请补进出口表，否则该项可能误报。"
        )
    return Finding(
        key="ipv6",
        title="IPv6 是否绕过隧道",
        status=LEAK,
        summary="IPv6 流量没有走公司出口，直接经由本机网络出网。",
        detail=detail,
        evidence=[str(ip) for ip in outside],
        fix_keys=("ipv6",),
    )


def _extract_webrtc_addresses(reports: list[dict[str, Any]]) -> dict[str, list[str]]:
    """从页面上报中提取 WebRTC 候选，按类型分组。

    只看**最近一次**上报：同一会话里上一次检测的候选可能来自另一个网络
    （例如刚切到 VPN），混在一起会得出错误的泄露结论。
    """
    buckets: dict[str, list[str]] = {"srflx": [], "host": [], "relay": [], "prflx": []}
    for report in reports[-1:]:
        candidates = report.get("payload", {}).get("candidates") or []
        if not isinstance(candidates, list):
            continue
        for item in candidates:
            if not isinstance(item, dict):
                continue
            ctype = str(item.get("type") or "").lower()
            address = str(item.get("address") or "").strip()
            ip = parse_ip(address)
            if ctype not in buckets:
                continue
            if ip is None:
                if address and address.endswith(".local"):
                    buckets["host"].append(address)
                continue
            buckets[ctype].append(str(ip))
    return buckets


def _dns_attempts(reports: list[dict[str, Any]]) -> int:
    """页面上报里声明的 DNS 触发次数（脚本发出 img 请求的次数）。"""
    total = 0
    for report in reports:
        if report.get("kind") != "timing":
            continue
        payload = report.get("payload", {})
        value = payload.get("dns")
        if isinstance(value, int) and value > 0:
            total = max(total, value)
    return total


def _webrtc_ipv6_candidates(reports: list[dict[str, Any]]) -> list[IPAddress]:
    buckets = _extract_webrtc_addresses(reports)
    out: list[IPAddress] = []
    for kind in ("srflx", "host"):
        for value in buckets[kind]:
            ip = parse_ip(value)
            if ip is not None and ip.version == 6:
                out.append(ip)
    return _unique(out)


def check_webrtc(config: Config, reports: list[dict[str, Any]], stun_enabled: bool) -> Finding:
    if not stun_enabled:
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=SKIPPED,
            summary="服务端未启用 STUN 探针，未检测 WebRTC。",
        )
    if not reports:
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=UNKNOWN,
            summary="浏览器没有回报 WebRTC 结果。",
            detail=[
                "可能是浏览器禁用了 WebRTC，或页面脚本被隐私扩展拦截。",
                "可以换一个浏览器、或在无痕窗口（禁用扩展）里重试。",
            ],
        )

    latest = reports[-1].get("payload", {})
    if latest.get("error"):
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=WARN,
            summary=f"WebRTC 探测没有成功：{latest.get('error')}",
            detail=["这不代表没有泄露，只代表这次没能取到候选地址；建议换浏览器重试。"],
        )
    if latest.get("unsupported"):
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=SKIPPED,
            summary="当前浏览器不支持 RTCPeerConnection，无法检测。",
        )

    buckets = _extract_webrtc_addresses(reports)
    srflx = [ip for ip in (_unique(parse_ip(x) for x in buckets["srflx"])) if ip]
    host = [ip for ip in (_unique(parse_ip(x) for x in buckets["host"])) if ip]
    relay = [ip for ip in (_unique(parse_ip(x) for x in buckets["relay"])) if ip]

    detail: list[str] = []

    if srflx:
        detail.append("STUN 反射地址（对面看到的你）——这就是 WebRTC 实际出网的地址：")
        for ip in srflx:
            mark = "公司出口" if config.table.is_corporate(ip) else "不在公司出口表内"
            detail.append(f"· {ip} —— {mark}（{_family_label(ip.version)}）")
    else:
        detail.append("没有拿到 STUN 反射地址：可能 UDP 被阻断，或 STUN 端口未放通。")

    if host:
        detail.append("本机候选地址：")
        for ip in host:
            detail.append(
                f"· {ip} —— {classify_address(ip)}" + ("，会被对方看到" if is_public(ip) else "")
            )
    if buckets["host"] and any(x.endswith(".local") for x in buckets["host"]):
        detail.append(
            "浏览器用 mDNS 名称（*.local）代替了本机地址，这是现代浏览器的隐私保护行为。"
        )
    if relay:
        detail.append("中继（relay）候选：" + "，".join(str(ip) for ip in relay))

    outside_srflx = [ip for ip in srflx if not config.table.is_corporate(ip)]
    ok_addrs = [ip for ip in srflx + host if config.table.is_corporate(ip)]
    public_leaks = [ip for ip in outside_srflx if is_public(ip)]
    # 本机的裸内网地址也会被对端看到（mDNS 名称不算，浏览器已在保护）。
    private_host = [ip for ip in host if ip.is_private and not config.table.is_corporate(ip)]

    if public_leaks:
        detail.append(
            "WebRTC 的 UDP 流量不经过浏览器的 HTTP 代理，很多 VPN 客户端也不接管它，"
            "因此这是最常见的“真实地址暴露”途径。"
        )
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=LEAK,
            summary="WebRTC 拿到了公司出口以外的公网地址，真实地址会暴露给对端。",
            detail=detail,
            evidence=[str(ip) for ip in public_leaks],
            fix_keys=("webrtc", "ipv6"),
        )

    if outside_srflx:
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=WARN,
            summary="WebRTC 的出网路径不在公司出口表内，但拿到的不是公网地址。",
            detail=[
                *detail,
                "建议确认 VPN 是否接管了 UDP；若公司出口有 NAT，请把对应地址段补进出口表。",
            ],
            evidence=[str(ip) for ip in outside_srflx],
            fix_keys=("webrtc",),
        )

    if private_host:
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=WARN,
            summary="WebRTC 会把本机内网地址直接告诉对端（未使用 mDNS 保护）。",
            detail=[
                *detail,
                "内网地址不像公网地址那样直接定位你，但会泄露公司网络结构；",
                "如果对端不需要直连，建议按下方建议限制 WebRTC 的本机候选。",
            ],
            evidence=[str(ip) for ip in private_host],
            fix_keys=("webrtc",),
        )

    if not srflx and not host:
        return Finding(
            key="webrtc",
            title="WebRTC 暴露的地址",
            status=UNKNOWN,
            summary="没有收集到任何 WebRTC 候选地址，无法判断。",
            detail=detail,
        )

    return Finding(
        key="webrtc",
        title="WebRTC 暴露的地址",
        status=OK,
        summary="WebRTC 只能看到公司出口地址（或仅本机加密名称），没有暴露真实地址。",
        detail=detail,
        evidence=[str(ip) for ip in ok_addrs],
    )


def check_tunnel_consistency(config: Config, observations: list[Observation]) -> Finding:
    """把 HTTP 观测的出口与 DNS 出口放在一起看，提示分流。"""
    http_ips = [ip for ip in (_unique(parse_ip(o.source_ip) for o in observations if o.kind == "http")) if ip]
    if not http_ips:
        return Finding(
            key="consistency",
            title="出口一致性",
            status=UNKNOWN,
            summary="没有采集到 HTTP 出口，无法做一致性比对。",
        )
    inside = [ip for ip in http_ips if config.table.is_corporate(ip)]
    outside = [ip for ip in http_ips if not config.table.is_corporate(ip)]
    if inside and outside:
        return Finding(
            key="consistency",
            title="出口一致性",
            status=LEAK,
            summary="同一个页面在不同探测中走了不同的出口，说明存在分流隧道或双网卡。",
            detail=[
                "公司出口：" + "，".join(str(ip) for ip in inside),
                "其他出口：" + "，".join(str(ip) for ip in outside),
                "常见原因：拆分隧道（split tunneling）把部分目标排除在隧道外、"
                "同时连着有线和无线、或在 IPv4/IPv6 上走了不同路径。",
            ],
            evidence=[str(ip) for ip in http_ips],
            fix_keys=("split_dns", "tunnel"),
        )
    return Finding(
        key="consistency",
        title="出口一致性",
        status=OK,
        summary="各次 HTTP 探测的出口一致，没有发现分流迹象。",
        detail=["出口地址：" + "，".join(str(ip) for ip in http_ips)],
    )


def build_report(
    config: Config,
    *,
    observations: list[Observation],
    reports: list[dict[str, Any]],
    app_ip: IPAddress | None,
    user_agent: str = "",
) -> Report:
    """把所有观测汇总成报告。"""
    findings = [
        check_app_egress(config, app_ip),
        check_dns_egress(config, observations, reports),
        check_ipv6(config, observations, reports),
        check_webrtc(config, reports, stun_enabled=config.stun.can_probe),
        check_tunnel_consistency(config, observations),
    ]

    addresses: dict[str, str] = {}
    if app_ip is not None:
        addresses["页面访问出口"] = str(app_ip)
    for obs in observations:
        if obs.kind == "dns" and obs.source_ip:
            addresses.setdefault("DNS 解析出口", obs.source_ip)
        if obs.kind == "http" and obs.source_ip and obs.source_family == 6:
            addresses.setdefault("IPv6 出口", obs.source_ip)
    buckets = _extract_webrtc_addresses(reports)
    if buckets["srflx"]:
        addresses.setdefault("WebRTC 反射地址", buckets["srflx"][-1])

    return Report(
        findings=findings,
        addresses=addresses,
        meta={
            "user_agent": user_agent,
            "dns_queries": sum(1 for o in observations if o.kind == "dns"),
            "http_probes": sum(1 for o in observations if o.kind == "http"),
            "webrtc_reports": len(reports),
        },
    )


__all__ = [
    "Finding",
    "Report",
    "build_report",
    "check_app_egress",
    "check_dns_egress",
    "check_ipv6",
    "check_webrtc",
    "check_tunnel_consistency",
    "OK",
    "WARN",
    "LEAK",
    "UNKNOWN",
    "SKIPPED",
    "STATUS_LABELS",
]
