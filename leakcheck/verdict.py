"""Verdict engine: turn raw observations into checks, findings and severity.

Design rules
------------
* Every conclusion names the **channel** it came from (HTTP / DNS / UDP-WebRTC /
  IPv6) and carries the concrete addresses as evidence, because "you may be
  leaking" without evidence is not actionable for the user or for IT.
* A channel with no data is ``UNKNOWN``, never ``PASS``.  A split-horizon
  resolver that never reaches our authoritative zone is *not* proof of
  compliance, and pretending otherwise is how leak tests lose trust.
* Classification uses the operator's exit inventory first, then well-known
  public resolvers, then private/special ranges, then "unexpected global
  address".  The order matters: an operator may deliberately list a corporate
  resolver that is also a public anycast range.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .config import AppConfig, ExitInventory
from .netutil import (IPAddress, addr_sort_key, address_scope, is_public_address,
                      parse_ip, sorted_unique)
from .storage import Observation, Session


class Severity(str, Enum):
    PASS = "pass"
    INFO = "info"
    UNKNOWN = "unknown"
    WARN = "warn"
    FAIL = "fail"

    @property
    def rank(self) -> int:
        return {"pass": 0, "info": 1, "unknown": 2, "warn": 3, "fail": 4}[self.value]

    @property
    def label(self) -> str:
        return {
            "pass": "通过",
            "info": "提示",
            "unknown": "无法判定",
            "warn": "需注意",
            "fail": "疑似泄露",
        }[self.value]


class Category(str, Enum):
    VPN = "vpn_egress"
    CORP_RESOLVER = "corp_resolver"
    OFFICE = "office_egress"
    THIRD_PARTY = "third_party_resolver"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    SPECIAL = "special"
    GLOBAL_UNKNOWN = "global_unknown"

    @property
    def label(self) -> str:
        return {
            "vpn_egress": "公司 VPN 出口",
            "corp_resolver": "公司解析器出口",
            "office_egress": "办公网直出",
            "third_party_resolver": "公共解析器",
            "private": "内网地址",
            "loopback": "本机",
            "special": "特殊用途地址",
            "global_unknown": "未知公网地址",
        }[self.value]


@dataclass(slots=True)
class Classification:
    address: IPAddress
    category: Category
    label: str
    network: str | None = None

    def as_row(self) -> dict[str, str]:
        return {
            "地址": str(self.address),
            "归属": self.label,
            "匹配网段": self.network or "-",
        }


@dataclass(slots=True)
class Evidence:
    channel: str
    label: str
    value: str
    extra: str = ""


@dataclass(slots=True)
class Check:
    key: str
    title: str
    severity: Severity
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    measured: bool = False


PRIMARY_CHECKS = ("http_egress", "dns_egress", "udp_egress")


@dataclass(slots=True)
class Report:
    checks: list[Check]
    session: Session
    observations: list[Observation]
    client_ip: IPAddress | None
    client_class: Classification | None
    os_family: str
    generated_at: float

    def check(self, key: str) -> Check | None:
        return next((c for c in self.checks if c.key == key), None)

    @property
    def severity(self) -> Severity:
        """Overall verdict.

        A leak always wins.  Otherwise an unmeasured *primary* channel (HTTP,
        DNS, UDP) makes the result UNKNOWN — never PASS — because silence is not
        evidence of compliance.  Secondary checks (IPv6, consistency, WebRTC
        disclosure) only matter when they actually found something.
        """
        if not self.checks:
            return Severity.UNKNOWN
        if any(c.severity is Severity.FAIL for c in self.checks):
            return Severity.FAIL
        if any(c.severity is Severity.WARN for c in self.checks):
            return Severity.WARN
        primary = [c for c in self.checks if c.key in PRIMARY_CHECKS]
        if any(c.severity is Severity.UNKNOWN for c in primary):
            return Severity.UNKNOWN
        if not any(c.measured for c in primary):
            return Severity.UNKNOWN
        return Severity.PASS

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.severity is Severity.FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.severity is Severity.WARN]

    @property
    def unknown(self) -> list[Check]:
        return [c for c in self.checks if c.severity is Severity.UNKNOWN]

    def headline(self) -> str:
        severity = self.severity
        if severity is Severity.FAIL:
            return "检测到疑似 VPN 泄露"
        if severity is Severity.WARN:
            return "存在需要复核的流量路径"
        if severity is Severity.UNKNOWN:
            return "检测未完成，部分通道没有数据"
        return "所有已检测通道均通过 VPN 出口"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _match(networks, addr: IPAddress) -> str | None:
    for network in networks:
        if network.version == addr.version and addr in network:
            return str(network)
    return None


def classify(inventory: ExitInventory, addr: IPAddress | None,
             channel: str = "http") -> Classification | None:
    """Attribute an observed address to an exit class.

    ``channel`` resolves the one ambiguity that matters in practice: a company
    may NAT its VPN **and** its DNS resolvers behind the *same* public prefix.
    Then a resolver address is not evidence that web traffic went out there, so
    the DNS channel consults the resolver list first and the HTTP/UDP channels
    consult the VPN list first.  Any address in either list is still "ours", and
    only addresses in neither can be a leak.
    """
    if addr is None:
        return None
    order: list[tuple[list, Category]] = [
        (inventory.vpn_egress.networks, Category.VPN),
        (inventory.corp_resolvers.networks, Category.CORP_RESOLVER),
    ]
    if channel == "dns":
        order.reverse()
    for networks, category in order:
        hit = _match(networks, addr)
        if hit:
            return Classification(addr, category, category.label, hit)
    hit = _match(inventory.office_egress.networks, addr)
    if hit:
        return Classification(addr, Category.OFFICE, Category.OFFICE.label, hit)
    vendor = inventory.public_resolver_name(addr)
    if vendor:
        return Classification(addr, Category.THIRD_PARTY, f"公共解析器（{vendor}）", None)
    scope = address_scope(addr)
    if scope == "loopback":
        return Classification(addr, Category.LOOPBACK, Category.LOOPBACK.label, None)
    if scope in ("private", "link_local"):
        return Classification(addr, Category.PRIVATE, Category.PRIVATE.label, None)
    if scope in ("unspecified", "multicast"):
        return Classification(addr, Category.SPECIAL, Category.SPECIAL.label, None)
    if inventory.is_ignored(addr):
        return Classification(addr, Category.PRIVATE, Category.PRIVATE.label, None)
    return Classification(addr, Category.GLOBAL_UNKNOWN, Category.GLOBAL_UNKNOWN.label, None)


# ---------------------------------------------------------------------------
# Shared per-channel judgement
# ---------------------------------------------------------------------------

# For each observation channel: which classifications count as "inside the
# tunnel" (or at least not evidence of a leak), and what to say about the rest.
def _judge_addresses(config: AppConfig, addrs: list[IPAddress], channel: str
                     ) -> tuple[Severity, list[str], list[IPAddress]]:
    """Return ``(worst, notes, good)`` for the addresses seen on one channel.

    ``good`` are the addresses that count as "through the company path"; they are
    used for the check's one-line summary.
    """
    worst = Severity.PASS
    notes: list[str] = []
    good: list[IPAddress] = []
    is_dns = channel == "dns"
    for addr in addrs:
        cls = classify(config.exits, addr, channel)
        if cls is None:
            continue
        category = cls.category
        scope = address_scope(addr)
        trusted = (Category.CORP_RESOLVER, Category.VPN) if is_dns else (Category.VPN,)
        if category in trusted:
            good.append(addr)
            continue
        if scope in ("private", "loopback"):
            notes.append(
                f"解析请求来自内网地址 {addr}：请求在隧道内被转发，属正常。"
                if is_dns
                else f"观测到内网地址 {addr}：流量在隧道内（或本机回环），属正常。"
            )
            good.append(addr)
            continue
        if category is Category.CORP_RESOLVER:
            notes.append(
                f"{addr} 属于公司解析器出口而非网页/UDP 出口，"
                "请确认出口清单是否把这几种地址混在同一网段。"
            )
            worst = max(worst, Severity.WARN, key=lambda s: s.rank)
        elif category is Category.OFFICE:
            notes.append(
                f"流量来自办公网出口 {addr}：在办公区属正常，在外部网络则说明没进隧道。"
            )
            worst = max(worst, Severity.WARN, key=lambda s: s.rank)
        elif category is Category.THIRD_PARTY:
            vendor = cls.label.removeprefix("公共解析器（").removesuffix("）")
            notes.append(
                f"解析请求由公共解析器 {addr}（{vendor}）发出：DNS 没有走公司解析路径，"
                "通常由浏览器「安全 DNS / DoH」或本机直连造成。"
                if is_dns
                else f"流量来自公共解析器 {addr}（{vendor}），不应出现在该通道。"
            )
            worst = max(worst, Severity.FAIL, key=lambda s: s.rank)
        else:
            notes.append(
                f"解析请求来自 {addr}，不在公司解析器或 VPN 出口清单内：DNS 疑似绕过隧道。"
                if is_dns
                else f"流量从 {addr} 发出，不在公司出口清单内：该通道疑似绕过了隧道。"
            )
            worst = max(worst, Severity.FAIL, key=lambda s: s.rank)
    return worst, notes, good


def _dedupe(observations: Iterable[Observation]) -> list[Observation]:
    """Collapse repeated identical channel reports for display.

    The key must include what actually distinguishes two observations.  For DNS
    that is the queried name/type — keying on ``kind`` alone (which DNS records do
    not set) would silently merge six real lookups into one and under-report both
    the count and the query types in the evidence table.
    """
    seen: set[tuple[str, ...]] = set()
    out: list[Observation] = []
    for obs in observations:
        detail = obs.detail
        key = (
            obs.channel,
            obs.source_ip,
            str(detail.get("kind", "")),
            str(detail.get("qname", "")),
            str(detail.get("qtype", "")),
            str(detail.get("path", "")),
            str(detail.get("local_port", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(obs)
    return out


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_http(config: AppConfig, observations: list[Observation]) -> Check:
    http_obs = [o for o in observations if o.channel == "http"]
    check = Check(
        key="http_egress",
        title="网页请求出口（TCP/HTTPS）",
        severity=Severity.UNKNOWN,
        summary="未收到网页请求上报。",
    )
    if not http_obs:
        check.summary = (
            "浏览器没有把网页请求送到检测服务。页面可能被拦截、跨域策略阻止，"
            "或自检页未完整加载。"
        )
        check.remediation = ["remediation.probe_blocked"]
        return check
    check.measured = True
    v4: list[IPAddress] = []
    v6: list[IPAddress] = []
    for obs in http_obs:
        addr = parse_ip(obs.source_ip)
        if addr is None:
            continue
        (v4 if addr.version == 4 else v6).append(addr)
        cls = classify(config.exits, addr)
        check.evidence.append(
            Evidence(
                "http",
                f"HTTP/{'IPv4' if addr.version == 4 else 'IPv6'}",
                f"{addr}（{cls.label if cls else '未分类'}）",
                str(obs.detail.get("path") or ""),
            )
        )

    worst, notes, good = _judge_addresses(config, sorted_unique(v4 + v6), "http")
    if good:
        check.summary = "网页请求从公司出口发出：" + "、".join(str(a) for a in good)
    elif notes:
        check.summary = notes[0]
    else:
        check.summary = "已收到网页请求，但地址无法归类。"
    check.details = notes if len(notes) > (1 if good else 0) else []
    check.severity = worst
    if worst is Severity.FAIL or worst is Severity.WARN:
        check.remediation = ["remediation.split_tunnel", "remediation.route_all"]
    return check


def _check_dns(config: AppConfig, observations: list[Observation]) -> Check:
    dns_obs = [o for o in observations if o.channel == "dns"]
    check = Check(
        key="dns_egress",
        title="DNS 解析出口",
        severity=Severity.UNKNOWN,
        summary="没有观察到发往探针权威服务器的解析请求。",
    )
    if not dns_obs:
        check.summary = (
            "检测服务没有收到任何针对探针域名的解析请求。常见原因："
            "① 浏览器启用了加密 DNS（DoH），解析被送到公共 DoH 服务；"
            "② 内网 DNS 对探针域名做了本地应答（split-horizon）；"
            "③ 页面无法解析或请求被拦截。"
        )
        check.details = [
            "仅凭“没有请求”无法证明 DNS 走了隧道，因此此项记为无法判定而不是通过。",
            "若内网解析器确实对探针域名返回了本地答案，本身是隔离得较好的表现，"
            "但仍建议在浏览器中关闭 DoH 后复测以取得证据。",
        ]
        check.remediation = ["remediation.dns_doh", "remediation.dns_client", "remediation.probe_blocked"]
        return check

    check.measured = True
    resolvers: dict[IPAddress, dict[str, Any]] = {}
    ecs_seen: dict[str, list[str]] = {}
    transports: set[str] = set()
    for obs in dns_obs:
        addr = parse_ip(obs.source_ip)
        if addr is None:
            continue
        transports.add(obs.transport or "udp")
        info = resolvers.setdefault(
            addr,
            {"count": 0, "ecs": set(), "qtypes": set(), "do": False, "edns": False},
        )
        info["count"] += 1
        info["qtypes"].add(str(obs.detail.get("qtype", "")))
        info["do"] = info["do"] or bool(obs.detail.get("do"))
        info["edns"] = info["edns"] or bool(obs.detail.get("edns"))
        ecs = obs.detail.get("ecs")
        if ecs:
            info["ecs"].add(str(ecs))
            ecs_seen.setdefault(str(ecs), []).append(str(addr))

    notes: list[str] = []
    for addr in sorted(resolvers, key=addr_sort_key):
        cls = classify(config.exits, addr, "dns")
        info = resolvers[addr]
        label = cls.label if cls else "未分类"
        if cls is not None and cls.category is Category.THIRD_PARTY:
            # cls.label already reads "公共解析器（Cloudflare）"; the note adds
            # "由公共解析器 ... 发出", so keep only the vendor part here.
            label = cls.label
        extra = []
        if info["ecs"]:
            extra.append("带 ECS: " + ", ".join(sorted(info["ecs"])))
        if info["do"]:
            extra.append("DNSSEC DO 位")
        check.evidence.append(
            Evidence(
                "dns",
                f"解析器 {addr}（{label}）",
                f"{info['count']} 次查询，类型 {', '.join(sorted(q for q in info['qtypes'] if q))}",
                "；".join(extra),
            )
        )

    worst, notes, corp_hits = _judge_addresses(
        config, sorted(resolvers, key=addr_sort_key), "dns"
    )

    if ecs_seen:
        notes.append(
            "解析器转发了 EDNS Client Subnet（ECS），你的真实网段 "
            + "、".join(sorted(ecs_seen))
            + " 被上游 DNS 看到，属于客户端地址泄露。"
        )
        worst = max(worst, Severity.FAIL, key=lambda s: s.rank)

    if notes:
        check.summary = notes[0]
    elif corp_hits:
        check.summary = "DNS 解析经公司出口：" + "、".join(str(a) for a in corp_hits)
    else:
        check.summary = "已观察到 DNS 查询，但出口地址无法归类。"

    all_qtypes = set().union(*(i["qtypes"] for i in resolvers.values()))
    if "AAAA" not in all_qtypes and "A" in all_qtypes and config.dns.answer_ipv6:
        notes.append(
            "没有看到 AAAA 查询：浏览器/系统可能没有发起 IPv6 解析（IPv6 已禁用或未分配地址）。"
        )
    check.details = notes
    check.severity = worst
    if worst is Severity.FAIL:
        check.remediation = ["remediation.dns_doh", "remediation.dns_client", "remediation.split_tunnel"]
    elif worst is Severity.WARN:
        check.remediation = ["remediation.dns_client", "remediation.split_tunnel"]
    return check


def _check_udp(config: AppConfig, observations: list[Observation],
                webrtc_detail: dict[str, Any] | None) -> Check:
    stun_obs = [o for o in observations if o.channel == "stun"]
    check = Check(
        key="udp_egress",
        title="UDP 出口（WebRTC / STUN）",
        severity=Severity.UNKNOWN,
        summary="没有收到 STUN 绑定请求。",
    )
    browser_candidates = _browser_candidates(webrtc_detail)
    if not stun_obs:
        if browser_candidates:
            check.summary = "浏览器报告了候选地址，但检测服务的 STUN 端口没有收到对应报文。"
            check.details = [
                "可能是 STUN 端口被防火墙/NAT 阻断，或浏览器禁止了该 WebRTC 连接。"
            ]
            check.severity = Severity.UNKNOWN
        else:
            check.details = [
                "浏览器可能不支持 WebRTC、被策略禁用，或自检页未在安全上下文（HTTPS）中打开。"
            ]
        check.remediation = ["remediation.webrtc_blocked", "remediation.stun_ports"]
        return check

    check.measured = True
    notes: list[str] = []
    seen: list[IPAddress] = []
    for obs in stun_obs:
        addr = parse_ip(obs.source_ip)
        if addr is None:
            continue
        seen.append(addr)
        check.evidence.append(
            Evidence(
                "stun",
                f"STUN/{'IPv4' if addr.version == 4 else 'IPv6'}",
                f"{addr}:{obs.source_port}",
                f"本地端口 {obs.detail.get('local_port')}",
            )
        )

    worst, notes, vpn_seen = _judge_addresses(config, sorted_unique(seen), "udp")
    if vpn_seen:
        check.summary = "UDP 从公司出口发出：" + "、".join(str(a) for a in vpn_seen)
    elif notes:
        check.summary = notes[0]
    else:
        check.summary = "已收到 STUN 报文，但地址无法归类。"

    # Compare what the browser told us with what we saw on the wire.
    if browser_candidates:
        wire = {str(a) for a in seen}
        exposed = [
            c for c in browser_candidates
            if c["type"] in {"srflx", "prflx"} and c.get("address")
            and c["address"] not in wire and parse_ip(c["address"]) is not None
        ]
        global_exposed = []
        for cand in exposed:
            addr = parse_ip(cand["address"])
            if addr is None or not is_public_address(addr):
                continue
            cls = classify(config.exits, addr)
            if cls and cls.category is Category.VPN:
                continue
            global_exposed.append(cand)
            notes.append(
                f"浏览器通过 WebRTC 向页面暴露了公网地址 {addr}（{cls.label if cls else '未分类'}），"
                "检测服务未在该地址上收到报文，说明该地址属于另一条出口。"
            )
            worst = max(worst, Severity.FAIL, key=lambda s: s.rank)
        host_candidates = [
            c for c in browser_candidates
            if c["type"] == "host" and c.get("address")
            and parse_ip(c["address"]) is not None
            and not str(c["address"]).endswith(".local")
        ]
        local_only = [
            c for c in host_candidates
            if (a := parse_ip(c["address"])) is not None
            and address_scope(a) in ("private", "link_local")
        ]
        if local_only:
            addrs = "、".join(str(c["address"]) for c in local_only[:5])
            notes.append(
                f"浏览器未启用 mDNS 混淆，向网页暴露了内网地址：{addrs}。"
                "这类地址会泄露内网结构（不是公网出口泄露，但属于 WebRTC 信息暴露）。"
            )
            worst = max(worst, Severity.WARN, key=lambda s: s.rank)
        check.details.extend(notes)
        if not global_exposed and not local_only:
            check.details.append("浏览器报告的候选地址与检测服务观测到的出口一致。")

    if not check.details:
        check.details = notes
    check.severity = worst
    if worst is Severity.FAIL:
        check.remediation = ["remediation.webrtc_block", "remediation.split_tunnel"]
    elif worst is Severity.WARN:
        check.remediation = ["remediation.webrtc_block", "remediation.dns_client"]
    return check


def _browser_candidates(detail: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not detail:
        return []
    candidates = detail.get("candidates")
    if not isinstance(candidates, list):
        return []
    out = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        out.append({
            "type": str(item.get("type") or ""),
            "address": str(item.get("address") or ""),
            "port": item.get("port"),
            "protocol": str(item.get("protocol") or ""),
        })
    return out


def _check_ipv6(config: AppConfig, observations: list[Observation],
                webrtc_detail: dict[str, Any] | None) -> Check:
    check = Check(
        key="ipv6_bypass",
        title="IPv6 是否绕过隧道",
        severity=Severity.PASS,
        summary="未发现 IPv6 出口证据。",
        measured=False,
    )
    v6_obs = [
        o for o in observations
        if parse_ip(o.source_ip) is not None and parse_ip(o.source_ip).version == 6  # type: ignore[union-attr]
    ]
    candidates = [c for c in _browser_candidates(webrtc_detail)
                  if parse_ip(c.get("address") or "") is not None
                  and parse_ip(c["address"]).version == 6]  # type: ignore[union-attr]

    worst = Severity.PASS
    notes: list[str] = []
    global_v6: list[IPAddress] = []
    for obs in v6_obs:
        addr = parse_ip(obs.source_ip)
        if addr is None:
            continue
        cls = classify(config.exits, addr)
        check.measured = True
        check.evidence.append(
            Evidence("ipv6", f"{obs.channel.upper()}/IPv6", str(addr), cls.label if cls else "")
        )
        if not is_public_address(addr):
            continue
        global_v6.append(addr)
        if cls and cls.category is Category.VPN:
            continue
        notes.append(
            f"检测服务在公网 IPv6 地址 {addr}（{cls.label if cls else '未分类'}）上收到了你的流量："
            "IPv6 走了隧道之外的路径。"
        )
        worst = max(worst, Severity.FAIL, key=lambda s: s.rank)

    for cand in candidates:
        addr = parse_ip(cand["address"])
        if addr is None or not is_public_address(addr) or cand["type"] == "host":
            continue
        if str(addr) in {str(o.source_ip) for o in v6_obs}:
            continue
        cls = classify(config.exits, addr)
        if cls and cls.category is Category.VPN:
            continue
        notes.append(
            f"浏览器通过 WebRTC 暴露了公网 IPv6 地址 {addr}（{cls.label if cls else '未分类'}）。"
        )
        worst = max(worst, Severity.FAIL, key=lambda s: s.rank)

    vpn_v6 = config.exits.vpn_egress.ipv6
    if not vpn_v6:
        notes.append(
            "公司出口清单中没有 IPv6 网段：若你所在网络有公网 IPv6，"
            "任何 IPv6 流量都只能走本地链路，建议在客户端禁用 IPv6 或在隧道内做阻断。"
        )
    if worst is not Severity.PASS:
        check.summary = notes[0]
        check.details = notes
        check.severity = worst
        check.remediation = ["remediation.ipv6_disable", "remediation.split_tunnel"]
        return check

    if global_v6:
        # Only claim "through the company egress" when a company IPv6 prefix
        # actually matched; otherwise an empty address list would render as
        # "IPv6 流量经公司出口：" with nothing after it.
        check.summary = "IPv6 流量经公司出口：" + "、".join(str(a) for a in sorted_unique(global_v6))
        check.details = notes
        check.severity = Severity.PASS
        return check

    if check.measured:
        # We saw IPv6 traffic, but only on non-public addresses (link-local etc.).
        # That is not a bypass: a link-local address cannot reach the Internet, so
        # there is nothing that could have escaped the tunnel.
        check.summary = "只观测到内网/链路本地 IPv6 地址，没有公网 IPv6 出口。"
        check.severity = Severity.PASS
        check.details = notes + [
            "链路本地或内网 IPv6 地址不具备访问公网的能力，因此不构成 IPv6 泄露。"
        ]
        return check

    check.summary = "没有观测到公网 IPv6 流量（可能本机未分配 IPv6 地址）。"
    check.details = notes or [
        "未分配 IPv6 地址时，这一项天然不会泄露；如公司网络已启用 IPv6，请复测。"
    ]
    # Nothing was measured, so this cannot be "pass" — silence is not evidence.
    # Any IPv6 candidates the browser reported are graded by the disclosure check.
    check.severity = Severity.UNKNOWN
    return check


def _check_consistency(config: AppConfig, observations: list[Observation]) -> Check:
    """Do DNS, HTTP and UDP agree on the same egress?"""
    check = Check(
        key="egress_consistency",
        title="各通道出口一致性",
        severity=Severity.UNKNOWN,
        summary="通道数量不足，无法比对。",
    )
    groups: dict[str, set[IPAddress]] = {}
    for obs in observations:
        # "webrtc" records what the page was *told* about candidates, not where a
        # connection came from; comparing it with real egress would double-count.
        if obs.channel == "webrtc":
            continue
        addr = parse_ip(obs.source_ip)
        if addr is None or not is_public_address(addr):
            continue
        groups.setdefault(obs.channel, set()).add(addr)
    if len(groups) < 2:
        return check
    check.measured = True
    summary_bits = []
    vpn_set = {a for a in sum((sorted(v, key=addr_sort_key) for v in groups.values()), [])
               if (classify(config.exits, a) or Classification(a, Category.GLOBAL_UNKNOWN, "")).category
               is Category.VPN}
    outside = {
        channel: sorted(addrs - vpn_set, key=addr_sort_key)
        for channel, addrs in groups.items()
    }
    outside = {k: v for k, v in outside.items() if v}
    if not outside:
        check.severity = Severity.PASS
        check.summary = "HTTP、DNS、UDP 均从公司出口发出。"
        return check

    outside_channels = set(outside)
    if outside_channels == set(groups):
        # Every channel left through the same non-corporate address: that is one
        # deliberate exit (full tunnel to somewhere else, or no tunnel at all),
        # not an inconsistency. Reporting it as "split brain" would point IT at
        # the wrong control.
        check.severity = Severity.WARN
        check.summary = "所有通道都从同一个非公司出口发出，更像是整体未使用公司 VPN。"
        check.details = [
            "各协议出口一致，说明不是分流规则漏配，而是整条连接没有进入公司隧道。",
            "请确认 VPN 客户端处于「已连接」状态、账号未过期，并且用的是公司配置。",
        ]
        check.remediation = ["remediation.not_connected", "remediation.split_tunnel"]
        return check

    for channel, addrs in outside.items():
        summary_bits.append(f"{channel}: " + "、".join(str(a) for a in addrs))
    check.severity = Severity.FAIL
    check.summary = "存在不一致的出口：" + "；".join(summary_bits)
    check.details = [
        "同一个客户端的不同协议走了不同出口，说明分流（split tunnel）规则只覆盖了部分流量。",
        "请按下方的分流配置建议，把这些协议统一纳入隧道。",
    ]
    check.remediation = ["remediation.split_tunnel"]
    return check


def _check_webrtc_disclosure(config: AppConfig,
                             webrtc_detail: dict[str, Any] | None) -> Check:
    check = Check(
        key="webrtc_disclosure",
        title="浏览器实时通信接口暴露",
        severity=Severity.UNKNOWN,
        summary="未收到浏览器的 WebRTC 候选信息。",
    )
    if not webrtc_detail:
        check.details = [
            "浏览器可能不支持 WebRTC、被企业策略禁用，或页面不在 HTTPS 安全上下文中。"
        ]
        check.remediation = ["remediation.webrtc_blocked"]
        return check
    if webrtc_detail.get("error"):
        check.summary = f"WebRTC 检测未完成：{webrtc_detail['error']}"
        check.details = [
            "浏览器拒绝创建 RTCPeerConnection。常见原因是页面不是 HTTPS（非安全上下文）"
            "或企业策略（WebRtcLocalIpsAllowedUrls / WebRtcIPHandling）禁止。"
        ]
        check.remediation = ["remediation.webrtc_blocked"]
        return check

    candidates = _browser_candidates(webrtc_detail)
    if not candidates:
        check.summary = "浏览器完成了候选收集，但没有得到任何候选地址。"
        check.details = ["全部候选为 mDNS 混淆地址或收集超时，通常说明暴露面已被收紧。"]
        check.severity = Severity.PASS
        return check
    check.measured = True
    public = [c for c in candidates
              if (a := parse_ip(c["address"])) is not None and is_public_address(a)]
    masked = [c for c in candidates if not c["address"] or c["address"].endswith(".local")]
    private = [c for c in candidates
               if (a := parse_ip(c["address"])) is not None
               and address_scope(a) in ("private", "link_local")]
    for cand in candidates:
        check.evidence.append(
            Evidence(
                "webrtc",
                f"候选 {cand['type'] or '?'}/{cand['protocol'] or '?'}",
                str(cand["address"] or "-") + (f":{cand['port']}" if cand.get("port") else ""),
                "",
            )
        )
    # A public candidate that *is* the company exit address is not a real leak:
    # every site the employee visits already sees that NAT address. It only
    # becomes a finding when it reveals an exit the employee should not have.
    foreign_public = []
    for cand in public:
        addr = parse_ip(cand["address"])
        cls = classify(config.exits, addr) if addr else None
        if cls and cls.category in (Category.VPN, Category.CORP_RESOLVER):
            continue
        foreign_public.append(cand)
    details = []
    if public and not foreign_public:
        details.append(
            "公网候选地址在公司出口清单内（" + "、".join(str(c["address"]) for c in public)
            + "），与网页请求出口一致，不构成额外泄露。"
        )
    if foreign_public:
        details.append(
            "浏览器向页面暴露了不属于公司出口的公网地址："
            + "、".join(str(c["address"]) for c in foreign_public)
            + "。任何能读取该页面的脚本都能拿到它。"
        )
    if private:
        details.append(
            "浏览器暴露了内网地址：" + "、".join(str(c["address"]) for c in private)
            + "（未做 mDNS 混淆）。"
        )
    if masked:
        details.append(f"{len(masked)} 个本地候选已做 mDNS 混淆（.local），不会泄露内网地址。")
    check.details = details
    if foreign_public:
        check.severity = Severity.WARN
        check.summary = ("通过 WebRTC 暴露了非公司出口的公网地址："
                         + "、".join(str(c["address"]) for c in foreign_public))
        check.remediation = ["remediation.webrtc_block"]
    elif private:
        check.severity = Severity.WARN
        check.summary = "通过 WebRTC 暴露了内网地址（未混淆）。"
        check.remediation = ["remediation.webrtc_block"]
    else:
        check.severity = Severity.PASS
        check.summary = (
            "WebRTC 未暴露额外地址（候选与公司出口一致或仅 mDNS 混淆候选）。"
        )
    return check


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def detect_os(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if "android" in ua:
        return "android"
    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        return "ios"
    if "cros" in ua:
        return "chromeos"
    if "windows" in ua:
        return "windows"
    if "macintosh" in ua or "mac os x" in ua:
        return "macos"
    if "linux" in ua:
        return "linux"
    return "unknown"


def evaluate(config: AppConfig, session: Session,
             observations: list[Observation]) -> Report:
    from .remediation import build_remediation

    observations = _dedupe(observations)
    webrtc_detail = None
    for obs in observations:
        if obs.channel == "webrtc":
            webrtc_detail = obs.detail
    client_ip = parse_ip(session.peer_ip)
    client_class = classify(config.exits, client_ip)
    os_family = detect_os(session.user_agent)

    checks = [
        _check_http(config, observations),
        _check_dns(config, observations),
        _check_udp(config, observations, webrtc_detail),
        _check_webrtc_disclosure(config, webrtc_detail),
        _check_ipv6(config, observations, webrtc_detail),
        _check_consistency(config, observations),
    ]
    for check in checks:
        check.remediation = build_remediation(check.key, check.severity, os_family, check.remediation)

    return Report(
        checks=checks,
        session=session,
        observations=observations,
        client_ip=client_ip,
        client_class=client_class,
        os_family=os_family,
        generated_at=session.created_at,
    )
