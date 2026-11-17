"""IP 地址分类和公司出口地址表。

地址表由配置中的 ``[[egress]]`` 条目构建，每条规则带若干标签：

``corporate``
    视为公司（VPN）出口。命中该标签的地址视为期望出口。
``dns``
    视为公司 DNS 的对外出口/解析器地址。DNS 探测只会看到递归解析器的
    出口地址，因此公司 DNS 的对外出口需要单独列出（通常和 VPN 出口相同）。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

CORPORATE_TAG = "corporate"
DNS_TAG = "dns"

# 常见公共解析器，只用于给结果加可读标签，不参与判定。
KNOWN_PUBLIC_RESOLVERS: dict[str, str] = {
    # IPv4
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare 1.1.1.1",
    "1.0.0.1": "Cloudflare 1.1.1.1",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "114.114.114.114": "114 DNS",
    "114.114.115.115": "114 DNS",
    "223.5.5.5": "阿里公共 DNS",
    "223.6.6.6": "阿里公共 DNS",
    "119.29.29.29": "腾讯 DNSPod",
    "182.254.116.116": "腾讯 DNSPod",
    "180.76.76.76": "百度公共 DNS",
    "76.76.2.0": "Control D",
    "94.140.14.14": "AdGuard DNS",
    # IPv6
    "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS",
    "2606:4700:4700::1111": "Cloudflare 1.1.1.1",
    "2606:4700:4700::1001": "Cloudflare 1.1.1.1",
    "2620:fe::fe": "Quad9",
    "2620:fe::9": "Quad9",
    "2400:3200::1": "阿里公共 DNS",
    "2400:3200:baba::1": "阿里公共 DNS",
    "2402:4e00::": "腾讯 DNSPod",
    "2a10:50c0::ad1:ff": "AdGuard DNS",
}

_DOC_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def parse_ip(value: str | None) -> IPAddress | None:
    """解析单个 IP，非法时返回 ``None``。"""
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def ip_family(ip: IPAddress | None) -> int | None:
    return None if ip is None else ip.version


def is_public(ip: IPAddress) -> bool:
    """是否为可在公网路由的单播地址。"""
    if not ip.is_global:
        return False
    return not any(ip in net for net in _DOC_NETWORKS if net.version == ip.version)


def is_cgnat(ip: IPAddress) -> bool:
    return ip.version == 4 and ip in _CGNAT


def classify_address(ip: IPAddress) -> str:
    """给地址一个中文分类标签。"""
    if ip.is_loopback:
        return "回环地址"
    if ip.is_link_local:
        return "链路本地地址"
    if ip.is_multicast:
        return "组播地址"
    if ip.is_unspecified:
        return "未指定地址"
    if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"):
        return "IPv6 内网地址 (ULA)"
    if is_cgnat(ip):
        return "运营商级 NAT 地址 (CGNAT)"
    if any(ip in net for net in _DOC_NETWORKS if net.version == ip.version):
        return "文档示例地址"
    if ip.is_private:
        return "内网地址 (RFC1918)"
    if ip.is_reserved:
        return "保留地址"
    if is_public(ip):
        return "公网地址"
    return "非公网地址"


def known_resolver_name(ip: IPAddress) -> str | None:
    return KNOWN_PUBLIC_RESOLVERS.get(str(ip))


@dataclass(frozen=True)
class NetworkRule:
    """一条出口/解析器地址段规则。"""

    network: IPNetwork
    label: str
    tags: frozenset[str]

    @property
    def cidr(self) -> str:
        return str(self.network)

    @property
    def family(self) -> int:
        return self.network.version

    def matches(self, ip: IPAddress) -> bool:
        return ip.version == self.network.version and ip in self.network


class EgressTable:
    """按最长前缀匹配的地址表。"""

    def __init__(self, rules: Iterable[NetworkRule] = ()):
        # 前缀越长越具体，匹配时优先。
        self._rules: tuple[NetworkRule, ...] = tuple(
            sorted(rules, key=lambda r: (r.family, -r.network.prefixlen))
        )

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[NetworkRule, ...]:
        return self._rules

    def match(self, ip: IPAddress | None, tag: str | None = None) -> NetworkRule | None:
        if ip is None:
            return None
        for rule in self._rules:
            if tag is not None and tag not in rule.tags:
                continue
            if rule.matches(ip):
                return rule
        return None

    def is_corporate(self, ip: IPAddress | None) -> bool:
        return self.match(ip, CORPORATE_TAG) is not None

    def is_expected_dns(self, ip: IPAddress | None) -> bool:
        """DNS 来源地址是否在公司允许范围内（公司出口或公司 DNS 出口）。"""
        return self.match(ip, CORPORATE_TAG) is not None or self.match(ip, DNS_TAG) is not None

    def describe(self, ip: IPAddress | None) -> str:
        """返回可读描述，例如 ``公司 VPN 出口（203.0.113.0/24）``。"""
        if ip is None:
            return "未知地址"
        rule = self.match(ip)
        if rule is not None:
            return f"{rule.label}（{rule.cidr}）"
        resolver = known_resolver_name(ip)
        if resolver:
            return f"{classify_address(ip)}，常见公共解析器：{resolver}"
        return classify_address(ip)
