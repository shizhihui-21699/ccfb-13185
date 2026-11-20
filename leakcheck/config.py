"""Configuration model and loader for the VPN leak self-check service.

Everything an operator may need to tune lives in one YAML file (see
``config.example.yaml``).  The dataclasses below validate it at start-up and
fail loudly with a readable message, because a wrong exit-address list would
silently turn every healthy machine into a "leak" (or vice versa).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .netutil import IPAddress, IPNetwork, parse_networks

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# Public "open" resolvers.  Seeing one of these as the source of our probe
# query normally means the endpoint talked to a public resolver directly, so
# the query did not use the corporate resolver path.
DEFAULT_PUBLIC_RESOLVERS: dict[str, list[str]] = {
    "Google": ["8.8.8.8/32", "8.8.4.4/32", "2001:4860:4860::8888/128", "2001:4860:4860::8844/128"],
    "Cloudflare": ["1.1.1.1/32", "1.0.0.1/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128"],
    "Quad9": ["9.9.9.9/32", "149.112.112.112/32", "2620:fe::fe/128", "2620:fe::9/128"],
    "OpenDNS": ["208.67.222.222/32", "208.67.220.220/32"],
    "AdGuard": ["94.140.14.14/32", "94.140.15.15/32"],
    "Yandex": ["77.88.8.8/32", "77.88.8.1/32"],
    "Comodo": ["8.26.56.26/32", "8.20.247.20/32"],
    "DNS.SB": ["185.222.222.222/32", "45.11.45.11/32"],
}

# Addresses that must never be treated as "a usable public egress" in the
# browser-visible channels (link-local / LLMNR / mDNS-style or internal
# scaffolding that VPN clients sometimes leave on an adapter).
DEFAULT_IGNORED_RANGES = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "192.0.0.0/24",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "::/128",
    "64:ff9b:1::/48",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]


class ConfigError(ValueError):
    """Raised when the YAML configuration is unusable."""


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} 必须是键值映射，实际是 {type(value).__name__}")
    return value


def _as_int(value: Any, where: str, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where} 必须是整数") from exc
    if number < minimum:
        raise ConfigError(f"{where} 不能小于 {minimum}")
    if maximum is not None and number > maximum:
        raise ConfigError(f"{where} 不能大于 {maximum}")
    return number


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass(slots=True)
class NetworkList:
    """A named set of addresses with a human description."""

    name: str
    description: str
    networks: list[IPNetwork]

    @property
    def ipv4(self) -> list[IPNetwork]:
        return [n for n in self.networks if n.version == 4]

    @property
    def ipv6(self) -> list[IPNetwork]:
        return [n for n in self.networks if n.version == 6]


@dataclass(slots=True)
class ExitInventory:
    """The address lists a compliant endpoint is expected to appear from."""

    vpn_egress: NetworkList
    corp_resolvers: NetworkList
    office_egress: NetworkList
    known_third_party_resolvers: dict[str, list[IPNetwork]] = field(default_factory=dict)
    ignored_ranges: list[IPNetwork] = field(default_factory=list)

    def public_resolver_name(self, addr: IPAddress) -> str | None:
        for vendor, networks in self.known_third_party_resolvers.items():
            for network in networks:
                if network.version == addr.version and addr in network:
                    return vendor
        return None

    def in_vpn_egress(self, addr: IPAddress | None) -> bool:
        return _in_any(self.vpn_egress.networks, addr)

    def in_corp_resolvers(self, addr: IPAddress | None) -> bool:
        return _in_any(self.corp_resolvers.networks, addr)

    def in_office_egress(self, addr: IPAddress | None) -> bool:
        return _in_any(self.office_egress.networks, addr)

    def is_ignored(self, addr: IPAddress | None) -> bool:
        return _in_any(self.ignored_ranges, addr)


def _in_any(networks: list[IPNetwork], addr: IPAddress | None) -> bool:
    if addr is None:
        return False
    return any(n.version == addr.version and addr in n for n in networks)


@dataclass(slots=True)
class ServerConfig:
    public_base_url: str
    collector_bind: str
    collector_port: int
    trusted_proxies: list[IPNetwork]
    session_ttl_seconds: int
    max_probes: int
    rate_limit_per_minute: int
    database_path: str
    hmac_secret: bytes
    allowed_origins: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DnsConfig:
    enabled: bool
    bind_host: str
    bind_port: int
    zone: str
    answer_ipv4: list[ipaddress.IPv4Address]
    answer_ipv6: list[ipaddress.IPv6Address]
    answer_ttl: int
    probe_token_ttl: int
    reflect_ecs_prefix: int
    echo_form: bool
    max_udp_payload: int
    worker_threads: int


@dataclass(slots=True)
class StunConfig:
    enabled: bool
    bind_host: str
    ports: list[int]
    public_ips: list[str]
    bind_ipv6: bool = True


@dataclass(slots=True)
class HttpProbeConfig:
    """TLS-only hostnames embedded in user-space protocols (QUIC/DoH)."""

    doh_endpoints: list[str]
    quic_probe_urls: list[str]


@dataclass(slots=True)
class RemediationConfig:
    support_contact: str
    support_url: str
    org_name: str
    internal_dns_servers: list[str]
    internal_ca_url: str


@dataclass(slots=True)
class AppConfig:
    site_title: str
    probe_domain: str
    server: ServerConfig
    dns: DnsConfig
    stun: StunConfig
    http_probe: HttpProbeConfig
    exits: ExitInventory
    remediation: RemediationConfig
    raw: dict[str, Any] = field(default_factory=dict)

    def probe_hostname(self, token: str) -> str:
        return f"{token}.{self.probe_domain}"


def _network_list(raw: Any, key: str, default_desc: str) -> NetworkList:
    mapping = _require_mapping(raw, key)
    values = mapping.get("addresses", [])
    if not isinstance(values, list):
        raise ConfigError(f"{key}.addresses 必须是列表")
    try:
        networks = parse_networks(values)
    except ValueError as exc:
        raise ConfigError(f"{key}.addresses 含非法地址: {exc}") from exc
    return NetworkList(
        name=str(mapping.get("name") or default_desc),
        description=str(mapping.get("description") or default_desc),
        networks=networks,
    )


def load_config(path: str | os.PathLike[str] | None = None) -> AppConfig:
    """Load and validate configuration from *path* (or ``LEAKCHECK_CONFIG``)."""
    path = Path(path or os.environ.get("LEAKCHECK_CONFIG", "config.yaml"))
    if not path.exists():
        example = path.with_name("config.example.yaml")
        hint = f"，可先复制 {example} 为 {path} 后修改" if example.exists() else ""
        raise ConfigError(f"找不到配置文件 {path}{hint}")
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    return config_from_dict(_require_mapping(raw, str(path)), path)


def config_from_dict(raw: dict[str, Any], path: Path | None = None) -> AppConfig:
    site = _require_mapping(raw.get("site") or {}, "site")
    domain = str(site.get("probe_domain") or "").strip().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ConfigError(
            "site.probe_domain 必须是委托给检测服务的完整域名，例如 probe.example-corp.net"
        )

    server_raw = _require_mapping(raw.get("server") or {}, "server")
    collector_bind = str(server_raw.get("collector_bind") or "127.0.0.1")
    collector_port = _as_int(server_raw.get("collector_port", 8081), "server.collector_port", 1, 65535)
    public_base_url = str(server_raw.get("public_base_url") or "").strip().rstrip("/")
    if not public_base_url:
        public_base_url = f"http://{collector_bind}:{collector_port}"
    try:
        trusted = parse_networks(server_raw.get("trusted_proxies", ["127.0.0.0/8", "::1/128"]))
    except ValueError as exc:
        raise ConfigError(f"server.trusted_proxies: {exc}") from exc

    secret_raw = server_raw.get("hmac_secret") or os.environ.get("LEAKCHECK_HMAC_SECRET")
    if secret_raw:
        hmac_secret = str(secret_raw).encode()
    else:
        # Ephemeral secret keeps a dev instance working; production must set one
        # so tokens survive restarts and can be validated by every worker.
        hmac_secret = secrets.token_bytes(32)

    server = ServerConfig(
        public_base_url=public_base_url,
        collector_bind=collector_bind,
        collector_port=collector_port,
        trusted_proxies=trusted,
        session_ttl_seconds=_as_int(server_raw.get("session_ttl_seconds", 900), "server.session_ttl_seconds", 60, 86400),
        max_probes=_as_int(server_raw.get("max_probes", 24), "server.max_probes", 1, 200),
        rate_limit_per_minute=_as_int(server_raw.get("rate_limit_per_minute", 60), "server.rate_limit_per_minute", 1),
        database_path=str(server_raw.get("database_path") or "data/leakcheck.db"),
        hmac_secret=hmac_secret,
        allowed_origins=_str_list(server_raw.get("allowed_origins", ["*"])) or ["*"],
    )

    dns_raw = _require_mapping(raw.get("dns") or {}, "dns")
    zone = str(dns_raw.get("zone") or domain).strip().rstrip(".")
    if zone != domain:
        raise ConfigError("dns.zone 必须与 site.probe_domain 相同（探针子域直接挂在它下面）")
    answer_v4 = dns_raw.get("answer_ipv4") or ["203.0.113.10"]
    answer_v6 = dns_raw.get("answer_ipv6") or []
    try:
        v4 = [ipaddress.IPv4Address(str(a)) for a in answer_v4]
        v6 = [ipaddress.IPv6Address(str(a)) for a in answer_v6]
    except ValueError as exc:
        raise ConfigError(f"dns.answer_ipv4/answer_ipv6: {exc}") from exc
    dns = DnsConfig(
        enabled=_as_bool(dns_raw.get("enabled", True)),
        bind_host=str(dns_raw.get("bind_host") or "0.0.0.0"),
        bind_port=_as_int(dns_raw.get("bind_port", 53), "dns.bind_port", 0, 65535),
        zone=zone,
        answer_ipv4=v4,
        answer_ipv6=v6,
        answer_ttl=_as_int(dns_raw.get("answer_ttl", 0), "dns.answer_ttl", 0, 86400),
        probe_token_ttl=_as_int(dns_raw.get("probe_token_ttl", 600), "dns.probe_token_ttl", 30, 86400),
        reflect_ecs_prefix=_as_int(dns_raw.get("reflect_ecs_prefix", 0), "dns.reflect_ecs_prefix", 0, 128),
        echo_form=_as_bool(dns_raw.get("echo_form", True)),
        max_udp_payload=_as_int(dns_raw.get("max_udp_payload", 1400), "dns.max_udp_payload", 512, 4096),
        worker_threads=_as_int(dns_raw.get("worker_threads", 8), "dns.worker_threads", 1, 128),
    )

    stun_raw = _require_mapping(raw.get("stun") or {}, "stun")
    ports_raw = stun_raw.get("ports") or list(range(3478, 3490))
    if not isinstance(ports_raw, list) or not ports_raw:
        raise ConfigError("stun.ports 必须是非空端口列表")
    ports = [_as_int(p, "stun.ports 元素", 0, 65535) for p in ports_raw]
    stun = StunConfig(
        enabled=_as_bool(stun_raw.get("enabled", True)),
        bind_host=str(stun_raw.get("bind_host") or "0.0.0.0"),
        ports=ports,
        public_ips=[str(ip) for ip in (stun_raw.get("public_ips") or [])],
        bind_ipv6=_as_bool(stun_raw.get("bind_ipv6", True)),
    )

    http_raw = _require_mapping(raw.get("http_probe") or {}, "http_probe")
    http_probe = HttpProbeConfig(
        doh_endpoints=_str_list(http_raw.get("doh_endpoints")),
        quic_probe_urls=_str_list(http_raw.get("quic_probe_urls")),
    )

    exits_raw = _require_mapping(raw.get("exit_inventory") or {}, "exit_inventory")
    vpn = _network_list(exits_raw.get("vpn_egress") or {"addresses": []}, "exit_inventory.vpn_egress", "公司 VPN 出口")
    corp_dns = _network_list(
        exits_raw.get("corp_resolvers") or {"addresses": []},
        "exit_inventory.corp_resolvers",
        "公司递归解析器出口",
    )
    office = _network_list(
        exits_raw.get("office_egress") or {"addresses": []},
        "exit_inventory.office_egress",
        "办公网直出",
    )
    if not vpn.networks:
        raise ConfigError(
            "exit_inventory.vpn_egress.addresses 不能为空：没有对照列表就无法判断是否泄露"
        )
    third_party: dict[str, list[IPNetwork]] = {}
    tp_raw = exits_raw.get("known_third_party_resolvers")
    if tp_raw is None:
        tp_raw = DEFAULT_PUBLIC_RESOLVERS
    elif isinstance(tp_raw, list) and not tp_raw:
        tp_raw = {}
    else:
        tp_raw = _require_mapping(tp_raw, "exit_inventory.known_third_party_resolvers")
    for vendor, values in tp_raw.items():
        try:
            third_party[str(vendor)] = parse_networks(_str_list(values))
        except ValueError as exc:
            raise ConfigError(f"exit_inventory.known_third_party_resolvers.{vendor}: {exc}") from exc
    ignored_raw = exits_raw.get("ignored_ranges")
    try:
        ignored = parse_networks(_str_list(ignored_raw) if ignored_raw is not None else DEFAULT_IGNORED_RANGES)
    except ValueError as exc:
        raise ConfigError(f"exit_inventory.ignored_ranges: {exc}") from exc

    exits = ExitInventory(
        vpn_egress=vpn,
        corp_resolvers=corp_dns,
        office_egress=office,
        known_third_party_resolvers=third_party,
        ignored_ranges=ignored,
    )

    rem_raw = _require_mapping(raw.get("remediation") or {}, "remediation")
    remediation = RemediationConfig(
        support_contact=str(rem_raw.get("support_contact") or "IT 服务台"),
        support_url=str(rem_raw.get("support_url") or ""),
        org_name=str(rem_raw.get("org_name") or "公司"),
        internal_dns_servers=_str_list(rem_raw.get("internal_dns_servers")),
        internal_ca_url=str(rem_raw.get("internal_ca_url") or ""),
    )

    return AppConfig(
        site_title=str(site.get("title") or "VPN 流量泄露自检"),
        probe_domain=domain,
        server=server,
        dns=dns,
        stun=stun,
        http_probe=http_probe,
        exits=exits,
        remediation=remediation,
        raw=raw,
    )


def _str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise ConfigError(f"期望字符串列表，实际是 {type(value).__name__}")


def redacted_dump(config: AppConfig) -> dict[str, Any]:
    """Serialise config for the diagnostics page without leaking the HMAC key."""
    data = dataclasses.asdict(config)
    data.pop("raw", None)
    data["server"].pop("hmac_secret", None)
    for key in ("networks",):
        for section in ("vpn_egress", "corp_resolvers", "office_egress"):
            data["exits"][section][key] = [str(n) for n in data["exits"][section][key]]
    data["exits"]["ignored_ranges"] = [str(n) for n in data["exits"]["ignored_ranges"]]
    data["exits"]["known_third_party_resolvers"] = {
        k: [str(n) for n in v] for k, v in data["exits"]["known_third_party_resolvers"].items()
    }
    data["dns"]["answer_ipv4"] = [str(a) for a in data["dns"]["answer_ipv4"]]
    data["dns"]["answer_ipv6"] = [str(a) for a in data["dns"]["answer_ipv6"]]
    data["server"]["trusted_proxies"] = [str(n) for n in data["server"]["trusted_proxies"]]
    return data
