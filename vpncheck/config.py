"""配置加载与校验。

配置使用 TOML（Python 3.11+ 标准库 ``tomllib``）。所有地址段、URL 和
监听参数都在启动时校验，出错时给出中文错误信息，避免带着半截配置上线。
"""

from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .nets import CORPORATE_TAG, DNS_TAG, EgressTable, IPNetwork, NetworkRule

DEFAULT_CONFIG_PATH = "config.toml"
ENV_CONFIG_PATH = "VPNCHECK_CONFIG"

_DOC_PREFIXES = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_LABEL = r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")
_URL_RE = re.compile(r"^https?://[^\s/]+(/[^\s]*)?$")


class ConfigError(ValueError):
    """配置不合法。"""


def _section(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, Mapping):
        raise ConfigError(f"[{name}] 必须是一个配置段")
    return value


def _string(
    section: Mapping[str, Any],
    key: str,
    *,
    where: str,
    default: str | None = None,
    required: bool = False,
) -> str | None:
    value = section.get(key, default)
    if value is None:
        if required:
            raise ConfigError(f"{where}.{key} 未设置")
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{where}.{key} 必须是字符串")
    value = value.strip()
    if not value:
        if required:
            raise ConfigError(f"{where}.{key} 不能为空")
        return None
    return value


def _integer(
    section: Mapping[str, Any],
    key: str,
    *,
    where: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}.{key} 必须是整数")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{where}.{key} 必须在 {minimum}..{maximum} 之间，当前为 {value}")
    return value


def _number(
    section: Mapping[str, Any],
    key: str,
    *,
    where: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}.{key} 必须是数字")
    value = float(value)
    if not minimum <= value <= maximum:
        raise ConfigError(f"{where}.{key} 必须在 {minimum}..{maximum} 之间，当前为 {value}")
    return value


def _boolean(section: Mapping[str, Any], key: str, *, where: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} 必须是 true 或 false")
    return value


def _string_list(
    section: Mapping[str, Any], key: str, *, where: str, default: tuple[str, ...] = ()
) -> tuple[str, ...]:
    value = section.get(key, list(default))
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{where}.{key} 必须是字符串数组")
    return tuple(item.strip() for item in value if item.strip())


def _networks(section: Mapping[str, Any], key: str, *, where: str) -> tuple[IPNetwork, ...]:
    raw = section.get(key)
    if raw is None:
        raw = []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ConfigError(f"{where}.{key} 必须是 CIDR 字符串或字符串数组")
    networks: list[IPNetwork] = []
    for item in raw:
        try:
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError as exc:
            raise ConfigError(f"{where}.{key} 中的 {item!r} 不是合法 CIDR：{exc}") from exc
        if network.prefixlen == 0:
            raise ConfigError(f"{where}.{key} 不能包含 0.0.0.0/0 或 ::/0")
        networks.append(network)
    return tuple(networks)


def _url(value: str | None, *, where: str, allow_none: bool = True) -> str | None:
    if value is None:
        if allow_none:
            return None
        raise ConfigError(f"{where} 未设置")
    if not _URL_RE.match(value):
        raise ConfigError(f"{where} 必须是 http(s) URL，当前为 {value!r}")
    return value.rstrip("/")


def _uri_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _host_from_url(url: str) -> str | None:
    """从 URL 中取出主机名（不含端口），失败返回 ``None``。"""
    match = re.match(r"^https?://(\[[^\]]+\]|[^/:\s]+)", url or "")
    if not match:
        return None
    host = match.group(1)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host or None


def _host(value: str | None, *, where: str, default: str) -> str:
    host = (value or default).strip()
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        if host not in {"localhost"}:
            raise ConfigError(f"{where} 必须是 IP 地址，当前为 {host!r}") from exc
    return host


def _domain(value: str | None, *, where: str) -> str:
    if not value:
        raise ConfigError(f"{where} 未设置")
    value = value.strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(value):
        raise ConfigError(f"{where} 不是合法域名：{value!r}")
    return value


@dataclass(frozen=True)
class AppConfig:
    title: str
    public_url: str | None
    allowed_origins: tuple[str, ...]
    session_ttl_seconds: int
    poll_interval_seconds: float
    privacy_notice_url: str | None
    helpdesk_contact: str | None


@dataclass(frozen=True)
class CollectorConfig:
    listen_host: str
    listen_port: int
    listen_host_v6: str | None
    listen_port_v6: int | None
    public_url_v4: str
    public_url_v6: str | None
    script_url: str
    trust_forwarded_for: bool
    trusted_proxies: tuple[IPNetwork, ...]

    @property
    def listeners(self) -> tuple[tuple[str, int], ...]:
        out = [(self.listen_host, self.listen_port)]
        if self.listen_host_v6:
            out.append((self.listen_host_v6, self.listen_port_v6 or self.listen_port))
        return tuple(out)


@dataclass(frozen=True)
class DnsConfig:
    enabled: bool
    zone: str
    listen_host: str
    listen_port: int
    listen_host_v6: str | None
    listen_port_v6: int | None
    answer_ipv4: tuple[str, ...]
    answer_ipv6: tuple[str, ...]
    ttl: int
    wait_seconds: float

    @property
    def listeners(self) -> tuple[tuple[str, int], ...]:
        out = [(self.listen_host, self.listen_port)]
        if self.listen_host_v6:
            out.append((self.listen_host_v6, self.listen_port_v6 or self.listen_port))
        return tuple(out)


@dataclass(frozen=True)
class StunConfig:
    enabled: bool
    listen_host: str
    listen_port: int
    listen_host_v6: str | None
    listen_port_v6: int | None
    public_host_v4: str
    public_port_v4: int
    public_host_v6: str | None
    public_port_v6: int | None
    port_range_base: int
    port_range_size: int

    @property
    def full_uris(self) -> tuple[str, ...]:
        out = [f"stun:{_uri_host(self.public_host_v4)}:{self.public_port_v4}"]
        if self.public_host_v6:
            out.append(f"stun:{_uri_host(self.public_host_v6)}:{self.public_port_v6}")
        return tuple(out)

    @property
    def port_range(self) -> tuple[int, int] | None:
        if self.port_range_size <= 0:
            return None
        return self.port_range_base, self.port_range_base + self.port_range_size - 1

    @property
    def can_probe(self) -> bool:
        return self.port_range_size > 0


@dataclass(frozen=True)
class PolicyConfig:
    app_requires_tunnel: bool


@dataclass(frozen=True)
class ProbesConfig:
    """探针在哪里运行。

    ``embedded``：与 Streamlit 同进程启动（单机、最省事）。
    ``external``：由 ``scripts/run_probes.py`` 或其他进程常驻，页面只读取
    共享的 SQLite；适合 53/3478 端口需要单独规划或采集端要横向扩展的部署。
    """

    mode: str

    @property
    def embedded(self) -> bool:
        return self.mode == "embedded"


@dataclass(frozen=True)
class EgressEntry:
    name: str
    networks: tuple[IPNetwork, ...]
    corporate: bool
    dns: bool

    def rules(self) -> tuple[NetworkRule, ...]:
        tags: set[str] = set()
        if self.corporate:
            tags.add(CORPORATE_TAG)
        if self.dns:
            tags.add(DNS_TAG)
        frozen = frozenset(tags)
        return tuple(NetworkRule(network=n, label=self.name, tags=frozen) for n in self.networks)


@dataclass(frozen=True)
class Config:
    app: AppConfig
    collector: CollectorConfig
    dns: DnsConfig
    stun: StunConfig
    policy: PolicyConfig
    probes: ProbesConfig
    egress: tuple[EgressEntry, ...]
    table: EgressTable
    source_path: Path

    @property
    def uses_documentation_addresses(self) -> bool:
        """出口表是否仍在使用 RFC 5737 / RFC 3849 示例地址。"""
        for entry in self.egress:
            for network in entry.networks:
                if any(
                    network.version == doc.version and network.subnet_of(doc)
                    for doc in _DOC_PREFIXES
                ):
                    return True
        return False

    @property
    def has_corporate_v6(self) -> bool:
        return any(rule.family == 6 for rule in self.table.rules if CORPORATE_TAG in rule.tags)

    def summary(self) -> str:
        parts = []
        for entry in self.egress:
            kinds = []
            if entry.corporate:
                kinds.append("公司出口")
            if entry.dns:
                kinds.append("DNS 出口")
            parts.append(
                f"{entry.name}（{'/'.join(kinds) or '公共解析器'}）："
                + ", ".join(str(n) for n in entry.networks)
            )
        return "；".join(parts) if parts else "未配置任何出口地址"


def _load_app(data: Mapping[str, Any]) -> AppConfig:
    section = _section(data, "app")
    where = "[app]"
    origins = _string_list(section, "allowed_origins", where=where)
    public_url = _url(_string(section, "public_url", where=where), where=f"{where}.public_url")
    if public_url and not origins:
        origins = (public_url,)
    if not origins:
        raise ConfigError("[app].allowed_origins 未设置，且无法从 public_url 推导")
    for origin in origins:
        if not _URL_RE.match(origin):
            raise ConfigError(f"[app].allowed_origins 中的 {origin!r} 不是合法 URL")
    return AppConfig(
        title=_string(section, "title", where=where, default="公司 VPN 泄露自检") or "公司 VPN 泄露自检",
        public_url=public_url,
        allowed_origins=tuple(origin.rstrip("/") for origin in origins),
        session_ttl_seconds=_integer(
            section, "session_ttl_seconds", where=where, default=900, minimum=120, maximum=86400
        ),
        poll_interval_seconds=_number(
            section, "poll_interval_seconds", where=where, default=1.0, minimum=0.5, maximum=10.0
        ),
        privacy_notice_url=_url(
            _string(section, "privacy_notice_url", where=where),
            where=f"{where}.privacy_notice_url",
        ),
        helpdesk_contact=_string(section, "helpdesk_contact", where=where),
    )


def _load_collector(data: Mapping[str, Any]) -> CollectorConfig:
    section = _section(data, "collector")
    where = "[collector]"
    public_v4 = _url(
        _string(section, "public_url_v4", where=where, required=True),
        where=f"{where}.public_url_v4",
        allow_none=False,
    )
    assert public_v4 is not None
    host_v6 = _string(section, "listen_host_v6", where=where)
    port_v6 = section.get("listen_port_v6")
    if host_v6 is None:
        if port_v6 is not None:
            raise ConfigError("[collector].listen_port_v6 已设置，但 listen_host_v6 未设置")
        v6_port: int | None = None
    else:
        _host(host_v6, where=f"{where}.listen_host_v6", default="::")
        v6_port = _integer(
            section, "listen_port_v6", where=where, default=8090, minimum=0, maximum=65535
        )
    return CollectorConfig(
        listen_host=_host(
            _string(section, "listen_host", where=where), where=f"{where}.listen_host", default="0.0.0.0"
        ),
        listen_port=_integer(
            section, "listen_port", where=where, default=8090, minimum=0, maximum=65535
        ),
        listen_host_v6=host_v6,
        listen_port_v6=v6_port,
        public_url_v4=public_v4,
        public_url_v6=_url(
            _string(section, "public_url_v6", where=where), where=f"{where}.public_url_v6"
        ),
        script_url=(
            _url(_string(section, "script_url", where=where), where=f"{where}.script_url")
            or public_v4 + "/probe/client.js"
        ),
        trust_forwarded_for=_boolean(section, "trust_forwarded_for", where=where, default=False),
        trusted_proxies=_networks(section, "trusted_proxies", where=where),
    )


def _load_dns(data: Mapping[str, Any]) -> DnsConfig:
    section = _section(data, "dns")
    where = "[dns]"
    enabled = _boolean(section, "enabled", where=where, default=True)
    zone = _string(section, "zone", where=where)
    zone = _domain(zone, where=f"{where}.zone") if enabled else (zone or "invalid.invalid")
    answers4 = _string_list(section, "answer_ipv4", where=where)
    answers6 = _string_list(section, "answer_ipv6", where=where)
    for value in answers4:
        try:
            if ipaddress.ip_address(value).version != 4:
                raise ValueError("不是 IPv4")
        except ValueError as exc:
            raise ConfigError(f"[dns].answer_ipv4 中的 {value!r} 不合法：{exc}") from exc
    for value in answers6:
        try:
            if ipaddress.ip_address(value).version != 6:
                raise ValueError("不是 IPv6")
        except ValueError as exc:
            raise ConfigError(f"[dns].answer_ipv6 中的 {value!r} 不合法：{exc}") from exc
    if enabled and not answers4 and not answers6:
        raise ConfigError("[dns] 已启用，但 answer_ipv4 / answer_ipv6 都为空，浏览器无法完成解析")
    host_v6 = _string(section, "listen_host_v6", where=where)
    if host_v6:
        _host(host_v6, where=f"{where}.listen_host_v6", default="::")
    return DnsConfig(
        enabled=enabled,
        zone=zone,
        listen_host=_host(
            _string(section, "listen_host", where=where), where=f"{where}.listen_host", default="0.0.0.0"
        ),
        listen_port=_integer(
            section, "listen_port", where=where, default=53, minimum=0, maximum=65535
        ),
        listen_host_v6=host_v6,
        listen_port_v6=(
            _integer(section, "listen_port_v6", where=where, default=53, minimum=0, maximum=65535)
            if host_v6
            else None
        ),
        answer_ipv4=answers4,
        answer_ipv6=answers6,
        ttl=_integer(section, "ttl", where=where, default=0, minimum=0, maximum=86400),
        wait_seconds=_number(
            section, "wait_seconds", where=where, default=8.0, minimum=2.0, maximum=60.0
        ),
    )


def _stun_host(value: str | None, *, where: str) -> str | None:
    """STUN 对外地址：IP 或域名均可（NAT 场景常用域名）。"""
    if value is None:
        return None
    host = value.strip()
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _DOMAIN_RE.match(host):
        raise ConfigError(f"{where} 必须是 IP 或域名，当前为 {value!r}")
    return host


def _load_stun(data: Mapping[str, Any], collector: CollectorConfig) -> StunConfig:
    section = _section(data, "stun")
    where = "[stun]"
    enabled = _boolean(section, "enabled", where=where, default=True)
    host4 = _stun_host(_string(section, "public_host_v4", where=where), where=f"{where}.public_host_v4")
    if enabled and not host4:
        # 未显式配置时沿用采集端主机名：两者常是同一台对外入口。
        host4 = _host_from_url(collector.public_url_v4)
        if not host4:
            raise ConfigError(
                "[stun] 已启用，但 public_host_v4 未设置，且无法从 collector.public_url_v4 推导"
            )
    host6 = _stun_host(_string(section, "public_host_v6", where=where), where=f"{where}.public_host_v6")
    port4 = _integer(section, "public_port_v4", where=where, default=3478, minimum=1, maximum=65535)
    port6 = (
        _integer(section, "public_port_v6", where=where, default=port4, minimum=1, maximum=65535)
        if host6
        else None
    )
    listen_host_v6 = _string(section, "listen_host_v6", where=where)
    if listen_host_v6:
        _host(listen_host_v6, where=f"{where}.listen_host_v6", default="::")
    range_section = section.get("port_range", {})
    if not isinstance(range_section, Mapping):
        raise ConfigError("[stun].port_range 必须是表")
    return StunConfig(
        enabled=enabled,
        listen_host=_host(
            _string(section, "listen_host", where=where), where=f"{where}.listen_host", default="0.0.0.0"
        ),
        listen_port=_integer(
            section, "listen_port", where=where, default=3478, minimum=0, maximum=65535
        ),
        listen_host_v6=listen_host_v6,
        listen_port_v6=(
            _integer(section, "listen_port_v6", where=where, default=3478, minimum=0, maximum=65535)
            if listen_host_v6
            else None
        ),
        public_host_v4=host4 or "invalid.invalid",
        public_port_v4=port4,
        public_host_v6=host6,
        public_port_v6=port6,
        port_range_base=_integer(
            range_section, "base", where=f"{where}.port_range", default=35000, minimum=1024, maximum=65500
        ),
        port_range_size=_integer(
            range_section, "size", where=f"{where}.port_range", default=0, minimum=0, maximum=2000
        ),
    )


def _load_probes(data: Mapping[str, Any]) -> ProbesConfig:
    section = _section(data, "probes")
    where = "[probes]"
    mode = (_string(section, "mode", where=where, default="embedded") or "embedded").lower()
    if mode not in {"embedded", "external"}:
        raise ConfigError(f"[probes].mode 只能是 embedded 或 external，当前为 {mode!r}")
    return ProbesConfig(mode=mode)


def _load_policy(data: Mapping[str, Any]) -> PolicyConfig:
    section = _section(data, "policy")
    where = "[policy]"
    return PolicyConfig(
        app_requires_tunnel=_boolean(section, "app_requires_tunnel", where=where, default=False)
    )


def _load_egress(data: Mapping[str, Any]) -> tuple[EgressEntry, ...]:
    raw = data.get("egress", [])
    if isinstance(raw, Mapping):
        raw = [raw]
    if not isinstance(raw, list):
        raise ConfigError("[[egress]] 必须是数组")
    entries: list[EgressEntry] = []
    for index, item in enumerate(raw):
        where = f"[[egress]] 第 {index + 1} 项"
        if not isinstance(item, Mapping):
            raise ConfigError(f"{where} 必须是表")
        name = _string(item, "name", where=where, required=True) or f"出口 {index + 1}"
        networks = _networks(item, "cidr", where=where)
        if not networks:
            raise ConfigError(f"{where}.cidr 不能为空")
        kind = (_string(item, "kind", where=where, default="corporate") or "corporate").lower()
        if kind not in {"corporate", "dns", "public-resolver"}:
            raise ConfigError(
                f"{where}.kind 只能是 corporate / dns / public-resolver，当前为 {kind!r}"
            )
        corporate = kind == "corporate"
        dns = kind == "dns" or (corporate and _boolean(item, "dns", where=where, default=True))
        entries.append(
            EgressEntry(name=name, networks=networks, corporate=corporate, dns=dns)
        )
    if not entries:
        raise ConfigError(
            "未配置任何 [[egress]] 出口地址。请在 config.toml 中列出公司 VPN 公网出口地址段。"
        )
    if not any(entry.corporate for entry in entries):
        raise ConfigError('至少需要一个 kind = "corporate" 的公司出口地址段，否则无法判定泄露')
    return tuple(entries)


def parse_config(data: Mapping[str, Any], *, source_path: Path) -> Config:
    app = _load_app(data)
    collector = _load_collector(data)
    dns = _load_dns(data)
    stun = _load_stun(data, collector)
    policy = _load_policy(data)
    probes = _load_probes(data)
    egress = _load_egress(data)
    rules = [rule for entry in egress for rule in entry.rules()]
    return Config(
        app=app,
        collector=collector,
        dns=dns,
        stun=stun,
        policy=policy,
        probes=probes,
        egress=egress,
        table=EgressTable(rules),
        source_path=source_path,
    )


def resolve_config_path(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path).expanduser().resolve()
    env = os.environ.get(ENV_CONFIG_PATH)
    if env:
        return Path(env).expanduser().resolve()
    return Path(DEFAULT_CONFIG_PATH).expanduser().resolve()


def load_config(path: str | Path | None = None) -> Config:
    """读取并校验配置。路径优先级：参数 > 环境变量 VPNCHECK_CONFIG > ./config.toml。"""
    config_path = resolve_config_path(path)
    if not config_path.exists():
        raise ConfigError(
            f"找不到配置文件 {config_path}。请复制 config.example.toml 为 config.toml，"
            "并按公司实际出口地址填写。"
        )
    try:
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{config_path} 不是合法 TOML：{exc}") from exc
    return parse_config(data, source_path=config_path)
