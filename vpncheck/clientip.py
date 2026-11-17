"""从请求/连接信息还原客户端地址。

采集端直连时使用 TCP 对端地址；部署在可信反向代理后面时，才按
``X-Forwarded-For`` 从右往左跳过可信代理。默认不信任该头，避免伪造。
"""

from __future__ import annotations

from collections.abc import Mapping

from .nets import IPAddress, IPNetwork, parse_ip

FORWARDED_HEADER = "x-forwarded-for"


def _peer(value: str | None) -> IPAddress | None:
    ip = parse_ip(value)
    if ip is None:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _trusted(ip: IPAddress, proxies: tuple[IPNetwork, ...]) -> bool:
    return any(ip.version == p.version and ip in p for p in proxies)


def _forwarded_values(headers: Mapping[str, str]) -> list[str]:
    raw = None
    for key, value in headers.items():
        if key.lower() == FORWARDED_HEADER and value:
            raw = value
            break
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def resolve_client_ip(
    peer_ip: str | None,
    headers: Mapping[str, str] | None = None,
    *,
    trust_forwarded_for: bool = False,
    trusted_proxies: tuple[IPNetwork, ...] = (),
) -> IPAddress | None:
    """返回客户端地址；无法确定时返回 ``None``。

    * ``peer_ip``：TCP 对端地址（Streamlit 的 ``st.context.ip_address``
      或采集端 socket 的 ``client_address``）。
    * ``headers``：仅当 ``trust_forwarded_for`` 为真且对端属于
      ``trusted_proxies`` 时读取 ``X-Forwarded-For``。
    """
    peer = _peer(peer_ip)
    if not trust_forwarded_for or not trusted_proxies or peer is None:
        return peer
    if not _trusted(peer, trusted_proxies):
        return peer

    chain: list[IPAddress] = []
    for raw in _forwarded_values(headers or {}):
        ip = _peer(raw)
        if ip is not None:
            chain.append(ip)
    chain.append(peer)

    # 从右往左跳过可信代理，第一个不可信地址即客户端。
    for ip in reversed(chain):
        if not _trusted(ip, trusted_proxies):
            return ip
    return chain[0] if chain else peer


__all__ = ["resolve_client_ip"]
