"""IP address helpers shared by the collector, the DNS probe and the verdict engine."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip(value: object) -> IPAddress | None:
    """Parse an address from headers / DNS / form input.

    Accepts bracketed IPv6 (``[2001:db8::1]``), ``ip:port`` (IPv4 only),
    IPv4-mapped IPv6 (normalised back to IPv4) and trailing whitespace.
    Returns ``None`` for anything that is not an address.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and "." in text:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def family(addr: IPAddress | None) -> int | None:
    if addr is None:
        return None
    return addr.version


def is_routable(addr: IPAddress) -> bool:
    """True when an address is a globally routable unicast address."""
    if not addr.is_global:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


# Non-public special-purpose ranges, spelled out explicitly instead of relying on
# ``ipaddress.is_global``.  The stdlib's ``is_private``/``is_global`` semantics
# have changed between Python releases (3.13 reclassified the documentation
# ranges), and this service must classify identically on every interpreter it is
# deployed to.  Documentation ranges are deliberately *not* listed: in a test or
# a pilot deployment they stand in for real public addresses.
_PRIVATE_RANGES = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",       # CGNAT / carrier-grade NAT
        "169.254.0.0/16",      # link-local
        "192.0.0.0/24",        # IETF protocol assignments
        "198.18.0.0/15",       # benchmarking
        "fc00::/7",            # unique local
        "fe80::/10",           # link-local
        "64:ff9b:1::/48",      # local-use NAT64
    )
)


def address_scope(addr: IPAddress) -> str:
    """One of ``loopback`` / ``unspecified`` / ``private`` / ``multicast`` /
    ``link_local`` / ``public``.

    Deterministic across Python versions; used for every "is this address
    something an outsider could see?" decision.
    """
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link_local"
    for network in _PRIVATE_RANGES:
        if network.version == addr.version and addr in network:
            return "private"
    return "public"


def is_public_address(addr: IPAddress) -> bool:
    """True for addresses that can identify the user on the public Internet."""
    return address_scope(addr) == "public"


def parse_network(value: str) -> IPNetwork:
    """Parse ``203.0.113.7`` or ``203.0.113.0/24`` strictly as a network."""
    return ipaddress.ip_network(str(value).strip(), strict=False)


def parse_networks(values: Iterable[object]) -> list[IPNetwork]:
    out: list[IPNetwork] = []
    for value in values:
        if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            out.append(value)
        elif value is None or str(value).strip() == "":
            continue
        else:
            out.append(parse_network(str(value)))
    return out


def net_contains(network: IPNetwork, addr: IPAddress) -> bool:
    if network.version != addr.version:
        return False
    return addr in network


def first_match(networks: Sequence[IPNetwork], addr: IPAddress | None) -> IPNetwork | None:
    if addr is None:
        return None
    for network in networks:
        if net_contains(network, addr):
            return network
    return None


def sorted_unique(addrs: Iterable[IPAddress]) -> list[IPAddress]:
    return sorted(set(addrs), key=lambda a: (a.version, int(a)))


def addr_sort_key(addr: IPAddress) -> tuple[int, int]:
    return (addr.version, int(addr))


def client_ip_from_forwarded(headers: dict[str, str], trusted_proxies: Sequence[IPNetwork],
                             peer: IPAddress | None) -> IPAddress | None:
    """Resolve the real client address from ``X-Forwarded-For`` honouring a proxy chain.

    Walks the chain right-to-left and returns the first address that is not one of
    our own trusted proxies.  Only trusts the header when the direct peer is itself
    a trusted proxy, so a client cannot spoof its own address.
    """
    if peer is None or not first_match(trusted_proxies, peer):
        return peer
    raw = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or ""
    chain = [parse_ip(part) for part in raw.split(",")]
    chain = [addr for addr in chain if addr is not None]
    for addr in reversed(chain):
        if not first_match(trusted_proxies, addr):
            return addr
    return peer
