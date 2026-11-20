"""Minimal STUN (RFC 5389) binding server used to observe the endpoint's UDP egress.

WebRTC is the one browser surface that sends UDP straight to a host we choose,
so a STUN binding request reveals the address the endpoint's UDP traffic
actually leaves from — the channel that split tunnels most often miss.

Attribution problem: a STUN message carries no URL, no cookie and no session
identifier.  We solve it by giving every self-check session its own UDP port
from a pool; the listener looks up which session owns the local port that
received the packet.  A request that arrives on an unallocated port is counted
but not attributed.

Both IPv4 and IPv6 sockets are bound (per port) so that IPv6 UDP bypass is
detected the same way as IPv4.
"""

from __future__ import annotations

import binascii
import logging
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any

from .config import AppConfig
from .netutil import IPAddress, parse_ip
from .storage import Store

log = logging.getLogger("leakcheck.stun")

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_USERNAME = 0x0006

FINGERPRINT_XOR = 0x5354554E


class StunError(ValueError):
    pass


@dataclass(slots=True)
class StunRequest:
    msg_type: int
    txid: bytes
    attributes: dict[int, bytes]
    source: tuple[Any, ...]
    raw_length: int
    family: int = 4

    @property
    def username(self) -> str | None:
        raw = self.attributes.get(ATTR_USERNAME)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return None

    @property
    def software(self) -> str | None:
        raw = self.attributes.get(ATTR_SOFTWARE)
        if raw is None:
            return None
        return raw.decode("utf-8", "replace").rstrip("\x00")


def parse_message(data: bytes) -> StunRequest:
    if len(data) < 20:
        raise StunError("报文过短")
    msg_type, length, cookie = struct.unpack("!HHI", data[:8])
    if cookie != MAGIC_COOKIE:
        raise StunError("magic cookie 不匹配（不是 STUN 报文）")
    if msg_type & 0xC000:
        raise StunError("最高两位必须为 0")
    if length % 4 != 0:
        raise StunError("属性长度未按 4 字节对齐")
    body = data[20 : 20 + length]
    if len(body) != length:
        raise StunError("报文被截断")
    txid = data[8:20]
    attributes: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack("!HH", body[offset : offset + 4])
        offset += 4
        value = body[offset : offset + attr_len]
        offset += attr_len
        offset += (-attr_len) % 4
        # Keep the first occurrence of each type (STUN allows list attrs, but
        # for our purpose the first is enough).
        attributes.setdefault(attr_type, value)
    return StunRequest(msg_type=msg_type, txid=txid, attributes=attributes,
                       source=(), raw_length=len(data))


def _pad4(value: bytes) -> bytes:
    return value + b"\x00" * ((-len(value)) % 4)


def _attr(attr_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", attr_type, len(value)) + _pad4(value)


def _xor_mapped(addr: IPAddress, port: int, txid: bytes) -> bytes:
    xport = port ^ (MAGIC_COOKIE >> 16)
    if addr.version == 4:
        payload = struct.pack("!HH", 0x0001, xport) + bytes(
            a ^ b for a, b in zip(addr.packed, struct.pack("!I", MAGIC_COOKIE))
        )
    else:
        mask = struct.pack("!I", MAGIC_COOKIE) + txid
        payload = struct.pack("!HH", 0x0002, xport) + bytes(
            a ^ b for a, b in zip(addr.packed, mask)
        )
    return _attr(ATTR_XOR_MAPPED_ADDRESS, payload)


def _mapped(addr: IPAddress, port: int) -> bytes:
    packed = struct.pack("!H", 0x0001 if addr.version == 4 else 0x0002)
    return _attr(ATTR_MAPPED_ADDRESS, packed + struct.pack("!H", port) + addr.packed)


def build_success(addr: IPAddress, port: int, txid: bytes, software: str,
                  include_fingerprint: bool = True) -> bytes:
    attrs = _xor_mapped(addr, port, txid) + _mapped(addr, port)
    attrs += _attr(ATTR_SOFTWARE, software.encode("utf-8")[:763])
    if include_fingerprint:
        # FINGERPRINT must be the last attribute and is computed over the whole
        # message with the length field already counting the fingerprint.
        body_len = len(attrs) + 8
        header = struct.pack("!HHI", BINDING_SUCCESS, body_len, MAGIC_COOKIE) + txid
        crc = (binascii.crc32(header + attrs) & 0xFFFFFFFF) ^ FINGERPRINT_XOR
        attrs += _attr(ATTR_FINGERPRINT, struct.pack("!I", crc))
        return header + attrs
    return struct.pack("!HHI", BINDING_SUCCESS, len(attrs), MAGIC_COOKIE) + txid + attrs


def build_error(txid: bytes, code: int = 400, reason: str = "Bad Request") -> bytes:
    body = struct.pack("!HBB", 0, code // 100, code % 100) + reason.encode("utf-8")
    attrs = _attr(ATTR_ERROR_CODE, body)
    return struct.pack("!HHI", BINDING_ERROR, len(attrs), MAGIC_COOKIE) + txid + attrs


@dataclass(slots=True)
class _PortSockets:
    port: int
    v4: socket.socket | None = None
    v6: socket.socket | None = None
    threads: list[threading.Thread] = field(default_factory=list)


class StunServer:
    """Binds every configured port on IPv4 and (optionally) IPv6."""

    def __init__(self, config: AppConfig, store: Store):
        self.config = config
        self.store = store
        self.software = f"leakcheck-stun/1 {config.site_title}"[:700]
        self._sockets: list[_PortSockets] = []
        self._running = threading.Event()
        self._lock = threading.Lock()
        self._stats = {"packets": 0, "unattributed": 0, "errors": 0}
        self.bind_ipv6 = config.stun.bind_ipv6
        self.bound_ports: list[int] = []

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if not self.config.stun.enabled:
            log.info("STUN 探针已禁用")
            return
        self._running.set()
        for port in self.config.stun.ports:
            holder = _PortSockets(port=port)
            try:
                sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock4.bind((self.config.stun.bind_host, port))
                sock4.settimeout(0.5)
                holder.v4 = sock4
            except OSError as exc:
                log.warning("STUN 端口 %s UDP/IPv4 绑定失败: %s", port, exc)
            if self.bind_ipv6:
                try:
                    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                    sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock6.bind(("::", port))
                    sock6.settimeout(0.5)
                    holder.v6 = sock6
                except OSError as exc:
                    log.debug("STUN 端口 %s UDP/IPv6 不可用: %s", port, exc)
            if holder.v4 is None and holder.v6 is None:
                continue
            # A configured port of 0 means "let the kernel choose" (used by the
            # self-test and by throwaway dev instances).
            actual_port = holder.v4.getsockname()[1] if holder.v4 is not None else holder.v6.getsockname()[1]
            holder.port = actual_port
            if holder.v6 is not None and holder.v4 is None:
                log.info("STUN 端口 %s 仅 IPv6 可用（IPv4 绑定失败）", actual_port)
            self._sockets.append(holder)
            self.bound_ports.append(actual_port)
            for sock, family in ((holder.v4, 4), (holder.v6, 6)):
                if sock is None:
                    continue
                thread = threading.Thread(
                    target=self._serve, args=(sock, actual_port, family),
                    name=f"stun-{actual_port}-v{family}", daemon=True,
                )
                thread.start()
                holder.threads.append(thread)
        if not self.bound_ports:
            log.error("STUN 探针未绑定任何端口，UDP 出口检测将不可用")
        else:
            log.info("STUN 探针已启动，端口 %s（%d 个）",
                     _ranges(self.bound_ports), len(self.bound_ports))

    def stop(self) -> None:
        self._running.clear()
        for holder in self._sockets:
            for sock in (holder.v4, holder.v6):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            for thread in holder.threads:
                thread.join(timeout=2)
        self._sockets.clear()
        log.info("STUN 探针已停止")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._stats, ports=len(self.bound_ports))

    # ------------------------------------------------------------------- serving
    def _serve(self, sock: socket.socket, port: int, family: int) -> None:
        while self._running.is_set():
            try:
                data, peer = sock.recvfrom(2048)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                self._handle(sock, data, peer, port, family)
            except Exception:  # noqa: BLE001 - never let one packet kill the loop
                log.exception("处理 STUN 报文失败")
                with self._lock:
                    self._stats["errors"] += 1

    def _handle(self, sock: socket.socket, data: bytes, peer: tuple[Any, ...],
                port: int, family: int) -> None:
        try:
            request = parse_message(data)
        except StunError as exc:
            log.debug("丢弃 STUN 报文: %s", exc)
            with self._lock:
                self._stats["errors"] += 1
            return
        with self._lock:
            self._stats["packets"] += 1

        source_ip = parse_ip(peer[0])
        token = self.store.lookup_stun_port(port)
        if source_ip is None or token is None:
            with self._lock:
                self._stats["unattributed"] += 1
            if request.msg_type == BINDING_REQUEST and source_ip is not None:
                sock.sendto(build_error(request.txid), peer)
            return

        if request.msg_type != BINDING_REQUEST:
            sock.sendto(build_error(request.txid, 400, "Unsupported Message Type"), peer)
            return

        detail = {
            "mapped": f"{source_ip}:{peer[1]}",
            "local_port": port,
            "family": family,
            "software": request.software,
            "username": request.username,
            "has_integrity": ATTR_MESSAGE_INTEGRITY in request.attributes,
            "has_fingerprint": ATTR_FINGERPRINT in request.attributes,
            "kind": "stun-binding",
        }
        try:
            self.store.add_observation(
                token, "stun", str(source_ip), int(peer[1]), "udp", detail
            )
        except Exception:  # noqa: BLE001
            log.exception("记录 STUN 观测失败")

        response = build_success(source_ip, int(peer[1]), request.txid, self.software)
        sock.sendto(response, peer)

    # -------------------------------------------------------------- diagnostics
    def self_query(self, token: str, port: int, family: int = 4, timeout: float = 3.0) -> dict[str, Any]:
        """Send a real binding request to the local listener (selftest use)."""
        txid = b"\x01" * 12
        request = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + txid
        af = socket.AF_INET if family == 4 else socket.AF_INET6
        host = "127.0.0.1" if family == 4 else "::1"
        with socket.socket(af, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(request, (host, port))
            data, _ = sock.recvfrom(2048)
        reply = parse_message(data)
        return {
            "type": hex(reply.msg_type),
            "mapped": reply.attributes.get(ATTR_XOR_MAPPED_ADDRESS, b"").hex(),
            "software": reply.software,
        }


def _ranges(ports: list[int]) -> str:
    if not ports:
        return "-"
    ports = sorted(ports)
    groups: list[tuple[int, int]] = []
    start = prev = ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        groups.append((start, prev))
        start = prev = port
    groups.append((start, prev))
    return ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in groups)
