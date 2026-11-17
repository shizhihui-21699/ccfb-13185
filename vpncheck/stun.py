"""最小 STUN 服务（RFC 5389），用于观察 WebRTC 的真实 UDP 出口。

原理
----
浏览器通过 ``RTCPeerConnection`` 向本服务的 STUN 端口发起 Binding 请求，
本服务看到的源地址/源端口就是该浏览器 UDP 流量的出口。把源地址与公司
出口表对比，即可判断 WebRTC 是否绕过隧道、是否暴露真实地址。

归因
----
浏览器 WebRTC API 无法在 ``stun:`` URI 中携带会话参数。因此本服务维护一个
**端口池**：页面为每个会话从池里认领一个端口（写入共享 SQLite，主键唯一），
STUN 端口池里的每个端口都只属于一个会话。这样每条观测都能精确归属，且
页面与探针分进程部署时也一致。

实现
----
一个线程用 ``selectors`` 同时监听池内所有 UDP 端口，不为每个端口/报文起
线程。只实现 Binding 请求与 XOR-MAPPED-ADDRESS / MAPPED-ADDRESS 应答，
不实现 TURN 中继、鉴权和 TCP，尽量减少暴露面。
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import selectors
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .config import StunConfig
from .nets import parse_ip
from .store import Store

LOGGER = logging.getLogger(__name__)

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
BINDING_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_ERROR_CODE = 0x0009
ATTR_SOFTWARE = 0x8022

_SOFTWARE = b"vpncheck/1.0"
_TICK = 5.0


class StunError(ValueError):
    """STUN 报文格式错误。"""


def _attr(kind: int, value: bytes) -> bytes:
    pad = (4 - len(value) % 4) % 4
    return struct.pack("!HH", kind, len(value)) + value + b"\x00" * pad


def parse_binding_request(data: bytes) -> bytes:
    """校验 Binding 请求并返回 12 字节事务标识。"""
    if len(data) < 20:
        raise StunError("报文过短")
    msg_type, length, cookie = struct.unpack("!HHI", data[:8])
    if msg_type != BINDING_REQUEST:
        raise StunError(f"不是 Binding 请求：0x{msg_type:04x}")
    if cookie != MAGIC_COOKIE:
        raise StunError("magic cookie 不匹配")
    if length % 4 != 0:
        raise StunError("长度字段未按 4 字节对齐")
    if 20 + length > len(data):
        raise StunError("长度字段超出报文")
    return data[8:20]


def _xor_mapped(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, txid: bytes
) -> bytes:
    xport = port ^ (MAGIC_COOKIE >> 16)
    if ip.version == 4:
        mask = struct.pack("!I", MAGIC_COOKIE)
        xaddr = bytes(a ^ b for a, b in zip(ip.packed, mask, strict=True))
        return b"\x00\x01" + struct.pack("!H", xport) + xaddr
    mask = struct.pack("!I", MAGIC_COOKIE) + txid
    xaddr = bytes(a ^ b for a, b in zip(ip.packed, mask, strict=True))
    return b"\x00\x02" + struct.pack("!H", xport) + xaddr


def _mapped(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> bytes:
    family = 0x01 if ip.version == 4 else 0x02
    return bytes([0, family]) + struct.pack("!H", port) + ip.packed


def build_binding_response(source_ip: str, source_port: int, txid: bytes) -> bytes:
    ip = parse_ip(source_ip)
    if ip is None:
        raise StunError(f"无法解析源地址 {source_ip!r}")
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    attributes = _attr(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped(ip, source_port, txid))
    attributes += _attr(ATTR_MAPPED_ADDRESS, _mapped(ip, source_port))
    attributes += _attr(ATTR_SOFTWARE, _SOFTWARE)
    return struct.pack("!HHI", BINDING_RESPONSE, len(attributes), MAGIC_COOKIE) + txid + attributes


def build_error_response(reason: str, txid: bytes) -> bytes:
    value = b"\x00\x00\x04\x00" + reason.encode()[:763]
    attributes = _attr(ATTR_ERROR_CODE, value)
    return struct.pack("!HHI", BINDING_ERROR, len(attributes), MAGIC_COOKIE) + txid + attributes


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class _Limiter:
    capacity: float = 200.0
    rate: float = 20.0
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self.capacity, now)
                self._buckets[key] = bucket
            else:
                bucket.tokens = min(
                    self.capacity, bucket.tokens + (now - bucket.last) * self.rate
                )
                bucket.last = now
            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            if len(self._buckets) > 10000:
                self._buckets.clear()
            return True


def _uri_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


class StunService:
    """端口池式 STUN 服务。"""

    def __init__(
        self,
        config: StunConfig,
        store: Store,
        *,
        on_binding: Callable[[str, dict[str, object]], None] | None = None,
    ):
        self.config = config
        self.store = store
        self._on_binding = on_binding
        self.limiter = _Limiter()
        self._sockets: dict[socket.socket, int] = {}
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = False

    # -- 端口认领（页面调用） ---------------------------------------------
    def port_for_session(self, session_id: str) -> int | None:
        """返回该会话的端口；尚未认领时尝试认领一个空闲端口。"""
        if not self.config.can_probe:
            return None
        existing = self.store.stun_port_of(session_id)
        if existing is not None:
            return existing
        port = self.store.claim_stun_port(session_id, self.config.port_range_base, self.config.port_range_size)
        if port is None:
            LOGGER.warning("STUN 端口池已耗尽（%s 个），会话 %s 无法做 WebRTC 检测",
                           self.config.port_range_size, session_id)
        return port

    def uris(self, session_id: str) -> tuple[str, ...]:
        port = self.port_for_session(session_id)
        if port is None:
            return ()
        out = [f"stun:{_uri_host(self.config.public_host_v4)}:{port}"]
        if self.config.public_host_v6:
            out.append(f"stun:{_uri_host(self.config.public_host_v6)}:{port}")
        return tuple(out)

    def release(self, session_id: str) -> None:
        self.store.release_stun_port(session_id)

    # -- 监听 -------------------------------------------------------------
    def start(self) -> None:
        if not self.config.enabled or self._started:
            return
        if not self.config.can_probe:
            LOGGER.warning("STUN 已启用但未配置 port_range，WebRTC 检测将不可用")
            return
        loopback_only = self.config.listen_host in {"127.0.0.1", "::1"}
        if loopback_only:
            LOGGER.warning("STUN 监听在回环地址上，只有本机浏览器能探测")
        bound = 0
        for offset in range(self.config.port_range_size):
            port = self.config.port_range_base + offset
            for host, family in (
                (self.config.listen_host, socket.AF_INET),
                (self.config.listen_host_v6, socket.AF_INET6),
            ):
                if not host:
                    continue
                sock = self._bind(host, port, family)
                if sock is None:
                    continue
                with self._lock:
                    self._sockets[sock] = port
                bound += 1
        if bound == 0:
            LOGGER.error("STUN 没有绑定到任何端口，WebRTC 检测不可用")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="stun-pool", daemon=True)
        self._thread.start()
        self._started = True
        LOGGER.info(
            "STUN 端口池已监听 %s-%s（%s 个 socket）",
            self.config.port_range_base,
            self.config.port_range_base + self.config.port_range_size - 1,
            bound,
        )

    def _bind(self, host: str, port: int, family: int) -> socket.socket | None:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            sock.setblocking(False)
            return sock
        except OSError as exc:
            sock.close()
            LOGGER.debug("STUN 端口 %s 绑定失败：%s", port, exc)
            return None

    def _serve(self) -> None:
        selector = selectors.DefaultSelector()
        with self._lock:
            for sock in self._sockets:
                selector.register(sock, selectors.EVENT_READ)
        last_gc = time.monotonic()
        try:
            while not self._stop.is_set():
                for key, _ in selector.select(timeout=_TICK):
                    self._drain(key.fileobj)  # type: ignore[arg-type]
                now = time.monotonic()
                if now - last_gc >= _TICK:
                    last_gc = now
                    try:
                        self.store.expire_stun_ports()
                    except Exception:  # noqa: BLE001
                        LOGGER.debug("清理 STUN 端口失败", exc_info=True)
        finally:
            selector.close()

    def _drain(self, sock: socket.socket) -> None:
        # 一次可读事件里尽量把积压报文读完，避免风暴时延迟累积。
        for _ in range(64):
            try:
                data, address = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            self._handle(sock, data, address)

    def _handle(self, sock: socket.socket, data: bytes, address) -> None:
        source_ip, source_port = address[0], address[1]
        try:
            txid = parse_binding_request(data)
        except StunError as exc:
            LOGGER.debug("忽略非法 STUN 报文：%s", exc)
            return
        if not self.limiter.allow(source_ip):
            return
        try:
            response = build_binding_response(source_ip, source_port, txid)
        except StunError as exc:
            LOGGER.warning("STUN 应答构造失败：%s", exc)
            return
        # 先记账再回包：即使回包在途中丢失，这次 Binding 也确实到达了本服务。
        self._record(sock, source_ip, source_port)
        try:
            sock.sendto(response, address)
        except OSError:
            LOGGER.debug("STUN 应答发送失败", exc_info=True)

    def _record(self, sock: socket.socket, source_ip: str, source_port: int) -> None:
        with self._lock:
            port = self._sockets.get(sock)
        if port is None:
            return
        session_id = self.store.session_for_stun_port(port)
        if session_id is None:
            return
        family = 4 if "." in source_ip else 6
        self.store.add_observation(
            session_id,
            "stun",
            source_ip=source_ip,
            source_family=family,
            transport="udp",
            detail={"port": source_port, "method": "binding", "pool_port": port},
        )
        if self._on_binding is not None:
            try:
                self._on_binding(session_id, {"source": source_ip, "port": source_port})
            except Exception:  # noqa: BLE001
                LOGGER.debug("STUN 观察者回调失败", exc_info=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
        with self._lock:
            for sock in self._sockets:
                with contextlib.suppress(OSError):
                    sock.close()
            self._sockets.clear()
        self._started = False
