"""授权 DNS 探针服务。

原理
----
员工浏览器访问检测页时，页面会对 ``<会话标识><序号>.<探针区域>`` 这类唯一
子域发起请求。域名唯一（TTL=0）保证不会被缓存，因此每次都会触发一次真实
递归查询。查询到达本服务时的**源地址**，就是该员工所用递归解析器的出口
地址——这正是我们要判断的东西：在企业 VPN 出口范围内 ⇒ 解析走隧道；
在公网 ISP 地址上 ⇒ DNS 泄露。

服务端只做权威应答，不转发、不缓存、不记录查询内容以外的东西。
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from dnslib import AAAA, NS, QTYPE, RCODE, RR, SOA, A, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from .config import DnsConfig
from .store import Store

LOGGER = logging.getLogger(__name__)


def _quiet_logger() -> Any:
    class _Logger:
        def log_recv(self, handler, data):  # noqa: D401, ARG002
            return None

        def log_send(self, handler, data):  # noqa: ARG002
            return None

        def log_request(self, handler, request):  # noqa: ARG002
            return None

        def log_reply(self, handler, reply):  # noqa: ARG002
            return None

        def log_truncated(self, handler, reply):  # noqa: ARG002
            return None

        def log_error(self, handler, e):
            LOGGER.warning("DNS 处理出错: %s", e)

        def log_data(self, dnsobj):  # noqa: ARG002
            return None

    return _Logger()


class _UDP6Server(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


class _TCP6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True


class _UDP4Server(socketserver.ThreadingUDPServer):
    daemon_threads = True


class _TCP4Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class _RateLimiter:
    """按来源地址的简单令牌桶，避免探针区被刷。"""

    capacity: int = 600
    refill_per_second: float = 20.0
    _buckets: dict[str, tuple[float, float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            tokens = min(float(self.capacity), tokens + (now - last) * self.refill_per_second)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            if len(self._buckets) > 20000:  # 防御性清理
                self._buckets.clear()
            return True


def parse_probe_label(label: str) -> tuple[str, int] | None:
    """从标签 ``<32 位会话标识><序号>`` 中解析出会话与序号。"""
    if len(label) != 34:
        return None
    sid, seq = label[:32], label[32:]
    if not all(ch in "0123456789abcdef" for ch in sid):
        return None
    if not all(ch in "0123456789abcdef" for ch in seq):
        return None
    return sid, int(seq, 16)


class ProbeResolver(BaseResolver):
    """只应答探针区域的权威解析器。"""

    def __init__(
        self,
        config: DnsConfig,
        store: Store,
        *,
        on_query: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.config = config
        self.store = store
        self.zone = config.zone.rstrip(".")
        self._on_query = on_query
        self._limiter = _RateLimiter()
        self._rrs4 = [RR(self.zone, QTYPE.A, rdata=A(ip), ttl=config.ttl) for ip in config.answer_ipv4]
        self._rrs6 = [
            RR(self.zone, QTYPE.AAAA, rdata=AAAA(ip), ttl=config.ttl) for ip in config.answer_ipv6
        ]

    # -- 工具 -------------------------------------------------------------
    def _under_zone(self, qname: str) -> bool:
        return qname == self.zone or qname.endswith("." + self.zone)

    def _soa(self) -> RR:
        return RR(
            self.zone,
            QTYPE.SOA,
            rdata=SOA(
                f"ns1.{self.zone}",
                f"hostmaster.{self.zone}",
                (1, 60, 60, 600, 0),
            ),
            ttl=self.config.ttl,
        )

    def _nxdomain(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    # -- 主流程 -----------------------------------------------------------
    def resolve(self, request: DNSRecord, handler: Any) -> DNSRecord:
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype
        source = handler.client_address[0] if handler.client_address else ""
        transport = getattr(handler, "protocol", "udp")

        if not self._under_zone(qname):
            return self._nxdomain(request)

        reply = request.reply()
        reply.header.aa = 1
        reply.header.ra = 0

        labels = qname.split(".")
        zone_labels = self.zone.split(".")
        sub = labels[: len(labels) - len(zone_labels)]

        # 空子域：SOA / NS，便于委托排查
        if not sub:
            if qtype == QTYPE.SOA:
                reply.add_answer(self._soa())
            elif qtype == QTYPE.NS:
                reply.add_answer(RR(self.zone, QTYPE.NS, rdata=NS(f"ns1.{self.zone}"), ttl=self.config.ttl))
            elif qtype in (QTYPE.A, QTYPE.AAAA):
                reply.add_answer(*self._rrs4)
                reply.add_answer(*self._rrs6)
            return reply

        probe = parse_probe_label(sub[0])
        if probe is None:
            return self._nxdomain(request)

        sid, seq = probe

        if self._limiter.allow(source):
            recorded = self.store.add_observation(
                sid,
                "dns",
                source_ip=source,
                source_family=4 if "." in source else 6,
                transport=transport,
                detail={
                    "qname": qname,
                    "qtype": QTYPE.get(qtype, str(qtype)),
                    "seq": seq,
                    "zone": self.zone,
                    "edns": any(getattr(rr, "rtype", None) == QTYPE.OPT for rr in request.ar),
                },
            )
            if recorded and self._on_query is not None:
                try:
                    self._on_query({"sid": sid, "seq": seq, "source": source})
                except Exception:  # noqa: BLE001 - 观察者异常不能影响应答
                    LOGGER.debug("DNS 观察者回调失败", exc_info=True)

        if qtype == QTYPE.A:
            reply.add_answer(*self._rrs4)
        elif qtype == QTYPE.AAAA:
            reply.add_answer(*self._rrs6)
        elif qtype in (QTYPE.CNAME, QTYPE.TXT, QTYPE.HTTPS):
            # 明确应答 NOERROR 空答案，避免页面等待超时过久
            pass
        return reply


class DnsProbeService:
    """管理 UDP/TCP、IPv4/IPv6 多个监听器。"""

    def __init__(
        self,
        config: DnsConfig,
        store: Store,
        *,
        on_query: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.config = config
        self.store = store
        self.resolver = ProbeResolver(config, store, on_query=on_query)
        self._servers: list[DNSServer] = []
        self._threads: list[threading.Thread] = []
        self._started = False
        self.logger = _quiet_logger()

    @property
    def zone(self) -> str:
        return self.config.zone

    def start(self) -> None:
        if not self.config.enabled or self._started:
            return
        for host, port in self.config.listeners:
            is_v6 = ":" in host
            server_cls_udp = _UDP6Server if is_v6 else _UDP4Server
            server_cls_tcp = _TCP6Server if is_v6 else _TCP4Server
            servers = []
            for tcp, server_cls in ((False, server_cls_udp), (True, server_cls_tcp)):
                srv = DNSServer(
                    self.resolver,
                    address=host,
                    port=port,
                    tcp=tcp,
                    logger=self.logger,
                    server=server_cls,
                )
                servers.append(srv)
            for srv in servers:
                srv.start_thread()
                self._servers.append(srv)
            LOGGER.info("DNS 探针已监听 %s:%s (UDP/TCP)", host, port)
        self._started = True

    def stop(self) -> None:
        for srv in self._servers:
            try:
                srv.stop()
            except Exception:  # noqa: BLE001
                LOGGER.debug("停止 DNS 监听器失败", exc_info=True)
        self._servers.clear()
        self._started = False

    def run_forever(self) -> None:
        self.start()
        for srv in self._servers:
            if srv.thread is not None:
                srv.thread.join()
