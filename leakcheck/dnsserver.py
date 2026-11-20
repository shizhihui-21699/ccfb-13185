"""Authoritative DNS probe listener.

Why an authoritative server and not a resolver?  A web page can never learn
which recursive resolver answered its query — but the *recursive* resolver must
ask the authoritative server for the zone, and that query arrives from the
resolver's own egress address.  So by delegating a throwaway zone
(``probe.example-corp.net``) to this server and having the page resolve
``<token>-sys1.probe.example-corp.net``, we observe:

* **which resolver** the endpoint actually used (corp resolver, ISP resolver,
  public resolver, or an internal split-horizon one that never reaches us);
* **from which address / transport** that resolver recursed (the DNS exit);
* whether the resolver **forwarded EDNS Client Subnet**, i.e. whether the
  endpoint's real subnet is being handed to upstream DNS — a client-address
  leak that survives even a correctly tunnelled resolver.

All answers are TTL 0 so repeated probes are never answered from cache.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any

from dnslib import (AAAA, EDNS0, EDNSOption, QTYPE, RR, SOA, TXT, A, DNSLabel,
                    DNSQuestion, DNSRecord)

from .config import AppConfig
from .netutil import IPAddress, parse_ip
from .storage import Store
from .tokens import TOKEN_LEN, is_valid

log = logging.getLogger("leakcheck.dns")

OPT_RR_TYPE = 41
ECS_OPT_CODE = 8
ZONE_APEX_SOA_TTL = 60


@dataclass(slots=True)
class DnsObservation:
    qname: str
    qtype: str
    transport: str
    edns: bool
    do_bit: bool
    udp_payload: int
    ecs: str | None


def _split_label(label: str) -> tuple[str, str]:
    """Return ``(token, variant)`` from ``<28-char token>-sys1``."""
    label = label.lower().rstrip(".")
    if len(label) <= TOKEN_LEN:
        return label, ""
    if label[TOKEN_LEN] == "-":
        return label[:TOKEN_LEN], label[TOKEN_LEN + 1 :]
    return label, ""


def _parse_ecs(data: bytes) -> tuple[str | None, bytes, int]:
    """Decode an EDNS Client Subnet option. Returns (cidr, raw, scope)."""
    if len(data) < 4:
        return None, data, 0
    family = struct.unpack("!H", data[:2])[0]
    source_prefix = data[2]
    scope = data[3]
    payload = data[4:]
    if family == 1:
        need = (source_prefix + 7) // 8
        raw = (payload + b"\x00" * 4)[:4]
        addr: IPAddress = ipaddress.IPv4Address(raw)
    elif family == 2:
        need = (source_prefix + 7) // 8
        raw = (payload + b"\x00" * 16)[:16]
        addr = ipaddress.IPv6Address(raw)
    else:
        return None, data, scope
    del need
    try:
        network = ipaddress.ip_network(f"{addr}/{source_prefix}", strict=False)
    except ValueError:
        return None, data, scope
    return str(network), data, scope


def _ecs_option_for(ecs_raw: bytes, ecs_cidr: str | None, scope: int) -> EDNSOption:
    """Echo the client subnet back, optionally rewriting the scope prefix."""
    if scope <= 0 or not ecs_raw:
        return EDNSOption(ECS_OPT_CODE, ecs_raw)
    data = bytearray(ecs_raw)
    if len(data) >= 4:
        data[3] = min(scope, 32 if data[0:2] == b"\x00\x01" else 128)
    return EDNSOption(ECS_OPT_CODE, bytes(data))


class DnsProbeHandler:
    """Shared request handling for UDP and TCP transports."""

    def __init__(self, config: AppConfig, store: Store):
        self.config = config
        self.store = store
        self.zone = config.dns.zone
        self._lock = threading.Lock()
        self._token_counts: dict[str, int] = {}

    # ------------------------------------------------------------------ helpers
    def _bump(self, token: str) -> bool:
        with self._lock:
            if len(self._token_counts) > 100_000:
                self._token_counts.clear()
            count = self._token_counts.get(token, 0) + 1
            self._token_counts[token] = count
            return count <= self.config.server.max_probes * 8

    def _under_zone(self, qname: str) -> str | None:
        name = qname.lower().rstrip(".")
        if name == self.zone:
            return ""
        suffix = "." + self.zone
        if name.endswith(suffix):
            relative = name[: -len(suffix)]
            if relative and "." not in relative:
                return relative
        return None

    def handle(self, data: bytes, peer: tuple[Any, ...], transport: str) -> bytes | None:
        try:
            request = DNSRecord.parse(data)
        except Exception:  # noqa: BLE001 - malformed packets are dropped by design
            log.debug("丢弃无法解析的 DNS 报文，来源 %s", peer)
            return None

        if request.header.qr:
            return None  # a response, not a query
        if len(request.questions) != 1:
            return self._error(request, rcode=1, transport=transport)  # FORMERR

        question: DNSQuestion = request.q
        qname = str(question.qname).lower().rstrip(".")
        qtype = QTYPE.get(question.qtype, str(question.qtype))
        peer_ip = parse_ip(peer[0])
        peer_port = int(peer[1]) if len(peer) > 1 else None

        opt = self._opt_from(request)
        edns = opt is not None
        do_bit = bool(getattr(opt, "edns_do", 0)) if opt else False
        udp_payload = int(getattr(opt, "edns_len", 0) or 0) if opt else 0
        ecs_cidr, ecs_raw, ecs_scope = None, b"", 0
        if opt is not None and isinstance(opt.rdata, list):
            for option in opt.rdata:
                if isinstance(option, EDNSOption) and option.code == ECS_OPT_CODE:
                    ecs_cidr, ecs_raw, ecs_scope = _parse_ecs(option.data)

        relative = self._under_zone(qname)
        if relative is None:
            return self._error(request, rcode=5, transport=transport)  # REFUSED

        if relative == "":
            return self._apex_reply(request, transport=transport)

        token, variant = _split_label(relative)
        if not is_valid(
            self.config.server.hmac_secret,
            token,
            max_age=self.config.dns.probe_token_ttl,
        ):
            log.info("无效/过期探针令牌 %s，来自 %s", token, peer_ip)
            return self._error(request, rcode=5, transport=transport)

        if peer_ip is not None and self._bump(token):
            detail = {
                "qname": qname,
                "qtype": qtype,
                "label": relative,
                "variant": variant,
                "edns": edns,
                "do": do_bit,
                "udp_payload": udp_payload,
                "ecs": ecs_cidr,
                "resolver_port": peer_port,
                "zone": self.zone,
            }
            try:
                self.store.add_observation(
                    token,
                    "dns",
                    str(peer_ip),
                    peer_port,
                    transport,
                    detail,
                )
            except Exception:  # noqa: BLE001 - never fail a DNS answer on logging
                log.exception("记录 DNS 观测失败")

        return self._probe_reply(
            request,
            variant=variant,
            qtype=question.qtype,
            transport=transport,
            ecs=(ecs_cidr, ecs_raw, ecs_scope),
            edns=edns,
            udp_payload=udp_payload,
            do_bit=do_bit,
        )

    # ------------------------------------------------------------------ replies
    def _opt_from(self, request: DNSRecord) -> RR | None:
        for rr in request.ar:
            if rr.rtype == OPT_RR_TYPE:
                return rr
        return None

    def _base_reply(self, request: DNSRecord) -> DNSRecord:
        reply = DNSRecord(
            header=request.header,
            questions=[request.q],
        )
        reply.header.qr = 1
        reply.header.ra = 0
        reply.header.aa = 1
        reply.header.rd = request.header.rd
        reply.header.id = request.header.id
        reply.header.q = 1
        reply.header.a = 0
        reply.header.auth = 0
        reply.header.ar = 0
        return reply

    def _add_opt(self, reply: DNSRecord, request: DNSRecord, udp_payload: int,
                 ecs: tuple[str | None, bytes, int], do_bit: bool) -> None:
        max_payload = min(
            max(udp_payload or 512, 512), self.config.dns.max_udp_payload
        )
        options = []
        ecs_cidr, ecs_raw, ecs_scope = ecs
        if ecs_raw:
            options.append(_ecs_option_for(ecs_raw, ecs_cidr, self.config.dns.reflect_ecs_prefix))
        reply.add_ar(
            EDNS0(
                request.q.qname,
                udp_len=max_payload,
                version=0,
                flags="do" if do_bit else "",
                opts=options,
            )
        )

    def _error(self, request: DNSRecord, rcode: int, transport: str) -> bytes:
        reply = self._base_reply(request)
        reply.header.rcode = rcode
        if rcode == 5:
            reply.header.aa = 0
        self._add_opt(reply, request, 512, (None, b"", 0), False)
        return reply.pack()

    def _apex_reply(self, request: DNSRecord, transport: str) -> bytes:
        reply = self._base_reply(request)
        zone = self.zone
        ns_name = f"ns1.{zone}"
        if request.q.qtype == QTYPE.SOA:
            reply.add_answer(
                RR(
                    zone,
                    rtype=QTYPE.SOA,
                    ttl=ZONE_APEX_SOA_TTL,
                    rdata=SOA(
                        mname=ns_name,
                        rname=f"hostmaster.{zone}",
                        times=(int(time.time()), 3600, 600, 86400, 5),
                    ),
                )
            )
        elif request.q.qtype == QTYPE.NS:
            reply.add_answer(RR(zone, rtype=QTYPE.NS, ttl=ZONE_APEX_SOA_TTL, rdata=DNSLabel(ns_name)))
        elif request.q.qtype in (QTYPE.A, QTYPE.AAAA):
            reply.header.aa = 1
            if request.q.qtype == QTYPE.A:
                for addr in self.config.dns.answer_ipv4:
                    reply.add_answer(RR(ns_name, rtype=QTYPE.A, ttl=ZONE_APEX_SOA_TTL, rdata=A(str(addr))))
            else:
                if self.config.dns.answer_ipv6:
                    for addr in self.config.dns.answer_ipv6:
                        reply.add_answer(
                            RR(ns_name, rtype=QTYPE.AAAA, ttl=ZONE_APEX_SOA_TTL, rdata=AAAA(str(addr)))
                        )
        elif request.q.qtype == QTYPE.TXT and self.config.dns.echo_form:
            reply.add_answer(
                RR(
                    zone,
                    rtype=QTYPE.TXT,
                    ttl=ZONE_APEX_SOA_TTL,
                    rdata=TXT(f"leakcheck-dns-probe={self.config.site_title}"),
                )
            )
        else:
            reply.header.aa = 0
            reply.header.rcode = 0
        self._add_opt(reply, request, 512, (None, b"", 0), False)
        return self._fit(reply, request, transport)

    def _probe_reply(self, request: DNSRecord, variant: str, qtype: int,
                     transport: str, ecs: tuple[str | None, bytes, int],
                     edns: bool, udp_payload: int, do_bit: bool) -> bytes:
        reply = self._base_reply(request)
        qname = request.q.qname
        v6_only = variant.startswith("v6")
        wants_txt = variant.startswith("txt")

        if qtype == QTYPE.A and not v6_only:
            for addr in self.config.dns.answer_ipv4:
                reply.add_answer(
                    RR(qname, rtype=QTYPE.A, ttl=self.config.dns.answer_ttl, rdata=A(str(addr)))
                )
        elif qtype == QTYPE.AAAA:
            for addr in self.config.dns.answer_ipv6:
                reply.add_answer(
                    RR(qname, rtype=QTYPE.AAAA, ttl=self.config.dns.answer_ttl, rdata=AAAA(str(addr)))
                )
        elif qtype == QTYPE.TXT and wants_txt and self.config.dns.echo_form:
            reply.add_answer(
                RR(
                    qname,
                    rtype=QTYPE.TXT,
                    ttl=self.config.dns.answer_ttl,
                    rdata=TXT(f"variant={variant}"),
                )
            )
        # HTTPS/SVCB (65) and others: NOERROR with an empty answer keeps
        # browsers from treating the name as broken.
        if edns:
            self._add_opt(reply, request, udp_payload, ecs, do_bit)
        return self._fit(reply, request, transport)

    def _fit(self, reply: DNSRecord, request: DNSRecord, transport: str) -> bytes:
        packed = reply.pack()
        if transport == "udp":
            limit = 512
            opt = self._opt_from(request)
            if opt is not None:
                limit = min(max(getattr(opt, "edns_len", 0) or 512, 512), self.config.dns.max_udp_payload)
            if len(packed) > limit:
                reply.header.tc = 1
                reply = self._base_reply(request)
                reply.header.tc = 1
                return reply.pack()
        return packed


class _UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = 4096

    def __init__(self, address, handler_class, handler: DnsProbeHandler):
        self.handler_obj = handler
        super().__init__(address, handler_class)


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # pragma: no cover - exercised via integration test
        data, sock = self.request
        handler: DnsProbeHandler = self.server.handler_obj  # type: ignore[attr-defined]
        response = handler.handle(data, self.client_address, "udp")
        if response:
            sock.sendto(response, self.client_address)


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler_class, handler: DnsProbeHandler):
        self.handler_obj = handler
        super().__init__(address, handler_class)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # pragma: no cover - exercised via integration test
        handler: DnsProbeHandler = self.server.handler_obj  # type: ignore[attr-defined]
        conn: socket.socket = self.request
        conn.settimeout(10.0)
        try:
            header = _recv_exact(conn, 2)
            if not header:
                return
            (length,) = struct.unpack("!H", header)
            if length == 0 or length > 65535:
                return
            payload = _recv_exact(conn, length)
            if not payload:
                return
            response = handler.handle(payload, self.client_address, "tcp")
            if response:
                conn.sendall(struct.pack("!H", len(response)) + response)
        except (TimeoutError, ConnectionError, OSError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class DnsProbeServer:
    """Runs the authoritative UDP+TCP listener on a background thread."""

    def __init__(self, config: AppConfig, store: Store):
        self.config = config
        self.store = store
        self.handler = DnsProbeHandler(config, store)
        self._udp: _UdpServer | None = None
        self._tcp: _TcpServer | None = None
        self._threads: list[threading.Thread] = []
        self.bound_port: int | None = None

    def start(self) -> None:
        if not self.config.dns.enabled:
            log.info("DNS 探针已禁用")
            return
        host = self.config.dns.bind_host
        port = self.config.dns.bind_port
        self._udp = _UdpServer((host, port), _UdpHandler, self.handler)
        self.bound_port = self._udp.server_address[1]
        self._tcp = _TcpServer((host, self.bound_port), _TcpHandler, self.handler)
        # A short poll interval keeps shutdown snappy for tests and restarts.
        for target, name in (
            (lambda: self._udp.serve_forever(poll_interval=0.05), "dns-udp"),
            (lambda: self._tcp.serve_forever(poll_interval=0.05), "dns-tcp"),
        ):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        log.info(
            "DNS 探针已启动 %s:%s (udp+tcp)，授权区 %s",
            host,
            self.bound_port,
            self.config.dns.zone,
        )

    def stop(self) -> None:
        for server in (self._udp, self._tcp):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=3)
        self._threads.clear()
        log.info("DNS 探针已停止")

    # -------------------------------------------------------------- diagnostics
    def self_query(self, token: str, qtype: str = "A", port: int | None = None) -> dict[str, Any]:
        """Send a real query through the local listener (used by selftest/CI)."""
        name = f"{token}-sys1.{self.config.dns.zone}"
        record = DNSRecord.question(name, qtype)
        payload = record.pack()
        target_port = port or self.bound_port or self.config.dns.bind_port
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3.0)
            sock.sendto(payload, ("127.0.0.1", target_port))
            data, _ = sock.recvfrom(4096)
        reply = DNSRecord.parse(data)
        return {
            "qname": name,
            "answers": [str(rr.rdata) for rr in reply.rr],
            "rcode": reply.header.rcode,
        }
