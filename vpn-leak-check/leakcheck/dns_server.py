"""权威 DNS 服务器。

原理：页面为每次检测生成唯一子域 <token>.dns.<zone>，员工机器的浏览器/系统
解析该域名时，其配置的 DNS 解析器会向本服务器（该 zone 的权威）发起递归查询，
查询包的源 IP 就是该解析器的出口地址 —— 与 config 里的公司 DNS 出口对照即可
判断 DNS 是否泄露。

同时本服务器还应答：
  - <zone> / ipv4.<zone> 的 A 记录（API 服务器地址）
  - ipv6.<zone> 的 AAAA 记录（仅 IPv6，用于检测 IPv6 是否绕过隧道）
"""
from __future__ import annotations

import logging
import socket

from dnslib import A, AAAA, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer, UDPServer

log = logging.getLogger("leakcheck.dns")


class _UDP6Server(UDPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        # 与 v4 监听共存：禁止 v6 通配 socket 兼收 v4-mapped
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class LeakResolver(BaseResolver):
    def __init__(self, zone: str, server_ipv4: str, server_ipv6: str, db):
        self.zone = zone.rstrip(".")
        self.dns_suffix = ".dns." + self.zone
        self.server_ipv4 = server_ipv4
        self.server_ipv6 = server_ipv6
        self.db = db

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = request.q.qtype
        src_ip = handler.client_address[0]
        if src_ip.startswith("::ffff:"):  # v4-mapped，归一化
            src_ip = src_ip[7:]

        if qname.endswith(self.dns_suffix):
            # <token>.dns.<zone> —— 记录解析器出口 IP
            token = qname[: -len(self.dns_suffix)].split(".")[-1]
            log.info("dns probe token=%s resolver=%s qtype=%s", token, src_ip, QTYPE[qtype])
            self.db.add_event(token, "dns", src_ip, {"qname": qname})
            if qtype == QTYPE.A and self.server_ipv4:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.server_ipv4), ttl=5))
            # AAAA 查询返回 NODATA：dns-hit 的 HTTP 回源强制走 IPv4
        elif qname == "ipv6." + self.zone:
            # 只有 AAAA 记录：浏览器只有具备 IPv6 连通性才能访问成功
            if qtype == QTYPE.AAAA and self.server_ipv6:
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(self.server_ipv6), ttl=5))
        elif qname in ("ipv4." + self.zone, self.zone, "api." + self.zone):
            if qtype == QTYPE.A and self.server_ipv4:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.server_ipv4), ttl=5))
            if qtype == QTYPE.AAAA and self.server_ipv6 and qname != "ipv4." + self.zone:
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(self.server_ipv6), ttl=5))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def start_dns_server(cfg: dict, db) -> None:
    """后台线程启动 UDP（+TCP）权威 DNS，v4/v6 各自尝试，失败仅告警。"""
    resolver = LeakResolver(
        cfg["zone"],
        cfg.get("server_ipv4", ""),
        cfg.get("server_ipv6", ""),
        db,
    )
    port = int(cfg["ports"]["dns"])
    started = []
    try:
        udp4 = DNSServer(resolver, port=port, address="0.0.0.0", tcp=False)
        udp4.start_thread()
        tcp4 = DNSServer(resolver, port=port, address="0.0.0.0", tcp=True)
        tcp4.start_thread()
        started.append("0.0.0.0(udp+tcp)")
    except OSError as exc:
        log.warning("DNS v4 监听端口 %s 失败：%s", port, exc)
    try:
        udp6 = DNSServer(resolver, port=port, address="::", tcp=False, server=_UDP6Server)
        udp6.start_thread()
        started.append("::(udp)")
    except OSError as exc:
        log.warning("DNS v6 监听端口 %s 失败：%s", port, exc)
    if not started:
        raise RuntimeError(f"DNS 服务器无法监听端口 {port}（需要 root/CAP_NET_BIND_SERVICE？）")
    log.info("DNS 服务器已启动: %s port %s", started, port)
