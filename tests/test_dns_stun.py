"""DNS 探针与 STUN 服务的端到端测试。"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

import pytest
from dnslib import QTYPE, DNSRecord

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import free_port, make_config  # noqa: E402

from vpncheck.config import DnsConfig  # noqa: E402
from vpncheck.dns_probe import DnsProbeService, parse_probe_label  # noqa: E402
from vpncheck.store import Store  # noqa: E402
from vpncheck.stun import (  # noqa: E402
    BINDING_RESPONSE,
    MAGIC_COOKIE,
    StunError,
    StunService,
    build_binding_response,
    parse_binding_request,
)


def _dns_config(port: int, zone: str = "probe.test.invalid") -> DnsConfig:
    config = make_config(
        dns={"listen_port": port, "zone": zone, "listen_host": "127.0.0.1"},
        stun={"enabled": False},
    )
    return config.dns


def _query(port: int, name: str, qtype: str = "A", *, tcp: bool = False) -> DNSRecord:
    request = DNSRecord.question(name, qtype)
    payload = request.pack()
    if tcp:
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            head = sock.recv(2)
            length = struct.unpack("!H", head)[0]
            data = b""
            while len(data) < length:
                data += sock.recv(length - len(data))
        finally:
            sock.close()
        return DNSRecord.parse(data)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return DNSRecord.parse(data)


@pytest.fixture()
def dns_service():
    sid = "a" * 32
    port = free_port()
    store = Store(":memory:")
    store.create_session(sid, ttl_seconds=300)
    service = DnsProbeService(_dns_config(port), store)
    service.start()
    time.sleep(0.05)
    yield service, store, sid, port
    service.stop()


def test_probe_label_parsing():
    sid = "0123456789abcdef0123456789abcdef"
    assert parse_probe_label(sid + "0f") == (sid, 15)
    assert parse_probe_label(sid + "00") == (sid, 0)
    assert parse_probe_label("not-a-session") is None
    assert parse_probe_label("Z" * 34) is None
    assert parse_probe_label(sid) is None


def test_dns_query_is_recorded_with_source(dns_service):
    service, store, sid, port = dns_service
    reply = _query(port, f"{sid}01.probe.test.invalid")
    assert reply.header.rcode == 0
    answers = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
    assert answers and str(answers[0].rdata) == "192.0.2.1"
    assert reply.header.aa == 1

    observations = store.observations(sid, "dns")
    assert len(observations) == 1
    obs = observations[0]
    assert obs.source_ip == "127.0.0.1"
    assert obs.source_family == 4
    assert obs.transport == "udp"
    assert obs.detail["seq"] == 1
    assert obs.detail["qname"].startswith(sid)


def test_dns_tcp_transport(dns_service):
    service, store, sid, port = dns_service
    reply = _query(port, f"{sid}02.probe.test.invalid", tcp=True)
    assert reply.header.rcode == 0
    obs = store.observations(sid, "dns")
    assert len(obs) == 1 and obs[0].transport == "tcp"


def test_dns_unknown_label_is_nxdomain(dns_service):
    service, store, sid, port = dns_service
    reply = _query(port, "unrelated.probe.test.invalid")
    assert reply.header.rcode == 3  # NXDOMAIN
    assert store.observations(sid, "dns") == []


def test_dns_outside_zone_is_refused(dns_service):
    service, store, sid, port = dns_service
    reply = _query(port, f"{sid}00.example.org")
    assert reply.header.rcode == 3


def test_dns_expired_session_not_recorded():
    sid = "b" * 32
    port = free_port()
    store = Store(":memory:")
    store.create_session(sid, ttl_seconds=1, now=time.time() - 10)
    service = DnsProbeService(_dns_config(port), store)
    service.start()
    try:
        time.sleep(0.05)
        reply = _query(port, f"{sid}00.probe.test.invalid")
        assert reply.header.rcode == 0  # 仍然应答，避免探测页卡住
        assert store.observations(sid, "dns") == []
    finally:
        service.stop()


# --------------------------------------------------------------------------
# STUN
# --------------------------------------------------------------------------
def _binding_request(txid: bytes = b"0123456789ab") -> bytes:
    return struct.pack("!HHI", 0x0001, 0, MAGIC_COOKIE) + txid


def test_stun_binding_response_roundtrip():
    txid = b"abcdefghijkl"
    response = build_binding_response("198.51.100.7", 54321, txid)
    msg_type, length, cookie = struct.unpack("!HHI", response[:8])
    assert msg_type == BINDING_RESPONSE
    assert cookie == MAGIC_COOKIE
    assert len(response) == 20 + length
    assert response[8:20] == txid
    # 解析 XOR-MAPPED-ADDRESS
    offset = 20
    found = {}
    while offset < len(response):
        kind, length = struct.unpack("!HH", response[offset : offset + 4])
        value = response[offset + 4 : offset + 4 + length]
        found[kind] = value
        offset += 4 + length + ((4 - length % 4) % 4)
    xor = found[0x0020]
    assert xor[1] == 0x01
    port = struct.unpack("!H", xor[2:4])[0] ^ (MAGIC_COOKIE >> 16)
    assert port == 54321
    ip = bytes(a ^ b for a, b in zip(xor[4:8], struct.pack("!I", MAGIC_COOKIE), strict=True))
    assert socket.inet_ntoa(ip) == "198.51.100.7"


def test_stun_rejects_bad_packets():
    with pytest.raises(StunError):
        parse_binding_request(b"\x00" * 4)
    with pytest.raises(StunError):
        parse_binding_request(struct.pack("!HHI", 0x0001, 0, 0) + b"x" * 12)
    with pytest.raises(StunError):
        parse_binding_request(struct.pack("!HHI", 0x0003, 0, MAGIC_COOKIE) + b"x" * 12)


def test_stun_end_to_end_allocates_port_and_records():
    port = free_port()
    config = make_config(
        dns={"enabled": False},
        stun={
            "enabled": True,
            "listen_host": "127.0.0.1",
            "port_range": {"base": port, "size": 4},
        },
    )
    store = Store(":memory:")
    sid = "c" * 32
    store.create_session(sid, ttl_seconds=300)
    service = StunService(config.stun, store)
    service.start()
    try:
        uris = service.uris(sid)
        assert len(uris) == 1 and uris[0].startswith("stun:")
        udp_port = int(uris[0].rsplit(":", 1)[1])
        assert udp_port == port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(_binding_request(), ("127.0.0.1", udp_port))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        assert struct.unpack("!H", data[:2])[0] == BINDING_RESPONSE
        obs = store.observations(sid, "stun")
        assert len(obs) == 1
        assert obs[0].source_ip == "127.0.0.1"
        assert obs[0].detail["method"] == "binding"
    finally:
        service.stop()


def test_stun_release_frees_port():
    port = free_port()
    config = make_config(
        dns={"enabled": False},
        stun={"port_range": {"base": port, "size": 2}},
    )
    store = Store(":memory:")
    sid = "d" * 32
    store.create_session(sid, ttl_seconds=300)
    service = StunService(config.stun, store)
    service.start()
    try:
        first = service.port_for_session(sid)
        assert first == port
        service.release(sid)
        assert service.port_for_session(sid) == port
    finally:
        service.stop()
