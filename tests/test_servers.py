"""Protocol-level tests for the DNS and STUN listeners (real sockets)."""

from __future__ import annotations

import socket
import struct
import time

import pytest
from dnslib import DNSHeader, DNSQuestion, DNSRecord, EDNS0, EDNSOption, QTYPE, TXT

from leakcheck.dnsserver import DnsProbeServer
from leakcheck.stunserver import (
    ATTR_XOR_MAPPED_ADDRESS,
    BINDING_REQUEST,
    BINDING_SUCCESS,
    MAGIC_COOKIE,
    StunError,
    StunServer,
    parse_message,
)
from leakcheck.tokens import new_token


@pytest.fixture()
def dns_server(config, store):
    config.dns.bind_port = 0
    server = DnsProbeServer(config, store)
    server.start()
    time.sleep(0.05)
    yield server
    server.stop()


@pytest.fixture()
def stun_server(config, store):
    config.stun.ports = [0, 0]
    server = StunServer(config, store)
    server.start()
    time.sleep(0.05)
    yield server
    server.stop()


def _udp_query(payload: bytes, port: int, timeout: float = 3.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    return data


def _query(name: str, qtype=QTYPE.A, edns: bool = False, ecs: bytes | None = None) -> bytes:
    record = DNSRecord(DNSHeader(id=0x4242, rd=1))
    record.add_question(DNSQuestion(name, qtype))
    if edns:
        options = [EDNSOption(8, ecs)] if ecs else []
        record.add_ar(EDNS0(name, udp_len=1232, opts=options))
    return record.pack()


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def test_dns_answers_a_and_records_observation(config, store, dns_server):
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    name = f"{token}-sys1.{config.dns.zone}"
    reply = DNSRecord.parse(_udp_query(_query(name), dns_server.bound_port))
    assert reply.header.rcode == 0
    assert [str(rr.rdata) for rr in reply.rr] == ["203.0.113.10"]
    assert reply.rr[0].ttl == 0

    observations = store.observations(token)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.channel == "dns"
    assert obs.source_ip == "127.0.0.1"
    assert obs.transport == "udp"
    assert obs.detail["qname"] == name
    assert obs.detail["variant"] == "sys1"


def test_dns_answers_aaaa_for_v6_variant(config, store, dns_server):
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    name = f"{token}-v6.{config.dns.zone}"
    reply = DNSRecord.parse(_udp_query(_query(name, QTYPE.AAAA), dns_server.bound_port))
    assert [str(rr.rdata) for rr in reply.rr] == ["2001:db8::10"]


def test_dns_records_ecs_and_do_bit(config, store, dns_server):
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    # family=1, source prefix 24, scope 0, 203.0.113.0
    ecs = struct.pack("!HBB", 1, 24, 0) + bytes([203, 0, 113, 0])
    name = f"{token}-sys2.{config.dns.zone}"
    record = DNSRecord(DNSHeader(id=1, rd=1))
    record.add_question(DNSQuestion(name, QTYPE.A))
    record.add_ar(EDNS0(name, udp_len=1232, flags="do", opts=[EDNSOption(8, ecs)]))
    DNSRecord.parse(_udp_query(record.pack(), dns_server.bound_port))

    obs = store.observations(token)[0]
    assert obs.detail["ecs"] == "203.0.113.0/24"
    assert obs.detail["do"] is True
    assert obs.detail["edns"] is True


def test_dns_refuses_forged_token(config, store, dns_server):
    name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa-sys1." + config.dns.zone
    reply = DNSRecord.parse(_udp_query(_query(name), dns_server.bound_port))
    assert reply.header.rcode == 5
    assert store.observations("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") == []


def test_dns_refuses_out_of_zone(config, dns_server):
    reply = DNSRecord.parse(_udp_query(_query("example.com"), dns_server.bound_port))
    assert reply.header.rcode == 5


def test_dns_apex_soa(config, dns_server):
    reply = DNSRecord.parse(_udp_query(_query(config.dns.zone, QTYPE.SOA), dns_server.bound_port))
    assert reply.header.rcode == 0
    assert reply.rr and reply.rr[0].rtype == QTYPE.SOA


def test_dns_txt_echo(config, store, dns_server):
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    name = f"{token}-txt.{config.dns.zone}"
    reply = DNSRecord.parse(_udp_query(_query(name, QTYPE.TXT), dns_server.bound_port))
    assert reply.rr and isinstance(reply.rr[0].rdata, TXT)


def test_dns_over_tcp(config, store, dns_server):
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    payload = _query(f"{token}-sys1.{config.dns.zone}")
    with socket.create_connection(("127.0.0.1", dns_server.bound_port), timeout=3) as conn:
        conn.sendall(struct.pack("!H", len(payload)) + payload)
        length = struct.unpack("!H", conn.recv(2))[0]
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                break
            data += chunk
    reply = DNSRecord.parse(data)
    assert reply.header.rcode == 0
    observations = store.observations(token)
    assert [o.transport for o in observations] == ["tcp"]


def test_dns_ignores_garbage(config, dns_server):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.6)
        sock.sendto(b"\x00" * 5, ("127.0.0.1", dns_server.bound_port))
        with pytest.raises(socket.timeout):
            sock.recvfrom(4096)


def test_dns_probe_cap_per_token(config, store, dns_server):
    config.server.max_probes = 1
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    handler = dns_server.handler
    peer = ("127.0.0.1", 5555)
    payload = _query(f"{token}-sys1.{config.dns.zone}")
    for _ in range(20):
        handler.handle(payload, peer, "udp")
    # max_probes=1 means the cap is max_probes*8 = 8 recorded observations.
    assert len(store.observations(token)) == 8


def test_dns_does_not_answer_questions_with_multiple_records(config, dns_server):
    record = DNSRecord(DNSHeader(id=9, rd=1))
    record.add_question(DNSQuestion("a." + config.dns.zone, QTYPE.A))
    record.add_question(DNSQuestion("b." + config.dns.zone, QTYPE.A))
    reply = DNSRecord.parse(_udp_query(record.pack(), dns_server.bound_port))
    assert reply.header.rcode == 1  # FORMERR


# ---------------------------------------------------------------------------
# STUN
# ---------------------------------------------------------------------------

def test_stun_binding_success_and_attribution(config, store, stun_server):
    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    port = store.assign_stun_port(token, stun_server.bound_ports, 900)
    assert port in stun_server.bound_ports

    txid = b"\x07" * 12
    request = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + txid
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(request, ("127.0.0.1", port))
        data, _ = sock.recvfrom(2048)
    reply = parse_message(data)
    assert reply.msg_type == BINDING_SUCCESS
    assert ATTR_XOR_MAPPED_ADDRESS in reply.attributes
    assert reply.software and "leakcheck" in reply.software

    observations = store.observations(token)
    assert len(observations) == 1
    assert observations[0].channel == "stun"
    assert observations[0].detail["local_port"] == port


def test_stun_unattributed_port_is_not_recorded(config, store, stun_server):
    port = stun_server.bound_ports[0]
    txid = b"\x08" * 12
    request = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + txid
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(request, ("127.0.0.1", port))
        data, _ = sock.recvfrom(2048)
    # Still answered (a client must not hang), but attributed to nobody.
    reply = parse_message(data)
    assert reply.msg_type != BINDING_SUCCESS
    assert stun_server.stats()["unattributed"] >= 1


def test_stun_response_passes_rfc5769_fingerprint_check(config, store, stun_server):
    """Recompute the FINGERPRINT the way a real client does."""
    import binascii

    token = new_token(config.server.hmac_secret)
    store.create_session(token, 900, "198.51.100.7", "UA", None)
    port = store.assign_stun_port(token, stun_server.bound_ports, 900)
    request = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + b"\x09" * 12
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(request, ("127.0.0.1", port))
        data, _ = sock.recvfrom(2048)
    length = struct.unpack("!H", data[2:4])[0]
    body = data[20 : 20 + length]
    assert body[-8:-4] == struct.pack("!HH", 0x8028, 4)
    fingerprint = struct.unpack("!I", body[-4:])[0]
    expected = (binascii.crc32(data[: 20 + length - 8]) & 0xFFFFFFFF) ^ 0x5354554E
    assert fingerprint == expected


def test_stun_rejects_non_stun(config, stun_server):
    with pytest.raises(StunError):
        parse_message(b"\x00" * 20)
    with pytest.raises(StunError):
        parse_message(b"\x00\x01\x00\x00DEADBEEF" + b"\x00" * 12)


def test_stun_ignores_garbage_datagrams(config, store, stun_server):
    port = stun_server.bound_ports[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"garbage-not-stun", ("127.0.0.1", port))
    time.sleep(0.15)
    assert stun_server.stats()["errors"] >= 1


def test_stun_port_pool_maps_to_newest_session(config, store, stun_server):
    old, new = new_token(b"a"), new_token(b"b")
    store.create_session(old, 900, "1.1.1.1", "UA", None)
    store.create_session(new, 900, "1.1.1.1", "UA", None)
    store.assign_stun_port(old, [stun_server.bound_ports[0]], 900)
    port = store.assign_stun_port(new, stun_server.bound_ports, 900)
    assert store.lookup_stun_port(port) == new
