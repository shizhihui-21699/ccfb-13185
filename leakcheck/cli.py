"""Operational entry point: ``python -m leakcheck``.

Sub-commands
------------
``all``        run the collector, DNS probe and STUN probe in one process
``collector``  HTTP API only
``dns``        authoritative DNS probe only
``stun``       STUN probe only
``selftest``   send synthetic probes through the local listeners and print what
               was observed — the fastest way to prove a deployment works
``check``      validate the configuration file and print the effective inventory
``export``     dump one session's observations as JSON (support use)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
from typing import Any

from .config import AppConfig, ConfigError, load_config, redacted_dump
from .storage import Store
from .tokens import new_token

log = logging.getLogger("leakcheck")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_check(config: AppConfig) -> int:
    print(f"站点标题      : {config.site_title}")
    print(f"探针域        : {config.probe_domain}")
    print(f"采集端        : {config.server.public_base_url}")
    print(f"数据库        : {config.server.database_path}")
    print(f"DNS 监听      : {config.dns.bind_host}:{config.dns.bind_port} "
          f"({'启用' if config.dns.enabled else '禁用'})")
    print(f"STUN 端口     : {config.stun.ports} "
          f"({'启用' if config.stun.enabled else '禁用'})")
    print()
    print("出口清单：")
    for label, inventory in (
        ("VPN 出口", config.exits.vpn_egress),
        ("解析器出口", config.exits.corp_resolvers),
        ("办公网直出", config.exits.office_egress),
    ):
        names = ", ".join(str(n) for n in inventory.networks) or "（空）"
        flag = "  ⚠ 空清单会导致该项永远判为泄露" if not inventory.networks and label != "办公网直出" else ""
        print(f"  {label:8s}: {names}{flag}")
    if config.exits.known_third_party_resolvers:
        vendors = ", ".join(config.exits.known_third_party_resolvers)
        print(f"  公共解析器: {vendors}")
    print()
    print(f"忽略网段数量  : {len(config.exits.ignored_ranges)}")
    print(f"HMAC 密钥     : {'来自配置/环境变量' if config.server.hmac_secret else '临时生成（进程重启后旧令牌失效）'}")
    return 0


def cmd_selftest(config: AppConfig, rounds: int = 1) -> int:
    """Exercise every local listener with synthetic traffic and print results."""
    from .dnsserver import DnsProbeServer
    from .stunserver import StunServer

    store = Store(config.server.database_path)
    dns = DnsProbeServer(config, store)
    stun = StunServer(config, store)
    failures: list[str] = []

    # Zero means "pick one": the self-test should not fight the production ports.
    if config.dns.enabled:
        dns.start()
    if config.stun.enabled:
        stun.start()

    token = new_token(config.server.hmac_secret)
    store.create_session(token, config.server.session_ttl_seconds, "127.0.0.1", "selftest", "selftest")
    port = store.assign_stun_port(token, stun.bound_ports or config.stun.ports,
                                  config.server.session_ttl_seconds)
    print(f"自检会话 {token}")

    if config.dns.enabled:
        for variant, qtype in (("sys1", "A"), ("v6", "AAAA"), ("txt", "TXT")):
            name = f"{token}-{variant}.{config.dns.zone}"
            try:
                result = _dns_query(name, qtype, "127.0.0.1", dns.bound_port or config.dns.bind_port)
                print(f"  DNS {qtype:5s} {name} -> rcode={result['rcode']} "
                      f"answers={result['answers'] or '(空)'}")
                if result["rcode"] != 0:
                    failures.append(f"DNS {qtype} 返回 rcode={result['rcode']}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"DNS {qtype} 查询失败: {exc}")
                print(f"  DNS {qtype:5s} 查询失败: {exc}")

    if config.stun.enabled and port is not None:
        try:
            reply = stun.self_query(token, port)
            print(f"  STUN  127.0.0.1:{port} -> {reply['type']} software={reply['software']!r}")
            if reply["type"] != "0x101":
                failures.append("STUN 未返回 Binding Success")
        except Exception as exc:  # noqa: BLE001
            failures.append(f"STUN 查询失败: {exc}")
            print(f"  STUN 查询失败: {exc}")

    observations = store.observations(token)
    counts = store.counts(token)
    print(f"  观测计数: {counts}")
    dns_hits = [o for o in observations if o.channel == "dns"]
    stun_hits = [o for o in observations if o.channel == "stun"]
    if config.dns.enabled and not dns_hits:
        failures.append("DNS 通道没有记录到任何观测")
    if config.stun.enabled and not stun_hits:
        failures.append("STUN 通道没有记录到任何观测")
    if dns_hits:
        print("  DNS 观测: " + ", ".join(
            f"{o.source_ip}:{o.source_port} {o.transport} {o.detail.get('qtype')}" for o in dns_hits
        ))

    dns.stop()
    stun.stop()

    if failures:
        print("\n自检失败：")
        for item in failures:
            print(f"  ✗ {item}")
        return 1
    print("\n自检通过：DNS 与 STUN 通道均能记录观测。")
    return 0


def _dns_query(name: str, qtype: str, host: str, port: int) -> dict[str, Any]:
    from dnslib import DNSRecord

    record = DNSRecord.question(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3.0)
        sock.sendto(record.pack(), (host, port))
        data, _ = sock.recvfrom(4096)
    reply = DNSRecord.parse(data)
    return {"rcode": reply.header.rcode, "answers": [str(rr.rdata) for rr in reply.rr]}


def cmd_collector(config: AppConfig) -> int:
    import uvicorn

    from .collector import create_app

    app = create_app(config)
    uvicorn.run(
        app,
        host=config.server.collector_bind,
        port=config.server.collector_port,
        log_level="info",
        proxy_headers=True,
    )
    return 0


def cmd_dns(config: AppConfig) -> int:
    from .dnsserver import DnsProbeServer

    store = Store(config.server.database_path)
    server = DnsProbeServer(config, store)
    server.start()
    return _wait_forever(server)


def cmd_stun(config: AppConfig) -> int:
    from .stunserver import StunServer

    store = Store(config.server.database_path)
    server = StunServer(config, store)
    server.start()
    return _wait_forever(server)


def cmd_all(config: AppConfig) -> int:
    """Run DNS, STUN and the HTTP collector in one process (small deployments)."""
    import uvicorn

    from .collector import create_app
    from .dnsserver import DnsProbeServer
    from .stunserver import StunServer

    store = Store(config.server.database_path)
    dns = DnsProbeServer(config, store)
    stun = StunServer(config, store)
    dns.start()
    stun.start()
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.server.collector_bind,
        port=config.server.collector_port,
        log_level="info",
        proxy_headers=True,
    )
    dns.stop()
    stun.stop()
    return 0


def _wait_forever(*servers) -> int:
    stop = threading.Event()

    def handle(signum, _frame):
        log.info("收到信号 %s，正在退出", signum)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handle)
        except ValueError:  # not in the main thread
            pass
    while not stop.is_set():
        stop.wait(1.0)
    for server in servers:
        server.stop()
    return 0


def cmd_export(config: AppConfig, token: str) -> int:
    store = Store(config.server.database_path)
    session = store.get_session(token)
    if session is None:
        print(f"找不到会话 {token}", file=sys.stderr)
        return 1
    payload = {
        "session": {
            "token": session.token,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "peer_ip": session.peer_ip,
            "user_agent": session.user_agent,
            "stage": session.stage,
            "stun_port": session.stun_port,
        },
        "observations": [
            {
                "channel": obs.channel,
                "observed_at": obs.observed_at,
                "source_ip": obs.source_ip,
                "source_port": obs.source_port,
                "transport": obs.transport,
                "detail": obs.detail,
            }
            for obs in store.observations(token)
        ],
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_export_token(config: AppConfig, ttl: int) -> int:
    """Mint a signed token and create its session (deployment smoke tests)."""
    store = Store(config.server.database_path)
    token = new_token(config.server.hmac_secret)
    store.create_session(token, max(ttl, config.server.session_ttl_seconds), None, "cli", "cli")
    port = store.assign_stun_port(token, config.stun.ports, max(ttl, config.server.session_ttl_seconds))
    print(token)
    print(
        f"# 探针名: {token}-<4位随机>sys1.{config.dns.zone}"
        f"\n# STUN 端口: {port if port is not None else '未分配'}"
        f"\n# 数据库: {config.server.database_path}",
        file=sys.stderr,
    )
    return 0


def cmd_purge(config: AppConfig, days: int) -> int:
    store = Store(config.server.database_path)
    removed = store.purge(keep_seconds=days * 86400)
    print(f"已清理 {removed} 条过期记录（保留 {days} 天）")
    return 0


# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakcheck",
        description="VPN 流量泄露自检服务（采集端 / DNS 探针 / STUN 探针）",
    )
    parser.add_argument("-c", "--config", default=os.environ.get("LEAKCHECK_CONFIG", "config.yaml"),
                        help="配置文件路径（默认 config.yaml）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="校验配置并打印生效的出口清单")
    sub.add_parser("selftest", help="用合成流量验证 DNS/STUN 监听器")
    sub.add_parser("all", help="同时运行采集端 + DNS + STUN")
    sub.add_parser("collector", help="只运行 HTTP 采集端")
    sub.add_parser("dns", help="只运行 DNS 授权探针")
    sub.add_parser("stun", help="只运行 STUN 探针")
    export = sub.add_parser("export", help="导出某个会话的观测数据")
    export.add_argument("token")
    export_token = sub.add_parser("export-token", help="生成一个探针令牌用于部署自测")
    export_token.add_argument("--ttl", type=int, default=900)
    purge = sub.add_parser("purge", help="清理过期数据")
    purge.add_argument("--days", type=int, default=7)
    sub.add_parser("dump-config", help="打印脱敏后的生效配置")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"配置错误: {exc}", file=sys.stderr)
        return 2
    command = args.command
    if command == "check":
        return cmd_check(config)
    if command == "selftest":
        return cmd_selftest(config)
    if command == "collector":
        return cmd_collector(config)
    if command == "dns":
        return cmd_dns(config)
    if command == "stun":
        return cmd_stun(config)
    if command == "all":
        return cmd_all(config)
    if command == "export":
        return cmd_export(config, args.token)
    if command == "export-token":
        return cmd_export_token(config, args.ttl)
    if command == "purge":
        return cmd_purge(config, args.days)
    if command == "dump-config":
        print(json.dumps(redacted_dump(config), ensure_ascii=False, indent=2, default=str))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
