#!/usr/bin/env python3
"""End-to-end check with a real browser.

This is *not* a unit test: it boots the real collector + DNS + STUN listeners,
drives a real Chromium through the actual probe page, and asserts that all four
channels produce server-side observations.

The browser is pointed at a tiny SOCKS5 proxy that performs remote DNS (exactly
what a corporate proxy or an HTTP-CONNECT proxy does).  That lets us observe a
real browser-initiated DNS lookup reaching the authoritative listener, while
HTTP goes through the proxy and WebRTC/STUN goes out over UDP directly — the
"only some protocols follow the tunnel" situation the service exists to catch.

Usage:  python scripts/e2e_browser.py [--headful]
Requires: playwright + chromium (``python -m playwright install chromium``).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from leakcheck.config import load_config  # noqa: E402

CONFIG_YAML = """
site:
  title: 端到端自检
  probe_domain: probe.e2e.test
server:
  public_base_url: http://127.0.0.1:{http_port}
  collector_bind: 127.0.0.1
  collector_port: {http_port}
  database_path: {db}
  hmac_secret: "e2e-secret-0123456789abcdefghijklmno"
  session_ttl_seconds: 900
  rate_limit_per_minute: 600
dns:
  enabled: true
  bind_host: 127.0.0.1
  bind_port: {dns_port}
  zone: probe.e2e.test
  answer_ipv4: ["127.0.0.1"]
  answer_ipv6: ["::1"]
stun:
  enabled: true
  bind_host: 127.0.0.1
  ports: [{stun_port}]
  public_ips: ["127.0.0.1"]
  bind_ipv6: false
exit_inventory:
  vpn_egress:
    addresses: ["198.51.100.0/24"]
  corp_resolvers:
    addresses: ["198.51.100.21/32"]
  office_egress:
    addresses: ["203.0.113.0/24"]
remediation:
  support_contact: IT 服务台
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Socks5RemoteDNS:
    """Minimal SOCKS5 server that resolves via the DNS probe, then refuses.

    Chrome sends the *hostname* to a SOCKS5 proxy (remote DNS), so the lookup a
    real user's resolver would perform happens here.  We forward it to the
    authoritative listener and then close the connection: the probe page's
    ``<img>`` load is expected to fail, the observation is what matters.
    """

    def __init__(self, dns_port: int):
        self.dns_port = dns_port
        self.server: asyncio.AbstractServer | None = None
        self.port = 0
        self.lookups: list[str] = []
        self._loop = asyncio.new_event_loop()
        self._thread: threading.Thread | None = None

    async def _start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    def start(self) -> None:
        """Serve on a dedicated event loop thread.

        ``asyncio.run(...)`` closes its loop when the coroutine returns, which
        would silently kill the listener — so the loop is kept alive here.
        """
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start())
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        async def _shutdown() -> None:
            if self.server:
                self.server.close()
                await self.server.wait_closed()

        if self.server:
            asyncio.run_coroutine_threadsafe(_shutdown(), self._loop).result(timeout=5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            greeting = await reader.readexactly(2)
            if greeting[0] != 0x05:
                return
            methods = await reader.readexactly(greeting[1])
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()

            header = await reader.readexactly(4)
            atyp = header[3]
            if atyp == 0x03:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode()
            elif atyp == 0x01:
                host = socket.inet_ntoa(await reader.readexactly(4))
            else:
                host = (await reader.readexactly(16)).hex()
            await reader.readexactly(2)  # port

            if host.endswith("probe.e2e.test"):
                self.lookups.append(host)
                await asyncio.to_thread(self._resolve, host)
            # Reply "host unreachable": the probe only needs the lookup to happen.
            writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, asyncio.CancelledError):
                pass

    def _resolve(self, name: str) -> None:
        query = bytearray(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        for label in name.split("."):
            query.append(len(label))
            query += label.encode()
        query += b"\x00\x00\x01\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.sendto(bytes(query), ("127.0.0.1", self.dns_port))
            try:
                sock.recvfrom(4096)
            except TimeoutError:
                pass


class PacServer:
    """Serve a PAC file that sends only the probe domain through SOCKS5.

    This models the common corporate setup: everything else is direct, but the
    corporate suffix is resolved by a proxy.  Only that suffix needs the proxy,
    so the page itself keeps loading normally (unlike a blanket --proxy-server).
    """

    def __init__(self, socks_port: int):
        self.socks_port = socks_port
        self.server: socket.socket | None = None
        self.port = 0
        self._thread: threading.Thread | None = None

    def _loop(self) -> None:
        assert self.server is not None
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(4096)
                    body = (
                        "function FindProxyForURL(url, host) {\n"
                        "  if (dnsDomainIs(host, '.probe.e2e.test')) {\n"
                        f"    return 'SOCKS5 127.0.0.1:{self.socks_port}';\n"
                        "  }\n"
                        "  return 'DIRECT';\n"
                        "}\n"
                    ).encode()
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                        + body
                    )
                except OSError:
                    pass

    def start(self) -> str:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}/proxy.pac"

    def stop(self) -> None:
        if self.server:
            self.server.close()


def wait_http(port: int, timeout: float = 20.0) -> None:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as resp:
                if resp.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    raise RuntimeError("采集端未在超时时间内就绪")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--keep", action="store_true", help="保留临时目录与服务日志")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    tmp = Path(tempfile.mkdtemp(prefix="leakcheck-e2e-"))
    http_port, dns_port, stun_port = free_port(), free_port(), free_port()
    config_path = tmp / "config.yaml"
    config_path.write_text(
        CONFIG_YAML.format(
            http_port=http_port, dns_port=dns_port, stun_port=stun_port,
            db=str(tmp / "leakcheck.db"),
        ),
        encoding="utf-8",
    )
    log_path = tmp / "server.log"
    log_file = log_path.open("w")
    server = subprocess.Popen(
        [sys.executable, "-m", "leakcheck", "-c", str(config_path), "all"],
        cwd=ROOT, stdout=log_file, stderr=subprocess.STDOUT,
    )
    failures: list[str] = []
    try:
        wait_http(http_port)
        load_config(config_path)  # fail fast on a broken config before booting

        socks = Socks5RemoteDNS(dns_port)
        socks.start()
        pac = PacServer(socks.port)
        pac_url = pac.start()
        print(f"采集端 :{http_port}  DNS :{dns_port}  STUN :{stun_port}  SOCKS5 :{socks.port}")

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=not args.headful,
                args=[
                    f"--proxy-pac-url={pac_url}",
                    "--disable-features=WebRtcHideLocalIpsWithMdns",
                ],
            )
            page = browser.new_page()
            console: list[str] = []
            page.on("console", lambda msg: console.append(msg.text))
            page.goto(f"http://127.0.0.1:{http_port}/probe.html", wait_until="load")
            # The standalone page creates its own session, runs the probe and polls.
            page.wait_for_selector("#state:has-text('采集完成')", timeout=45000)
            rows = page.inner_text("#rows")
            print("\n--- 页面结果 ---")
            print(rows)
            state = page.inner_text("#state")
            print(f"状态: {state}")
            browser.close()

        pac.stop()
        socks.stop()

        # Inspect what the server actually recorded.
        token = None
        import sqlite3

        conn = sqlite3.connect(tmp / "leakcheck.db")
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT token FROM sessions ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            failures.append("没有创建任何会话")
        else:
            token = row["token"]
            rows = conn.execute(
                "SELECT channel, source_ip, transport, detail_json FROM observations WHERE token=?",
                (token,),
            ).fetchall()
            by_channel: dict[str, list[dict]] = {}
            for item in rows:
                by_channel.setdefault(item["channel"], []).append(
                    {"ip": item["source_ip"], "transport": item["transport"],
                     "detail": json.loads(item["detail_json"] or "{}")}
                )
            print("\n--- 服务端观测 ---")
            for channel in ("http", "dns", "stun", "webrtc"):
                items = by_channel.get(channel, [])
                print(f"{channel:7s} {len(items):3d} 条")
                for item in items[:4]:
                    print(f"    {item['ip']} {item['transport']} {item['detail'].get('kind') or item['detail'].get('qtype') or ''}")
            for channel in ("http", "dns", "stun", "webrtc"):
                if not by_channel.get(channel):
                    failures.append(f"{channel} 通道没有观测")
            dns_names = [
                item["detail"].get("qname", "")
                for item in by_channel.get("dns", [])
            ]
            if token and not any(token in name for name in dns_names):
                failures.append("DNS 观测中的查询名不含本次会话令牌")
            stun_ports = {item["detail"].get("local_port") for item in by_channel.get("stun", [])}
            if stun_ports and stun_ports != {stun_port}:
                failures.append(f"STUN 观测的本地端口异常: {stun_ports}")
        conn.close()

        print("\n--- 浏览器侧 SOCKS DNS 解析 ---")
        print(socks.lookups[:8])
        if not any("probe.e2e.test" in name for name in socks.lookups):
            failures.append("浏览器没有发起探针域名的解析")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        log_file.close()
        if not args.keep and not failures:
            for path in [*tmp.glob("*")]:
                path.unlink()
            tmp.rmdir()
        else:
            print(f"\n服务日志: {log_path}")

    print()
    if failures:
        print("端到端检查失败：")
        for failure in failures:
            print(f"  ✗ {failure}")
        return 1
    print("端到端检查通过：真实浏览器在四个通道都产生了服务端可观测的记录。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
