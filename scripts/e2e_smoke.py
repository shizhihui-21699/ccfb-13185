"""端到端冒烟测试：启动 Streamlit + 探针，用真实浏览器走一遍。

需要 Playwright 与 Chromium（仅本地开发用，不在生产依赖里）：
    pip install playwright && playwright install chromium
    python scripts/e2e_smoke.py

脚本会在随机端口上启动服务，用无头 Chrome 打开页面，等待探测完成后
把页面上的各项结论打印出来。
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(0.4)
    return False


def build_config(
    workdir: Path, collector_port: int, stun_base: int, dns_port: int | None = None
) -> Path:
    if dns_port is None:
        dns_block = """
[dns]
enabled = false
zone = "probe.test.invalid"
"""
    else:
        dns_block = f"""
[dns]
enabled = true
zone = "probe.test.invalid"
listen_host = "127.0.0.1"
listen_port = {dns_port}
answer_ipv4 = ["192.0.2.1"]
wait_seconds = 3.0
"""
    config = f"""
[app]
title = "端到端自检"
public_url = "http://127.0.0.1:8501"
allowed_origins = ["http://127.0.0.1:8501"]
session_ttl_seconds = 600
poll_interval_seconds = 1.0

[collector]
listen_host = "127.0.0.1"
listen_port = {collector_port}
public_url_v4 = "http://127.0.0.1:{collector_port}"
trust_forwarded_for = false
trusted_proxies = []

{dns_block}
[stun]
enabled = true
listen_host = "127.0.0.1"
listen_port = 3478
public_host_v4 = "127.0.0.1"
public_port_v4 = 3478
port_range = {{ base = {stun_base}, size = 32 }}

[policy]
app_requires_tunnel = false

[[egress]]
name = "本机回路（测试用）"
cidr = ["127.0.0.0/8"]
kind = "corporate"
"""
    path = workdir / "config.toml"
    path.write_text(config, encoding="utf-8")
    return path


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("需要 playwright：pip install playwright && playwright install chromium")
        return 2

    workdir = Path(tempfile.mkdtemp(prefix="vpncheck-e2e-"))
    collector_port = free_port()
    stun_base = free_port(socket.SOCK_DGRAM)
    # DNS 需要 53 端口且页面必须真能解析到探针；本地无权威 DNS 时跳过，
    # 用 VPNCHECK_E2E_DNS=1 强制开启（需要把 probe.test.invalid 指到 127.0.0.1）。
    dns_port = None
    if os.environ.get("VPNCHECK_E2E_DNS") == "1":
        dns_port = int(os.environ.get("VPNCHECK_E2E_DNS_PORT", "5399"))
    config_path = build_config(workdir, collector_port, stun_base, dns_port)
    env = {
        **os.environ,
        "VPNCHECK_CONFIG": str(config_path),
        "VPNCHECK_DB": str(workdir / "e2e.sqlite3"),
        "STREAMLIT_SERVER_HEADLESS": "true",
        "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false",
        "STREAMLIT_SERVER_PORT": "8501",
        "STREAMLIT_SERVER_ADDRESS": "127.0.0.1",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "app.py")],
        env=env,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    collected: list[str] = []
    try:
        if not wait_for("http://127.0.0.1:8501/_stcore/health"):
            print("服务未能启动")
            out = proc.stdout.read() if proc.stdout else ""
            print(out[-4000:])
            return 1

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                args=["--no-sandbox", "--use-fake-ui-for-media-stream"]
            )
            page = browser.new_page()
            page.on("console", lambda m: collected.append(f"[console:{m.type}] {m.text}"))
            page.goto("http://127.0.0.1:8501", wait_until="domcontentloaded")
            deadline = time.time() + 45
            text = ""
            while time.time() < deadline:
                page.wait_for_timeout(1500)
                text = page.inner_text("body")
                if "未发现泄露" in text or "检测到泄露" in text or "有项目需要确认" in text:
                    break
            browser.close()

        print("=" * 70)
        print(page_text_excerpt(text))
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if collected:
            print("=" * 70)
            print("浏览器控制台：")
            for line in collected[:20]:
                print(" ", line)

    db_path = workdir / "e2e.sqlite3"
    if db_path.exists():
        import sqlite3

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        print("=" * 70)
        print("数据库中的观测：")
        for row in conn.execute(
            "SELECT kind, source_ip, source_family, transport FROM observations"
        ):
            print(
                f"  {row['kind']:<6} {row['source_ip']:<20}"
                f" family={row['source_family']} {row['transport']}"
            )
        for row in conn.execute("SELECT kind, payload FROM browser_reports"):
            payload = json.loads(row["payload"])
            print(f"  report {row['kind']}: {json.dumps(payload, ensure_ascii=False)[:400]}")
        conn.close()
    return 0


def page_text_excerpt(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    keep = []
    for line in lines:
        if len(line) > 200:
            line = line[:200] + "…"
        keep.append(line)
    return "\n".join(keep[:80])


if __name__ == "__main__":
    raise SystemExit(main())
