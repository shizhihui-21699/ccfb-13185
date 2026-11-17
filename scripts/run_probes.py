"""只启动探针服务（采集端 + DNS + STUN），不启动 Streamlit。

适用场景
--------
* 采集端需要绑定 53/3478 等需要在系统层做过端口规划的端口；
* 希望把采集与页面分机部署，或由 systemd/supervisor 单独守护。

Streamlit 页面在 ``app.py`` 里会自己按需启动这三个服务；两者**不要**同时
运行，否则端口冲突。生产建议：

* ``scripts/run_probes.py`` 用 systemd 常驻；
* ``app.py`` 用独立的 unit 跑 Streamlit，且配置里把采集端地址指向上面这台。
  为了让页面自身也能做本地检测，``app.py`` 检测到采集端健康检查失败时会
  回退到内嵌模式（见 README「部署方式」）。
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vpncheck.collector import CollectorService  # noqa: E402
from vpncheck.config import ConfigError, load_config  # noqa: E402
from vpncheck.dns_probe import DnsProbeService  # noqa: E402
from vpncheck.store import Store  # noqa: E402
from vpncheck.stun import StunService  # noqa: E402

LOGGER = logging.getLogger("vpncheck.probes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动 VPN 自检的采集端、DNS 探针与 STUN")
    parser.add_argument("-c", "--config", help="配置文件路径（默认 ./config.toml）")
    parser.add_argument("--db", help="SQLite 路径（默认 <配置目录>/data/vpncheck.sqlite3）")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        LOGGER.error("配置错误：%s", exc)
        return 2

    db_path = args.db or str(Path(config.source_path).parent / "data" / "vpncheck.sqlite3")
    store = Store(db_path, ttl_seconds=config.app.session_ttl_seconds)
    services = {
        "collector": CollectorService(config.collector, config.app, store),
        "dns": DnsProbeService(config.dns, store),
        "stun": StunService(config.stun, store),
    }

    stop = threading.Event()

    def _shutdown(signum, _frame):  # noqa: ANN001, ARG001
        LOGGER.info("收到信号 %s，正在停止……", signum)
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    for name, service in services.items():
        try:
            service.start()
        except OSError as exc:
            LOGGER.error("启动 %s 失败：%s", name, exc)
            for other in services.values():
                other.stop()
            return 1

    LOGGER.info("全部探针已启动；出口表：%s", config.summary())
    try:
        while not stop.is_set():
            stop.wait(1.0)
    finally:
        for service in services.values():
            service.stop()
        store.close()
        LOGGER.info("已停止")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
