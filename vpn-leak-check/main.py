"""单进程启动器：权威 DNS（UDP/TCP 53）+ 探针 API（8000）+ Streamlit 页面（8501）。

用法：
    python main.py [-c config.yaml]
"""
from __future__ import annotations

import argparse
import logging
import os
import pathlib
import threading

import yaml

from leakcheck import shared
from leakcheck.db import DB

ROOT = pathlib.Path(__file__).resolve().parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("leakcheck.main")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default=str(ROOT / "config.yaml"))
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    db_path = os.environ.get("LEAKCHECK_DB", str(ROOT / "leakcheck.db"))
    db = DB(db_path)
    purged = db.purge_old(float(cfg.get("retention_seconds", 86400)))
    if purged:
        log.info("已清理 %s 条过期会话", purged)

    shared.CFG = cfg
    shared.DB = db

    # 1) 权威 DNS（后台线程）
    from leakcheck.dns_server import start_dns_server
    start_dns_server(cfg, db)

    # 2) 探针 API（后台线程，v4 + v6 双监听；单绑 "::" 在部分平台不收 IPv4）
    import uvicorn
    from leakcheck.api import create_app
    app = create_app(db, cfg)
    for host in ("0.0.0.0", "::"):
        api_cfg = uvicorn.Config(
            app, host=host, port=int(cfg["ports"]["api"]), log_level="warning"
        )
        threading.Thread(target=uvicorn.Server(api_cfg).run, daemon=True).start()
    log.info("API 已启动: 端口 %s (IPv4 + IPv6)", cfg["ports"]["api"])

    # 3) Streamlit 页面（主线程，bootstrap 需要）
    from streamlit import config as st_config
    from streamlit.web import bootstrap

    st_config.set_option("server.port", int(cfg["ports"]["web"]))
    st_config.set_option("server.address", "0.0.0.0")
    st_config.set_option("server.headless", True)
    st_config.set_option("browser.gatherUsageStats", False)
    log.info("Web 页面已启动: 端口 %s", cfg["ports"]["web"])
    bootstrap.run(str(ROOT / "leakcheck" / "ui.py"), False, [], {})


if __name__ == "__main__":
    main()
