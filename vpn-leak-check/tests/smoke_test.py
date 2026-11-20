"""冒烟测试：高端口启动 DNS + API，模拟一次完整检测并校验判定逻辑。

用法：.venv/bin/python tests/smoke_test.py
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, ".")

from leakcheck.analysis import analyze
from leakcheck.api import create_app
from leakcheck.db import DB
from leakcheck.dns_server import start_dns_server

CFG = {
    "zone": "check.test",
    "server_ipv4": "127.0.0.1",
    "server_ipv6": "",
    "company_egress": ["127.0.0.0/8"],
    "company_dns": ["127.0.0.0/8"],
    "company_egress_v6": [],
    "stun_servers": [],
    "ports": {"dns": 15353, "api": 18000, "web": 18501},
    "trust_proxy_headers": False,
}

TOKEN = "smoketest01"
failures = []


def check(name, cond, extra=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")
    if not cond:
        failures.append(name)


def dns_query(qname, qtype="A", server=("127.0.0.1", 15353)):
    from dnslib import DNSRecord
    q = DNSRecord.question(qname, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q.pack(), server)
    data, _ = s.recvfrom(4096)
    s.close()
    return DNSRecord.parse(data)


def http_get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


def main():
    db = DB(tempfile.mktemp(suffix=".db"))
    db.create_session(TOKEN)

    start_dns_server(CFG, db)

    import uvicorn
    api = uvicorn.Server(uvicorn.Config(
        create_app(db, CFG), host="127.0.0.1", port=18000, log_level="error"))
    threading.Thread(target=api.run, daemon=True).start()
    time.sleep(1.5)

    print("== 1. DNS 权威服务器 ==")
    r = dns_query(f"{TOKEN}.dns.check.test")
    got_a = str(r.rr[0].rdata) if r.rr else ""
    check("唯一子域解析返回服务器地址", got_a == "127.0.0.1", f"(A={got_a})")
    r6 = dns_query("ipv6.check.test", "AAAA")
    check("ipv6 子域无 AAAA（未配置 v6 时）", len(r6.rr) == 0)
    r4 = dns_query("ipv4.check.test")
    check("ipv4 子域返回 A 记录", r4.rr and str(r4.rr[0].rdata) == "127.0.0.1")

    print("== 2. 探针 API ==")
    web = http_get(f"http://127.0.0.1:18000/api/probe/web?token={TOKEN}")
    check("web 探针返回出口 IP", web.get("ip") == "127.0.0.1", f"({web})")
    hit = http_get(f"http://127.0.0.1:18000/api/probe/dns-hit?token={TOKEN}")
    check("dns-hit 回源记录", hit.get("ip") == "127.0.0.1")
    req = urllib.request.Request(
        f"http://127.0.0.1:18000/api/report/{TOKEN}",
        data=json.dumps({"webrtc": [{"ip": "192.168.1.5", "type": "host"},
                                    {"ip": "45.67.89.10", "type": "srflx"}]}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    rep = json.loads(urllib.request.urlopen(req, timeout=3).read())
    check("webrtc 上报", rep.get("received") == 2)

    print("== 3. 判定逻辑（正常场景：全部走隧道） ==")
    events = db.get_events(TOKEN)
    check("DNS 事件已记录解析器出口", any(e["kind"] == "dns" and e["ip"] == "127.0.0.1" for e in events))
    # webrtc 里的 203.0.113.9 不在公司段内，正常场景应判泄露——把它从事件里排除模拟干净场景
    clean = [e for e in events if not (e["kind"] == "webrtc" and e["ip"] == "45.67.89.10")]
    res = analyze(CFG, db.get_session(TOKEN), clean)
    by_key = {c["key"]: c["status"] for c in res["checks"]}
    check("web=ok", by_key["web"] == "ok")
    check("dns=ok", by_key["dns"] == "ok")
    check("webrtc=ok", by_key["webrtc"] == "ok")
    check("ipv6=ok(无连通)", by_key["ipv6"] == "ok")

    print("== 4. 判定逻辑（泄露场景） ==")
    leak_events = clean + [
        {"kind": "web", "ip": "8.8.8.8", "ts": 0, "extra": {}},
        {"kind": "dns", "ip": "114.114.114.114", "ts": 0, "extra": {}},
        {"kind": "webrtc", "ip": "45.67.89.10", "ts": 0, "extra": {"type": "srflx"}},
        {"kind": "ipv6", "ip": "240e:1234::1", "ts": 0, "extra": {}},
    ]
    res2 = analyze(CFG, {"user_agent": "Mozilla/5.0 (Windows NT 10.0)"}, leak_events)
    by_key2 = {c["key"]: c["status"] for c in res2["checks"]}
    check("web=fail(非公司出口)", by_key2["web"] == "fail")
    check("dns=fail(解析器泄露)", by_key2["dns"] == "fail")
    check("webrtc=fail(暴露真实IP)", by_key2["webrtc"] == "fail")
    check("ipv6=fail(绕过隧道)", by_key2["ipv6"] == "fail")
    check("overall=fail", res2["overall"] == "fail")
    check("OS 识别为 windows", res2["os"] == "windows")

    print()
    if failures:
        print(f"❌ {len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("✅ 全部冒烟测试通过")


if __name__ == "__main__":
    main()
