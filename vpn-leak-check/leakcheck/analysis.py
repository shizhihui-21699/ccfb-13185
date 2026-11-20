"""判定逻辑：把探针事件对照公司出口列表，得出每项检测的结论和修复建议。"""
from __future__ import annotations

import ipaddress


def _nets(cidrs: list[str]) -> list[ipaddress._BaseNetwork]:
    out = []
    for c in cidrs or []:
        try:
            out.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            pass
    return out


def _in_any(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        a.is_private or a.is_loopback or a.is_link_local
        or a.is_multicast or a.is_unspecified or a.is_reserved
    )


def detect_os(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "windows" in ua:
        return "windows"
    if "android" in ua:
        return "android"
    if "iphone" in ua or "ipad" in ua:
        return "ios"
    if "mac os" in ua or "macintosh" in ua:
        return "macos"
    if "linux" in ua:
        return "linux"
    return "unknown"


def analyze(cfg: dict, session: dict | None, events: list[dict]) -> dict:
    egress = _nets(cfg.get("company_egress"))
    dns_ok = _nets(cfg.get("company_dns")) or egress
    egress6 = _nets(cfg.get("company_egress_v6"))

    checks: list[dict] = []

    # ---------- 1. Web 流量出口 ----------
    web = [e for e in events if e["kind"] == "web"]
    if web:
        ip = web[-1]["ip"]
        if _in_any(ip, egress):
            checks.append({
                "key": "web", "title": "Web 流量出口", "status": "ok",
                "summary": f"出口 {ip} 属于公司地址段，网页流量经 VPN 隧道。",
                "details": "",
            })
        else:
            checks.append({
                "key": "web", "title": "Web 流量出口", "status": "fail",
                "summary": f"出口 {ip} 不在公司地址段内 —— 流量未走 VPN 隧道！",
                "details": "可能原因：VPN 未连接 / 分流（split tunnel）配置错误 / 代理绕过。",
            })
    else:
        checks.append({
            "key": "web", "title": "Web 流量出口", "status": "warn",
            "summary": "未收到 Web 探测请求，请重新检测。",
            "details": "",
        })

    # ---------- 2. DNS 解析出口 ----------
    dns = [e for e in events if e["kind"] == "dns"]
    if dns:
        resolvers = sorted({e["ip"] for e in dns})
        leaked = [r for r in resolvers if not _in_any(r, dns_ok)]
        if leaked:
            checks.append({
                "key": "dns", "title": "DNS 解析出口", "status": "fail",
                "summary": f"DNS 查询从非公司出口发出：{', '.join(leaked)} —— DNS 泄露！",
                "details": (
                    f"检测到的解析器出口：{', '.join(resolvers)}\n\n"
                    "这表示系统的 DNS 请求绕过了 VPN 隧道，访问内网域名可能失败，"
                    "且访问记录会被第三方解析器（运营商/公共 DNS）看到。"
                ),
            })
        else:
            checks.append({
                "key": "dns", "title": "DNS 解析出口", "status": "ok",
                "summary": f"解析器出口 {', '.join(resolvers)} 均为公司地址，DNS 未泄露。",
                "details": "",
            })
    else:
        checks.append({
            "key": "dns", "title": "DNS 解析出口", "status": "warn",
            "summary": "权威服务器未收到本次唯一域名的查询。",
            "details": "可能是本地/浏览器缓存或 DoH 绕过系统解析器，请刷新后重测；若反复出现请排查 DoH。",
        })

    # ---------- 3. WebRTC 真实地址 ----------
    rtc = [e for e in events if e["kind"] == "webrtc"]
    if rtc:
        public_leaks = sorted({
            e["ip"] for e in rtc
            if _is_public(e["ip"]) and not _in_any(e["ip"], egress) and not _in_any(e["ip"], egress6)
        })
        local_ips = sorted({e["ip"] for e in rtc if not _is_public(e["ip"])})
        if public_leaks:
            checks.append({
                "key": "webrtc", "title": "WebRTC 地址暴露", "status": "fail",
                "summary": f"浏览器通过 WebRTC 暴露了真实公网地址：{', '.join(public_leaks)}",
                "details": (
                    "网页可通过 RTCPeerConnection 拿到本机候选地址，绕过 VPN 暴露真实位置。\n"
                    f"同时收集到的局域网地址：{', '.join(local_ips) or '无'}"
                ),
            })
        else:
            checks.append({
                "key": "webrtc", "title": "WebRTC 地址暴露", "status": "ok",
                "summary": "WebRTC 未暴露非公司公网地址。",
                "details": f"收集到的局域网地址：{', '.join(local_ips) or '无（浏览器已做 mDNS 隐藏）'}",
            })
    else:
        checks.append({
            "key": "webrtc", "title": "WebRTC 地址暴露", "status": "info",
            "summary": "未收集到 WebRTC 候选地址（浏览器可能已禁用或屏蔽 WebRTC）。",
            "details": "",
        })

    # ---------- 4. IPv6 绕过 ----------
    v6 = [e for e in events if e["kind"] == "ipv6"]
    if v6:
        ip = v6[-1]["ip"]
        if _in_any(ip, egress6):
            checks.append({
                "key": "ipv6", "title": "IPv6 流量", "status": "ok",
                "summary": f"IPv6 出口 {ip} 属于公司地址段，IPv6 走了隧道。",
                "details": "",
            })
        else:
            checks.append({
                "key": "ipv6", "title": "IPv6 流量", "status": "fail",
                "summary": f"IPv6 流量从非公司出口 {ip} 发出 —— IPv6 绕过了 VPN 隧道！",
                "details": "很多 VPN 只接管 IPv4，双栈机器的 IPv6 流量会直连外网。",
            })
    else:
        checks.append({
            "key": "ipv6", "title": "IPv6 流量", "status": "ok",
            "summary": "未检测到 IPv6 连通（无 IPv6 或已被阻断），不存在 IPv6 绕过。",
            "details": "",
        })

    order = {"fail": 0, "warn": 1, "info": 2, "ok": 3}
    overall = min((c["status"] for c in checks), key=lambda s: order[s], default="ok")
    return {
        "checks": checks,
        "overall": overall,
        "os": detect_os((session or {}).get("user_agent", "")),
        "events": events,
    }


# ---------------- 修复建议 ----------------

_COMMON = """\
**通用建议**
- 确认 VPN 客户端为**全隧道（full tunnel）**模式；如必须分流，把检测域名与公司业务域名加入隧道路由。
- 在浏览器企业策略中**禁用 DoH**（Chrome: `DnsOverHttpsMode=off`；Edge/Firefox 同理），防止浏览器绕过系统 DNS。
- 在浏览器企业策略中限制 WebRTC：Chrome/Edge 设置 `WebRtcLocalhostIpHandling = disable_non_proxied_udp`，或禁用非代理 UDP。
"""

_FIXES = {
    "windows": """\
**Windows 修复建议**
1. **强制 DNS 走隧道**（管理员 PowerShell）：
   - 调低 VPN 接口跃点数：`Set-NetIPInterface -InterfaceAlias "VPN连接名" -InterfaceMetric 1`
   - 调高物理网卡跃点数：`Set-NetIPInterface -InterfaceAlias "以太网" -InterfaceMetric 5000`
2. **关闭智能多宿主名称解析**（防止并发向所有网卡发 DNS）：
   组策略 → 计算机配置 → 管理模板 → 网络 → DNS 客户端 → “关闭智能多宿主名称解析” = 已启用；
   或注册表 `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient` 新建 `DisableSmartNameResolution`(DWORD)=1。
3. **IPv6 泄露**：在 VPN 适配器属性中取消勾选 “Internet 协议版本 6 (TCP/IPv6)”，
   或 `Disable-NetAdapterBinding -Name "适配器名" -ComponentID ms_tcpip6`。
4. **WebRTC**：Edge/Chrome 企业策略 `WebRtcLocalhostIpHandling` 设为 `disable_non_proxied_udp`。
""",
    "macos": """\
**macOS 修复建议**
1. **调整服务顺序**：系统设置 → 网络 → …菜单 → 设定服务顺序，把 VPN 拖到最上方；
   命令行可用 `networksetup -listnetworkserviceorder` 查看。
2. **检查 DNS 生效情况**：`scutil --dns`，确认公司 DNS 出现在首位 resolver。
3. **IPv6 泄露**：`networksetup -setv6off "Wi-Fi"`（恢复用 `-setv6automatic`）。
4. **WebRTC**：Safari 默认不暴露本机地址；Chrome 请用企业策略或扩展限制 WebRTC。
""",
    "linux": """\
**Linux 修复建议**
1. **systemd-resolved 独占 DNS**：`resolvectl domain tun0 ~.` 并 `resolvectl dns tun0 <公司DNS>`，
   `~.` 路由域会让所有 DNS 查询只走隧道接口。
2. **NetworkManager**：`nmcli con mod <VPN连接名> ipv4.dns-priority -1`（负值 = 独占 DNS）。
3. **检查路由**：`ip route` 确认默认路由指向 tun0；`resolvectl status` 确认 DNS 作用域。
4. **IPv6 泄露**：`sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1`，
   或 `nmcli con mod <连接名> ipv6.method disabled`。
5. **WebRTC**：浏览器企业策略限制，或防火墙阻断非 VPN 接口的 UDP。
""",
    "android": """\
**Android 修复建议**
1. 关闭“私人 DNS (Private DNS/DoT)”或将其指向公司 DoT 服务器：设置 → 网络 → 私人 DNS。
2. 在 VPN 应用（或企业 MDM 的 VPN 配置）中开启**始终在线 VPN** 与**屏蔽未使用 VPN 的连接**。
3. 确认 VPN 配置包含 IPv6 隧道，或在 WLAN 高级设置中关闭 IPv6（部分机型需 MDM 下发）。
""",
    "ios": """\
**iOS / iPadOS 修复建议**
1. 通过 MDM 下发 VPN 配置并启用 **On Demand / 始终在线**。
2. 确认 VPN 配置为全隧道且包含 IPv6；iOS 上 DNS 一般随 VPN 配置生效，若泄露请检查描述文件中的 DNS 服务器与匹配域。
""",
    "unknown": """\
**修复建议**
未能识别操作系统。请参考页面中的通用建议，或在 Windows / macOS / Linux 标签思路下排查：
DNS 是否只走隧道接口、IPv6 是否被隧道接管、浏览器是否启用了 DoH / WebRTC。
""",
}


def fix_suggestions_markdown(os_key: str) -> str:
    return _COMMON + "\n" + _FIXES.get(os_key, _FIXES["unknown"])
