"""各操作系统的修复建议。

建议按「问题类型 × 操作系统」组织。页面根据浏览器上报的 User-Agent 猜出
平台，优先展示对应条目；猜不出来时并列显示，避免给出无用的说明。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .analysis import LEAK, WARN, Finding

WINDOWS = "windows"
MACOS = "macos"
LINUX = "linux"
IOS = "ios"
ANDROID = "android"
OTHER = "other"

PLATFORM_LABELS = {
    WINDOWS: "Windows",
    MACOS: "macOS",
    LINUX: "Linux",
    IOS: "iOS / iPadOS",
    ANDROID: "Android",
    OTHER: "通用",
}

# 建议条目：哪一类浏览器需要额外操作
BROWSER_KEYS = ("chrome", "edge", "firefox", "safari")


@dataclass(frozen=True)
class FixItem:
    key: str
    title: str
    severity: str
    steps: dict[str, tuple[str, ...]]
    note: str = ""

    def steps_for(self, platforms: tuple[str, ...]) -> list[tuple[str, tuple[str, ...]]]:
        chosen = [(p, self.steps[p]) for p in platforms if p in self.steps]
        if not chosen and OTHER in self.steps:
            chosen = [(OTHER, self.steps[OTHER])]
        return chosen


def detect_platform(user_agent: str | None) -> tuple[str, ...]:
    """根据 User-Agent 粗略判断平台，只用于挑选建议文案。"""
    ua = (user_agent or "").lower()
    if not ua:
        return (WINDOWS, MACOS, LINUX)
    if "android" in ua:
        return (ANDROID,)
    if re.search(r"iphone|ipad|ipod", ua):
        return (IOS,)
    if "windows" in ua:
        return (WINDOWS,)
    if "mac os x" in ua or "macintosh" in ua:
        return (MACOS,)
    if "linux" in ua or "x11" in ua:
        return (LINUX,)
    return (OTHER,)


def detect_browser(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if "edg/" in ua:
        return "edge"
    if "firefox/" in ua:
        return "firefox"
    if "chrome/" in ua or "chromium" in ua:
        return "chrome"
    if "safari/" in ua:
        return "safari"
    return ""


_FIXES: tuple[FixItem, ...] = (
    FixItem(
        key="dns",
        title="把 DNS 交回公司解析器",
        severity=LEAK,
        steps={
            WINDOWS: (
                "断开并重新连接 VPN；重连时观察客户端是否提示“使用公司 DNS”。",
                "设置 → 网络和 Internet → 以太网/Wi-Fi → 当前连接 → DNS 服务器分配 → 编辑，"
                "改为自动（DHCP），让 VPN 下发的 DNS 生效。",
                "如果手动配过 8.8.8.8 / 114.114.114.114 之类的公共 DNS，请删除这些条目。",
                "在 PowerShell 里执行 ipconfig /flushdns，然后重新检测。",
            ),
            MACOS: (
                "系统设置 → 网络 → 选中当前服务 → 详细信息 → DNS，清空手动添加的服务器。",
                "在终端执行 sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder。",
                "确认 VPN 客户端处于“全局/全隧道”模式，而不是“仅特定网段”。",
                "重新连接 VPN 后再次运行自检。",
            ),
            LINUX: (
                "检查 /etc/resolv.conf 或 NetworkManager 连接的 DNS 设置，确认指向公司 DNS。",
                "systemd-resolved 环境下执行 resolvectl status，确认当前链路的 DNS 服务器。",
                "执行 sudo resolvectl flush-caches。",
                "若用 openvpn，确认配置里有 --pull 与 dhcp-option DNS，且没有 override。",
            ),
            IOS: (
                "设置 → 通用 → VPN 与设备管理，删除后重新安装公司 VPN 描述文件。",
                "设置 → 无线局域网 → 当前网络 → 配置 DNS，改为自动。",
            ),
            ANDROID: (
                "设置 → 网络和互联网 → 私人 DNS，改为“关闭”或公司指定的 DoT 主机名。",
                "在公司 VPN 客户端里确认已启用“通过 VPN 发送所有流量”。",
            ),
        },
        note="公司 DNS 的对外出口地址也要写进服务端出口表，否则可能误判。",
    ),
    FixItem(
        key="doh",
        title="关闭浏览器的加密 DNS（DoH），或改用公司 DoH",
        severity=LEAK,
        steps={
            OTHER: (
                "Chrome / Edge：设置 → 隐私和安全 → 安全 → 使用安全 DNS，改为关闭或“自定义”公司 DoH 地址。",
                "Firefox：设置 → 隐私与安全 → DNS over HTTPS，改为关闭，或填入公司 DoH 地址。",
                "关闭后重启浏览器，再跑一次自检。",
            ),
        },
        note="浏览器开启安全 DNS 时会绕开系统（也就是 VPN 下发）的 DNS，这是 DNS 泄露最常见的成因。",
    ),
    FixItem(
        key="ipv6",
        title="处理 IPv6 绕过隧道",
        severity=LEAK,
        steps={
            WINDOWS: (
                "先确认是否真的需要 IPv6：在 PowerShell 执行 Get-NetIPAddress -AddressFamily IPv6 查看是否有公网地址。",
                "若 VPN 不承载 IPv6，可在网卡属性里取消勾选“Internet 协议版本 6 (TCP/IPv6)”，"
                "或让 VPN 客户端下发禁用 IPv6 的策略。",
                "更推荐的做法是让 VPN 接管 IPv6（下发 ::/0 路由），而不是在本机禁用。",
                "改完后重新连接 VPN 并刷新页面。",
            ),
            MACOS: (
                "系统设置 → 网络 → 当前服务 → 详细信息 → TCP/IP，将“配置 IPv6”改为仅本地连接。",
                "或在 VPN 配置中启用“通过 VPN 发送所有流量（含 IPv6）”。",
            ),
            LINUX: (
                "临时关闭：sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1。",
                "永久关闭：写入 /etc/sysctl.d/99-no-ipv6.conf 并执行 sudo sysctl --system。",
                "更推荐在 VPN 配置里下发 ::/0 路由，把 IPv6 一并接管。",
            ),
            IOS: (
                "iOS 不允许单独关闭 IPv6；请让 IT 在 VPN 配置文件中下发 IPv6 路由（::/0）。",
            ),
            ANDROID: (
                "Android 不允许单独关闭 IPv6；请让 IT 在 VPN 配置中下发 IPv6 路由。",
            ),
        },
        note="如果公司确实需要 IPv6，正确的方向是让 VPN 承载 IPv6，而不是长期在本机禁用。",
    ),
    FixItem(
        key="webrtc",
        title="限制 WebRTC 暴露真实地址",
        severity=LEAK,
        steps={
            OTHER: (
                "Chrome / Edge：安装并启用“WebRTC Network Limiter”一类策略扩展，"
                "或由 IT 通过企业策略把 WebRTC 的 IP 处理策略设为 default_public_interface_only。",
                "Firefox：地址栏打开 about:config，将 media.peerconnection.ice.default_address_only 设为 true。",
                "企业侧更彻底的做法：在防火墙上阻断内网到外部 STUN（3478/udp）的直连，只放通公司中继。",
                "注意：完全禁用 WebRTC 可能影响公司会议系统，改动前先和 IT 确认。",
            ),
        },
        note="WebRTC 的 UDP 流量通常不经过浏览器代理，很多 VPN 客户端也不会接管，需要单独处理。",
    ),
    FixItem(
        key="tunnel",
        title="确认 VPN 处于全隧道模式",
        severity=WARN,
        steps={
            WINDOWS: (
                "打开公司 VPN 客户端的连接设置，把“拆分隧道 / Split Tunneling”改为关闭。",
                "确认同一时间只连着一个 VPN 或代理，避免路由互相覆盖。",
                "断开后重新连接，然后刷新本页。",
            ),
            MACOS: (
                "在公司 VPN 客户端里关闭“仅路由公司网段”之类的选项。",
                "检查系统设置 → 网络 → VPN 的“发送所有流量”是否勾选。",
            ),
            LINUX: (
                "检查 VPN 配置是否带 default route（openvpn 的 redirect-gateway def1）。",
                "ip route 查看默认路由是否指向 tun/wg 接口。",
            ),
            IOS: (
                "在公司 VPN 客户端里确认“发送所有流量”已开启。",
            ),
            ANDROID: (
                "在公司 VPN 客户端里确认“通过 VPN 发送所有流量”已开启。",
            ),
        },
    ),
    FixItem(
        key="split_dns",
        title="检查分流规则是否把部分域名排除在隧道外",
        severity=WARN,
        steps={
            OTHER: (
                "让 IT 核对 VPN 客户端的路由与 DNS 分流列表，确认没有把公共域名排除在外。",
                "同时连着有线与无线、或同时启用两个 VPN 时，也容易出现出口不一致。",
                "确认后重新连接并刷新本页。",
            ),
        },
    ),
)

FIX_BY_KEY = {item.key: item for item in _FIXES}


def fixes_for(report_findings: list[Finding]) -> list[FixItem]:
    """按严重程度收集需要展示的修复建议，去重并保持顺序。"""
    keys: list[str] = []
    for finding in report_findings:
        if finding.status not in {LEAK, WARN}:
            continue
        for key in finding.fix_keys:
            if key not in keys:
                keys.append(key)
    return [FIX_BY_KEY[k] for k in keys if k in FIX_BY_KEY]


def render_steps(item: FixItem, platforms: tuple[str, ...]) -> list[str]:
    """把建议展开成「平台：步骤」形式，便于页面渲染或导出文本。"""
    out: list[str] = []
    for platform, steps in item.steps_for(platforms):
        label = PLATFORM_LABELS.get(platform, platform)
        for index, step in enumerate(steps, start=1):
            out.append(f"{label} · {index}. {step}")
    return out


def browser_hint(user_agent: str | None) -> str | None:
    browser = detect_browser(user_agent)
    hints = {
        "chrome": "检测到你使用 Chromium 内核浏览器，安全 DNS 与 WebRTC 设置都在「设置 → 隐私和安全」里。",
        "edge": "检测到你使用 Edge，安全 DNS 与 WebRTC 设置都在「设置 → 隐私、搜索和服务」里。",
        "firefox": "检测到你使用 Firefox，DNS over HTTPS 与 WebRTC 设置在「设置 → 隐私与安全」及 about:config 里。",
        "safari": "检测到你使用 Safari，它跟随系统 DNS；如需关闭加密 DNS，请在系统设置里检查 iCloud 私密代理。",
    }
    return hints.get(browser)


def fix_markdown(
    findings: list[Finding], user_agent: str | None, *, helpdesk: str | None = None
) -> str:
    """生成可直接贴给 IT 求助的 Markdown 文本。"""
    platforms = detect_platform(user_agent)
    lines = ["## VPN 泄露自检 · 需要处理的项目", ""]
    actionable = [f for f in findings if f.status in {LEAK, WARN}]
    if not actionable:
        lines.append("没有发现需要处理的项目。")
    for finding in actionable:
        lines.append(f"### {finding.title}（{finding.label}）")
        lines.append("")
        lines.append(finding.summary)
        if finding.evidence:
            lines.append("")
            lines.append("证据：" + "，".join(f"`{e}`" for e in finding.evidence))
        for item in fixes_for([finding]):
            lines.append("")
            lines.append(f"**{item.title}**")
            for step in render_steps(item, platforms):
                lines.append(f"- {step}")
            if item.note:
                lines.append(f"- 说明：{item.note}")
        lines.append("")
    if helpdesk:
        lines.append(f"仍无法解决请联系：{helpdesk}")
    return "\n".join(lines).strip() + "\n"
