"""Per-OS remediation guidance attached to each finding.

The text is deliberately specific: "check your VPN settings" is useless.  Each
recipe names the exact setting, the GUI path, and (where it exists) a command
that shows the current value so the user can verify the change instead of
guessing.  Commands are shown, never executed — the service is a web page.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

OS_LABEL = {
    "windows": "Windows 10 / 11",
    "macos": "macOS",
    "linux": "Linux",
    "android": "Android",
    "ios": "iOS / iPadOS",
    "chromeos": "ChromeOS",
    "unknown": "通用",
}

OS_ALIASES = {
    "windows": ("windows", "unknown"),
    "macos": ("macos", "unknown"),
    "linux": ("linux", "unknown"),
    "android": ("android", "unknown"),
    "ios": ("ios", "macos", "unknown"),
    "chromeos": ("chromeos", "linux", "unknown"),
    "unknown": ("unknown",),
}


@dataclass(slots=True)
class RemediationStep:
    title: str
    body: str
    commands: list[tuple[str, str]] = field(default_factory=list)  # (语言, 命令)
    verify: str = ""


@dataclass(slots=True)
class Recipe:
    headline: str
    steps: list[RemediationStep]


def _s(title: str, body: str, commands: list[tuple[str, str]] | None = None,
       verify: str = "") -> RemediationStep:
    return RemediationStep(title, body, commands or [], verify)


# ---------------------------------------------------------------------------
# Recipes.  Key = check key / hint key, then per-OS variant.
# ---------------------------------------------------------------------------

RECIPES: dict[str, dict[str, Recipe]] = {
    # ------------------------------------------------------------- split tunnel
    "remediation.split_tunnel": {
        "windows": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道（Windows）",
            [
                _s(
                    "确认 VPN 适配器接管了全部流量",
                    "在「设置 → 网络和 Internet → VPN → 你的连接 → 属性」中确认没有勾选"
                    "「使用远程网络的默认网关」（Use default gateway on remote network）的反向设置。"
                    "如果使用全局模式客户端，请切换到「全局 / Full tunnel」而不是「分流 / Split tunnel」。",
                    [],
                    "ipconfig /all | findstr /i \"description dns suffix\"",
                ),
                _s(
                    "检查是否为 VPN 适配器单独指定了 DNS",
                    "分流配置里经常给物理网卡留了本地 DNS（例如路由器地址），"
                    "导致解析绕过隧道。应让 VPN 虚拟网卡成为首选 DNS，"
                    "或由客户端下发内网 DNS。",
                    [("powershell", "Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,ServerAddresses")],
                ),
                _s(
                    "关闭「按流量计费的连接」导致的隧道降级",
                    "部分客户端在计量连接下会只代理 TCP 443，"
                    "DNS 与 UDP 会直接走本地网络。"
                    "「设置 → 网络和 Internet → 你的连接 → 属性」里确认未按流量计费。",
                ),
                _s(
                    "让 UDP 走隧道",
                    "Windows 防火墙或客户端规则若只允许 TCP，"
                    "WebRTC/UDP 就会从物理网卡发出。检查 VPN 客户端的「允许 UDP / 允许直连」开关并关闭直连。",
                    [("powershell", "Get-NetFirewallProfile | Select-Object Name,Enabled")],
                ),
            ],
        ),
        "macos": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道（macOS）",
            [
                _s(
                    "确认服务顺序：VPN 在物理网卡之前",
                    "「系统设置 → 网络 → 右下角 … → 设定服务顺序」，把 VPN 接口拖到 Wi-Fi / 以太网之前。",
                    [],
                    "scutil --nwi",
                ),
                _s(
                    "检查每个接口的 DNS 配置",
                    "分流客户端有时只给 utun 接口下发一条内网 DNS，"
                    "系统仍会并行使用 Wi-Fi 的 DNS。确认 Wi-Fi 上没有残留的公共 DNS。",
                    [("bash", "scutil --dns | grep -A3 'resolver #1'\nnetworksetup -getdnsservers Wi-Fi")],
                ),
                _s(
                    "确认不是「按需连接」把流量放出去了",
                    "「系统设置 → 网络 → VPN → 选项」里，按需规则（On Demand）"
                    "若只对部分域名触发，其余流量会走物理网卡。关闭按需或改为始终连接。",
                ),
                _s(
                    "确认 IPv6 与 UDP 的处理",
                    "很多 macOS 客户端只接管 IPv4。若 Wi-Fi 拿到公网 IPv6，"
                    "浏览器会优先用 IPv6 直连，完全绕过隧道。",
                    [("bash", "ifconfig | grep inet6\nnetstat -rn -f inet6 | head")],
                ),
            ],
        ),
        "linux": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道（Linux）",
            [
                _s(
                    "确认默认路由确实指向 tun/tap 设备",
                    "分流配置通常靠策略路由实现，但 DNS 查询会走 NetworkManager/systemd-resolved 的接口选择，"
                    "不一定遵守你的路由规则。",
                    [
                        ("bash", "ip route show default\nip -6 route show default"),
                        ("bash", "resolvectl status | sed -n '1,40p'"),
                    ],
                ),
                _s(
                    "避免 systemd-resolved 泄漏",
                    "resolved 默认对所有接口做并行查询（LLMNR/mDNS 也会走本地链路）。"
                    "把 VPN 的 DNS 设为全局默认，并关闭物理链路上的 DNS。",
                    [
                        ("bash", "# /etc/systemd/resolved.conf.d/vpn.conf\n[Resolve]\nDNS=10.10.0.53\nDomains=~."),
                        ("bash", "resolvectl flush-caches && resolvectl status | grep -E 'Current DNS|DNS Servers'"),
                    ],
                ),
                _s(
                    "用 nftables 兜底：非隧道接口只放行隧道端点",
                    "客户端分流规则写错时，内核防火墙是最后一道防线。"
                    "把 VPN 服务器地址之外的所有出站限制到 tun 接口。",
                    [
                        ("bash", "nft list ruleset | grep -i -E 'oif|tun'"),
                        ("bash", "ss -tnp | grep -E 'ESTAB' | head"),
                    ],
                ),
            ],
        ),
        "android": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道（Android）",
            [
                _s(
                    "检查应用是否被排除在 VPN 之外",
                    "「设置 → 网络和互联网 → VPN → 你的连接 → 始终开启的 VPN / 例外应用」，"
                    "确认浏览器没有被加入例外列表。",
                ),
                _s(
                    "关闭「私人 DNS」",
                    "私人 DNS（Private DNS，DoT）会让所有解析绕过 VPN 下发的 DNS。"
                    "设为「关闭」或「自动」。",
                ),
                _s(
                    "关闭私有网络的智能分流",
                    "部分系统「设置 → 网络 → VPN → 高级」中有「绕过 VPN 的局域网流量」，"
                    "开启后局域网 DNS 与 UDP 会走本地。",
                ),
            ],
        ),
        "ios": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道（iOS / iPadOS）",
            [
                _s(
                    "确认 VPN 处于「始终开启」",
                    "「设置 → 通用 → VPN 与设备管理 → VPN」中确认状态为「已连接」，"
                    "并在描述文件里启用按需连接（Connect On Demand）而不是手动连接。",
                ),
                _s(
                    "关闭 iCloud 私人中继",
                    "iCloud+ 的「私人中继」会代理 Safari 流量，绕过 VPN。"
                    "「设置 → Apple ID → iCloud → 私人中继」关闭后复测。",
                ),
                _s(
                    "关闭「限制 IP 地址跟踪」对局域网的影响",
                    "iOS 15+ 的「限制 IP 地址跟踪」会让 Safari 使用代理，"
                    "可能导致 DNS 走不同路径；若复测结果不稳定，可临时关闭后再测。",
                ),
            ],
        ),
        "chromeos": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道（ChromeOS）",
            [
                _s(
                    "确认 VPN 设置为「全局」",
                    "「设置 → 网络 → VPN → 高级」中的「允许其他网络使用此连接」需开启，"
                    "否则仅 Google 服务走隧道。",
                ),
                _s("关闭 Secure DNS", "「设置 → 隐私和安全 → 安全 → 使用安全 DNS」设为关闭。"),
            ],
        ),
        "unknown": Recipe(
            "把 DNS 与 UDP 纳入 VPN 隧道",
            [
                _s(
                    "使用全局（Full tunnel）模式",
                    "分流模式下只有办公网段走隧道时，DNS、UDP、IPv6 都可能从本地网络发出。"
                    "需要泄露防护时请改用全局模式。",
                ),
                _s(
                    "检查 VPN 客户端的「允许本地网络访问」",
                    "该选项为方便打印机等设备而放行局域网，副作用是局域网 DNS 与 UDP 绕过隧道。"
                    "出差场景应关闭。",
                ),
                _s(
                    "关闭浏览器的安全 DNS / 私人 DNS",
                    "Chrome、Edge、Firefox 的加密 DNS 会直接连公共 DoH，绕过 VPN 下发的解析器。",
                ),
            ],
        ),
    },
    "remediation.route_all": {
        "windows": Recipe(
            "让所有地址走 VPN（Windows 路由）",
            [
                _s(
                    "查看当前路由表，确认 0.0.0.0/0 指向 VPN",
                    "如果默认路由仍指向物理网卡，说明客户端只添加了办公网段路由。",
                    [("powershell", "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | Format-Table ifIndex,NextHop,RouteMetric")],
                ),
                _s(
                    "为 VPN 接口添加更低 metric 的默认路由（需管理员）",
                    "注意：这会覆盖物理网卡默认路由，断开 VPN 前请保留恢复命令。",
                    [("powershell", "route add 0.0.0.0 mask 0.0.0.0 <VPN网关> metric 1 if <VPN接口号>\nroute delete 0.0.0.0 mask 0.0.0.0")],
                ),
            ],
        ),
        "macos": Recipe(
            "让所有地址走 VPN（macOS 路由）",
            [
                _s(
                    "检查是否只有部分网段走 utun",
                    "分流客户端通常添加 10/8 之类网段，公网流量仍走 Wi-Fi。",
                    [("bash", "netstat -rn -f inet | head -20\nnetstat -rn -f inet6 | head -10")],
                ),
                _s(
                    "开启客户端「发送所有流量」",
                    "WireGuard 的 AllowedIPs 要包含 0.0.0.0/0 与 ::/0；OpenVPN 需要去掉 pull-filter ignore redirect-gateway。",
                ),
            ],
        ),
        "linux": Recipe(
            "让所有地址走 VPN（Linux 路由）",
            [
                _s(
                    "检查默认路由与策略路由",
                    "确认 main 表和自定义表中都没有把公网流量送回物理网卡。",
                    [
                        ("bash", "ip route get 1.1.1.1 ip 2>/dev/null || ip route get 1.1.1.1\nip rule show"),
                    ],
                ),
                _s(
                    "WireGuard 的 AllowedIPs 必须覆盖全部网段",
                    "AllowedIPs = 0.0.0.0/0, ::/0。若只写了办公网段，其余流量不会进隧道。",
                    [("bash", "wg show | sed -n '1,20p'")],
                ),
            ],
        ),
        "unknown": Recipe(
            "让所有地址走 VPN",
            [
                _s("改用全局模式", "把客户端的分流网段改为 0.0.0.0/0 与 ::/0，或在客户端中启用「全局 / Full tunnel」。"),
            ],
        ),
    },
    # ------------------------------------------------------------------- DNS
    "remediation.dns_doh": {
        "windows": Recipe(
            "关闭浏览器与系统的加密 DNS（Windows）",
            [
                _s(
                    "Chrome / Edge：关闭「使用安全 DNS」",
                    "chrome://settings/security → 关闭「使用安全 DNS」。"
                    "企业策略 SecureDnsMode 应设为 off，且 DnsOverHttpsTemplates 留空。",
                    [("powershell", "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name DnsOverHttpsMode -ErrorAction SilentlyContinue")],
                ),
                _s(
                    "Windows 11：关闭系统 DoH",
                    "「设置 → 网络和 Internet → 以太网/Wi-Fi → DNS 服务器分配」，"
                    "关闭「通过 HTTPS 加密」选项。",
                    [("powershell", "Get-DnsClientDohServerAddress\nGet-DnsClientGlobalSetting | Select-Object -ExpandProperty SuffixSearchList")],
                ),
                _s("Firefox", "about:preferences#privacy → 关闭「启用基于 HTTPS 的 DNS」，或改为「关闭」。"),
            ],
        ),
        "macos": Recipe(
            "关闭浏览器与系统的加密 DNS（macOS）",
            [
                _s(
                    "Chrome / Edge：关闭「使用安全 DNS」",
                    "chrome://settings/security → 关闭。企业策略 SecureDnsMode=off。",
                ),
                _s(
                    "Firefox",
                    "about:preferences#privacy → 关闭「启用基于 HTTPS 的 DNS」。"
                    "about:config 中 network.trr.mode=5 可强制关闭。",
                ),
                _s(
                    "系统级 DoH 描述文件",
                    "若安装了 DNS over HTTPS 的配置描述文件，"
                    "「系统设置 → 通用 → VPN 与设备管理」中移除后复测。",
                    [("bash", "scutil --dns | grep -i 'https\\|doh'")],
                ),
            ],
        ),
        "linux": Recipe(
            "关闭加密 DNS（Linux）",
            [
                _s("Chrome / Edge", "chrome://settings/security → 关闭「使用安全 DNS」。"),
                _s(
                    "systemd-resolved 的 DoT",
                    "若 DNSOverTLS=yes，解析会走 853 端口而非内网 DNS。改为 no 后重启服务。",
                    [("bash", "grep -r DNSOverTLS /etc/systemd/resolved.conf*\nsudo systemctl restart systemd-resolved")],
                ),
                _s("检查是否有 DNS 代理进程", "确保没有 dnscrypt-proxy / cloudflared 之类的本地代理在监听 53 端口。",
                   [("bash", "ss -lunp | grep ':53 '")]),
            ],
        ),
        "android": Recipe(
            "关闭私人 DNS（Android）",
            [
                _s("设置路径", "「设置 → 网络和互联网 → 私人 DNS」→ 关闭（或自动）。"),
                _s("Chrome", "chrome://settings/security → 关闭「使用安全 DNS」。"),
            ],
        ),
        "ios": Recipe(
            "关闭加密 DNS（iOS）",
            [
                _s("系统", "「设置 → 无线局域网 → (i) → 配置 DNS → 自动」。"),
                _s("Safari / 描述文件", "移除 iCloud 私人中继或自定义 DoH 描述文件后复测。"),
            ],
        ),
        "chromeos": Recipe("关闭 Secure DNS（ChromeOS）", [_s("设置路径", "「设置 → 隐私和安全 → 安全 → 使用安全 DNS」→ 关闭。")]),
        "unknown": Recipe(
            "关闭加密 DNS（DoH / DoT）",
            [
                _s(
                    "浏览器里关闭「安全 DNS」",
                    "Chrome/Edge: chrome://settings/security；Firefox: about:preferences#privacy。"
                    "关闭后解析才会走系统（也就是 VPN 下发）的 DNS。",
                ),
                _s(
                    "关闭系统级加密 DNS",
                    "移除系统上的 DoH/DoT 配置（配置描述文件、systemd-resolved 的 DNSOverTLS、"
                    "本地 dnscrypt-proxy 等），让解析走 VPN 下发的内网 DNS。",
                ),
            ],
        ),
    },
    "remediation.dns_client": {
        "windows": Recipe(
            "让系统解析走公司 DNS（Windows）",
            [
                _s(
                    "确认 VPN 适配器是首选 DNS",
                    "「网络连接 → VPN 适配器 → IPv4 属性 → 使用下面的 DNS 服务器」填写内网 DNS；"
                    "物理网卡上的公共 DNS 全部清空。",
                    [("powershell", "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | Format-Table InterfaceAlias,AddressFamily,ServerAddresses")],
                ),
                _s(
                    "清空 DNS 缓存并重新注册",
                    "改完后必须清缓存，否则旧的公共解析结果仍会被复用。",
                    [("powershell", "Clear-DnsClientCache\nipconfig /flushdns")],
                ),
                _s(
                    "确认没有 NRPT 规则把探针域名送到本地解析器",
                    "NRPT（名称解析策略表）里针对特定后缀的规则会让某些域名绕过 VPN DNS。",
                    [("powershell", "Get-DnsClientNrptRule | Format-List NameSpace,NameServers")],
                ),
            ],
        ),
        "macos": Recipe(
            "让系统解析走公司 DNS（macOS）",
            [
                _s(
                    "把内网 DNS 设到 VPN 接口",
                    "不要在 Wi-Fi 上写 8.8.8.8 之类的公共 DNS；"
                    "「系统设置 → 网络 → VPN → 详细信息 → DNS」添加内网 DNS。",
                    [("bash", "scutil --dns | sed -n '1,30p'")],
                ),
                _s(
                    "清除 DNS 缓存",
                    "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
                    [("bash", "sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder")],
                ),
                _s(
                    "检查 /etc/resolv.conf 是否被手工改过",
                    "手工写入的 nameserver 优先级高于 VPN 下发值。",
                    [("bash", "cat /etc/resolv.conf")],
                ),
            ],
        ),
        "linux": Recipe(
            "让系统解析走公司 DNS（Linux）",
            [
                _s(
                    "确认 resolved 的当前 DNS 与作用域",
                    "Domains=~. 表示作为全局默认；若物理链路有更高优先级，会让解析泄漏。",
                    [("bash", "resolvectl status\nresolvectl dns")],
                ),
                _s(
                    "用连接配置固定 VPN 的 DNS",
                    "NetworkManager: nmcli connection modify <vpn> ipv4.dns \"10.10.0.53\" ipv4.ignore-auto-dns yes。",
                    [("bash", "nmcli -f NAME,TYPE,IP4.DNS connection show")],
                ),
                _s("清缓存", "sudo resolvectl flush-caches", [("bash", "sudo resolvectl flush-caches")]),
            ],
        ),
        "android": Recipe(
            "让解析走公司 DNS（Android）",
            [
                _s("关闭私人 DNS", "「设置 → 网络和互联网 → 私人 DNS」→ 关闭。"),
                _s("确认 VPN 下发 DNS", "VPN 客户端应推送内网 DNS；若客户端有「DNS 分流」开关，关闭它。"),
            ],
        ),
        "ios": Recipe(
            "让解析走公司 DNS（iOS）",
            [
                _s("关闭私人中继与加密 DNS", "「设置 → Apple ID → iCloud → 私人中继」关闭。"),
                _s("确认 VPN 配置描述文件包含 DNS 设置", "重新安装包含 DNS 配置的描述文件。"),
            ],
        ),
        "chromeos": Recipe("让解析走公司 DNS（ChromeOS）", [_s("设置路径", "「设置 → 网络 → 你的网络 → 名称服务器」改为 VPN 下发的内网 DNS。")]),
        "unknown": Recipe(
            "让解析走公司 DNS",
            [
                _s("清空物理网卡上的公共 DNS", "把 8.8.8.8 / 114.114.114.114 这类公共 DNS 从所有非 VPN 接口移除。"),
                _s("清 DNS 缓存后再测", "不清楚怎么清时，重启 VPN 客户端通常也会刷新解析路径。"),
            ],
        ),
    },
    # ----------------------------------------------------------- WebRTC / UDP
    "remediation.webrtc_block": {
        "windows": Recipe(
            "限制 WebRTC 暴露真实地址（Windows）",
            [
                _s(
                    "Chrome / Edge 策略：只允许特定 URL 使用 WebRTC",
                    "部署 WebRtcLocalIpsAllowedUrls 或 WebRtcIPHandlingPolicy=disable_non_proxied_udp，"
                    "可阻止页面拿到本机/公网候选地址。",
                    [("powershell", "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name WebRtcIPHandlingPolicy -ErrorAction SilentlyContinue")],
                ),
                _s(
                    "Firefox：关闭非代理 UDP",
                    "about:config → media.peerconnection.ice.proxy_only = true（需走代理时）",
                ),
                _s(
                    "VPN 客户端：禁止 UDP 直连",
                    "客户端里的「允许 UDP 直连 / 允许 P2P」开关会绕过隧道，出差场景应关闭。",
                ),
            ],
        ),
        "macos": Recipe(
            "限制 WebRTC 暴露真实地址（macOS）",
            [
                _s(
                    "Chrome / Edge 策略",
                    "配置 WebRtcIPHandlingPolicy=disable_non_proxied_udp，"
                    "或 WebRtcLocalIpsAllowedUrls 仅允许自检域名。",
                ),
                _s("Safari", "Safari 默认对本地候选做 mDNS 混淆；若暴露公网地址，检查 VPN 是否接管了 UDP。"),
                _s("Firefox", "about:config → media.peerconnection.ice.obfuscate_host_addresses = true"),
            ],
        ),
        "linux": Recipe(
            "限制 WebRTC 暴露真实地址（Linux）",
            [
                _s(
                    "浏览器策略文件",
                    "/etc/opt/chrome/policies/managed/webrtc.json 写入 "
                    '{"WebRtcIPHandlingPolicy":"disable_non_proxied_udp"}（Edge 对应 /etc/opt/edge/policies/managed/）。',
                    [("bash", "ls /etc/opt/*/policies/managed/ 2>/dev/null")],
                ),
                _s("Firefox", "about:config → media.peerconnection.ice.obfuscate_host_addresses = true"),
            ],
        ),
        "android": Recipe(
            "限制 WebRTC 暴露真实地址（Android）",
            [
                _s("系统无策略时", "Android 无法直接限制 WebRTC；可靠做法是让 VPN 以全局 UDP 模式接管，从而隐藏真实出口。"),
                _s("Chrome", "chrome://flags 中不提供该开关，需由企业 MDM 下发 WebRtcIPHandlingPolicy 策略。"),
            ],
        ),
        "ios": Recipe(
            "限制 WebRTC 暴露真实地址（iOS）",
            [
                _s("Safari", "Safari 默认 mDNS 混淆；若暴露公网地址，说明 UDP 未走隧道，需修 VPN 配置。"),
                _s("企业管理", "通过 MDM 部署 WebRTC 限制配置，或在 VPN 侧阻断非隧道 UDP。"),
            ],
        ),
        "chromeos": Recipe("限制 WebRTC（ChromeOS）", [_s("管理策略", "在 Google Admin 控制台中设置 WebRtcIPHandlingPolicy。")]),
        "unknown": Recipe(
            "限制 WebRTC 暴露真实地址",
            [
                _s("浏览器策略", "Chrome/Edge 设置 WebRtcIPHandlingPolicy=disable_non_proxied_udp；Firefox 开启 mDNS 混淆。"),
                _s("VPN 侧兜底", "在隧道外阻断 UDP 3478/19302 等常用 STUN 端口，避免直连暴露出口。"),
            ],
        ),
    },
    "remediation.webrtc_blocked": {
        "unknown": Recipe(
            "自检页无法使用 WebRTC",
            [
                _s(
                    "使用 HTTPS 打开自检页",
                    "WebRTC 只在安全上下文可用。http:// 打开时浏览器会直接拒绝创建连接。",
                ),
                _s("换一个浏览器复测", "企业策略可能禁用了 WebRTC；用未被策略约束的浏览器对比结果。"),
            ],
        ),
    },
    # ----------------------------------------------------------------- IPv6
    "remediation.ipv6_disable": {
        "windows": Recipe(
            "阻断 IPv6 绕过隧道（Windows）",
            [
                _s(
                    "在 VPN 适配器上禁用 IPv6（首选）",
                    "「网络连接 → VPN 适配器 → IPv6 → 取消勾选」。"
                    "这样即便物理网卡有公网 IPv6，浏览器也无法通过隧道接口使用它。",
                    [("powershell", "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Format-Table Name,Enabled")],
                ),
                _s(
                    "或在客户端配置中下发 ::/0 路由",
                    "让 IPv6 默认路由同样指向 VPN；缺少这条路由就是典型的 IPv6 泄露。",
                    [("powershell", "Get-NetRoute -DestinationPrefix '::/0' | Format-Table ifIndex,NextHop")],
                ),
                _s(
                    "临时验证",
                    "禁用后访问 IPv6 测试站点，若无法连通说明 IPv6 已不会直出。",
                    [("powershell", "Resolve-DnsName -Type AAAA ifconfig.co")],
                ),
            ],
        ),
        "macos": Recipe(
            "阻断 IPv6 绕过隧道（macOS）",
            [
                _s(
                    "在服务顺序中把 VPN 置于最前，并确认 utun 有 ::/0",
                    "netstat -rn -f inet6 若默认路由指向 en0，IPv6 就会直出。",
                    [("bash", "netstat -rn -f inet6 | head -5")],
                ),
                _s(
                    "只在 Wi-Fi 上关闭 IPv6（无法下发路由时）",
                    "「系统设置 → 网络 → Wi-Fi → 详细信息 → TCP/IP → 配置 IPv6 → 仅本地链路」。",
                    [("bash", "networksetup -setv6off Wi-Fi   # 需要时用 -setv6automatic 恢复")],
                ),
            ],
        ),
        "linux": Recipe(
            "阻断 IPv6 绕过隧道（Linux）",
            [
                _s(
                    "确认 IPv6 默认路由指向 tun",
                    "ip -6 route show default",
                    [("bash", "ip -6 route show default\nip -6 addr show scope global")],
                ),
                _s(
                    "在物理接口上关闭 IPv6",
                    "sysctl net.ipv6.conf.wlan0.disable_ipv6=1（写入 /etc/sysctl.d/ 持久化）。",
                    [("bash", "sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1\nsudo sysctl -w net.ipv6.conf.all.disable_ipv6=1")],
                ),
                _s(
                    "nftables 兜底",
                    "在物理接口上丢弃所有 IPv6 出站，仅保留隧道接口。",
                    [("bash", "sudo nft add rule inet filter output oifname != \"tun0\" ip6 daddr != ::1 drop")],
                ),
            ],
        ),
        "android": Recipe(
            "阻断 IPv6 绕过隧道（Android）",
            [
                _s("系统无开关", "Android 无法单独关闭 IPv6；需 VPN 客户端以全局模式接管 IPv6（下发 ::/0）或由企业 MDM 关闭该网络的 IPv6。"),
                _s("临时规避", "连接不提供 IPv6 的热点，或在热点侧关闭 IPv6。"),
            ],
        ),
        "ios": Recipe(
            "阻断 IPv6 绕过隧道（iOS）",
            [
                _s("系统无开关", "iOS 不支持按接口关闭 IPv6；请让 VPN 配置下发 ::/0，"
                    "或联系 IT 在隧道侧阻断 IPv6 直出。"),
                _s("临时规避", "关闭 Wi-Fi 使用蜂窝网络时通常为运营商 IPv6，仍可能直出；最稳妥是修 VPN 配置。"),
            ],
        ),
        "chromeos": Recipe("阻断 IPv6（ChromeOS）", [_s("设置路径", "「设置 → 网络 → 你的网络 → IPv6」关闭，或让 VPN 接管 IPv6 路由。")]),
        "unknown": Recipe(
            "阻断 IPv6 绕过隧道",
            [
                _s("首选：让隧道下发 ::/0", "在 VPN 配置中加入 IPv6 默认路由，IPv6 就会和 IPv4 一样走隧道。"),
                _s("次选：在客户端/系统关闭 IPv6", "无法下发路由时，关闭物理网卡的 IPv6 是最直接的缓解。"),
            ],
        ),
    },
    # ------------------------------------------------------------ misc hints
    "remediation.stun_ports": {
        "unknown": Recipe(
            "STUN 端口不可达",
            [
                _s(
                    "放行检测服务的 UDP 端口",
                    "检测服务使用一组 UDP 端口做 STUN 探测。若公司防火墙只放行 443，"
                    "这一项会显示“无法判定”。请让 IT 放行检测服务的 UDP 端口段（见服务端配置 stun.ports）。",
                ),
            ],
        ),
    },
    "remediation.probe_blocked": {
        "unknown": Recipe(
            "自检页请求没有到达检测服务",
            [
                _s(
                    "确认自检页是完整加载的",
                    "如果页面在 iframe 中被嵌入、或有脚本拦截器，"
                    "探测脚本可能没有运行。请用独立标签页打开检测地址。",
                ),
                _s(
                    "临时关闭广告拦截/隐私插件",
                    "uBlock、Privacy Badger 等会拦截探测用的像素请求与 DNS 解析。",
                ),
                _s(
                    "确认网络策略允许访问检测服务",
                    "若只有办公网可访问，出差时请通过 VPN 打开；访问不到检测服务本身就是分流问题的信号。",
                ),
            ],
        ),
    },
    "remediation.not_connected": {
        "windows": Recipe(
            "确认 VPN 真的连上了（Windows）",
            [
                _s(
                    "检查连接状态与账号",
                    "「设置 → 网络和 Internet → VPN」确认你的连接显示「已连接」。"
                    "密码修改后旧的保存凭据会继续尝试旧密码并静默失败。",
                    [("powershell", "Get-VpnConnection | Format-Table Name,ServerAddress,ConnectionStatus")],
                ),
                _s(
                    "检查客户端是否被策略切到「仅办公网段」",
                    "很多客户端在检测到公司内网时只代理办公网段，其余直出。"
                    "出差场景请手动选择「全局 / Full tunnel」。",
                    [("powershell", 'ipconfig | findstr /i "adapter IPv4"')],
                ),
                _s(
                    "查看 VPN 客户端日志",
                    "Windows 内置 VPN 的事件在「事件查看器 → 应用程序和服务日志 → "
                    "Microsoft → Windows → RasClient」；第三方客户端通常在 %ProgramData% 下。",
                    [("powershell", "Get-WinEvent -LogName 'Microsoft-Windows-RasClient/Operational' -MaxEvents 20")],
                ),
            ],
        ),
        "macos": Recipe(
            "确认 VPN 真的连上了（macOS）",
            [
                _s(
                    "检查状态与路由",
                    "菜单栏图标应为「已连接」。若显示已连接但出口仍在本地，"
                    "通常是配置只推送了部分路由。",
                    [("bash", "scutil --nc list\nifconfig utun0 2>/dev/null | head -5")],
                ),
                _s(
                    "检查是否连到了错误的配置",
                    "多套 VPN 配置（例如「全球」与「办公网」）容易选错。",
                    [("bash", "scutil --nc status '你的 VPN 名称'")],
                ),
            ],
        ),
        "linux": Recipe(
            "确认 VPN 真的连上了（Linux）",
            [
                _s(
                    "检查隧道设备与路由",
                    "设备存在不代表流量会走它；要看默认路由和策略路由。",
                    [("bash", "ip link show type tun\nip route get 1.1.1.1")],
                ),
                _s(
                    "检查 NetworkManager 连接状态",
                    "nmcli 可以看到连接是否真的激活，以及推送了哪些路由。",
                    [("bash", "nmcli connection show --active\nnmcli connection show <连接名> | grep -i ip4")],
                ),
            ],
        ),
        "unknown": Recipe(
            "确认 VPN 真的连上了",
            [
                _s(
                    "确认客户端处于已连接状态",
                    "所有通道都走同一个非公司出口，最常见的两种原因是：VPN 未连接，"
                    "或客户端被切到了「仅办公网段 / 分流」模式。",
                ),
                _s(
                    "断开重连并复测",
                    "账号过期、证书轮换、客户端升级后都可能出现「看起来已连接」但实际未生效。"
                    "先完全退出客户端（不是最小化），再重新连接后刷新本页。",
                ),
            ],
        ),
    },
    "remediation.report_to_it": {
        "unknown": Recipe(
            "把结果交给 IT",
            [
                _s(
                    "复制本页结果",
                    "页面底部的“导出结果”会生成一段可粘贴的文本，包含各通道观测到的出口地址，"
                    "足以让 IT 定位是哪条分流规则没生效。",
                ),
            ],
        ),
    },
}


def build_remediation(check_key: str, severity, os_family: str,
                      hints: list[str] | None = None) -> list[RemediationStep]:
    """Resolve hint keys into OS-appropriate, de-duplicated steps."""
    from .verdict import Severity  # local import avoids a cycle

    steps: list[RemediationStep] = []
    seen: set[str] = set()
    if severity in (Severity.PASS, Severity.INFO) and not hints:
        return steps
    keys = list(hints or [])
    if check_key in ("http_egress", "dns_egress", "udp_egress", "egress_consistency"):
        keys.append("remediation.split_tunnel")
    for key in keys:
        variants = RECIPES.get(key)
        if not variants:
            continue
        recipe = None
        for candidate in OS_ALIASES.get(os_family, ("unknown",)):
            if candidate in variants:
                recipe = variants[candidate]
                break
        if recipe is None:
            continue
        for step in recipe.steps:
            signature = step.title
            if signature in seen:
                continue
            seen.add(signature)
            steps.append(step)
    if steps:
        steps.append(
            RemediationStep(
                "确认修复效果",
                "改完后刷新本页复测。若结果仍有“疑似泄露”，请把页面底部的导出结果发给 IT，"
                "并附上你使用的 VPN 客户端与版本。",
            )
        )
    return steps


def steps_to_markdown(steps: list[RemediationStep]) -> str:
    lines: list[str] = []
    for index, step in enumerate(steps, 1):
        lines.append(f"**{index}. {step.title}**")
        lines.append("")
        lines.append(step.body)
        for language, command in step.commands:
            lines.append("")
            lines.append(f"```{language}")
            lines.append(command)
            lines.append("```")
        if step.verify:
            lines.append("")
            lines.append(f"验证：`{step.verify}`")
        lines.append("")
    return "\n".join(lines).strip()


def steps_to_html(steps: list[RemediationStep]) -> str:
    parts = ['<ol class="leakcheck-steps">']
    for step in steps:
        parts.append("<li>")
        parts.append(f"<strong>{html.escape(step.title)}</strong>")
        parts.append(f"<p>{html.escape(step.body)}</p>")
        for language, command in step.commands:
            parts.append(
                f'<pre class="leakcheck-cmd"><code data-lang="{html.escape(language)}">'
                f"{html.escape(command)}</code></pre>"
            )
        if step.verify:
            parts.append(f"<p class=\"leakcheck-verify\">验证：<code>{html.escape(step.verify)}</code></p>")
        parts.append("</li>")
    parts.append("</ol>")
    return "\n".join(parts)


def os_label(os_family: str) -> str:
    return OS_LABEL.get(os_family, OS_LABEL["unknown"])
