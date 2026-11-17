"""页面片段渲染。

Streamlit 的 ``st.html`` 会净化 HTML，内联脚本里出现 ``<`` 紧跟字母的文本
（如注释、字符串比较）会被当作标签剥掉，脚本会被截断。因此页面只放一段
很小的内联引导脚本，真正的探测逻辑从采集端以 ``<script src>`` 外链加载。

外链脚本的地址必须由配置显式给出（``collector.script_url``），默认与
``public_url_v4`` 同源，避免依赖 Host 头。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProbePlan:
    session_id: str
    ipv4_base: str
    ipv6_base: str | None
    dns_zone: str | None
    dns_rounds: int
    dns_wait: float
    stun_uris: tuple[str, ...]
    report_url: str
    ipv4_probe_url: str
    ipv6_probe_url: str | None
    script_url: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sid": self.session_id,
            "ipv4Probe": self.ipv4_probe_url,
            "ipv6Probe": self.ipv6_probe_url,
            "dnsZone": self.dns_zone,
            "dnsRounds": self.dns_rounds,
            "dnsWait": self.dns_wait,
            "stunUris": list(self.stun_uris),
            "reportUrl": self.report_url,
        }


def _json_attr(value: Any) -> str:
    """把 JSON 安全地放进 HTML 属性。"""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("'", "&#39;")
        .replace('"', "&quot;")
    )
    return text


def _attr(value: str) -> str:
    """转义 URL 等属性值。"""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


_CSS = """
.vpncheck-card {
  border: 1px solid rgba(128, 128, 128, .35);
  border-radius: 10px;
  padding: 12px 14px;
  font-size: 13px;
  line-height: 1.7;
}
.vpncheck-card strong { font-weight: 600; }
.vpncheck-status { opacity: .85; }
.vpncheck-error { color: #b3261e; }
"""

# 引导脚本刻意保持极简：只用 if/字符串拼接，不出现比较符号，避免被净化截断。
_BOOTSTRAP = (
    "(function(){"
    "var d=document.getElementById('vpncheck-cfg');"
    "if(!d)return;"
    "var s=document.createElement('script');"
    "s.src=d.getAttribute('data-script');"
    "s.async=true;"
    "s.onerror=function(){"
    "var e=document.getElementById('vpncheck-status');"
    "if(e){e.textContent='探测脚本加载失败，请刷新页面或联系 IT。';"
    "e.className='vpncheck-status vpncheck-error';}};"
    "(document.head||document.body).appendChild(s);"
    "})();"
)


def render(plan: ProbePlan) -> str:
    """渲染注入到 Streamlit 页面中的探测卡片与引导脚本。"""
    cfg = _json_attr(plan.as_dict())
    script = _attr(plan.script_url)
    zone_note = plan.dns_zone or "未配置 DNS 探针区域"
    return (
        f"<style>{_CSS}</style>"
        '<div class="vpncheck-card">'
        "<div><strong>正在浏览器里做实时检测</strong></div>"
        '<div class="vpncheck-status" id="vpncheck-status">初始化……</div>'
        f'<div class="vpncheck-status">DNS 探针区域：{_attr(zone_note)}</div>'
        "</div>"
        f'<div id="vpncheck-cfg" data-cfg="{cfg}" data-script="{script}" hidden></div>'
        f"<script>{_BOOTSTRAP}</script>"
    )
