"""Streamlit 页面：员工连上 VPN 后打开，一键完成四项泄露检测。"""
from __future__ import annotations

import json
import time
import uuid

import streamlit as st
import streamlit.components.v1 as components

from leakcheck import shared
from leakcheck.analysis import analyze, fix_suggestions_markdown

PROBE_SECONDS = 12

st.set_page_config(page_title="VPN 泄露自检", page_icon="🛡️", layout="centered")

CFG = shared.CFG
DB = shared.DB


def build_probe_html(token: str) -> str:
    api_port = int(CFG["ports"]["api"])
    zone = CFG["zone"]
    opts = json.dumps({
        "token": token,
        "api": f"http://{zone}:{api_port}",
        "apiV6": f"http://ipv6.{zone}:{api_port}",
        "apiV4": f"http://ipv4.{zone}:{api_port}",
        "dnsProbe": f"http://{token}.dns.{zone}:{api_port}",
        "stun": CFG.get("stun_servers", []),
    })
    return """
<div id="st" style="font:14px system-ui;color:#666">正在初始化探针…</div>
<script>
const OPT = __OPTS__;
const stEl = document.getElementById('st');
const say = m => { stEl.textContent = m; };
const get = async u => { try { const r = await fetch(u, {cache: 'no-store'}); return await r.json(); } catch (e) { return null; } };

function collectWebRTC() {
  return new Promise(resolve => {
    const found = {};
    let pc;
    try { pc = new RTCPeerConnection({iceServers: OPT.stun.map(u => ({urls: u}))}); }
    catch (e) { return resolve([]); }
    const timer = setTimeout(done, 4000);
    function done() {
      clearTimeout(timer);
      try { pc.close(); } catch (e) {}
      resolve(Object.values(found));
    }
    pc.onicecandidate = ev => {
      if (!ev.candidate) { done(); return; }
      const c = ev.candidate.candidate || '';
      const tm = c.match(/typ\\s+(host|srflx|prflx|relay)/);
      const type = tm ? tm[1] : 'unknown';
      (c.match(/(?:\\d{1,3}\\.){3}\\d{1,3}|[0-9a-fA-F:]{3,}/g) || []).forEach(ip => {
        if (!/\\.local$/.test(ip)) found[ip + '|' + type] = {ip, type};
      });
    };
    try {
      pc.createDataChannel('x');
      pc.createOffer().then(o => pc.setLocalDescription(o)).catch(done);
    } catch (e) { done(); }
  });
}

(async () => {
  say('1/4 检测 Web 流量出口…');
  await get(`${OPT.api}/api/probe/web?token=${OPT.token}`);

  say('2/4 检测 DNS 解析出口…');
  await new Promise(res => {
    const img = new Image();
    img.onload = img.onerror = res;
    img.src = `${OPT.dnsProbe}/api/probe/dns-hit?token=${OPT.token}&_=${Math.random()}`;
    setTimeout(res, 5000);
  });

  say('3/4 检测 IPv6 连通…');
  await get(`${OPT.apiV6}/api/probe/ipv6?token=${OPT.token}`);
  await get(`${OPT.apiV4}/api/probe/ipv4?token=${OPT.token}`);

  say('4/4 检测 WebRTC 地址暴露…');
  const ips = await collectWebRTC();
  await fetch(`${OPT.api}/api/report/${OPT.token}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({webrtc: ips}),
  }).catch(() => {});
  say('检测完成，正在生成报告…');
})();
</script>
""".replace("__OPTS__", opts)


def render_result(result: dict) -> None:
    overall = result["overall"]
    if overall == "fail":
        st.error("## 🛡️ 检测结果：存在泄露，请按下方建议处理")
    elif overall == "warn":
        st.warning("## 🛡️ 检测结果：部分项目未能确认，建议重新检测")
    else:
        st.success("## 🛡️ 检测结果：未发现泄露")

    box = {"ok": st.success, "warn": st.warning, "fail": st.error, "info": st.info}
    for c in result["checks"]:
        box[c["status"]](f"**{c['title']}** — {c['summary']}")
        if c["details"]:
            with st.expander(f"{c['title']} · 详情"):
                st.text(c["details"])

    st.divider()
    st.subheader("🛠 修复建议")
    st.markdown(fix_suggestions_markdown(result["os"]))

    with st.expander("原始探针数据（管理员排查用）"):
        st.json(result["events"])


def main() -> None:
    st.title("🛡️ VPN 泄露自检")
    st.caption("连接公司 VPN 后点击“开始检测”，约 15 秒出结果。检测数据仅保存在检测服务器本地，24 小时内自动清除。")

    if CFG["zone"].endswith("example.com"):
        st.warning("⚠️ 当前仍是示例配置：请管理员在 `config.yaml` 中设置真实的 `zone`、服务器地址与公司出口列表。")

    with st.expander("检测原理说明"):
        st.markdown(
            "- **Web 出口**：你的浏览器访问检测 API，服务端记录 TCP 对端 IP。\n"
            "- **DNS 出口**：页面解析一个每次检测唯一的子域名，公司权威 DNS 记录发来查询的解析器出口 IP。\n"
            "- **WebRTC**：浏览器 RTCPeerConnection 收集本机候选地址并上报，看是否暴露真实公网 IP。\n"
            "- **IPv6**：页面访问一个只有 AAAA 记录的域名，若能连通说明 IPv6 流量存在，再比对其出口。"
        )

    if "token" not in st.session_state:
        st.session_state["token"] = uuid.uuid4().hex[:12]
    token = st.session_state["token"]
    DB.create_session(token)

    col1, col2 = st.columns([1, 1])
    start = col1.button("🚀 开始检测", type="primary", use_container_width=True)
    reset = col2.button("↺ 重新检测", use_container_width=True)
    if reset:
        for k in ("token", "detecting", "done"):
            st.session_state.pop(k, None)
        st.rerun()

    if start:
        st.session_state["detecting"] = True
        st.session_state["done"] = False

    if st.session_state.get("detecting"):
        components.html(build_probe_html(token), height=60)
        bar = st.progress(0, text="检测中，请保持本页面打开…")
        for i in range(PROBE_SECONDS):
            time.sleep(1)
            bar.progress((i + 1) / PROBE_SECONDS, text=f"检测中… {i + 1}/{PROBE_SECONDS} 秒")
        st.session_state["detecting"] = False
        st.session_state["done"] = True
        st.rerun()

    if st.session_state.get("done"):
        result = analyze(CFG, DB.get_session(token), DB.get_events(token))
        render_result(result)
        if st.button("🔄 刷新结果（探针数据可能稍有延迟）"):
            st.rerun()


main()
