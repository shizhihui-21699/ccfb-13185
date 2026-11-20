"""Browser-side probe: HTML/JS served into the Streamlit page.

Everything here runs **in the employee's browser**, so it stays dependency-free
and readable, and it never reports an address it merely guessed: the beacons
exist so the *server* can see the egress, while WebRTC candidates are reported as
"what the page was told" and cross-checked against the server's own observations
by the verdict engine.

Probes run in this order (each stage updates the session so the Streamlit side
can show progress):

1. ``http``   – beacons to ``/px.gif`` (cache-busted) and
   ``/api/v1/observe/http``; a couple of rounds so a mid-test reconnect is seen.
2. ``dns``    – resolve unique ``<token>-sys<N>.<probe domain>`` names by
   pointing an ``<img>`` at ``https://<name>/``.  The image load fails (there is
   no web server there) but the lookup reaches our authoritative listener, which
   records the resolver's egress address.
3. ``webrtc`` – an ``RTCPeerConnection`` whose only ICE server is *our* STUN
   listener on the session's own UDP port, then report every candidate verbatim.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any


def _js_json(value: Any) -> str:
    """JSON safe to inline inside a <script> block."""
    return json.dumps(value, ensure_ascii=False).replace("</", "<\\/")


def stun_targets(config: Any, port: int) -> list[str]:
    """STUN ``host:port`` targets the browser should try, IPv4 and IPv6.

    Only the port the server allocated to this session is used: STUN carries no
    session identity, so a probe to any other port could not be attributed.
    """
    targets: list[str] = []
    for ip in config.stun.public_ips:
        text = str(ip)
        targets.append(f"[{text}]:{port}" if ":" in text else f"{text}:{port}")
    if not targets:
        host = config.server.public_base_url.split("//")[-1].split("/")[0]
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        if host.startswith("["):
            host = host.split("]")[0] + "]"
        targets.append(f"{host}:{port}")
    return targets


_PROBE_JS = r"""
(function () {
  "use strict";

  function now() { return (window.performance && performance.now) ? performance.now() : Date.now(); }

  function logLine(msg) {
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ source: "leakcheck", type: "log", text: msg }, "*");
      }
    } catch (e) { /* cross-origin parent: ignore */ }
  }

  async function stage(S, name) {
    try {
      await fetch(S.apiBase + "/api/v1/stage", {
        method: "POST",
        mode: "cors",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: S.token, stage: name }),
        keepalive: true
      });
    } catch (e) { /* progress reporting is best effort */ }
  }

  async function beacon(S, kind, extra) {
    // Two transports on purpose: an <img> load is not blocked by CORS or by
    // privacy extensions that filter fetch(), while the POST gives us a body.
    await new Promise(function (resolve) {
      const img = new Image();
      let settled = false;
      const done = function () { if (settled) return; settled = true; resolve(); };
      img.onload = done;
      img.onerror = done;
      img.src = S.apiBase + "/px.gif?t=" + encodeURIComponent(S.token) +
                "&k=" + encodeURIComponent(kind) + "&r=" + Math.random().toString(36).slice(2);
      setTimeout(done, 4000);
    });
    try {
      await fetch(S.apiBase + "/api/v1/observe/http", {
        method: "POST",
        mode: "cors",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({ token: S.token, kind: kind }, extra || {})),
        keepalive: true
      });
    } catch (e) {
      logLine("HTTP 信标上报失败：" + (e && e.message ? e.message : e));
    }
  }

  function resolveName(name, timeoutMs) {
    // A failed <img> load still performs the DNS lookup. TTL 0 on our zone plus
    // a unique label per attempt keeps every lookup on the wire.
    return new Promise(function (resolve) {
      const started = now();
      const img = new Image();
      let settled = false;
      const done = function (state) {
        if (settled) return;
        settled = true;
        resolve({ name: name, state: state, ms: Math.round(now() - started) });
      };
      img.onload = function () { done("loaded"); };
      img.onerror = function () { done("error"); };
      img.src = "https://" + name + "/?_=" + Date.now();
      setTimeout(function () { done("timeout"); }, timeoutMs || 3500);
    });
  }

  async function dnsProbe(S) {
    const rounds = Math.max(2, Math.min(6, S.dnsRounds || 3));
    // A per-run suffix defeats the browser's own DNS cache: if this script is
    // re-run in the same session (component remount, user reload) the names must
    // still be unique, otherwise the lookup never leaves the machine and the
    // server would see zero queries and report a false "cannot determine".
    const run = Math.random().toString(36).slice(2, 8);
    const lookups = [];
    for (let i = 1; i <= rounds; i++) {
      const name = S.token + "-" + run + "s" + i + "." + S.probeDomain;
      lookups.push(resolveName(name, 3500));
      // A short gap lets resolvers coalesce A/AAAA without hiding a rotation
      // between networks (which is what a reconnect looks like).
      await new Promise(function (r) { setTimeout(r, 120); });
    }
    const results = await Promise.all(lookups);
    const failures = results.filter(function (r) { return r.state !== "error"; });
    return { results: results, unusual: failures.length };
  }

  function parseCandidate(line) {
    const parts = String(line || "").split(" ");
    if (parts.length < 8) return null;
    const port = parseInt(parts[5], 10);
    const typeIndex = parts.indexOf("typ");
    return {
      foundation: (parts[0] || "").replace(/^candidate:/, "").slice(0, 32),
      protocol: parts[2],
      address: parts[4],
      port: isNaN(port) ? null : port,
      type: typeIndex >= 0 ? parts[typeIndex + 1] : ""
    };
  }

  function webrtcProbe(S) {
    return new Promise(function (resolve) {
      if (!window.RTCPeerConnection) {
        resolve({ error: "浏览器不支持 RTCPeerConnection", candidates: [] });
        return;
      }
      const urls = (S.stunTargets || []).map(function (t) { return "stun:" + t; });
      let pc;
      try {
        pc = new RTCPeerConnection({
          iceServers: urls.length ? [{ urls: urls }] : [],
          iceCandidatePoolSize: 4,
          iceTransportPolicy: "all"
        });
      } catch (e) {
        resolve({ error: "创建 RTCPeerConnection 失败：" + (e.message || e), candidates: [] });
        return;
      }
      const seen = {};
      const candidates = [];
      let finished = false;

      function finish() {
        if (finished) return;
        finished = true;
        try { pc.close(); } catch (e) { /* ignore */ }
        resolve({
          candidates: candidates,
          mdns: candidates.some(function (c) { return /\.local$/i.test(c.address || ""); }),
          elapsed_ms: Math.round(now() - started)
        });
      }

      const started = now();
      pc.onicecandidate = function (event) {
        if (!event.candidate) { finish(); return; }
        const parsed = parseCandidate(event.candidate.candidate);
        if (!parsed) return;
        const key = parsed.type + "|" + parsed.protocol + "|" + parsed.address + "|" + parsed.port;
        if (seen[key]) return;
        seen[key] = true;
        candidates.push(parsed);
        // srflx/prflx are the addresses a remote peer would see; stop as soon as
        // we have one of each family so the page does not linger.
        const haveV4 = candidates.some(function (c) { return c.type === "srflx" && c.address.indexOf(":") < 0; });
        const haveV6 = candidates.some(function (c) { return c.type === "srflx" && c.address.indexOf(":") >= 0; });
        if (haveV4 && haveV6) finish();
      };

      try {
        pc.createDataChannel("leakcheck");
      } catch (e) { /* Safari without data channels still gathers STUN */ }

      pc.createOffer().then(function (offer) {
        return pc.setLocalDescription(offer);
      }).catch(function (e) {
        if (!finished) {
          finished = true;
          try { pc.close(); } catch (err) { /* ignore */ }
          resolve({ error: "创建 WebRTC 提议失败：" + (e.message || e), candidates: candidates });
        }
      });

      setTimeout(finish, S.webrtcTimeout || 6000);
    });
  }

  async function run(S) {
    const summary = { started: new Date().toISOString() };
    try {
      // Stage 1: HTTP egress, two rounds with a gap.
      await stage(S, "http");
      await beacon(S, "round1");
      await new Promise(function (r) { setTimeout(r, 700); });
      await beacon(S, "round2", { round: 2 });

      // Stage 2: DNS.
      await stage(S, "dns");
      const dns = await dnsProbe(S);
      summary.dns = dns;

      // Stage 3: WebRTC / UDP.
      await stage(S, "webrtc");
      const webrtc = await webrtcProbe(S);
      try {
        await fetch(S.apiBase + "/api/v1/observe/webrtc", {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            token: S.token,
            candidates: webrtc.candidates || [],
            error: webrtc.error || null,
            elapsed_ms: webrtc.elapsed_ms || 0,
            mdns: !!webrtc.mdns,
            browser: navigator.userAgent
          })
        });
      } catch (e) {
        logLine("WebRTC 候选上报失败：" + (e && e.message ? e.message : e));
      }
      summary.webrtc = webrtc;

      // Final beacon so the server can see the egress at the end of the run too.
      await beacon(S, "done");
      await stage(S, "done");
      try {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ source: "leakcheck", type: "done", summary: summary }, "*");
        }
      } catch (e) { /* ignore */ }
    } catch (e) {
      await stage(S, "error");
      logLine("自检脚本异常：" + (e && e.message ? e.message : e));
    }
  }

  window.leakcheckRun = run;
})();
"""

_IFRAME_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · 自检探针</title>
<style>
  :root { color-scheme: light dark; }
  body {
    margin: 0;
    font: 13px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
          "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
    padding: 10px 12px;
    background: transparent;
  }
  .row { display: flex; gap: 8px; align-items: center; margin: 4px 0; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #9aa0a6; flex: none; }
  .dot.on { background: #1a7f37; }
  .dot.warn { background: #bf8700; }
  .dot.err { background: #cf222e; }
  .name { font-weight: 600; min-width: 6.5em; }
  .hint { opacity: .7; }
  pre {
    white-space: pre-wrap; word-break: break-all; margin: 6px 0 0;
    padding: 8px; border-radius: 6px; font-size: 11px;
    background: rgba(127,127,127,.12);
  }
</style>
</head>
<body>
  <div class="row"><span class="dot" id="d-http"></span><span class="name">网页出口</span><span class="hint" id="t-http">等待</span></div>
  <div class="row"><span class="dot" id="d-dns"></span><span class="name">DNS 解析</span><span class="hint" id="t-dns">等待</span></div>
  <div class="row"><span class="dot" id="d-webrtc"></span><span class="name">实时通信</span><span class="hint" id="t-webrtc">等待</span></div>
  <pre id="log" hidden></pre>
<script>
const SETTINGS = __SETTINGS__;
</script>
<script>
__PROBE_JS__
</script>
<script>
(function () {
  const settings = SETTINGS;
  const lines = [];
  function mark(id, cls, text) {
    const dot = document.getElementById("d-" + id);
    const label = document.getElementById("t-" + id);
    if (dot) { dot.className = "dot " + (cls || ""); }
    if (label) { label.textContent = text; }
  }
  function log(text) {
    lines.push(new Date().toLocaleTimeString() + "  " + text);
    const box = document.getElementById("log");
    box.hidden = false;
    box.textContent = lines.slice(-8).join("\\n");
  }
  if (!settings.token) {
    mark("http", "err", "缺少会话令牌");
  } else {
    mark("http", "warn", "进行中");
    const originalStage = window.leakcheckRun;
    // Progress is reported by the probe itself through /api/v1/stage; mirror it
    // locally so the employee sees movement without waiting for the server.
    const timer = setInterval(function () {
      const dns = document.getElementById("t-dns");
      if (dns && dns.textContent === "进行中") { mark("webrtc", "warn", "进行中"); }
    }, 500);
    setTimeout(function () { mark("dns", "warn", "进行中"); }, 1800);
    setTimeout(function () { mark("webrtc", "warn", "进行中"); }, 4200);
    Promise.resolve(originalStage(settings)).then(function () {
      clearInterval(timer);
      mark("http", "on", "已上报");
      mark("dns", "on", "已发起查询");
      mark("webrtc", "on", "已收集候选");
      log("自检脚本执行完毕，结果已提交。");
    }).catch(function (e) {
      clearInterval(timer);
      mark("http", "err", "执行失败");
      log(String(e));
    });
  }
})();
</script>
</body>
</html>
"""


def build_probe_html(config: Any, token: str, stun_port: int) -> str:
    """Return the iframe document that runs the probes for one session."""
    settings = {
        "token": token,
        "apiBase": config.server.public_base_url,
        "probeDomain": config.probe_domain,
        "stunTargets": stun_targets(config, stun_port),
        "dnsRounds": max(2, min(6, config.server.max_probes // 4 or 2)),
        "webrtcTimeout": 6000,
    }
    return (
        _IFRAME_TEMPLATE.replace("__TITLE__", escape(config.site_title))
        .replace("__SETTINGS__", _js_json(settings))
        .replace("__PROBE_JS__", _PROBE_JS)
    )


_STANDALONE_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · 浏览器自检</title>
<style>
  :root { color-scheme: light dark; --fg:#1f2328; --bg:#ffffff; --mut:#59636e; --line:#d1d9e0; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e6edf3; --bg:#0d1117; --mut:#9198a1; --line:#30363d; }
  }
  body { margin:0; padding:28px 18px 60px; background:var(--bg); color:var(--fg);
    font:14px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
         "Hiragino Sans GB", "Microsoft YaHei", sans-serif; }
  main { max-width: 760px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  p.lead { color: var(--mut); margin: 0 0 24px; }
  table { width:100%; border-collapse: collapse; margin-top: 8px; }
  th, td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); font-size:13px; }
  th { color: var(--mut); font-weight:600; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
  .badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px;
    border:1px solid var(--line); }
  .warn { color:#9a6700; } .err { color:#cf222e; } .ok { color:#1a7f37; }
  #log { margin-top:18px; white-space:pre-wrap; font-size:12px; color:var(--mut); }
  a.button { display:inline-block; margin-top:24px; padding:8px 14px; border-radius:6px;
    border:1px solid var(--line); text-decoration:none; color:inherit; }
</style>
</head>
<body>
<main>
  <h1>__TITLE__ · 浏览器自检</h1>
  <p class="lead">本页只做一件事：让服务端观测你的浏览器把请求和解析从哪个出口发出去。数据仅用于本次判断。</p>
  <div id="state" class="badge">准备中…</div>
  <table>
    <thead><tr><th>通道</th><th>服务端观测到的出口</th></tr></thead>
    <tbody id="rows"><tr><td colspan="2" class="warn">正在采集…</td></tr></tbody>
  </table>
  <div id="log"></div>
  <a class="button" href="/">返回自检首页（Streamlit 版，含完整判定与修复建议）</a>
</main>
<script>
__PROBE_JS__
</script>
<script>
(function () {
  const stateEl = document.getElementById("state");
  const rowsEl = document.getElementById("rows");
  const logEl = document.getElementById("log");
  function log(t) { logEl.textContent += t + "\\n"; }
  const origin = location.origin;

  async function boot() {
    const res = await fetch(origin + "/api/v1/session", {
      method: "POST",
      headers: { "X-Client-Hint": "standalone" }
    });
    if (!res.ok) { throw new Error("无法创建会话：" + res.status); }
    const session = await res.json();
    stateEl.textContent = "采集中…";
    stateEl.className = "badge warn";
    const targets = [];
    if (session.stun_port) {
      // The server allocated this port to our session; STUN traffic arriving on
      // any other port cannot be attributed, so only this one is probed.
      targets.push((session.stun_host || location.hostname) + ":" + session.stun_port);
    }
    const settings = {
      token: session.token,
      apiBase: origin,
      probeDomain: session.probe_domain,
      stunTargets: targets,
      dnsRounds: 3,
      webrtcTimeout: 6000
    };
    await window.leakcheckRun(settings);
    log("采集完成，正在读取结果…");
    await poll(session.token, 0);
  }

  async function poll(token, attempt) {
    if (attempt > 30) {
      stateEl.textContent = "等待超时，请刷新重试";
      stateEl.className = "badge err";
      return;
    }
    const res = await fetch(origin + "/api/v1/observations/" + token);
    if (res.ok) {
      const data = await res.json();
      const rows = data.rows || [];
      if (rows.length) {
        rowsEl.innerHTML = rows.map(function (r) {
          return "<tr><td><code>" + r.channel + "</code></td><td><code>" +
                 (r.address || "-") + "</code></td></tr>";
        }).join("");
      }
      if (data.stage === "done") {
        stateEl.textContent = "采集完成";
        stateEl.className = "badge ok";
        return;
      }
    }
    setTimeout(function () { poll(token, attempt + 1); }, 1000);
  }

  boot().catch(function (e) {
    stateEl.textContent = "自检失败";
    stateEl.className = "badge err";
    log(String(e));
  });
})();
</script>
</body>
</html>
"""


def standalone_page(config: Any) -> str:
    return _STANDALONE_TEMPLATE.replace("__TITLE__", escape(config.site_title)).replace(
        "__PROBE_JS__", _PROBE_JS
    )


class _DefaultView:
    """Fallback title used when the module is imported without configuration."""

    site_title = "VPN 流量泄露自检"


STANDALONE_PAGE = standalone_page(_DefaultView())
