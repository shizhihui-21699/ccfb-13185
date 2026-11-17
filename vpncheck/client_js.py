"""浏览器端探测脚本（以静态文件形式由采集端提供）。

为什么是独立文件而不是内联到 ``st.html``：
Streamlit 的 ``st.html`` 会先做 HTML 净化，脚本里出现 ``<`` 紧跟字母的文本
（例如注释、字符串比较）会被当作标签剥离，导致脚本被截断而不执行。把脚本
作为 ``<script src=...>`` 外链加载可以完全避开这类解析问题，也便于浏览器
缓存与版本控制。

脚本只与自检页的采集端通信，读取 ``#vpncheck-cfg`` 上的 ``data-cfg``。
"""

from __future__ import annotations

VERSION = "1.0.0"

CLIENT_JS = r"""
(function () {
  "use strict";
  var cfgEl = document.getElementById("vpncheck-cfg");
  if (!cfgEl) return;
  var cfg;
  try { cfg = JSON.parse(cfgEl.getAttribute("data-cfg")); } catch (e) { return; }
  if (!cfg || !cfg.sid) return;

  // Streamlit 每次重跑都可能重新插入脚本，用标记保证同一会话只跑一次。
  window.__vpncheckDone = window.__vpncheckDone || {};
  if (window.__vpncheckDone[cfg.sid]) return;
  window.__vpncheckDone[cfg.sid] = true;

  var statusEl = document.getElementById("vpncheck-status");
  function setStatus(text) { if (statusEl) statusEl.textContent = text; }

  function rand() {
    try {
      var a = new Uint8Array(8);
      crypto.getRandomValues(a);
      return Array.prototype.map.call(a, function (x) {
        return ("0" + x.toString(16)).slice(-2);
      }).join("");
    } catch (e) {
      return String(Date.now()) + Math.floor(Math.random() * 1e6);
    }
  }

  function post(kind, data) {
    try {
      return fetch(cfg.reportUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sid: cfg.sid, kind: kind, data: data || {} }),
        mode: "cors",
        cache: "no-store",
        credentials: "omit",
        keepalive: true
      }).catch(function () { return null; });
    } catch (e) {
      return Promise.resolve(null);
    }
  }

  function notifyParent() {
    try {
      window.parent.postMessage({ type: "vpncheck:done", sid: cfg.sid }, "*");
    } catch (e) {}
  }

  // ---------- 1. HTTP 出口（IPv4 / IPv6 分开看） ----------
  function httpProbe(url, label) {
    if (!url) return Promise.resolve(null);
    var target = url + "?s=" + encodeURIComponent(cfg.sid) + "&n=" + rand();
    var started = Date.now();
    return fetch(target, {
      mode: "cors",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer"
    }).then(function (resp) {
      if (!resp.ok) throw new Error("status " + resp.status);
      return resp.json();
    }).then(function (body) {
      return {
        label: label, ok: true, address: body.ip,
        family: body.family, ms: Date.now() - started
      };
    }).catch(function (err) {
      // 跨域 fetch 被拦截时退回到图片探针：仍能留下一次真实连接。
      return new Promise(function (resolve) {
        var img = new Image();
        var settled = false;
        function finish(result) { if (!settled) { settled = true; resolve(result); } }
        img.onload = function () { finish({ label: label, ok: true, via: "img" }); };
        img.onerror = function () {
          finish({ label: label, ok: false, via: "img",
                   error: String((err && err.message) || err) });
        };
        img.src = url + "/pixel.gif?s=" + encodeURIComponent(cfg.sid) + "&n=" + rand();
        setTimeout(function () { finish({ label: label, ok: false, timeout: true }); }, 5000);
      });
    });
  }

  // ---------- 2. DNS 探测 ----------
  // 每个域名唯一、服务端 TTL=0，确保每次都是真实递归查询而不是缓存命中。
  function dnsProbe() {
    var zone = cfg.dnsZone;
    if (!zone) return Promise.resolve([]);
    var rounds = Math.max(1, Math.min(6, cfg.dnsRounds || 3));
    var waitMs = Math.max(2000, Math.min(60000, (cfg.dnsWait || 8) * 1000));
    var jobs = [];
    for (var i = 0; i < rounds; i++) {
      var seq = ("0" + i.toString(16)).slice(-2);
      var host = cfg.sid + seq + "." + zone;
      jobs.push(new Promise(function (resolve) {
        var img = new Image();
        var settled = false;
        function finish() {
          if (settled) return;
          settled = true;
          resolve({ host: host, triggered: true });
        }
        img.onload = finish;
        img.onerror = finish;
        img.src = "https://" + host + "/p.gif?n=" + rand();
        setTimeout(finish, waitMs);
      }));
    }
    return Promise.all(jobs);
  }

  // ---------- 3. WebRTC ----------
  function webrtcProbe() {
    var RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection ||
              window.mozRTCPeerConnection;
    if (!RTC) return Promise.resolve({ unsupported: true, candidates: [] });
    if (!cfg.stunUris || !cfg.stunUris.length) {
      return Promise.resolve({ unsupported: true, reason: "no-stun", candidates: [] });
    }
    return new Promise(function (resolve) {
      var candidates = [];
      var pc = null;
      var finished = false;
      function finish(error) {
        if (finished) return;
        finished = true;
        try { if (pc) pc.close(); } catch (e) {}
        resolve({ candidates: candidates, error: error || null });
      }
      try {
        pc = new RTC({ iceServers: [{ urls: cfg.stunUris }] });
      } catch (e) {
        resolve({ candidates: [], error: "RTCPeerConnection 初始化失败" });
        return;
      }
      pc.onicecandidate = function (event) {
        if (!event.candidate) return;
        var parts = (event.candidate.candidate || "").split(" ");
        // candidate:foundation component transport priority address port typ TYPE
        if (parts.length <= 7) return;
        candidates.push({
          type: parts[7],
          address: parts[4],
          port: parts[5],
          protocol: parts[2]
        });
      };
      try { pc.createDataChannel("probe"); } catch (e) {}
      pc.createOffer().then(function (offer) {
        return pc.setLocalDescription(offer);
      }).catch(function () {
        finish("createOffer/setLocalDescription 失败");
      });
      setTimeout(function () { finish(null); }, 4000);
    });
  }

  // ---------- 汇总 ----------
  setStatus("正在检测 DNS、IPv4/IPv6 与 WebRTC……");
  Promise.all([
    httpProbe(cfg.ipv4Probe, "ipv4"),
    httpProbe(cfg.ipv6Probe, "ipv6")
  ]).then(function (http) {
    var results = http.filter(Boolean);
    var addresses = results.map(function (r) { return r.address || "?"; });
    setStatus("已取得 HTTP 出口：" + addresses.join(" / "));
    return post("timing", { http: results });
  }).then(function () {
    return dnsProbe();
  }).then(function (dns) {
    setStatus("已触发 " + dns.length + " 次 DNS 探测，正在等待解析器回应……");
    return post("timing", { dns: dns.length });
  }).then(function () {
    setStatus("正在检查 WebRTC 暴露的地址……");
    return webrtcProbe();
  }).then(function (rtc) {
    return post("webrtc", rtc);
  }).then(function () {
    setStatus("检测完成，结果正在汇总……");
    setTimeout(notifyParent, 300);
  }).catch(function () {
    setStatus("检测过程中出现错误，请刷新页面重试。");
  });
})();
"""


def client_js() -> str:
    return CLIENT_JS
