# VPN 泄露自检站

员工连上公司 VPN 后打开页面，一键检测四类泄露，并对照公司出口地址列表给出结论和对应操作系统的修复建议。

## 检测原理

| 检测项 | 原理 | 判定 |
|---|---|---|
| Web 流量出口 | 浏览器访问探针 API，服务端记录 TCP 对端 IP | 命中 `company_egress` → 正常 |
| DNS 解析出口 | 每次检测生成唯一子域 `<token>.dns.<zone>`，本机权威 DNS 记录发来递归查询的**解析器出口 IP** | 命中 `company_dns` → 正常，否则 DNS 泄露 |
| WebRTC 暴露 | 页面 JS 用 `RTCPeerConnection` + STUN 收集候选地址并上报 | 出现非公司公网 IP → 泄露 |
| IPv6 绕过 | 页面访问只有 AAAA 记录的 `ipv6.<zone>`，能连通即存在 IPv6 出口 | 出口不在 `company_egress_v6` → 绕过隧道 |

## 架构与部署（单容器三服务）

```
┌────────────────────────────── 一台有公网 IP 的服务器 ──┐
│  python main.py                                       │
│  ├─ 权威 DNS   :53/udp+tcp   （dnslib，记录解析器出口）│
│  ├─ 探针 API   :8000/tcp     （FastAPI，记录流量出口） │
│  └─ Web 页面   :8501/tcp     （Streamlit）             │
│  共享 SQLite（leakcheck.db，24h 自动清理）             │
└───────────────────────────────────────────────────────┘
```

### 1. DNS 委托（关键前提）

在域名注册商/DNS 服务商处，把检测子域委托给本服务器：

```
check.example.com.   300  IN  NS  ns1-check.example.com.
ns1-check.example.com. 300 IN  A   <服务器公网IP>
ns1-check.example.com. 300 IN  AAAA <服务器公网IPv6>   # 可选
```

### 2. 配置

编辑 `config.yaml`：`zone`、服务器地址、`company_egress`（公司 VPN 出口 CIDR）、`company_dns`（公司解析器出口）、`company_egress_v6`。

### 3. 启动

Docker（推荐）：

```bash
docker compose up -d --build
```

或裸机（监听 53 端口需要 root）：

```bash
pip install -r requirements.txt
sudo python main.py
```

防火墙放行：`53/udp`、`53/tcp`、`8000/tcp`、`8501/tcp`。

### 4. 使用

员工连上 VPN → 打开 `http://<服务器>:8501` → 点“开始检测” → 约 15 秒出报告。

## 生产化建议

- **HTTPS**：用 Caddy/nginx 反代 8501 与 8000 并签证书（Caddy 可自动签发；通配符证书可让 `*.dns.<zone>` 的 dns-hit 也走 HTTPS，避免页面 HTTPS 后浏览器拦截混合内容）。反代后把 `trust_proxy_headers` 置 `true`。
- **纯内网变体**：若检测页只允许 VPN 内访问，可把服务部署在内网，内网 DNS 把 `check.corp` 之类的私有域直接指向服务器；此时 Web 出口一项天然为内网地址，可只看 DNS/WebRTC/IPv6 三项。
- **STUN**：公网 STUN（默认 Google）可能被封，建议用 coturn 自建并改 `stun_servers`。

## 局限性

- 浏览器 **DoH** 会绕过系统解析器，DNS 项可能显示“未收到查询”——报告会提示，建议企业策略禁用 DoH 后重测。
- 新版浏览器用 **mDNS（.local）** 隐藏局域网候选地址，WebRTC 项主要看公网 srflx 候选。
- 唯一子域 + 5 秒 TTL 已规避缓存，但极端情况下中间解析器仍可能缓存，重测即可。

## 隐私

检测数据（出口 IP、User-Agent）只写入服务器本地 SQLite，默认 24 小时自动清理，不外发任何第三方。
