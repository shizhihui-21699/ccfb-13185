# 公司 VPN 泄露自检

员工连上公司 VPN 后打开一个网页，页面自动检查四件事，并与公司的出口地址表
对照，判断是否存在泄露：

| 检查项 | 怎么测 | 判定依据 |
| --- | --- | --- |
| 访问自检页的出口 | 服务端看到的连接地址（不可伪造） | 是否在公司出口表内 |
| **DNS 解析出口** | 唯一子域名触发真实递归查询，看解析器从哪个出口发出 | 递归解析器的出口是否在公司出口表内 |
| **IPv6 是否绕过隧道** | 用只解析到 AAAA 的域名访问采集端 | 采集端看到的 IPv6 来源是否在公司出口表内 |
| **WebRTC 暴露的地址** | 本服务自带的最小 STUN 服务，读 `srflx`/`host` 候选 | 反射地址是否在公司出口表内 |
| 出口一致性 | 多次 HTTP 探测是否走了不同出口 | 是否存在分流/双网卡 |

结论分五档：**泄露 / 需注意 / 无法判定 / 未执行 / 正常**。所有「无法判定」
都写明原因和重试方法，不会把"没测到"说成"没问题"。页面对每个泄露项按操作
系统给出可执行的修复步骤（Windows / macOS / Linux / iOS / Android），并可
下载一份可直接贴给 IT 的 Markdown 报告。

---

## 1. 快速开始（单机试运行）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

cp config.example.toml config.toml     # 按公司实际出口地址改
streamlit run app.py                    # 页面 + 探针同进程启动
```

默认在 `http://localhost:8501`。示例配置里的出口表是 RFC 5737 文档地址，
页面会明确警告「结果不能当真」——必须先把真实出口地址填进去。

跑测试：

```bash
pip install -r requirements-dev.txt
python -m pytest -q            # 86 项单元/集成测试
python scripts/e2e_smoke.py    # 真实浏览器端到端冒烟（需 playwright install chromium）
```

## 2. 配置要点

完整注释见 `config.example.toml`，最容易踩坑的四点：

1. **`[[egress]]` 出口表是整个判定的基准。**
   `kind = "corporate"` 是公司 VPN 的**公网出口**地址段。DNS 项看到的是
   **递归解析器**的出口，不是员工电脑的地址；如果公司 DNS 出站有独立 NAT，
   要额外加一条 `kind = "dns"`。漏配会造成误报。
2. **DNS 探针区域必须由本服务作权威，且 TTL=0。**
   页面查询 `<会话标识><序号>.zone`；这些域名必须唯一（本服务不缓存即可），
   否则会被公共解析器缓存，观测不到真实出口。
   注册示例：`probe.vpncheck.corp.example.com  NS  ns1.vpncheck.corp.example.com`
   并把 `ns1` 指向本机，或者在权威 DNS 上把该子域委派过来。
3. **IPv6 检测需要给采集端单独的 AAAA 域名**（`collector.public_url_v6`）。
   不配则该项显示「未执行」，而不是「正常」。
4. **WebRTC 检测需要一段 UDP 端口池**（`[stun].port_range`）。
   每个会话独占一个端口，所以端口池大小 ≈ 同时在线的自检人数上限。
   防火墙要放通 `base .. base+size-1/udp` 整段；用 Docker 时端口映射也必须
   是整段（见 `docker-compose.yml`）。

## 3. 部署方式

### 方式 A：单进程（推荐给中小团队）

`probes.mode = "embedded"`。Streamlit 进程内启动 HTTP 采集端、DNS 探针和
STUN。优点是一个进程、一份配置；缺点是 Streamlit 重启会短暂中断探针，
且 53/3478 端口由运行 Streamlit 的用户绑定。

Docker：

```bash
mkdir -p data && cp config.example.toml data/config.toml
docker compose up -d --build
```

镜像以非 root 用户运行，53 端口在容器内不需要额外权限（容器网络命名空间
内 53 属于非特权端口）。

### 方式 B：探针与页面分离（推荐给生产）

`probes.mode = "external"`。三个探针由 `scripts/run_probes.py` 常驻，
Streamlit 只读共享 SQLite（`VPNCHECK_DB` 指向同一个文件）：

```bash
# 探针机（可绑 53/3478，可水平扩展）
python scripts/run_probes.py --config /etc/vpncheck/config.toml \
    --db /var/lib/vpncheck/vpncheck.sqlite3

# 页面机
VPNCHECK_CONFIG=/etc/vpncheck/config.toml \
VPNCHECK_DB=/var/lib/vpncheck/vpncheck.sqlite3 \
streamlit run app.py
```

systemd 单元见 `deploy/vpncheck-probes.service`、`deploy/vpncheck-app.service`。
注意：SQLite 要放在两台机器都能访问的本地盘/持久卷上（共享网络文件系统上
SQLite 的 WAL 不可靠，建议探针与页面同机、由 systemd 分别守护两个 unit）。

### 反向代理与 TLS

**页面必须是 HTTPS**：页面是 https 时，浏览器会直接拒绝 http 的探测请求
（混合内容），IPv4/IPv6 与上报都会失败。示例见 `deploy/nginx.conf.example`。

采集端必须拿到**真实客户端地址**，否则出口判定全部失真：

- 采集端与员工直连 → 保持 `trust_forwarded_for = false`（默认）。
- 采集端在反向代理之后 → 打开 `trust_forwarded_for`，并把代理出口写进
  `trusted_proxies`。程序只从右往左跳过可信代理，客户端自带伪造的
  `X-Forwarded-For` 不会被采信。

## 4. 判定原理与局限

**为什么 DNS 要单独看解析器出口。**
浏览器自己不查 DNS，它把查询交给系统 → 公司 DNS/运营商 DNS → 递归解析器。
所以探针看到的是**递归解析器**的出口地址。若解析器是 8.8.8.8，出口就是
Google 的地址；若解析器是公司 DNS，出口就是公司出口。这正是"DNS 是否走隧道"
的真实体现。

**加密 DNS（DoH/DoT）会让 DNS 项变成「无法判定」。**
浏览器开启"安全 DNS"后直接连公共解析器，探测域名根本不会被本地解析。页面
不会因此显示「正常」，而是提示关闭安全 DNS 或改用公司 DoH——这是有意为之，
把不确定说成安全比误报更危险。

**WebRTC 的自报数据如何处理。**
候选地址由页面脚本上报，理论上可伪造，但地址是浏览器在真实 UDP 交互中从
STUN 服务拿到的，因此仍具参考价值。私有地址和 mDNS 名称（`*.local`）不算
"真实地址泄露"，只在说明里列出。

**出口表可能是最好与最坏的一环。** 公司出口若经常变化（多线路、云上弹性
IP），出口表会漂移，造成误报/漏报。建议把出口表纳入网络组变更流程，并在页面
上用明显的警告提示"出口表仍是示例地址"。

**已明确不做的事**：不读 Cookie/localStorage/文件，不收集任何身份信息，不做
速率以外的流量分析，不把探测结果与员工身份关联（会话随机、15 分钟后自毁）。

## 5. 端点一览

采集端（默认 8090）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/probe/ip` | 返回对端地址；`?s=<会话>` 时记录观测 |
| GET | `/probe/pixel.gif` | 1×1 透明图，供 `<img>` 降级探测 |
| GET | `/probe/client.js` | 浏览器探测脚本（静态资源） |
| POST | `/probe/report` | 接收 WebRTC/时序上报，校验 `Origin` 与会话 |
| GET | `/healthz` | 健康检查 |

DNS 探针：`<会话标识><两位序号>.<zone>` 的 A/AAAA 查询，权威应答、TTL=0。
STUN：端口池内每个端口归属一个会话，只应答 Binding 请求。

所有 HTTP 响应带 `Cache-Control: no-store`；上报体上限 64 KiB；DNS/STUN/HTTP
都按来源地址做令牌桶限流。

## 6. 数据与隐私

- 会话标识是 128 位随机数，仅存在于服务端，不写 Cookie，不与账号绑定。
- 只保存判定所需字段：来源地址、探测类型、时间戳、简短明细。
- 会话 `session_ttl_seconds`（默认 15 分钟）后连同其观测、上报、STUN 端口
  一起删除；页面每次加载都会触发一次过期清理。
- 日志默认 `INFO`，不记录完整查询名（只有 `DEBUG` 级别才可能有明细）。
