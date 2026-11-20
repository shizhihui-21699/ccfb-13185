# VPN 流量泄露自检站

员工出差连上公司 VPN 后，打开一个网页就能知道**自己的流量是否真的走了隧道**：
网页请求从哪个出口发出、DNS 解析是谁代答的、WebRTC/UDP 有没有从本地网络直出、IPv6 有没有绕过隧道。
结果会对照公司出口地址清单判为「通过 / 无法判定 / 需注意 / 疑似泄露」，并按员工的操作系统给出对应的修复建议。

```
                    ┌──────────────────────────────────────────────┐
   员工浏览器 ──────▶│ Streamlit 自检页 + 内嵌浏览器探针            │
   (已连 VPN)        └───────────────┬──────────────────────────────┘
                                     │  ① HTTP/像素请求（TCP 出口）
                                     │  ② 解析 *.probe.(公司域)（DNS 出口）
                                     │  ③ WebRTC → STUN（UDP 出口）
                                     ▼
   ┌─────────────────────┬───────────────────────┬──────────────────────┐
   │ FastAPI 采集端 :8081│ 权威 DNS 探针 :53     │ STUN 探针 UDP 端口池 │
   └─────────┬───────────┴───────────┬───────────┴──────────┬───────────┘
             └───────────────┬───────┴──────────────────────┘
                             ▼
                     SQLite（WAL，三进程共用）
                             ▼
                  判定引擎（对照出口地址清单）→ 修复建议
```

## 检测原理（以及为什么必须这样检测）

| 通道 | 怎么观测 | 能发现什么 |
| --- | --- | --- |
| **网页出口** | 浏览器向采集端请求像素图与上报接口，服务端记录 **TCP 对端地址** | TCP/HTTPS 是否走了隧道 |
| **DNS 出口** | 浏览器解析随机子域 `*.probe.公司域`；该域的**权威服务器**由本服务运营，记录**递归解析器**的源地址 | DNS 是否走公司解析器、是否被 DoH 劫持、是否转发 ECS 泄露客户端网段 |
| **UDP 出口** | 浏览器用 WebRTC 向本服务的 STUN 端口发 UDP，服务端记录 **UDP 对端地址**；页面再上报它看到的候选地址 | UDP 是否绕过隧道（分流规则最常见的漏洞） |
| **IPv6** | 从上面三类观测中筛出 IPv6 地址，并结合浏览器报告的 IPv6 候选 | IPv6 是否走了隧道之外的路径 |
| **一致性** | 比对各通道的出口是否同属公司地址 | 分流规则只覆盖了部分协议 |

**为什么需要权威 DNS 服务器**：网页无法知道「是谁替我解析的域名」。
只有让解析请求真正到达我们运营的权威服务器，服务端才能看到递归解析器的出口地址。

**「无法判定」是刻意的**：没有任何观测时不会判为「通过」。内网 split-horizon 解析器
对探针域名做本地应答，和浏览器把解析送到公共 DoH，在观测上完全一样——两者都不能算证据。
判定页会说明原因并给出取得证据的办法。

## 快速开始（本地跑通）

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp config.example.yaml config.yaml
# 至少修改：site.probe_domain、exit_inventory.vpn_egress.addresses、server.hmac_secret

python -m leakcheck -c config.yaml check        # 校验配置并打印生效的出口清单
python -m leakcheck -c config.yaml selftest     # 用合成流量验证 DNS/STUN 监听器
python -m leakcheck -c config.yaml all          # 采集端 + DNS + STUN（前台运行）

# 另一个终端
LEAKCHECK_CONFIG=config.yaml python -m streamlit run leakcheck/app.py
```

打开 <http://127.0.0.1:8501>。也可直接访问采集端自带的独立版页面
<http://127.0.0.1:8081/probe.html>（无 Streamlit 依赖，便于排障）。

没有公网域名也能验证探针链路：见 `scripts/e2e_browser.py`，它用真实 Chromium
配合一个 SOCKS5 远程 DNS 代理，把四个通道全部跑通并检查服务端记录。

## 生产部署

推荐四个 systemd 单元（见 `deploy/systemd/`）：

| 单元 | 说明 |
| --- | --- |
| `leakcheck-collector` | FastAPI 采集端，监听 127.0.0.1:8081，由 nginx 反代 |
| `leakcheck-dns` | 权威 DNS 探针，53/udp + 53/tcp，需要公网可达 |
| `leakcheck-stun` | STUN 探针，占一组 UDP 端口（每会话一个） |
| `leakcheck-web` | Streamlit 页面，监听 127.0.0.1:8501 |

配套文件：

- `deploy/nginx/leakcheck.conf.md` —— HTTPS 反代、CSP、`X-Real-IP` 传递、防火墙清单
- `deploy/DNS-DELEGATION.md` —— 探针域名的 NS 委派与验证步骤（**部署前必读**）
- `deploy/docker-compose.yml` + `Dockerfile` —— 小规模自建可用单容器（`network_mode: host`）

必须做的三件事：

1. **委派探针域名**到本服务的 DNS 探针，否则 DNS 通道永远是「无法判定」。
2. **填对出口清单**。`exit_inventory.vpn_egress` 为空时服务拒绝启动——空清单会把所有流量判成泄露。
3. **固定 `hmac_secret`**（配置或 `LEAKCHECK_HMAC_SECRET`）。缺失时会用临时密钥，进程重启后旧令牌全部失效。

## 判定规则

| 观测到的地址属于 | 结论 |
| --- | --- |
| VPN 出口 / 公司解析器出口 | 通过 |
| 内网 / 回环 / 链路本地 | 通过（说明在隧道内） |
| 办公网直出 | 需注意（在办公区正常，外部网络即为未进隧道） |
| 已知公共解析器（DNS 通道） | 疑似泄露（通常是浏览器「安全 DNS」） |
| 其它公网地址 | 疑似泄露 |
| 解析请求携带 EDNS Client Subnet | 疑似泄露（真实网段被上游看到） |
| 没有观测 | 无法判定 |

同一个公网前缀既用于 VPN 也用于解析器出口时，DNS 通道优先匹配解析器清单、其它通道优先匹配 VPN 清单
（`verdict.classify(..., channel=...)`）。这样 NAT 复用同一地址段不会造成误判。

## 隐私与数据

- 不记录姓名、账号、内网 URL；会话令牌是 HMAC 签名的随机值，只用于关联本次观测。
- 数据保留 7 天（`python -m leakcheck purge --days 7`，可放进 cron）。
- 采集端不信任页面传来的任何地址：报告里的地址全部来自内核给出的对端地址或 DNS/STUN 监听器。
- 合规提示：DNS 探针会看到**递归解析器的出口地址**，属于网络侧元数据，不涉及内容。
  若公司有员工监控告知要求，请在自检页上说明（页面默认已写明「数据仅用于本次判断」）。

## 测试

```bash
.venv/bin/python -m pytest -q            # 90 个单元/协议/渲染测试，约 7 秒
.venv/bin/python scripts/e2e_browser.py  # 真实浏览器端到端（需 playwright + chromium）
```

覆盖范围：

- `tests/test_verdict.py` —— 每条判定路径，包括「没有数据不能判通过」与 NAT 复用同一网段
- `tests/test_core.py` —— 令牌签名/过期/伪造、配置校验、SQLite 并发写入、STUN 端口分配
- `tests/test_servers.py` —— 真实 socket 上的 DNS（UDP/TCP/EDNS/ECS/伪造令牌）与 STUN（含 RFC 5769 指纹校验）
- `tests/test_collector.py` —— 会话、像素探针、CORS、限速、上报清洗
- `tests/test_app_render.py` —— 用 Streamlit `AppTest` 跑真实 `app.py`：泄露/通过/无数据三种界面，
  以及「采集完成后停止轮询」与「配置路径变了不能复用旧数据库」
- `scripts/e2e_browser.py` —— Chromium + SOCKS5 远程 DNS，四个通道全通

## 目录

```
leakcheck/
  config.py      配置模型与校验（失败信息直接可读）
  tokens.py      HMAC 签名会话令牌（DNS 标签安全）
  netutil.py     IP 分类（跨 Python 版本行为一致）
  storage.py     SQLite 存储，三进程共享
  dnsserver.py   权威 DNS 探针（UDP/TCP、EDNS、ECS 回显）
  stunserver.py  STUN 探针（RFC 5389，按端口归因会话）
  collector.py   FastAPI 采集端
  frontend.py    浏览器探针（内嵌 iframe + 独立版页面）
  verdict.py     判定引擎
  remediation.py 分操作系统修复建议
  app.py         Streamlit 界面
  cli.py         运维入口（all/collector/dns/stun/selftest/check/export/purge）
```

## 已知限制

- **每个会话独占一个 STUN 端口**：STUN 报文没有会话标识，端口是唯一的归因依据。
  端口池大小 = 可同时自检人数；超出时复用最旧会话的端口（归因精度下降，不影响正确性）。
- **WebRTC 需要 HTTPS**：`http://` 打开时该通道显示「无法判定」。
- **split-horizon 解析器**除非配了条件转发，否则观测不到（判定为「无法判定」，不是「通过」）。
- 浏览器扩展（uBlock 等）可能拦截像素请求；判定页会提示用独立标签页复测。
