# DNS 委派：让探针域名真正到达本服务

DNS 出口检测的整个前提是：员工浏览器解析 `<token>-xxxx.probe.example-corp.net` 时，
**递归解析器必须来问我们**。这需要把探针域名委派给本服务运营的权威 DNS。

选一个**独立的子域**（例如 `probe.example-corp.net`），不要用主域，也不要和办公网真实域名混用：
探针区只回答随机令牌子域，其它查询一律 REFUSED。

## 1. 准备两台（或一台）权威服务器

`config.yaml` 的 `dns.answer_ipv4` 是探针子域返回的地址，建议填一个你能记录访问的 Web 地址，
这样即使页面只发了 HTTPS 请求也能多一条 TCP 级证据。

```
ns1.probe.example-corp.net.  A    203.0.113.10
ns1.probe.example-corp.net.  AAAA 2001:db8::10
```

> 只部署一台也可以，但公网递归解析器对单点故障很敏感。至少要有一台独立公网 IP，
> 且 53/TCP 与 53/UDP 都要放行（大响应与部分解析器只走 TCP）。

## 2. 在主域里加 NS 委派记录

```zone
; example-corp.net 区域文件
probe.example-corp.net.       3600  IN  NS  ns1.probe.example-corp.net.
probe.example-corp.net.       3600  IN  NS  ns2.probe.example-corp.net.

; 胶水记录（如果 ns1 在本域下，必须提供，否则解析器无法找到权威服务器）
ns1.probe.example-corp.net.   3600  IN  A    203.0.113.10
ns1.probe.example-corp.net.   3600  IN  AAAA 2001:db8::10
```

若用公共 DNS 托管商（Cloudflare / Route53 / 阿里云 DNS 等），在托管控制台添加
`probe` 子域的 **NS 记录**，并在本服务所在 DNS 托管商那里添加 `ns1` 的 A/AAAA 记录。

## 3. 验证委派真的生效

```bash
# 直接问权威服务器：必须返回 SOA（说明服务在跑、区名一致）
dig @203.0.113.10 probe.example-corp.net SOA +short

# 从公共递归解析器问：必须能拿到 NOERROR 与 SOA，且 ANSWER 来自我们的权威服务器
dig @1.1.1.1 probe.example-corp.net SOA

# 端到端：造一个合法令牌的查询，确认服务端记录了观测
TOKEN=$(python -m leakcheck -c config.yaml export-token)
dig @1.1.1.1 "$TOKEN-abc123sys1.probe.example-corp.net" A +short
python -m leakcheck -c config.yaml export "$TOKEN"
```

第三步里 `dig` 的输出应当是 `203.0.113.10`（`answer_ipv4`）。随后 `export` 里应当出现一条
`channel=dns`、`source_ip` 为**解析器地址**的观测——这个地址就是我们要判定的 DNS 出口。

## 4. 常见部署形态与判定差异

| 形态 | 员工侧看到的现象 | 服务端观测 | 判定 |
| --- | --- | --- | --- |
| 全局 VPN + 内网递归解析器 | 解析正常 | 递归解析器的公网出口在本公司 `corp_resolvers` 清单内 | 通过 |
| 全局 VPN，但解析器对探针域名做本地应答 | 解析正常（拿到伪造/内网地址） | **没有任何观测** | 无法判定（不是通过） |
| 分流 VPN，DNS 未走隧道 | 解析正常 | 来自本地 ISP / 公共解析器地址 | 疑似泄露 |
| 浏览器启用 DoH | 解析正常 | 来自 Google/Cloudflare DoH 出口，或完全没有观测 | 疑似泄露 / 无法判定 |
| 解析器转发 ECS | 解析正常 | 观测里带 `ecs` 字段 | 疑似泄露（客户端网段被上游看到） |

## 5. 为什么 split-horizon 不是「通过」

如果内网 DNS 对 `*.probe.example-corp.net` 直接返回本地答案，我们的权威服务器永远收不到查询。
这种情况下**好消息**是解析确实在隧道内完成，**坏消息**是我们没有证据证明这一点——
它和「浏览器 DoH 把解析送到了公网」在观测上完全一样。

因此判定页把它记为「无法判定」，并在修复建议里提示关闭 DoH 后复测；
如果你们的 DNS 团队希望得到确定性结论，可以在内网解析器上为探针域名配置**转发**
（conditional forwarder）到本服务的 53 端口，这样既保留 split-horizon 又留下证据。
