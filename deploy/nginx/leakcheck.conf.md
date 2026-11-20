# 反向代理配置（nginx）

Streamlit 和采集端跑在同一台机器上，由 nginx 统一对外提供 HTTPS：

- `/`        → Streamlit（8501），员工打开的自检页
- `/api/`、`/px.gif`、`/px.png`、`/probe.html`、`/healthz` → 采集端（8081）

两个要点：

1. **HTTPS 是硬性要求**。WebRTC 只在安全上下文可用；用 `http://` 打开时该通道会显示「无法判定」，
   而不是「通过」——但那就丢掉了最能暴露泄露的证据。
2. **不要改写客户端地址**。采集端的判定完全依赖 TCP 对端地址，因此这里传 `X-Real-IP` 并把
   代理网段写进 `server.trusted_proxies`；若再套一层 CDN/LB，请把那一层的网段也加进去。

DNS 与 STUN 不走这里：它们需要独立监听 53/TCP+UDP 与 STUN 的 UDP 端口。

```nginx
# /etc/nginx/conf.d/leakcheck.conf
upstream leakcheck_streamlit { server 127.0.0.1:8501; keepalive 16; }
upstream leakcheck_collector { server 127.0.0.1:8081; keepalive 16; }

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name leakcheck.example-corp.net;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name leakcheck.example-corp.net;

    ssl_certificate     /etc/ssl/certs/leakcheck.crt;
    ssl_certificate_key /etc/ssl/private/leakcheck.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # 自检页体积很小；限制请求体，探针最多发 16KB JSON。
    client_max_body_size 32k;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # 自检页需要 WSS / 内联脚本（Streamlit 与探针都依赖内联 JS）。
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://leakcheck.example-corp.net; frame-ancestors 'self'" always;

    # 采集端：探针调用的 API 与像素图。把真实客户端地址原样传下去。
    location ~ ^/(api/|px\.(gif|png)$|probe\.html$|healthz$) {
        proxy_pass http://leakcheck_collector;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 15s;
    }

    # Streamlit：需要 WebSocket 升级。
    location / {
        proxy_pass http://leakcheck_streamlit;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host       $host;
        proxy_set_header X-Real-IP  $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_read_timeout 86400s;
    }
}
```

## 若 Streamlit 与采集端分域部署

把 `server.allowed_origins` 改成显式来源列表，例如：

```yaml
server:
  public_base_url: https://collector.example-corp.net
  allowed_origins:
    - https://leakcheck.example-corp.net
```

探针的 `apiBase` 来自 `public_base_url`，跨域请求由采集端的 CORS 中间件放行；
配置成 `["*"]` 虽然可用，但会把采集端变成任何页面都能写入观测的目标。

## 防火墙清单

| 端口 | 协议 | 用途 | 来源 |
| --- | --- | --- | --- |
| 443 | TCP | 自检页 + 采集端 | 员工所在网络 |
| 53 | UDP + TCP | 权威 DNS 探针 | 公网（递归解析器） |
| `stun.ports` | UDP | STUN / WebRTC 出口观测 | 员工所在网络 |

STUN 端口段需要与 `config.yaml` 里的 `stun.ports` 保持一致——端口数量决定可同时自检的人数，
每个会话独占一个端口。
