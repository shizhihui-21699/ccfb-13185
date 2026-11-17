"""VPN 泄露自检服务。

模块划分：

* :mod:`vpncheck.config`      配置加载与校验
* :mod:`vpncheck.nets`        公司出口地址表与 IP 分类
* :mod:`vpncheck.clientip`    客户端地址还原（含可信代理下的 XFF 处理）
* :mod:`vpncheck.store`       会话与观测存储（SQLite，带 TTL）
* :mod:`vpncheck.dns_probe`   授权探针 DNS 服务
* :mod:`vpncheck.stun`        最小 STUN 服务（按会话分配 UDP 端口）
* :mod:`vpncheck.collector`   HTTP 采集端（探针接口 + 上报接口）
* :mod:`vpncheck.analysis`    结果关联与判定
* :mod:`vpncheck.guidance`    各操作系统修复建议
* :mod:`vpncheck.client_js`   浏览器端探测脚本（由采集端静态提供）
* :mod:`vpncheck.probe_page`  页面注入片段（引导加载脚本）
* ``app.py``                  Streamlit 页面
"""

__version__ = "1.0.0"
