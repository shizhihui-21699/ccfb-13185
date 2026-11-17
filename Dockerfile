# 单机部署：探针与 Streamlit 同容器（probes.mode = "embedded"）。
# 需要对外暴露：Streamlit 页面端口、采集端 HTTP、DNS 53、STUN 端口池。
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    VPNCHECK_CONFIG=/data/config.toml

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY vpncheck ./vpncheck
COPY app.py ./
COPY scripts ./scripts
COPY config.example.toml ./

# 运行期间挂载 /data，放 config.toml 与 SQLite 数据
RUN mkdir -p /data && useradd --create-home --uid 10001 vpncheck \
    && chown -R vpncheck:vpncheck /data /app
USER vpncheck

EXPOSE 8501/tcp 8090/tcp 53/udp 53/tcp 3478/udp

# 探针端口池（3478 之外）由配置决定，compose 里按需映射
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=2)"

CMD ["streamlit", "run", "app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
