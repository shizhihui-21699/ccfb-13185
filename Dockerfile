# 单容器：采集端 + DNS 探针 + STUN 探针 + Streamlit。
# 生产推荐按 deploy/systemd/ 拆成四个单元，以便 DNS/STUN 用独立权限与独立公网入口；
# 这个镜像适合小规模自建或先在测试环境跑通。
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/leakcheck

COPY pyproject.toml README.md ./
COPY leakcheck ./leakcheck
COPY config.example.yaml ./

RUN pip install --no-cache-dir . \
    && useradd --system --home /var/lib/leakcheck --create-home leakcheck \
    && mkdir -p /var/lib/leakcheck && chown -R leakcheck:leakcheck /var/lib/leakcheck

USER leakcheck
ENV LEAKCHECK_CONFIG=/etc/leakcheck/config.yaml

EXPOSE 8081 8501 53/udp 53/tcp 3478-3489/udp
VOLUME ["/var/lib/leakcheck"]

CMD ["python", "-m", "leakcheck", "all"]
