FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# 53/udp+tcp: 权威 DNS；8000: 探针 API；8501: Web 页面
EXPOSE 53/udp 53/tcp 8000 8501

CMD ["python", "main.py"]
