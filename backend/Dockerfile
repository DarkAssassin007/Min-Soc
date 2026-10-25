# Mini SOC backend image (API + pipeline + ML inference).
#
# The container runs the same runtime the desktop deployment uses:
# collectors -> pipeline -> detection -> alerts -> SQLite, plus the REST/WS API.
# Live packet capture is disabled by default (containers cannot see host
# interfaces without extra privileges); enable the syslog/API/simulator
# collectors instead, or run with --network host and NET_RAW/NET_ADMIN caps.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# libpcap is required by scapy even when capture is disabled (import time).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend/ backend/
COPY ml/ ml/
COPY detection-rules/ detection-rules/
COPY .env.example .env

ENV MINI_SOC_HOME=/data \
    MINI_SOC_DATABASE_URL=sqlite+pysqlite:////data/mini_soc.db \
    MINI_SOC_RULES_PATH=/app/detection-rules \
    MINI_SOC_COLLECTOR_NETWORK_ENABLED=false \
    MINI_SOC_COLLECTOR_SYSLOG_ENABLED=true \
    MINI_SOC_COLLECTOR_SYSTEM_ENABLED=false \
    MINI_SOC_HOST=0.0.0.0 \
    MINI_SOC_PORT=8000

VOLUME ["/data"]
EXPOSE 8000

WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
