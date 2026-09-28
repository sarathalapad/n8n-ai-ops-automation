# Build from the repository root:  docker build -f service/Dockerfile .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPSGUARD_AUDIT_PATH=/data/audit.jsonl

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY service/opsguard ./opsguard

# Run as an unprivileged user; only the audit volume is writable.
RUN useradd --system --uid 10001 opsguard && mkdir -p /data && chown opsguard /data
USER opsguard
VOLUME ["/data"]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "opsguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
