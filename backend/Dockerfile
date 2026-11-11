# TrustVault API + static frontend. Build context is the project root (see docker-compose.yml).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FRONTEND_DIR=/app/frontend

RUN groupadd --system --gid 10001 tv && useradd --system --uid 10001 --gid tv --home-dir /app --shell /usr/sbin/nologin tv

WORKDIR /app/backend
COPY backend/requirements.txt ./
# Every package is checked against the SHA-256 hashes in requirements.txt; a mismatch aborts the build.
RUN pip install --require-hashes --no-deps -r requirements.txt && \\\n    pip install --no-cache-dir 'psycopg[binary]==3.2.9'

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
RUN rm -rf /app/backend/data /app/backend/.env /app/backend/db.env && mkdir -p /app/data && chown tv:tv /app/data

USER tv
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=4s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-server-header"]
