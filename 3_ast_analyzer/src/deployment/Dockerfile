FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY src/deployment/requirements.txt ./requirements.txt
RUN python -m pip wheel --wheel-dir /wheelhouse -r requirements.txt

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    JOB_DB_PATH=/data/jobs.sqlite3 \
    FEEDBACK_PATH=/data/false_positive_feedback.jsonl

RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 autoforge \
    && useradd --system --uid 10001 --gid autoforge --home-dir /app autoforge \
    && mkdir -p /app /data \
    && chown -R autoforge:autoforge /app /data

COPY --from=builder /wheelhouse /wheelhouse
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse \
    fastapi httpx prometheus-client psutil tree-sitter tree-sitter-language-pack "uvicorn[standard]" \
    && rm -rf /wheelhouse

WORKDIR /app
COPY --chown=autoforge:autoforge src ./src

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "src.deployment.webhook_app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
