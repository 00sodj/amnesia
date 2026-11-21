FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AMNESIA_DB=/data/amnesia.db \
    AMNESIA_AUDIT=/data/audit/memory.jsonl

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies

RUN pip install --no-cache-dir ".[server]" \
    && useradd --create-home --shell /usr/sbin/nologin amnesia \
    && mkdir -p /data/audit \
    && chown -R amnesia:amnesia /data

USER amnesia

ENTRYPOINT ["amnesia-server"]
