# ========================================================
# SafeX Multi-Stage Production Container
# ========================================================

FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/root/.local/bin:$PATH \
    PYTHONPATH=/app

COPY --from=builder /root/.local /root/.local
COPY safex/ ./safex/
COPY safex_cli.py .
COPY pyproject.toml .

# Security: Non-root user
RUN addgroup --system --gid 1001 safexgroup && \
    adduser --system --uid 1001 --gid 1001 safexuser && \
    chown -R safexuser:safexgroup /app

USER safexuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

CMD ["python", "-m", "uvicorn", "safex.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
