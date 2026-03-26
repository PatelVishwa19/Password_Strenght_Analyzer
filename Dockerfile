# ─────────────────────────────────────────────────────────────────
# Password Strength Analyzer — Dockerfile
# Multi-stage build: keeps final image lean and secure
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: Build dependencies ──────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Production image ────────────────────────────────────
FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app.py          ./app.py
COPY templates/      ./templates/
COPY static/         ./static/

# Ensure non-root ownership
RUN chown -R appuser:appuser /app

USER appuser

# Expose internal port (Nginx will proxy to this)
EXPOSE 8000

# Environment defaults — override in docker-compose or kubernetes
ENV FLASK_DEBUG=false \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Production server: Gunicorn with 4 workers
# Workers = (2 × CPU cores) + 1  →  adjust to your server
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--timeout", "30", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "warning", \
     "app:app"]
