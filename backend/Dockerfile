# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for psycopg2, python3-saml (xmlsec1), etc.
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    pkg-config \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN groupadd -r auditgraph && useradd -r -g auditgraph -d /app -s /sbin/nologin auditgraph \
    && chown -R auditgraph:auditgraph /app

# Environment
ENV APP_ENV=prod
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

USER auditgraph

# Run with gunicorn — 2 workers, 120s timeout, preload to avoid DDL deadlock
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "--preload", "--access-logfile", "-", "wsgi:app"]
