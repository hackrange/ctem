FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    libldap2-dev \
    libsasl2-dev \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first (better layer caching)
COPY requirements.txt .
# The base image's pip has published advisories; the app never runs pip, but what ships should be current
RUN pip install --no-cache-dir --upgrade "pip>=25.3" && pip install --no-cache-dir -r requirements.txt

# App source
COPY api/ ./api/

# Non-root user. The code stays owned by root and read-only to it, so nothing running in the app can rewrite it; it
# writes only to the spool (group root, so -g root) and temp space
RUN useradd -r -u 1000 -g root ctem
USER ctem

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Forwarded headers are read by the app, and only from the reverse proxy (api/core/trusted_proxy.py), not by uvicorn
# from any peer
ENV TRUSTED_PROXY_HOST=nginx
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--no-proxy-headers"]
