# MX-RECON — production container image
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=mx_recon.settings

# non-root runtime user
RUN groupadd -r mx-recon && useradd -r -g mx-recon -d /app -s /usr/sbin/nologin mx-recon

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY manage.py .
COPY mx_recon/ mx_recon/
COPY scanner/ scanner/

# collect static assets into STATIC_ROOT at build time (Whitenoise serves them)
RUN python manage.py collectstatic --noinput \
    && mkdir -p /app/var/cache \
    && chown -R mx-recon:mx-recon /app

USER mx-recon

EXPOSE 8000

# The container always listens on 8000 internally; the published host port is
# chosen by MX_RECON_PORT in docker-compose.yml (default 583).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status==200 else 1)"

# DJANGO_SECRET_KEY / DJANGO_ALLOWED_HOSTS etc. come from the environment
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:8000 --workers 3 --threads 4 --timeout 90 --access-logfile - --error-logfile - mx_recon.wsgi:application"]
