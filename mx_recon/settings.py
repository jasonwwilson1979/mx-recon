"""
MX-RECON Django settings — hardened, environment-driven, database-free.

The scanner is stateless (no models), so no database is configured. Every
deployment knob is exposed via DJANGO_* environment variables so the same
image runs in development, in Docker, and behind a reverse proxy in Portainer.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_bool(name: str, default: str = "false") -> bool:
    return env(name, default).lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)))
    except ValueError:
        return default


# ---------------------------------------------------------------- security core
SECRET_KEY = env("DJANGO_SECRET_KEY") or ("ephemeral:" + secrets.token_urlsafe(48))
DEBUG = env_bool("DJANGO_DEBUG", "false")

ALLOWED_HOSTS = [h for h in (x.strip() for x in env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")) if h]
CSRF_TRUSTED_ORIGINS = [o for o in (x.strip() for x in env("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",")) if o]

# Set True only when running behind a reverse proxy (Nginx Proxy Manager, Traefik, Caddy…)
TRUST_PROXY = env_bool("DJANGO_TRUST_PROXY", "false")
if TRUST_PROXY and env("DJANGO_PROXY_SSL_HEADER", "true").lower() in ("1", "true", "yes", "on"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ---------------------------------------------------------------- applications
INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "scanner",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "mx_recon.middleware.HardeningHeadersMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "mx_recon.urls"
WSGI_APPLICATION = "mx_recon.wsgi.application"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": []},
    },
]

# The scanner is stateless — no database, no sessions, no admin.
DATABASES = {}

# ---------------------------------------------------------------- hardening
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True  # token is read from the hidden form input, not JS cookies
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_AGE = 60 * 60 * 12

# HTTPS posture — enable via env when TLS terminates in front of the container.
SECURE_SSL_REDIRECT = env_bool("DJANGO_SSL_REDIRECT", "false")
SECURE_HSTS_SECONDS = env_int("DJANGO_HSTS_SECONDS", 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_HSTS_SUBDOMAINS", "false")
SECURE_HSTS_PRELOAD = env_bool("DJANGO_HSTS_PRELOAD", "false")
if not DEBUG:
    _cookie_secure = env_bool("DJANGO_COOKIE_SECURE", "false")
    SESSION_COOKIE_SECURE = _cookie_secure
    CSRF_COOKIE_SECURE = _cookie_secure

MX_RECON_CSP = env(
    "DJANGO_CSP",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' "
    "https://fonts.googleapis.com; font-src https://fonts.gstatic.com 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'",
)

# ---------------------------------------------------------------- scanner tuning
MX_RECON_RATE_LIMIT = env_int("DJANGO_RATE_LIMIT", 30)        # scans per window per IP
MX_RECON_RATE_WINDOW = env_int("DJANGO_RATE_WINDOW", 300)     # window seconds
MX_RECON_MAX_QUERIES = env_int("DJANGO_MAX_QUERIES", 350)     # hard cap per scan
MX_RECON_DEADLINE = float(env("DJANGO_DEADLINE", "30"))       # hard wall-clock cap (s)
MX_RECON_DNS_TIMEOUT = float(env("DJANGO_DNS_TIMEOUT", "3"))  # per-nameserver timeout (s)
MX_RECON_DNS_LIFETIME = float(env("DJANGO_DNS_LIFETIME", "6"))  # total query lifetime (s)
# Public resolvers used only to retry reverse (PTR) lookups when the system
# resolver returns no data — Docker/cloud resolvers often do not answer
# in-addr.arpa queries at all. Set DJANGO_DNS_FALLBACK="" to disable.
MX_RECON_DNS_FALLBACK = [ns.strip() for ns in env("DJANGO_DNS_FALLBACK", "1.1.1.1,8.8.8.8").split(",") if ns.strip()]
# Resolver the UI offers by default, plus optional custom entries:
#   DJANGO_RESOLVERS_EXTRA="internal|Internal DNS 10.0.0.53|10.0.0.53"
MX_RECON_RESOLVER_DEFAULT = env("DJANGO_RESOLVER_DEFAULT", "system")
MX_RECON_RESOLVERS_EXTRA = env("DJANGO_RESOLVERS_EXTRA", "")
# RBL zones to skip, comma-separated zone names — e.g. if a list misbehaves on
# your resolver: DJANGO_RBL_DISABLED="dnsbl.sorbs.net,dnsbl-1.uceprotect.net"
MX_RECON_RBL_DISABLED = env("DJANGO_RBL_DISABLED", "")
# Add your own blacklist zones. IP zones are queried as <reversed-ip>.<zone>,
# domain zones as <domain>.<zone>; format "zone|Label|url" (label and url are
# optional, separate multiple zones with ';'):
#   DJANGO_RBL_EXTRA_IP="zen.example.net|Example IP RBL|https://example.net/rbl"
#   DJANGO_RBL_EXTRA_DOMAIN="dbl.example.net|Example Domain RBL"
MX_RECON_RBL_EXTRA_IP = env("DJANGO_RBL_EXTRA_IP", "")
MX_RECON_RBL_EXTRA_DOMAIN = env("DJANGO_RBL_EXTRA_DOMAIN", "")
# Domain-control module: RDAP (modern WHOIS over HTTPS) lookup + NS/SOA/DNSSEC
# analysis. Set DJANGO_WHOIS=false to skip the outbound HTTPS lookup.
MX_RECON_WHOIS = env_bool("DJANGO_WHOIS", "true")
MX_RECON_WHOIS_TIMEOUT = float(env("DJANGO_WHOIS_TIMEOUT", "6"))
# Shown in the topbar ("BUILD vX.Y.Z") and in the boot log, so a stale deploy
# or a cached page is obvious at a glance.
MX_RECON_VERSION = env("DJANGO_VERSION", "3.11.0")

# ---------------------------------------------------------------- static files
STATIC_URL = "/static/"
# Static assets live in the app package (scanner/static/...) and are discovered
# by the app-directories finder; no extra STATICFILES_DIRS entry is needed.
STATIC_ROOT = BASE_DIR / "staticfiles"
# Production serves compressed, content-hashed assets via Whitenoise; the
# Dockerfile runs collectstatic at build time to produce the manifest.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
        if not DEBUG
        else "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}
WHITENOISE_USE_FINDERS = DEBUG
WHITENOISE_AUTOREFRESH = DEBUG

# ---------------------------------------------------------------- cache (rate limiting)
_cache_dir = env("DJANGO_CACHE_DIR") or str(BASE_DIR / "var" / "cache")
os.makedirs(_cache_dir, exist_ok=True)
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": _cache_dir,
        "TIMEOUT": 600,
        "OPTIONS": {"MAX_ENTRIES": 10000},
    }
}

USE_TZ = True
