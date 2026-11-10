"""ASGI entrypoint (kept for future async/SSE upgrades)."""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mx_recon.settings")

application = get_asgi_application()
