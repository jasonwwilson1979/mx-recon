"""WSGI entrypoint — served by Gunicorn in the container image."""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mx_recon.settings")

application = get_wsgi_application()
