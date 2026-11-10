"""Additional response-hardening middleware (CSP + Permissions-Policy)."""
from django.conf import settings


class HardeningHeadersMiddleware:
    """Attach Content-Security-Policy and Permissions-Policy to every response.

    The MX-RECON UI keeps its stylesheet inline (style-src 'unsafe-inline'), but all
    JavaScript is served as an external static file, so `script-src 'self'`
    holds without weakening script execution policy.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if settings.MX_RECON_CSP:
            response.headers.setdefault("Content-Security-Policy", settings.MX_RECON_CSP)
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response
