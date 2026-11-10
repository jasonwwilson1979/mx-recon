"""MX-RECON HTTP layer — UI, JSON scan API, resolver probe, healthcheck."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST

from . import rblcheck
from .diagnostics import Diagnoser
from .engine import DnspythonBackend, Engine
from .ratelimit import check_rate_limit
from .resolvers import as_list, nameservers_for
from .validators import DomainValidationError, validate_domain, validate_selector

# 128 KB of pasted headers is far more than any real message needs.
MAX_DIAGNOSE_BYTES = 128 * 1024
# Each resolver self-test costs four lookups; cap how many we will run at once.
MAX_RBL_CHECK_RESOLVERS = 10


@never_cache
def index(request):
    """Serve the MX-RECON console UI.

    Never cached, so layout/UI changes appear as soon as the container is
    redeployed instead of being masked by a stale page in the browser. The
    version marker in the topbar identifies the running build.
    """
    return render(request, "scanner/index.html", {"version": settings.MX_RECON_VERSION})


def _client_ip(request) -> str:
    """Client IP for rate limiting. X-Forwarded-For is honoured only when
    DJANGO_TRUST_PROXY is enabled (i.e. the request came through our proxy)."""
    if settings.TRUST_PROXY:
        xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or "unknown"


@require_GET
def api_resolvers(request):
    """Resolver choices the UI may offer (a server-side allow-list)."""
    return JsonResponse({
        "default": settings.MX_RECON_RESOLVER_DEFAULT,
        "resolvers": as_list(settings.MX_RECON_RESOLVERS_EXTRA, settings.MX_RECON_RESOLVER_DEFAULT),
    })


def _validated_resolver(raw, default: str = "") -> str:
    """Return an allow-listed resolver id or raise DomainValidationError."""
    resolver_id = (str(raw or "").strip().lower()) or default or settings.MX_RECON_RESOLVER_DEFAULT
    try:
        nameservers_for(resolver_id, settings.MX_RECON_RESOLVERS_EXTRA)
    except ValueError as exc:
        raise DomainValidationError(str(exc)) from exc
    return resolver_id


def _backend_for(resolver_id: str):
    """Build a DNS backend for an allow-listed resolver id."""
    nameservers, label = nameservers_for(resolver_id, settings.MX_RECON_RESOLVERS_EXTRA)
    return DnspythonBackend(
        timeout=settings.MX_RECON_DNS_TIMEOUT,
        lifetime=settings.MX_RECON_DNS_LIFETIME,
        nameservers=nameservers,
        label=label,
    )


@require_GET
def api_probe(request):
    """Boot-time resolver health probe (mirrors the original DoH boot check)."""
    try:
        resolver_id = _validated_resolver(request.GET.get("resolver", ""))
    except DomainValidationError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    backend = _backend_for(resolver_id)
    started = time.monotonic()
    status, records = backend.query("iana.org", "A")
    ms = int((time.monotonic() - started) * 1000)
    ok = status == "NOERROR" and any(r["type"] == "A" for r in records)
    return JsonResponse({
        "ok": ok,
        "resolver": backend.describe(),
        "resolver_id": resolver_id,
        "ms": ms if ok else None,
    })


@require_GET
def api_rbl_check(request):
    """Resolver self-test: does Spamhaus answer this resolver truthfully?

    `?resolver=<id>` tests one resolver (default: the configured default);
    `?resolver=all` tests every allow-listed one. Each resolver costs four
    lookups, so the count is capped and the endpoint is rate-limited per client.
    """
    ip = _client_ip(request)
    if not check_rate_limit(f"rbl:{ip}", settings.MX_RECON_RATE_LIMIT, settings.MX_RECON_RATE_WINDOW):
        resp = JsonResponse({"error": "Rate limit exceeded — cool down and retry shortly."}, status=429)
        resp["Retry-After"] = str(settings.MX_RECON_RATE_WINDOW)
        return resp

    raw = str(request.GET.get("resolver", "")).strip().lower()
    test_all = raw in ("all", "*") or str(request.GET.get("all", "")).lower() in ("1", "true", "yes")
    try:
        if test_all:
            ids = [r["id"] for r in as_list(settings.MX_RECON_RESOLVERS_EXTRA,
                                            settings.MX_RECON_RESOLVER_DEFAULT)]
            ids = ids[:MAX_RBL_CHECK_RESOLVERS]
        else:
            ids = [_validated_resolver(raw)]
    except DomainValidationError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    def probe(resolver_id):
        try:
            return rblcheck.check_resolver(_backend_for(resolver_id), resolver_id)
        except Exception:  # noqa: BLE001 — one unusable resolver must not sink the test
            return {
                "resolver_id": resolver_id,
                "resolver": resolver_id,
                "verdict": "no_answer",
                "headline": rblcheck.HEADLINES["no_answer"],
                "detail": "This resolver could not be queried at all.",
                "fix": rblcheck.RBL_FIX_ADVICE,
                "checks": [],
            }

    with ThreadPoolExecutor(max_workers=min(4, len(ids))) as pool:
        results = list(pool.map(probe, ids))

    resp = JsonResponse({
        "results": results,
        "summary": rblcheck.summarise(results),
        "default": settings.MX_RECON_RESOLVER_DEFAULT,
    })
    resp["Cache-Control"] = "no-store"
    return resp


@require_POST
@csrf_protect
def api_scan(request):
    """Run a full scan. Body: {"domain": "...", "selector": "..." (optional)}.

    Returns {"report": {...}, "logs": [{ts, cls, msg, ph}, ...]}.
    """
    ip = _client_ip(request)
    if not check_rate_limit(ip, settings.MX_RECON_RATE_LIMIT, settings.MX_RECON_RATE_WINDOW):
        resp = JsonResponse({"error": "Rate limit exceeded — cool down and retry shortly."}, status=429)
        resp["Retry-After"] = str(settings.MX_RECON_RATE_WINDOW)
        return resp

    try:
        payload = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Malformed JSON body."}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({"error": "Malformed JSON body."}, status=400)

    try:
        domain = validate_domain(str(payload.get("domain") or ""))
        selector = validate_selector(str(payload.get("selector") or ""))
        resolver_id = _validated_resolver(payload.get("resolver", ""))
    except DomainValidationError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    engine = Engine(
        domain,
        selector,
        resolver_id=resolver_id,
        max_queries=settings.MX_RECON_MAX_QUERIES,
        deadline=settings.MX_RECON_DEADLINE,
        whois_enabled=settings.MX_RECON_WHOIS,
        whois_timeout=settings.MX_RECON_WHOIS_TIMEOUT,
    )
    try:
        report, logs = engine.run()
    except Exception:  # noqa: BLE001 — never leak internals to the client
        return JsonResponse({"error": "Scan failed due to an internal error."}, status=502)

    resp = JsonResponse({"report": report, "logs": logs})
    resp["Cache-Control"] = "no-store"
    return resp


@require_GET
def healthz(request):
    """Container healthcheck endpoint."""
    return JsonResponse({"ok": True, "service": "mx-recon"})


@require_POST
@csrf_protect
def api_diagnose(request):
    """Explain why a delivered message was filtered.

    Body: {"headers": "<pasted raw headers>", "domain": "optional override"}.
    Returns {"report": {...}, "logs": [...]}.
    """
    ip = _client_ip(request)
    if not check_rate_limit(ip, settings.MX_RECON_RATE_LIMIT, settings.MX_RECON_RATE_WINDOW):
        resp = JsonResponse({"error": "Rate limit exceeded — cool down and retry shortly."}, status=429)
        resp["Retry-After"] = str(settings.MX_RECON_RATE_WINDOW)
        return resp

    if len(request.body or b"") > MAX_DIAGNOSE_BYTES:
        return JsonResponse({"error": "Pasted headers exceed the 128 KB limit."}, status=413)
    try:
        payload = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Malformed JSON body."}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({"error": "Malformed JSON body."}, status=400)

    raw_headers = str(payload.get("headers") or "")
    if not raw_headers.strip():
        return JsonResponse({"error": "Paste the email headers you want analysed."}, status=400)

    domain = str(payload.get("domain") or "").strip()
    try:
        if domain:
            domain = validate_domain(domain)
        resolver_id = _validated_resolver(payload.get("resolver", ""))
    except DomainValidationError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    try:
        report, logs = Diagnoser(raw_headers, domain=domain, resolver_id=resolver_id).run()
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except Exception:  # noqa: BLE001 — never leak internals
        return JsonResponse({"error": "Diagnosis failed due to an internal error."}, status=502)

    resp = JsonResponse({"report": report, "logs": logs})
    resp["Cache-Control"] = "no-store"
    return resp
