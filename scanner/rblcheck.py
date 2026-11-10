"""
Resolver self-test for blacklist (RBL/DNSBL) lookups.

Spamhaus refuses queries that arrive from public open resolvers, from
unattributable resolvers and from IP ranges it has blocked. Some public
resolvers go further and answer a blanket NXDOMAIN ("not listed") instead of
erroring, so a blocked setup looks perfectly clean rather than obviously broken.

Spamhaus publishes RFC5782 operational test entries for exactly this purpose:

    test.dbl.spamhaus.org          -> 127.0.1.2   (must be listed)
    dbltest.com.dbl.spamhaus.org   -> 127.0.1.2   (must be listed)
    example.com.dbl.spamhaus.org   -> NXDOMAIN    (IANA reserved, never listed)

Querying the *listed* test entry through a resolver therefore tells us which of
four things is happening:

    ok           the test entry answers with a listing code -> answers are real
    refused      Spamhaus answers an error code in 127.255.255.0/24
    false_clean  the test entry answers NXDOMAIN -> everything looks clean, nothing is
    no_answer    nothing came back (timeout, blocked egress, broken resolver)

The DBL test entry is authoritative (Spamhaus documents its expected answer); the
ZEN probe is reported alongside it as a second data point for the IP zones.
"""
from __future__ import annotations

from .engine import RBL_FIX_ADVICE

# Spamhaus's documented test entries (see the DBL FAQ, "How can I test the DBL?").
DBL_TEST_LISTED = "test.dbl.spamhaus.org"           # RFC5782 operational test
DBL_TEST_DOMAIN = "dbltest.com.dbl.spamhaus.org"    # documented "listed" domain
DBL_TEST_CLEAN = "example.com.dbl.spamhaus.org"     # documented "not listed" domain
ZEN_TEST_IP = "2.0.0.127.zen.spamhaus.org"          # SBL test entry (127.0.0.2)

VERDICT_ORDER = {"ok": 0, "partial": 1, "false_clean": 2, "refused": 3, "no_answer": 4}

HEADLINES = {
    "ok": "Spamhaus answers this resolver with real data",
    "partial": "This resolver answers some Spamhaus lookups but not others",
    "refused": "Spamhaus refuses this resolver",
    "false_clean": "This resolver is answered with a blanket NXDOMAIN",
    "no_answer": "This resolver returned nothing",
}

DETAILS = {
    "ok": ("The RFC5782 test entry {query} returned {code}, so a CLEAN row from this "
           "resolver means what it says."),
    "partial": ("Only some test entries came back as documented — the rest were refused or "
                "answered NXDOMAIN. A resolver that is over Spamhaus's free query quota, is "
                "being rate-limited, or has cached a refusal behaves exactly like this. Treat "
                "its blacklist rows as unverified and re-run later."),
    "refused": ("Spamhaus answered the test entry with the error code {code} instead of a "
                "listing. Queries from this resolver are refused — not listed, just unanswerable."),
    "false_clean": ("The test entry {query} came back NXDOMAIN instead of the documented "
                    "127.0.1.2. Everything would look clean through this resolver, including "
                    "domains that are genuinely listed."),
    "no_answer": "No answer came back at all — check the resolver address and outbound DNS (UDP/TCP 53).",
}


def _listing_code(records) -> str:
    """First 127.x answer, i.e. a DNSBL listing/error code ('' when none)."""
    for rec in records or []:
        if rec.get("type") == "A" and str(rec.get("data", "")).startswith("127."):
            return str(rec["data"])
    return ""


def _verdict_for_listed(status: str, records) -> tuple:
    """(verdict, code) for a *listed* test entry: it must answer with a listing."""
    code = _listing_code(records)
    if code.startswith("127.255.255."):
        return "refused", code          # Spamhaus's "blocked / error" range
    if code:
        return "ok", code
    if status in ("NXDOMAIN", "NOERROR"):
        return "false_clean", ""        # the entry exists, so NXDOMAIN is a lie
    return "no_answer", ""


def _verdict_for_clean(status: str, records) -> tuple:
    """(verdict, code) for a name that must never be listed."""
    code = _listing_code(records)
    if code.startswith("127.255.255."):
        return "refused", code
    if code:
        return "unexpected", code       # example.com is never listed: answers are being rewritten
    if status in ("NXDOMAIN", "NOERROR"):
        return "ok", ""
    return "no_answer", ""


def _verdict_for_advisory(status: str, records) -> tuple:
    """(verdict, code) for the ZEN probe.

    Spamhaus documents the RFC5782 entry for the DBL, but the ZEN test entry is
    only referenced in their examples, so a listing code proves the IP zones
    answer while NXDOMAIN proves nothing — it is reported as inconclusive.
    """
    code = _listing_code(records)
    if code.startswith("127.255.255."):
        return "refused", code
    if code:
        return "ok", code
    if status in ("NXDOMAIN", "NOERROR"):
        return "inconclusive", ""
    return "no_answer", ""


def check_resolver(backend, resolver_id: str = "", label: str = "") -> dict:
    """Run the Spamhaus test entries through one resolver backend.

    `backend` is anything with the DnspythonBackend query() shape, so tests can
    inject a stub. Returns a JSON-ready dict (see the module docstring).
    """
    probes = [
        ("RFC5782 DBL test (must be listed)", DBL_TEST_LISTED, "listed", "127.0.1.2"),
        ("DBL listed domain (must be listed)", DBL_TEST_DOMAIN, "listed", "127.0.1.2"),
        ("DBL clean domain (must not be listed)", DBL_TEST_CLEAN, "clean", "NXDOMAIN"),
        ("ZEN test IP (advisory)", ZEN_TEST_IP, "advisory", "127.0.0.2"),
    ]
    checks = []
    for title, query, kind, expected in probes:
        status, records = backend.query(query, "A")
        if kind == "listed":
            verdict, code = _verdict_for_listed(status, records)
        elif kind == "clean":
            verdict, code = _verdict_for_clean(status, records)
        else:
            verdict, code = _verdict_for_advisory(status, records)
        checks.append({
            "kind": kind,
            "title": title,
            "query": query,
            "status": status,
            "answer": code or ("NXDOMAIN" if status in ("NXDOMAIN", "NOERROR") else status),
            "expected": expected,
            "verdict": verdict,
        })

    listed = [c for c in checks if c["kind"] == "listed"]
    clean_probe, zen = checks[2], checks[3]
    listed_ok = sum(1 for c in listed if c["verdict"] == "ok")
    refused = sum(1 for c in checks if c["verdict"] == "refused")
    nxdomain = sum(1 for c in listed if c["verdict"] == "false_clean")

    if clean_probe["verdict"] == "unexpected":
        verdict = "partial"                      # answers are being rewritten/filtered
    elif listed_ok == len(listed) and clean_probe["verdict"] == "ok" \
            and zen["verdict"] in ("ok", "inconclusive"):
        verdict = "ok"
    elif listed_ok:
        verdict = "partial"
    elif refused:
        verdict = "refused"
    elif nxdomain:
        verdict = "false_clean"
    else:
        verdict = "no_answer"

    primary = listed[0]
    detail = DETAILS[verdict].format(query=primary["query"], code=primary["answer"])
    if verdict == "ok":
        detail += " IP zones (ZEN) answer too." if zen["verdict"] == "ok" else ""
    elif verdict in ("refused", "false_clean", "partial"):
        detail += " " + RBL_FIX_ADVICE + "."
    return {
        "resolver_id": resolver_id,
        "resolver": backend.describe() if hasattr(backend, "describe") else (label or resolver_id),
        "verdict": verdict,
        "headline": HEADLINES[verdict],
        "detail": detail,
        "fix": "" if verdict == "ok" else RBL_FIX_ADVICE,
        "checks": checks,
    }


def summarise(results) -> dict:
    """Overall picture across several resolvers, plus which one to use."""
    results = list(results or [])
    working = [r["resolver_id"] for r in results if r["verdict"] == "ok"]
    unreliable = [r["resolver_id"] for r in results if r["verdict"] == "partial"]
    if working:
        headline = f"{len(working)} of {len(results)} resolver(s) can query Spamhaus truthfully"
    elif unreliable:
        headline = "No resolver answers Spamhaus reliably — some answer only part of the time"
    elif any(r["verdict"] == "false_clean" for r in results):
        headline = "No resolver can query Spamhaus — and at least one is hiding it as CLEAN"
    else:
        headline = "No resolver can query Spamhaus"
    return {
        "headline": headline,
        "working": working,
        "unreliable": unreliable,
        "recommended": working[0] if working else "",
        "count": len(results),
    }
