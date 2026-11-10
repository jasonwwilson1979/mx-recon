"""
DNS resolver registry.

The browser may only choose from this allow-list — arbitrary nameserver
addresses are never accepted from the client (that would turn the scanner into
an open DNS relay). Self-hosters can add their own resolver through the
DJANGO_RESOLVERS_EXTRA environment variable:

    DJANGO_RESOLVERS_EXTRA="internal|Internal DNS 10.0.0.53|10.0.0.53;vpn|VPN DNS|10.8.0.1,10.8.0.2"
"""
from __future__ import annotations

import re

BUILTIN = {
    "system": {
        "label": "System default",
        "nameservers": [],
        "note": "Whatever the host/container is configured to use (best for RBL checks).",
        "public": False,
    },
    "cloudflare": {
        "label": "Cloudflare (1.1.1.1)",
        "nameservers": ["1.1.1.1", "1.0.0.1"],
        "note": "Fast public resolver, no filtering.",
        "public": True,
    },
    "google": {
        "label": "Google (8.8.8.8)",
        "nameservers": ["8.8.8.8", "8.8.4.4"],
        "note": "Widely used public resolver.",
        "public": True,
    },
    "quad9": {
        "label": "Quad9 (9.9.9.9)",
        "nameservers": ["9.9.9.9", "149.112.112.112"],
        "note": "Malware-blocking public resolver.",
        "public": True,
    },
    "opendns": {
        "label": "OpenDNS (208.67.222.222)",
        "nameservers": ["208.67.222.222", "208.67.220.220"],
        "note": "Cisco OpenDNS, blocks some categories.",
        "public": True,
    },
    "adguard": {
        "label": "AdGuard DNS (94.140.14.14)",
        "nameservers": ["94.140.14.14", "94.140.15.15"],
        "note": "Ad/tracker filtering resolver.",
        "public": True,
    },
}

# Public resolvers are shared, unattributable and often filtered, so Spamhaus
# either refuses them (Cloudflare returns 127.255.255.254 = "blocked") or answers
# a blanket NXDOMAIN that reads as a *false* clean (Google). We flag them so the
# UI can warn that blacklist results are not trustworthy through them.

DEFAULT_RESOLVER = "system"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_IP_RE = re.compile(r"^[0-9a-fA-F:.]{2,45}$")


def _parse_extra(raw: str) -> dict:
    """Parse `id|Label|ip[,ip][;id|Label|ip]` into registry entries."""
    extra = {}
    for chunk in (raw or "").split(";"):
        parts = [part.strip() for part in chunk.split("|")]
        if len(parts) != 3 or not all(parts):
            continue
        rid, label, servers = parts
        servers = [s.strip() for s in servers.split(",") if s.strip()]
        if not _ID_RE.match(rid) or not servers or not all(_IP_RE.match(s) for s in servers):
            continue
        extra[rid] = {
            "label": label[:60],
            "nameservers": servers,
            "note": "Custom resolver (DJANGO_RESOLVERS_EXTRA).",
            # An operator-supplied resolver is assumed to be their own (internal
            # or self-hosted), so it is not flagged as public.
            "public": False,
        }
    return extra


def registry(extra_raw: str = "") -> dict:
    reg = {rid: dict(cfg) for rid, cfg in BUILTIN.items()}
    reg.update(_parse_extra(extra_raw))
    return reg


def as_list(extra_raw: str = "", default_id: str = DEFAULT_RESOLVER) -> list:
    reg = registry(extra_raw)
    default_id = (default_id or DEFAULT_RESOLVER).strip().lower()
    if default_id not in reg:
        default_id = DEFAULT_RESOLVER
    return [
        {
            "id": rid,
            "label": cfg["label"],
            "nameservers": cfg["nameservers"],
            "note": cfg["note"],
            "public": bool(cfg.get("public")),
            "default": rid == default_id,
        }
        for rid, cfg in reg.items()
    ]


def is_public(resolver_id: str, extra_raw: str = "") -> bool:
    """True when the resolver is a shared public service.

    Blacklist operators (Spamhaus above all) cannot attribute such queries to a
    customer, so they refuse them or answer a blanket "not listed" — meaning RBL
    results through these resolvers are untrustworthy either way.
    """
    rid = (resolver_id or DEFAULT_RESOLVER).strip().lower()
    return bool(registry(extra_raw).get(rid, {}).get("public"))


def nameservers_for(resolver_id: str, extra_raw: str = ""):
    """Return (nameservers, label) for a resolver id; raise ValueError if unknown."""
    reg = registry(extra_raw)
    rid = (resolver_id or DEFAULT_RESOLVER).strip().lower()
    if rid not in reg:
        raise ValueError(f"Unknown resolver '{resolver_id}'.")
    cfg = reg[rid]
    return list(cfg["nameservers"]), cfg["label"]
