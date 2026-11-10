"""Strict input validation for scan targets.

The public scan endpoint must never become a proxy for attacking internal
networks or abusing resolvers, so targets are locked down to well-formed,
globally-routable *domain names* — IP literals and special-use names are
rejected outright.
"""
from __future__ import annotations

import ipaddress
import re

__all__ = ["DomainValidationError", "normalize_domain", "validate_domain", "validate_selector"]


class DomainValidationError(ValueError):
    """Raised when a scan target fails validation."""


# One DNS label: alphanumeric, interior hyphens allowed, 1-63 chars.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")
_SELECTOR_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

_MAX_DOMAIN_LEN = 253

# Names that must never be scanned from a public service.
_DENIED_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "invalid",
    "test",
    "example",
    "arpa",
    "onion",
)

MAX_SELECTOR_LEN = 63


def normalize_domain(raw: str) -> str:
    """Mirror the client-side normaliser: emails, URLs, ports and _dmarc
    prefixes are stripped so the bare domain remains."""
    d = (raw or "").strip().lower()
    if "@" in d:
        d = d.split("@")[-1]
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0].split("?")[0]
    d = re.sub(r"^_dmarc\.", "", d)
    return d.strip(".")


def validate_domain(raw: str) -> str:
    """Return the normalised, validated domain or raise DomainValidationError."""
    domain = normalize_domain(raw)
    if not domain:
        raise DomainValidationError("No target domain supplied.")
    if len(domain) > _MAX_DOMAIN_LEN:
        raise DomainValidationError("Domain exceeds the 253-character DNS limit.")
    if not _DOMAIN_RE.match(domain):
        raise DomainValidationError(
            "Target must be a valid hostname such as example.com "
            "(letters, digits, hyphens; no IP addresses)."
        )
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass  # expected — genuine domains are not IP literals
    else:
        raise DomainValidationError("IP addresses are not valid scan targets — use a hostname.")
    tld = domain.rsplit(".", 1)[-1]
    if tld.isdigit():
        raise DomainValidationError("IP-literal targets are not allowed.")
    for suffix in _DENIED_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            raise DomainValidationError(f"Special-use names (*.{suffix}) cannot be scanned.")
    return domain


def validate_selector(raw: str) -> str:
    """Validate an optional DKIM selector (empty string = auto-probe)."""
    selector = (raw or "").strip().lower()
    selector = re.sub(r"\._domainkey\..*$", "", selector)  # tolerate full record names
    if not selector:
        return ""
    if len(selector) > MAX_SELECTOR_LEN or not _SELECTOR_RE.match(selector):
        raise DomainValidationError("DKIM selector must be 1-63 chars: a-z, 0-9, interior hyphens.")
    return selector
