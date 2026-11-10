"""
WHOIS via RDAP + nameserver-provider attribution.

RDAP is the ICANN-mandated successor to port-43 WHOIS: the same registry data
(registrar, registration/expiry dates, status flags, delegated nameservers,
DNSSEC signing) but structured JSON over HTTPS — which also works from
containers and networks where outbound TCP/43 is blocked.

No third-party dependencies: the IANA bootstrap file tells us which registry
RDAP server to ask, with rdap.org as a fallback redirector.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
REDIRECT_URL = "https://rdap.org/domain/{domain}"
USER_AGENT = "MX-RECON/3.6 (+email-security-diagnostics)"
BOOTSTRAP_TTL = 6 * 3600

_bootstrap = {"at": 0.0, "map": {}}

# Nameserver suffix -> hosting/DNS provider (best effort, first match wins).
PROVIDERS = (
    ("cloudflare.com", "Cloudflare"),
    ("ns.cloudflare.com", "Cloudflare"),
    ("awsdns", "AWS Route 53"),
    ("dns.google", "Google Cloud DNS"),
    ("ns1.google.com", "Google"),
    ("ns2.google.com", "Google"),
    ("ns3.google.com", "Google"),
    ("ns4.google.com", "Google"),
    ("googledomains.com", "Google Domains"),
    ("azure-dns", "Azure DNS"),
    ("domaincontrol.com", "GoDaddy"),
    ("secureserver.net", "GoDaddy"),
    ("registrar-servers.com", "Namecheap"),
    ("namecheap.com", "Namecheap"),
    ("dnsmadeeasy.com", "DNS Made Easy"),
    ("nsone.net", "NS1"),
    ("p01.nsone", "NS1"),
    ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Linode"),
    ("hetzner", "Hetzner"),
    ("ovh.net", "OVH"),
    ("ovh.com", "OVH"),
    ("gandi.net", "Gandi"),
    ("ultradns", "UltraDNS"),
    ("akamai", "Akamai"),
    ("akam.net", "Akamai"),
    ("vercel-dns.com", "Vercel"),
    ("netlify.com", "Netlify"),
    ("wixdns.net", "Wix"),
    ("squarespace.com", "Squarespace"),
    ("wordpress.com", "WordPress.com"),
    ("shopify.com", "Shopify"),
    ("markmonitor.com", "MarkMonitor"),
    ("cscdns.net", "CSC"),
    ("worldnic.com", "Network Solutions"),
    ("network-solutions", "Network Solutions"),
    ("register.com", "Register.com"),
    ("porkbun.com", "Porkbun"),
    ("name.com", "Name.com"),
    ("dynect.net", "Oracle Dyn"),
    ("rackspace.com", "Rackspace"),
    ("dnsimple.com", "DNSimple"),
    ("easydns", "easyDNS"),
    ("siteground", "SiteGround"),
    ("ionos", "IONOS"),
    ("1and1", "IONOS"),
    ("strato", "STRATO"),
    ("arubabusiness", "Aruba"),
    ("zoneedit", "ZoneEdit"),
    ("he.net", "Hurricane Electric"),
    ("hostgator.com", "HostGator"),
    ("bluehost.com", "Bluehost"),
    ("microsoftonline.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("ns.namespace4you", "STRATO"),
    ("one.com", "One.com"),
)


def provider_for(nameserver: str) -> str:
    """Best-effort hosting/DNS provider for a nameserver hostname."""
    name = (nameserver or "").lower().rstrip(".")
    for suffix, label in PROVIDERS:
        if suffix in name:
            return label
    return "self-hosted / unknown"


# ------------------------------------------------------------------ RDAP


def _get_json(url: str, timeout: float):
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8", "replace")
        return json.loads(payload), response.geturl()


def bootstrap_map(timeout: float = 6.0) -> dict:
    """TLD -> registry RDAP base URL, from the IANA bootstrap file (cached)."""
    now = time.time()
    if _bootstrap["map"] and (now - _bootstrap["at"]) < BOOTSTRAP_TTL:
        return _bootstrap["map"]
    try:
        data, _url = _get_json(BOOTSTRAP_URL, timeout)
        mapping = {}
        for service in data.get("services", []) or []:
            if len(service) < 2 or not service[1]:
                continue
            base = str(service[1][0]).rstrip("/")
            for tld in service[0] or []:
                mapping[str(tld).lower()] = base
        if mapping:
            _bootstrap["map"] = mapping
            _bootstrap["at"] = now
    except Exception:  # noqa: BLE001 — fall back to the rdap.org redirector
        pass
    return _bootstrap["map"]


def _vcard_name(entity: dict):
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for field in vcard[1] or []:
        if isinstance(field, list) and len(field) >= 4 and str(field[0]).lower() in ("fn", "org"):
            value = field[3]
            if isinstance(value, list):
                value = " ".join(str(part) for part in value)
            return str(value)[:120]
    return None


def parse_rdap(data: dict) -> dict:
    """Flatten an RDAP domain object into the fields MX-RECON cares about."""
    out = {
        "registrar": None,
        "registrar_id": None,
        "status": [],
        "events": {},
        "nameservers": [],
        "dnssec": None,
        "abuse_contact": None,
    }
    for entity in data.get("entities", []) or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        name = _vcard_name(entity)
        if "registrar" in roles:
            out["registrar"] = name or out["registrar"]
            for public_id in entity.get("publicIds", []) or []:
                if "iana" in str(public_id.get("type", "")).lower():
                    out["registrar_id"] = public_id.get("identifier")
            if not out["registrar_id"] and re.match(r"^[0-9]{1,6}$", str(entity.get("handle") or "")):
                out["registrar_id"] = entity["handle"]  # some registries only expose it here
        elif "abuse" in roles and name and not out["abuse_contact"]:
            out["abuse_contact"] = name
    for event in data.get("events", []) or []:
        action = str(event.get("eventAction") or "").lower()
        if action and event.get("eventDate"):
            out["events"][action] = event["eventDate"]
    out["status"] = [str(s) for s in (data.get("status") or [])]
    for server in data.get("nameservers", []) or []:
        name = str(server.get("ldhName") or server.get("unicodeName") or "").lower().rstrip(".")
        if name:
            out["nameservers"].append(name)
    secure = data.get("secureDNS") or {}
    if secure:
        out["dnssec"] = bool(secure.get("delegationSigned"))
    return out


def rdap_lookup(domain: str, timeout: float = 6.0) -> dict:
    """Registry/registrar data for a domain (never raises)."""
    tld = domain.rsplit(".", 1)[-1].lower()
    base = bootstrap_map(timeout).get(tld)
    candidates = []
    if base:
        candidates.append(f"{base}/domain/{domain}")
    candidates.append(REDIRECT_URL.format(domain=domain))

    error = None
    for url in candidates:
        try:
            data, final_url = _get_json(url, timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"available": True, "error": "no registry record (RDAP 404 — unregistered or unsupported)"}
            error = f"HTTP {exc.code}"
            continue
        except Exception as exc:  # noqa: BLE001 — timeouts, TLS, DNS, JSON
            error = type(exc).__name__
            continue
        result = parse_rdap(data)
        result["source"] = final_url
        result["available"] = False
        return result
    return {"error": error or "RDAP unavailable"}

