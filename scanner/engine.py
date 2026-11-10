"""
MX-RECON forensic engine — server-side Python port of the MX-RECON v2.5 pipeline.

Seven modules, executed in order, all over a hardened dnspython resolver with
per-query timeouts, a per-scan query budget and a wall-clock deadline:

  01 ENUM   zone enumeration (A / AAAA / NS / SOA / TXT / CNAME)
  02 MX     mail-exchanger topology, rDNS hygiene, RFC 2181/5321 checks
  03 SPF    recursive include/redirect tree walk with RFC 7208 lookup budget
  04 DKIM   selector probing + key-strength estimation
  05 DMARC  policy parsing and posture assessment
  06 RBL    IP + domain blacklist matrix (Spamhaus / SURBL / SpamCop class)
  07 REPORT 0-100 posture scoring, remediation directives, full record vault

Everything observed is captured into a deduplicated inventory so the report
is fully transparent about what was queried and what answered.
"""
from __future__ import annotations

import html
import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .resolvers import is_public, nameservers_for
from . import relays, whois

# ------------------------------------------------------------------ constants

RBL_IP = [
    {"zone": "zen.spamhaus.org", "name": "Spamhaus ZEN", "url": "https://check.spamhaus.org/"},
    {"zone": "bl.spamcop.net", "name": "SpamCop BL", "url": "https://www.spamcop.net/bl.shtml"},
    {"zone": "b.barracudacentral.org", "name": "Barracuda BRBL", "url": "https://www.barracudacentral.org/rbl/removal-request"},
    {"zone": "dnsbl.sorbs.net", "name": "SORBS Composite", "url": "https://www.sorbs.net/"},
    {"zone": "psbl.surriel.com", "name": "PSBL", "url": "http://psbl.surriel.com/"},
    {"zone": "spam.dnsbl.sorbs.net", "name": "SORBS Spam", "url": "https://www.sorbs.net/"},
    {"zone": "dnsbl-1.uceprotect.net", "name": "UCEprotect L1", "url": "http://www.uceprotect.net/"},
    {"zone": "db.wpbl.info", "name": "WPBL", "url": "http://www.wpbl.info/"},
]

RBL_DOM = [
    {"zone": "dbl.spamhaus.org", "name": "Spamhaus DBL", "url": "https://check.spamhaus.org/"},
    {"zone": "multi.surbl.org", "name": "SURBL Multi", "url": "https://www.surbl.org/"},
]

# NOTE: multi.uribl.com is deliberately not queried. URIBL answers 127.0.0.1
# ("query blocked / not authorised") to unregistered or public resolvers — which
# used to be misread as a listing for every domain. See classify_rbl().

# Spamhaus refuses queries that arrive from public/open resolvers (8.8.8.8,
# 1.1.1.1, most cloud DNS) or from IP ranges it has blocked: instead of an answer
# it returns an error code in 127.255.255.0/24. The supported alternatives are to
# query from our own IP, or to use Spamhaus's Data Query Service zones
# (<key>.zen.dq.spamhaus.net / <key>.dbl.dq.spamhaus.net).
PUBLIC_SPAMHAUS_SUFFIX = ".spamhaus.org"
DQS_SUFFIX = ".dq.spamhaus.net"
RBL_FIX_ADVICE = (
    "Spamhaus only answers resolvers it can attribute, so public/cloud DNS gets an error code "
    "instead of a listing. Fix: use the \"System default\" resolver (so the query leaves from this "
    "host's own IP), point DJANGO_RESOLVERS_EXTRA at your own recursive resolver, or register "
    "Spamhaus DQS and query the *.dq.spamhaus.net zones via DJANGO_RBL_EXTRA_IP / "
    "DJANGO_RBL_EXTRA_DOMAIN — see README \u2192 \"Spamhaus answers BLOCKED\""
)

COMMON_SELECTORS = [
    "google", "selector1", "selector2", "s1", "s2", "k1", "k2", "default",
    "mail", "mx", "protonmail", "pm1", "sig1", "dkim", "dkim1", "m1",
    "smtp", "zmail",
]

# ------------------------------------------------------------------ regexes
_RE_SPF_REC = re.compile(r"^v=spf1(\s|$)", re.I)
_RE_INCLUDE = re.compile(r"^[+~?-]?include:(.+)$", re.I)
_RE_REDIRECT = re.compile(r"^redirect=(.+)$", re.I)
_RE_A_MX_PTR = re.compile(r"^[+~?-]?(a|mx|ptr)([:/]|$)", re.I)
_RE_EXISTS = re.compile(r"^exists:", re.I)
_RE_ALL = re.compile(r"^[+~?-]?all$", re.I)
_RE_IP_RULE = re.compile(r"\bip[46]:", re.I)
_RE_DKIM_P = re.compile(r"(^|;\s*)p=([^;\s]*)", re.I)
_RE_DKIM_ANY_P = re.compile(r"(^|;\s*)p=", re.I)
_RE_DKIM_K = re.compile(r"(^|;\s*)k=([^;\s]+)", re.I)
_RE_DKIM_HINT = re.compile(r"v=dkim1", re.I)
_RE_DMARC = re.compile(r"v=DMARC1", re.I)
_RE_STS = re.compile(r"v=STSv1", re.I)
_RE_TLSRPT = re.compile(r"v=TLSRPTv1", re.I)
_RE_BIMI = re.compile(r"v=BIMI1", re.I)
_RE_TAGS = re.compile(r"<[^>]+>")


def _h(value) -> str:
    """HTML-escape untrusted text before it is embedded in log/rec HTML."""
    return html.escape(str(value), quote=True)


def _of(records, rtype: str) -> list:
    return [r["data"] for r in (records or []) if r["type"] == rtype]


def _txts(records) -> list:
    return _of(records, "TXT")


def rev_ip(ip: str) -> str:
    """Reverse-DNS query name for an IPv4 or IPv6 address."""
    return ipaddress.ip_address(ip).reverse_pointer


def classify_rbl(status: str, records):
    """Classify an RBL answer: (state, return-code).

    Not every 127.x answer is a listing:
      * 127.0.0.1            — "query blocked / not authorised" (used by URIBL
                               for unregistered or public resolvers)
      * 127.255.255.x        — Spamhaus's "you are using a blocked resolver"
    Both are inconclusive, never a listing. Other 127.0.0.x codes are listings.
    """
    a = _of(records, "A")
    if a:
        if any(x == "127.0.0.1" or x.startswith("127.255.255.") for x in a):
            return "blocked", a[0]
        return "listed", a[0]
    if status in ("NOERROR", "NXDOMAIN"):
        return "clean", None
    return "err", None


def is_public_spamhaus(zone: str) -> bool:
    """True for the public Spamhaus zones (zen/dbl.spamhaus.org) that refuse
    queries from public resolvers. DQS zones (*.dq.spamhaus.net) are not public
    in that sense — they answer keyed or IP-registered queries normally."""
    z = str(zone or "").lower().rstrip(".")
    return z.endswith(PUBLIC_SPAMHAUS_SUFFIX) and not z.endswith(DQS_SUFFIX)


def blocked_rbl_zones(ip_matrix, dom_matrix) -> set:
    """Zone names that refused or failed the query (inconclusive, not listings)."""
    names = {
        r["zone"] for r in (ip_matrix or [])
        if any(c.get("status") in ("blocked", "err") for c in r.get("cells", []))
    }
    names |= {
        r["zone"] for r in (dom_matrix or [])
        if r.get("status") in ("blocked", "err")
    }
    return names


def rbl_blocked_hint(zones) -> str:
    """One log line explaining why zones refused us, and what to change."""
    names = sorted(zones)
    listed = ", ".join(_h(z) for z in names)
    if any(is_public_spamhaus(z) for z in names):
        return f"{listed} refused the query (inconclusive — never a listing). {RBL_FIX_ADVICE}."
    return (
        f"{listed} did not answer — inconclusive, not a listing. Re-run, or query through a "
        "different resolver (some lists rate-limit or refuse unattributable resolvers)."
    )


_RE_ZONE_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def parse_extra_zones(raw: str) -> list:
    """Parse `zone|Label|url[;zone|Label|url]` into RBL zone entries.

    Label and url are optional — `zone` and `zone|Label` both work. IPs, bare
    single labels and anything else that is not a hostname are ignored.
    """
    zones = []
    for chunk in str(raw or "").split(";"):
        parts = [p.strip() for p in chunk.split("|")]
        if not parts or not parts[0]:
            continue
        zone = parts[0].lower().rstrip(".")
        if not _RE_ZONE_NAME.match(zone):
            continue
        try:
            ipaddress.ip_address(zone)
        except ValueError:
            pass
        else:
            continue  # an IP literal is not a zone name
        zones.append({
            "zone": zone,
            "name": (parts[1] if len(parts) > 1 and parts[1] else zone)[:60],
            "url": (parts[2] if len(parts) > 2 else "")[:200],
            "custom": True,
        })
    return zones


def active_rbl_zones():
    """RBL zones to query: built-ins plus operator extras, minus disabled ones.

    Extras come from DJANGO_RBL_EXTRA_IP / DJANGO_RBL_EXTRA_DOMAIN (IP zones are
    queried as `<reversed-ip>.<zone>`, domain zones as `<domain>.<zone>`).
    Duplicates of an existing zone are ignored and DJANGO_RBL_DISABLED applies
    to built-ins and extras alike.
    """
    disabled = {
        z.strip().lower().rstrip(".")
        for z in str(_settings("MX_RECON_RBL_DISABLED", "")).split(",")
        if z.strip()
    }
    ip_zones = list(RBL_IP) + parse_extra_zones(_settings("MX_RECON_RBL_EXTRA_IP", ""))
    dom_zones = list(RBL_DOM) + parse_extra_zones(_settings("MX_RECON_RBL_EXTRA_DOMAIN", ""))

    def keep(entries):
        seen = set()
        out = []
        for entry in entries:
            zone = entry["zone"].lower()
            if zone in disabled or zone in seen:
                continue
            seen.add(zone)
            out.append(entry)
        return out

    return keep(ip_zones), keep(dom_zones)


def dkim_key_bits(raw: str) -> tuple:
    """(algo, bits, revoked, key) estimated from the p= payload length."""
    m = _RE_DKIM_P.search(raw or "")
    key = m.group(2) if m else ""
    revoked = key == ""
    km = _RE_DKIM_K.search(raw or "")
    algo = km.group(2).lower() if km else "rsa"
    length = len(key)
    bits = 0 if revoked else (1024 if length < 250 else 2048 if length < 560 else 4096)
    return algo, bits, revoked, key


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in (record or "").split(";"):
        i = part.find("=")
        if i > 0:
            tags[part[:i].strip().lower()] = part[i + 1:].strip()
    return tags


def _settings_fallback():
    """Public fallback resolvers from Django settings (empty outside Django)."""
    try:
        from django.conf import settings

        return list(getattr(settings, "MX_RECON_DNS_FALLBACK", []) or [])
    except Exception:  # pragma: no cover — Django not configured
        return []


def _days_until(iso: str):
    """Whole days from now until an ISO-8601 timestamp (None when unparseable)."""
    try:
        when = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return max(0, (when - datetime.now(timezone.utc)).days)
    except Exception:  # noqa: BLE001
        return None


def _settings(name: str, default):
    """Read a Django setting without exploding outside a configured app."""
    try:
        from django.conf import settings

        return getattr(settings, name, default)
    except Exception:  # pragma: no cover — Django not configured
        return default


class DnspythonBackend:
    """Thin adapter that turns dnspython answers into plain dict records.

    Reverse (PTR) lookups are retried against a public fallback resolver when
    the system resolver returns nothing — many container/cloud resolvers do not
    answer in-addr.arpa queries at all, which would otherwise show up as a
    false "no reverse DNS" finding. Swappable in tests with a stub backend
    exposing the same `query()` shape.
    """

    def __init__(self, timeout: float = 3.0, lifetime: float = 6.0, fallback=None,
                 resolver=None, fallback_resolver=None, nameservers=None, label: str = ""):
        import dns.rdatatype
        import dns.resolver

        self._dns = dns.resolver
        self._rdatatype = dns.rdatatype
        self._timeout = timeout
        self._lifetime = lifetime
        self._label = (label or "").strip()
        self._resolver = resolver or self._build_resolver(timeout, lifetime, nameservers)
        self._fallback_servers = list(fallback) if fallback is not None else _settings_fallback()
        self._fallback_resolver = fallback_resolver
        self.fallback_enabled = bool(fallback_resolver is not None or self._fallback_servers)
        self.last_source = "system"

    def _build_resolver(self, timeout: float, lifetime: float, nameservers=None):
        servers = [s for s in (nameservers or []) if s]
        resolver = self._dns.Resolver(configure=not servers)
        if servers:
            resolver.nameservers = list(servers)
        resolver.timeout = timeout
        resolver.lifetime = lifetime
        resolver.search = []
        try:
            resolver.use_search_by_default = False
        except AttributeError:  # pragma: no cover — older dnspython
            pass
        resolver.cache = self._dns.LRUCache(4096)
        return resolver

    def _get_fallback(self):
        if self._fallback_resolver is None and self._fallback_servers:
            resolver = self._dns.Resolver(configure=False)
            resolver.nameservers = list(self._fallback_servers)
            resolver.timeout = self._timeout
            resolver.lifetime = self._lifetime
            resolver.search = []
            self._fallback_resolver = resolver
        return self._fallback_resolver

    def describe(self) -> str:
        servers = list(getattr(self._resolver, "nameservers", None) or [])
        if self._label:
            return f"{self._label} (dnspython)" + (f" · {', '.join(str(s) for s in servers)}" if servers else "")
        names = sorted({str(ns) for ns in servers})
        return "system resolver (dnspython)" + (
            f": {', '.join(n.rstrip('.') for n in names[:4])}" if names else ""
        )

    def _run(self, resolver, name: str, rtype: str):
        try:
            answer = resolver.resolve(name, rtype)
        except self._dns.NXDOMAIN:
            return "NXDOMAIN", []
        except self._dns.NoAnswer:
            return "NOERROR", []
        except Exception:
            return "ERR", []
        records = []
        for rdata in answer:
            if rdata.rdtype == self._rdatatype.TXT:
                data = b"".join(rdata.strings).decode("utf-8", "replace")
            elif rdata.rdtype == self._rdatatype.MX:
                data = f"{rdata.preference} {rdata.exchange}"
            else:
                data = rdata.to_text()
            records.append(
                {"type": self._rdatatype.to_text(rdata.rdtype), "data": data, "ttl": getattr(answer, "ttl", None)}
            )
        return "NOERROR", records

    def query(self, name: str, rtype: str):
        self.last_source = "system"
        status, records = self._run(self._resolver, name, rtype)
        if rtype.upper() == "PTR" and not records:
            fallback = self._get_fallback()
            if fallback is not None:
                fb_status, fb_records = self._run(fallback, name, rtype)
                if fb_records:
                    self.last_source = "fallback"
                    return fb_status, fb_records
        return status, records


# ------------------------------------------------------------------ engine


class Engine:
    """One scan = one Engine instance. Produces (report, logs)."""

    def __init__(self, domain: str, selector: str = "", backend=None, resolver_id: str = "",
                 max_queries: int = 350, deadline: float = 30.0, max_workers: int = 16,
                 whois_enabled: bool = True, whois_timeout: float = 6.0, rdap_fn=None):
        self.domain = domain
        self.selector = (selector or "").strip().lower()
        self.whois_enabled = bool(whois_enabled)
        self.whois_timeout = float(whois_timeout)
        self.rdap_fn = rdap_fn or whois.rdap_lookup
        self.resolver_id = (resolver_id or _settings("MX_RECON_RESOLVER_DEFAULT", "system") or "system").strip().lower()
        # Shared public resolvers cannot be attributed to us by blacklist
        # operators, so their RBL answers are untrustworthy (refused, or a
        # blanket "not listed"). Flagged in the log and in the report.
        self.resolver_public = is_public(self.resolver_id, _settings("MX_RECON_RESOLVERS_EXTRA", ""))
        if backend is not None:
            self.backend = backend
        else:
            nameservers, label = nameservers_for(
                self.resolver_id, _settings("MX_RECON_RESOLVERS_EXTRA", "")
            )
            self.backend = DnspythonBackend(
                timeout=float(_settings("MX_RECON_DNS_TIMEOUT", 3)),
                lifetime=float(_settings("MX_RECON_DNS_LIFETIME", 6)),
                nameservers=nameservers,
                label=label,
            )
        self.logs = []
        self.max_queries = max_queries
        self.deadline = deadline
        self.t0 = time.monotonic()
        self._qcount = 0
        self._budget_warned = False
        self._vault = []
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._recs = []

    # ---------------------------------------------------------- primitives
    def log(self, msg: str, cls: str = "info", ph: str | None = None) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.logs.append({"ts": ts, "cls": cls, "msg": msg, "ph": ph})

    def q(self, name: str, rtype: str, cat: str = "zone"):
        """Run one DNS query inside the query/time budget; capture the vault."""
        if self._qcount >= self.max_queries or (time.monotonic() - self.t0) > self.deadline:
            if not self._budget_warned:
                self._budget_warned = True
                self.log("query/time budget exhausted — remaining probes short-circuited", "warn")
            return "ERR", []
        self._qcount += 1
        status, records = self.backend.query(name, rtype)
        for r in records:
            self._vault.append(
                {"qname": name, "rtype": r["type"], "data": r["data"], "ttl": r.get("ttl"), "cat": cat}
            )
        return status, records

    def _qmap(self, jobs):
        """Parallel queries, results in input order."""
        return list(self._pool.map(lambda j: self.q(*j), jobs))

    def _rec(self, sev: int, tag: str, html_text: str) -> None:
        self._recs.append({"sev": sev, "tag": tag, "html": html_text})

    # ---------------------------------------------------------- 01 ENUM
    def _step_enum(self):
        self.log("[01] zone enumeration: A / AAAA / NS / SOA / TXT / CNAME", "dns", ph="enum")
        d = self.domain
        (q_a, q_aaaa, q_ns, q_soa, q_txt, q_cname, q_www) = self._qmap([
            (d, "A"), (d, "AAAA"), (d, "NS"), (d, "SOA"), (d, "TXT"), (d, "CNAME"),
            ("www." + d, "CNAME"),
        ])
        zone = {
            "a": _of(q_a[1], "A"),
            "aaaa": _of(q_aaaa[1], "AAAA"),
            "ns": _of(q_ns[1], "NS"),
            "soa": (_of(q_soa[1], "SOA") or [None])[0],
            "cname": (_of(q_cname[1], "CNAME") or [None])[0],
            "wwwCname": (_of(q_www[1], "CNAME") or [None])[0],
            "txt": _txts(q_txt[1]),
        }
        self.log(f"A={len(zone['a'])} AAAA={len(zone['aaaa'])} NS={len(zone['ns'])} TXT={len(zone['txt'])}", "dns")
        if zone["cname"]:
            self.log(f"apex CNAME detected: {_h(zone['cname'])} (RFC-1034 edge case)", "warn")
        return zone

    # ---------------------------------------------------------- 02 MX
    def _step_mx(self, zone):
        status, records = self.q(self.domain, "MX")
        mx = []
        for data in _of(records, "MX"):
            parts = data.split()
            if len(parts) < 2:
                continue
            try:
                prio = int(parts[0])
            except ValueError:
                continue
            mx.append({"prio": prio, "host": parts[1].rstrip(".")})
        mx.sort(key=lambda m: m["prio"])
        self.log(f"[02] MX enumeration → {len(mx)} record(s)", "dns", ph="mx")

        mx_info = {}
        if mx:
            def probe(m):
                a4 = self.q(m["host"], "A")
                a6 = self.q(m["host"], "AAAA")
                cn = self.q(m["host"], "CNAME")
                ips = _of(a4[1], "A") + _of(a6[1], "AAAA")
                ptr = None
                if ips:
                    ptrs = _of(self.q(rev_ip(ips[0]), "PTR")[1], "PTR")
                    ptr = ptrs[0].rstrip(".") if ptrs else None
                return m["host"], {"ips": ips, "ptr": ptr, "cname": bool(_of(cn[1], "CNAME"))}

            for host, info in self._pool.map(probe, mx):
                mx_info[host] = info

            cname_mx = [m for m in mx if mx_info[m["host"]]["cname"]]
            no_a = [m for m in mx if not mx_info[m["host"]]["ips"]]
            no_ptr = [m for m in mx if not mx_info[m["host"]]["ptr"]]
            if cname_mx:
                self.log(f"RFC 2181 violation: {len(cname_mx)} MX target(s) are CNAMEs", "warn")
                self._rec(1, "RFC", "MX target(s) point to a CNAME, violating RFC 2181 §10.3 — replace with direct A/AAAA records.")
            if no_a:
                hosts = ", ".join(_h(m["host"]) for m in no_a)
                self.log(f"{len(no_a)} MX host(s) unresolvable to IP", "fail")
                self._rec(0, "MX", f"MX host(s) with no A/AAAA record — mail delivery to them will fail: <span class=\"mono\">{hosts}</span>.")
            if no_ptr:
                self.log(f"{len(no_ptr)}/{len(mx)} MX host(s) missing PTR", "warn")
                self._rec(2, "PTR", "Missing reverse-DNS (PTR) on mail server IPs — many receivers greylist or reject mail from hosts without matching rDNS.")
        else:
            if zone["a"]:
                self.log("no MX records — implicit MX fallback on apex A (RFC 5321 §5.1)", "warn")
                self._rec(2, "MX", "No MX records published; senders fall back to the apex A record. Publish explicit MX records for reliability.")
            else:
                self.log("no MX and no A record — domain cannot receive mail", "fail")
                self._rec(0, "MX", "Domain has neither MX nor A records — it cannot receive email at all.")
        return mx, mx_info

    # ---------------------------------------------------------- 03 SPF
    def _spf_walk(self, domain: str, depth: int, seen: set, totals: dict) -> dict:
        node = {"domain": domain, "depth": depth, "children": [], "lookups": 0, "status": "OK", "all": None}
        status, records = self.q(domain, "TXT")
        rec = next((t for t in _txts(records) if _RE_SPF_REC.match(t)), None)
        if not rec:
            node["status"] = "NXDOMAIN" if status == "NXDOMAIN" else "NO SPF"
            return node
        jobs = []
        for raw in rec.split():
            m = _RE_INCLUDE.match(raw)
            if m:
                node["lookups"] += 1
                child = m.group(1).rstrip(".")
                if depth < 4 and child.lower() not in seen and totals["nodes"] < 25:
                    seen.add(child.lower())
                    totals["nodes"] += 1
                    jobs.append(child)
                else:
                    node["children"].append(
                        {"domain": child, "depth": depth + 1, "status": "TRUNC", "lookups": 0, "children": []}
                    )
                continue
            m = _RE_REDIRECT.match(raw)
            if m:
                node["lookups"] += 1
                child = m.group(1).rstrip(".")
                if depth < 4 and child.lower() not in seen and totals["nodes"] < 25:
                    seen.add(child.lower())
                    totals["nodes"] += 1
                    jobs.append(child)
                continue
            if _RE_A_MX_PTR.match(raw) or _RE_EXISTS.match(raw):
                node["lookups"] += 1
                continue
            if _RE_ALL.match(raw):
                node["all"] = raw
        subs = list(self._pool.map(lambda c: self._spf_walk(c, depth + 1, seen, totals), jobs))
        for sub in subs:
            node["children"].append(sub)
            node["lookups"] += sub["lookups"]
        return node

    @staticmethod
    def _collect_all(node):
        if node.get("all"):
            return node["all"]
        for child in node.get("children", []):
            found = Engine._collect_all(child)
            if found:
                return found
        return None

    def _step_spf(self, zone):
        spf_rec = next((t for t in zone["txt"] if _RE_SPF_REC.match(t)), None)
        tree = all_term = None
        spf_ips = 0
        if spf_rec:
            self.log("[03] SPF record located — walking include tree…", "dns", ph="spf")
            seen = {self.domain.lower()}
            totals = {"nodes": 1}
            tree = self._spf_walk(self.domain, 0, seen, totals)
            all_term = self._collect_all(tree)
            spf_ips = len(_RE_IP_RULE.findall(spf_rec))
            self.log(f"include-tree DNS lookups: {tree['lookups']}/10 budget", "dns")
            if all_term == "+all":
                self._rec(0, "SPF", "SPF ends in <span class=\"mono\">+all</span> — any host on the internet is authorised to send as this domain. Change to <span class=\"mono\">-all</span> immediately.")
            if all_term == "?all":
                self._rec(1, "SPF", "SPF ends in <span class=\"mono\">?all</span> (neutral) — receivers gain no enforcement signal. Prefer <span class=\"mono\">-all</span>.")
            if all_term == "~all":
                self._rec(3, "SPF", "SPF ends in <span class=\"mono\">~all</span> (softfail). Once fully mapped, tighten to <span class=\"mono\">-all</span> for hard enforcement.")
            if not all_term:
                self._rec(1, "SPF", "SPF record has no <span class=\"mono\">all</span> terminator — behaviour is undefined. Append <span class=\"mono\">-all</span>.")
            if tree["lookups"] > 10:
                self._rec(1, "SPF", f"SPF requires ~{tree['lookups']} DNS lookups — beyond the RFC 7208 limit of 10. Receivers may stop evaluation and treat SPF as absent. Flatten includes or use macros.")
                self.log(f"SPF exceeds 10-lookup RFC limit ({tree['lookups']})", "warn")
        else:
            self.log("no SPF record found", "fail", ph="spf")
            self._rec(0, "SPF", "No SPF record published. Any host can spoof mail from this domain. Start with <span class=\"mono\">v=spf1 mx -all</span> and add legitimate senders.")
        return {"record": spf_rec, "lookups": tree["lookups"] if tree else 0,
                "all": all_term, "ips": spf_ips, "tree": tree}

    # ---------------------------------------------------------- 04 DKIM
    def _step_dkim(self):
        sel_list = [self.selector] if self.selector else COMMON_SELECTORS
        if self.selector:
            self.log(f'[04] DKIM probe — selector "{_h(self.selector)}"', "dns", ph="dkim")
        else:
            self.log(f"[04] DKIM probe — auto-scanning {len(sel_list)} common selectors", "dns", ph="dkim")

        def probe(sel):
            txts = _txts(self.q(f"{sel}._domainkey.{self.domain}", "TXT")[1])
            rec = next((t for t in txts if _RE_DKIM_HINT.search(t) or _RE_DKIM_ANY_P.search(t)), None)
            return {"selector": sel, "raw": rec} if rec else None

        hits = [h for h in self._pool.map(probe, sel_list) if h]
        best_bits = 0
        for k in hits:
            algo, bits, revoked, _key = dkim_key_bits(k["raw"])
            k["algo"], k["bits"], k["revoked"] = algo, bits, revoked
            best_bits = max(best_bits, bits)
            self.log(
                f"key found: {_h(k['selector'])}._domainkey — "
                + ("REVOKED (empty p=)" if revoked else f"{algo.upper()} ~{bits}-bit"),
                "warn" if revoked else "ok",
            )
        if not hits:
            self.log("no DKIM keys discovered", "fail")
            if self.selector:
                self._rec(1, "DKIM", f"No DKIM record at <span class=\"mono\">{_h(self.selector)}._domainkey</span>. Verify the selector with your provider or leave the field blank to auto-probe.")
            else:
                self._rec(1, "DKIM", "No DKIM key found among 18 common selectors. Unsigned mail is trivially spoofable and scores poorly with Gmail/Outlook. Publish a 2048-bit key.")
        elif best_bits == 1024:
            self._rec(2, "DKIM", "A 1024-bit DKIM key was detected — factorable by well-resourced adversaries. Rotate to 2048-bit.")
        return hits

    # ---------------------------------------------------------- 05 DMARC
    def _step_dmarc(self):
        txts = _txts(self.q(f"_dmarc.{self.domain}", "TXT")[1])
        dm_rec = next((t for t in txts if re.search(r"v=DMARC1", t, re.I)), None)
        dm = None
        if dm_rec:
            dm = parse_dmarc(dm_rec)
            self.log(f"[05] DMARC located — policy={_h(dm.get('p', '?'))} pct={_h(dm.get('pct', '100'))}", "dns", ph="dmarc")
            if (dm.get("p") or "").lower() == "none":
                self._rec(1, "DMARC", "DMARC policy is <span class=\"mono\">p=none</span> (monitor only). Forgery is not blocked — advance to <span class=\"mono\">quarantine</span>, then <span class=\"mono\">reject</span>.")
            if dm.get("p") and not dm.get("rua"):
                self._rec(2, "DMARC", "No <span class=\"mono\">rua=</span> aggregate reporting address — you are flying blind on authentication failures.")
            if dm.get("pct") and str(dm["pct"]).isdigit() and int(dm["pct"]) < 100:
                self._rec(3, "DMARC", f"DMARC applies to only {_h(dm['pct'])}% of messages. Ramp to <span class=\"mono\">pct=100</span> when reports are clean.")
        else:
            self.log(f"no DMARC record at _dmarc.{_h(self.domain)}", "fail", ph="dmarc")
            self._rec(0, "DMARC", f"No DMARC record. Spoofed mail from this domain faces zero policy enforcement. Minimum viable: <span class=\"mono\">v=DMARC1; p=none; rua=mailto:dmarc@{_h(self.domain)}</span>.")
        return {"record": dm_rec, "parsed": dm}

    # ---------------------------------------------------------- 09 RELAY EXPOSURE
    def _step_relay(self, spf, dmarc):
        """Who else can send as this domain? (echo-spoofing exposure)

        EchoSpoofing-style abuse needs no broken record: it hands mail to a relay
        the domain already authorises, and the relay re-sends it with its own SPF
        authorisation and DKIM signature. This step shows how much sending
        authority is delegated, and which gaps let a relay-injected message in.
        """
        result = relays.analyse(spf, {**(dmarc.get("parsed") or {}), "record": dmarc.get("record") or ""})
        if not spf.get("record"):
            return result          # the SPF step already raised the missing record
        self.log(
            f"relay/echo-spoof exposure — {result['verdict']}"
            + (f" · {len(result['findings'])} finding(s)" if result["findings"] else "")
            + (f" · relay(s): {', '.join(r['label'] for r in result['relays'])}" if result["relays"] else ""),
            "warn" if result["verdict"] in ("EXPOSED", "ELEVATED") else "dns",
        )
        for finding in result["findings"]:
            if finding["sev"] > 2:
                continue           # advisory only: shown on the card, not as a directive
            self._rec(finding["sev"], "RELAY", f"{finding['title']} — {finding['detail']} {finding['fix']}")
        return result

    # ---------------------------------------------------------- 06 RBL
    def _step_rbl(self, mx, mx_info):
        ip_zones, dom_zones = active_rbl_zones()
        ips_seq = []
        for m in mx:
            ips_seq.extend(mx_info[m["host"]]["ips"])
        probe_ips = list(dict.fromkeys(ips_seq))[:3]
        custom_ip = sum(1 for z in ip_zones if z.get("custom"))
        custom_dom = sum(1 for z in dom_zones if z.get("custom"))
        self.log(
            f"[06] blacklist sweep — {len(probe_ips)} IP(s) × {len(ip_zones)} zones"
            + (f" ({custom_ip} custom)" if custom_ip else "")
            + f", {len(dom_zones)} domain lists"
            + (f" ({custom_dom} custom)" if custom_dom else ""),
            "dns", ph="rbl",
        )
        if self.resolver_public:
            self.log(
                f"resolver '{self.resolver_id}' is a shared public resolver — blacklist operators cannot "
                "attribute the query to us, so Spamhaus may refuse it (BLOCKED) or answer a blanket "
                "NXDOMAIN that looks clean. Treat these rows as unverified; run the T-01 RBL self-test "
                "(diagnostics panel) to see which resolvers actually answer.",
                "warn", ph="rbl",
            )

        def ip_row(lst):
            cells = []
            for ip in probe_ips:
                state, code = classify_rbl(*self.q(f"{rev_ip(ip)}.{lst['zone']}", "A", cat="rbl"))
                cells.append({"ip": ip, "status": state, "code": code})
            return {"zone": lst["zone"], "name": lst["name"], "url": lst["url"],
                    "custom": bool(lst.get("custom")), "cells": cells}

        def dom_row(lst):
            state, code = classify_rbl(*self.q(f"{self.domain}.{lst['zone']}", "A", cat="rbl"))
            return {"zone": lst["zone"], "name": lst["name"], "url": lst["url"],
                    "custom": bool(lst.get("custom")), "status": state, "code": code}

        ip_matrix = list(self._pool.map(ip_row, ip_zones))
        dom_matrix = list(self._pool.map(dom_row, dom_zones))

        listed = sum(1 for r in ip_matrix for c in r["cells"] if c["status"] == "listed")
        listed += sum(1 for r in dom_matrix if r["status"] == "listed")
        blocked = sum(1 for r in ip_matrix for c in r["cells"] if c["status"] in ("blocked", "err"))
        blocked += sum(1 for r in dom_matrix if r["status"] in ("blocked", "err"))

        if listed:
            self.log(f"{listed} LISTING(S) detected — reputation compromised", "fail")
            self._rec(0, "RBL", f"{listed} blacklist listing(s) detected. Identify the cause (compromised host, open relay, spam run), stop the bleeding, then request delisting via each zone's removal portal.")
        elif blocked:
            self.log(f"no listings detected — {blocked} zone check(s) inconclusive (resolver blocked)", "warn")
            refused = blocked_rbl_zones(ip_matrix, dom_matrix)
            if refused:
                self.log(rbl_blocked_hint(refused), "warn", ph="rbl")
        else:
            self.log("all zone checks returned clean", "ok")
        if any(r["status"] == "listed" for r in dom_matrix):
            self._rec(0, "SPAM", "The domain itself appears on spam-domain lists (Spamhaus DBL / SURBL) — typically means spamvertised URLs or malicious redirects reference this host.")
        return ip_matrix, dom_matrix, probe_ips, listed, blocked

    # ---------------------------------------------------------- extras
    def _step_extras(self):
        (q_sts, q_tls, q_bimi) = self._qmap([
            (f"_mta-sts.{self.domain}", "TXT"),
            (f"_smtp._tls.{self.domain}", "TXT"),
            (f"default._bimi.{self.domain}", "TXT"),
        ])
        sts = next((t for t in _txts(q_sts[1]) if _RE_STS.search(t)), None)
        tlsr = next((t for t in _txts(q_tls[1]) if _RE_TLSRPT.search(t)), None)
        bimi = next((t for t in _txts(q_bimi[1]) if _RE_BIMI.search(t)), None)
        if not sts:
            self._rec(3, "TLS", "No MTA-STS policy — opportunistic TLS downgrade attacks remain possible inbound. Consider <span class=\"mono\">_mta-sts TXT + policy host</span>.")
        if not tlsr:
            self._rec(3, "TLS", "No TLS-RPT record — you receive no visibility into inbound TLS delivery failures.")
        return {"mtasts": sts, "tlsrpt": tlsr, "bimi": bimi}

    # ---------------------------------------------------------- 07 CONTROL
    def _step_control(self, zone):
        self.log("[07] domain control — NS · SOA · WHOIS/RDAP · DNSSEC", "dns", ph="control")
        ns_names = [n.rstrip(".") for n in zone["ns"]]

        def probe(ns):
            ips = _of(self.q(ns, "A")[1], "A") + _of(self.q(ns, "AAAA")[1], "AAAA")
            return {"name": ns, "ips": ips, "provider": whois.provider_for(ns)}

        nameservers = list(self._pool.map(probe, ns_names)) if ns_names else []
        providers = sorted({n["provider"] for n in nameservers})
        if nameservers:
            shown = ", ".join(f"{n['name']} ({n['provider']})" for n in nameservers[:4])
            if len(nameservers) > 4:
                shown += f" +{len(nameservers) - 4} more"
            self.log(f"NS: {shown}", "dns")
            self.log(f"DNS provider(s): {', '.join(providers)}", "dns")
        else:
            self.log("no NS records published — delegation cannot resolve", "fail")
            self._rec(1, "DNS", "No NS records are published for the apex — the domain has no working delegation.")

        soa_primary = (zone["soa"] or "").split(" ")[0].rstrip(".") or None
        soa_in_ns = bool(soa_primary) and soa_primary.lower() in [n.lower() for n in ns_names]
        if soa_primary and ns_names and not soa_in_ns:
            self._rec(2, "DNS", f"The SOA primary nameserver (<span class=\"mono\">{_h(soa_primary)}</span>) is not one of "
                               "the delegated NS records — zone transfers and NOTIFY messages may fail.")

        dnskey_records = _of(self.q(self.domain, "DNSKEY")[1], "DNSKEY")
        dnssec = {
            "registry_signed": None,
            "dnskey_published": bool(dnskey_records),
            "dnskey_count": len(dnskey_records),
        }
        who = {"enabled": self.whois_enabled}
        if self.whois_enabled:
            try:
                who.update(self.rdap_fn(self.domain, timeout=self.whois_timeout) or {})
            except Exception:  # noqa: BLE001 — WHOIS must never break a scan
                who["error"] = "lookup failed"
            if who.get("error"):
                self.log(f"WHOIS/RDAP: {who['error']}", "warn")
            else:
                registrar = who.get("registrar") or "unknown registrar"
                self.log("WHOIS: registrar " + _h(registrar)
                         + (f" (IANA {_h(who['registrar_id'])})" if who.get("registrar_id") else ""), "dns")
                events = who.get("events") or {}
                if events.get("registration"):
                    self.log(f"registered {events['registration'][:10]}", "dns")
                if events.get("expiration"):
                    days = _days_until(events["expiration"])
                    who["days_to_expiry"] = days
                    self.log(f"expires {events['expiration'][:10]}"
                             + (f" (in {days} days)" if days is not None else ""),
                             "warn" if (days is not None and days <= 90) else "dns")
                    if days is not None and days <= 30:
                        self._rec(0, "WHOIS", f"The domain registration expires in {days} day(s) "
                                              f"(<span class=\"mono\">{_h(events['expiration'][:10])}</span>). Renew now — "
                                              "an expired domain stops receiving mail entirely.")
                    elif days is not None and days <= 90:
                        self._rec(2, "WHOIS", f"Domain registration expires in {days} day(s) "
                                              f"(<span class=\"mono\">{_h(events['expiration'][:10])}</span>). Renew well "
                                              "before expiry to avoid an outage.")
                statuses = [str(s).lower() for s in (who.get("status") or [])]
                for bad in ("pending delete", "redemption period", "client hold", "server hold"):
                    if any(bad in s for s in statuses):
                        self._rec(0, "WHOIS", f"Registry status contains <span class=\"mono\">{_h(bad)}</span> — the domain "
                                              "is suspended or about to be deleted, so mail will stop.")
                registry_ns = [n.lower() for n in (who.get("nameservers") or [])]
                live_ns = [n.lower() for n in ns_names]
                if registry_ns and live_ns:
                    missing = [n for n in registry_ns if n not in live_ns]
                    extra = [n for n in live_ns if n not in registry_ns]
                    if missing or extra:
                        parts = []
                        if missing:
                            parts.append("the registry lists " + ", ".join(_h(n) for n in missing)
                                         + " which the zone does not publish")
                        if extra:
                            parts.append("the zone publishes " + ", ".join(_h(n) for n in extra)
                                         + " which the registry does not list")
                        self._rec(1, "DNS", "Registry and live nameservers disagree: " + "; ".join(parts)
                                            + ". Delegation is out of sync (a recent change may not have propagated, or the "
                                              "domain is managed somewhere else).")
                    else:
                        self.log("delegation confirmed: registry nameservers match the live zone", "ok")
                if who.get("dnssec") is not None:
                    dnssec["registry_signed"] = bool(who["dnssec"])

        if dnssec["registry_signed"] is True and not dnssec["dnskey_published"]:
            self._rec(1, "DNSSEC", "The registry publishes a DS record but the zone serves no DNSKEY — DNSSEC is broken "
                                   "and validating resolvers will fail to resolve this domain.")
        elif dnssec["registry_signed"] is False and dnssec["dnskey_published"]:
            self._rec(3, "DNSSEC", "The zone is signed (DNSKEY published) but no DS exists at the registry, so nobody "
                                   "validates the signature — an 'island of security'.")
        elif dnssec["registry_signed"] and dnssec["dnskey_published"]:
            self.log("DNSSEC: signed and validated end-to-end", "ok")
        elif not dnssec["dnskey_published"]:
            self._rec(3, "DNSSEC", "The zone is not DNSSEC-signed, so an on-path attacker can forge or strip "
                                   "the SPF/DMARC/DKIM answers receivers rely on when judging whether mail "
                                   "from this domain is genuine. Most DNS hosts (Cloudflare, Route 53, Azure "
                                   "DNS) enable it with one click.")

        return {
            "nameservers": nameservers,
            "providers": providers,
            "soa_primary": soa_primary,
            "soa_primary_in_ns": soa_in_ns,
            "dnssec": dnssec,
            "whois": who,
        }

    # ---------------------------------------------------------- 07 REPORT
    def _score(self, spf, dkim_hits, dmarc, mx, mx_info, zone, listed, blocked, probe_ips):
        s_spf = s_dkim = s_dm = s_mx = s_rbl = 0
        if spf["record"]:
            s_spf = {"-all": 25, "~all": 15, "?all": 5}.get(spf["all"], 0)
            if spf["lookups"] > 10:
                s_spf = min(s_spf, 8)
        if dkim_hits:
            best = max(k["bits"] for k in dkim_hits)
            s_dkim = 20 if best >= 2048 else 10 if best >= 1024 else 2
        if dmarc["parsed"]:
            p = (dmarc["parsed"].get("p") or "").lower()
            s_dm = 30 if p == "reject" else 22 if p == "quarantine" else 8
        if mx:
            ok = sum(1 for m in mx if mx_info[m["host"]]["ips"])
            s_mx = 15 if ok == len(mx) else round(15 * ok / len(mx))
        else:
            s_mx = 5 if zone["a"] else 0
        if listed:
            s_rbl = 0
        else:
            s_rbl = 6 if (blocked and not probe_ips) else 10
        score = s_spf + s_dkim + s_dm + s_mx + s_rbl
        if score >= 90:
            verdict = "HARDENED"
        elif score >= 70:
            verdict = "STRONG"
        elif score >= 50:
            verdict = "MODERATE"
        elif score >= 30:
            verdict = "WEAK"
        else:
            verdict = "CRITICAL"
        return score, verdict, {"spf": s_spf, "dkim": s_dkim, "dmarc": s_dm, "mx": s_mx, "rbl": s_rbl}

    def _finalize(self, spf, dkim_hits, dmarc, relay, mx, mx_info, zone, protocols, control,
                  ip_matrix, dom_matrix, probe_ips, listed, blocked):
        score, verdict, breakdown = self._score(
            spf, dkim_hits, dmarc, mx, mx_info, zone, listed, blocked, probe_ips
        )
        seen = set()
        inventory = []
        for r in self._vault:
            key = f"{r['qname']}|{r['rtype']}|{r['data']}"
            if key in seen:
                continue
            seen.add(key)
            inventory.append({"type": r["rtype"], "name": r["qname"], "value": r["data"],
                              "ttl": r["ttl"], "source": r["cat"]})
        self.log(f"[08] record vault captured {len(self._vault)} answer(s) — {len(inventory)} unique", "dns", ph="report")

        recs = sorted(self._recs, key=lambda r: r["sev"])
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        report = {
            "target": self.domain,
            "selector": self.selector or "(auto)",
            "started": now,
            "finished": now,
            "ms": int((time.monotonic() - self.t0) * 1000),
            "resolver": self.backend.describe() if hasattr(self.backend, "describe") else "system resolver",
            "resolver_id": self.resolver_id,
            "resolver_public": self.resolver_public,
            "score": score,
            "verdict": verdict,
            "breakdown": breakdown,
            "mx": [{"prio": m["prio"], "host": m["host"], **mx_info[m["host"]]} for m in mx],
            "spf": spf,
            "dkim": [{"selector": k["selector"], "algo": k["algo"], "bits": k["bits"],
                      "revoked": k["revoked"], "record": k["raw"], "raw": k["raw"]} for k in dkim_hits],
            "dmarc": dmarc,
            "blacklists": {"ip": ip_matrix, "domain": dom_matrix},
            "zone": {"a": zone["a"], "aaaa": zone["aaaa"], "ns": zone["ns"], "soa": zone["soa"],
                     "cname": zone["cname"], "wwwCname": zone["wwwCname"]},
            "protocols": protocols,
            "control": control,
            "relay": relay,
            "recommendations": [
                {"sev": r["sev"], "tag": r["tag"], "html": r["html"],
                 "text": _RE_TAGS.sub("", r["html"])}
                for r in recs
            ],
            "inventory": inventory,
        }
        cls = "ok" if score >= 70 else "warn" if score >= 40 else "fail"
        self.log(
            f"──── SCAN COMPLETE — POSTURE {score}/100 ({verdict}) · {len(recs)} DIRECTIVE(S) · "
            f"{len(inventory)} RECORDS CAPTURED ────", cls,
        )
        return report

    # ---------------------------------------------------------- orchestrator
    def run(self):
        try:
            self.log(f"──── ENGAGING TARGET: {_h(self.domain).upper()} ────", "info")
            zone = self._step_enum()
            mx, mx_info = self._step_mx(zone)
            spf = self._step_spf(zone)
            dkim_hits = self._step_dkim()
            dmarc = self._step_dmarc()
            relay = self._step_relay(spf, dmarc)
            ip_matrix, dom_matrix, probe_ips, listed, blocked = self._step_rbl(mx, mx_info)
            protocols = self._step_extras()
            control = self._step_control(zone)
            report = self._finalize(spf, dkim_hits, dmarc, relay, mx, mx_info, zone, protocols, control,
                                    ip_matrix, dom_matrix, probe_ips, listed, blocked)
            return report, self.logs
        finally:
            self._pool.shutdown(wait=False, cancel_futures=True)

