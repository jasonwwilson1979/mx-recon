"""
MX-RECON diagnostics — explain why a specific message landed in spam.

Takes the parsed headers of a delivered message and cross-checks them against
live DNS: the DKIM selector actually used, the SPF record of the envelope
domain (evaluated against the sending IP), the DMARC policy and alignment,
reverse DNS and IP reputation. Produces a ranked list of root causes with
evidence and fixes, plus a 0-100 deliverability risk score.
"""
from __future__ import annotations

import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import escape as esc

from .engine import DnspythonBackend, active_rbl_zones, classify_rbl, rev_ip
from .engine import _settings as setting
from .resolvers import nameservers_for
from .headers import parse_message_headers

# ------------------------------------------------------------------ SPF eval

_SPF_MECH = re.compile(r"^([+~?-])?([a-z0-9]+)(?::(.*))?$", re.I)
_RESULT_OF = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def _net_contains(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _data(record):
    """Accept either normalised record dicts or bare strings from a query fn."""
    return record["data"] if isinstance(record, dict) else record


def org_domain(domain: str):
    """Very small organisational-domain helper (last two labels)."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


class SpfEvaluator:
    """Bounded, best-effort RFC 7208 evaluator.

    Supports ip4/ip6/a/mx/include/all and the redirect modifier. Macros are not
    expanded (the pasted headers do not give us the SMTP session context), and
    ptr is ignored per RFC 7208 §5.5. Lookup/depth limits mirror the RFC's
    10-DNS-query budget.
    """

    def __init__(self, query, max_lookups: int = 10, max_depth: int = 8):
        self.query = query
        self.max_lookups = max_lookups
        self.max_depth = max_depth

    def evaluate(self, domain: str, ip: str) -> dict:
        state = {"lookups": 0, "trace": []}
        status, records = self.query(domain, "TXT")
        spf_records = [d for d in (_data(r) for r in records) if d.lower().startswith("v=spf1")]
        if len(spf_records) > 1:
            return {"result": "permerror", "mechanism": "multiple v=spf1 records",
                    "lookups": 0, "trace": [], "record": spf_records[0]}
        result, mechanism = self._eval(domain, ip, state, 0, frozenset())
        return {
            "result": result,
            "mechanism": mechanism,
            "lookups": state["lookups"],
            "trace": state["trace"],
            "record": spf_records[0] if spf_records else None,
        }

    def _eval(self, domain, ip, state, depth, seen):
        if depth > self.max_depth or domain in seen:
            return "permerror", "include/redirect loop"
        seen = seen | {domain}
        _, records = self.query(domain, "TXT")
        record = next((d for d in (_data(r) for r in records) if d.lower().startswith("v=spf1")), None)
        if not record:
            return "none", None

        terms = record.split()[1:]
        redirect = None
        for term in terms:
            if term.lower().startswith("redirect="):
                redirect = term.split("=", 1)[1]
                continue
            m = _SPF_MECH.match(term)
            if not m:
                continue
            qualifier = m.group(1) or "+"
            mech = m.group(2).lower()
            arg = m.group(3) or ""

            if mech == "all":
                return _RESULT_OF[qualifier], term

            if mech in ("ip4", "ip6"):
                if arg and _net_contains(arg, ip):
                    return _RESULT_OF[qualifier], term
                continue

            if mech == "include":
                if state["lookups"] >= self.max_lookups:
                    return "permerror", "DNS lookup limit exceeded"
                state["lookups"] += 1
                state["trace"].append(f"include:{arg}")
                res, _ = self._eval(arg.rstrip("."), ip, state, depth + 1, seen)
                if res == "pass":
                    return _RESULT_OF[qualifier], term
                if res in ("permerror", "temperror"):
                    return res, term
                if res == "none":
                    return "permerror", f"include:{arg} has no SPF record"
                continue

            if mech in ("a", "mx"):
                if state["lookups"] >= self.max_lookups:
                    return "permerror", "DNS lookup limit exceeded"
                state["lookups"] += 1
                target, _, cidr = arg.partition("/")
                target = target or domain
                names = [target]
                if mech == "mx":
                    _, mx_records = self.query(target, "MX")
                    names = [d.split()[-1].rstrip(".") for d in (_data(r) for r in mx_records) if " " in d] or [target]
                state["trace"].append(f"{mech}:{target}")
                for name in names:
                    for rtype in ("A", "AAAA"):
                        _, addrs = self.query(name, rtype)
                        for addr in (_data(a) for a in addrs):
                            if cidr:
                                if _net_contains(f"{addr}/{cidr}", ip):
                                    return _RESULT_OF[qualifier], term
                            elif addr == ip:
                                return _RESULT_OF[qualifier], term
                continue

            if mech == "exists":
                state["lookups"] += 1  # macros not expanded — cannot be evaluated
                continue
            # ptr is deprecated (RFC 7208 §5.5) and deliberately ignored

        if redirect:
            if state["lookups"] >= self.max_lookups:
                return "permerror", "DNS lookup limit exceeded"
            state["lookups"] += 1
            res, _ = self._eval(redirect.rstrip("."), ip, state, depth + 1, seen)
            return res, f"redirect={redirect}"
        return "neutral", None


# --------------------------------------------------------------- diagnostics


class Diagnoser:
    """Cross-check a delivered message's headers against live DNS posture."""

    def __init__(self, raw_headers: str, domain: str = "", backend=None, resolver_id: str = "",
                 max_workers: int = 12):
        self.parsed = parse_message_headers(raw_headers)
        self.resolver_id = (resolver_id or setting("MX_RECON_RESOLVER_DEFAULT", "system") or "system").strip().lower()
        if backend is not None:
            self.backend = backend
        else:
            nameservers, label = nameservers_for(self.resolver_id, setting("MX_RECON_RESOLVERS_EXTRA", ""))
            self.backend = DnspythonBackend(
                timeout=float(setting("MX_RECON_DNS_TIMEOUT", 3)),
                lifetime=float(setting("MX_RECON_DNS_LIFETIME", 6)),
                nameservers=nameservers,
                label=label,
            )
        self.override = (domain or "").strip().lower() or None
        self.logs = []
        self.dns_checks = []
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._t0 = time.monotonic()
        self.domain = (
            self.override
            or self.parsed["from"].get("domain")
            or self.parsed.get("mail_from_domain")
        )

    # ------------------------------------------------------------ primitives
    def log(self, msg: str, cls: str = "info") -> None:
        self.logs.append({
            "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "cls": cls,
            "msg": msg,
            "ph": None,
        })

    def q(self, name: str, rtype: str, note: str = ""):
        status, records = self.backend.query(name, rtype)
        self.dns_checks.append({
            "query": name,
            "type": rtype,
            "status": status,
            "result": (", ".join(r["data"] for r in records)[:400] or "—"),
            "note": note,
        })
        return status, records

    def _txt(self, name: str):
        return [r["data"] for r in self.q(name, "TXT")[1]]

    # ------------------------------------------------------------- DKIM
    def _check_dkim(self):
        from .engine import dkim_key_bits

        out = []
        for sig in self.parsed["signatures"]:
            d, s = sig.get("domain"), sig.get("selector")
            entry = {
                "source": sig["source"],
                "domain": d,
                "selector": s,
                "algo": sig["algo"],
                "canon": sig["canon"],
                "signed_headers": sig["signed_headers"],
                "signature_bits": sig["signature_bits"],
                "covers_from": "from" in sig["signed_headers"],
                "unknown_tags": sig["unknown_tags"],
                "dns_status": None,
                "dns_record": None,
                "dns_bits": None,
                "dns_revoked": None,
                "internal": sig["source"] == "X-Google-DKIM-Signature",
            }
            if d and s:
                name = f"{s}._domainkey.{d}"
                status, records = self.q(name, "TXT", "DKIM public key for the selector used in the message")
                txt = next(
                    (r["data"] for r in records
                     if "v=dkim1" in r["data"].lower() or "p=" in r["data"].lower()),
                    None,
                )
                entry["dns_status"] = status
                entry["dns_record"] = txt
                if txt:
                    _algo, bits, revoked, _key = dkim_key_bits(txt)
                    entry["dns_bits"], entry["dns_revoked"] = bits, revoked
                self.log(
                    f"DKIM {name}: " + ("published" + (f" (~{entry['dns_bits']}-bit)" if entry["dns_bits"] else "")
                                        if txt else "NO RECORD"),
                    "ok" if txt else "fail",
                )
            out.append(entry)
        return out

    # -------------------------------------------------------------- SPF
    def _check_spf(self):
        p = self.parsed
        ip = p.get("sending_ip")
        spf_domain = p.get("mail_from_domain") or self.domain
        reported = p["final_auth"]["methods"].get("spf") if p.get("final_auth") else None
        info = {
            "ip": ip,
            "ip_source": p.get("sending_ip_source"),
            "helo": p.get("helo"),
            "mail_from": p.get("mail_from"),
            "domain": spf_domain,
            "reported": (reported or {}).get("result"),
            "reported_reason": (reported or {}).get("reason"),
            "received_spf": p["received_spf"][0]["result"] if p["received_spf"] else None,
            "record": None,
            "evaluated": None,
            "mechanism": None,
            "lookups": None,
            "trace": [],
        }
        if ip and spf_domain:
            result = SpfEvaluator(self.q).evaluate(spf_domain, ip)
            info.update({
                "record": result["record"],
                "evaluated": result["result"],
                "mechanism": result["mechanism"],
                "lookups": result["lookups"],
                "trace": result["trace"],
            })
            self.log(
                f"SPF {spf_domain} vs {ip} → {result['result']}"
                + (f" ({result['mechanism']})" if result["mechanism"] else ""),
                "ok" if result["result"] == "pass" else "warn",
            )
        return info

    # ------------------------------------------------------------- DMARC
    def _check_dmarc(self):
        from .engine import parse_dmarc

        record = next((t for t in self._txt(f"_dmarc.{self.domain}") if "v=dmarc1" in t.lower()), None)
        parsed = parse_dmarc(record) if record else None
        reported = self.parsed["final_auth"]["methods"].get("dmarc") if self.parsed.get("final_auth") else None
        from_dom = self.domain
        dkim_aligned = any(
            org_domain(sig.get("domain") or "") == org_domain(from_dom)
            for sig in self.parsed["signatures"] if sig.get("domain")
        )
        spf_aligned = org_domain(self.parsed.get("mail_from_domain") or "") == org_domain(from_dom)
        if record:
            self.log(f"DMARC _dmarc.{self.domain}: p={(parsed or {}).get('p', '?')}", "dns")
        else:
            self.log(f"DMARC _dmarc.{self.domain}: NOT PUBLISHED", "fail")
        return {
            "record": record,
            "parsed": parsed,
            "reported": (reported or {}).get("result"),
            "reported_reason": (reported or {}).get("reason"),
            "alignment": {"dkim": dkim_aligned, "spf": spf_aligned},
        }

    # ---------------------------------------------------------- reputation
    def _check_reputation(self):
        ip = self.parsed.get("sending_ip")
        info = {"ip": ip, "ptr": None, "fcrdns": None, "rbl": []}
        if not ip:
            return info
        ptrs = [r["data"] for r in self.q(rev_ip(ip), "PTR", "reverse DNS of the sending IP")[1]]
        via_fallback = getattr(self.backend, "last_source", "system") == "fallback"
        if via_fallback:
            self.dns_checks[-1]["note"] += (
                " — answered by the fallback resolver (the system resolver returned no data)"
            )
        ptr = ptrs[0].rstrip(".") if ptrs else None
        info["ptr"] = ptr
        info["ptr_fallback_used"] = via_fallback
        info["ptr_fallback_available"] = bool(getattr(self.backend, "fallback_enabled", False))
        if ptr:
            info["fcrdns"] = ip in [r["data"] for r in self.q(ptr, "A")[1]]

        def probe(zone):
            state, code = classify_rbl(*self.q(f"{rev_ip(ip)}.{zone}", "A"))
            return {"zone": zone, "status": state, "code": code}

        ip_zones, _dom_zones = active_rbl_zones()
        info["rbl"] = list(self._pool.map(
            lambda l: {**probe(l["zone"]), "name": l["name"], "url": l["url"],
                       "custom": bool(l.get("custom"))}, ip_zones
        ))
        listed = [r["zone"] for r in info["rbl"] if r["status"] == "listed"]
        summary = ("LISTED on " + ", ".join(listed)) if listed else "no listings"
        self.log(
            f"IP reputation {ip}: {summary} · rDNS {ptr or 'MISSING'}"
            + ("" if ptr is None else (" (forward-confirmed)" if info["fcrdns"] else " (does not forward-confirm)"))
            + (" · via fallback resolver" if via_fallback else ""),
            "fail" if listed else ("warn" if not ptr else "ok"),
        )
        return info

    # -------------------------------------------------------------- analysis
    def _analyse(self, dkim, spf, dmarc, reputation):
        p = self.parsed
        causes, passing = [], []

        def cause(sev, tag, title, evidence, fix):
            causes.append({"sev": sev, "tag": tag, "title": title, "evidence": evidence, "fix": fix})

        final = p.get("final_auth") or {}
        methods = final.get("methods", {})
        gw_dkim = methods.get("dkim") or {}
        gw_spf = methods.get("spf") or {}
        gw_dkim_result = gw_dkim.get("result")
        gw_spf_result = gw_spf.get("result")
        primary = [d for d in dkim if not d["internal"]]

        # ------------------------------------------------------------- DKIM
        if not primary:
            cause(1, "DKIM", "Message carries no DKIM signature for the sending domain",
                  ["Only intermediate-hop signatures were found; receivers cannot verify the sender."],
                  "Enable DKIM signing on the sending platform and publish the public key at &lt;selector&gt;._domainkey.&lt;domain&gt;.")
        for d in primary:
            sel = f"{d['selector']}._domainkey.{d['domain']}" if d["selector"] and d["domain"] else None
            gw_reason = gw_dkim.get("reason") or ""
            gw_note = f" ({esc(gw_reason)})" if gw_reason else ""
            failed = gw_dkim_result in ("fail", "hardfail", "permerror")
            if failed and d["dns_record"] is None and sel:
                cause(0, "DKIM", "DKIM failed: the signing selector has no public key in DNS",
                      [f"The receiving gateway reported <b>dkim={esc(gw_dkim_result)}</b>{gw_note}.",
                       f"The message was signed with <b>d={esc(d['domain'])}; s={esc(d['selector'])}</b>, but a live "
                       f"lookup of <b>{esc(sel)}</b> returned <b>{esc(d['dns_status'])}</b> — no key exists.",
                       "Without a key the signature cannot be verified, so it is a hard fail and the message "
                       "loses its strongest trust signal."],
                      f"Publish the DKIM public key at <b>{esc(sel)}</b> (export it from the sending platform / "
                      "ESP), or sign with a selector that already resolves. Re-run this diagnosis afterwards.")
            elif failed:
                detail = (
                    f"A key <b>is</b> published at <b>{esc(sel)}</b>"
                    + (f" (~{d['dns_bits']}-bit)" if d["dns_bits"] else "")
                    + ", so this is not a missing key."
                ) if sel else "The selector could not be derived from the signature."
                cause(0, "DKIM", "DKIM signature failed verification",
                      [f"Gateway verdict: <b>dkim={esc(gw_dkim_result)}</b>{gw_note}.", detail,
                       "Usual causes: the key was rotated after signing, a header listed in h= was modified in "
                       "transit, or the body changed (bh mismatch)."],
                      "Re-sign a test message and verify end-to-end; when rotating keys keep the previous "
                      "selector published until old mail has drained.")
            elif gw_dkim_result == "pass":
                passing.append(f"DKIM <b>pass</b> for {esc(d['domain'])}"
                               + (f" (selector {esc(d['selector'])})" if d["selector"] else ""))
            if d["dns_record"] and d["dns_bits"] and d["dns_bits"] < 2048:
                cause(2, "DKIM", f"DKIM key is only ~{d['dns_bits']}-bit",
                      [f"<b>{esc(sel)}</b> publishes a {d['dns_bits']}-bit key.",
                       "Short RSA keys are factorable and are scored down by some receivers."],
                      "Rotate to a 2048-bit (or stronger) DKIM key.")
            if not d["covers_from"]:
                cause(1, "DKIM", "DKIM signature does not cover the From header",
                      ["The h= tag omits <b>from</b>; RFC 6376 requires From to be signed."],
                      "Re-configure the signer to include From in the signed headers.")
            if d["signature_bits"] and d["dns_bits"] and d["signature_bits"] != d["dns_bits"]:
                cause(2, "DKIM", "Signature length does not match the published key size",
                      [f"The signature implies ~{d['signature_bits']}-bit but the DNS key is ~{d['dns_bits']}-bit "
                       "— the key may have been rotated since the message was signed."],
                      "Confirm which selector is active and keep old keys published during rotation.")
            if d["unknown_tags"]:
                cause(3, "DKIM", "Non-standard DKIM tag(s): " + esc(", ".join(d["unknown_tags"])),
                      [f"<b>{esc(d['source'])}</b> carries tag(s) not defined by RFC 6376: "
                       f"{esc(', '.join(d['unknown_tags']))}.",
                       "Often indicates a non-standard signer or a header mangled in transit."],
                      "Have the sending platform re-issue the signature with standard tags.")

        # -------------------------------------------------------------- SPF
        spf_result = spf.get("evaluated")
        spf_domain = spf.get("domain") or self.domain
        spf_ip = spf.get("ip")
        if spf_result == "pass":
            passing.append(f"SPF <b>pass</b> — {esc(spf_ip)} is authorised by {esc(spf_domain)}"
                           + (f" ({esc(spf.get('mechanism'))})" if spf.get("mechanism") else ""))
        elif spf_result in ("fail", "hardfail"):
            cause(0, "SPF", "Sending IP is not authorised by the envelope domain's SPF record",
                  [f"Live evaluation of <b>{esc(spf_domain)}</b> for {esc(spf_ip)} → <b>{esc(spf_result)}</b>.",
                   f"Published record: <b>{esc(spf.get('record') or '(none)')}</b>"],
                  "Add the sending service's IP ranges to SPF (or route mail through an authorised sender), then re-check.")
        elif spf_result in ("none", "permerror"):
            cause(1, "SPF", f"SPF could not authorise the sender (<b>{esc(spf_result)}</b>)",
                  [f"Evaluating <b>{esc(spf_domain)}</b> for {esc(spf_ip)} returned <b>{esc(spf_result)}</b>"
                   + (f" at {esc(spf.get('mechanism'))}" if spf.get("mechanism") else "") + ".",
                   f"Published record: <b>{esc(spf.get('record') or '(none)')}</b>"],
                  "Publish a valid SPF record for the envelope domain and include every legitimate sender.")
        elif spf_result in ("softfail", "neutral", "temperror"):
            cause(2, "SPF", f"SPF returned <b>{esc(spf_result)}</b> for the sending IP",
                  [f"Evaluating <b>{esc(spf_domain)}</b> for {esc(spf_ip)} returned <b>{esc(spf_result)}</b>"
                   + (f" at {esc(spf.get('mechanism'))}" if spf.get("mechanism") else "") + ".",
                   "A non-pass SPF result is a weak or negative signal for the receiver."],
                  "Tighten the record so legitimate senders return pass, and finish with <b>-all</b> once mapped.")
        if spf_result and gw_spf_result and gw_spf_result != spf_result and gw_spf_result in ("pass", "fail"):
            cause(2, "SPF", "SPF verdict differs between the gateway and live DNS",
                  [f"Gateway saw <b>spf={esc(gw_spf_result)}</b>"
                   + (f" ({esc(gw_spf.get('reason'))})" if gw_spf.get("reason") else "")
                   + f", live evaluation returns <b>{esc(spf_result)}</b>.",
                   "The record or the sending path likely changed since delivery."],
                  "Re-test with a fresh message; if it persists, confirm which resolver and envelope domain the "
                  "gateway used.")

        # ------------------------------------------------------------ DMARC
        dm_parsed = dmarc.get("parsed")
        align = dmarc.get("alignment") or {}
        dmarc_pass = ((align.get("spf") and gw_spf_result == "pass")
                      or (align.get("dkim") and gw_dkim_result == "pass"))
        if not dm_parsed:
            extra = f" (gateway verdict: <b>dmarc={esc(dmarc.get('reported'))}</b>)" if dmarc.get("reported") else ""
            cause(1, "DMARC", "No DMARC policy is published for this domain",
                  [f"<b>_dmarc.{esc(self.domain)}</b> has no record{extra}.",
                   "Without DMARC there is no alignment-based policy: a DKIM or SPF failure cannot be "
                   "compensated for, and the message falls back to reputation/content scoring."],
                  f"Publish <b>v=DMARC1; p=none; rua=mailto:dmarc@{esc(self.domain)}</b> to start collecting "
                  "reports, then move to quarantine and finally reject once DKIM/SPF are clean.")
        else:
            policy = (dm_parsed.get("p") or "none").lower()
            if policy == "none":
                cause(2, "DMARC", "DMARC is in monitor-only mode (p=none)",
                      ["The policy exists but instructs receivers to take no action on authentication failures."],
                      "Once reports show clean alignment, ramp to <b>p=quarantine</b>, then <b>p=reject</b>.")
            else:
                passing.append(f"DMARC policy <b>p={esc(policy)}</b> published")
            if not dm_parsed.get("rua"):
                cause(2, "DMARC", "No DMARC aggregate reporting address (rua=)",
                      ["Without rua= you receive no visibility into authentication failures."],
                      f"Add <b>rua=mailto:dmarc@{esc(self.domain)}</b> to the DMARC record.")
            if policy in ("quarantine", "reject"):
                if dmarc_pass:
                    passing.append("This message would pass DMARC (aligned SPF/DKIM)")
                else:
                    cause(1, "DMARC", "This message would fail DMARC under the published policy",
                          [f"Policy is <b>p={esc(policy)}</b>; alignment: SPF "
                           f"{'aligned' if align.get('spf') else 'not aligned'}, DKIM "
                           f"{'aligned' if align.get('dkim') else 'not aligned'}.",
                           "Neither aligned mechanism passed, so the policy would quarantine/reject this mail."],
                          "Fix the DKIM/SPF failure above; that also restores DMARC alignment.")
            elif align.get("spf") or align.get("dkim"):
                passing.append("DMARC alignment is intact (From domain matches the SPF/DKIM domain)")

        # ---------------------------------------------------------- reputation
        ip = reputation.get("ip")
        rbl = reputation.get("rbl") or []
        listed = [r for r in rbl if r["status"] == "listed"]
        if ip and listed:
            zones = ", ".join(f"<b>{esc(r['zone'])}</b>" for r in listed)
            cause(0 if len(listed) > 1 else 1, "RBL", f"Sending IP is blacklisted on {len(listed)} zone(s)",
                  [f"{esc(ip)} is listed on: {zones}.",
                   "Listings depress reputation at every major receiver, independent of SPF/DKIM."],
                  "Request delisting from each zone and fix the root cause (compromised host, open relay, spam run).")
        elif ip and rbl:
            inconclusive = [r for r in rbl if r["status"] in ("blocked", "err")]
            detail = ""
            if inconclusive:
                names = ", ".join(esc(r["zone"]) for r in inconclusive[:4])
                detail = f" ({len(inconclusive)} zone(s) inconclusive: {names})"
            passing.append(f"No blacklist listings for {esc(ip)}{detail}")
        if ip and not reputation.get("ptr"):
            evidence = [f"No PTR record exists for <b>{esc(ip)}</b>."]
            if reputation.get("ptr_fallback_available"):
                evidence.append("Confirmed with both the system resolver and the fallback resolver.")
            cause(2, "rDNS", "Sending IP has no reverse DNS (PTR)", evidence,
                  "Have the sending provider publish a PTR that matches the HELO/EHLO hostname.")
        elif reputation.get("ptr") and reputation.get("fcrdns") is False:
            cause(2, "rDNS", "Reverse DNS does not forward-confirm",
                  [f"PTR is <b>{esc(reputation['ptr'])}</b> but that name does not resolve back to {esc(ip)}."],
                  "Make the PTR and A records match (forward-confirmed rDNS).")
        elif reputation.get("ptr"):
            passing.append(f"Forward-confirmed rDNS: {esc(reputation['ptr'])} ⇄ {esc(ip)}")

        # ------------------------------------------ gateway scoring headers
        ss = p.get("spam_status") or {}
        spam_flag = (p.get("spam_flag") or "").lower().startswith("yes") or ss.get("flag") == "yes"
        if spam_flag:
            detail = ""
            if ss.get("score") is not None and ss.get("required") is not None:
                detail = f" — score {ss['score']} vs required {ss['required']}"
            cause(0, "FILTER", "The receiving filter explicitly marked this message as spam",
                  [f"<b>X-Spam-Flag: Yes</b>{detail}.",
                   "This is the direct reason the message was filed to spam; the authentication failures "
                   "above are what the filter scored."],
                  "Fix the failing authentication checks first, then re-test — the flag usually clears with them.")
        if ss.get("score") is not None and ss.get("required") is not None and ss["score"] >= ss["required"]:
            rules = (f"Rules triggered: <b>{esc(', '.join(ss['tests'][:12]))}</b>"
                     if ss.get("tests") else "No per-rule breakdown was included in the headers.")
            cause(0, "FILTER", f"Spam score {ss['score']} exceeds the {ss['required']} threshold",
                  [rules, "Scores above threshold are quarantined regardless of authentication."],
                  "Work through the failing checks listed in this report; content/reputation rules resolve with them.")
        elif ss.get("score") is not None:
            threshold = ss.get("required")
            passing.append(f"Spam score {ss['score']}" + (
                f" is below the {threshold} threshold" if threshold is not None else " recorded (no threshold in headers)"))
        scl = p.get("scl")
        if scl is not None and scl >= 5:
            cause(1, "FILTER", f"Microsoft spam confidence level SCL {scl}",
                  [f"<b>SCL:{scl}</b> — 5 and above routes to the Junk folder, 7+ is high-confidence spam."],
                  "Fix authentication alignment and sender reputation, then re-test to a Microsoft mailbox.")
        elif scl is not None:
            passing.append(f"Microsoft SCL {scl} (delivered as non-spam)")
        for h in p["gateway"]:
            if h["name"].lower() == "x-bess-reason":
                cause(2, "GATEWAY", "Gateway reason code: <b>" + esc(h["value"]) + "</b>",
                      ["The gateway stamps a vendor reason code naming the mechanism/rule it acted on; here it "
                       "points at DKIM, matching the failed DKIM verdict in Authentication-Results."],
                      "Treat the cited mechanism as the primary fix target.")

        # ------------------------------------------------------------ hygiene
        from_domain = (p.get("from") or {}).get("domain")
        mid_domain = p.get("message_id_domain")
        if mid_domain and from_domain and org_domain(mid_domain) != org_domain(from_domain):
            cause(3, "HYGIENE", "Message-ID domain does not match the From domain",
                  [f"Message-ID is <b>@{esc(mid_domain)}</b> while From is <b>{esc(from_domain)}</b>.",
                   "Common when mail is composed or sent through Gmail/an ESP; a weak signal on its own."],
                  "Where possible send through a domain-consistent mail path so Message-ID matches From.")
        rp = (p.get("return_path") or {}).get("domain")
        if rp and from_domain and org_domain(rp) != org_domain(from_domain):
            cause(2, "HYGIENE", "Envelope sender (Return-Path) domain differs from From",
                  [f"Return-Path <b>{esc(rp)}</b> vs From <b>{esc(from_domain)}</b>.",
                   "Legitimate for ESPs, but it breaks SPF-based DMARC alignment for the visible domain."],
                  "Align the envelope domain with the From domain (custom return-path) where your provider allows it.")
        if not p.get("message_id"):
            cause(1, "HYGIENE", "Message has no Message-ID header",
                  ["Filters and receivers treat a missing Message-ID as malformed mail."],
                  "Ensure the sending platform adds a unique Message-ID to every message.")
        if not p.get("date"):
            cause(2, "HYGIENE", "Message has no Date header",
                  ["A missing Date is a strong malformed-message signal."],
                  "Ensure a valid RFC 5322 Date header is added.")
        hops = p.get("received") or []
        if hops and not hops[0].get("encrypted"):
            cause(2, "TRANSPORT", "Message reached the receiving gateway over plaintext SMTP",
                  [f"The topmost Received shows <b>with {esc(hops[0].get('with') or 'SMTP')}</b> and no TLS details."],
                  "Require TLS on every sending path, and consider MTA-STS + TLS-RPT for your domain.")
        elif hops:
            tls = hops[0].get("tls") or "encrypted"
            cipher = f" · {esc(hops[0].get('cipher'))}" if hops[0].get("cipher") else ""
            passing.append(f"TLS on the final hop: {esc(tls)}{cipher}")
        if (p.get("precedence") or "").lower() == "bulk" and not p.get("list_unsubscribe"):
            cause(3, "HYGIENE", "Bulk message without List-Unsubscribe",
                  ["Precedence: bulk is set but no unsubscribe mechanism is advertised."],
                  "Add List-Unsubscribe and List-Unsubscribe-Post headers for bulk/marketing mail.")

        causes.sort(key=lambda c: c["sev"])
        return causes, passing

    # ---------------------------------------------------------------- scoring
    @staticmethod
    def _risk(causes):
        risk = sum({0: 40, 1: 25, 2: 12, 3: 4}.get(c["sev"], 4) for c in causes)
        risk = min(100, risk)
        if risk >= 60:
            verdict = "CRITICAL"
        elif risk >= 40:
            verdict = "HIGH"
        elif risk >= 20:
            verdict = "MODERATE"
        else:
            verdict = "LOW"
        return risk, verdict

    # ------------------------------------------------------------ orchestrator
    def run(self):
        try:
            p = self.parsed
            if p["header_count"] == 0:
                raise ValueError("No email headers were found in the pasted text.")
            if not self.domain:
                raise ValueError("Could not determine a domain from the headers — enter one in the domain field.")
            self.log(f"──── DIAGNOSTICS ENGAGED — {p['header_count']} header(s) · target {self.domain} ────", "info")
            self.log(
                f"message from {p['from'].get('email') or '?'} · {len(p['received'])} hop(s) · sending IP "
                f"{p.get('sending_ip') or '?'} ({p.get('sending_ip_source') or 'source unknown'})",
                "dns",
            )

            dkim = self._check_dkim()
            spf = self._check_spf()
            dmarc = self._check_dmarc()
            reputation = self._check_reputation()
            causes, passing = self._analyse(dkim, spf, dmarc, reputation)
            risk, verdict = self._risk(causes)
            headline = causes[0]["title"] if causes else "No delivery-blocking problems found in this message"
            self.log(
                f"──── DIAGNOSIS COMPLETE — RISK {risk}/100 ({verdict}) · {len(causes)} finding(s) · "
                f"{len(passing)} check(s) passed ────",
                "ok" if risk < 40 else "warn" if risk < 60 else "fail",
            )

            report = {
                "generated": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "ms": int((time.monotonic() - self._t0) * 1000),
                "domain": self.domain,
                "resolver": self.backend.describe() if hasattr(self.backend, "describe") else "system resolver",
                "resolver_id": self.resolver_id,
                "risk": risk,
                "verdict": verdict,
                "headline": headline,
                "message": {
                    "from": p["from"].get("email"),
                    "from_name": p["from"].get("name"),
                    "from_domain": p["from"].get("domain"),
                    "to": p["to"].get("email"),
                    "subject": p["subject"],
                    "date": p["date"],
                    "message_id": p["message_id"],
                    "return_path": p["return_path"].get("email"),
                    "mail_from": p.get("mail_from"),
                    "helo": p.get("helo"),
                    "sending_ip": p.get("sending_ip"),
                    "sending_ip_source": p.get("sending_ip_source"),
                    "hops": len(p["received"]),
                    "header_count": p["header_count"],
                },
                "causes": causes,
                "passing": passing,
                "auth": ([{"kind": "Authentication-Results", **ar} for ar in p["auth_results"]]
                         + [{"kind": "ARC-Authentication-Results", **ar} for ar in p["arc_auth_results"]]),
                "final_authserv": (p["final_auth"] or {}).get("authserv"),
                "dkim": dkim,
                "spf": spf,
                "dmarc": dmarc,
                "reputation": reputation,
                "received": p["received"],
                "gateway": p["gateway"],
                "dns_checks": self.dns_checks,
            }
            return report, self.logs
        finally:
            self._pool.shutdown(wait=False, cancel_futures=True)
