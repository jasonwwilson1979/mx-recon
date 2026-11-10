"""MX-RECON test suite — pure-unit (stubbed DNS) + Django view/ratelimit tests."""
from __future__ import annotations

import json

from django.conf import settings
from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings

from scanner import views as scanner_views
from scanner.diagnostics import Diagnoser, SpfEvaluator, org_domain
from scanner.engine import (
    COMMON_SELECTORS,
    Engine,
    classify_rbl,
    dkim_key_bits,
    parse_dmarc,
    rev_ip,
)
from scanner.headers import parse_message_headers
from scanner.ratelimit import check_rate_limit
from scanner.validators import DomainValidationError, normalize_domain, validate_domain, validate_selector


# --------------------------------------------------------------------- fakes
def _rec(rtype, data, ttl=300):
    return {"type": rtype, "data": data, "ttl": ttl}


class FakeBackend:
    """Stub DNS backend: {(name, rtype): (status, [records])} table."""

    def __init__(self, table=None):
        self.table = table or {}
        self.calls = []

    def query(self, name, rtype):
        self.calls.append((name, rtype))
        return self.table.get((name.lower(), rtype), ("NOERROR", []))

    def describe(self):
        return "stub resolver"


def gmail_like_backend():
    """Canned zone that should score a perfect 100/HARDENED."""
    d = "acme-corp.com"
    table = {
        (d, "A"): ("NOERROR", [_rec("A", "93.184.216.34")]),
        (d, "AAAA"): ("NOERROR", [_rec("AAAA", "2606:2800:220:1:248:1893:25c8:1946")]),
        (d, "NS"): ("NOERROR", [_rec("NS", "ns1.acme-corp.com.")]),
        (d, "SOA"): ("NOERROR", [_rec("SOA", "ns1.acme-corp.com. hostmaster.acme-corp.com. 2026010101 7200 3600 1209600 3600")]),
        (d, "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 include:_spf.acme-corp.com ip4:93.184.216.0/24 -all")]),
        (d, "CNAME"): ("NOERROR", []),
        ("www." + d, "CNAME"): ("NOERROR", [_rec("CNAME", "acme-corp.com.")]),
        (d, "MX"): ("NOERROR", [_rec("MX", "10 mail.acme-corp.com.")]),
        ("mail.acme-corp.com", "A"): ("NOERROR", [_rec("A", "93.184.216.34")]),
        ("mail.acme-corp.com", "AAAA"): ("NOERROR", []),
        ("mail.acme-corp.com", "CNAME"): ("NOERROR", []),
        ("34.216.184.93.in-addr.arpa", "PTR"): ("NOERROR", [_rec("PTR", "mail.acme-corp.com.")]),
        ("_spf.acme-corp.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 ~all")]),
        ("_dmarc." + d, "TXT"): ("NOERROR", [_rec("TXT", "v=DMARC1; p=reject; rua=mailto:dmarc@acme-corp.com; pct=100")]),
        ("google._domainkey." + d, "TXT"): ("NOERROR", [_rec("TXT", "v=DKIM1; k=rsa; p=" + "MIIBIjANBgkq" * 25)]),
        ("_mta-sts." + d, "TXT"): ("NOERROR", [_rec("TXT", "v=STSv1; id=2026")]),
        ("_smtp._tls." + d, "TXT"): ("NOERROR", [_rec("TXT", "v=TLSRPTv1; rua=mailto:tls@acme-corp.com")]),
        ("default._bimi." + d, "TXT"): ("NOERROR", []),
        (d, "DNSKEY"): ("NOERROR", [_rec("DNSKEY", "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl")]),
        ("ns1.acme-corp.com", "A"): ("NOERROR", [_rec("A", "192.0.2.53")]),
    }
    return FakeBackend(table)


# --------------------------------------------------------------------- units
class ValidatorTests(SimpleTestCase):
    def test_normalisation(self):
        self.assertEqual(normalize_domain("HTTPS://Example.com/path:8080?q"), "example.com")
        self.assertEqual(normalize_domain("user@Example.COM"), "example.com")
        self.assertEqual(normalize_domain("_dmarc.example.com"), "example.com")

    def test_accepts_valid(self):
        self.assertEqual(validate_domain("example.com"), "example.com")
        self.assertEqual(validate_domain("sub.domain.example.co.uk"), "sub.domain.example.co.uk")

    def test_rejects_ip_literals(self):
        for bad in ["192.168.1.1", "8.8.8.8"]:
            with self.assertRaises(DomainValidationError):
                validate_domain(bad)

    def test_rejects_special_use_names(self):
        for bad in ["localhost", "router.local", "intranet.corp", "foo.internal", "x.arpa"]:
            with self.assertRaises(DomainValidationError):
                validate_domain(bad)

    def test_rejects_garbage(self):
        for bad in ["", "a", "under_score.com", "-bad.com", "bad-.com", "a" * 300 + ".com"]:
            with self.assertRaises(DomainValidationError):
                validate_domain(bad)

    def test_selector(self):
        self.assertEqual(validate_selector(" Google "), "google")
        self.assertEqual(validate_selector("sel._domainkey.example.com"), "sel")
        self.assertEqual(validate_selector(""), "")
        with self.assertRaises(DomainValidationError):
            validate_selector("bad_selector!")


class HelperTests(SimpleTestCase):
    def test_rev_ip(self):
        self.assertEqual(rev_ip("93.184.216.34"), "34.216.184.93.in-addr.arpa")
        self.assertTrue(rev_ip("2606:2800:220:1:248:1893:25c8:1946").endswith(".ip6.arpa"))

    def test_dkim_bits(self):
        algo, bits, revoked, key = dkim_key_bits("v=DKIM1; k=rsa; p=" + "A" * 300)
        self.assertEqual((algo, bits, revoked), ("rsa", 2048, False))
        self.assertTrue(dkim_key_bits("v=DKIM1; p=")[2])
        algo, bits, _, _ = dkim_key_bits("v=DKIM1; k=ed25519; p=" + "A" * 40)
        self.assertEqual((algo, bits), ("ed25519", 1024))

    def test_parse_dmarc(self):
        tags = parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:a@b.c; pct=50")
        self.assertEqual(tags["p"], "quarantine")
        self.assertEqual(tags["pct"], "50")

    def test_classify_rbl(self):
        self.assertEqual(classify_rbl("NOERROR", [_rec("A", "127.0.0.2")]), ("listed", "127.0.0.2"))
        self.assertEqual(classify_rbl("NOERROR", [_rec("A", "127.255.255.254")])[0], "blocked")
        self.assertEqual(classify_rbl("NXDOMAIN", [])[0], "clean")
        self.assertEqual(classify_rbl("ERR", [])[0], "err")

    def test_rbl_blocked_codes_are_never_listings(self):
        """127.0.0.1 = "query blocked / not authorised" (URIBL et al), not a listing."""
        self.assertEqual(classify_rbl("NOERROR", [_rec("A", "127.0.0.1")])[0], "blocked")
        self.assertEqual(classify_rbl("NOERROR", [_rec("A", "127.255.255.254")])[0], "blocked")
        self.assertEqual(classify_rbl("NOERROR", [_rec("A", "127.0.0.2")])[0], "listed")

class EngineTests(SimpleTestCase):
    def test_full_scan_perfect_domain(self):
        backend = gmail_like_backend()
        engine = Engine("acme-corp.com", "", backend=backend, whois_enabled=False)
        report, logs = engine.run()

        self.assertEqual(report["score"], 100)
        self.assertEqual(report["verdict"], "HARDENED")
        self.assertEqual(report["breakdown"], {"spf": 25, "dkim": 20, "dmarc": 30, "mx": 15, "rbl": 10})
        self.assertEqual(report["recommendations"], [])
        # relay/echo-spoof exposure: nothing delegated, only the relaxed-alignment advisory
        self.assertEqual(report["relay"]["verdict"], "HARDENED")
        self.assertEqual([f["key"] for f in report["relay"]["findings"]], ["relaxed-alignment"])
        self.assertEqual(len(report["mx"]), 1)
        self.assertEqual(report["mx"][0]["ptr"], "mail.acme-corp.com")
        self.assertEqual(report["dmarc"]["parsed"]["p"], "reject")
        self.assertTrue(any(k["selector"] == "google" for k in report["dkim"]))
        self.assertTrue(any(log["ph"] == "enum" for log in logs))
        self.assertTrue(any("SCAN COMPLETE" in log["msg"] for log in logs))
        self.assertTrue(any(r["type"] == "MX" for r in report["inventory"]))

    def test_spf_tree_and_budget(self):
        d = "acme-corp.com"
        table = {
            (d, "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 include:spf1.acme-corp.com include:spf2.acme-corp.com -all")]),
            ("spf1.acme-corp.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 a mx -all")]),
            ("spf2.acme-corp.com", "TXT"): ("NXDOMAIN", []),
        }
        engine = Engine(d, "", backend=FakeBackend(table))
        spf = engine._step_spf({"txt": ["v=spf1 include:spf1.acme-corp.com include:spf2.acme-corp.com -all"]})
        # 2 include mechanisms + child's a + mx mechanisms = 4 lookups (ip4 is not counted)
        self.assertEqual(spf["lookups"], 4)
        self.assertEqual(spf["all"], "-all")
        statuses = {c["domain"]: c["status"] for c in spf["tree"]["children"]}
        self.assertEqual(statuses.get("spf2.acme-corp.com"), "NXDOMAIN")

    def test_dkim_auto_probes_all_selectors(self):
        engine = Engine("example.test", "", backend=FakeBackend({}))
        hits = engine._step_dkim()
        self.assertEqual(hits, [])
        self.assertTrue(any("no DKIM keys discovered" in log["msg"] for log in engine.logs))

    def test_common_selector_list_is_18(self):
        self.assertEqual(len(COMMON_SELECTORS), 18)

    def test_query_budget_stops_runaway(self):
        engine = Engine("example.test", "", backend=FakeBackend({}), max_queries=5)
        for _ in range(10):
            engine.q("x.test", "TXT")
        status, records = engine.q("y.test", "TXT")
        self.assertEqual(status, "ERR")
        self.assertEqual(records, [])
        self.assertTrue(any("budget" in log["msg"] for log in engine.logs))

    def test_uribl_is_not_queried(self):
        from scanner.engine import RBL_DOM

        zones = [z["zone"] for z in RBL_DOM]
        self.assertNotIn("multi.uribl.com", zones)
        self.assertIn("dbl.spamhaus.org", zones)
        self.assertIn("multi.surbl.org", zones)

    @override_settings(MX_RECON_RBL_DISABLED="dnsbl.sorbs.net, multi.surbl.org")
    def test_rbl_zones_can_be_disabled_by_env(self):
        from scanner.engine import active_rbl_zones

        ip_zones, dom_zones = active_rbl_zones()
        ip_names = [z["zone"] for z in ip_zones]
        dom_names = [z["zone"] for z in dom_zones]
        self.assertNotIn("dnsbl.sorbs.net", ip_names)
        self.assertNotIn("multi.surbl.org", dom_names)
        self.assertIn("zen.spamhaus.org", ip_names)
        self.assertIn("dbl.spamhaus.org", dom_names)

    def test_extra_zone_parsing(self):
        from scanner.engine import parse_extra_zones

        raw = "zen.example.net|Example IP RBL|https://example.net/rbl;dbl.example.net;1.2.3.4;single;bad_zone"
        zones = parse_extra_zones(raw)
        self.assertEqual([z["zone"] for z in zones], ["zen.example.net", "dbl.example.net"])
        self.assertEqual(zones[0]["name"], "Example IP RBL")
        self.assertEqual(zones[0]["url"], "https://example.net/rbl")
        self.assertTrue(zones[0]["custom"])
        self.assertEqual(zones[1]["name"], "dbl.example.net")   # label defaults to the zone
        self.assertEqual(zones[1]["url"], "")                   # url is optional
        self.assertEqual(parse_extra_zones(""), [])

    @override_settings(MX_RECON_RBL_EXTRA_IP="zen.example.net|Example IP RBL",
                       MX_RECON_RBL_EXTRA_DOMAIN="dbl.example.net")
    def test_custom_zones_are_added(self):
        from scanner.engine import active_rbl_zones

        ip_zones, dom_zones = active_rbl_zones()
        self.assertEqual(ip_zones[-1]["zone"], "zen.example.net")
        self.assertTrue(ip_zones[-1]["custom"])
        self.assertEqual(dom_zones[-1]["zone"], "dbl.example.net")

    @override_settings(MX_RECON_RBL_EXTRA_IP="zen.example.net", MX_RECON_RBL_DISABLED="zen.example.net")
    def test_custom_zones_can_also_be_disabled(self):
        from scanner.engine import active_rbl_zones

        ip_zones, _ = active_rbl_zones()
        self.assertNotIn("zen.example.net", [z["zone"] for z in ip_zones])

    @override_settings(MX_RECON_RBL_EXTRA_IP="zen.spamhaus.org")
    def test_custom_zone_duplicating_a_builtin_is_ignored(self):
        from scanner.engine import active_rbl_zones

        ip_zones, _ = active_rbl_zones()
        self.assertEqual([z["zone"] for z in ip_zones].count("zen.spamhaus.org"), 1)

    @override_settings(MX_RECON_RBL_EXTRA_IP="zen.example.net|Example IP RBL")
    def test_scan_queries_and_reports_custom_zones(self):
        backend = gmail_like_backend()
        report, logs = Engine("acme-corp.com", "", backend=backend, whois_enabled=False).run()

        self.assertTrue(any(name.endswith("zen.example.net") for name, _rtype in backend.calls))
        custom = [z for z in report["blacklists"]["ip"] if z.get("custom")]
        self.assertEqual(len(custom), 1)
        self.assertEqual(custom[0]["zone"], "zen.example.net")
        self.assertEqual(custom[0]["name"], "Example IP RBL")
        self.assertTrue(any("custom" in entry["msg"] for entry in logs))

    def test_public_spamhaus_detection(self):
        from scanner.engine import is_public_spamhaus

        self.assertTrue(is_public_spamhaus("zen.spamhaus.org"))
        self.assertTrue(is_public_spamhaus("dbl.spamhaus.org"))
        self.assertTrue(is_public_spamhaus("ZEN.Spamhaus.ORG."))
        self.assertFalse(is_public_spamhaus("zen.dq.spamhaus.net"))   # DQS zones answer normally
        self.assertFalse(is_public_spamhaus("key.dbl.dq.spamhaus.net"))
        self.assertFalse(is_public_spamhaus("bl.spamcop.net"))
        self.assertFalse(is_public_spamhaus(""))

    def test_blocked_rbl_zones_collects_refusals_only(self):
        from scanner.engine import blocked_rbl_zones

        ip_matrix = [
            {"zone": "zen.spamhaus.org", "cells": [{"status": "blocked"}, {"status": "clean"}]},
            {"zone": "bl.spamcop.net", "cells": [{"status": "listed"}, {"status": "clean"}]},
        ]
        dom_matrix = [
            {"zone": "dbl.spamhaus.org", "status": "err"},
            {"zone": "multi.surbl.org", "status": "clean"},
        ]
        self.assertEqual(blocked_rbl_zones(ip_matrix, dom_matrix),
                         {"zen.spamhaus.org", "dbl.spamhaus.org"})
        self.assertEqual(blocked_rbl_zones([], []), set())

    def test_blocked_hint_explains_the_spamhaus_fix(self):
        from scanner.engine import rbl_blocked_hint

        hint = rbl_blocked_hint({"dbl.spamhaus.org", "zen.spamhaus.org"})
        for needle in ("dbl.spamhaus.org", "zen.spamhaus.org", "inconclusive", "never a listing",
                       "System default", "dq.spamhaus.net", "DJANGO_RESOLVERS_EXTRA",
                       "DJANGO_RBL_EXTRA_DOMAIN"):
            self.assertIn(needle, hint)
        generic = rbl_blocked_hint({"zen.example.net"})
        self.assertIn("zen.example.net", generic)
        self.assertNotIn("dq.spamhaus.net", generic)

    def test_scan_logs_the_spamhaus_fix_when_dbl_refuses(self):
        backend = gmail_like_backend()
        backend.table[("acme-corp.com.dbl.spamhaus.org", "A")] = ("NOERROR", [_rec("A", "127.255.255.254")])
        report, logs = Engine("acme-corp.com", "", backend=backend, whois_enabled=False).run()

        dom = {z["zone"]: z["status"] for z in report["blacklists"]["domain"]}
        self.assertEqual(dom["dbl.spamhaus.org"], "blocked")     # inconclusive, not a listing
        hints = [e for e in logs if "dq.spamhaus.net" in e["msg"]]
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["cls"], "warn")
        self.assertEqual(hints[0]["ph"], "rbl")
        self.assertIn("dbl.spamhaus.org", hints[0]["msg"])
        self.assertIn("System default", hints[0]["msg"])
        self.assertFalse(any(r["tag"] == "SPAM" for r in report["recommendations"]))  # never a directive

    def test_no_fix_hint_when_every_zone_answers(self):
        _report, logs = Engine("acme-corp.com", "", backend=gmail_like_backend(), whois_enabled=False).run()

        self.assertFalse(any("dq.spamhaus.net" in e["msg"] for e in logs))

    def test_unsigned_zone_gets_a_dnssec_advisory(self):
        """No DNSKEY = the SPF/DMARC/DKIM answers can be forged in transit."""
        backend = gmail_like_backend()
        backend.table.pop(("acme-corp.com", "DNSKEY"))
        report, _logs = Engine("acme-corp.com", "", backend=backend, whois_enabled=False).run()

        dnssec_recs = [r for r in report["recommendations"] if r["tag"] == "DNSSEC"]
        self.assertEqual(len(dnssec_recs), 1)
        self.assertEqual(dnssec_recs[0]["sev"], 3)
        self.assertIn("not DNSSEC-signed", dnssec_recs[0]["text"])
        self.assertFalse(report["control"]["dnssec"]["dnskey_published"])

    def test_scan_reports_relay_exposure(self):
        """A shared relay in SPF plus a non-enforcing DMARC policy is the
        EchoSpoofing precondition — the scan must say so."""
        backend = gmail_like_backend()
        backend.table[("acme-corp.com", "TXT")] = ("NOERROR", [_rec("TXT", "v=spf1 include:pphosted.com ~all")])
        backend.table[("pphosted.com", "TXT")] = ("NOERROR", [_rec("TXT", "v=spf1 ip4:148.163.0.0/16 -all")])
        backend.table[("_dmarc.acme-corp.com", "TXT")] = (
            "NOERROR", [_rec("TXT", "v=DMARC1; p=none; rua=mailto:dmarc@acme-corp.com")])
        report, logs = Engine("acme-corp.com", "", backend=backend, whois_enabled=False).run()

        relay = report["relay"]
        self.assertEqual(relay["verdict"], "ELEVATED")
        self.assertEqual([r["label"] for r in relay["relays"]], ["Proofpoint"])
        keys = [f["key"] for f in relay["findings"]]
        for expected in ("dmarc-none", "shared-relay", "softfail"):
            self.assertIn(expected, keys)
        self.assertTrue(any("relay/echo-spoof exposure" in log["msg"] for log in logs))
        self.assertTrue(any(rec["tag"] == "RELAY" for rec in report["recommendations"]))

    def test_public_resolver_is_flagged_in_log_and_report(self):
        report, logs = Engine("acme-corp.com", "", backend=gmail_like_backend(),
                              resolver_id="cloudflare", whois_enabled=False).run()

        self.assertTrue(report["resolver_public"])
        self.assertEqual(report["resolver_id"], "cloudflare")
        warned = [e for e in logs if "public resolver" in e["msg"]]
        self.assertEqual(len(warned), 1)
        self.assertEqual(warned[0]["cls"], "warn")
        self.assertIn("cloudflare", warned[0]["msg"])

        own, own_logs = Engine("acme-corp.com", "", backend=gmail_like_backend(),
                               resolver_id="system", whois_enabled=False).run()
        self.assertFalse(own["resolver_public"])
        self.assertFalse(any("public resolver" in e["msg"] for e in own_logs))

    @override_settings(MX_RECON_RBL_DISABLED="dbl.spamhaus.org",
                       MX_RECON_RBL_EXTRA_DOMAIN="YOUR-KEY.dbl.dq.spamhaus.net|Spamhaus DBL (DQS)")
    def test_dqs_zone_answers_and_is_not_treated_as_public(self):
        backend = gmail_like_backend()
        backend.table[("acme-corp.com.your-key.dbl.dq.spamhaus.net", "A")] = ("NOERROR", [_rec("A", "127.0.0.2")])
        report, logs = Engine("acme-corp.com", "", backend=backend, whois_enabled=False).run()

        dom = {z["zone"]: z for z in report["blacklists"]["domain"]}
        self.assertNotIn("dbl.spamhaus.org", dom)                       # public zone disabled
        dqs = dom["your-key.dbl.dq.spamhaus.net"]                       # key is lower-cased, as DNS requires
        self.assertEqual(dqs["status"], "listed")
        self.assertEqual(dqs["code"], "127.0.0.2")
        self.assertTrue(dqs["custom"])
        self.assertFalse(any("refused" in e["msg"] for e in logs))


# --------------------------------------------------------------------- HTTP
class RateLimitTests(SimpleTestCase):
    @override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
    def test_window_blocks_after_limit(self):
        cache.clear()
        for _ in range(3):
            self.assertTrue(check_rate_limit("1.2.3.4", 3, 300))
        self.assertFalse(check_rate_limit("1.2.3.4", 3, 300))
        self.assertTrue(check_rate_limit("5.6.7.8", 3, 300))  # other clients unaffected


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ViewTests(SimpleTestCase):
    def setUp(self):
        cache.clear()   # rate-limit counters must not leak between tests or from live runs

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_scan_api_happy_path(self):
        from unittest.mock import patch

        real_engine = scanner_views.Engine

        class PatchedEngine(real_engine):
            def __init__(self, domain, selector="", **kwargs):
                kwargs.pop("backend", None)
                kwargs["whois_enabled"] = False   # keep tests offline
                super().__init__(domain, selector, backend=gmail_like_backend(), **kwargs)

        with patch.object(scanner_views, "Engine", PatchedEngine):
            resp = Client().post(
                "/api/scan",
                data='{"domain":"acme-corp.com"}',
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["report"]["target"], "acme-corp.com")
        self.assertEqual(body["report"]["verdict"], "HARDENED")
        self.assertIn("logs", body)

    def test_scan_api_rejects_bad_domain(self):
        resp = Client().post(
            "/api/scan",
            data='{"domain":"192.168.1.1"}',
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())

    def test_scan_api_rejects_get(self):
        self.assertEqual(Client().get("/api/scan").status_code, 405)

    def test_scan_api_rate_limited(self):
        from unittest.mock import patch

        client = Client()
        real_engine = scanner_views.Engine

        class PatchedEngine(real_engine):
            def __init__(self, domain, selector="", **kwargs):
                kwargs.pop("backend", None)
                kwargs["whois_enabled"] = False   # keep tests offline
                super().__init__(domain, selector, backend=gmail_like_backend(), **kwargs)

        with patch.object(scanner_views, "Engine", PatchedEngine):
            for _ in range(3):
                client.post(
                    "/api/scan",
                    data='{"domain":"acme-corp.com"}',
                    content_type="application/json",
                    REMOTE_ADDR="10.9.9.9",
                )
            with override_settings(MX_RECON_RATE_LIMIT=1):
                resp = client.post(
                    "/api/scan",
                    data='{"domain":"acme-corp.com"}',
                    content_type="application/json",
                    REMOTE_ADDR="10.9.9.9",
                )
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)

    def test_healthz_and_probe(self):
        self.assertEqual(Client().get("/healthz").status_code, 200)
        resp = Client().get("/api/probe")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("ok", resp.json())

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_index_serves_ui(self):
        resp = Client().get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "MX-RECON")
        self.assertContains(resp, "csrfmiddlewaretoken")
        # one card per row, hard-coded: no switcher, no spans, no dense flow
        self.assertContains(resp, ".rgrid{display:grid;grid-template-columns:minmax(0,1fr)")
        self.assertNotContains(resp, "layoutSwitch")
        self.assertNotContains(resp, "data-layout")
        self.assertNotContains(resp, "grid-auto-flow:dense")
        # the scanning sweep line must survive refactors: element, fade-in rule, and
        # JS-driven movement (a CSS @keyframes sweep can be suppressed by the OS or
        # browser "reduce motion" setting, which parked the line at the top)
        self.assertContains(resp, '<div class="scanline"></div>')
        self.assertContains(resp, "body.scanning .scanline{opacity:.9}")
        self.assertContains(resp, "transform:translate3d(0,-6px,0)")
        self.assertNotContains(resp, "@keyframes sweep")
        self.assertNotContains(resp, "grid-row:span 2")
        self.assertIn("no-store", resp["Cache-Control"])
        # visible build marker so a stale deploy/cached page is obvious
        self.assertContains(resp, 'data-mx-recon-version="')
        self.assertContains(resp, "BUILD")


# ------------------------------------------------------------------ diagnostics

SAMPLE_HEADERS = """X-BESS-REASON: dkim
Received: from outbound9-encrypted-mta.paubox.com (outbound9-encrypted-mta.paubox.com [52.27.124.21]) by mx-inbound40-4.us-east-2c.ess.aws.cudaops.com (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO); Tue, 13 Oct 2026 22:06:23 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=drcfamilydentistry.com; s=paubox; t=1791929182;
 bh=w9CzZ+k57fLcVcWZmBapvZwnyUf/hEZYLGOaalFC654=;
 h=References:In-Reply-To:From:Date:Subject:To:From;
 b=QbO4JZ2G3yuWqMereq97QOOxR7QGuGsfmmWppTorG/sopnkO+rSeINQPCgs3sFu3p
  6d/qK7hmFW2NwsbgzLEPL8xOJtoCnFr9aKPmpNNoVDbObPRBa6KWjHpse+afyClO6J
  8aD1GhYA6eVNURNC2tU7GmLDZebQPnjJWZjWZfQc=
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
 (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
 by outbound9-encrypted-mta.paubox.com (Postfix) with ESMTPS id 4j47hV3xF1z41Vk
 for <acastro@gps.dental>; Tue, 13 Oct 2026 22:06:18 +0000 (UTC)
Authentication-Results: outbound9.prod.paubox.net; arc=pass smtp.remote-ip=209.85.128.71
From: Lillian Panabaker <lillian@drcfamilydentistry.com>
Date: Tue, 13 Oct 2026 15:06:00 -0700
Message-ID: <CAJmq4Kx8cKqu1bWAe_L0CEkN-h+0MBzOWeWDT4XP2bx_7R8O4w@mail.gmail.com>
Subject: Re: Budget exclusion
To: Abigail Castro <acastro@gps.dental>
Authentication-Results: mx-inbound40-4.us-east-2c.ess.aws.cudaops.com; spf=pass (sender IP is 52.27.124.21) smtp.mailfrom=lillian@drcfamilydentistry.com; dkim=fail (No key [DKIM DNS record not found]) header.d=drcfamilydentistry.com; dmarc=none header.from=lillian@drcfamilydentistry.com
Received-SPF: pass (mx-inbound40-4.us-east-2c.ess.aws.cudaops.com: domain of lillian@drcfamilydentistry.com designates 52.27.124.21 as permitted sender)
X-BESS-BRTS-Status:1
"""

DIAG_TABLE = {
    ("paubox._domainkey.drcfamilydentistry.com", "TXT"): ("NXDOMAIN", []),
    ("_dmarc.drcfamilydentistry.com", "TXT"): ("NXDOMAIN", []),
    ("drcfamilydentistry.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 include:paubox.com -all")]),
    ("paubox.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 ip4:52.27.124.21 -all")]),
    ("21.124.27.52.in-addr.arpa", "PTR"): ("NOERROR", [_rec("PTR", "outbound9-encrypted-mta.paubox.com.")]),
    ("outbound9-encrypted-mta.paubox.com", "A"): ("NOERROR", [_rec("A", "52.27.124.21")]),
}


class HeaderParsingTests(SimpleTestCase):
    def test_sample_header_structure(self):
        p = parse_message_headers(SAMPLE_HEADERS)
        self.assertGreaterEqual(p["header_count"], 12)
        self.assertEqual(p["from"]["domain"], "drcfamilydentistry.com")
        self.assertEqual(p["from"]["email"], "lillian@drcfamilydentistry.com")
        self.assertEqual(p["to"]["domain"], "gps.dental")
        self.assertEqual(p["subject"], "Re: Budget exclusion")
        self.assertEqual(p["message_id_domain"], "mail.gmail.com")
        self.assertEqual(len(p["received"]), 2)
        self.assertEqual(p["sending_ip"], "52.27.124.21")
        self.assertEqual(p["sending_ip_source"], "topmost Received")
        self.assertEqual(p["helo"], "outbound9-encrypted-mta.paubox.com")
        self.assertEqual(p["mail_from"], "lillian@drcfamilydentistry.com")
        self.assertEqual(p["mail_from_domain"], "drcfamilydentistry.com")

    def test_received_hops(self):
        p = parse_message_headers(SAMPLE_HEADERS)
        top, second = p["received"]
        self.assertEqual(top["by"], "mx-inbound40-4.us-east-2c.ess.aws.cudaops.com")
        self.assertEqual(top["tls"], "TLSv1.2")
        self.assertTrue(top["encrypted"])
        self.assertEqual(second["with"], "ESMTPS")
        self.assertEqual(second["tls"], "TLSv1.3")
        self.assertEqual(second["for"], "acastro@gps.dental")

    def test_authentication_results_verdicts(self):
        p = parse_message_headers(SAMPLE_HEADERS)
        self.assertEqual(p["final_auth"]["authserv"], "mx-inbound40-4.us-east-2c.ess.aws.cudaops.com")
        methods = p["final_auth"]["methods"]
        self.assertEqual(methods["spf"]["result"], "pass")
        self.assertEqual(methods["dkim"]["result"], "fail")
        self.assertIn("No key", methods["dkim"]["reason"])
        self.assertEqual(methods["dmarc"]["result"], "none")
        self.assertEqual(methods["spf"]["props"]["smtp.mailfrom"], "lillian@drcfamilydentistry.com")

    def test_dkim_signature_and_gateway_headers(self):
        p = parse_message_headers(SAMPLE_HEADERS)
        sig = p["signatures"][0]
        self.assertEqual(sig["domain"], "drcfamilydentistry.com")
        self.assertEqual(sig["selector"], "paubox")
        self.assertEqual(sig["algo"], "rsa-sha256")
        self.assertEqual(sig["signature_bits"], 1024)
        self.assertTrue(sig["covers_from"])
        names = [g["name"].lower() for g in p["gateway"]]
        self.assertIn("x-bess-reason", names)
        self.assertIn("x-bess-brts-status", names)
        reason = next(g for g in p["gateway"] if g["name"].lower() == "x-bess-reason")
        self.assertIn("reason code", reason["note"])
        self.assertEqual(p["received_spf"][0]["result"], "pass")
        self.assertEqual(p["received_spf"][0]["ip"], "52.27.124.21")

class SpfEvaluatorTests(SimpleTestCase):
    @staticmethod
    def _query(table):
        return lambda name, rtype: table.get((name.lower(), rtype), ("NOERROR", []))

    def test_include_pass(self):
        table = {
            ("a.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 include:b.net -all")]),
            ("b.net", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 ip4:52.27.124.21 -all")]),
        }
        result = SpfEvaluator(self._query(table)).evaluate("a.com", "52.27.124.21")
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["mechanism"], "include:b.net")
        self.assertEqual(result["lookups"], 1)

    def test_ip_fail_and_softfail(self):
        table = {("a.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 ip4:10.0.0.0/8 -all")])}
        self.assertEqual(SpfEvaluator(self._query(table)).evaluate("a.com", "52.27.124.21")["result"], "fail")
        table = {("a.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 ip4:10.0.0.0/8 ~all")])}
        self.assertEqual(SpfEvaluator(self._query(table)).evaluate("a.com", "52.27.124.21")["result"], "softfail")

    def test_no_record_and_multiple_records(self):
        self.assertEqual(SpfEvaluator(self._query({})).evaluate("a.com", "1.2.3.4")["result"], "none")
        table = {("a.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 -all"), _rec("TXT", "v=spf1 +all")])}
        self.assertEqual(SpfEvaluator(self._query(table)).evaluate("a.com", "1.2.3.4")["result"], "permerror")

    def test_include_without_record_is_permerror(self):
        table = {("a.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 include:missing.net -all")])}
        self.assertEqual(SpfEvaluator(self._query(table)).evaluate("a.com", "1.2.3.4")["result"], "permerror")

    def test_a_mechanism_match(self):
        table = {
            ("a.com", "TXT"): ("NOERROR", [_rec("TXT", "v=spf1 a -all")]),
            ("a.com", "A"): ("NOERROR", [_rec("A", "52.27.124.21")]),
        }
        self.assertEqual(SpfEvaluator(self._query(table)).evaluate("a.com", "52.27.124.21")["result"], "pass")

    def test_org_domain(self):
        self.assertEqual(org_domain("mail.drcfamilydentistry.com"), "drcfamilydentistry.com")


class DiagnoserTests(SimpleTestCase):
    def test_sample_message_diagnosis(self):
        report, logs = Diagnoser(SAMPLE_HEADERS, backend=FakeBackend(DIAG_TABLE)).run()

        self.assertEqual(report["domain"], "drcfamilydentistry.com")
        self.assertEqual(report["message"]["sending_ip"], "52.27.124.21")
        self.assertEqual(report["spf"]["evaluated"], "pass")          # include:paubox.com authorises the IP
        self.assertEqual(report["dmarc"]["parsed"], None)             # no DMARC published
        self.assertIsNone(report["dkim"][0]["dns_record"])            # selector not published
        self.assertEqual(report["dkim"][0]["selector"], "paubox")

        dkim_causes = [c for c in report["causes"] if c["tag"] == "DKIM"]
        self.assertTrue(any(c["sev"] == 0 and "no public key" in c["title"] for c in dkim_causes))
        self.assertTrue(any(c["tag"] == "DMARC" for c in report["causes"]))
        self.assertGreaterEqual(report["risk"], 60)
        self.assertEqual(report["verdict"], "CRITICAL")
        self.assertTrue(any("SPF" in item for item in report["passing"]))
        self.assertTrue(any("DIAGNOSIS COMPLETE" in entry["msg"] for entry in logs))
        # every DNS lookup the diagnosis made is disclosed
        self.assertTrue(any(c["query"] == "paubox._domainkey.drcfamilydentistry.com" for c in report["dns_checks"]))


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class DiagnoseViewTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    @staticmethod
    def _patched_diagnoser():
        from unittest.mock import patch

        real = scanner_views.Diagnoser

        class Patched(real):
            def __init__(self, raw_headers, domain="", **kwargs):
                kwargs.pop("backend", None)
                super().__init__(raw_headers, domain=domain, backend=FakeBackend(DIAG_TABLE), **kwargs)

        return patch.object(scanner_views, "Diagnoser", Patched)

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_diagnose_api(self):
        with self._patched_diagnoser():
            resp = Client().post(
                "/api/diagnose",
                data=json.dumps({"headers": SAMPLE_HEADERS}),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["report"]["verdict"], "CRITICAL")
        self.assertEqual(body["report"]["domain"], "drcfamilydentistry.com")
        self.assertIn("logs", body)

    def test_diagnose_api_requires_headers(self):
        resp = Client().post("/api/diagnose", data='{"headers":""}', content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    def test_diagnose_api_rejects_bad_domain_override(self):
        with self._patched_diagnoser():
            resp = Client().post(
                "/api/diagnose",
                data=json.dumps({"headers": SAMPLE_HEADERS, "domain": "10.0.0.1"}),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 400)

    def test_diagnose_api_rejects_get(self):
        self.assertEqual(Client().get("/api/diagnose").status_code, 405)


# ------------------------------------------------------- resolver fallback


class _FakeRdata:
    def __init__(self, rdtype, text):
        self.rdtype = rdtype
        self._text = text
        if rdtype == 16:  # TXT — the adapter joins rdata.strings
            self.strings = (text.encode("utf-8"),)

    def to_text(self):
        return self._text


class _FakeAnswer:
    def __init__(self, rdatas):
        self._rdatas = rdatas
        self.ttl = 300

    def __iter__(self):
        return iter(self._rdatas)


class _FakeResolver:
    """Canned answers; raises NoAnswer for anything not in the table."""

    def __init__(self, table=None):
        self.table = table or {}

    def resolve(self, name, rtype):
        from dns.resolver import NoAnswer

        if (name, rtype) not in self.table:
            raise NoAnswer()
        rdtype, text = self.table[(name, rtype)]
        return _FakeAnswer([_FakeRdata(rdtype, text)])


def _resolver_from_table(table):
    import dns.rdatatype

    converted = {}
    for (name, rtype), (_status, records) in table.items():
        if records:
            converted[(name, rtype)] = (dns.rdatatype.from_text(rtype), records[0]["data"])
    return _FakeResolver(converted)


class WhoisTests(SimpleTestCase):
    def test_provider_attribution(self):
        from scanner.whois import provider_for

        self.assertEqual(provider_for("ns1.cloudflare.com"), "Cloudflare")
        self.assertEqual(provider_for("ns-123.awsdns-45.org"), "AWS Route 53")
        self.assertEqual(provider_for("ns1.my-own-server.net"), "self-hosted / unknown")
        self.assertEqual(provider_for(""), "self-hosted / unknown")

    def test_parse_rdap(self):
        from scanner.whois import parse_rdap

        data = {
            "entities": [
                {"roles": ["registrar"],
                 "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]],
                 "publicIds": [{"type": "IANA", "identifier": "292"}]},
                {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "abuse@example.net"]]]},
            ],
            "events": [
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-09-14T04:00:00Z"},
            ],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
            "secureDNS": {"delegationSigned": True},
        }
        out = parse_rdap(data)
        self.assertEqual(out["registrar"], "MarkMonitor Inc.")
        self.assertEqual(out["registrar_id"], "292")
        self.assertEqual(out["events"]["expiration"], "2026-09-14T04:00:00Z")
        self.assertEqual(out["nameservers"], ["ns1.example.com"])
        self.assertTrue(out["dnssec"])
        self.assertIn("client transfer prohibited", out["status"])
        self.assertEqual(out["abuse_contact"], "abuse@example.net")


class ControlStepTests(SimpleTestCase):
    """NS resolution, SOA consistency, DNSSEC and WHOIS findings (no network)."""

    @staticmethod
    def _rdap(**overrides):
        data = {
            "registrar": "Example Registrar",
            "registrar_id": "999",
            "status": ["client transfer prohibited"],
            "events": {"registration": "2015-04-01T00:00:00Z", "expiration": "2099-04-01T00:00:00Z"},
            "nameservers": ["ns1.example.net", "ns2.example.net"],
            "dnssec": True,
            "source": "https://rdap.example/domain/acme-corp.com",
        }
        data.update(overrides)
        return lambda domain, timeout=6.0: dict(data)

    def _engine(self, table, **rdap_overrides):
        return Engine("acme-corp.com", "", backend=FakeBackend(table), rdap_fn=self._rdap(**rdap_overrides))

    def test_control_step_reports_ns_soa_whois_and_dnssec(self):
        table = {
            ("acme-corp.com", "NS"): ("NOERROR", [_rec("NS", "ns1.example.net."), _rec("NS", "ns2.example.net.")]),
            ("ns1.example.net", "A"): ("NOERROR", [_rec("A", "192.0.2.1")]),
            ("ns2.example.net", "A"): ("NOERROR", [_rec("A", "192.0.2.2")]),
            ("acme-corp.com", "DNSKEY"): ("NOERROR", [_rec("DNSKEY", "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dx")]),
        }
        zone = {"ns": ["ns1.example.net.", "ns2.example.net."],
                "soa": "ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600"}
        engine = self._engine(table)
        control = engine._step_control(zone)

        self.assertEqual([n["name"] for n in control["nameservers"]], ["ns1.example.net", "ns2.example.net"])
        self.assertEqual(control["nameservers"][0]["ips"], ["192.0.2.1"])
        self.assertTrue(control["soa_primary_in_ns"])
        self.assertTrue(control["dnssec"]["dnskey_published"])
        self.assertTrue(control["dnssec"]["registry_signed"])
        self.assertEqual(control["whois"]["registrar"], "Example Registrar")
        self.assertGreater(control["whois"]["days_to_expiry"], 1000)
        self.assertFalse(any(r["tag"] == "DNSSEC" for r in engine._recs))

    def test_control_step_flags_soa_and_delegation_mismatch(self):
        table = {
            ("acme-corp.com", "NS"): ("NOERROR", [_rec("NS", "ns1.example.net.")]),
            ("ns1.example.net", "A"): ("NOERROR", [_rec("A", "192.0.2.1")]),
        }
        zone = {"ns": ["ns1.example.net."],
                "soa": "ns9.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600"}
        engine = self._engine(table, nameservers=["ns1.example.net", "ns3.example.net"])
        control = engine._step_control(zone)

        self.assertFalse(control["soa_primary_in_ns"])
        dns_recs = [r["html"] for r in engine._recs if r["tag"] == "DNS"]
        self.assertTrue(any("SOA primary" in r for r in dns_recs))
        self.assertTrue(any("disagree" in r for r in dns_recs))

    def test_control_step_flags_broken_dnssec(self):
        engine = self._engine({})                        # registry says signed...
        engine._step_control({"ns": [], "soa": None})    # ...but the zone has no DNSKEY
        self.assertTrue(any(r["tag"] == "DNSSEC" and r["sev"] == 1 for r in engine._recs))

    def test_control_step_flags_imminent_expiry(self):
        from datetime import datetime, timedelta, timezone

        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        engine = self._engine({}, events={"expiration": soon})
        control = engine._step_control({"ns": [], "soa": None})

        self.assertLessEqual(control["whois"]["days_to_expiry"], 10)
        self.assertTrue(any(r["tag"] == "WHOIS" and r["sev"] == 0 for r in engine._recs))

    def test_control_step_survives_a_whois_failure(self):
        def boom(domain, timeout=6.0):
            raise RuntimeError("rdap exploded")

        engine = Engine("acme-corp.com", "", backend=FakeBackend({}), rdap_fn=boom)
        control = engine._step_control({"ns": [], "soa": None})

        self.assertIn("error", control["whois"])
        self.assertTrue(any("WHOIS/RDAP" in entry["msg"] for entry in engine.logs))

    def test_whois_can_be_disabled(self):
        engine = Engine("acme-corp.com", "", backend=FakeBackend({}), whois_enabled=False)
        control = engine._step_control({"ns": [], "soa": None})
        self.assertEqual(control["whois"], {"enabled": False})


class ResolverTests(SimpleTestCase):
    def test_registry_lists_builtins(self):
        from scanner.resolvers import as_list, nameservers_for

        ids = [r["id"] for r in as_list()]
        for expected in ("system", "cloudflare", "google", "quad9"):
            self.assertIn(expected, ids)
        self.assertEqual(nameservers_for("cloudflare")[0], ["1.1.1.1", "1.0.0.1"])
        self.assertEqual(nameservers_for("system")[0], [])

    def test_public_resolvers_are_flagged(self):
        """Spamhaus cannot attribute public-resolver queries, so RBL answers
        through them are untrustworthy — the flag drives a UI warning."""
        from scanner.resolvers import as_list, is_public

        flagged = {r["id"]: r["public"] for r in as_list()}
        self.assertFalse(flagged["system"])
        for rid in ("cloudflare", "google", "quad9", "opendns", "adguard"):
            self.assertTrue(flagged[rid], rid)
        self.assertTrue(is_public("cloudflare"))
        self.assertFalse(is_public("system"))
        self.assertFalse(is_public(""))                       # defaults to system
        self.assertFalse(is_public("local", "local|LAN|10.0.0.53"))   # operator's own resolver

    def test_unknown_resolver_is_rejected(self):
        from scanner.resolvers import nameservers_for

        for bad in ("evil.example.com", "8.8.8.8", "not a resolver", ""):
            if bad == "":
                continue  # empty means "default"
            with self.assertRaises(ValueError):
                nameservers_for(bad)

    def test_extra_resolvers_are_parsed_and_validated(self):
        from scanner.resolvers import as_list, nameservers_for

        extra = "internal|Internal DNS 10.0.0.53|10.0.0.53;broken entry;x|Bad|not-an-ip"
        nameservers, label = nameservers_for("internal", extra)
        self.assertEqual(nameservers, ["10.0.0.53"])
        self.assertEqual(label, "Internal DNS 10.0.0.53")
        ids = [r["id"] for r in as_list(extra)]
        self.assertIn("internal", ids)
        self.assertNotIn("x", ids)  # invalid nameserver rejected

    def test_default_marker_follows_setting(self):
        from scanner.resolvers import as_list

        rows = as_list("", "google")
        self.assertTrue([r for r in rows if r["id"] == "google"][0]["default"])


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ResolverApiTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def test_resolvers_endpoint(self):
        body = Client().get("/api/resolvers").json()
        self.assertIn("system", [r["id"] for r in body["resolvers"]])
        self.assertIn("default", body)

    def test_probe_accepts_known_resolver(self):
        resp = Client().get("/api/probe?resolver=cloudflare")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["resolver_id"], "cloudflare")

    def test_probe_rejects_unknown_resolver(self):
        resp = Client().get("/api/probe?resolver=1.2.3.4")
        self.assertEqual(resp.status_code, 400)

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_scan_rejects_unknown_resolver(self):
        resp = Client().post(
            "/api/scan",
            data=json.dumps({"domain": "example.com", "resolver": "1.1.1.1"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_scan_passes_selected_resolver_to_the_engine(self):
        from unittest.mock import patch

        real = scanner_views.Engine
        captured = {}

        class Patched(real):
            def __init__(self, domain, selector="", **kwargs):
                captured["resolver_id"] = kwargs.get("resolver_id")
                kwargs.pop("backend", None)
                kwargs["whois_enabled"] = False   # keep tests offline
                super().__init__(domain, selector, backend=gmail_like_backend(), **kwargs)

        with patch.object(scanner_views, "Engine", Patched):
            resp = Client().post(
                "/api/scan",
                data=json.dumps({"domain": "acme-corp.com", "resolver": "quad9"}),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(captured["resolver_id"], "quad9")


class DnsBackendFallbackTests(SimpleTestCase):
    """PTR lookups must fall back to a public resolver when the system one is silent."""

    def test_ptr_uses_fallback_when_system_resolver_is_silent(self):
        import dns.rdatatype

        from scanner.engine import DnspythonBackend

        fallback = _FakeResolver({
            ("21.124.27.52.in-addr.arpa", "PTR"): (dns.rdatatype.PTR, "outbound9-encrypted-mta.paubox.com."),
        })
        backend = DnspythonBackend(resolver=_FakeResolver(), fallback_resolver=fallback)
        status, records = backend.query("21.124.27.52.in-addr.arpa", "PTR")

        self.assertEqual(status, "NOERROR")
        self.assertEqual(records[0]["data"], "outbound9-encrypted-mta.paubox.com.")
        self.assertEqual(backend.last_source, "fallback")
        self.assertTrue(backend.fallback_enabled)

    def test_non_ptr_queries_never_use_the_fallback(self):
        import dns.rdatatype

        from scanner.engine import DnspythonBackend

        fallback = _FakeResolver({("example.com", "A"): (dns.rdatatype.A, "1.2.3.4")})
        backend = DnspythonBackend(resolver=_FakeResolver(), fallback_resolver=fallback)
        status, records = backend.query("example.com", "A")

        self.assertEqual(status, "NOERROR")
        self.assertEqual(records, [])
        self.assertEqual(backend.last_source, "system")

    def test_reputation_discloses_fallback_use(self):
        import dns.rdatatype

        from scanner.diagnostics import Diagnoser
        from scanner.engine import DnspythonBackend

        table = {k: v for k, v in DIAG_TABLE.items() if k != ("21.124.27.52.in-addr.arpa", "PTR")}
        backend = DnspythonBackend(
            resolver=_resolver_from_table(table),
            fallback_resolver=_FakeResolver({
                ("21.124.27.52.in-addr.arpa", "PTR"): (dns.rdatatype.PTR, "outbound9-encrypted-mta.paubox.com."),
            }),
        )
        report, _logs = Diagnoser(SAMPLE_HEADERS, backend=backend).run()

        self.assertEqual(report["reputation"]["ptr"], "outbound9-encrypted-mta.paubox.com")
        self.assertTrue(report["reputation"]["ptr_fallback_used"])
        self.assertTrue(any("fallback resolver" in c["note"] for c in report["dns_checks"]))





# --------------------------------------------------- resolver self-test (RBL)
class RblCheckTests(SimpleTestCase):
    """Spamhaus's RFC5782 test entries decide whether a resolver is trustworthy.

    test.dbl.spamhaus.org must answer 127.0.1.2; a resolver that returns NXDOMAIN
    for it is being fed "not listed" for everything, which is worse than an error
    because clean-looking rows are meaningless.
    """

    def setUp(self):
        from scanner.rblcheck import DBL_TEST_CLEAN, DBL_TEST_DOMAIN, DBL_TEST_LISTED, ZEN_TEST_IP

        self.names = {
            "listed": DBL_TEST_LISTED,
            "domain": DBL_TEST_DOMAIN,
            "clean": DBL_TEST_CLEAN,
            "zen": ZEN_TEST_IP,
        }
        self.OK_TABLE = {
            (DBL_TEST_LISTED, "A"): ("NOERROR", [_rec("A", "127.0.1.2")]),
            (DBL_TEST_DOMAIN, "A"): ("NOERROR", [_rec("A", "127.0.1.2")]),
            (DBL_TEST_CLEAN, "A"): ("NXDOMAIN", []),
            (ZEN_TEST_IP, "A"): ("NOERROR", [_rec("A", "127.0.0.2")]),
        }

    def _check(self, overrides=None):
        from scanner.rblcheck import check_resolver

        table = dict(self.OK_TABLE)
        table.update(overrides or {})
        return check_resolver(FakeBackend(table), "system")

    def test_ok_when_test_entries_answer(self):
        res = self._check()
        self.assertEqual(res["verdict"], "ok")
        self.assertEqual(res["fix"], "")
        self.assertEqual(res["resolver"], "stub resolver")
        self.assertEqual(len(res["checks"]), 4)
        self.assertIn("127.0.1.2", res["detail"])

    def test_refused_when_every_probe_is_an_error_code(self):
        err = ("NOERROR", [_rec("A", "127.255.255.254")])
        res = self._check({
            (self.names["listed"], "A"): err,
            (self.names["domain"], "A"): err,
            (self.names["clean"], "A"): err,
            (self.names["zen"], "A"): err,
        })
        self.assertEqual(res["verdict"], "refused")
        self.assertIn("127.255.255.254", res["detail"])
        self.assertIn("dq.spamhaus.net", res["fix"])

    def test_partial_when_only_some_entries_answer(self):
        """The measured behaviour of a resolver over Spamhaus's free quota."""
        res = self._check({
            (self.names["listed"], "A"): ("NXDOMAIN", []),
            (self.names["clean"], "A"): ("NOERROR", [_rec("A", "127.255.255.254")]),
            (self.names["zen"], "A"): ("NOERROR", [_rec("A", "127.255.255.254")]),
        })
        self.assertEqual(res["verdict"], "partial")
        self.assertIn("some Spamhaus lookups", res["headline"])
        self.assertIn("quota", res["detail"])
        self.assertTrue(res["fix"])

    def test_false_clean_when_the_test_entry_is_nxdomain(self):
        """The Google Public DNS behaviour: refusal disguised as 'not listed'."""
        res = self._check({
            (self.names["listed"], "A"): ("NXDOMAIN", []),
            (self.names["domain"], "A"): ("NXDOMAIN", []),
            (self.names["zen"], "A"): ("NXDOMAIN", []),
        })
        self.assertEqual(res["verdict"], "false_clean")
        self.assertIn("blanket NXDOMAIN", res["headline"])
        self.assertIn("127.0.1.2", res["detail"])
        self.assertTrue(res["fix"])

    def test_no_answer_when_nothing_comes_back(self):
        err = ("ERR", [])
        res = self._check({
            (self.names["listed"], "A"): err,
            (self.names["domain"], "A"): err,
            (self.names["clean"], "A"): err,
            (self.names["zen"], "A"): err,
        })
        self.assertEqual(res["verdict"], "no_answer")
        self.assertIn("No answer", res["detail"])

    def test_zen_refusal_downgrades_an_otherwise_ok_resolver(self):
        res = self._check({(self.names["zen"], "A"): ("NOERROR", [_rec("A", "127.255.255.254")])})
        self.assertEqual(res["verdict"], "partial")

    def test_zen_inconclusive_still_allows_an_ok_verdict(self):
        """The ZEN test entry is only advisory — NXDOMAIN there proves nothing."""
        res = self._check({(self.names["zen"], "A"): ("NXDOMAIN", [])})
        self.assertEqual(res["verdict"], "ok")

    def test_a_listed_clean_domain_means_answers_are_rewritten(self):
        res = self._check({(self.names["clean"], "A"): ("NOERROR", [_rec("A", "127.0.1.2")])})
        self.assertEqual(res["verdict"], "partial")

    def test_summarise_recommends_the_first_working_resolver(self):
        from scanner.rblcheck import summarise

        summary = summarise([
            {"resolver_id": "cloudflare", "verdict": "refused"},
            {"resolver_id": "google", "verdict": "partial"},
            {"resolver_id": "opendns", "verdict": "ok"},
        ])
        self.assertEqual(summary["recommended"], "opendns")
        self.assertEqual(summary["working"], ["opendns"])
        self.assertEqual(summary["unreliable"], ["google"])
        self.assertIn("1 of 3", summary["headline"])

    def test_summarise_reports_when_only_partial_resolvers_exist(self):
        from scanner.rblcheck import summarise

        summary = summarise([{"resolver_id": "system", "verdict": "partial"}])
        self.assertEqual(summary["recommended"], "")
        self.assertIn("reliably", summary["headline"])

    def test_summarise_calls_out_the_hidden_failure(self):
        from scanner.rblcheck import summarise

        summary = summarise([{"resolver_id": "google", "verdict": "false_clean"}])
        self.assertEqual(summary["recommended"], "")
        self.assertIn("hiding it as CLEAN", summary["headline"])




@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class RblCheckApiTests(SimpleTestCase):
    """GET /api/rbl-check — the UI's self-test button."""

    def setUp(self):
        cache.clear()

    def _table(self):
        from scanner.rblcheck import DBL_TEST_CLEAN, DBL_TEST_DOMAIN, DBL_TEST_LISTED, ZEN_TEST_IP

        return {
            (DBL_TEST_LISTED, "A"): ("NOERROR", [_rec("A", "127.0.1.2")]),
            (DBL_TEST_DOMAIN, "A"): ("NOERROR", [_rec("A", "127.0.1.2")]),
            (DBL_TEST_CLEAN, "A"): ("NXDOMAIN", []),
            (ZEN_TEST_IP, "A"): ("NOERROR", [_rec("A", "127.0.0.2")]),
        }

    def _get(self, query):
        from unittest.mock import patch

        with patch.object(scanner_views, "_backend_for", lambda rid: FakeBackend(self._table())):
            return Client().get(query)

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_single_resolver(self):
        resp = self._get("/api/rbl-check?resolver=system")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "no-store")
        body = resp.json()
        self.assertEqual(len(body["results"]), 1)
        self.assertEqual(body["results"][0]["resolver_id"], "system")
        self.assertEqual(body["results"][0]["verdict"], "ok")
        self.assertEqual(body["summary"]["recommended"], "system")
        self.assertIn("default", body)

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_all_resolvers(self):
        body = self._get("/api/rbl-check?resolver=all").json()
        ids = [r["resolver_id"] for r in body["results"]]
        self.assertGreaterEqual(len(ids), 4)
        self.assertEqual(len(ids), len(set(ids)))          # each tested once
        self.assertIn("system", ids)

    @override_settings(MX_RECON_RATE_LIMIT=1000)
    def test_defaults_to_the_configured_resolver(self):
        body = self._get("/api/rbl-check").json()
        self.assertEqual(body["results"][0]["resolver_id"], settings.MX_RECON_RESOLVER_DEFAULT)

    def test_rejects_unknown_resolver(self):
        self.assertEqual(Client().get("/api/rbl-check?resolver=1.2.3.4").status_code, 400)
        self.assertEqual(Client().get("/api/rbl-check?resolver=evil.example.com").status_code, 400)

    def test_rejects_post(self):
        self.assertEqual(Client().post("/api/rbl-check").status_code, 405)

    @override_settings(MX_RECON_RATE_LIMIT=1)
    def test_is_rate_limited(self):
        cache.clear()
        self.assertEqual(self._get("/api/rbl-check?resolver=system").status_code, 200)
        resp = self._get("/api/rbl-check?resolver=system")
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp)


# ------------------------------------------------- relay / echo-spoof exposure
class RelayTests(SimpleTestCase):
    """Echo spoofing uses SPF/DKIM/DMARC rather than breaking them, so the checks
    are about delegated trust and the gaps that let a relay-injected message in."""

    def _analyse(self, record, all_term="-all", dmarc=None, includes=None, include_all="-all"):
        from scanner.relays import analyse

        spf = {
            "record": record,
            "all": all_term,
            "tree": {"children": [{"domain": d, "all": include_all, "depth": 1, "children": []}
                                  for d in (includes or [])]},
        }
        return analyse(spf, dmarc if dmarc is not None else {
            "record": "v=DMARC1; p=reject; rua=mailto:dmarc@acme.com; adkim=s; aspf=s",
            "p": "reject", "rua": "mailto:dmarc@acme.com", "adkim": "s", "aspf": "s",
        })

    def test_attribution_of_known_relays(self):
        from scanner.relays import attribute, is_shared

        self.assertEqual(attribute("spf.protection.outlook.com")["label"], "Microsoft 365")
        self.assertEqual(attribute("mail.pphosted.com")["label"], "Proofpoint")
        self.assertEqual(attribute("sendgrid.net")["kind"], "esp")
        self.assertEqual(attribute("shopify.com")["kind"], "hosting")
        self.assertIsNone(attribute("mail.acme-corp.com"))
        self.assertIsNone(attribute(""))
        self.assertFalse(is_shared("acme-corp.com"))
        self.assertTrue(is_shared("eu.mimecast.com"))

    def test_hardened_domain_has_no_findings(self):
        result = self._analyse("v=spf1 ip4:203.0.113.5 -all")
        self.assertEqual(result["verdict"], "HARDENED")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["relays"], [])

    def test_shared_relay_is_reported(self):
        result = self._analyse("v=spf1 include:pphosted.com -all", includes=["pphosted.com"])
        self.assertEqual(result["verdict"], "WATCH")
        self.assertEqual([r["label"] for r in result["relays"]], ["Proofpoint"])
        self.assertEqual([f["key"] for f in result["findings"]], ["shared-relay"])
        self.assertEqual(result["includes"][0]["provider"], "Proofpoint")

    def test_permissive_all_is_exposed(self):
        self.assertEqual(self._analyse("v=spf1 +all", all_term="+all")["verdict"], "EXPOSED")
        self.assertEqual(self._analyse("v=spf1 ?all", all_term="?all")["verdict"], "EXPOSED")
        # no all term at all is equally open (RFC 7208 default is neutral)
        self.assertEqual(self._analyse("v=spf1 ip4:203.0.113.5", all_term=None)["verdict"], "EXPOSED")

    def test_ip_ranges_are_graded(self):
        exposed = self._analyse("v=spf1 ip4:10.0.0.0/8 -all")
        self.assertEqual(exposed["verdict"], "EXPOSED")
        self.assertEqual(exposed["findings"][0]["key"], "open-cidr")

        elevated = self._analyse("v=spf1 ip4:203.0.113.0/16 -all")
        self.assertEqual(elevated["verdict"], "ELEVATED")
        self.assertEqual(elevated["findings"][0]["key"], "broad-cidr")

        ok = self._analyse("v=spf1 ip4:203.0.113.0/24 -all")
        self.assertEqual(ok["verdict"], "HARDENED")

    def test_ptr_mechanism_is_flagged(self):
        result = self._analyse("v=spf1 ptr:acme-corp.com -all")
        self.assertIn("ptr-mechanism", [f["key"] for f in result["findings"]])

    def test_softfail_is_a_finding(self):
        result = self._analyse("v=spf1 ip4:203.0.113.5 ~all", all_term="~all")
        self.assertEqual(result["verdict"], "WATCH")
        self.assertIn("softfail", [f["key"] for f in result["findings"]])

    def test_permissive_include_is_a_finding(self):
        result = self._analyse("v=spf1 include:open.example -all",
                               includes=["open.example"], include_all="+all")
        self.assertEqual(result["verdict"], "ELEVATED")
        keys = [f["key"] for f in result["findings"]]
        self.assertIn("open-include", keys)
        self.assertIn("open.example", result["findings"][0]["detail"])

    def test_dmarc_gaps_are_reported(self):
        from scanner.relays import analyse

        spf = {"record": "v=spf1 ip4:203.0.113.5 -all", "all": "-all", "tree": {"children": []}}
        none_policy = analyse(spf, {"record": "v=DMARC1; p=none; rua=mailto:a@b.c", "p": "none",
                                    "rua": "mailto:a@b.c"})
        self.assertEqual(none_policy["verdict"], "ELEVATED")
        self.assertIn("dmarc-none", [f["key"] for f in none_policy["findings"]])

        missing = analyse(spf, {})
        self.assertEqual(missing["verdict"], "EXPOSED")
        self.assertIn("no-dmarc", [f["key"] for f in missing["findings"]])

        gaps = analyse(spf, {"record": "v=DMARC1; p=reject", "p": "reject"})
        keys = [f["key"] for f in gaps["findings"]]
        self.assertIn("no-rua", keys)
        self.assertIn("relaxed-alignment", keys)

        partial = analyse(spf, {"record": "v=DMARC1; p=reject; rua=mailto:a@b.c; pct=25",
                                "p": "reject", "rua": "mailto:a@b.c", "pct": "25"})
        self.assertIn("dmarc-pct", [f["key"] for f in partial["findings"]])

    def test_findings_are_ordered_by_severity_and_carry_a_fix(self):
        result = self._analyse("v=spf1 include:pphosted.com ~all", all_term="~all",
                               dmarc={"record": "v=DMARC1; p=none", "p": "none"},
                               includes=["pphosted.com"])
        severities = [f["sev"] for f in result["findings"]]
        self.assertEqual(severities, sorted(severities))
        self.assertEqual(result["verdict"], "ELEVATED")
        for finding in result["findings"]:
            self.assertTrue(finding["title"] and finding["detail"] and finding["fix"])
        self.assertEqual(result["checked"], {"spf_all": "~all", "dmarc_policy": "none"})

    def test_weak_subdomain_policy_is_flagged(self):
        weak = self._analyse("v=spf1 ip4:203.0.113.5 -all",
                             dmarc={"record": "v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c",
                                    "p": "reject", "sp": "none", "rua": "mailto:a@b.c"})
        self.assertIn("weak-subdomain-policy", [f["key"] for f in weak["findings"]])
        self.assertEqual(weak["verdict"], "ELEVATED")

        equal = self._analyse("v=spf1 ip4:203.0.113.5 -all",
                              dmarc={"record": "v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.c",
                                     "p": "reject", "sp": "reject", "rua": "mailto:a@b.c"})
        self.assertNotIn("weak-subdomain-policy", [f["key"] for f in equal["findings"]])
        # no sp= at all means subdomains inherit p — that is fine
        inherited = self._analyse("v=spf1 ip4:203.0.113.5 -all")
        self.assertNotIn("weak-subdomain-policy", [f["key"] for f in inherited["findings"]])

    def test_guidance_is_provider_specific(self):
        result = self._analyse("v=spf1 include:spf.protection.outlook.com -all",
                               includes=["spf.protection.outlook.com"])
        self.assertEqual(result["verdict"], "WATCH")
        self.assertEqual([g["label"] for g in result["guidance"]], ["Microsoft 365"])
        steps = " ".join(result["guidance"][0]["steps"])
        self.assertIn("SMTP AUTH", steps)
        self.assertIn("DKIM", steps)

        generic = self._analyse("v=spf1 include:relay.unknown-host.example -all",
                                includes=["relay.unknown-host.example"])
        self.assertEqual(generic["guidance"], [])           # unknown provider: no invented advice

    def test_actions_are_tailored_and_deduplicated(self):
        result = self._analyse("v=spf1 include:sendgrid.net ~all", all_term="~all",
                               dmarc={"record": "v=DMARC1; p=none", "p": "none"},
                               includes=["sendgrid.net"])
        titles = [a["title"] for a in result["actions"]]
        self.assertEqual(len(titles), len(set(titles)))
        self.assertIn("Harden the sending platform, not the DNS", titles)
        self.assertIn("Enforce DMARC", titles)
        self.assertIn("Tighten SPF to a hard fail", titles)
        # ordered by severity: the DMARC gap (HIGH) comes before the relay (MEDIUM)
        self.assertLess(titles.index("Enforce DMARC"), titles.index("Harden the sending platform, not the DNS"))

    def test_hardened_domain_needs_no_actions(self):
        self.assertEqual(self._analyse("v=spf1 ip4:203.0.113.5 -all")["actions"], [])
