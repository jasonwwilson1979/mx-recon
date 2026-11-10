"""
Optional front-end render smoke test.

Runs the browser bundle (scanner/static/scanner/mx-recon.js) inside a real JS
engine (QuickJS) against a stubbed DOM, then feeds it a genuine diagnostics
report and asserts the rendered HTML. This catches template-literal/typo
breakage in the UI without needing a browser.

Skipped automatically when the optional `quickjs` package is not installed
(dev-only dependency: `pip install quickjs`).
"""
from __future__ import annotations

import json
import pathlib
import unittest

from django.test import SimpleTestCase

from scanner.diagnostics import Diagnoser
from scanner.tests import DIAG_TABLE, SAMPLE_HEADERS, FakeBackend

try:  # optional dev dependency — the test is skipped when absent
    import quickjs
except ImportError:  # pragma: no cover
    quickjs = None

BUNDLE = pathlib.Path(__file__).parent / "static" / "scanner" / "mx-recon.js"

DOM_STUB = r"""
var __els = {};
function __makeEl(sel){
  return { sel: sel, innerHTML:'', textContent:'', value:'', style:{}, dataset:{}, children:[], __q:{},
    classList:{ add:function(){}, remove:function(){}, toggle:function(){}, contains:function(){return false;} },
    addEventListener:function(){}, appendChild:function(child){ this.children.push(child); return child; },
    remove:function(){}, removeChild:function(){}, setAttribute:function(){}, getAttribute:function(){ return null; },
    contains:function(){ return true; }, getClientRects:function(){ return []; },
    getBoundingClientRect:function(){ return {top:0,left:0}; }, scrollIntoView:function(){}, focus:function(){},
    scrollTop:0, scrollHeight:0, offsetTop:0,
    querySelector:function(s){
      if(s === '.ch'){ if(!this.__q[s]) this.__q[s] = __cached(this.sel + ' ' + s); return this.__q[s]; }
      return null;
    },
    querySelectorAll:function(){ return []; } };
}
function __cached(sel){ if(!__els[sel]) __els[sel] = __makeEl(sel); return __els[sel]; }
var document = {
  querySelector: __cached,
  querySelectorAll: function(){ return []; },
  getElementById: function(id){ return __cached('#' + id); },
  addEventListener: function(){},
  createElement: function(){ return __makeEl('tmp'); },
  execCommand: function(){ return false; },
  activeElement: { tagName: 'BODY' },
  body: __makeEl('body')
};
var window = { addEventListener:function(){}, scrollY:0 };
var localStorage = { _v:{}, getItem:function(k){ return this._v[k] || null; },
                     setItem:function(k,v){ this._v[k] = String(v); } };
var navigator = {};
var fetch = function(){ return Promise.resolve({ ok:true, status:200,
  json:function(){ return Promise.resolve({ ok:true, resolver:'stub resolver', ms:1, default:'system',
    resolvers:[{id:'system', label:'System default', nameservers:[], note:'', default:true}] }); } }); };
var setInterval = function(){ return 0; };
var setTimeout = function(){ return 0; };
var requestAnimationFrame = function(){};
var performance = { now:function(){ return 0; } };
function __get(sel){ return __els[sel] ? __els[sel].innerHTML : null; }
function __getText(sel){ return __els[sel] ? __els[sel].textContent : null; }
function __childClass(sel, i){
  var e = __els[sel];
  return e && e.children && e.children[i] ? e.children[i].className : null;
}
"""


@unittest.skipUnless(quickjs, "quickjs not installed (optional: pip install quickjs)")
class JsRenderTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from scanner.engine import Engine
        from scanner.tests import gmail_like_backend

        report, _logs = Diagnoser(SAMPLE_HEADERS, backend=FakeBackend(DIAG_TABLE)).run()
        cls.report = report
        scan_report, _scan_logs = Engine(
            "acme-corp.com", "", backend=gmail_like_backend(),
            rdap_fn=lambda domain, timeout=6.0: {
                "registrar": "Example Registrar",
                "registrar_id": "999",
                "status": ["client transfer prohibited"],
                "events": {"registration": "2015-04-01T00:00:00Z", "expiration": "2099-04-01T00:00:00Z"},
                "nameservers": ["ns1.acme-corp.com"],
                "dnssec": True,
                "source": "https://rdap.example/domain/acme-corp.com",
            },
        ).run()
        cls.ctx = quickjs.Context()
        cls.ctx.eval(DOM_STUB)
        cls.ctx.eval(BUNDLE.read_text(encoding="utf-8"))
        cls.ctx.eval("var R = " + json.dumps(report) + ";")
        cls.ctx.eval("var S = " + json.dumps(scan_report) + ";")
        cls.ctx.eval("renderDiag(R);")

    def html(self, selector: str) -> str:
        return self.ctx.eval(f"__get('{selector}')") or ""

    def test_bundle_defines_renderers(self):
        self.assertEqual(self.ctx.eval("typeof renderDiag"), "function")
        self.assertEqual(self.ctx.eval("typeof startScan"), "function")

    def test_verdict_banner(self):
        verdict = self.html("#diagVerdict")
        self.assertIn("CRITICAL", verdict)
        self.assertIn(str(self.report["risk"]), verdict)
        self.assertIn("drcfamilydentistry.com", verdict)

    def test_root_causes_render(self):
        causes = self.html("#cb-diagcauses")
        self.assertIn("no public key", causes)
        self.assertIn("paubox._domainkey.drcfamilydentistry.com", causes)
        self.assertIn("FIX //", causes)
        self.assertIn("FINDING", self.html("#st-diagcauses"))

    def test_checks_passed_render(self):
        passed = self.html("#cb-diagpass")
        self.assertIn("passlist", passed)
        self.assertIn("SPF", passed)

    def test_auth_table_render(self):
        auth = self.html("#cb-diagauth")
        self.assertIn("cudaops.com", auth)
        self.assertIn("SPF", auth.upper())
        self.assertIn("DKIM", auth.upper())

    def test_dkim_and_spf_panels(self):
        dkim = self.html("#cb-diagdkim")
        self.assertIn("NXDOMAIN", dkim)
        self.assertIn("1024", dkim)
        spf = self.html("#cb-diagspf")
        self.assertIn("PASS", spf)
        self.assertIn("52.27.124.21", spf)

    def test_hops_gateway_and_dns_panels(self):
        hops = self.html("#cb-diaghops")
        self.assertIn("TLSv1.2", hops)
        self.assertIn("outbound9-encrypted-mta.paubox.com", hops)
        gateway = self.html("#cb-diaggate")
        self.assertIn("X-BESS-REASON", gateway)
        dns = self.html("#cb-diagdns")
        self.assertIn("paubox._domainkey.drcfamilydentistry.com", dns)

    # ---------------------------------------------------------- info buttons

    def test_info_buttons_are_injected_into_card_headers(self):
        self.ctx.eval("attachInfoButtons();")
        self.assertEqual(self.ctx.eval("__childClass('#card-spf .ch', 0)"), "infobtn")
        self.assertEqual(self.ctx.eval("__childClass('#card-dkim .ch', 0)"), "infobtn")
        self.assertEqual(self.ctx.eval("__childClass('#card-dmarc .ch', 0)"), "infobtn")
        self.assertEqual(self.ctx.eval("__childClass('#card-diagdkim .ch', 0)"), "infobtn")

    def test_spf_explainer(self):
        self.ctx.eval("showInfo('spf');")
        self.assertEqual(self.ctx.eval("__getText('#infoPopTitle')"), "SPF")
        self.assertEqual(self.ctx.eval("__getText('#infoPopFull')"), "Sender Policy Framework")
        self.assertIn("Who is allowed to send email", self.ctx.eval("__getText('#infoPopQ')"))
        self.assertIn("v=spf1", self.ctx.eval("__getText('#infoPopExample')"))

    def test_dkim_and_dmarc_explainers(self):
        self.ctx.eval("showInfo('dkim');")
        self.assertEqual(self.ctx.eval("__getText('#infoPopFull')"), "DomainKeys Identified Mail")
        self.assertIn("altered in transit", self.ctx.eval("__getText('#infoPopQ')"))
        self.ctx.eval("showInfo('dmarc');")
        self.assertIn("Domain-based Message Authentication", self.ctx.eval("__getText('#infoPopFull')"))
        self.assertIn("fails SPF and DKIM", self.ctx.eval("__getText('#infoPopQ')"))

    def test_related_protocol_chips_on_the_zone_card(self):
        self.ctx.eval("showInfo('cname');")
        note = self.ctx.eval("__get('#infoPopNote')")
        self.assertIn("MTA-STS", note)
        self.assertIn("BIMI", note)

    def test_resolver_and_info_functions_exist(self):
        for name in ("loadResolvers", "probeResolver", "onResolverChange", "showInfo", "hideInfo"):
            self.assertEqual(self.ctx.eval(f"typeof {name}"), "function", name)

    def test_layout_is_one_card_per_row(self):
        # the layout is hard-coded now: no switcher, no stored preference
        self.assertEqual(self.ctx.eval("typeof applyLayout"), "undefined")
        self.assertEqual(self.ctx.eval("typeof initLayout"), "undefined")

    # ---------------------------------------------------------- RBL refusals

    def test_rbl_helpers_exist(self):
        for name in ("rblRefusedZones", "rblFixNote", "isPublicSpamhaus"):
            self.assertEqual(self.ctx.eval(f"typeof {name}"), "function", name)

    def test_rbl_fix_note_renders_when_spamhaus_refuses(self):
        self.ctx.eval("""
          var B = JSON.parse(JSON.stringify(S));
          B.blacklists.domain.forEach(function(z){
            if(z.zone === 'dbl.spamhaus.org'){ z.status = 'blocked'; z.code = '127.255.255.254'; }
          });
          renderRep(B.blacklists.domain);
          renderRBL(B.blacklists);
        """)
        rep = self.html("#cb-rep")
        self.assertIn("RESOLVER BLOCKED", rep)
        self.assertIn("dbl.spamhaus.org", rep)
        self.assertIn("System default", rep)
        self.assertIn("dq.spamhaus.net", rep)
        self.assertIn("DJANGO_RBL_EXTRA_DOMAIN", rep)
        self.assertIn("DJANGO_RBL_DISABLED", rep)
        self.assertIn("System default", self.html("#cb-rbl"))

    def test_no_rbl_fix_note_when_every_zone_answers(self):
        self.ctx.eval("renderRep(S.blacklists.domain); renderRBL(S.blacklists);")
        self.assertNotIn("dq.spamhaus.net", self.html("#cb-rep"))
        self.assertNotIn("Spamhaus refused", self.html("#cb-rbl"))
        self.assertEqual(self.ctx.eval("rblRefusedZones(S.blacklists).length"), 0)

    def test_scan_summary_marks_inconclusive_zones(self):
        self.ctx.eval("""
          var B2 = JSON.parse(JSON.stringify(S));
          B2.blacklists.domain.forEach(function(z){
            if(z.zone === 'dbl.spamhaus.org'){ z.status = 'blocked'; z.code = '127.255.255.254'; }
          });
          var __summary = buildScanSummary(B2);
        """)
        self.assertIn("clean (1 zone(s) inconclusive: dbl.spamhaus.org)",
                      self.ctx.eval("__summary"))

    def test_public_resolver_warning_renders_on_both_rbl_cards(self):
        self.ctx.eval("""
          REPORT = { resolver: 'Cloudflare (1.1.1.1) (dnspython)', resolver_public: true };
          renderRep(S.blacklists.domain);
          renderRBL(S.blacklists);
        """)
        rep = self.html("#cb-rep")
        self.assertIn("Cloudflare (1.1.1.1)", rep)
        self.assertIn("false CLEAN", rep)
        self.assertIn("System default", rep)
        self.assertIn("false CLEAN", self.html("#cb-rbl"))
        self.ctx.eval("""var __pub = buildScanSummary(Object.assign({}, S,
            { resolver_public: true, resolver: 'Cloudflare (1.1.1.1) (dnspython)' }));""")
        self.assertIn("public DNS — blacklist rows unverified", self.ctx.eval("__pub"))

    def test_no_public_resolver_warning_for_system_resolver(self):
        self.ctx.eval("""
          REPORT = { resolver: 'system resolver (dnspython)', resolver_public: false };
          renderRep(S.blacklists.domain);
          renderRBL(S.blacklists);
          REPORT = null;
        """)
        self.assertNotIn("false CLEAN", self.html("#cb-rep"))
        self.assertNotIn("false CLEAN", self.html("#cb-rbl"))

    # ---------------------------------------------------------- scan sweep line

    def test_scan_banner_and_sweep_helpers_exist(self):
        for name in ("sessionId", "buildVersion", "resolverLabel", "replayLogs", "startScan",
                     "startSweep", "stopSweep", "cancelSweep", "sweepOffset"):
            self.assertEqual(self.ctx.eval(f"typeof {name}"), "function", name)

    def test_sweep_duration_and_banner_prefix(self):
        self.assertEqual(self.ctx.eval("SCAN_SWEEP_MS"), 2600)
        self.assertEqual(self.ctx.eval("SCAN_BANNER_PREFIX"), "──── ENGAGING TARGET")

    def test_sweep_offset_travels_down_the_page_and_wraps(self):
        top = self.ctx.eval("sweepOffset(0, 0, 1000)")
        half = self.ctx.eval("sweepOffset(1300, 0, 1000)")
        bottom = self.ctx.eval("sweepOffset(2599, 0, 1000)")
        wrapped = self.ctx.eval("sweepOffset(2600, 0, 1000)")
        self.assertEqual(top, -6)               # starts just above the viewport
        self.assertGreater(half, 400)           # half a cycle in, it is mid-page
        self.assertLess(half, 600)
        self.assertGreater(bottom, 990)         # reaches the bottom edge
        self.assertEqual(wrapped, -6)           # then repeats from the top

    def test_start_sweep_moves_the_line_and_stop_resets_it(self):
        self.ctx.eval("startSweep();")
        started = self.ctx.eval("__els['.scanline'].style.transform")
        self.assertIn("translate3d", started)
        self.ctx.eval("stopSweep();")
        self.assertEqual(self.ctx.eval("__els['.scanline'].style.transform"), "translate3d(0,-6px,0)")

    def test_boot_log_announces_the_js_driven_sweep(self):
        # a stale deploy should be obvious at a glance: the boot log names the sweep
        # implementation, so check the shipped bundle carries the announcement
        self.assertIn("scan sweep armed — JS-driven", BUNDLE.read_text(encoding="utf-8"))

    def test_sweep_line_advances_frame_by_frame(self):
        """Drives the sweep with a fake rAF clock: the transform must change from
        frame to frame, i.e. the line really travels down the page."""
        transforms = self.ctx.eval("""
          var __savedRAF = requestAnimationFrame, __savedNow = performance.now;
          var __seen = [];
          try{
            var __frames = [], __clock = 0;
            requestAnimationFrame = function(cb){ __frames.push(cb); return __frames.length; };
            cancelAnimationFrame = function(){};
            performance.now = function(){ return __clock; };
            startSweep();
            __clock = 650;  __frames.shift()();
            __seen.push(document.querySelector('.scanline').style.transform);
            __clock = 1300; __frames.shift()();
            __seen.push(document.querySelector('.scanline').style.transform);
          }finally{
            requestAnimationFrame = __savedRAF; performance.now = __savedNow;
          }
          stopSweep();
          __seen.join('|');
        """)
        first, second = transforms.split("|")
        self.assertIn("translate3d", first)
        self.assertNotEqual(first, second)          # it moved between frames

    def test_replay_skips_the_duplicate_scan_banner(self):
        msgs = self.ctx.eval("""
          logbody.children.length = 0;
          replayLogs([
            {msg: SCAN_BANNER_PREFIX + ': TEST.COM ────', cls:'info', ts:'00:00:01'},
            {msg:'MARKER-LINE-ONE', cls:'dns', ts:'00:00:02'}
          ]);
          logbody.children.map(function(c){ return c.innerHTML; }).join('|');
        """)
        self.assertIn("MARKER-LINE-ONE", msgs)
        self.assertNotIn("ENGAGING TARGET", msgs)      # one banner per scan, printed at click

    def test_resolver_label_falls_back_to_system_default(self):
        self.assertEqual(self.ctx.eval("resolverLabel()"), "System default")

    def test_start_scan_prints_one_banner_with_scan_context(self):
        self.ctx.eval("""
          logbody.children.length = 0;
          $('#inDomain').value = 'example.com';
          startScan();
        """)
        # startScan is async: drain its continuation here (the stub scan body has no
        # report, so it aborts) rather than letting it land inside another test
        self.ctx.eval("void 0; scanBusy = false;")
        msgs = self.ctx.eval("logbody.children.map(function(c){ return c.innerHTML; }).join('|');")
        self.assertIn("ENGAGING TARGET: EXAMPLE.COM", msgs)
        self.assertIn("modules armed", msgs)          # resolver / build / session context line
        self.assertIn("resolver System default", msgs)
        self.assertEqual(len(msgs.split("ENGAGING TARGET")) - 1, 1)   # never duplicated

    # ---------------------------------------------------------- RBL self-test

    def test_rbl_self_test_helpers_exist(self):
        for name in ("runRblCheck", "renderRblCheck", "rblCheckPlaceholder"):
            self.assertEqual(self.ctx.eval(f"typeof {name}"), "function", name)

    def test_rbl_self_test_placeholder_and_info_button(self):
        self.ctx.eval("renderRblCheck(null); attachInfoButtons();")
        html = self.html("#cb-rblcheck")
        self.assertIn("TEST ALL RESOLVERS", html)
        self.assertIn("RFC5782", html)
        self.assertIn("NOT RUN", self.html("#st-rblcheck"))
        self.assertEqual(self.ctx.eval("__childClass('#card-rblcheck .ch', 0)"), "infobtn")

    def test_rbl_self_test_renders_verdicts_and_the_fix(self):
        self.ctx.eval("""
          renderRblCheck({
            default: 'system',
            summary: {headline: '1 of 2 resolver(s) can query Spamhaus truthfully',
                      working: ['system'], recommended: 'system', count: 2},
            results: [
              {resolver_id:'system', resolver:'system resolver (dnspython)', verdict:'ok',
               headline:'Spamhaus answers this resolver with real data',
               detail:'The RFC5782 test entry returned 127.0.1.2.', fix:'',
               checks:[{query:'test.dbl.spamhaus.org', answer:'127.0.1.2', expected:'127.0.1.2'}]},
              {resolver_id:'google', resolver:'Google (8.8.8.8) (dnspython)', verdict:'false_clean',
               headline:'This resolver is answered with a blanket NXDOMAIN',
               detail:'test.dbl.spamhaus.org came back NXDOMAIN instead of 127.0.1.2.',
               fix:'use the "System default" resolver or Spamhaus DQS zones',
               checks:[{query:'test.dbl.spamhaus.org', answer:'NXDOMAIN', expected:'127.0.1.2'}]}
            ]});
        """)
        html = self.html("#cb-rblcheck")
        self.assertIn("1 of 2 resolver(s)", html)
        self.assertIn("FALSE CLEAN", html)
        self.assertIn("DJANGO_RESOLVER_DEFAULT=system", html)
        self.assertIn("FIX //", html)
        self.assertIn("127.0.1.2", html)
        self.assertIn("DEFAULT", html)
        self.assertIn("1/2 USABLE", self.html("#st-rblcheck"))

    def test_rbl_self_test_explainer(self):
        self.ctx.eval("showInfo('rblcheck');")
        self.assertEqual(self.ctx.eval("__getText('#infoPopTitle')"), "RBL SELF-TEST")
        self.assertIn("blanket NXDOMAIN", self.ctx.eval("__get('#infoPopBody')"))
        self.assertIn("127.0.1.2", self.ctx.eval("__getText('#infoPopExample')"))

    # ------------------------------------------------- relay / echo-spoof card

    def test_relay_card_renders(self):
        self.ctx.eval("""
          renderRelay({
            verdict:'ELEVATED', headline:'Sending authority is delegated or weakly enforced',
            relays:[{domain:'pphosted.com', label:'Proofpoint', kind:'gateway', kind_label:'mail security gateway'}],
            includes:[{domain:'pphosted.com', all:'-all', provider:'Proofpoint', kind:'gateway'},
                      {domain:'_spf.google.com', all:'~all', provider:'Google Workspace', kind:'cloud'}],
            checked:{spf_all:'~all', dmarc_policy:'none'},
            findings:[
              {key:'dmarc-none', sev:1, title:'DMARC policy is p=none',
               detail:'DMARC is monitoring only: failures are reported but never blocked.',
               fix:'Advance to <b>p=quarantine</b>, then <b>p=reject</b>.'},
              {key:'shared-relay', sev:2, title:'Sending authority is delegated to shared infrastructure',
               detail:'SPF authorises <b>Proofpoint</b> — the precondition for echo-spoofing.',
               fix:'Confirm each platform enforces domain ownership.'}
            ]});
          attachInfoButtons();
        """)
        html = self.html("#cb-relay")
        self.assertIn("DELEGATED TO", html)
        self.assertIn("Proofpoint", html)
        self.assertIn("mail security gateway", html)
        self.assertIn("p=none", html)
        self.assertIn("HIGH", html)                     # severity chip for sev 1
        self.assertIn("SPF INCLUDES", html)
        self.assertIn("Google Workspace", html)
        self.assertIn("ELEVATED", self.html("#st-relay"))
        self.assertEqual(self.ctx.eval("__childClass('#card-relay .ch', 0)"), "infobtn")

    def test_relay_card_hardened_state(self):
        self.ctx.eval("renderRelay({verdict:'HARDENED', headline:'Nothing in DNS lets a relay inject mail as this domain', relays:[], includes:[], checked:{}, findings:[]});")
        html = self.html("#cb-relay")
        self.assertIn("Nothing in DNS lets a relay inject mail", html)
        self.assertIn("No relay or policy exposure", html)
        self.assertIn("HARDENED", self.html("#st-relay"))

    def test_relay_explainer(self):
        self.ctx.eval("showInfo('relay');")
        self.assertEqual(self.ctx.eval("__getText('#infoPopTitle')"), "RELAY / ECHO-SPOOF")
        self.assertIn("echo", self.ctx.eval("__get('#infoPopBody')").lower())
        self.assertIn("pphosted.com", self.ctx.eval("__getText('#infoPopExample')"))

    def test_relay_card_shows_next_actions_and_provider_guidance(self):
        self.ctx.eval("""
          renderRelay({
            verdict:'WATCH', headline:'No open policy, but the delegation/visibility gaps remain',
            relays:[{domain:'spf.protection.outlook.com', label:'Microsoft 365', kind:'cloud',
                     kind_label:'hosted mail platform'}],
            includes:[{domain:'spf.protection.outlook.com', all:'-all', provider:'Microsoft 365', kind:'cloud'}],
            checked:{spf_all:'-all', dmarc_policy:'reject'},
            findings:[
              {key:'shared-relay', sev:2, title:'Sending authority is delegated to shared infrastructure',
               detail:'SPF authorises Microsoft 365.', fix:'Confirm each platform enforces domain ownership.'},
              {key:'relaxed-alignment', sev:3, title:'Relaxed DMARC alignment', detail:'adkim=r/aspf=r.',
               fix:'Consider adkim=s; aspf=s.'}],
            actions:[
              {title:'Harden the sending platform, not the DNS',
               detail:'You cannot remove the relay from SPF while you send through it.'},
              {title:'Consider strict alignment', detail:'Add adkim=s; aspf=s once reports are clean.'}],
            guidance:[{label:'Microsoft 365', kind_label:'hosted mail platform',
                       steps:['Turn on MFA and Conditional Access.',
                              'Disable SMTP AUTH on mailboxes that do not need it.']}]
          });
        """)
        html = self.html("#cb-relay")
        self.assertIn("NEXT ACTIONS", html)
        self.assertIn("Harden the sending platform", html)
        self.assertIn("HOW TO HARDEN", html)
        self.assertIn("SMTP AUTH", html)
        self.assertIn("WATCH", self.html("#st-relay"))

    def test_scan_summary_reports_relay_exposure(self):
        text = self.ctx.eval("buildScanSummary(S);")
        self.assertIn("Relay exposure:", text)

    # ---------------------------------------------------------- copy summary

    def test_copy_helpers_exist(self):
        for name in ("copyText", "copySummary", "buildScanSummary", "buildDiagSummary",
                     "showCopyFallback", "hideCopy"):
            self.assertEqual(self.ctx.eval(f"typeof {name}"), "function", name)

    def test_scan_summary_is_compact_and_plain(self):
        text = self.ctx.eval("buildScanSummary(S);")
        self.assertIn("MX-RECON — email security summary", text)
        self.assertIn("acme-corp.com", text)
        self.assertIn("Score 100/100 (HARDENED)", text)
        self.assertIn("What to fix: nothing", text)
        self.assertIn("Records", text)
        self.assertIn("MTA-STS yes", text)
        self.assertIn("registrar Example Registrar", text)
        self.assertIn("ns1.acme-corp.com", text)
        self.assertNotIn("<b>", text)              # no HTML in the pasted text
        self.assertLess(len(text), 2200)           # small enough for a chat message
        self.assertLess(len(text.split("\n")), 34)

    def test_domain_control_card_renders(self):
        self.ctx.eval("renderControl(S.control);")
        card = self.html("#cb-control")
        self.assertIn("Example Registrar", card)
        self.assertIn("999", card)                       # IANA registrar id
        self.assertIn("ns1.acme-corp.com", card)
        self.assertIn("AUTHORITATIVE NAMESERVERS", card)
        self.assertIn("DNSSEC", card)
        self.assertIn("Example Registrar", self.html("#st-control"))

    def test_diag_summary_is_compact_and_plain(self):
        text = self.ctx.eval("buildDiagSummary(R);")
        self.assertIn("MX-RECON — delivery diagnosis", text)
        self.assertIn("drcfamilydentistry.com", text)
        self.assertIn("Risk ", text)
        self.assertIn("CRITICAL", text)
        self.assertIn("no public key", text)       # the root cause is carried over
        self.assertIn("52.27.124.21", text)
        self.assertIn("paubox._domainkey.drcfamilydentistry.com", text)
        self.assertIn("Generated by MX-RECON", text)
        self.assertNotIn("<b>", text)
        self.assertLess(len(text), 2500)
        self.assertLess(len(text.split("\n")), 40)
