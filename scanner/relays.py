"""
Relay / echo-spoofing exposure analysis.

"Echo spoofing" (the EchoSpoofing campaign documented by Guardio Labs in 2024)
does not break SPF, DKIM or DMARC — it *uses* them. An attacker hands a message
to a relay the victim domain has already authorised (an ESP, a security gateway,
a hosting platform), and that relay re-sends ("echoes") it from its own trusted
infrastructure with its own SPF authorisation and its own DKIM signature. The
recipient sees a perfectly authenticated message carrying content the domain
owner never sent: SPF pass, DKIM pass, DMARC pass.

The precondition is always the same: the domain's SPF/DKIM delegate sending
authority to shared infrastructure without proof that whoever injects mail owns
the domain. Nothing in DNS can prove that from the outside — but we can show how
much trust is delegated, and the DNS-level weaknesses that let a relay-injected
message be delivered.

This module attributes SPF includes and sending hosts to known providers and
turns that into findings. It never claims a relay *is* exploitable: it reports
delegated trust plus the configuration gaps that turn delegation into exposure.
"""
from __future__ import annotations

import html
import re

# suffix, label, kind — kind is what the provider is, not how bad it is.
#   gateway  mail security gateway / filtering relay
#   esp      bulk email / transactional sending platform
#   cloud    hosted mail platform (multi-tenant by design)
#   hosting  shared web/mail hosting
PROVIDERS = [
    ("pphosted.com", "Proofpoint", "gateway"),
    ("ppe-hosted.com", "Proofpoint Essentials", "gateway"),
    ("proofpoint.com", "Proofpoint", "gateway"),
    ("mimecast.com", "Mimecast", "gateway"),
    ("barracudanetworks.com", "Barracuda", "gateway"),
    ("iphmx.com", "Cisco Email Security", "gateway"),
    ("messagelabs.com", "Broadcom Email Security", "gateway"),
    ("hornetsecurity.com", "Hornetsecurity", "gateway"),
    ("avanan.com", "Avannan", "gateway"),
    ("paubox.com", "Paubox", "gateway"),
    ("spf.protection.outlook.com", "Microsoft 365", "cloud"),
    ("protection.outlook.com", "Microsoft 365", "cloud"),
    ("_spf.google.com", "Google Workspace", "cloud"),
    ("zoho.com", "Zoho Mail", "cloud"),
    ("zoho.eu", "Zoho Mail (EU)", "cloud"),
    ("amazonses.com", "Amazon SES", "esp"),
    ("sendgrid.net", "SendGrid", "esp"),
    ("mailgun.net", "Mailgun", "esp"),
    ("mailgun.org", "Mailgun", "esp"),
    ("mandrillapp.com", "Mailchimp Transactional", "esp"),
    ("mcsv.net", "Mailchimp", "esp"),
    ("sparkpostmail.com", "SparkPost", "esp"),
    ("mailjet.com", "Mailjet", "esp"),
    ("mtasv.net", "Postmark", "esp"),
    ("sendinblue.com", "Brevo (Sendinblue)", "esp"),
    ("brevo.com", "Brevo", "esp"),
    ("elasticemail.com", "Elastic Email", "esp"),
    ("salesforce.com", "Salesforce", "esp"),
    ("hubspotemail.net", "HubSpot", "esp"),
    ("hubspot.com", "HubSpot", "esp"),
    ("klaviyomail.com", "Klaviyo", "esp"),
    ("createsend.com", "Campaign Monitor", "esp"),
    ("cmail19.com", "Campaign Monitor", "esp"),
    ("cmail20.com", "Campaign Monitor", "esp"),
    ("customer.io", "Customer.io", "esp"),
    ("mailerlite.com", "MailerLite", "esp"),
    ("activecampaign.com", "ActiveCampaign", "esp"),
    ("constantcontact.com", "Constant Contact", "esp"),
    ("sendpulse.com", "SendPulse", "esp"),
    ("intercom.io", "Intercom", "esp"),
    ("zendesk.com", "Zendesk", "esp"),
    ("freshdesk.com", "Freshdesk", "esp"),
    ("secureserver.net", "GoDaddy", "hosting"),
    ("websitewelcome.com", "HostGator", "hosting"),
    ("ovh.net", "OVH", "hosting"),
    ("ionos.com", "IONOS", "hosting"),
    ("gandi.net", "Gandi", "hosting"),
    ("siteground.com", "SiteGround", "hosting"),
    ("wix.com", "Wix", "hosting"),
    ("squarespace.com", "Squarespace", "hosting"),
    ("shopify.com", "Shopify", "hosting"),
    ("wordpress.com", "WordPress.com", "hosting"),
]

KIND_LABELS = {
    "gateway": "mail security gateway",
    "esp": "bulk sending platform",
    "cloud": "hosted mail platform",
    "hosting": "shared hosting",
}

_RE_IP4 = re.compile(r"\bip4:([0-9./]+)", re.I)
_RE_IP6 = re.compile(r"\bip6:([0-9a-f:/]+)", re.I)
_RE_ZONE_SUFFIX = re.compile(r"[^a-z0-9.-]")


def attribute(host: str):
    """Provider for a hostname/SPF target, or None. Longest suffix wins."""
    name = _RE_ZONE_SUFFIX.sub("", str(host or "").lower().rstrip("."))
    if not name:
        return None
    best = None
    for suffix, label, kind in PROVIDERS:
        if name == suffix or name.endswith("." + suffix):
            if best is None or len(suffix) > len(best[0]):
                best = (suffix, label, kind)
    if not best:
        return None
    return {"suffix": best[0], "label": best[1], "kind": best[2],
            "kind_label": KIND_LABELS.get(best[2], best[2]), "host": name}


def is_shared(host: str) -> bool:
    return attribute(host) is not None


# --------------------------------------------------------------------- findings
# severity follows the engine's convention: 0 = critical, 3 = advisory.
FINDINGS = {
    "open-spf": (0, "SPF authorises everyone",
                 "The SPF record ends in <b>+all</b>/<b>?all</b> (or has no <b>all</b> at all), so every host "
                 "on the internet is allowed to send as this domain. Relay abuse needs no relay here.",
                 "Publish <b>-all</b> and list only the senders you control."),
    "open-cidr": (0, "SPF authorises an enormous IP range",
                  "An <b>ip4/ip6</b> mechanism covers almost the whole internet, which is equivalent to "
                  "<b>+all</b>: anyone inside that range can send as this domain.",
                  "Replace the range with the exact sending hosts, or flatten it to the /24s in use."),
    "broad-cidr": (1, "SPF authorises a broad IP range",
                   "A wide <b>ip4/ip6</b> range means hosts you do not run can pass SPF for this domain.",
                   "Narrow the range, or move the sending service behind a dedicated relay."),
    "shared-relay": (2, "Sending authority is delegated to shared infrastructure",
                     "SPF authorises <b>{relays}</b>. Anyone who can inject outbound mail through one of "
                     "those platforms can pass SPF for this domain — the precondition for echo-spoofing. "
                     "Whether it is exploitable depends on the platform: it must verify that a tenant owns "
                     "the domain before letting it send as that domain.",
                     "Confirm each platform enforces domain ownership for outbound mail (Microsoft 365 does; "
                     "Proofpoint added tenant approval after the 2024 campaign), restrict which tenants may "
                     "relay, and watch DMARC <b>rua</b> reports for senders you did not authorise."),
    "open-include": (1, "An included SPF policy is permissive",
                     "<b>include:{domain}</b> resolves to an SPF record that ends in <b>+all</b>/<b>?all</b>, "
                     "so the domain inherits an open policy through it.",
                     "Ask the provider for a strict SPF record, or stop including them."),
    "ptr-mechanism": (2, "SPF uses the deprecated ptr: mechanism",
                      "<b>ptr:</b> authorises any host whose reverse DNS matches this domain — slow, "
                      "unreliable, and it widens the sending set beyond what you control (RFC 7208 §5.5 "
                      "advises against it).",
                      "Replace <b>ptr:</b> with explicit <b>ip4:</b>/<b>ip6:</b> entries or an "
                      "<b>include:</b> of the provider's own SPF."),
    "softfail": (2, "SPF soft-fails instead of hard-failing",
                 "The record ends in <b>~all</b> (SoftFail). Many receivers treat SoftFail as neutral, so "
                 "mail from an unauthorised host — including a relay that injected it — is usually still "
                 "delivered.",
                 "Once you are sure all legitimate senders are listed, tighten to <b>-all</b>."),
    "no-dmarc": (0, "No DMARC record",
                 "Without DMARC there is no policy tying SPF/DKIM to the visible From address, so nothing "
                 "tells a receiver to reject relay-injected mail.",
                 "Publish <b>v=DMARC1; p=none; rua=mailto:dmarc@…</b> to start collecting reports, then "
                 "move to <b>p=quarantine</b> and <b>p=reject</b>."),
    "dmarc-none": (1, "DMARC policy is p=none",
                   "DMARC is monitoring only: failures are reported but never blocked, so an "
                   "echo-spoofed message that fails authentication is still delivered.",
                   "Advance to <b>p=quarantine</b>, then <b>p=reject</b>."),
    "dmarc-pct": (2, "DMARC applies to only part of your mail",
                  "<b>pct</b> is below 100, so the policy is not applied to every message.",
                  "Raise <b>pct</b> to 100 (or remove it — 100 is the default)."),
    "no-rua": (2, "No DMARC aggregate reporting",
               "Nothing reports who is sending as this domain. DMARC <b>rua</b> reports are the only "
               "practical way to notice echo-spoofing: mail that authenticates perfectly for your domain "
               "from infrastructure you do not recognise.",
               "Add <b>rua=mailto:dmarc@yourdomain</b> and review the reports."),
    "relaxed-alignment": (3, "Relaxed DMARC alignment",
                          "The default relaxed alignment lets a <i>subdomain</i> of yours satisfy SPF/DKIM "
                          "alignment, which widens what a relay can sign for.",
                          "Consider <b>adkim=s; aspf=s</b> once you know all legitimate senders use the "
                          "exact From domain."),
    "weak-subdomain-policy": (1, "Subdomains have a weaker DMARC policy",
                              "<b>sp={sp}</b> is weaker than <b>p={p}</b>, so mail claiming to come from a "
                              "subdomain of this domain is treated more leniently — a relay can use a "
                              "subdomain to escape enforcement.",
                              "Remove <b>sp=</b> (subdomains then inherit <b>p</b>) or set "
                              "<b>sp=reject</b>."),
}

VERDICT_HEADLINES = {
    "EXPOSED": "Relay abuse needs no relay here — the policy is effectively open",
    "ELEVATED": "Sending authority is delegated or weakly enforced",
    "WATCH": "No open policy, but the delegation/visibility gaps remain",
    "HARDENED": "Nothing in DNS lets a relay inject mail as this domain",
}

# The fix for a delegated relay is almost never in DNS — it is on the platform.
PROVIDER_GUIDANCE = {
    "Microsoft 365": [
        "Turn on MFA and Conditional Access — a compromised mailbox is the most common way mail is injected "
        "through your own tenant.",
        "Disable SMTP AUTH on mailboxes that do not need it (Exchange admin centre → Recipients → Mailboxes "
        "→ Email apps); it is the path most often abused for relay injection.",
        "Review Mail flow → Connectors and any 'direct send' / SMTP-relay configuration, and remove anything "
        "you do not recognise.",
        "Turn on outbound spam policies plus the 'suspicious email sending patterns' alert, and set an "
        "outbound rate limit.",
        "Confirm DKIM is enabled for this domain in Defender → Email authentication (selector1/selector2 "
        "published).",
    ],
    "Proofpoint": [
        "Ask Proofpoint to confirm tenant approval / approved-senders is enforced for your organisation — "
        "they added it after the 2024 EchoSpoofing campaign.",
        "Review which senders and tenants are permitted to relay as this domain.",
    ],
    "Google Workspace": [
        "Restrict which users may send as this domain, and keep app passwords / less-secure access off.",
        "Review Apps → Gmail → Routing and compliance rules for anything that rewrites senders.",
    ],
    "Amazon SES": [
        "Verify the domain (not just an address), send from a dedicated configuration set, and restrict the "
        "IAM keys that can send.",
    ],
    "SendGrid": [
        "Enable Domain Authentication (not just a verified sender) so only your account can send as this "
        "domain.",
    ],
    "Salesforce": ["Review which orgs and users may send from this domain, and keep DKIM verification on."],
    "HubSpot": ["Require domain authentication (DKIM) and review which users may send from this domain."],
}

KIND_GUIDANCE = {
    "gateway": [
        "Review the gateway's outbound relay rules: only your own tenant/connector should be allowed to "
        "relay as this domain.",
        "Ask the provider to confirm they verify domain ownership for outbound mail.",
    ],
    "esp": [
        "Require domain verification (SPF/DKIM records) before the platform will send as this domain, and "
        "check that no shared sub-user can set this From domain.",
        "Rotate and scope API keys — most relay abuse starts with a leaked sending key.",
    ],
    "cloud": [
        "Restrict which accounts in the platform may send as this domain, and require MFA on them.",
        "Confirm DKIM signing is enabled for the custom domain.",
    ],
    "hosting": [
        "Shared hosting often lets any account on the server send as any domain hosted there — ask the host "
        "how per-domain ownership is enforced.",
        "If it cannot be enforced, move mail to a platform that verifies domain ownership.",
    ],
}


# The order matters: this is the checklist the card shows under "NEXT ACTIONS".
ACTION_FOR_FINDING = {
    "open-spf": ("Close the SPF policy",
                 "Replace <b>+all</b>/<b>?all</b> with <b>-all</b> and list only the senders you control."),
    "open-cidr": ("Shrink the authorised IP range", "Replace the huge CIDR with the exact hosts in use."),
    "no-dmarc": ("Publish DMARC",
                 "Start at <b>p=none; rua=mailto:dmarc@…</b>, read the reports, then move to "
                 "<b>p=quarantine</b> and <b>p=reject</b>."),
    "broad-cidr": ("Narrow the authorised IP range", "A /16 lets hosts you do not run pass SPF."),
    "open-include": ("Fix or drop the permissive include",
                     "The included policy ends in <b>+all</b>, so you inherit an open policy through it."),
    "dmarc-none": ("Enforce DMARC", "Move <b>p=none</b> to <b>p=quarantine</b>, then <b>p=reject</b>."),
    "shared-relay": ("Harden the sending platform, not the DNS",
                     "You cannot remove the relay from SPF while you send through it — the leverage is "
                     "tenant-side, see HOW TO HARDEN below."),
    "softfail": ("Tighten SPF to a hard fail",
                 "Move <b>~all</b> to <b>-all</b> once every legitimate sender is listed."),
    "ptr-mechanism": ("Replace ptr: with explicit hosts", "RFC 7208 §5.5 advises against <b>ptr:</b>."),
    "dmarc-pct": ("Apply DMARC to all mail", "Set <b>pct=100</b> (or remove it)."),
    "no-rua": ("Turn on DMARC reporting",
               "Add <b>rua=mailto:…</b> — it is how you notice a relay sending as you."),
    "weak-subdomain-policy": ("Stop subdomains being weaker",
                              "Remove <b>sp=</b> so subdomains inherit <b>p</b>, or set <b>sp=reject</b>."),
    "relaxed-alignment": ("Consider strict alignment",
                          "Add <b>adkim=s; aspf=s</b> once the reports show every legitimate sender uses the "
                          "exact From domain."),
}

def _prefix_len(mechanism: str, v6: bool) -> int:
    """Prefix length of an ip4:/ip6: mechanism (bare hosts count as /32, /128)."""
    if "/" in mechanism:
        try:
            return int(mechanism.split("/", 1)[1])
        except ValueError:
            return 128 if v6 else 32
    return 128 if v6 else 32


def analyse(spf: dict, dmarc: dict) -> dict:
    """Relay / echo-spoof exposure for one domain.

    `spf` is the engine's SPF step result ({record, all, lookups, tree}); `dmarc`
    is the parsed DMARC tags ({p, rua, pct, adkim, aspf, ...}).
    """
    record = str((spf or {}).get("record") or "")
    all_term = (spf or {}).get("all")
    findings = []

    def add(key, **fmt):
        sev, title, detail, fix = FINDINGS[key]
        findings.append({"key": key, "sev": sev, "title": title,
                         "detail": detail.format(**fmt), "fix": fix})

    # ---------------------------------------------------------------- SPF policy
    if all_term in ("+all", "?all"):
        add("open-spf")
    elif all_term is None and record:
        add("open-spf")            # no all term: nothing is authorised or denied
    elif all_term == "~all":
        add("softfail")

    ip4s = _RE_IP4.findall(record)
    ip6s = _RE_IP6.findall(record)
    if any(_prefix_len(m, False) <= 8 for m in ip4s) or any(_prefix_len(m, True) <= 32 for m in ip6s):
        add("open-cidr")
    elif any(_prefix_len(m, False) < 24 for m in ip4s) or any(_prefix_len(m, True) < 64 for m in ip6s):
        add("broad-cidr")

    if re.search(r"(^|\s)[+~?-]?ptr:", record, re.I):
        add("ptr-mechanism")

    # ------------------------------------------------------------- SPF includes
    includes, relays, seen = [], [], set()
    for node in ((spf or {}).get("tree") or {}).get("children", []) or []:
        domain = str(node.get("domain") or "")
        if not domain:
            continue
        provider = attribute(domain)
        includes.append({"domain": domain, "all": node.get("all"),
                         "provider": (provider or {}).get("label", ""),
                         "kind": (provider or {}).get("kind", "")})
        if provider and provider["label"] not in seen:
            seen.add(provider["label"])
            relays.append({"domain": domain, "label": provider["label"],
                           "kind": provider["kind"], "kind_label": provider["kind_label"]})
        if node.get("all") in ("+all", "?all"):
            add("open-include", domain=html.escape(domain))

    if relays:
        add("shared-relay", relays=", ".join(html.escape(r["label"]) for r in relays))

    # ---------------------------------------------------------------- DMARC side
    if not (dmarc or {}).get("record"):
        add("no-dmarc")
    else:
        if str(dmarc.get("p") or "none").lower() == "none":
            add("dmarc-none")
        if not dmarc.get("rua"):
            add("no-rua")
        pct = str(dmarc.get("pct") or "100")
        if pct.isdigit() and int(pct) < 100:
            add("dmarc-pct")
        if str(dmarc.get("adkim") or "r").lower() == "r" and str(dmarc.get("aspf") or "r").lower() == "r":
            add("relaxed-alignment")
        rank = {"none": 0, "quarantine": 1, "reject": 2}
        sub_policy = str(dmarc.get("sp") or "").lower()
        if sub_policy and rank.get(sub_policy, 0) < rank.get(str(dmarc.get("p") or "none").lower(), 0):
            add("weak-subdomain-policy", sp=sub_policy, p=str(dmarc.get("p") or "none").lower())

    findings.sort(key=lambda f: f["sev"])
    worst = findings[0]["sev"] if findings else 4
    verdict = {0: "EXPOSED", 1: "ELEVATED", 2: "WATCH"}.get(worst, "HARDENED")

    guidance = []
    for relay in relays:
        steps = PROVIDER_GUIDANCE.get(relay["label"]) or KIND_GUIDANCE.get(relay["kind"], [])
        if steps:
            guidance.append({"label": relay["label"], "kind_label": relay["kind_label"], "steps": steps})

    actions = []
    for finding in findings:
        action = ACTION_FOR_FINDING.get(finding["key"])
        if action and action[0] not in [a["title"] for a in actions]:
            actions.append({"title": action[0], "detail": action[1]})

    return {
        "verdict": verdict,
        "headline": VERDICT_HEADLINES[verdict],
        "includes": includes,
        "relays": relays,
        "findings": findings,
        "guidance": guidance,
        "actions": actions,
        "checked": {"spf_all": all_term or "(none)",
                    "dmarc_policy": (dmarc or {}).get("p") or "(none)"},
    }
