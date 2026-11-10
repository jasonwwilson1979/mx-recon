# MX-RECON — Email Security & DNS Forensics Console (Django)

A server-side rewrite of the original single-file browser console
(`legacy/mx-recon-prototype.html`, kept in the repo for reference). The entire reconnaissance engine now runs in
**Python (Django + dnspython)**: the scan logic never ships to the browser, targets are strictly validated,
and the service is hardened for public deployment behind a reverse proxy — e.g. as a Portainer stack built
straight from this GitHub repo.

## What it does

One scan runs seven modules against a domain's whole email delivery chain:

| # | Module | Checks |
|---|--------|--------|
| 01 | ENUM | A / AAAA / NS / SOA / TXT / CNAME (apex + `www`), RFC 1034 apex-CNAME detection |
| 02 | MX | MX topology, per-host A/AAAA/CNAME resolution, rDNS (PTR), RFC 2181 §10.3 + RFC 5321 §5.1 checks |
| 03 | SPF | recursive include/redirect tree walk, `all` terminator analysis, RFC 7208 10-lookup budget |
| 04 | DKIM | selector probing (or 18 common selectors), key algorithm + strength estimation, revocation detection |
| 05 | DMARC | policy parsing (`p`, `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`), posture assessment |
| 06 | RELAY | **echo-spoofing exposure**: attributes every SPF include to a known relay/ESP/hosting provider, grades the `all` terminator, IP ranges and `ptr:`/permissive includes, and checks the DMARC gaps that let a relay-injected message through |
| 07 | RBL | 8 IP zones × up to 3 MX IPs + 2 domain zones (Spamhaus DBL, SURBL), Spamhaus sub-code decoding; "blocked / not authorised" answers (`127.0.0.1`, `127.255.255.x`) are treated as inconclusive, never as listings |
| 08 | CONTROL | nameserver resolution + provider attribution, SOA-vs-NS consistency, DNSKEY vs registry DS, and WHOIS/RDAP (registrar, created/expiry, status flags, delegated nameservers) |
| 09 | REPORT | 0–100 posture score, severity-ranked remediation directives, full deduplicated record inventory |

## Relay / echo-spoofing exposure — "can someone else send as us?"

The **M-06 RELAY / ECHO-SPOOF EXPOSURE** card answers the question the other records can't: **how much sending
authority has this domain delegated, and does anything stop a relay from using it?**

Echo spoofing (the EchoSpoofing campaign documented by Guardio Labs in 2024) never breaks SPF, DKIM or DMARC —
it *uses* them. An attacker hands a message to a relay the victim domain already authorises (an ESP, a mail
security gateway, a hosting platform); the relay **echoes** it back out from its own trusted infrastructure
with its own SPF authorisation and its own DKIM signature. The recipient sees a perfectly authenticated
message: SPF pass, DKIM pass, DMARC pass — carrying content the domain owner never sent. The precondition is
always the same: sending authority delegated to shared infrastructure that does not prove the injecting party
owns the domain.

MX-RECON can't prove a relay verifies ownership from the outside — but it can show the delegation and grade the
DNS-level gaps that turn delegation into exposure:

| Finding | Severity | What it means |
| --- | --- | --- |
| `open-spf` | CRITICAL | `+all`/`?all`, or no `all` term: everyone may send as you |
| `open-cidr` | CRITICAL | an `ip4:`/`ip6:` range covering most of the internet (e.g. `/8`) |
| `no-dmarc` | CRITICAL | nothing tells receivers to reject relay-injected mail |
| `broad-cidr` | HIGH | a wide range (e.g. `/16`) that hosts you don't run can send from |
| `open-include` | HIGH | an `include:` that resolves to a permissive (`+all`) policy you inherit |
| `dmarc-none` | HIGH | `p=none`: failures are reported, never blocked |
| `shared-relay` | MEDIUM | SPF authorises a known relay/ESP/hosting provider — the echo-spoof precondition |
| `softfail` | MEDIUM | `~all`: many receivers treat SoftFail as neutral, so unauthorised mail still lands |
| `ptr-mechanism` | MEDIUM | `ptr:` widens the sending set to "any host whose reverse DNS matches" (RFC 7208 §5.5) |
| `dmarc-pct` | MEDIUM | `pct<100`: the policy only applies to part of your mail |
| `no-rua` | MEDIUM | no aggregate reports — the only practical way to notice echo spoofing happening |
| `relaxed-alignment` | ENHANCE | default `adkim=r`/`aspf=r` lets a subdomain satisfy alignment |

Verdicts: **EXPOSED** (any CRITICAL) → **ELEVATED** (any HIGH) → **WATCH** (MEDIUM only) → **HARDENED**
(nothing, or advisories only). Every finding except the advisory carries a severity-ranked directive in
M-11, and the card lists the SPF includes it attributed (e.g. *Proofpoint — mail security gateway*, *SendGrid —
bulk sending platform*).

This check is **not** part of the 0–100 posture score (that scale is SPF 25 / DKIM 20 / DMARC 30 / MX 15 /
RBL 10 and stays comparable) — it reports separately, because "your SPF is well-formed" and "you delegate
sending authority to five shared platforms" are both true at once.

**What to do with it:** confirm each platform enforces domain ownership for outbound mail (Microsoft 365
requires a verified domain; Proofpoint added tenant approval after the 2024 campaign; some shared hosts and
trial tenants do not), restrict which tenants may relay, tighten `~all` → `-all`, get DMARC to `p=reject;
pct=100`, add `rua=` reporting and actually read it, and consider `adkim=s; aspf=s`. Real-world example:
`github.com` scans **ELEVATED** (five relays, `~all`, a broad CIDR) while `example.com` scans **WATCH**
(`-all`, `p=reject`, but no `rua=`).

### Worked example — hardening a `WATCH` result (Microsoft 365)

A typical well-configured M365 domain scans **WATCH** with exactly two findings:

```
DELEGATED TO   Microsoft 365 (hosted mail platform, via spf.protection.outlook.com)
MEDIUM         Sending authority is delegated to shared infrastructure
ENHANCE        Relaxed DMARC alignment
SPF ALL › -all · DMARC POLICY › reject · DKIM › selector1/selector2, 2048-bit · rua present
```

**`WATCH` here is the healthy outcome, not a fault.** You cannot have `HARDENED` while sending through a
hosted platform — `HARDENED` requires the sending infrastructure to be yours. The two findings are therefore
handled differently:

1. **MEDIUM `shared-relay` — fix it on the platform, not in DNS.** `include:spf.protection.outlook.com`
   authorises Microsoft's whole shared sending pool, so anyone who can inject outbound mail *through M365* can
   pass SPF for you. M365 requires a verified domain before a tenant can send as it, so the realistic attack
   path is your own tenant (stolen credentials, a rogue connector, or relay/SMTP-AUTH abuse). The card's
   **HOW TO HARDEN** block is the checklist: MFA + Conditional Access, SMTP AUTH off on mailboxes that don't
   need it, review Mail flow → Connectors and "direct send", outbound spam policies + the suspicious-sending
   alert, and DKIM enabled for the custom domain. Removing the include would break your own mail.
2. **ENHANCE `relaxed-alignment` — optional tightening.** DMARC's default relaxed alignment lets a *subdomain*
   satisfy SPF/DKIM alignment. Adding `adkim=s; aspf=s` closes that, but only do it once your `rua` reports show
   every legitimate sender using the exact From domain — an ESP that signs as `mail.yourdomain` or rewrites the
   envelope would then stop aligning.

Then look at what the **other** cards say, because those are the gaps that are actually fixable from DNS:

- **DNSSEC (M-10)** — if the zone isn't signed you get an advisory directive. Without it an on-path attacker
  can forge or strip the very SPF/DMARC/DKIM answers receivers use to judge your mail. Cloudflare, Route 53
  and Azure DNS all enable it with one click (and `.dev`/`.app` are HSTS-preloaded TLDs that suit it).
- **MTA-STS + TLS-RPT (M-09)** — inbound TLS hardening: a policy host plus a reporting address.
- **`sp=` (M-06)** — if you ever set `sp=none` while `p=reject`, subdomains become the weak link; the card now
  flags a weaker subdomain policy.
- **Keep reading the `rua` reports** — that is how you would ever notice relay-injected mail, because it
  authenticates *perfectly*.

## Header diagnostics — "why did this email go to spam?"

Paste the raw headers of a delivered message (or the whole source) into the **DIAGNOSTICS** panel and MX-RECON
explains the delivery failure by cross-checking the message against live DNS:

- **Every Authentication-Results** on the message, with the destination gateway's verdict identified
  (spf / dkim / dmarc / arc per hop)
- **DKIM:** the selector actually used (`s=`) for the signing domain (`d=`) is looked up live —
  *"no public key in DNS"* is called out as the root cause when the key was never published, plus
  key-size, missing-`From`-coverage, signature/key size mismatch and non-standard tags
- **SPF:** the envelope domain's record is re-evaluated against the real sending IP with a bounded RFC 7208
  evaluator (ip4/ip6/a/mx/include/redirect, 10-lookup budget) and compared with the gateway's verdict
- **DMARC:** policy, `rua`, and whether this message would pass alignment (SPF and DKIM domains vs From)
- **Reputation:** PTR / forward-confirmed rDNS, plus the sending IP against the blacklist zones
- **Filter signals:** `X-Spam-Flag`/`X-Spam-Status` score vs threshold and triggered rules, Microsoft SCL,
  and gateway-specific headers (e.g. Barracuda `X-BESS-REASON`, `X-BESS-BRTS-Status`) surfaced verbatim
- **Transport & hygiene:** plaintext hops in the Received chain, Return-Path/Message-ID mismatches,
  missing Date/Message-ID, bulk mail without List-Unsubscribe

Output: a 0–100 deliverability **risk score** with a verdict, a severity-ranked **root-cause list** where
every finding carries its evidence and a concrete fix, a **checks-passed** list, and a full **DNS
cross-check log** disclosing every lookup performed.

Every card and diagnostics panel also carries an **ⓘ info button** with a plain-English explainer: what the
record stands for, the question it answers, a small real example and a practical note — e.g. ⓘ SPF →
*"Sender Policy Framework — who is allowed to send email for this domain?"*, ⓘ DKIM → *"DomainKeys Identified
Mail — was this email altered in transit, and is it genuinely from the sender?"*, ⓘ DMARC → *"Domain-based
Message Authentication — what should I do if an email fails SPF and DKIM?"*.

The results grid is uniform and **one card per row**, hard-coded: rows always line up and card bodies scroll
horizontally instead of clipping. There is deliberately no layout switcher.

While a scan runs, the **scan sweep line** — a cyan line that travels down the screen — marks the state
visually, and the **SCAN LOG** opens each scan with a banner plus its context:

```
──── ENGAGING TARGET: ACME-CORP.COM ────
scan 4F2A9C · resolver System default · engine v3.11.0 · 8 modules armed
```

The sweep is positioned by JavaScript on every frame (`startSweep()` in `mx-recon.js`), deliberately **not** by a
CSS `@keyframes` animation: OS/browser *reduce motion* settings, extensions and CSS resets that force
`animation:none!important` silently killed the animation and left the line parked at the top of the page. A
JS-driven `transform` cannot be suppressed that way (with a `setInterval` fallback if `requestAnimationFrame`
is missing). The sweep is held open for at least one full pass (2.6 s), so a fast server-side scan still shows
it rather than flashing past. The banner is printed once, at the moment you press **RUN SCAN** (the engine's own
copy is skipped during log replay), so there is exactly one header per scan.

**COPY SUMMARY** (in the results header and in the diagnostics panel) puts a short plain-text digest on your
clipboard: score/risk, the ranked findings with their fixes, and the key records — around 2 KB / 30 lines,
sized for pasting into an email, a Teams chat or a ticket. If the browser blocks the clipboard (typical on a
plain-HTTP deployment where the Clipboard API is unavailable), the summary opens in a panel for manual
copying instead of silently failing. **EXPORT JSON** still produces the full machine-readable dossier.

## Resolver selection

The scan console has a **RESOLVER** dropdown so you can compare how a domain looks from different vantage
points — and, importantly, run blacklist checks from your own resolver (Spamhaus and several other zones
refuse queries from public resolvers):

| Option | Nameservers |
|--------|-------------|
| System default | whatever the host/container uses — *best for RBL accuracy* |
| Cloudflare | `1.1.1.1`, `1.0.0.1` |
| Google | `8.8.8.8`, `8.8.4.4` |
| Quad9 | `9.9.9.9`, `149.112.112.112` |
| OpenDNS | `208.67.222.222`, `208.67.220.220` |
| AdGuard | `94.140.14.14`, `94.140.15.15` |

Your choice is remembered in the browser (marked **★ last used**) and applies to the health probe, scans and
diagnoses. **The list is a server-side allow-list**: the browser can never pass arbitrary nameserver
addresses (that would make the scanner an open DNS relay) — unknown ids are rejected with `400`.

Add your own resolver (e.g. an internal one) via environment variables:

```
DJANGO_RESOLVERS_EXTRA="internal|Internal DNS 10.0.0.53|10.0.0.53;vpn|VPN DNS|10.8.0.1,10.8.0.2"
DJANGO_RESOLVER_DEFAULT=internal
```

## Domain control — who owns and serves the domain

The **M-10 DOMAIN CONTROL — WHOIS / NS** card answers "who is actually in charge of these records?":

- **WHOIS via RDAP** (the ICANN-mandated JSON successor to port-43 WHOIS, so it also works from containers
  where TCP/43 is blocked): registrar + IANA ID, created / last-changed / **expiry** dates, registry status
  flags, and the nameservers the registry has delegated. The registry is found through the IANA bootstrap
  file, with `rdap.org` as a fallback; a lookup failure never fails the scan.
- **Nameserver analysis:** every NS is resolved to its IPs and attributed to a provider (Cloudflare, Route 53,
  GoDaddy, Azure, Google, …), so you can see where the zone really lives.
- **Delegation cross-check:** registry nameservers vs live NS records — a mismatch means delegation changed and
  has not propagated, or the domain is managed by another provider.
- **Zone authority & DNSSEC:** the SOA primary is checked against the NS list, and the registry's DS is compared
  with the zone's DNSKEY — catching "DS but no DNSKEY" (validation fails → mail servers can't resolve you) and
  "DNSKEY but no DS" (island of security).
- Findings feed the remediation list, e.g. *"registration expires in 24 days — renew now"* (CRITICAL),
  *"registry status contains pending delete"*, or a broken-DNSSEC warning.

Set `DJANGO_WHOIS=false` to skip the outbound lookup entirely (privacy-restricted environments).

Add your own RBLs (internal blocklists, paid feeds, regional lists) without touching the code — set them in the
Portainer stack environment:

```
DJANGO_RBL_EXTRA_IP="zen.internal.example|Internal IP RBL|https://intranet/rbl"
DJANGO_RBL_EXTRA_DOMAIN="dbl.internal.example|Internal Domain RBL"
DJANGO_RBL_DISABLED="dnsbl.sorbs.net,dnsbl-1.uceprotect.net"
```

- **IP zones** are queried as `<reversed-ip>.<zone>` (e.g. `21.124.27.52.zen.internal.example`) against every
  MX IP; **domain zones** as `<domain>.<zone>`.
- Format is `zone|Label|url` — the label and url are optional (`zone` alone works), and multiple zones are
  separated with `;`. Anything that is not a valid hostname (IPs, single labels, typos) is ignored.
- Custom zones appear in the **M-08 IP BLACKLIST MATRIX** and **M-07 REPUTATION** cards marked with a
  `CUSTOM` chip, count towards the posture score exactly like built-ins, and show up in the diagnostics and
  the scan log (`… × 9 zones (1 custom) …`).
- Duplicates of an existing zone are skipped, and `DJANGO_RBL_DISABLED` applies to custom zones too.
- Return-code note: `127.0.0.1` and `127.255.255.x` are treated as **blocked / inconclusive** (that is what
  URIBL and Spamhaus use for unregistered resolvers), so if your private list uses `127.0.0.1` as its
  "listed" code, use a different code (e.g. `127.0.0.2`) — otherwise it will show as BLOCKED rather than LISTED.

### Spamhaus answers `BLOCKED` — why, and how to fix it

`zen.spamhaus.org` and `dbl.spamhaus.org` refuse queries that arrive from public/open resolvers (Google
8.8.8.8, Cloudflare 1.1.1.1, most cloud and VPS resolvers) and from IP ranges Spamhaus has blocked. Instead of
an answer they return an **error code in `127.255.255.0/24`** — MX-RECON shows that as `BLOCKED` (or
`RESOLVER BLOCKED` in M-07), which is *inconclusive*, **never** a listing, and never costs you score points.
Spamhaus's own FAQ: *"We recommend using your own DNS servers when doing DNSBL queries to Spamhaus."*

Three ways out, cheapest first:

1. **Query from your own IP (free).** Leave the resolver on **System default** so the lookup leaves from the
   container's own address. Watch out for the upstream: Docker's embedded DNS (`127.0.0.11`) forwards to the
   host's `/etc/resolv.conf`, so if the host uses `1.1.1.1` Spamhaus still sees a public resolver. Point the
   stack at your own **recursive** resolver instead (Unbound, BIND, or Pi-hole in recursive mode — a forwarder
   that relays to 8.8.8.8 does not help):
   ```
   DJANGO_RESOLVERS_EXTRA="local|Local Unbound|10.0.0.53"
   ```
2. **Use Spamhaus DQS (Data Query Service).** The supported path for cloud/registered setups: the DQS zones
   answer queries authenticated either by your registered source IP or by your **query key** placed in the zone
   name, so keyed queries work from any IP. Register in the Spamhaus portal (a free tier exists for
   non-commercial use), then swap the public zones for the DQS ones:
   ```
   DJANGO_RBL_EXTRA_IP="YOUR-DQS-KEY.zen.dq.spamhaus.net|Spamhaus ZEN (DQS)|https://check.spamhaus.org/"
   DJANGO_RBL_EXTRA_DOMAIN="YOUR-DQS-KEY.dbl.dq.spamhaus.net|Spamhaus DBL (DQS)|https://check.spamhaus.org/"
   DJANGO_RBL_DISABLED="zen.spamhaus.org,dbl.spamhaus.org"
   ```
   DQS answers use the same `127.0.0.x` listing codes as the public zones, so they render (and score) exactly
   the same — and because the zones are *added*, not replaced, the public ones stay off via
   `DJANGO_RBL_DISABLED` so you never double-count a zone. Without a key, drop the `YOUR-DQS-KEY.` label and
   register the container's egress IP instead.
3. **Ignore it.** `BLOCKED` is honest about being unverified; verify the IP or domain by hand at
   <https://check.spamhaus.org/>.

**The trap worth knowing:** through some resolvers the query does not fail — it *succeeds* and answers
NXDOMAIN, which MX-RECON (correctly) reads as `CLEAN`. And a resolver can be *partially* refused: over Spamhaus's
free query quota, some lookups answer and others return error codes.

Rather than guess, use the built-in **T-01 RBL RESOLVER SELF-TEST** (Diagnostics section, also
`GET /api/rbl-check?resolver=all`). It runs Spamhaus's own documented test entries and reports one of five
verdicts per resolver:

| Verdict | Meaning |
| --- | --- |
| `OK` | every test entry answered as documented — `CLEAN` rows are trustworthy |
| `PARTIAL` | some answered, some refused/NXDOMAIN — over quota or rate-limited; treat rows as unverified |
| `REFUSED` | Spamhaus answered error codes (`127.255.255.x`) for everything |
| `FALSE CLEAN` | the test entry answered NXDOMAIN — nothing is being checked, everything looks clean |
| `NO ANSWER` | nothing came back at all (resolver unreachable, DNS egress blocked) |

Measured on a typical home/dev network (2026-10-22):

| Resolver | Verdict | Detail |
| --- | --- | --- |
| OpenDNS 208.67.222.222 | **OK** | `test.dbl.spamhaus.org → 127.0.1.2`, ZEN `→ 127.0.0.2` |
| System default (via router/ISP) | PARTIAL | `dbltest.com → 127.0.1.2`, but other entries returned error codes |
| Google 8.8.8.8 | FALSE CLEAN | NXDOMAIN for entries that must be listed |
| Cloudflare / Quad9 / AdGuard | REFUSED | `127.255.255.254` on every probe |

So a green Spamhaus row is only proof when the self-test says `OK` for the resolver in use. MX-RECON also flags
scans run through a known public resolver (`resolver_public` in the report JSON): the **M-07** and **M-08**
cards warn, the scan log says the rows are unverified, and `COPY SUMMARY` appends *"(public DNS — blacklist
rows unverified)"* to the resolver line. The scan log also spells out which zones refused and the fixes, and
the diagnostics panel names the inconclusive zones next to the "no listings" verdict.

### Inside a container: what your resolver actually is

`System default` inside the container is **Docker's embedded DNS (`127.0.0.11`)**, which forwards to whatever
the *host* is configured with — often the router, which forwards to the ISP. Any of those hops can be
refused by Spamhaus. To see and fix it:

1. Portainer → **Containers → mx-recon → Console** → `cat /etc/resolv.conf` (look for `127.0.0.11`, then check the
   host's own `/etc/resolv.conf`).
2. Pin the container to a resolver you control — the compose file accepts a commented `dns:` block:
   ```yaml
   dns:
     - 192.168.1.1      # your router, Pi-hole or Unbound
   ```
3. Re-run **T-01** in the UI. If nothing is `OK`, go to Spamhaus DQS (option 2 above) — that is the only path
   that works from a cloud/hosting IP.

There is deliberately **no UI editor** for these: MX-RECON is unauthenticated, so anything writable from the
browser would let any visitor point the scanner at arbitrary DNS zones. Configure them server-side instead.

## Why server-side Python?

- **Code protection** — the engine (scoring model, selector list, zone lists, heuristics) is no longer
  visible in the page source; the browser only receives rendered results.
- **Security** — CSRF-protected JSON API, per-IP rate limiting, strict domain validation (no IP literals or
  RFC 6761 special-use names), DNS timeouts, per-scan query budget + wall-clock deadline, security headers
  (CSP, HSTS, nosniff, frame-deny, referrer policy), non-root container.
- **Speed & reliability** — thread-parallel DNS with a shared LRU cache, correct IPv6 reverse pointers via
  `ipaddress`, TCP fallback handled by dnspython.

## Repository layout

```
manage.py                  Django entrypoint
mx_recon/                     project config (settings, urls, wsgi, asgi, CSP middleware)
scanner/
  engine.py                the forensic engine (all 7 modules, logging, scoring, inventory)
  headers.py               raw email-header parsing (Received chain, auth results, DKIM/ARC, gateway headers)
  diagnostics.py           "why did it go to spam?" — SPF evaluator, DNS cross-checks, risk scoring, root causes
  validators.py            strict target/selector validation (anti-SSRF, anti-abuse)
  ratelimit.py             per-IP fixed-window limiter (shared file-backed cache)
  views.py                 /, /api/scan, /api/diagnose, /api/probe, /healthz
  urls.py, apps.py, tests.py, tests_js.py
  templates/scanner/index.html   the MX-RECON console UI + left sidebar nav + diagnostics panel
  static/scanner/mx-recon.js        API client + renderers + log replay + scroll-spy
Dockerfile, docker-compose.yml   container + Portainer stack definition
.github/workflows/ci.yml         tests + GHCR image publish on main
legacy/mx-recon-prototype.html    original client-side prototype (reference only — not served)
```

## Local development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# dev server (DEBUG on so static files are served directly)
$env:DJANGO_DEBUG="true"
python manage.py runserver 127.0.0.1:8000
# → http://127.0.0.1:8000
```

No database, no migrations — the service is stateless.

## Tests

```powershell
python manage.py check
python manage.py test
```

The suite covers validators (IP-literal/special-use rejection), RBL classification, DKIM bit estimation,
DMARC parsing, the full engine (stubbed DNS backend — no network needed), the JSON API, rate limiting,
header parsing against a real gateway-stamped message, the RFC 7208 SPF evaluator, the diagnostics engine,
and the UI template.

Optional extra: `pip install quickjs` enables `scanner/tests_js.py`, which runs the browser bundle
(`mx-recon.js`) inside a real JS engine against a stubbed DOM and asserts the diagnostics panels render
correctly — a browser-free front-end smoke test (skipped automatically when quickjs is absent).

## Docker

```powershell
docker build -t mx-recon:local .

# Container listens on 8000 internally; pick any published host port (583 here)
docker run --rm -p 583:8000 -e DJANGO_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(64))')" mx-recon:local
# → http://localhost:583   (health: http://localhost:583/healthz)

# Or publish a different host port, e.g. 590
docker run --rm -p 590:8000 -e DJANGO_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(64))')" mx-recon:local
# → http://localhost:590
```

## Push to GitHub

```powershell
git init -b main
git add -A
git commit -m "MX-RECON: Django rewrite — server-side Python scan engine, hardening, container deployment"
git remote add origin https://github.com/jasonwwilson1979/mx-recon.git   # create the repo on GitHub first
git push -u origin main
```

The included CI workflow runs `manage.py check` + the test suite on every push, and on `main` also builds
and publishes the image to GitHub Container Registry as `ghcr.io/jasonwwilson1979/mx-recon:latest`
(if your repo has a different owner/name, adjust `image:` in `docker-compose.yml`).

## Deploy to Portainer (stack built from this GitHub repo)

1. Push the repo to GitHub (above). If the repo is **private**, add your GitHub credentials under
   *Portainer → Settings → Credentials* (or use a Personal Access Token).
2. In Portainer: **Stacks → + Add stack**.
3. Name it `mx-recon`.
4. Under **Build method**, choose **Repository**.
5. Fill in:
   - **Repository URL**: `https://github.com/jasonwwilson1979/mx-recon`
   - **Repository reference**: `refs/heads/main`
   - **Compose path**: `docker-compose.yml`
   - Enable **GitOps updates** (optional): poll/Webhook so pushes auto-redeploy.
6. Under **Environment variables**, add:
   - `DJANGO_SECRET_KEY` — **required**; generate with
     `python -c "import secrets;print(secrets.token_urlsafe(64))"`
   - `DJANGO_ALLOWED_HOSTS` — e.g. `mx-recon.example.com` (add your LAN IP too if you hit it directly)
   - `DJANGO_CSRF_TRUSTED_ORIGINS` — e.g. `https://mx-recon.example.com`
   - `DJANGO_TRUST_PROXY` — `true` when behind Nginx Proxy Manager / Traefik / Caddy
   - Optional: `DJANGO_SSL_REDIRECT=true`, `DJANGO_HSTS_SECONDS=31536000` once HTTPS works end-to-end
   - Optional: `MX_RECON_PORT` — the published host port (default `583`); set e.g. `590` when 583 is already taken
   - Optional, blacklist tuning: `DJANGO_RBL_EXTRA_IP` / `DJANGO_RBL_EXTRA_DOMAIN` (your own zones, or
     Spamhaus DQS `*.dq.spamhaus.net`), `DJANGO_RBL_DISABLED`, `DJANGO_RESOLVERS_EXTRA`
7. Click **Deploy the stack**. Portainer builds the image from the repo and starts the container with a
   healthcheck on `/healthz`.

> **Prefer a prebuilt image?** Delete the `build:` block from `docker-compose.yml` and the stack will pull
> `ghcr.io/...:latest` produced by CI (make the GHCR package public, or add a registry credential in
> Portainer).

> **Behind a reverse proxy**, forward to `http://<host>:583` (or your `MX_RECON_PORT`) and set `DJANGO_TRUST_PROXY=true` so client
> IPs (rate limiting) come from `X-Forwarded-For` and HTTPS is detected via `X-Forwarded-Proto`.

### Cloudflare + the published port

The stack publishes **`${MX_RECON_PORT:-583}` on the host → container port 8000** — set `MX_RECON_PORT` in the
stack environment (or `.env`) to change the port you browse to, e.g. `MX_RECON_PORT=590`. The container
itself always listens on 8000. How the published port behaves with Cloudflare:

- **Cloudflare Tunnel (recommended, works with any port)** — `cloudflared` connects *outbound* to your origin, so
  any origin port is allowed. Point the tunnel's public hostname at `http://<host>:583` (or your `MX_RECON_PORT`), or at
  `http://mx-recon:8000` when cloudflared runs inside this stack
  (see the commented service in `docker-compose.yml`). The public URL is served on 443 with Cloudflare TLS.
  Then set: `DJANGO_TRUST_PROXY=true`, `DJANGO_ALLOWED_HOSTS=mx-recon.example.com`,
  `DJANGO_CSRF_TRUSTED_ORIGINS=https://mx-recon.example.com`.
- **DNS-only (grey cloud) + port-forward** — a record pointing at your public IP with router forwarding
  `<port> → <docker-host>:<MX_RECON_PORT>`. Works on any port, but exposes your origin IP and skips Cloudflare's proxy.
- **Proxied (orange cloud) — port 583 is NOT supported.** Cloudflare's proxy only accepts
  HTTP `80, 8080, 8880, 2052, 2082, 2086, 2095` and HTTPS `443, 8443, 2053, 2083, 2087, 2096`
  ([Cloudflare network ports](https://developers.cloudflare.com/fundamentals/reference/network-ports/)).
  For orange-cloud either publish a supported host port instead (set `MX_RECON_PORT` to one of those, e.g. `8443`) or put a
  reverse proxy (Nginx Proxy Manager/Traefik) on 443 in front of `mx-recon:8000`.

## API reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | MX-RECON console UI |
| `/api/scan` | POST | Run a scan. Body `{"domain": "example.com", "selector": "google"}` (selector optional). Returns `{"report": {...}, "logs": [...]}`. CSRF-protected; `429` with `Retry-After` when rate-limited; `400` on invalid target. |
| `/api/diagnose` | POST | Diagnose a delivered message. Body `{"headers": "<raw headers>", "domain": "optional override"}`. Returns `{"report": {...}, "logs": [...]}` with risk score, root causes, auth results, DKIM/SPF/DMARC cross-checks and the DNS query log. 128 KB body cap; `400`/`429` as above. |
| `/api/probe` | GET | Resolver health probe used by the UI boot sequence. Optional `?resolver=<id>`. |
| `/api/rbl-check` | GET | Resolver self-test: runs Spamhaus's documented test entries (`test.dbl.spamhaus.org` must answer `127.0.1.2`) and returns a per-resolver verdict (`ok`/`partial`/`refused`/`false_clean`/`no_answer`) plus the fix. `?resolver=<id>` or `?resolver=all` (capped, rate-limited, `no-store`). |
| `/api/resolvers` | GET | Resolver allow-list for the UI dropdown (ids, labels, nameservers, notes, default). |
| `/healthz` | GET | Container healthcheck. |

## Environment variables

Every variable below is wired through `docker-compose.yml`, so setting it in the Portainer stack's
**Environment variables** is enough — no image rebuild, just *Update the stack* (values are read when the
container starts). `.env.example` lists the same set for local use.

| Variable | Default | Notes |
|----------|---------|-------|
| `DJANGO_SECRET_KEY` | ephemeral random | **Set in production** — otherwise sessions/CSRF break on restart |
| `DJANGO_DEBUG` | `false` | Never enable in production |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Comma-separated hostnames |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | *(empty)* | Comma-separated origins incl. scheme |
| `DJANGO_TRUST_PROXY` | `false` | Honour `X-Forwarded-For`/`Proto` |
| `DJANGO_SSL_REDIRECT` | `false` | Redirect HTTP → HTTPS |
| `DJANGO_HSTS_SECONDS` | `0` | e.g. `31536000` once HTTPS is proven |
| `DJANGO_RATE_LIMIT` / `DJANGO_RATE_WINDOW` | `30` / `300` | Scans per IP per window (seconds) |
| `DJANGO_MAX_QUERIES` / `DJANGO_DEADLINE` | `350` / `30` | Per-scan DNS query cap / wall-clock seconds |
| `DJANGO_DNS_TIMEOUT` / `DJANGO_DNS_LIFETIME` | `3` / `6` | Per-nameserver timeout / total query lifetime |
| `DJANGO_CACHE_DIR` | `./var/cache` | Rate-limit counter cache (shared by all Gunicorn workers) |
| `MX_RECON_PORT` | `583` | Published **host** port — the port you browse to (always maps to container 8000). Consumed by compose; never passed into the container. |
| `DJANGO_RESOLVER_DEFAULT` | `system` | Resolver pre-selected in the UI dropdown. Keep `system` for trustworthy blacklist results — public resolvers are flagged in the UI because Spamhaus refuses them (BLOCKED) or answers a blanket NXDOMAIN that looks clean. |
| `DJANGO_RESOLVERS_EXTRA` | *(empty)* | Add custom resolvers: `"id\|Label\|ip[,ip][;id2\|Label2\|ip]"`. |
| `DJANGO_DNS_FALLBACK` | `1.1.1.1,8.8.8.8` | Public resolvers used **only** to retry reverse (PTR) lookups when the system resolver returns nothing (Docker/cloud resolvers often don't answer `in-addr.arpa`). Set empty to disable. |
| `DJANGO_RBL_DISABLED` | *(empty)* | Comma-separated RBL zone names to skip, e.g. `dnsbl.sorbs.net,dnsbl-1.uceprotect.net` — handy when a list misbehaves on your resolver, and how you turn off the public Spamhaus zones once you move to DQS. `multi.uribl.com` is no longer queried at all (it answers "blocked" to unregistered resolvers). |
| `DJANGO_RBL_EXTRA_IP` | *(empty)* | Add your own **IP-based** blacklist zones: `zone\|Label\|url` (label and url optional, `;`-separate several). Queried as `<reversed-ip>.<zone>`. Also how you add Spamhaus DQS IP zones, e.g. `YOUR-DQS-KEY.zen.dq.spamhaus.net`. |
| `DJANGO_RBL_EXTRA_DOMAIN` | *(empty)* | Add your own **domain-based** blacklist zones: `zone\|Label\|url`. Queried as `<domain>.<zone>`. Also how you add Spamhaus DQS domain zones, e.g. `YOUR-DQS-KEY.dbl.dq.spamhaus.net`. |
| `DJANGO_WHOIS` | `true` | Domain-control module: RDAP (modern WHOIS over HTTPS) lookup. Set `false` to skip the outbound HTTPS request. |
| `DJANGO_WHOIS_TIMEOUT` | `6` | RDAP request timeout in seconds. |

## Security summary

- All scan logic server-side; browser receives rendered JSON only
- CSRF-protected API + same-site strict cookies; `CSRF_COOKIE_HTTPONLY`
- Per-IP rate limiting (fixed window, shared cache), `Retry-After` on `429`
- Target validation: hostnames only — IP literals, `localhost`, `*.local/.internal/.arpa/...` rejected
- DNS timeouts + per-scan query budget + wall-clock deadline (DoS containment)
- CSP (`script-src 'self'`), HSTS (opt-in), `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  Referrer-Policy, Permissions-Policy
- Non-root container user, `no-new-privileges`, healthcheck, no database to attack
- Untrusted values HTML-escaped before reaching the log/rec renderers

> MX-RECON is reconnaissance tooling for domains you own or are authorised to test. Only scan what you're
> permitted to scan.

