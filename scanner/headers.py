"""
Raw email-header parsing for the MX-RECON diagnostics engine.

Pure parsing only — no DNS, no network. Turns a pasted header blob (or a full
message source) into a structured picture: the Received chain, every
Authentication-Results verdict, DKIM/ARC signatures, Received-SPF, and the
gateway / spam-scoring headers added by filtering systems.
"""
from __future__ import annotations

import re

# ------------------------------------------------------------------ unfolding

_RE_FIELD = re.compile(r"^([!-9;-~]+):[ \t]?(.*)$")


def unfold(raw: str):
    """Return ordered (name, value) header pairs, unfolding continuations.

    Stops at the first empty line (start of the body) so a whole message
    source can be pasted safely.
    """
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    pairs = []
    state = {"name": None, "buf": []}

    def flush():
        if state["name"] is not None:
            pairs.append((state["name"], "\n".join(state["buf"]).strip()))
        state["name"], state["buf"] = None, []

    for line in text.split("\n"):
        if not line.strip():
            if state["name"] is not None:
                flush()
                break
            continue
        if line[0] in " \t" and state["name"] is not None:
            state["buf"].append(line.strip())
            continue
        m = _RE_FIELD.match(line)
        if not m:
            continue
        flush()
        state["name"], state["buf"] = m.group(1), [m.group(2)]
    flush()
    return pairs


class ParsedHeaders:
    """Case-insensitive, duplicate-preserving view over parsed header pairs."""

    def __init__(self, pairs):
        self.pairs = list(pairs)
        self._by_name = {}
        for name, value in self.pairs:
            self._by_name.setdefault(name.lower(), []).append(value)

    def all(self, name):
        return list(self._by_name.get(name.lower(), []))

    def get(self, name, default=None):
        vals = self._by_name.get(name.lower())
        return vals[0] if vals else default

    def has(self, name):
        return name.lower() in self._by_name

    def names(self):
        return [name for name, _ in self.pairs]


# ------------------------------------------------------------------ Received

_RE_FROM_HOST = re.compile(r"\bfrom\s+([^\s;(]+)", re.I)
_RE_BY_HOST = re.compile(r"\bby\s+([^\s;(]+)", re.I)
_RE_WITH = re.compile(r"\bwith\s+([A-Za-z0-9-]+)", re.I)
_RE_FOR = re.compile(r"\bfor\s+<?([^\s;>]+)>?", re.I)
_RE_IP_LIT = re.compile(r"\[([0-9a-fA-F:.]+)\]")
_RE_TRAIL_DATE = re.compile(r";\s*([^;]+)$")
_RE_TLS_VER = re.compile(r"(TLSv[\d.]+)", re.I)
_RE_CIPHER = re.compile(r"cipher[= ]([A-Za-z0-9_-]+)", re.I)
_RE_BITS = re.compile(r"bits[= ](\d+)", re.I)
_RE_VERIFY = re.compile(r"verify=(\w+)", re.I)
_RE_PROTO = re.compile(r"\b(ESMTPSA|ESMTPS|ESMTP|SMTPS|SMTP)\b")
_RE_ESMTP_ID = re.compile(r"\bid\s+([A-Za-z0-9]+)", re.I)


def parse_received(value: str) -> dict:
    """Parse one Received: header into hop details."""
    flat = value.replace("\n", " ")
    ip = None
    m = _RE_IP_LIT.search(flat)
    if m:
        ip = m.group(1)
    proto_m = _RE_PROTO.search(flat)
    proto = proto_m.group(1).upper() if proto_m else None
    tls_m = _RE_TLS_VER.search(flat)
    cipher_m = _RE_CIPHER.search(flat)
    bits_m = _RE_BITS.search(flat)
    verify_m = _RE_VERIFY.search(flat)
    date_m = _RE_TRAIL_DATE.search(flat)
    id_m = _RE_ESMTP_ID.search(flat)
    return {
        "from": (_RE_FROM_HOST.search(flat).group(1) if _RE_FROM_HOST.search(flat) else None),
        "ip": ip,
        "by": (_RE_BY_HOST.search(flat).group(1) if _RE_BY_HOST.search(flat) else None),
        "with": proto,
        "tls": tls_m.group(1) if tls_m else None,
        "cipher": cipher_m.group(1) if cipher_m else None,
        "bits": int(bits_m.group(1)) if bits_m else None,
        "verify": verify_m.group(1) if verify_m else None,
        "queue_id": id_m.group(1) if id_m else None,
        "for": (_RE_FOR.search(flat).group(1) if _RE_FOR.search(flat) else None),
        "date": date_m.group(1).strip() if date_m else None,
        "encrypted": bool(tls_m) or (proto is not None and proto.endswith("S")),
        "raw": flat.strip(),
    }


# ------------------------------------------------- Authentication-Results

_RE_AUTH_CLAUSE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*=\s*([a-z][a-z0-9]*)\s*(.*)$", re.I)
_RE_AUTH_PROP = re.compile(r"([a-z][a-z0-9]*(?:\.[a-z][a-z0-9-]*)*)\s*=\s*([^\s;()\[]+)", re.I)


def parse_auth_results(value: str) -> dict:
    """Parse one Authentication-Results / ARC-Authentication-Results header."""
    flat = value.replace("\n", " ")
    clauses = [c.strip() for c in flat.split(";")]
    authserv = clauses[0].strip() if clauses else ""
    methods = {}
    for clause in clauses[1:]:
        if not clause:
            continue
        m = _RE_AUTH_CLAUSE.match(clause)
        if not m:
            continue  # e.g. ARC instance "i=1"
        method, result, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
        props = {}
        for pm in _RE_AUTH_PROP.finditer(rest):
            props.setdefault(pm.group(1).lower(), pm.group(2).rstrip(";,"))
        reason = ""
        rm = re.search(r"\(([^)]*)\)", rest)
        if rm:
            reason = rm.group(1).strip()
        bm = re.search(r"\[([^\]]*)\]", rest)
        if bm:
            extra = bm.group(1).strip()
            if extra and extra not in reason:
                reason = f"{reason} [{extra}]" if reason else extra
        methods[method] = {"result": result, "reason": reason, "props": props, "raw": clause}
    return {"authserv": authserv, "methods": methods, "raw": flat.strip()}


# ------------------------------------------------------- DKIM / ARC signatures

_RE_TAG_SPLIT = re.compile(r";\s*")
_RE_TAG = re.compile(r"^([a-z][a-z0-9_-]*)\s*=\s*(.*)$", re.I)

DKIM_TAGS = {"v", "a", "c", "d", "s", "t", "x", "i", "l", "q", "h", "z", "bh", "b"}
ARC_SEAL_TAGS = {"i", "a", "t", "cv", "d", "s", "b"}
ARC_MSGSIG_TAGS = {"i", "a", "c", "d", "s", "t", "x", "h", "bh", "b", "f"}


def parse_tag_value(value: str):
    """Split a DKIM/ARC style `tag=value; tag=value` header into (dict, order)."""
    tags, order = {}, []
    for part in _RE_TAG_SPLIT.split(value.replace("\n", " ")):
        m = _RE_TAG.match(part.strip())
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip()
        if key not in tags:
            tags[key] = val
            order.append(key)
    return tags, order


def b64_bits(value: str):
    """Estimate the signing key size (bits) from a base64 signature length."""
    b = re.sub(r"\s+", "", value or "")
    if not b:
        return None
    bits = ((len(b) * 3) // 4) * 8
    for size in (512, 1024, 2048, 3072, 4096):
        if abs(bits - size) <= 64:
            return size
    return bits


def parse_signature(value: str, source: str) -> dict:
    """Parse a DKIM-Signature / ARC-Seal / ARC-Message-Signature header."""
    tags, order = parse_tag_value(value)
    allowed = DKIM_TAGS
    if source == "ARC-Seal":
        allowed = ARC_SEAL_TAGS
    elif source == "ARC-Message-Signature":
        allowed = ARC_MSGSIG_TAGS
    signed = [h.strip().lower() for h in (tags.get("h") or "").split(":") if h.strip()]
    return {
        "source": source,
        "domain": tags.get("d"),
        "selector": tags.get("s"),
        "algo": (tags.get("a") or "rsa-sha256").lower(),
        "canon": (tags.get("c") or "").lower() or None,
        "timestamp": tags.get("t"),
        "expires": tags.get("x"),
        "instance": tags.get("i"),
        "chain_validation": tags.get("cv"),
        "body_hash": tags.get("bh"),
        "signed_headers": signed,
        "covers_from": "from" in signed,
        "signature_bits": b64_bits(tags.get("b")),
        "empty_signature": not (tags.get("b") or "").strip(),
        "unknown_tags": [t for t in order if t not in allowed],
        "tags": tags,
        "raw": value.replace("\n", " ").strip(),
    }


# ------------------------------------------------------------- Received-SPF


def parse_received_spf(value: str) -> dict:
    flat = value.replace("\n", " ").strip()
    m = re.match(r"^([a-z]+)\s*(?:\((.*)\))?", flat, re.I)
    result = m.group(1).lower() if m else None
    detail = (m.group(2) or "").strip() if m else ""
    ip = re.search(r"designates\s+([0-9a-fA-F:.]+)", detail)
    dom = re.search(r"domain of\s+([^\s]+)", detail)
    return {
        "result": result,
        "detail": detail,
        "ip": ip.group(1) if ip else None,
        "domain": dom.group(1) if dom else None,
        "raw": flat,
    }


# ------------------------------------------------- gateway / scoring headers

GATEWAY_PREFIXES = (
    "x-bess-", "x-barracuda-", "x-spam", "x-spamexperts", "x-proofpoint-",
    "x-forefront-", "x-microsoft-antispam", "x-ms-exchange-", "x-google-",
    "x-gm-", "x-cloudmark-", "x-mimecast", "x-ironport-", "x-sophos-",
    "x-sonicwall-", "x-originatororg",
)

GATEWAY_EXACT = {
    "authentication-results", "arc-authentication-results", "received-spf",
    "x-mailer", "x-php-originating-script", "x-priority", "precedence",
    "list-unsubscribe", "list-id", "return-path", "reply-to", "message-id",
    "dkim-signature", "arc-seal", "arc-message-signature",
    "x-google-dkim-signature", "x-authenticated-sender",
}


def parse_spam_status(value: str) -> dict:
    """Parse SpamAssassin's X-Spam-Status / X-Spam-Flag style values."""
    flat = value.replace("\n", " ")
    score = re.search(r"score=(-?[\d.]+)", flat)
    required = re.search(r"required=(-?[\d.]+)", flat)
    tests = re.search(r"tests=([^\s]+)", flat)
    flag = re.match(r"\s*(Yes|No)", flat, re.I)
    return {
        "flag": flag.group(1).lower() if flag else None,
        "score": float(score.group(1)) if score else None,
        "required": float(required.group(1)) if required else None,
        "tests": tests.group(1).split(",") if tests else [],
    }


def parse_scl(*values):
    """Extract Microsoft's spam confidence level (SCL) from report headers."""
    for value in values:
        if not value:
            continue
        m = re.search(r"\bSCL:(\d+)", value)
        if m:
            return int(m.group(1))
    return None


def gateway_note(name: str, value: str) -> str:
    """Conservative, best-effort interpretation of gateway-added headers.

    Vendor-specific codes (e.g. Barracuda X-BESS-*) are surfaced verbatim; the
    note only states what the header demonstrably carries.
    """
    flat = value.replace("\n", " ").strip()
    low = name.lower()
    if low == "x-spam-flag":
        return ("receiving filter marked this message as spam"
                if flat.lower().startswith("yes") else "receiving filter did not mark this as spam")
    if low == "x-spam-status":
        st = parse_spam_status(flat)
        if st["score"] is not None and st["required"] is not None:
            over = "OVER" if st["score"] >= st["required"] else "under"
            return f"spam score {st['score']} vs threshold {st['required']} ({over} threshold)"
        return "spam filter score/status"
    if low == "x-spam-level":
        return f"spam level bar ({len(flat.strip())} asterisks)"
    if low == "x-bess-reason":
        return f"gateway reason code: {flat} (vendor-specific; names the mechanism/rule flagged)"
    if low == "x-bess-brts-status":
        return "BRTS = Barracuda Real-Time System reputation lookup status"
    if low == "x-bess-apparent-source-ip":
        return "source IP the gateway attributes the message to"
    if low.startswith("x-forefront-antispam-report") or low == "x-microsoft-antispam":
        scl = parse_scl(flat)
        return f"Microsoft anti-spam report (SCL={scl})" if scl is not None else "Microsoft anti-spam report"
    if low.endswith("scl"):
        return f"Microsoft spam confidence level: {flat.strip()}"
    if low == "x-php-originating-script":
        return "message generated by a PHP script on the sending server — a common spam signal"
    if low == "precedence":
        return "bulk-mail precedence hint"
    if low == "list-unsubscribe":
        return "unsubscribe mechanism present (bulk/marketing mail)"
    if low == "return-path":
        return "envelope sender (bounce address)"
    if low == "message-id":
        return "message identifier; its domain often differs from From for ESP-sent mail"
    return ""


def extract_gateway_headers(ph: ParsedHeaders):
    """Pull out every filtering/reputation/scoring header added in transit."""
    out = []
    for name, value in ph.pairs:
        low = name.lower()
        if low in GATEWAY_EXACT or any(low.startswith(p) for p in GATEWAY_PREFIXES):
            out.append({
                "name": name,
                "value": value.replace("\n", " ").strip(),
                "note": gateway_note(name, value),
            })
    return out


# --------------------------------------------------------------- addresses


def split_address(value: str):
    """Return (display_name, email, domain) from a raw address header."""
    raw = (value or "").replace("\n", " ").strip()
    if not raw:
        return None, None, None
    m = re.search(r"<([^>]+)>", raw)
    if m:
        email = m.group(1).strip()
        display = raw[: m.start()].strip().strip('"').strip() or None
    else:
        email = raw.split()[0].strip()
        display = None
    domain = email.rsplit("@", 1)[-1].lower().strip(".") if "@" in email else None
    return display, (email.lower() or None), domain


def message_id_domain(value: str):
    m = re.search(r"@([^>\s]+)", value or "")
    return m.group(1).lower().rstrip(".") if m else None


# --------------------------------------------------------------- top level


def parse_message_headers(raw: str) -> dict:
    """Parse a pasted header blob into the full diagnostics input structure."""
    ph = ParsedHeaders(unfold(raw))

    received = [parse_received(v) for v in ph.all("Received")]
    auth_results = [parse_auth_results(v) for v in ph.all("Authentication-Results")]
    arc_auth = [parse_auth_results(v) for v in ph.all("ARC-Authentication-Results")]
    signatures = [parse_signature(v, "DKIM-Signature") for v in ph.all("DKIM-Signature")]
    signatures += [parse_signature(v, "X-Google-DKIM-Signature") for v in ph.all("X-Google-DKIM-Signature")]
    arc_seals = [parse_signature(v, "ARC-Seal") for v in ph.all("ARC-Seal")]
    arc_msg = [parse_signature(v, "ARC-Message-Signature") for v in ph.all("ARC-Message-Signature")]
    received_spf = [parse_received_spf(v) for v in ph.all("Received-SPF")]

    from_name, from_email, from_domain = split_address(ph.get("From", ""))
    _, reply_email, reply_domain = split_address(ph.get("Reply-To", ""))
    _, return_email, return_domain = split_address(ph.get("Return-Path", ""))
    _, to_email, to_domain = split_address(ph.get("To", ""))
    msg_id = ph.get("Message-ID")

    def verdict_weight(ar):
        return (sum(2 for k in ("spf", "dkim", "dmarc") if k in ar["methods"])
                + (1 if "arc" in ar["methods"] else 0))

    # The destination verdict is the Authentication-Results carrying the most
    # spf/dkim/dmarc verdicts (intermediate hops usually only stamp arc=).
    final_auth = max(auth_results, key=verdict_weight) if auth_results else None

    # The connecting IP the receiving gateway saw = the `from` address of the
    # topmost Received; fall back to Received-SPF, then Authentication-Results.
    sending_ip, sending_ip_source = None, None
    if received and received[0].get("ip"):
        sending_ip, sending_ip_source = received[0]["ip"], "topmost Received"
    if not sending_ip and received_spf and received_spf[0].get("ip"):
        sending_ip, sending_ip_source = received_spf[0]["ip"], "Received-SPF"
    if not sending_ip and final_auth:
        for method in ("spf", "dkim"):
            props = final_auth["methods"].get(method, {}).get("props", {}) or {}
            if props.get("smtp.remote-ip"):
                sending_ip, sending_ip_source = props["smtp.remote-ip"], "Authentication-Results"
                break

    mail_from = None
    if final_auth:
        mail_from = (final_auth["methods"].get("spf", {}).get("props", {}) or {}).get("smtp.mailfrom")
    mail_from_domain = mail_from.rsplit("@", 1)[-1].lower() if mail_from and "@" in mail_from else None

    return {
        "header_count": len(ph.pairs),
        "received": received,
        "auth_results": auth_results,
        "arc_auth_results": arc_auth,
        "final_auth": final_auth,
        "signatures": signatures,
        "arc_seals": arc_seals,
        "arc_message_signatures": arc_msg,
        "received_spf": received_spf,
        "gateway": extract_gateway_headers(ph),
        "from": {"raw": ph.get("From"), "name": from_name, "email": from_email, "domain": from_domain},
        "reply_to": {"email": reply_email, "domain": reply_domain},
        "return_path": {"email": return_email, "domain": return_domain},
        "to": {"email": to_email, "domain": to_domain},
        "subject": ph.get("Subject"),
        "date": ph.get("Date"),
        "message_id": msg_id,
        "message_id_domain": message_id_domain(msg_id),
        "mail_from": mail_from,
        "mail_from_domain": mail_from_domain,
        "sending_ip": sending_ip,
        "sending_ip_source": sending_ip_source,
        "helo": received[0].get("from") if received else None,
        "spam_status": next((parse_spam_status(v) for v in ph.all("X-Spam-Status")), None),
        "spam_flag": ph.get("X-Spam-Flag"),
        "scl": parse_scl(
            ph.get("X-Forefront-Antispam-Report"),
            ph.get("X-Microsoft-Antispam"),
            ph.get("X-MS-Exchange-Organization-SCL"),
        ),
        "list_unsubscribe": ph.get("List-Unsubscribe"),
        "precedence": ph.get("Precedence"),
        "x_mailer": ph.get("X-Mailer"),
        "headers": ph.pairs,
    }
