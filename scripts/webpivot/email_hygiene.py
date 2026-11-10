#!/usr/bin/env python3
# cti-expert skill — ported from the Quarry OSINT toolkit (github.com/7onez/quarry): email_hygiene_runner.py
"""email_hygiene.py — deterministic 0-100 + A-F email-domain hygiene grading.

Scores every address from four signals and a fixed, unit-testable penalty model
(no ML, no fuzz — identical inputs always yield an identical grade):

  is_disposable  -60   burner/throwaway provider (built-in list; optional API)
  mx_valid False -30   domain resolves but has NO MX -> cannot receive mail
  mx_valid None  -10   MX lookup was transient/unknown (don't hard-punish)
  is_free        -15   free webmail (gmail/outlook/...) -> low attribution
  is_role        -10   PER-EMAIL: local-part is a role mailbox (info@, admin@, ...)

  score = clamp(100 - penalties, 0, 100)
  grade: A>=85  B>=70  C>=55  D>=40  F<40

is_disposable / mx_valid / is_free are per-DOMAIN; is_role is per-EMAIL. MX is
checked keyless via DNS-over-HTTPS (dns.google, then cloudflare-dns). Disposable
detection works fully offline from the built-in list; an optional burner API key
(CHONGLUADAO_API_KEY) only augments it — never required.

SPOOFABILITY (separate block, the 0-100/A-F grade above is unchanged): for every email domain
plus any bare domain / --domains entry (a subject's estate), SPF (effective `all` qualifier,
include/redirect walk, >10 DNS-querying terms = permerror) and DMARC (p, sp, pct, rua) are read
with the engine's own parse_spf/parse_dmarc (intel_engine/WebPivot/tools/wp_recon.py) and graded
  spoofable  no DMARC, or p=none with ~all/?all/+all/missing/permerror SPF
  protected  p=reject|quarantine, pct=100, SPF -all|~all
  partial    anything in between
Thresholds: scripts/references/email_spoofability.json. A posture FACT, never attribution.

Usage:
  uv run email_hygiene.py admin@mailinator.com john.smith@example.com ceo@acme.com
  uv run email_hygiene.py --stdin --pretty < emails.txt
  uv run email_hygiene.py ceo@acme.com -o hygiene.json
  uv run email_hygiene.py ceo@example.com --domains example.net,example.org --table
  uv run email_hygiene.py ceo@example.com --no-spoof   # hygiene grade only, no TXT lookups
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

import os
import re
import json
import argparse
import concurrent.futures
from collections import Counter
import urllib.request
import urllib.error
from urllib.parse import urlencode

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

_WP = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                                    "intel_engine", "WebPivot", "tools"))
if _WP not in sys.path:
    sys.path.append(_WP)
from wp_ua import DEFAULT_UA as UA  # noqa: E402 — the one User-Agent source (Android Chrome)
import wp_http  # noqa: E402 — the one transport

# ── optional burner/disposable API key: env first, then the unified skill-root
# .env managed by /apikeys (../../ from scripts/webpivot/), overridable via
# CTI_API_KEYS_ENV. Env always wins. The disposable check works with NO key. ──
_CUSTOMIZATION_ENV = (os.environ.get("CTI_API_KEYS_ENV")
                      or os.environ.get("CTI_WEBPIVOT_ENV")
                      or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env"))
def _load_customization_env(path=_CUSTOMIZATION_ENV):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass
_load_customization_env()
def _secret(*names):
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None

# Burner-check endpoint (chongluadao.vn) — returns {"is_burner_email": true|false}.
BURNER_API_URL = "https://feeds.chongluadao.vn/external/checkburneremail"

# ── built-in signal lists — ported verbatim from the Quarry data/*.yaml files ──
# data/disposable-email-domains.yaml — well-known throwaway services (a safety
# net, NOT a comprehensive database; the optional burner API is the wide net).
DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.de", "guerrillamail.info", "guerrillamail.biz", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "spam4.me", "yopmail.com", "yopmail.fr",
    "cool.fr.nf", "jetable.fr.nf", "nospam.ze.tc", "nomail.xl.cx", "mega.zik.dj",
    "speed.1s.fr", "courriel.fr.nf", "moncourrier.fr.nf", "monemail.fr.nf",
    "monmail.fr.nf", "trashmail.com", "trashmail.me", "trashmail.net", "trashmail.at",
    "trashmail.io", "trashmail.org", "throwam.com", "throwaway.email", "spamgourmet.com",
    "tempmail.com", "tempmail.net", "temp-mail.org", "temp-mail.ru", "dispostable.com",
    "mailnull.com", "spamfree24.org", "mailnesia.com", "maildrop.cc", "anonbox.net",
    "discard.email", "fakeinbox.com", "fakeinbox.net", "mailbox52.ga", "mailmoat.com",
    "mailscrap.com", "mailsiphon.com", "mytemp.email", "owlpic.com", "safetymail.info",
    "spamavert.com", "tempemail.com", "tempr.email", "trashdevil.com", "trbvm.com",
    "filzmail.com", "spamhereplease.com", "spamspot.com", "10minutemail.com",
    "10minutemail.net", "10minutemail.org", "10minutemail.de", "20minutemail.com",
    "mohmal.com",
})

# data/free-email-providers.yaml — free (non-disposable) webmail; low attribution.
FREE_PROVIDERS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.in",
    "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it", "yahoo.com.ar", "yahoo.com.br",
    "yahoo.com.au", "ymail.com", "outlook.com", "outlook.fr", "hotmail.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it",
    "live.com", "live.co.uk", "live.fr", "live.de", "msn.com", "aol.com",
    "proton.me", "protonmail.com", "protonmail.ch", "icloud.com", "me.com",
    "mac.com", "gmx.com", "gmx.net", "gmx.de", "gmx.fr", "gmx.at", "mail.com",
    "zoho.com", "zohomail.com", "yandex.com", "yandex.ru", "yandex.ua", "qq.com",
    "163.com", "126.com", "yeah.net", "sina.com", "sina.cn", "sohu.com", "mail.ru",
    "inbox.ru", "list.ru", "bk.ru", "internet.ru", "rediffmail.com", "web.de",
    "freenet.de", "t-online.de", "arcor.de", "laposte.net", "wanadoo.fr", "orange.fr",
    "free.fr", "sfr.fr", "neuf.fr", "libero.it", "virgilio.it", "alice.it",
    "tiscali.it", "fastmail.com", "fastmail.fm", "tutanota.com", "tutanota.de",
    "tuta.io", "mailfence.com", "disroot.org", "riseup.net", "cock.li", "airmail.cc",
})

# data/role-account-localparts.yaml — functional mailboxes that are not a person.
ROLE_LOCALPARTS = frozenset({
    "admin", "administrator", "admins", "info", "information", "support", "helpdesk",
    "help", "sales", "contact", "contacts", "hello", "noreply", "no-reply", "no_reply",
    "donotreply", "do-not-reply", "postmaster", "abuse", "webmaster", "hostmaster",
    "billing", "billing-support", "payments", "accounts", "security", "privacy",
    "legal", "compliance", "team", "office", "mail", "email", "marketing",
    "newsletter", "news", "press", "media", "pr", "jobs", "careers", "hr",
    "humanresources", "recruitment", "hiring", "it", "ops", "operations", "devops",
    "sysadmin", "root", "daemon", "mailer-daemon", "bounce", "bounces", "feedback",
    "report", "reports", "alerts", "notifications", "notify", "reply", "signup",
    "register", "account", "members", "member", "users", "user", "customers",
    "customer", "clients", "client", "service", "services", "tech", "technical",
    "api", "system", "sys", "bot", "robot", "automated", "auto", "machine",
    "office365", "google", "microsoft", "aws", "azure",
})

# TLD: letters, or a punycode IDN TLD (`xn--p1ai` = .рф) — DNS returns IDN ccTLDs in that form.
_EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.(?:[A-Za-z]{2,}|xn--[A-Za-z0-9-]+))$")
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.(?:[a-z]{2,}|xn--[a-z0-9-]+)$")


# ── disposable signal ─────────────────────────────────────────────────────────
def _check_burner_api(domain, api_key, timeout=10):
    """Burner-API verdict for a domain: True/False, or None on any error.

    The key is sent only in the X-API-KEY header and is NEVER logged/printed —
    exceptions are swallowed to avoid surfacing a Request repr that includes it.
    """
    q = BURNER_API_URL + "?" + urlencode({"q": domain})
    r = wp_http.request(q, headers={"X-API-KEY": api_key}, timeout=timeout, bounded=True)
    if not r.ok:
        return None
    try:
        data = json.loads(r.body)
        return bool(data.get("is_burner_email", False))
    except Exception:
        return None


def check_disposable(domain, api_key=None):
    """True if the domain is a throwaway/burner provider.

    The built-in list is primary and the always-on fallback. When a key is set,
    the burner API augments it (OR); a failed API call degrades to the list.
    """
    domain = domain.lower()
    local_hit = domain in DISPOSABLE_DOMAINS
    if api_key:
        api_result = _check_burner_api(domain, api_key)
        if api_result is not None:
            return bool(api_result or local_hit)
    return local_hit


def is_free(domain):
    """True if the domain is a known free webmail provider."""
    return domain.lower() in FREE_PROVIDERS


def is_role(localpart):
    """True if the local-part is a known role/functional mailbox (per-email)."""
    return localpart.lower().strip() in ROLE_LOCALPARTS


# ── MX validity via DNS-over-HTTPS (keyless, zero-dep) ─────────────────────────
def mx_lookup(domain, timeout=8):
    """Resolve MX for a domain over DoH.

    True  -> >=1 MX record present
    False -> domain resolves with no MX, or does not exist (confirmed no mail)
    None  -> transient/unknown (both DoH providers unreachable or SERVFAIL)
    """
    providers = (
        ("https://dns.google/resolve", None),
        ("https://cloudflare-dns.com/dns-query",
         {"Accept": "application/dns-json"}),
    )
    for base, headers in providers:
        q = base + "?" + urlencode({"name": domain, "type": "MX"})
        r = wp_http.request(q, headers=headers, timeout=timeout, bounded=True)
        if not r.ok:
            continue  # transient for this provider — try the next one
        try:
            data = json.loads(r.body)
        except Exception:
            continue  # transient for this provider — try the next one
        status = data.get("Status")
        if status == 0:  # NOERROR
            answers = data.get("Answer") or []
            # RFC 7505 "null MX": a single `0 .` record is a PRESENT record whose meaning is
            # "this domain accepts no mail". Counting it as an MX inverts the signal — the
            # domain that explicitly refuses mail would grade A. Treat it as no MX.
            mx = [a for a in answers if isinstance(a, dict) and a.get("type") == 15]
            real = [a for a in mx
                    if (a.get("data") or "").strip().split()[-1].rstrip(".") not in ("", ".")]
            return bool(real)  # True = deliverable MX; False = none, or RFC 7505 null MX
        if status == 3:  # NXDOMAIN — domain does not exist
            return False
        # SERVFAIL / other rcode — indeterminate; fall through to next provider
    return None


def _mx_lookup_many(domains, timeout=8):
    """Batch MX lookup across distinct domains. Returns {domain: bool|None}."""
    out = {}
    if not domains:
        return out
    workers = min(8, len(domains))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(mx_lookup, d, timeout): d for d in domains}
        for fut in concurrent.futures.as_completed(futs):
            d = futs[fut]
            try:
                out[d] = fut.result()
            except Exception:
                out[d] = None
    return out


# ── scoring (ported EXACTLY — do not change weights or thresholds) ─────────────
def score_domain(is_disposable, mx_valid, is_free_):
    """Per-domain score (0-100)."""
    score = 100
    if is_disposable:
        score -= 60
    if mx_valid is False:
        score -= 30
    elif mx_valid is None:
        score -= 10
    if is_free_:
        score -= 15
    return max(0, min(100, score))


def score_email(domain_score, is_role_):
    """Apply the per-email role penalty on top of the domain score."""
    score = domain_score
    if is_role_:
        score -= 10
    return max(0, min(100, score))


def grade(score):
    """Map a numeric score to an A-F letter grade."""
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def grade_emails(emails, api_key=None, mx_timeout=8):
    """Grade a list of emails. Groups per-domain signals, scores per-email."""
    # parse + validate (invalid addresses are skipped, mirroring the source)
    parsed = []  # (email, localpart, domain)
    for raw in emails:
        raw = (raw or "").strip()
        m = _EMAIL_RE.match(raw)
        if m:
            parsed.append((raw, raw.split("@")[0], m.group(1).lower()))

    # dedupe domains (order-preserving) -> per-domain signals + scores
    domains_ordered = list(dict.fromkeys(d for _, _, d in parsed))
    mx = _mx_lookup_many(domains_ordered, timeout=mx_timeout)

    domains_out = {}
    for d in domains_ordered:
        disp = check_disposable(d, api_key)
        free = is_free(d)
        mxv = mx.get(d)
        sc = score_domain(disp, mxv, free)
        domains_out[d] = {
            "score": sc, "grade": grade(sc),
            "is_disposable": disp, "mx_valid": mxv, "is_free": free,
        }

    # per-email enrichment: role flag + combined score/grade
    results = []
    for raw, lp, d in parsed:
        drec = domains_out[d]
        role = is_role(lp)
        esc = score_email(drec["score"], role)
        results.append({
            "email": raw, "domain": d,
            "score": esc, "grade": grade(esc),
            "is_disposable": drec["is_disposable"],
            "mx_valid": drec["mx_valid"],
            "is_free": drec["is_free"],
            "is_role": role,
        })

    return {
        "results": results,
        "domains": domains_out,
        "summary": {"emails": len(results), "domains": len(domains_out)},
    }


# ── spoofability: SPF + DMARC posture per domain (a subject's estate) ─────────
# Parsing REUSES the engine's parse_spf / parse_dmarc (intel_engine/WebPivot/tools/wp_recon.py,
# the same parser that fills artifacts.mail.spf/.dmarc for wp_analyze). Thresholds live in
# scripts/references/email_spoofability.json. The grade is a posture FACT — whether a third party
# can send mail passing as the domain — never evidence about who owns it (RULE 5).
_SPOOF_FALLBACK = {
    "limits": {"max_dns_lookups": 10, "max_include_depth": 6, "required_pct": 100},
    "doh_endpoints": ["https://dns.google/resolve"],
    "protected_policies": ["reject"],
    "protected_spf_all": ["-all"],
    "weak_spf_all": ["~all", "?all", "+all", "missing", "permerror"],
}
_SPOOF_CAVEAT = ("posture fact about the domain's mail authentication, not attribution: it says "
                 "whether others can send mail passing as this domain, never who owns it")


def _engine_module(name):
    """A canonical engine module from intel_engine/WebPivot/tools, or None."""
    tools = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "..", "..", "intel_engine", "WebPivot", "tools"))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        return __import__(name)
    except Exception:  # noqa: BLE001
        return None


def _spoof_refs():
    refs = _engine_module("wp_refs")
    if refs is None:
        print("[!] wp_refs unavailable — email_spoofability.json not loaded, using the embedded "
              "minimum", file=sys.stderr)
        return dict(_SPOOF_FALLBACK)
    return refs.load_ref(refs.ref_path(__file__, "email_spoofability.json"), _SPOOF_FALLBACK)


def txt_lookup(name, timeout=8):
    """TXT records for `name`: list (possibly empty = NOERROR/NXDOMAIN with none) or None
    (indeterminate). DoH first so an empty answer is distinguishable from an unreachable
    resolver — through the engine's wp_net.fetch (Android UA, proxy handling) when present —
    then the engine's dig/nslookup reader."""
    net = _engine_module("wp_net")
    for base in (_spoof_refs()["doh_endpoints"] if net is not None else []):
        q = base + "?" + urlencode({"name": name, "type": "TXT"})
        try:
            if net is not None:
                _u, st, _h, body = net.fetch(q, timeout=timeout,
                                             extra_headers={"Accept": "application/dns-json"})
                if st != 200:
                    continue
                data = json.loads(body.decode("utf-8", "replace") if isinstance(body, bytes) else body)
        except Exception:
            continue
        status = data.get("Status")
        if status in (0, 3):
            out = []
            for a in data.get("Answer") or []:
                if isinstance(a, dict) and a.get("type") == 16:
                    # DoH returns quoted 255-char chunks: '"v=spf1 ..." "rest"' -> one string
                    s = re.sub(r'"\s+"', "", (a.get("data") or "").strip()).strip().strip('"')
                    if s:
                        out.append(s)
            return out
    recon = _engine_module("wp_recon")
    if recon is not None:
        try:
            recs = recon._txt_records(name, timeout=timeout)
            return recs if recs else None
        except Exception:  # noqa: BLE001
            return None
    return None


def _norm_all(tok):
    """parse_spf's `all` (tok[-4:]) -> '-all'/'~all'/'?all'/'+all'; a bare 'all' is '+all'."""
    if not tok:
        return None
    tok = tok.lower()
    return tok if tok[:1] in "-~?+" else "+" + tok.lstrip()[-3:]


def spf_walk(domain, recon, lookup=txt_lookup, limits=None, timeout=8):
    """Evaluate a domain's SPF the way a receiver would, for posture purposes.

    Returns {raw, all, lookups, permerror, reasons, includes}: `all` is the EFFECTIVE terminal
    qualifier ('-all'/'~all'/'?all'/'+all'/'missing'/'permerror'), following redirect= when the
    top record has no `all`. `lookups` counts every DNS-querying term across the include tree
    (RFC 7208 §4.6.4); more than max_dns_lookups is a permerror."""
    limits = limits or _SPOOF_FALLBACK["limits"]
    max_lookups = int(limits.get("max_dns_lookups", 10))
    max_depth = int(limits.get("max_include_depth", 6))
    state = {"lookups": 0, "reasons": [], "unresolved": []}

    def _count(spf_raw):
        return sum(1 for t in spf_raw.split()
                   if re.match(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr\b|ptr:|exists:)", t, re.I)
                   or t.lower().startswith("redirect="))

    def _walk(name, depth, seen):
        state["max_depth"] = max(depth, state.get("max_depth", 0))
        if depth > max_depth:
            state["unresolved"].append(name)
            state["reasons"].append(f"include depth > {max_depth}; evaluation incomplete")
            return None
        if state["lookups"] > max_lookups:
            return "permerror"
        recs = lookup(name, timeout=timeout)
        if recs is None:
            state["unresolved"].append(name)
            return None
        spfs = [r for r in recs if r.lower().startswith("v=spf1")]
        if len(spfs) > 1:
            state["reasons"].append(f"{name}: multiple SPF records (permerror)")
            return "permerror"
        if not spfs:
            if depth:
                state["reasons"].append(f"{name}: include/redirect has no SPF (permerror)")
                return "permerror"
            return None
        parsed = recon.parse_spf(spfs)
        includes = [t.lstrip("+-~?").split(":", 1)[1] for t in parsed["raw"].split()
                    if t.lstrip("+-~?").lower().startswith("include:")]
        parsed["includes"] = includes
        state["lookups"] += _count(parsed["raw"])
        for inc in includes:
            if inc.lower() in seen:
                state["reasons"].append(f"{inc}: cyclic include (permerror)")
                return "permerror"
            if _walk(inc, depth + 1, seen | {inc.lower()}) == "permerror":
                return "permerror"
        if not parsed["all"] and parsed["redirect"]:
            target = parsed["redirect"]
            if target.lower() in seen:
                state["reasons"].append(f"{target}: cyclic redirect (permerror)")
                return "permerror"
            red = _walk(target, depth + 1, seen | {target.lower()})
            if red == "permerror":
                return red
            if red:
                parsed["all"] = red["all"]
        return parsed

    top = _walk(domain, 0, {domain.lower()})
    out = {"raw": None, "all": "missing", "lookups": 0, "permerror": False,
           "includes": [], "redirect": None}
    out["include_depth"] = state.get("max_depth", 0)
    if top == "permerror":
        out.update(all="permerror", permerror=True)
    elif top:
        out.update(raw=top["raw"], includes=top["includes"], redirect=top["redirect"])
        eff = _norm_all(top["all"])
        out["all"] = eff or "missing"
        out["permerror"] = eff == "permerror"
    out["lookups"] = state["lookups"]
    if state["lookups"] > max_lookups:
        out["permerror"] = True
        out["all"] = "permerror"
        state["reasons"].append(f"{state['lookups']} DNS-querying SPF terms > {max_lookups} (permerror)")
    if state["unresolved"]:
        out["all"] = "unknown"
        out["unresolved"] = state["unresolved"]
    out["reasons"] = state["reasons"]
    return out


def dmarc_read(domain, recon, lookup=txt_lookup, timeout=8):
    """DMARC posture {raw,p,sp,pct,rua_present,ruf_present} | None (no record) | {"error":...}."""
    recs = lookup("_dmarc." + domain, timeout=timeout)
    if recs is None:
        return {"error": "DMARC lookup indeterminate (resolvers unreachable)"}
    if len([r for r in recs if r.lower().startswith("v=dmarc1")]) > 1:
        return {"error": "multiple DMARC records; policy invalid"}
    d = recon.parse_dmarc(recs)
    if not d:
        return None
    m = re.search(r"(?:^|;)\s*pct\s*=\s*([^;]+)", d["raw"], re.I)
    try:
        pct = int(m.group(1).strip()) if m else 100
        if not 0 <= pct <= 100:
            raise ValueError("pct outside 0-100")
    except ValueError:
        return {"error": "invalid DMARC pct"}
    return {"raw": d["raw"], "p": (d["p"] or "").lower() or None,
            "sp": (d["sp"] or "").lower() or None,
            "pct": pct,
            "rua_present": bool(d["rua"]), "ruf_present": bool(d["ruf"])}


def spoof_grade(spf, dmarc, refs):
    """(grade, reasons) from an spf_walk() and a dmarc_read() result.

    spoofable : no DMARC, or DMARC p=none with a weak SPF terminal (~all/?all/+all/missing/permerror)
    protected : DMARC p in protected_policies, pct == required_pct, SPF all in protected_spf_all
    partial   : anything in between (enforcing at pct<100, p=none behind -all, weak SPF behind
                an enforcing DMARC, ...)"""
    lim = refs["limits"]
    weak = set(refs["weak_spf_all"])
    strong_all = set(refs["protected_spf_all"])
    enforcing = set(refs["protected_policies"])
    req_pct = int(lim.get("required_pct", 100))
    spf_all = spf.get("all") or "missing"
    reasons = []
    if not dmarc:
        reasons.append("no DMARC record — receivers have no policy to apply")
        return "spoofable", reasons
    p = dmarc.get("p") or "none"
    if p == "none":
        if spf_all in weak:
            reasons.append(f"DMARC p=none (monitor only) and SPF {spf_all}")
            return "spoofable", reasons
        reasons.append(f"DMARC p=none (monitor only), SPF {spf_all}; protection not established")
        return "partial", reasons
    if p in enforcing and dmarc.get("pct", 100) >= req_pct and spf_all in strong_all:
        reasons.append(f"DMARC p={p} pct={dmarc.get('pct', 100)} with SPF {spf_all}")
        sp = dmarc.get("sp")
        if sp == "none":
            reasons.append("but sp=none — SUBDOMAINS are spoofable")
        return "protected", reasons
    if p not in enforcing:
        reasons.append(f"DMARC p={p} is not an enforcing policy")
    if dmarc.get("pct", 100) < req_pct:
        reasons.append(f"DMARC pct={dmarc.get('pct')} < {req_pct} — only part of failing mail is acted on")
    if spf_all not in strong_all:
        reasons.append(f"SPF terminal {spf_all} does not deny unknown senders")
    return "partial", reasons


def spoofability(domains, lookup=txt_lookup, timeout=8):
    """Spoofability table for a list of domains (a subject's estate). One row per domain:
    {domain, grade, spf_all, spf_lookups, spf_permerror, dmarc_p, dmarc_sp, dmarc_pct,
    rua_present, reasons, caveat}. Never raises; an unparseable/unavailable engine yields
    {"skipped": ...} rows."""
    recon = _engine_module("wp_recon")
    if not domains:
        return []
    if recon is None or not hasattr(recon, "parse_spf"):
        return [{"domain": d, "skipped": "engine SPF/DMARC parser (wp_recon) unavailable"}
                for d in domains]
    refs = _spoof_refs()

    def _one(d):
        try:
            spf = spf_walk(d, recon, lookup=lookup, limits=refs["limits"], timeout=timeout)
            dmarc = dmarc_read(d, recon, lookup=lookup, timeout=timeout)
        except Exception as e:  # noqa: BLE001 — never let one domain abort the table
            return {"domain": d, "error": f"{type(e).__name__}: {e}"}
        if isinstance(dmarc, dict) and dmarc.get("error"):
            return {"domain": d, "error": dmarc["error"], "spf_all": spf.get("all")}
        g, why = spoof_grade(spf, dmarc, refs)
        dm = dmarc or {}
        return {"domain": d, "grade": g,
                "spf_all": spf.get("all"), "spf_lookups": spf.get("lookups"),
                "spf_permerror": spf.get("permerror"), "spf_raw": spf.get("raw"),
                "spf_include_depth": spf.get("include_depth"),
                "dmarc_p": dm.get("p"), "dmarc_sp": dm.get("sp"),
                "dmarc_pct": dm.get("pct"), "rua_present": dm.get("rua_present", False),
                "dmarc_raw": dm.get("raw"),
                "reasons": spf.get("reasons", []) + why,
                "caveat": _SPOOF_CAVEAT}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(domains))) as pool:
        return list(pool.map(_one, domains))


def spoof_table_md(rows):
    """Markdown table of spoofability rows."""
    L = ["| Domain | Grade | SPF all | SPF lookups | DMARC p | sp | pct | rua | Basis |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r.get("skipped") or r.get("error"):
            L.append(f"| {r['domain']} | — | {r.get('spf_all') or ''} | | | | | | "
                     f"{r.get('skipped') or r.get('error')} |")
            continue
        L.append(f"| {r['domain']} | {r['grade']} | {r['spf_all']} | {r['spf_lookups']} | "
                 f"{r['dmarc_p'] or '—'} | {r['dmarc_sp'] or '—'} | "
                 f"{'' if r['dmarc_pct'] is None else r['dmarc_pct']} | "
                 f"{'yes' if r['rua_present'] else 'no'} | "
                 + "; ".join(r["reasons"]).replace("|", "/") + " |")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        description="Deterministic 0-100 + A-F email-domain hygiene grading (Quarry port).")
    ap.add_argument("emails", nargs="*",
                    help="email address(es) to grade; a bare domain is graded for spoofability only")
    ap.add_argument("--domains", default="",
                    help="comma/space-separated extra domains (a subject's estate) for the "
                         "spoofability table")
    ap.add_argument("--no-spoof", action="store_true",
                    help="skip the SPF/DMARC spoofability block (no TXT lookups)")
    ap.add_argument("--table", action="store_true",
                    help="print the spoofability table as markdown on stdout instead of JSON "
                         "(JSON still goes to -o when given)")
    ap.add_argument("--stdin", action="store_true",
                    help="also read emails from stdin, one per line")
    ap.add_argument("--pretty", action="store_true", help="pretty-print the JSON output")
    ap.add_argument("-o", "--out", help="write JSON to FILE instead of stdout")
    ap.add_argument("--mx-timeout", type=int, default=8,
                    help="per-request DNS-over-HTTPS timeout in seconds (default 8)")
    args = ap.parse_args()

    items = list(args.emails)
    if args.stdin:
        try:
            items += [ln.strip() for ln in sys.stdin if ln.strip()]
        except Exception:
            pass
    emails = [x for x in items if "@" in x]
    bare = [x.strip().lower().rstrip(".") for x in items if "@" not in x]
    bare += [d.strip().lower().rstrip(".") for d in args.domains.replace(",", " ").split()]
    bare_ok = [d for d in bare if _DOMAIN_RE.match(d)]
    if not emails and not bare_ok:
        ap.error("provide email(s) or domain(s) as arguments, via --domains, or via --stdin")

    api_key = _secret("CHONGLUADAO_API_KEY", "BURNER_API_KEY",
                      "CHONGLUADAO_KEY", "CLD_API_KEY")
    result = grade_emails(emails, api_key=api_key, mx_timeout=args.mx_timeout)
    if not args.no_spoof:
        spoof_domains = list(dict.fromkeys(list(result["domains"]) + bare_ok))
        rows = spoofability(spoof_domains, timeout=args.mx_timeout)
        result["spoofability"] = rows
        result["summary"]["spoofability"] = dict(
            Counter(r.get("grade") or ("skipped" if r.get("skipped") else "error") for r in rows))

    out_json = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(out_json + "\n")
        except Exception as e:
            print(f"[!] could not write {args.out}: {e}", file=sys.stderr)
            print(out_json)
        if args.table and result.get("spoofability"):
            print(spoof_table_md(result["spoofability"]))
    elif args.table and result.get("spoofability"):
        print(spoof_table_md(result["spoofability"]))
    else:
        print(out_json)

    n = result["summary"]["emails"]
    m = result["summary"]["domains"]
    if n:
        avg = round(sum(r["score"] for r in result["results"]) / n)
        avg_g = grade(avg)
    else:
        avg, avg_g = 0, "-"
    skipped = len(emails) - n + (len(bare) - len(bare_ok))
    extra = f"; skipped {skipped} invalid" if skipped > 0 else ""
    print(f"graded {n} emails across {m} domains; avg grade {avg_g} ({avg}){extra}",
          file=sys.stderr)
    if result.get("spoofability"):
        print("spoofability: " + ", ".join(f"{r['domain']}={r.get('grade') or 'n/a'}"
                                           for r in result["spoofability"]), file=sys.stderr)


if __name__ == "__main__":
    main()
