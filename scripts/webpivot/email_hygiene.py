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

Usage:
  uv run email_hygiene.py admin@mailinator.com john.smith@example.com ceo@acme.com
  uv run email_hygiene.py --stdin --pretty < emails.txt
  uv run email_hygiene.py ceo@acme.com -o hygiene.json
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

UA = "cti-expert/1.0"

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

_EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")


# ── disposable signal ─────────────────────────────────────────────────────────
def _check_burner_api(domain, api_key, timeout=10):
    """Burner-API verdict for a domain: True/False, or None on any error.

    The key is sent only in the X-API-KEY header and is NEVER logged/printed —
    exceptions are swallowed to avoid surfacing a Request repr that includes it.
    """
    try:
        q = BURNER_API_URL + "?" + urlencode({"q": domain})
        req = urllib.request.Request(q, headers={"User-Agent": UA, "X-API-KEY": api_key})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
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
        ("https://dns.google/resolve", {"User-Agent": UA}),
        ("https://cloudflare-dns.com/dns-query",
         {"User-Agent": UA, "Accept": "application/dns-json"}),
    )
    for base, headers in providers:
        try:
            q = base + "?" + urlencode({"name": domain, "type": "MX"})
            req = urllib.request.Request(q, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.load(r)
        except Exception:
            continue  # transient for this provider — try the next one
        status = data.get("Status")
        if status == 0:  # NOERROR
            answers = data.get("Answer") or []
            has_mx = any(isinstance(a, dict) and a.get("type") == 15 for a in answers)
            return bool(has_mx)  # True = has MX; False = resolves but none
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


def main():
    ap = argparse.ArgumentParser(
        description="Deterministic 0-100 + A-F email-domain hygiene grading (Quarry port).")
    ap.add_argument("emails", nargs="*", help="email address(es) to grade")
    ap.add_argument("--stdin", action="store_true",
                    help="also read emails from stdin, one per line")
    ap.add_argument("--pretty", action="store_true", help="pretty-print the JSON output")
    ap.add_argument("-o", "--out", help="write JSON to FILE instead of stdout")
    ap.add_argument("--mx-timeout", type=int, default=8,
                    help="per-request DNS-over-HTTPS timeout in seconds (default 8)")
    args = ap.parse_args()

    emails = list(args.emails)
    if args.stdin:
        try:
            emails += [ln.strip() for ln in sys.stdin if ln.strip()]
        except Exception:
            pass
    if not emails:
        ap.error("provide email(s) as arguments or via --stdin")

    api_key = _secret("CHONGLUADAO_API_KEY", "BURNER_API_KEY",
                      "CHONGLUADAO_KEY", "CLD_API_KEY")
    result = grade_emails(emails, api_key=api_key, mx_timeout=args.mx_timeout)

    out_json = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(out_json + "\n")
        except Exception as e:
            print(f"[!] could not write {args.out}: {e}", file=sys.stderr)
            print(out_json)
    else:
        print(out_json)

    n = result["summary"]["emails"]
    m = result["summary"]["domains"]
    if n:
        avg = round(sum(r["score"] for r in result["results"]) / n)
        avg_g = grade(avg)
    else:
        avg, avg_g = 0, "-"
    skipped = len(emails) - n
    extra = f"; skipped {skipped} invalid" if skipped > 0 else ""
    print(f"graded {n} emails across {m} domains; avg grade {avg_g} ({avg}){extra}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
