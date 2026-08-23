#!/usr/bin/env python3
"""
en_forms.py — DETECT the authentication surface of a site: the login form, the password field,
and the registration page. The passive, free half of the Engage skill.

WHAT IT DOES
------------
Fetches a page (GET only — this reads the page, it does not act) and reads every `<form>`, then
classifies each one by the FIELDS IT CARRIES, not by a word in the URL:

  * LOGIN            — an identifier field (email/username/phone) + a password field, and NO
                       confirm-password field; small; submit text like "log in / sign in".
  * REGISTER         — a password field plus a CONFIRM-password field, and/or a referral/invite
                       code, a terms checkbox, extra identity fields, or submit text like
                       "sign up / register / create account". The confirm-password field is the
                       single strongest tell.
  * PASSWORD-RESET   — an identifier but no password ("forgot / recover").

It then follows ONE hop to the linked register page (and/or the login page) so that when the
entry page shows only a login box, the signup form is found too — confirmed by reading that
page's fields, never by trusting the link's URL.

Alongside the forms it surfaces what ENGAGEMENT would need to know: the form's POST `action` (the
auth endpoint — a pivot, and often the backend/API host the HTML never otherwise names), whether
a CAPTCHA or an OTP/verification step blocks an automated signup, and whether a referral/invite
code is required (a closed-funnel tell and a clustering pivot).

WHY DETECTION IS SEPARATE FROM ENGAGEMENT
-----------------------------------------
This module only READS. Creating the account is `en_engage.py`, which is gated, synthetic-only,
and never runs from here. Detection tells you whether engagement is even possible and what it
would cost before anyone touches the operator's box — that ordering is the whole point.

SPA CAVEAT
----------
Many kits render the login/register form in JavaScript, so it is absent from the static HTML.
When no `<form>` is found but the page smells like an auth surface (auth links, framework
bundles, `/login`·`/register` routes), the result says so and points you at a rendered fetch
(WebPivot `pivot_extract --render`) rather than reporting "no login form" — absence in static
HTML is not absence on the page.

USAGE
-----
    en_forms.py https://site.example                     # detect, print JSON
    en_forms.py https://site.example --leads             # human-readable summary
    en_forms.py https://site.example -o out.json --pretty
    en_forms.py https://site.example --no-crawl          # do not follow the register/login hop
    en_forms.py https://site.example --proxy http://127.0.0.1:8080   # read via research egress
    en_forms.py saved_page.html                          # offline, analyse saved HTML
    cat page.html | en_forms.py -                        # from stdin

Zero required dependencies (Python 3 stdlib). Uses `requests` only if already installed.
"""
from __future__ import annotations

import argparse
import gzip
import html
import json
import os
import sys
import zlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from en_refs import load_ref, ref_path  # noqa: E402

# --- reference data (RULE 3): tunable in references/engage.json, minimal fallback here ----------
_FALLBACK = {
    "identifier_fields": ["email", "username", "user", "login", "account", "phone", "tel", "mobile"],
    "password_fields": ["password", "passwd", "pass", "pwd", "pin"],
    "confirm_password_tokens": ["confirm", "repeat", "retype", "again", "password2", "re_password"],
    "login_submit_terms": ["log in", "login", "sign in", "signin"],
    "register_submit_terms": ["sign up", "signup", "register", "create account", "join"],
    "reset_terms": ["forgot", "reset", "recover"],
    "register_link_tokens": ["register", "signup", "sign-up", "join", "create-account"],
    "login_link_tokens": ["login", "signin", "sign-in", "auth"],
    "referral_tokens": ["referral", "invite", "invitecode", "promo", "sponsor", "affiliate", "ref_code"],
    "otp_tokens": ["otp", "verify", "verification", "code", "2fa", "sms"],
    "captcha_markers": ["recaptcha", "hcaptcha", "turnstile", "geetest", "captcha"],
    "terms_tokens": ["agree", "terms", "tos", "privacy", "consent"],
    "thresholds": {"max_login_fields": 4, "register_min_fields": 3,
                   "crawl_register_hops": 1, "fetch_timeout_s": 20},
}
_REF = load_ref(ref_path(__file__, "engage.json"), _FALLBACK)
IDENTIFIER = [t.lower() for t in _REF["identifier_fields"]]
PASSWORD = [t.lower() for t in _REF["password_fields"]]
CONFIRM = [t.lower() for t in _REF["confirm_password_tokens"]]
LOGIN_TERMS = [t.lower() for t in _REF["login_submit_terms"]]
REGISTER_TERMS = [t.lower() for t in _REF["register_submit_terms"]]
RESET_TERMS = [t.lower() for t in _REF["reset_terms"]]
REGISTER_LINKS = [t.lower() for t in _REF["register_link_tokens"]]
LOGIN_LINKS = [t.lower() for t in _REF["login_link_tokens"]]
REFERRAL = [t.lower() for t in _REF["referral_tokens"]]
OTP = [t.lower() for t in _REF["otp_tokens"]]
CAPTCHA = [t.lower() for t in _REF["captcha_markers"]]
TERMS = [t.lower() for t in _REF["terms_tokens"]]
TH = _REF["thresholds"]

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# --- fetch (stdlib; requests if present) --------------------------------------------------------
def _fetch(url: str, timeout: int, proxy: str = None):
    """Return (final_url, status, html_text). GET only. Never raises — returns ('', 0, '') on error."""
    headers = {"User-Agent": DEFAULT_UA, "Accept": "text/html,application/xhtml+xml"}
    try:
        import requests  # type: ignore
        proxies = {"http": proxy, "https": proxy} if proxy else None
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True,
                         proxies=proxies, verify=True)
        return r.url, r.status_code, r.text
    except ImportError:
        pass
    except Exception as exc:  # requests present but failed
        print(f"[en_forms] fetch error: {exc}", file=sys.stderr)
        return "", 0, ""
    import urllib.request
    import urllib.error
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers) if handlers else None
    req = urllib.request.Request(url, headers=headers)
    try:
        with (opener.open(req, timeout=timeout) if opener
              else urllib.request.urlopen(req, timeout=timeout)) as resp:
            raw = resp.read()
            enc = (resp.headers.get("content-encoding") or "").lower()
            if "gzip" in enc:
                raw = gzip.decompress(raw)
            elif "deflate" in enc:
                raw = zlib.decompress(raw)
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.geturl(), resp.status, raw.decode(charset, "replace")
    except urllib.error.HTTPError as e:
        try:
            return url, e.code, (e.read() or b"").decode("utf-8", "replace")
        except Exception:
            return url, e.code, ""
    except Exception as exc:
        print(f"[en_forms] fetch error: {exc}", file=sys.stderr)
        return "", 0, ""


# --- HTML parsing -------------------------------------------------------------------------------
class _FormParser(HTMLParser):
    """Collect <form>s with their fields + submit labels, plus page-level auth links and anti-bot
    markers. Inputs appearing OUTSIDE any form are kept separately — an SPA renders the real form
    later, but a stray password input still tells us the page is an auth surface."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.orphan_fields = []
        self.links = []          # (href, text)
        self.captcha_hits = set()
        self._stack = []         # open <form> dicts
        self._btn = None         # open <button> -> accumulate its text
        self._a = None           # open <a href=...> -> accumulate its text

    # -- helpers
    def _field(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        name = " ".join(x for x in (a.get("name"), a.get("id"), a.get("placeholder"),
                                    a.get("autocomplete"), a.get("aria-label")) if x)
        f = {"tag": tag, "type": (a.get("type") or ("select" if tag == "select" else "text")).lower(),
             "name": a.get("name") or a.get("id") or "", "id": a.get("id") or "",
             "placeholder": a.get("placeholder") or "", "autocomplete": a.get("autocomplete") or "",
             "required": ("required" in a) or (a.get("aria-required") == "true"),
             "_hay": name.lower()}
        return f

    def _mark_captcha(self, s):
        s = (s or "").lower()
        for m in CAPTCHA:
            if m in s:
                self.captcha_hits.add(m)

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._stack.append({
                "action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                "id": a.get("id", ""), "class": a.get("class", ""),
                "fields": [], "submit_labels": [], "_hay": (a.get("id", "") + " " + a.get("class", "")).lower(),
            })
        elif tag in ("input", "select", "textarea"):
            f = self._field(tag, attrs)
            if a.get("type", "").lower() in ("submit", "button", "image"):
                lbl = a.get("value") or a.get("aria-label") or ""
                (self._stack[-1]["submit_labels"] if self._stack else []).append(lbl)
            elif a.get("type", "").lower() not in ("hidden",) or self._is_referral(f):
                (self._stack[-1]["fields"] if self._stack else self.orphan_fields).append(f)
            self._mark_captcha(a.get("class", "") + " " + a.get("id", "") + " " + a.get("data-sitekey", ""))
        elif tag == "button":
            self._btn = ""
        elif tag == "a":
            self._a = a.get("href", "")
            self._a_text = ""
        elif tag in ("script", "iframe", "div"):
            self._mark_captcha(a.get("src", "") + " " + a.get("class", "") + " " + a.get("id", "")
                               + " " + a.get("data-sitekey", ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._stack:
            self.forms.append(self._stack.pop())
        elif tag == "button":
            if self._btn is not None and self._stack:
                self._stack[-1]["submit_labels"].append(self._btn.strip())
            self._btn = None
        elif tag == "a":
            if self._a is not None and (self._a or getattr(self, "_a_text", "")):
                self.links.append((self._a, getattr(self, "_a_text", "").strip()))
            self._a = None

    def handle_data(self, data):
        if self._btn is not None:
            self._btn += data
        if self._a is not None:
            self._a_text = getattr(self, "_a_text", "") + data

    @staticmethod
    def _is_referral(f):
        return any(t in f["_hay"] for t in REFERRAL)


def _has(tokens, hay):
    return any(t in hay for t in tokens)


def _classify(form):
    """Return (kind, confidence, signals) for one parsed form."""
    fields = form["fields"]
    submit = " ".join(form.get("submit_labels", [])).lower()
    hay_all = form["_hay"] + " " + " ".join(f["_hay"] for f in fields) + " " + submit

    has_pw = any(f["type"] == "password" or _has(PASSWORD, f["_hay"]) for f in fields)
    pw_count = sum(1 for f in fields if f["type"] == "password" or _has(PASSWORD, f["_hay"]))
    has_confirm = any(_has(CONFIRM, f["_hay"]) for f in fields) or pw_count >= 2
    has_ident = any(_has(IDENTIFIER, f["_hay"]) or f["type"] in ("email", "tel") for f in fields)
    has_referral = any(_is_ref(f) for f in fields)
    has_terms = any(f["type"] == "checkbox" and _has(TERMS, f["_hay"]) for f in fields)
    has_otp = any(_is_otp(f) for f in fields)
    n_visible = len(fields)

    signals = []
    if has_pw:
        signals.append("password_field")
    if has_confirm:
        signals.append("confirm_password_field")
    if has_ident:
        signals.append("identifier_field")
    if has_referral:
        signals.append("referral_field")
    if has_terms:
        signals.append("terms_checkbox")
    if has_otp:
        signals.append("otp_field")

    reg_words = _has(REGISTER_TERMS, submit) or _has(REGISTER_TERMS, form["_hay"])
    login_words = _has(LOGIN_TERMS, submit) or _has(LOGIN_TERMS, form["_hay"])
    reset_words = _has(RESET_TERMS, hay_all)

    # --- decision ladder (order matters: confirm-password dominates) --------------------------
    if has_pw and (has_confirm or has_referral or has_terms or reg_words
                   or n_visible > TH["max_login_fields"]):
        conf = 0.9 if has_confirm else (0.8 if (has_referral or reg_words) else 0.6)
        return "register", conf, signals
    if reset_words and has_ident and not has_pw:
        return "password_reset", 0.75, signals
    if has_pw and has_ident and not has_confirm:
        conf = 0.9 if login_words else (0.75 if n_visible <= TH["max_login_fields"] else 0.6)
        return "login", conf, signals
    if has_pw and not has_ident:
        # password present but no obvious identifier (e.g. a set-new-password step)
        return ("register" if has_confirm else "login"), 0.5, signals
    if reg_words and n_visible >= TH["register_min_fields"]:
        return "register", 0.55, signals
    if login_words:
        return "login", 0.5, signals
    return "other", 0.2, signals


def _is_ref(f):
    return any(t in f["_hay"] for t in REFERRAL)


def _is_otp(f):
    """OTP/verification field — but NOT a referral/invite code, which also carries 'code'."""
    return any(t in f["_hay"] for t in OTP) and not _is_ref(f)


def _field_public(f):
    return {k: f[k] for k in ("tag", "type", "name", "id", "placeholder",
                              "autocomplete", "required") if f.get(k) not in ("", False)}


def _abs_action(base, action):
    if not action:
        return base
    try:
        return urljoin(base, action)
    except Exception:
        return action


def detect(html_text: str, base_url: str = "") -> dict:
    """Parse one page's HTML and return its authentication surface (no network)."""
    p = _FormParser()
    try:
        p.feed(html_text or "")
    except Exception as exc:
        print(f"[en_forms] parse error: {exc}", file=sys.stderr)

    out = {"login": [], "register": [], "password_reset": [], "other": []}
    for form in p.forms:
        kind, conf, signals = _classify(form)
        action_abs = _abs_action(base_url, form["action"])
        rec = {
            "kind": kind, "confidence": round(conf, 2),
            "action": action_abs, "method": form["method"].upper(),
            "signals": signals,
            "fields": [_field_public(f) for f in form["fields"]],
            "submit_labels": [html.unescape(s).strip() for s in form["submit_labels"] if s and s.strip()],
        }
        if _off_host(base_url, action_abs):
            rec["action_is_offsite"] = True
        out.setdefault(kind, []).append(rec)

    # auth links (for the one-hop crawl + as leads)
    reg_links, login_links = [], []
    for href, text in p.links:
        hay = (href + " " + text).lower()
        target = _abs_action(base_url, href)
        if _has(REGISTER_LINKS, hay) and target not in reg_links:
            reg_links.append(target)
        elif _has(LOGIN_LINKS, hay) and target not in login_links:
            login_links.append(target)

    orphan_pw = any(f["type"] == "password" or _has(PASSWORD, f["_hay"]) for f in p.orphan_fields)

    return {
        "forms": out,
        "register_links": reg_links[:8],
        "login_links": login_links[:8],
        "captcha": sorted(p.captcha_hits),
        "orphan_password_field": orphan_pw,
        "n_forms": len(p.forms),
    }


def _off_host(base, target):
    try:
        b, t = urlparse(base).netloc.lower(), urlparse(target).netloc.lower()
        return bool(b) and bool(t) and b.split(":")[0] != t.split(":")[0]
    except Exception:
        return False


def _looks_spa(html_text: str) -> bool:
    h = (html_text or "").lower()
    return any(m in h for m in ("__next_data__", "window.__nuxt", "ng-version", "id=\"root\"",
                                "id=\"app\"", "data-reactroot", "vue", "react", "reactdom",
                                "__initial_state__", "webpack", "createreactapp", "svelte",
                                "ng-app", "data-v-app", "window.__"))


def _auth_words_in_text(html_text: str) -> bool:
    """Does the page's text carry login/register wording (any language in the reference) even
    though no <form> was found? On an SPA the auth surface is a JS route: the words are in the
    nav, but the form is only built after render. This is the tell that 'no form in static HTML'
    means 'render the auth route', not 'this site has no login'."""
    h = (html_text or "").lower()
    return any(t in h for t in LOGIN_TERMS + REGISTER_TERMS)


# --- build the full result (fetch + one-hop crawl + engagement plan) ----------------------------
def analyze(target: str, *, crawl: bool = True, proxy: str = None) -> dict:
    timeout = int(TH.get("fetch_timeout_s", 20))
    is_url = target.startswith("http://") or target.startswith("https://")
    pages = {}
    if is_url:
        final, status, body = _fetch(target, timeout, proxy)
        base = final or target
        pages[base] = {"status": status, "html": body}
    elif target == "-":
        body = sys.stdin.read()
        base, status = "", 0
        pages[""] = {"status": 0, "html": body}
    else:
        with open(target, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        base, status = "", 0
        pages[target] = {"status": 0, "html": body}

    primary = detect(pages[base if is_url else list(pages)[0]]["html"],
                     base if is_url else "")

    # merge across the entry page + one hop to register/login
    merged = {"login": list(primary["forms"]["login"]),
              "register": list(primary["forms"]["register"]),
              "password_reset": list(primary["forms"]["password_reset"])}
    captcha = set(primary["captcha"])
    followed = []
    if is_url and crawl and int(TH.get("crawl_register_hops", 1)) > 0:
        hop_targets = []
        if not merged["register"]:
            hop_targets += primary["register_links"][:1]
        if not merged["login"]:
            hop_targets += primary["login_links"][:1]
        for hop in dict.fromkeys(hop_targets):
            if _off_host(base, hop):
                continue
            f2, s2, b2 = _fetch(hop, timeout, proxy)
            if not b2:
                continue
            d2 = detect(b2, f2 or hop)
            followed.append({"url": f2 or hop, "status": s2,
                             "found": {k: len(v) for k, v in d2["forms"].items() if v}})
            for k in ("login", "register", "password_reset"):
                merged[k].extend(d2["forms"][k])
            captcha |= set(d2["captcha"])

    page_html = pages[base if is_url else list(pages)[0]]["html"]
    return _finish(target, base, status, primary, merged, sorted(captcha), followed,
                   spa=_looks_spa(page_html), auth_hint=_auth_words_in_text(page_html),
                   proxy=proxy)


def _finish(target, base, status, primary, merged, captcha, followed, *, spa, proxy, auth_hint=False):
    login = _dedup(merged["login"])
    register = _dedup(merged["register"])
    reset = _dedup(merged["password_reset"])

    pivots = []
    for rec in login + register:
        if rec.get("action") and rec["action"] != base:
            pivots.append({"kind": "auth_endpoint", "value": rec["action"],
                           "note": "form POST target" + (" (off-site backend/API)"
                                                         if rec.get("action_is_offsite") else "")})
    # referral params seen anywhere → clustering pivot / closed-funnel tell
    for rec in register + login:
        for f in rec["fields"]:
            hay = (f.get("name", "") + f.get("id", "") + f.get("placeholder", "")).lower()
            if any(t in hay for t in REFERRAL):
                pivots.append({"kind": "referral_field", "value": f.get("name") or f.get("id"),
                               "note": "invite/referral code — closed-funnel tell + cluster pivot"})
    pivots = _dedup_pivots(pivots)

    # engagement plan — what en_engage would need, and what blocks it
    blockers = []
    if captcha:
        blockers.append("captcha:" + ",".join(captcha))
    req_fields = []
    if register:
        best = max(register, key=lambda r: r["confidence"])
        for f in best["fields"]:
            hay = (f.get("name", "") + f.get("id", "") + f.get("placeholder", "")).lower()
            if any(t in hay for t in OTP) and not any(t in hay for t in REFERRAL):
                blockers.append("verification:otp_field")
            if f.get("type") not in ("checkbox", "hidden"):
                req_fields.append({"name": f.get("name") or f.get("id"), "type": f.get("type"),
                                   "required": f.get("required", False)})
    registerable = bool(register) and "captcha" not in " ".join(blockers)

    result = {
        "meta": {
            "tool": "en_forms", "target": target, "final_url": base or None,
            "http_status": status or None, "via_proxy": bool(proxy),
        },
        "auth_surface": {
            "login": login, "register": register, "password_reset": reset,
            "login_links": primary["login_links"], "register_links": primary["register_links"],
            "captcha": captcha, "followed": followed,
        },
        "pivots": pivots,
        "engagement_plan": {
            "registerable": registerable,
            "required_fields": req_fields,
            "blockers": sorted(set(blockers)),
            "note": _plan_note(login, register, blockers, spa, primary, auth_hint),
            "next": ("mint a synthetic identity (en_persona.py) then run the GATED en_engage.py "
                     "--preflight — engagement is outbound/attributable/irreversible and needs "
                     "explicit confirmation + non-attributable egress"),
        },
    }
    return result


def _plan_note(login, register, blockers, spa, primary, auth_hint=False):
    if not (login or register):
        if spa or auth_hint or primary["login_links"] or primary["register_links"] or primary["orphan_password_field"]:
            why = []
            if spa:
                why.append("JS-rendered app")
            if auth_hint:
                why.append("login/register wording in the page text but no <form>")
            if primary["login_links"] or primary["register_links"]:
                why.append("auth links present")
            if primary["orphan_password_field"]:
                why.append("a stray password field")
            return ("No auth form in the STATIC HTML, but this IS an auth surface (" +
                    "; ".join(why) + "). The login/register form is a CLIENT-SIDE ROUTE built "
                    "only after render. Get the route from WebPivot's SPA route table "
                    "(spa_route:* — typically /auth, /login, /register, /dang-nhap) or "
                    "`pivot_extract --render`, then run detection on the RENDERED auth route. "
                    "Absence in static HTML is not absence on the page.")
        return "No login or registration form detected on this page."
    parts = []
    if login and not register:
        parts.append("Login form found; no signup form on the reachable pages — look for an "
                     "invite-only registration or an existing/leaked credential (try_first).")
    if register:
        parts.append("Registration form found.")
    if blockers:
        parts.append("Blockers present — a synthetic signup cannot pass these automatically: "
                     + "; ".join(sorted(set(blockers))) + ". The tool never solves or evades them.")
    return " ".join(parts)


def _dedup(recs):
    seen, out = set(), []
    for r in sorted(recs, key=lambda x: -x["confidence"]):
        key = (r["kind"], r["action"], tuple(sorted(f.get("name", "") for f in r["fields"])))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _dedup_pivots(pivots):
    seen, out = set(), []
    for p in pivots:
        key = (p["kind"], p["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


# --- CLI ----------------------------------------------------------------------------------------
def _leads(result: dict) -> str:
    m, a, plan = result["meta"], result["auth_surface"], result["engagement_plan"]
    lines = [f"# Auth surface — {m.get('final_url') or m.get('target')}"]
    if m.get("http_status"):
        lines.append(f"  HTTP {m['http_status']}" + ("  (via proxy)" if m["via_proxy"] else ""))
    for kind in ("login", "register", "password_reset"):
        for r in a[kind]:
            fset = ", ".join(f.get("name") or f.get("type") for f in r["fields"]) or "(no visible fields)"
            lines.append(f"  [{kind.upper()} {r['confidence']:.2f}] {r['method']} {r['action']}")
            lines.append(f"      fields: {fset}")
            if r.get("signals"):
                lines.append(f"      signals: {', '.join(r['signals'])}")
    if a["captcha"]:
        lines.append(f"  CAPTCHA: {', '.join(a['captcha'])}  (blocks automated signup)")
    if not (a["login"] or a["register"]):
        lines.append("  (no auth form in static HTML)")
    if result["pivots"]:
        lines.append("\n# Pivots")
        for p in result["pivots"]:
            lines.append(f"  {p['kind']}: {p['value']}  — {p.get('note', '')}")
    lines.append("\n# Engagement plan")
    lines.append(f"  registerable: {plan['registerable']}")
    if plan["blockers"]:
        lines.append(f"  blockers: {', '.join(plan['blockers'])}")
    if plan["required_fields"]:
        req = ", ".join(f"{f['name']}({f['type']}{'*' if f['required'] else ''})"
                        for f in plan["required_fields"])
        lines.append(f"  register needs: {req}")
    lines.append(f"  note: {plan['note']}")
    lines.append(f"  next: {plan['next']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Detect a site's login / password / registration forms.")
    ap.add_argument("target", help="URL, path to saved HTML, or - for stdin")
    ap.add_argument("-o", "--out", help="write JSON here")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("--leads", action="store_true", help="human-readable summary instead of JSON")
    ap.add_argument("--no-crawl", action="store_true", help="do not follow the register/login hop")
    ap.add_argument("--proxy", help="route the fetch through this proxy (research egress)")
    args = ap.parse_args(argv)

    result = analyze(args.target, crawl=not args.no_crawl, proxy=args.proxy)

    if args.leads:
        print(_leads(result))
    else:
        blob = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(blob)
            print(f"wrote {args.out}", file=sys.stderr)
            print(_leads(result))
        else:
            print(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
