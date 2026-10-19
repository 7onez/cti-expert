#!/usr/bin/env python3
"""osint_industries.py — OSINT Industries v2 account-existence lookup for one strong selector.

Selector types: email, phone (E.164), username, name, wallet. One POST to
`api.osint.industries/v2/request` (`api-key` header, OSINT_INDUSTRIES_API_KEY) runs the vendor's
module set against the selector and returns, per platform, whether an account is registered plus
whatever that platform exposes: display name, username, id, profile URL, dates, masked email/phone
hints, HIBP breach rows and WHOIS rows (Whoxy) for an email.

Cost: 1 credit per lookup, +3 when `--premium` and a premium module applies. `credits` is free.
Every billed call is ledgered through api_usage.record (provider `osintindustries`).

Attribution rail (SKILL.md RULE 5). A module hit says an account EXISTS for this selector today.
It does not say who registered it, or when. Display names are self-declared, and masked hints are
tail-character comparisons that are not identity evidence in either direction. Results are leads
and corroboration only. Never use them to link two domains, never use one to name an operator,
and never pivot to the current holders of a number. Nothing here writes to the KB.

Spend and memo:
  --free-only / CTI_FREE_ONLY=1 → HELD, no request.
  No key                        → NOT CONSULTED, no request.
  --case <id|dir>               → the raw response is saved to cases/<id>/osint_industries/
                                   <type>_<selector>.json. A later call for the same selector
                                   reads that file instead of buying the lookup again (--refresh
                                   overrides). INTEL_CASE is set so the ledger row is case-scoped.

Tri-state, never raises: lookup() returns {"status": "ok", …}, {"status": "HELD …"} /
{"status": "NOT CONSULTED …"} / {"status": "skipped", …}, or {"status": "unavailable", "error"}.

CLI:
  osint_industries.py email registrant@example.com --case CASE-0001
  osint_industries.py phone +61400000000 --pretty
  osint_industries.py name "Registrant Name" --no-exact-match
  osint_industries.py credits
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, "..", ".."))
WP = os.path.join(SKILL, "intel_engine", "WebPivot", "tools")
sys.path.insert(0, HERE)
import keyed_feeds  # noqa: E402 — .env loader, secret lookup, key scrubbing, api_usage ledger

# --- reference DATA (RULE 3): the fallback is the conservative minimum — the documented
#     endpoints and defaults, the five documented types and the caveat line.
_OI_FALLBACK = {
    "settings": {"ua": "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
                 "timeout_seconds": 60, "timeout_min": 25, "timeout_max": 80,
                 "socket_grace_seconds": 40, "max_modules": 60},
    "endpoints": {"base": "https://api.osint.industries", "request": "/v2/request",
                  "credits": "/misc/credits"},
    "types": ["email", "phone", "username", "name", "wallet"],
    "status_reasons": {"401": "OSINT Industries rejected the key", "402": "out of credits"},
    "caveat": {"text": "A hit means an account exists for this selector today. Display names are "
                       "self-declared; masked hints are not identity evidence in either direction."},
}


def _load_refs():
    try:
        if WP not in sys.path:
            sys.path.insert(0, WP)
        from wp_refs import load_ref, ref_path  # noqa: E402
        return load_ref(ref_path(__file__, "osint_industries.json"), _OI_FALLBACK)
    except Exception:  # noqa: BLE001 — loader missing: the conservative minimum, loudly
        print("[!] osint_industries.json not loaded — using the embedded minimum", file=sys.stderr)
        return dict(_OI_FALLBACK)


_REFS = _load_refs()
SETTINGS = _REFS["settings"]
ENDPOINTS = _REFS["endpoints"]
TYPES = list(_REFS["types"])
STATUS_REASONS = {str(k): v for k, v in (_REFS.get("status_reasons") or {}).items()}
CAVEAT = str((_REFS.get("caveat") or {}).get("text") or _OI_FALLBACK["caveat"]["text"])
UA = SETTINGS.get("ua") or _OI_FALLBACK["settings"]["ua"]
MAX_MODULES = int(SETTINGS.get("max_modules") or 60)
_MAX_BODY = 16 * 1024 * 1024        # a name search returns ~100 KB; never truncate valid JSON

EMAIL_RE = re.compile(r"^[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ().-]{6,20}$")
_PROFILE_KEYS = ("name", "first_name", "last_name", "username", "id", "profile_url", "location",
                 "creation_date", "last_seen", "email", "phone", "email_hint", "phone_hint",
                 "website", "gender", "language", "verified", "private")


def oi_key():
    return keyed_feeds.secret("OSINT_INDUSTRIES_API_KEY")


def no_spend(flag=False):
    v = (os.environ.get("CTI_FREE_ONLY") or "").strip().lower()
    return bool(flag) or v in ("1", "true", "yes")


def guess_type(selector):
    """email / phone / username. A person name or a wallet must be typed explicitly: guessing
    `name` from a two-word string would silently buy a namesake flood."""
    s = (selector or "").strip()
    if EMAIL_RE.match(s):
        return "email"
    if PHONE_RE.match(s) and sum(c.isdigit() for c in s) >= 7 and (s.startswith("+") or s.isdigit()):
        return "phone"
    if s and " " not in s:
        return "username"
    return ""


def normalize_query(typ, selector):
    s = (selector or "").strip()
    if typ == "phone":
        digits = re.sub(r"[^0-9]", "", s)
        return ("+" + digits) if digits else ""
    if typ == "email":
        return s.lower()
    if typ == "username":
        return s.lstrip("@")
    return s


def _clamp_timeout(t):
    lo = int(SETTINGS.get("timeout_min") or 25)
    hi = int(SETTINGS.get("timeout_max") or 80)
    t = int(t or SETTINGS.get("timeout_seconds") or 60)
    return max(lo, min(hi, t))


def _http(method, path, key, body=None, timeout=60):
    """(status, data | None, error | None). Never raises; the key is scrubbed from any error."""
    url = ENDPOINTS["base"].rstrip("/") + path
    headers = {"api-key": key, "accept": "application/json", "User-Agent": UA}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.getcode(), r.read(_MAX_BODY)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(4000)
        except Exception:  # noqa: BLE001
            raw = b""
        reason = STATUS_REASONS.get(str(e.code)) or ""
        detail = keyed_feeds._scrub(raw.decode("utf-8", "replace"), key)[:200]
        return e.code, None, f"HTTP {e.code}" + (f" — {reason}" if reason else "") + (
            f": {detail}" if detail and not reason else "")
    except Exception as e:  # noqa: BLE001 — network / timeout
        return 0, None, type(e).__name__ + ": " + keyed_feeds._scrub(e, key)
    try:
        return status, json.loads(raw.decode("utf-8", "replace") or "null"), None
    except ValueError:
        return status, None, "response was not JSON"


def credits():
    """Remaining credit balance. Free (not ledgered as spend). The endpoint answers a bare integer
    in practice and `{"credits": N}` per the docs; both are read."""
    key = oi_key()
    if not key:
        return {"status": "NOT CONSULTED — no OSINT_INDUSTRIES_API_KEY set"}
    status, data, err = _http("GET", ENDPOINTS["credits"], key, timeout=30)
    if err:
        return {"status": "unavailable", "error": err}
    if isinstance(data, dict):
        data = data.get("credits")
    return {"status": "ok", "credits": data if isinstance(data, (int, float)) else None}


# ------------------------------------------------------------------------------- normaliser
def _spec_value(spec, k):
    v = spec.get(k)
    if isinstance(v, dict) and "value" in v:
        return v.get("value")
    return None


def _platform_vars(spec):
    out = {}
    for p in spec.get("platform_variables") or []:
        if not isinstance(p, dict):
            continue
        v = p.get("value")
        if v in (None, "", [], {}) or isinstance(v, (dict, list)):
            continue
        out[str(p.get("key"))] = v
    return out


def normalize(rows):
    """Raw module list → {accounts: [...], breaches: [...], whois: [...]}, empties dropped.

    One row per spec_format entry, because one module can return several accounts (a name search
    returns every namesake). A breach spec (`breach: true`) becomes a breach row; a `whoxy` spec
    becomes a WHOIS row; everything else is an account row."""
    accounts, breaches, whois = [], [], []
    for m in rows if isinstance(rows, list) else []:
        if not isinstance(m, dict):
            continue
        module = str(m.get("module") or "?")
        for spec in m.get("spec_format") or [{}]:
            if not isinstance(spec, dict):
                continue
            pv = _platform_vars(spec)
            if _spec_value(spec, "breach") is True:
                breaches.append({k: v for k, v in {
                    "source": module, "title": pv.get("title") or _spec_value(spec, "name"),
                    "domain": _spec_value(spec, "website"),
                    "breach_date": pv.get("breach_date") or _spec_value(spec, "creation_date"),
                    "data_classes": pv.get("data_classes"),
                    "pwn_count": pv.get("breach_count")}.items() if v not in (None, "")})
                continue
            if module == "whoxy":
                whois.append({k: v for k, v in {
                    "domain": pv.get("domain_name") or _spec_value(spec, "website"),
                    "registration_date": pv.get("registration_date"),
                    "registrar": pv.get("registrar"), "updated": pv.get("updated"),
                    "expiry": pv.get("expiry")}.items() if v not in (None, "")})
                continue
            row = {"module": module}
            for k in _PROFILE_KEYS:
                v = _spec_value(spec, k)
                if v not in (None, "", [], {}):
                    row[k] = v
            for k, v in pv.items():
                if k not in row and len(str(v)) <= 200:
                    row[k] = v
            cat = m.get("category")
            cat = cat.get("name") if isinstance(cat, dict) else cat
            if cat:
                row["category"] = cat
            accounts.append(row)
    return {"accounts": accounts[:MAX_MODULES], "breaches": breaches[:MAX_MODULES],
            "whois": whois[:MAX_MODULES], "accounts_total": len(accounts)}


# ------------------------------------------------------------------------------- case memo
def _case_dir(case):
    if not case:
        return None
    c = str(case)
    if os.path.isabs(c) or os.sep in c:
        return os.path.normpath(c)
    home = os.environ.get("INTEL_HOME") or os.path.join(SKILL, "intel_engine")
    return os.path.join(home, "cases", c)


def memo_path(case_dir, typ, query):
    slug = re.sub(r"[^A-Za-z0-9._+-]", "_", f"{typ}_{query}")[:180]
    return os.path.join(case_dir, "osint_industries", slug + ".json")


def _memo_read(path, typ, query, premium):
    try:
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
    except (OSError, ValueError):
        return None
    q = rec.get("query") or {}
    if rec.get("http_status") != 200 or q.get("type") != typ or q.get("query") != query:
        return None
    if premium and not q.get("premium"):
        return None                     # a standard-module memo does not answer a premium ask
    return rec


def _memo_write(path, rec):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# ------------------------------------------------------------------------------- lookup
def _summary(typ, query, rec, source):
    norm = normalize(rec.get("results"))
    return {"status": "ok", "type": typ, "query": query, "source": source,
            "fetched_at": rec.get("fetched_at"), "premium": bool((rec.get("query") or {}).get("premium")),
            "hits": norm["accounts_total"] + len(norm["breaches"]) + len(norm["whois"]),
            **norm, "caveat": CAVEAT}


def lookup(typ, selector, *, timeout=None, premium=False, exact_match=True, case=None,
           refresh=False, free_only=False):
    typ = (typ or "").strip().lower() or guess_type(selector)
    if typ not in TYPES:
        return {"status": "skipped", "skipped": f"unsupported selector type {typ!r} "
                f"(one of {', '.join(TYPES)}; a person name or wallet must be typed explicitly)"}
    query = normalize_query(typ, selector)
    if not query:
        return {"status": "skipped", "skipped": "empty selector", "type": typ}
    cdir = _case_dir(case)
    path = memo_path(cdir, typ, query) if cdir else None
    if path and not refresh:
        rec = _memo_read(path, typ, query, premium)
        if rec:
            return _summary(typ, query, rec, "case memo (not re-bought)")
    if no_spend(free_only):
        return {"status": "HELD — free-only (1 credit per lookup)", "type": typ, "query": query}
    key = oi_key()
    if not key:
        return {"status": "NOT CONSULTED — no OSINT_INDUSTRIES_API_KEY set", "type": typ, "query": query}
    if cdir:
        os.environ.setdefault("INTEL_CASE", os.path.basename(os.path.normpath(cdir)))
    t = _clamp_timeout(timeout)
    body = {"type": typ, "query": query, "timeout": t, "premium": bool(premium)}
    if typ == "name":
        body["exact_match"] = bool(exact_match)
    t0 = time.time()
    status, data, err = _http("POST", ENDPOINTS["request"], key, body=body,
                              timeout=t + int(SETTINGS.get("socket_grace_seconds") or 40))
    ok = status == 200 and err is None and isinstance(data, list)
    n = len(data) if isinstance(data, list) else None
    keyed_feeds._ledger("osintindustries", f"request:{typ}", query, results=n, ok=ok)
    if not ok:
        return {"status": "unavailable", "type": typ, "query": query, "http_status": status,
                "error": err or "response was not a module list"}
    rec = {"query": body, "http_status": status,
           "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "elapsed_s": round(time.time() - t0, 1), "results": data}
    if path:
        _memo_write(path, rec)
    out = _summary(typ, query, rec, "live")
    if path:
        out["saved"] = path
    return out


def main():
    ap = argparse.ArgumentParser(description="OSINT Industries v2 account-existence lookup "
                                             "(1 credit; `credits` is free).")
    ap.add_argument("type", help=f"{'|'.join(TYPES)}|auto|credits")
    ap.add_argument("selector", nargs="?", default="")
    ap.add_argument("--premium", action="store_true", help="include premium modules (+3 credits)")
    ap.add_argument("--timeout", type=int, help="module deadline sent to the API (25-80 s)")
    ap.add_argument("--no-exact-match", action="store_true", help="name search: loose matches too")
    ap.add_argument("--case", help="case id or dir: save the raw response and reuse it")
    ap.add_argument("--refresh", action="store_true", help="ignore the case memo and buy again")
    ap.add_argument("--free-only", action="store_true", help="send nothing (HELD)")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    keyed_feeds.load_keys()
    if a.type == "credits":
        out = credits()
    else:
        if not a.selector:
            ap.error("selector is required")
        out = lookup("" if a.type == "auto" else a.type, a.selector, timeout=a.timeout,
                     premium=a.premium, exact_match=not a.no_exact_match, case=a.case,
                     refresh=a.refresh, free_only=a.free_only)
    print(json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False))
    return 1 if str(out.get("status", "")).startswith("unavailable") else 0


if __name__ == "__main__":
    sys.exit(main())
