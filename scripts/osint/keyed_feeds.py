#!/usr/bin/env python3
"""keyed_feeds.py — the keys .env held that no collector sent.

abuse.ch (Auth-Key header, required since 2024), Hudson Rock Cavalier v3
(`api-key` header on api.hudsonrock.com), ZoneCruncher/ZETAlytics
(`token` query param on zonecruncher.com/api/v2), and the Spamhaus Intelligence API
(username/password -> 24 h bearer token, cached on disk so a run never logs in per query —
Spamhaus penalises that). Keyless callers get NOT CONSULTED and make no request. A present key
is attached on every call.

Stealer passwords and session cookies are stripped before anything is returned.
The token/key is scrubbed out of error strings — urllib puts it in the URL.
"""
# /// script
# requires-python = ">=3.9"
# ///
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, "..", ".."))
UA = "cti-expert/keyed-feeds (OSINT research)"

_LOADED = False
_REDACT = {"password", "pass", "passwd", "pwd", "cookie", "cookies",
           "session", "session_cookie", "employee_session_cookies"}


def _ledger(provider, action, query, *, results=None, ok=True):
    """Record one keyed call in the shared api_usage ledger (AGENTS.md: every metered call is
    ledgered). Case comes from INTEL_CASE (set by deep_profile/the pipeline). Never raises."""
    try:
        wp = os.path.join(SKILL, "intel_engine", "WebPivot", "tools")
        if wp not in sys.path:
            sys.path.append(wp)
        import api_usage  # noqa: E402
        api_usage.record(provider, action, credits=1, query=query, results=results, ok=ok)
    except Exception:  # noqa: BLE001 — the ledger never breaks a lookup
        pass


def load_keys():
    """Env wins. Then the skill-root .env. Never overrides a var already set."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    path = os.environ.get("CTI_API_KEYS_ENV") or os.path.join(SKILL, ".env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and v and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        pass


def secret(*names):
    load_keys()
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def _scrub(text, *extra):
    s = "" if text is None else str(text)
    for sec in extra:
        if sec:
            s = s.replace(sec, "[redacted]")
            s = s.replace(urllib.parse.quote(sec, safe=""), "[redacted]")
    return s[:300]


def redact(obj):
    """Drop stealer passwords and session material. Keep the rest of the hit."""
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items() if str(k).lower() not in _REDACT}
    return obj


def _open(req, timeout, secret_value):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(200000)
            code = r.getcode()
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(4000)
        except Exception:  # noqa: BLE001
            pass
        return code_body(e.code, raw, secret_value)
    except Exception as e:  # noqa: BLE001
        return None, {"error": type(e).__name__ + ": " + _scrub(e, secret_value)}
    return code_body(code, raw, secret_value)


def code_body(code, raw, secret_value):
    text = raw.decode("utf-8", "replace") if raw else ""
    try:
        data = json.loads(text) if text else {}
    except Exception:  # noqa: BLE001
        data = {"raw": _scrub(text, secret_value)}
    if code and code >= 400:
        msg = ""
        if isinstance(data, dict):
            msg = data.get("message") or data.get("error") or data.get("query_status") or ""
        return None, {"error": "HTTP %s%s" % (code, (": " + _scrub(msg, secret_value)) if msg else "")}
    return data, None


def _get(url, headers, timeout, secret_value):
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    return _open(urllib.request.Request(url, headers=h), timeout, secret_value)


def _post(url, body, headers, timeout, secret_value, form=False):
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    if form:
        data = urllib.parse.urlencode(body).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    return _open(urllib.request.Request(url, data=data, headers=h), timeout, secret_value)


def abusech_key():
    return secret("ABUSE_CH_API_KEY", "ABUSECH_API_KEY", "URLHAUS_AUTH_KEY")


def abusech_lookup(ind, kind, timeout=20):
    """URLhaus + ThreatFox (+ MalwareBazaar for a hash). Auth-Key or no request."""
    key = abusech_key()
    if not key:
        return {"status": "NOT CONSULTED — no ABUSE_CH_API_KEY set", "auth": None}
    headers = {"Auth-Key": key}
    out = {"status": "ok", "auth": "Auth-Key", "listed": False, "feeds": {}}
    if kind == "url":
        data, err = _post("https://urlhaus-api.abuse.ch/v1/url/", {"url": ind}, headers, timeout, key, form=True)
        out["feeds"]["urlhaus"] = err or _urlhaus(data)
    elif kind in ("domain", "ip"):
        data, err = _post("https://urlhaus-api.abuse.ch/v1/host/", {"host": ind}, headers, timeout, key, form=True)
        out["feeds"]["urlhaus"] = err or _urlhaus(data)
    elif kind == "hash":
        data, err = _post("https://mb-api.abuse.ch/api/v1/",
                          {"query": "get_info", "hash": ind}, headers, timeout, key, form=True)
        out["feeds"]["malwarebazaar"] = err or _bazaar(data)
    if kind in ("domain", "ip", "url"):
        data, err = _post("https://threatfox-api.abuse.ch/api/v1/",
                          {"query": "search_ioc", "search_term": ind, "exact_match": True},
                          headers, timeout, key, form=False)
        out["feeds"]["threatfox"] = err or _threatfox(data)
    listed = []
    for name, feed in out["feeds"].items():
        if isinstance(feed, dict) and feed.get("listed"):
            listed.append(name)
        if isinstance(feed, dict) and feed.get("error") and feed.get("listed") is not True:
            out.setdefault("errors", []).append("%s: %s" % (name, feed["error"]))
    out["listed"] = bool(listed)
    out["listed_on"] = listed
    if out["feeds"] and all(isinstance(v, dict) and v.get("error") for v in out["feeds"].values()):
        out["status"] = "unavailable"
    return out


def _urlhaus(data):
    if not isinstance(data, dict):
        return {"error": "unparseable"}
    qs = data.get("query_status")
    urls = data.get("urls") or []
    listed = qs in ("is_listed", "listed") or bool(urls)
    return {"query_status": qs, "listed": listed, "url_count": len(urls) if isinstance(urls, list) else 0}


def _threatfox(data):
    if not isinstance(data, dict):
        return {"error": "unparseable"}
    rows = data.get("data") or []
    if isinstance(rows, dict):
        rows = [rows]
    listed = data.get("query_status") == "ok" and bool(rows)
    fams = []
    for row in rows[:5] if isinstance(rows, list) else []:
        fam = row.get("malware_printable") or row.get("malware")
        if fam and fam not in fams:
            fams.append(fam)
    return {"query_status": data.get("query_status"), "listed": listed,
            "hit_count": len(rows) if isinstance(rows, list) else 0, "families": fams}


def _bazaar(data):
    if not isinstance(data, dict):
        return {"error": "unparseable"}
    rows = data.get("data") or []
    listed = data.get("query_status") == "ok" and bool(rows)
    return {"query_status": data.get("query_status"), "listed": listed,
            "hit_count": len(rows) if isinstance(rows, list) else 0}


def hudsonrock_key():
    return secret("HUDSONROCK_API_KEY")


def hudsonrock_lookup(selector, timeout=30):
    """Premium Cavalier v3. Sends `api-key`. No key → no request (the free
    Cavalier host does not accept this key and must not be pretended to)."""
    key = hudsonrock_key()
    if not key:
        return {"status": "NOT CONSULTED — no HUDSONROCK_API_KEY set", "auth": None}
    sel = (selector or "").strip()
    host = sel.split("://", 1)[-1].split("/")[0].split(":")[0].lower()
    if "@" in sel and " " not in sel:
        url = "https://api.hudsonrock.com/json/v3/search-by-login/emails"
        body = {"logins": [sel]}
        kind = "email"
    else:
        url = "https://api.hudsonrock.com/json/v3/search-by-domain"
        body = {"domains": [host]}
        kind = "domain"
    data, err = _post(url, body, {"api-key": key}, timeout, key, form=False)
    if err:
        _ledger("hudsonrock", f"search-by-{kind}", sel, ok=False)
        return {"status": "unavailable", "auth": "api-key", "kind": kind, **err}
    clean = redact(data if isinstance(data, dict) else {"data": data})
    rows = clean.get("data") if isinstance(clean, dict) else None
    if not isinstance(rows, list):
        rows = []
    summary = []
    for row in rows[:15]:
        if not isinstance(row, dict):
            continue
        summary.append({k: row.get(k) for k in
                        ("date_compromised", "date_uploaded", "stealer_family", "stealer",
                         "computer_name", "operating_system", "ip", "employeeAt", "clientAt")
                        if row.get(k)})
    _ledger("hudsonrock", f"search-by-{kind}", sel, results=len(rows))
    return {"status": "ok", "auth": "api-key", "kind": kind, "endpoint": url.split("/json/v3/", 1)[-1],
            "hits": len(rows), "credentials_redacted": True, "records": summary,
            "nextCursor": bool(isinstance(clean, dict) and clean.get("nextCursor"))}


def zonecruncher_key():
    return secret("ZONECRUNCHER_API_KEY")


def zonecruncher_lookup(selector, timeout=25, size=10):
    """Official v2 client auth: `token` query param on zonecruncher.com/api/v2/.
    Email → email_address (reverse registrant/SOA). Anything else → domain2ip."""
    key = zonecruncher_key()
    if not key:
        return {"status": "NOT CONSULTED — no ZONECRUNCHER_API_KEY set", "auth": None}
    sel = (selector or "").strip()
    if "@" in sel and " " not in sel:
        endpoint, q = "email_address", sel
    else:
        endpoint = "domain2ip"
        q = sel.split("://", 1)[-1].split("/")[0].split(":")[0].lower()
    url = ("https://zonecruncher.com/api/v2/%s?q=%s&size=%d&token=%s"
           % (endpoint, urllib.parse.quote(q, safe=""), int(size), urllib.parse.quote(key, safe="")))
    data, err = _get(url, {}, timeout, key)
    if err:
        _ledger("zonecruncher", endpoint, q, ok=False)
        return {"status": "unavailable", "auth": "token", "endpoint": endpoint, **err}
    if isinstance(data, dict) and data.get("error") and not data.get("results"):
        return {"status": "unavailable", "auth": "token", "endpoint": endpoint,
                "error": _scrub(data.get("error") or data.get("message"), key)}
    rows = []
    if isinstance(data, dict):
        rows = data.get("results") or data.get("data") or data.get("records") or []
    elif isinstance(data, list):
        rows = data
    if not isinstance(rows, list):
        rows = []
    domains = []
    for row in rows:
        if isinstance(row, str) and row not in domains:
            domains.append(row)
        elif isinstance(row, dict):
            for field in ("domain", "qname", "value", "rrname", "ip"):
                v = row.get(field)
                if v and v not in domains:
                    domains.append(v)
                    break
    _ledger("zonecruncher", endpoint, q, results=len(rows))
    return {"status": "ok", "auth": "token", "endpoint": endpoint, "q": q,
            "hits": len(rows), "values": domains[:25]}


# ── Spamhaus Intelligence API (SIA) ─────────────────────────────────────────
SPAMHAUS_API = "https://api.spamhaus.org"
_SPAMHAUS_TOKEN_FILE = os.path.join(SKILL, ".spamhaus-token.json")   # gitignored, chmod 600
_SPAMHAUS_REFRESH_S = 600            # re-login this long before the 24 h token expires
_SPAMHAUS_IP_LIMIT = 50              # history rows per IP; a /32 query costs 1 whatever the rows


def spamhaus_creds():
    return (secret("SPAMHAUS_USERNAME", "SPAMHAUS_USER"),
            secret("SPAMHAUS_PASSWORD", "SPAMHAUS_PASS"))


def _spamhaus_token(force=False, timeout=20):
    """(token, None) or (None, error). Reuses the cached token until it is near expiry; a
    different username (rotated account) never reuses another account's token."""
    user, pw = spamhaus_creds()
    if not (user and pw):
        return None, {"error": "no SPAMHAUS_USERNAME/SPAMHAUS_PASSWORD"}
    tag = hashlib.sha256(user.encode()).hexdigest()[:16]
    if not force:
        try:
            with open(_SPAMHAUS_TOKEN_FILE, encoding="utf-8") as f:
                c = json.load(f)
            if (c.get("user") == tag and c.get("token")
                    and int(c.get("expires") or 0) - _SPAMHAUS_REFRESH_S > time.time()):
                return c["token"], None
        except Exception:  # noqa: BLE001 — no/corrupt cache: log in
            pass
    data, err = _post(SPAMHAUS_API + "/api/v1/login",
                      {"username": user, "password": pw, "realm": "intel"}, {}, timeout, pw)
    if err:
        return None, {"error": "login " + err.get("error", "failed")}
    tok = data.get("token") if isinstance(data, dict) else None
    if not tok:
        return None, {"error": "login returned no token"}
    try:
        tmp = _SPAMHAUS_TOKEN_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"user": tag, "token": tok,
                       "expires": int(data.get("expires") or time.time() + 86400)}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _SPAMHAUS_TOKEN_FILE)
    except OSError:
        pass
    return tok, None


def _spamhaus_get(path, timeout):
    """GET with the bearer token; one forced re-login on 401 (expired/revoked token).
    Spamhaus answers "no data" as HTTP 404 {"code":404} — returned as ({}, None), not an error."""
    tok, err = _spamhaus_token(timeout=timeout)
    if err:
        return None, err
    data, err = _get(SPAMHAUS_API + path, {"Authorization": "Bearer " + tok}, timeout, tok)
    if err and str(err.get("error", "")).startswith("HTTP 401"):
        tok, err = _spamhaus_token(force=True, timeout=timeout)
        if err:
            return None, err
        data, err = _get(SPAMHAUS_API + path, {"Authorization": "Bearer " + tok}, timeout, tok)
    if err and str(err.get("error", "")).startswith("HTTP 404"):
        return {}, None
    return data, err


def spamhaus_lookup(ind, kind, timeout=20):
    """IP -> XBL/CSS/BCL listing history (12 months; `active` = still listed). Domain (registrable,
    no www.) -> reputation score, tags, compromised flag, and current DBL listing. 1 SIA query per
    IP, 2 per domain, each ledgered as a COUNT. Developer License = free (no credits; 5,000
    queries/month enforced by the vendor's 429), so like Webamon it is NOT held under --free-only."""
    user, pw = spamhaus_creds()
    if not (user and pw):
        return {"status": "NOT CONSULTED — no SPAMHAUS_USERNAME/SPAMHAUS_PASSWORD set"}
    q = (ind or "").strip()
    if kind == "ip":
        path = ("/api/intel/v1/byobject/cidr/ALL/listed/history/%s?limit=%d"
                % (urllib.parse.quote(q, safe=""), _SPAMHAUS_IP_LIMIT))
        data, err = _spamhaus_get(path, timeout)
        if err:
            _ledger("spamhaus", "ip_history", q, ok=False)
            return {"status": "unavailable", **err}
        rows = data.get("results") if isinstance(data, dict) else None
        rows = rows if isinstance(rows, list) else []
        now = time.time()
        listings = [{"dataset": r.get("dataset"), "listed": r.get("listed"),
                     "valid_until": r.get("valid_until"),
                     "active": int(r.get("valid_until") or 0) > now,
                     "detection": r.get("detection"), "botname": r.get("botname"),
                     "heuristic": r.get("heuristic")} for r in rows if isinstance(r, dict)]
        _ledger("spamhaus", "ip_history", q, results=len(listings))
        return {"status": "ok", "kind": "ip", "history_count": len(listings),
                # measured live: an active C2 hit the row limit — the count is a floor, not a total
                "history_capped": len(listings) >= _SPAMHAUS_IP_LIMIT,
                "active_datasets": sorted({x["dataset"] for x in listings
                                           if x["active"] and x["dataset"]}),
                "listings": listings[:15]}
    if kind == "domain":
        d = urllib.parse.quote(q.lower().rstrip("."), safe="")
        gen, err = _spamhaus_get("/api/intel/v2/byobject/domain/%s" % d, timeout)
        _ledger("spamhaus", "domain", q, ok=not err)
        if err:
            return {"status": "unavailable", **err}
        lst, err2 = _spamhaus_get("/api/intel/v2/byobject/domain/%s/listing" % d, timeout)
        _ledger("spamhaus", "domain_listing", q, ok=not err2)
        gen = gen if isinstance(gen, dict) else {}
        lst = lst if isinstance(lst, dict) else {}
        listed = lst.get("is-listed", lst.get("is_listed"))
        out = {"status": "ok", "kind": "domain", "domain": q, "known": bool(gen),
               "score": gen.get("score"), "tags": gen.get("tags") or [],
               "abused": bool(gen.get("abused")), "last_seen": gen.get("last-seen"),
               "listed": listed is True or str(listed).lower() == "true",
               "listed_until": lst.get("listed-until")}
        if err2:
            out["listing_error"] = err2.get("error")
        return out
    return {"status": "n/a for this indicator type"}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Send a configured key to its vendor. No key → NOT CONSULTED.")
    ap.add_argument("vendor", choices=["abusech", "hudsonrock", "zonecruncher", "spamhaus"])
    ap.add_argument("selector")
    ap.add_argument("--kind", default="", help="abusech/spamhaus: url|domain|ip|hash (default: guess)")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    if a.vendor == "abusech":
        kind = a.kind or ("url" if "://" in a.selector else "hash" if len(a.selector) in (32, 40, 64) else "domain")
        out = abusech_lookup(a.selector, kind)
    elif a.vendor == "spamhaus":
        kind = a.kind or ("ip" if a.selector.replace(".", "").isdigit() else "domain")
        out = spamhaus_lookup(a.selector, kind)
    elif a.vendor == "hudsonrock":
        out = hudsonrock_lookup(a.selector)
    else:
        out = zonecruncher_lookup(a.selector)
    print(json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False))
    return 0 if not str(out.get("status", "")).startswith("unavailable") else 1


if __name__ == "__main__":
    sys.exit(main() or 0)
