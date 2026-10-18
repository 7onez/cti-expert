#!/usr/bin/env python3
"""wp_certkit — CertKit (app.certkit.io) Discovery: a CT search export, ~1 year, expired included.

CertKit has NO API for Discovery, so this logs in with the analyst's own web account
(CERTKIT_EMAIL / CERTKIT_PASSWORD in the skill .env), then downloads the Discovery CSV export:

    GET /login                      → antiforgery token
    POST /login                     → session cookie, redirect to /app/<collection-id>
    GET /app/<id>/discovery?search=<d>&excludeExpired=false&handler=Export → one CSV

FRAGILE BY NATURE — it scrapes a web session. MFA on the account, a renamed form field or a changed
redirect breaks it; every such case returns `failed` with the reason (`mfa`, `form-changed`,
`credentials-rejected`), never an empty listing. The session (cookies + collection id) is cached
under the gitignored MEMORY/ (0600) for `session_ttl_seconds`, so per-host collector subprocesses do
not log in once each. Dates are DAY-ONLY (wp_ct never merges such rows on dates); serials are real
x509 serials in hex. Free: no credits; recorded to the usage ledger at 0 for visibility.

Returns the wp_ct source shape: {'source':'certkit','status','rows','n','errors'}. Never raises.
"""
import csv
import http.cookiejar
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import DEFAULT_UA, _secret  # noqa: E402
from wp_refs import ref_path, load_ref  # noqa: E402

try:
    import api_usage
except Exception:  # noqa: BLE001
    api_usage = None

_FALLBACK = {"certkit": {"base_url": "https://app.certkit.io", "login_path": "/login",
                         "request_timeout_seconds": 60, "session_ttl_seconds": 3600}}
CFG = load_ref(ref_path(__file__, "ct_sources.json"), _FALLBACK)["certkit"]
_ENGINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_APP = re.compile(r"/app/([A-Za-z0-9_-]+)")
_TOKEN = re.compile(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"')


def certkit_configured():
    return bool(_secret("CERTKIT_EMAIL") and _secret("CERTKIT_PASSWORD"))


def _session_path():
    return os.environ.get("CERTKIT_SESSION_STATE") or os.path.join(_ENGINE, "MEMORY",
                                                                   "certkit_session.json")


def _opener(jar):
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", DEFAULT_UA)]
    return op


def _load_session():
    """(jar, collection_id) from the cache when still fresh, else (None, None)."""
    try:
        with open(_session_path(), encoding="utf-8") as f:
            doc = json.load(f)
        if doc.get("email") != _secret("CERTKIT_EMAIL") or time.time() - doc["at"] > CFG["session_ttl_seconds"]:
            return None, None
        jar = http.cookiejar.CookieJar()
        for c in doc["cookies"]:
            jar.set_cookie(http.cookiejar.Cookie(
                0, c["name"], c["value"], None, False, c["domain"], True, c["domain"].startswith("."),
                c["path"], True, c["secure"], None, False, None, None, {}))
        return jar, doc["collection"]
    except Exception:  # noqa: BLE001 — a missing/stale cache just means log in again
        return None, None


def _save_session(jar, collection):
    path = _session_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        doc = {"at": time.time(), "email": _secret("CERTKIT_EMAIL"), "collection": collection,
               "cookies": [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path,
                            "secure": c.secure} for c in jar]}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
    except Exception:  # noqa: BLE001
        pass


def _drop_session():
    try:
        os.remove(_session_path())
    except OSError:
        pass


def login():
    """Fresh web login → (jar, collection_id, None) or (None, None, reason)."""
    base, to = CFG["base_url"], CFG["request_timeout_seconds"]
    jar = http.cookiejar.CookieJar()
    op = _opener(jar)
    url = base + CFG["login_path"]
    try:
        with op.open(url, timeout=to) as r:
            page = r.read().decode("utf-8", "replace")
        tok = _TOKEN.search(page)
        if not tok or 'name="email"' not in page or 'name="password"' not in page:
            return None, None, "form-changed: login form fields not found"
        data = urllib.parse.urlencode({"returnUrl": "/", "email": _secret("CERTKIT_EMAIL"),
                                       "password": _secret("CERTKIT_PASSWORD"),
                                       "__RequestVerificationToken": tok.group(1)}).encode()
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded", "Referer": url})
        with op.open(req, timeout=to) as r:
            final, body = r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, None, f"login HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, None, f"login {type(e).__name__}: {e}"[:160]
    path = urllib.parse.urlparse(final).path.lower()
    if re.search(r"2fa|mfa|two-?factor|authenticator", path):
        return None, None, "mfa: the account requires a second factor (disable MFA for this account)"
    m = _APP.search(urllib.parse.urlparse(final).path)
    if not m:
        if 'name="password"' in body:
            return None, None, "credentials-rejected: still on the login form"
        return None, None, f"form-changed: unexpected post-login page {path}"
    _save_session(jar, m.group(1))
    return jar, m.group(1), None


def _export(jar, collection, domain):
    url = (f"{CFG['base_url']}/app/{collection}/discovery?"
           + urllib.parse.urlencode({"search": domain, "excludeExpired": "false", "handler": "Export"}))
    with _opener(jar).open(url, timeout=CFG["request_timeout_seconds"]) as r:
        ctype = r.headers.get("Content-Type") or ""
        body = r.read().decode("utf-8-sig", "replace")
    if "csv" not in ctype.lower():
        raise PermissionError("session expired (export answered HTML, not CSV)")
    return body


def parse_csv(body):
    """Discovery CSV → list of dicts (the export's own column names)."""
    return [row for row in csv.DictReader(io.StringIO(body)) if row]


def certkit_fetch(domain):
    """The Discovery export for `domain` → wp_ct source result. Names are filtered to `domain` and
    its subdomains (Discovery's search is a substring match)."""
    import wp_ct  # noqa: PLC0415 — wp_ct imports this module lazily; avoid the cycle at import time
    out = {"source": "certkit", "window": wp_ct.WINDOWS.get("certkit"), "rows": [], "errors": []}
    if not certkit_configured():
        out.update(status="skipped-no-key", n=0)
        return out
    jar, coll = _load_session()
    body, err = None, None
    for fresh in ((False, True) if jar else (True,)):
        if fresh:
            jar, coll, err = login()
            if err:
                break
        try:
            body = _export(jar, coll, domain)
            break
        except PermissionError as e:
            _drop_session()
            err = str(e)
        except urllib.error.HTTPError as e:
            err = f"export HTTP {e.code}"
            break
        except Exception as e:  # noqa: BLE001
            err = f"export {type(e).__name__}: {e}"[:160]
            break
    if body is None:
        out["errors"].append(err or "export failed")
        out.update(status="failed", n=0)
        if api_usage:
            api_usage.record("certkit", "discovery_export", credits=0, query=domain, ok=False)
        return out
    dom = domain.lower()
    for row in parse_csv(body):
        names = [n.strip().lower() for n in re.split(r"[;,]", row.get("SANs") or "") if n.strip()]
        names += [(row.get("Common Name") or "").strip().lower()]
        names = [n for n in dict.fromkeys(names)
                 if n and (n.lstrip("*.") == dom or n.lstrip("*.").endswith("." + dom))]
        if not names:
            continue
        out["rows"].append(wp_ct._cert(
            "certkit", serial=row.get("Serial Number"),
            issuer=row.get("Issuer Common Name") or row.get("Issuer Organization"),
            common_name=(row.get("Common Name") or "").strip().lower() or None, names=names,
            not_before=row.get("Not Before"), not_after=row.get("Not After")))
    out["status"] = "complete"
    out["n"] = len(wp_ct.dedup_certs(out["rows"]))
    if api_usage:
        api_usage.record("certkit", "discovery_export", credits=0, query=domain, results=out["n"])
    return out


if __name__ == "__main__":
    r = certkit_fetch(sys.argv[1] if len(sys.argv) > 1 else "example.com")
    print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=2))
    for c in r["rows"][:5]:
        print(c["not_before"], c["serial"], c["issuer_cn"], c["names"][:3])
