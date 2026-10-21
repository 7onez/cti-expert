#!/usr/bin/env python3
"""wp_buckets — the GrayHatWarfare client for WebPivot: open buckets, the shortener corpus, the git corpus.

One GRAYHATWARFARE_API_KEY opens three indexes:
  * buckets    — publicly readable object storage (Amazon S3, Azure Blob, Google Cloud Storage,
                 DigitalOcean Spaces) and the files inside it;
  * shorteners — the long URLs public link shorteners (goo.gl, bit.ly, tinyurl…) expanded to, with the
                 short link and its discovery date. A HISTORICAL corpus (discovery dates 2017–2025;
                 goo.gl stopped resolving in 2025): a hit says the URL existed and was shared, never
                 that it is live;
  * git        — public GitHub/GitLab/Bitbucket repositories: files (TruffleHog secret tags + the
                 commits that held them), committers (author name + e-mail), e-mail domains.

GRADING — collecting is not attributing (rungs.json, CLAUDE.md RULE 5):
  * bucket, bucket-file, shortener and secret-file hits are EXPOSURE / mentions — facts, never edges;
  * a committer whose author e-mail sits on the target's own mail domain is a LEAD (git.committer_email
    -> kit): git author e-mails are unauthenticated, anyone can commit as anyone@domain. Managed mail
    domains (references/grayhatwarfare.json managed_mail_domains) are refused in domain mode — that
    list is millions of strangers. An exact address is always looked up;
  * a repository file that hard-codes the case token is code reuse (git.code -> kit) ONLY after its raw
    file was fetched and the token found in it — the content index tokenises, so an unverified hit is
    a mention.

API facts verified live (2026-10):
  * auth `Authorization: Bearer <key>`; 401 = bad key; 429 above 3 parallel requests (1 for regex);
  * GET grayhatwarfare.com/api/account -> {accountType: free|premium|enterprise, expirationDate} (free);
  * buckets: /api/v2/buckets|files?keywords=&limit=;
  * shorteners: /api/v1/files/{start}/{limit}?keywords=&domains=&ext= ; /subdomains/{start}/{limit}?keywords=
    ; /subdomain/{a,b}/files/{start}/{limit}. `domains` matches the EXACT host only; `keywords` is a
    substring match over the whole URL, query strings included;
  * git: /api/v1/files?keywords|content|remote ; /users?filter|email-domain|remote ; /repositories?filter.
    The documented `repository` filter is IGNORED (it returns the whole index) — the working name is
    `remote`; responses carry remote/remoteId, not repository/repositoryId; repositories?email-domain
    and ?user answer 400/500.
  Every result is therefore post-filtered here to the exact selector it was asked about.

Keyless fallback: the site: dorks (handbook/discovery-paths.md). Never report a keyless run as
"no exposure".
"""
import argparse
import datetime
import json
import os
import re
import sys
import contextlib
import contextvars
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA, _registrable  # noqa: E402 — shared skill-root .env loader + UA
from wp_refs import ref_path, load_ref                   # noqa: E402 — reference DATA (RULE 3)

try:
    import api_usage                        # licensed-API credit ledger (optional)
except Exception:
    api_usage = None

# --- reference DATA. The fallback is the minimum that keeps every mode working and still refuses the
#     biggest shared mail providers if the JSON goes missing.
_GHW_FALLBACK = {
    "endpoints": {"buckets": "https://buckets.grayhatwarfare.com/api/v2",
                  "shorteners": "https://shorteners.grayhatwarfare.com/api/v1",
                  "git": "https://git.grayhatwarfare.com/api/v1",
                  "account": "https://grayhatwarfare.com/api/account",
                  "buckets_ui": "https://buckets.grayhatwarfare.com/buckets/keywords/any/"},
    "limits": {"timeout": 25, "content_timeout": 90, "page_max": 1000, "parallel": 3, "retry_429": 2,
               "retry_sleep": 1.5, "verify_raw": 10, "raw_max_bytes": 2000000,
               "exposure_subdomains": 25, "exposure_urls": 200, "committers": 100, "ingest_rows": 50},
    "handle_hosts": {"telegram": ["t.me", "telegram.me"]},
    "managed_mail_domains": ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
                             "users.noreply.github.com"],
    "raw_hosts": ["github.com", "raw.githubusercontent.com"],
}
_REF = load_ref(ref_path(__file__, "grayhatwarfare.json"), _GHW_FALLBACK)
ENDPOINTS = _REF["endpoints"]
LIMITS = _REF["limits"]
HANDLE_HOSTS = {k: [str(h).lower() for h in v] for k, v in (_REF["handle_hosts"] or {}).items()}
MANAGED_MAIL = frozenset(str(d).lower() for d in _REF["managed_mail_domains"])
RAW_HOSTS = frozenset(str(h).lower() for h in _REF["raw_hosts"])

API_BASE = ENDPOINTS["buckets"]
UI_URL = ENDPOINTS["buckets_ui"]

# Master off switch (e.g. --no-buckets). Only the NETWORK calls honour it; the dorks are free.
ENABLED = True

MEMO_NS = "grayhatwarfare"      # cases/<case>/grayhatwarfare/<sha>.json (wp_casememo): once per case


def _lim(name):
    v = LIMITS.get(name)
    return v if v is not None else _GHW_FALLBACK["limits"][name]


_SLOTS = threading.BoundedSemaphore(max(1, int(_lim("parallel"))))


def ghw_key():
    """The GrayHatWarfare API key, or None."""
    return _secret("GRAYHATWARFARE_API_KEY", "GRAYHAT_API_KEY", "GHW_API_KEY")


def ghw_configured():
    """True when a key is available and GrayHatWarfare isn't switched off."""
    return ENABLED and bool(ghw_key())


def dork(keyword, index="buckets"):
    """The keyless Google/Bing dork that substitutes for the API when no key is set."""
    return f'site:{index}.grayhatwarfare.com "{keyword}"'


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("grayhatwarfare", action, credits=1, query=None,
                             results=results, ok=ok)
        except Exception:
            pass


def _call(service, path, params=None, timeout=None):
    """One GrayHatWarfare API call -> (data, error). Never raises. Holds one of the account's parallel
    slots and backs off on HTTP 429 (the parallel-request cap) before giving up."""
    url = ENDPOINTS[service] + (f"/{path}" if path else "")
    q = {k: v for k, v in (params or {}).items() if v not in (None, "")}
    if q:
        url += "?" + urllib.parse.urlencode(q)
    tries = 1 + max(0, int(_lim("retry_429")))
    for attempt in range(tries):
        try:
            with _SLOTS:
                req = urllib.request.Request(url, headers={
                    "User-Agent": DEFAULT_UA, "Accept": "application/json",
                    "Authorization": f"Bearer {ghw_key()}"})
                with urllib.request.urlopen(req, timeout=timeout or _lim("timeout")) as r:
                    return json.load(r), None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt + 1 < tries:
                time.sleep(float(_lim("retry_sleep")) * (attempt + 1))
                continue
            if e.code == 401:
                return None, {"error": "HTTP 401 — GrayHatWarfare rejected the key"}
            if e.code == 429:
                return None, {"error": "HTTP 429 — GrayHatWarfare parallel-request cap"}
            return None, {"error": f"HTTP {e.code}"}
        except Exception as e:  # noqa: BLE001 — contract: never raise
            return None, {"error": str(e)}
    return None, {"error": "HTTP 429 — GrayHatWarfare parallel-request cap"}


# The case a lookup belongs to. Set per call by case_scope() — never by mutating WP_CASE_DIR, which in
# a long-lived process (MCP server, harness, a loop over cases) may already name ANOTHER case.
_CASE_SCOPE = contextvars.ContextVar("ghw_case_dir", default=None)


@contextlib.contextmanager
def case_scope(case_dir):
    """Memoise every lookup inside the block under `case_dir`'s grayhatwarfare/ memo (restored on
    exit). `case_dir=None` keeps the caller's scope."""
    token = _CASE_SCOPE.set(case_dir) if case_dir else None
    try:
        yield
    finally:
        if token is not None:
            _CASE_SCOPE.reset(token)


def _memo(key, fn):
    """Once per CASE: a repeat lookup reads the case memo instead of re-querying. The case is the
    explicit case_scope() when one is active, else the process WP_CASE_DIR (a collector subprocess
    the pipeline launched for exactly one case). Errors are never frozen (wp_casememo.memoisable)."""
    try:
        import wp_casememo
    except Exception:  # noqa: BLE001
        return fn()
    cdir = _CASE_SCOPE.get()
    hit = wp_casememo.get(MEMO_NS, key, cdir)
    if hit is not None:
        return dict(hit, cached=True) if isinstance(hit, dict) else hit
    val = fn()
    wp_casememo.put(MEMO_NS, key, val, cdir)
    return val


def _keyless(out, keyword, index):
    out["skipped"] = "no GRAYHATWARFARE_API_KEY configured — run the dork by hand (see 'dork')"
    out["dork"] = dork(keyword, index)
    return out


def _iso(ts):
    try:
        return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _host(v):
    v = str(v or "").strip().lower()
    if "://" in v:
        v = urllib.parse.urlparse(v).hostname or ""
    return v.split("/")[0].split(":")[0].rstrip(".")


# ------------------------------------------------------------------------------------------ account
def account(timeout=None):
    """{tier, expires} from the FREE account endpoint; {tier:'unknown', error} on failure; None
    keyless. Spends no search, so it is the entitlement probe."""
    if not ghw_configured():
        return None
    data, err = _call("account", "", None, timeout)
    if err:
        return {"tier": "unknown", **err}
    data = data if isinstance(data, dict) else {}
    tier = str(data.get("accountType") or data.get("type") or "unknown").lower()
    return {"tier": tier, "expires": data.get("expirationDate")}


# ------------------------------------------------------------------------------------------ buckets
def buckets(keyword, limit=20, exact=False, timeout=None):
    """Open buckets whose name matches `keyword` -> {keyword, results, buckets:[...], ui}.
    Keyless -> {keyword, skipped, dork, ui}."""
    out = {"mode": "buckets", "keyword": keyword, "ui": UI_URL + urllib.parse.quote(keyword or "")}
    if not ghw_configured():
        return _keyless(out, keyword, "buckets")

    def _go():
        params = {"keywords": keyword, "limit": limit}
        if exact:
            params["exact"] = "true"
        data, err = _call("buckets", "buckets", params, timeout)
        if err:
            return dict(out, **err)
        rows = [{"id": b.get("id"), "bucket": b.get("bucket"), "fileCount": b.get("fileCount"),
                 "type": b.get("type")} for b in (data.get("buckets") or [])]
        _record("buckets", len(rows), ok=True)
        return dict(out, results=(data.get("meta") or {}).get("results"), buckets=rows)
    return _memo(f"buckets|{keyword}|{limit}|{bool(exact)}", _go)


def files(keyword, limit=20, timeout=None):
    """Exposed bucket files matching `keyword` -> {keyword, results, files:[...]}. Keyless ->
    {keyword, skipped, dork}."""
    out = {"mode": "files", "keyword": keyword}
    if not ghw_configured():
        return _keyless(out, keyword, "buckets")

    def _go():
        data, err = _call("buckets", "files", {"keywords": keyword, "limit": limit}, timeout)
        if err:
            return dict(out, **err)
        rows = [{"filename": f.get("filename") or f.get("fullPath"), "bucket": f.get("bucket"),
                 "size": f.get("size"), "url": f.get("url")} for f in (data.get("files") or [])]
        _record("files", len(rows), ok=True)
        return dict(out, results=(data.get("meta") or {}).get("results"), files=rows)
    return _memo(f"files|{keyword}|{limit}", _go)


# --------------------------------------------------------------------------------------- shorteners
_SHORT_RE = re.compile(r"https?://[^/?#\s]+/[A-Za-z0-9_-]+")


def _clean_short(v):
    """The short link itself. The index stores some goo.gl links mangled as
    `https://goo.gl/?si=1https://goo.gl/<code>?si=1`; the real link is the last `host/<code>`."""
    s = str(v or "")
    found = _SHORT_RE.findall(s)
    return found[-1] if found else (s or None)


def _short_row(u):
    return {"url": u.get("url"), "host": str(u.get("subDomain") or "").lower(),
            "short": _clean_short(u.get("shortUrl")), "ext": u.get("ext"), "mime": u.get("mimeType"),
            "discovered": _iso(u.get("discoveredTimestamp"))}


def short_subdomains(apex, limit=None, timeout=None):
    """Every host under `apex` the shortener corpus saw a short link point at ->
    {apex, results, subdomains:[{host, urls}]} — a subdomain-enumeration source (subdomain_enum)."""
    apex = _registrable(_host(apex)) or _host(apex)
    out = {"mode": "short_subdomains", "apex": apex}
    if not ghw_configured():
        return _keyless(out, apex, "shorteners")
    limit = int(limit or _lim("page_max"))

    def _go():
        data, err = _call("shorteners", f"subdomains/0/{limit}",
                          {"keywords": apex, "order": "count", "direction": "desc"}, timeout)
        if err:
            return dict(out, **err)
        seen = {}
        for s in data.get("subDomains") or []:
            h = str(s.get("subDomain") or "").lower()
            # `keywords` is a substring match: keep only hosts that really sit under the apex. The
            # index can carry one host under two ids — merge them.
            if h == apex or h.endswith("." + apex):
                seen[h] = (seen.get(h) or 0) + int(s.get("urlsCount") or 0)
        rows = [{"host": h, "urls": n} for h, n in sorted(seen.items(), key=lambda kv: -kv[1])]
        _record("short_subdomains", len(rows), ok=True)
        return dict(out, results=len(rows), scanned=data.get("domainsCount"), subdomains=rows)
    return _memo(f"short_subdomains|{apex}|{limit}", _go)


def short_urls(hosts, limit=None, ext=None, timeout=None):
    """Historical long URLs on the EXACT `hosts` (list or comma string) -> {hosts, results, urls:[
    {url, host, short, ext, mime, discovered}]} newest first: hidden paths, documents, invite/ref/
    utm parameters. Feed the persisted list to url_paths(mode='patterns')."""
    if isinstance(hosts, str):
        hosts = hosts.replace(",", " ").split()
    want = []
    for h in hosts or []:
        h = _host(h)
        if h and h not in want:
            want.append(h)
    want = want[:int(_lim("exposure_subdomains"))]
    out = {"mode": "short_urls", "hosts": want}
    if not want:
        return dict(out, error="no host given")
    if not ghw_configured():
        return _keyless(out, want[0], "shorteners")
    limit = min(int(limit or _lim("exposure_urls")), int(_lim("page_max")))

    def _go():
        path = "subdomain/" + ",".join(urllib.parse.quote(h, safe="") for h in want) + f"/files/0/{limit}"
        data, err = _call("shorteners", path,
                          {"order": "timestamp", "direction": "desc", "ext": ext}, timeout)
        if err:
            return dict(out, **err)
        hs = set(want)
        rows = [_short_row(u) for u in (data.get("urls") or []) if str(u.get("subDomain") or "").lower() in hs]
        _record("short_urls", len(rows), ok=True)
        return dict(out, results=data.get("urlsCount"), urls=rows)
    return _memo(f"short_urls|{','.join(want)}|{limit}|{ext or ''}", _go)


def _handle(selector):
    """(kind, token) for a Telegram handle / WhatsApp number selector, else (None, '')."""
    s = str(selector or "").strip()
    low = s.lower()
    host = _host(low) if "/" in low or "://" in low else ""
    parsed = urllib.parse.urlparse(low if "://" in low else "https://" + low) if host else None
    if host in HANDLE_HOSTS.get("whatsapp", []):
        digits = (re.sub(r"\D", "", parsed.path)
                  or re.sub(r"\D", "", (urllib.parse.parse_qs(parsed.query).get("phone") or [""])[0]))
        return ("whatsapp", digits) if len(digits) >= 6 else (None, "")
    if not host and re.fullmatch(r"\+?[\d\s().-]{6,}", s):
        digits = re.sub(r"\D", "", s)
        return ("whatsapp", digits) if len(digits) >= 6 else (None, "")
    if host in HANDLE_HOSTS.get("telegram", []):
        segs = [p for p in parsed.path.split("/") if p]
        if segs and segs[0] == "s":
            segs = segs[1:]
        return ("telegram", segs[0]) if segs else (None, "")
    # a bare word is a handle only when written as one (@handle; Telegram usernames are 5–32 chars)
    if low.startswith("@") and re.fullmatch(r"[a-z0-9_]{5,32}", low[1:]):
        return "telegram", low[1:]
    return None, ""


def short_handle(selector, limit=None, timeout=None):
    """Short links whose long URL is the operator's Telegram handle (t.me/<h>, @h) or WhatsApp number
    (wa.me/<digits>, +<digits>) -> {kind, token, results, urls:[...]}: the bit.ly/goo.gl links the
    operator spread, with their discovery dates."""
    kind, token = _handle(selector)
    out = {"mode": "short_handle", "selector": selector, "kind": kind, "token": token}
    if not kind:
        return dict(out, error="not a Telegram handle (t.me/<h>, @<h>) or WhatsApp number (wa.me/<n>, +<n>)")
    hosts = HANDLE_HOSTS.get(kind) or []
    if not ghw_configured():
        return _keyless(out, f"{hosts[0] if hosts else ''}/{token}", "shorteners")
    limit = min(int(limit or _lim("page_max")), int(_lim("page_max")))

    def _go():
        data, err = _call("shorteners", f"files/0/{limit}",
                          {"domains": ",".join(hosts), "keywords": token,
                           "order": "timestamp", "direction": "desc"}, timeout)
        if err:
            return dict(out, **err)
        rows = []
        for u in data.get("urls") or []:
            url = str(u.get("url") or "")
            if kind == "whatsapp":
                hit = token in re.sub(r"\D", "", url)
            else:
                k2, t2 = _handle(url)
                hit = k2 == "telegram" and t2 == token
            if hit:
                rows.append(_short_row(u))
        _record("short_handle", len(rows), ok=True)
        return dict(out, results=len(rows), scanned=data.get("urlsCount"), urls=rows)
    return _memo(f"short_handle|{kind}|{token}|{limit}", _go)


# ---------------------------------------------------------------------------------------------- git
def is_managed_mail(domain):
    d = _host(domain)
    return d in MANAGED_MAIL or any(d.endswith("." + m) for m in MANAGED_MAIL)


def git_committers(selector, limit=None, timeout=None):
    """Git committer identities for an exact e-mail, or for every author e-mail on a SELF-HOSTED mail
    domain -> {selector, by, results, committers:[{email, name, username, repos, id}]}. A managed mail
    domain (gmail.com…) is refused without a call. Git author e-mails are UNAUTHENTICATED: each row is
    a lead to confirm with github_harvest, never an owner link."""
    sel = str(selector or "").strip().lower()
    by = "email" if "@" in sel else "domain"
    if by == "domain":
        sel = _host(sel)
        sel = _registrable(sel) or sel
    out = {"mode": "git_committers", "selector": sel, "by": by}
    if not sel:
        return dict(out, error="no selector given")
    if by == "domain" and is_managed_mail(sel):
        return dict(out, skipped=f"{sel} is a managed mail domain — its committers are strangers, "
                                 f"not the operator; look up an exact address instead",
                    skipped_kind="entitlement", committers=[])
    if not ghw_configured():
        return _keyless(out, sel, "git")
    limit = min(int(limit or _lim("committers")), int(_lim("page_max")))

    def _go():
        params = {"filter": sel} if by == "email" else {"email-domain": sel}
        params["limit"] = limit
        data, err = _call("git", "users", params, timeout)
        if err:
            return dict(out, **err)
        rows = []
        for u in data.get("users") or []:
            em = str(u.get("email") or "").lower()
            dom = em.rsplit("@", 1)[-1] if "@" in em else ""
            # post-filter: an unknown filter value must never turn into "the whole index"
            if (by == "email" and em == sel) or (by == "domain" and (dom == sel or dom.endswith("." + sel))):
                rows.append({"email": em, "name": u.get("name") or u.get("username") or "",
                             "username": u.get("username") or "", "repos": u.get("totalRepositories"),
                             "id": u.get("id")})
        _record("git_committers", len(rows), ok=True)
        return dict(out, results=len(rows), scanned=(data.get("meta") or {}).get("results"),
                    committers=rows,
                    next="github_harvest each address — git author e-mails are unauthenticated")
    return _memo(f"git_committers|{by}|{sel}|{limit}", _go)


def raw_host_allowed(url):
    """True only for an https URL on a public git hosting raw host (references raw_hosts). The `raw`
    link comes from the vendor response, so it is untrusted: anything else — another scheme, a target
    host, an IP literal, a private name — is never fetched."""
    try:
        p = urllib.parse.urlparse(str(url or ""))
    except ValueError:
        return False
    host = (p.hostname or "").lower().rstrip(".")
    return p.scheme == "https" and host in RAW_HOSTS and not p.username and not p.password


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when the NEXT hop is itself an allowlisted raw host (github.com/…/raw/
    → raw.githubusercontent.com); any other hop aborts the fetch."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not raw_host_allowed(newurl):
            raise urllib.error.HTTPError(newurl, code, "redirect to a non-allowlisted host refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_RAW_OPENER = urllib.request.build_opener(_AllowlistRedirect)


def _fetch_raw(url, timeout=None):
    """Raw text of a public repository file (no GHW key sent), or None — None also for any URL or
    redirect hop outside the raw-host allowlist (the row then stays an unverified mention)."""
    if not raw_host_allowed(url):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
        with _RAW_OPENER.open(req, timeout=timeout or _lim("timeout")) as r:
            if not raw_host_allowed(r.geturl()):
                return None
            return r.read(int(_lim("raw_max_bytes"))).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def _git_file_row(f):
    return {"repo": f.get("remote") or f.get("repository"), "repo_id": f.get("remoteId") or f.get("repositoryId"),
            "path": f.get("fullPath") or f.get("file"), "link": f.get("link"), "raw": f.get("raw"),
            "tags": list(f.get("tags") or []), "modified": _iso(f.get("lastModified")),
            "commits": [v.get("commitHash") for v in (f.get("vulnerableVersions") or []) if v.get("commitHash")]}


def git_code(token, limit=20, verify=None, timeout=None):
    """Public repository files whose CONTENT carries `token` (tracker id, wallet, API host, kit
    string) -> {token, results, files:[{repo, path, link, raw, tags, verified}]}. The index tokenises,
    so the first `verify` hits get their raw file fetched: verified=True means the exact token is in
    it (code reuse, kit); False/None rows are mentions only."""
    tok = str(token or "").strip()
    out = {"mode": "git_code", "token": tok}
    if len(tok) < 6:
        return dict(out, error="token too short to be distinctive (need ≥ 6 characters)")
    if not ghw_configured():
        return _keyless(out, tok, "git")
    limit = min(int(limit or 20), int(_lim("page_max")))
    verify = int(_lim("verify_raw") if verify is None else verify)

    def _go():
        data, err = _call("git", "files", {"content": tok, "limit": limit},
                          timeout or _lim("content_timeout"))
        if err:
            return dict(out, **err)
        rows = [_git_file_row(f) for f in (data.get("files") or [])]
        for i, r in enumerate(rows):
            if i < verify:
                text = _fetch_raw(r["raw"])
                r["verified"] = None if text is None else (tok.lower() in text.lower())
            else:
                r["verified"] = None
        _record("git_code", len(rows), ok=True)
        return dict(out, results=(data.get("meta") or {}).get("results"), files=rows,
                    verified=sum(1 for r in rows if r["verified"]))
    return _memo(f"git_code|{tok}|{limit}|{verify}", _go)


def _canon_repo(v):
    s = str(v or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][\w.-]*/[\w.-]+", s):
        s = "https://github.com/" + s
    s = re.sub(r"\.git$", "", s.rstrip("/"))
    p = urllib.parse.urlparse(s if "://" in s else "https://" + s)
    return f"{(p.hostname or '').lower()}{p.path.lower()}"


def git_secrets(repo, timeout=None):
    """Files of ONE repository (owner/repo or its URL) that TruffleHog flagged as carrying a secret
    -> {repo, files_total, results, files:[{path, tags, link, commits}]}. Detector tags and commits
    only — the API never returns the secret, and neither does this."""
    want = _canon_repo(repo)
    out = {"mode": "git_secrets", "repo": repo}
    if not want or "/" not in want:
        return dict(out, error="give owner/repo or a repository URL")
    if not ghw_configured():
        return _keyless(out, want, "git")

    def _go():
        name = want.split("/", 1)[1]
        data, err = _call("git", "repositories", {"filter": name, "limit": int(_lim("page_max"))}, timeout)
        if err:
            return dict(out, **err)
        rid = next((r.get("id") for r in (data.get("repositories") or [])
                    if _canon_repo(r.get("url")) == want), None)
        if rid is None:
            _record("git_secrets", 0, ok=True)
            return dict(out, indexed=False, results=0, files=[])
        data, err = _call("git", "files", {"remote": rid, "limit": int(_lim("page_max"))}, timeout)
        if err:
            return dict(out, **err)
        rows = []
        for f in data.get("files") or []:
            if str(f.get("remoteId") or f.get("repositoryId") or rid) != str(rid):
                continue
            row = _git_file_row(f)
            row["tags"] = [t for t in row["tags"] if str(t).startswith("trufflehog_")]
            if row["tags"] or row["commits"]:
                rows.append(row)
        _record("git_secrets", len(rows), ok=True)
        return dict(out, indexed=True, repo_id=rid, files_total=(data.get("meta") or {}).get("results"),
                    results=len(rows), files=rows)
    return _memo(f"git_secrets|{want}", _go)


# ------------------------------------------------------------------------------- per-apex composite
def exposure(apex):
    """The per-apex auto-fire: open buckets for the brand label, every host the shortener corpus saw
    under the apex, the historical long URLs on those hosts, and the committers on the apex's mail
    domain (refused for managed mail). Each part is memoised once per case."""
    apex = _registrable(_host(apex)) or _host(apex)
    out = {"apex": apex, "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    out["buckets"] = buckets(apex.split(".")[0])
    subs = short_subdomains(apex)
    out["short_subdomains"] = subs
    ranked = sorted(subs.get("subdomains") or [], key=lambda s: -(s.get("urls") or 0))
    hosts = [apex] + [s["host"] for s in ranked if s.get("host") != apex]
    out["short_urls"] = short_urls(hosts)
    out["git_committers"] = git_committers(apex)
    return out


# ------------------------------------------------------------------------------------- typed KB rows
def rows_for(res):
    """Typed corpus rows (pivot_routes/ingest_typed shape) for one result. Exposure and shortener
    hits are mentions (facts only); committers are git.committer_email and verified code hits git.code
    — both kit in rungs.json, so neither can ever become an edge. Capped by limits.ingest_rows."""
    if not isinstance(res, dict) or res.get("error") or res.get("skipped"):
        return []
    mode, src = res.get("mode"), "grayhatwarfare"
    rows = []

    def mention(value, **ev):
        rows.append({"type": "mention", "value": str(value), "rung_class": "string",
                     "source": f"{src}.{mode}", "evidence": {k: v for k, v in ev.items() if v not in (None, "", [])}})
    if mode == "buckets":
        for b in res.get("buckets") or []:
            if b.get("bucket"):
                mention(b["bucket"], kind="open_bucket", files=b.get("fileCount"), cloud=b.get("type"))
    elif mode == "files":
        for f in res.get("files") or []:
            if f.get("url"):
                mention(f["url"], kind="bucket_file", bucket=f.get("bucket"), size=f.get("size"))
    elif mode == "short_subdomains":
        for s in res.get("subdomains") or []:
            mention(s["host"], kind="shortener_host", urls=s.get("urls"))
    elif mode in ("short_urls", "short_handle"):
        for u in res.get("urls") or []:
            if u.get("url"):
                mention(u["url"], kind="short_link", short=u.get("short"), discovered=u.get("discovered"))
    elif mode == "git_committers":
        for c in res.get("committers") or []:
            rows.append({"type": "email", "value": c["email"], "rung_class": "git.committer_email",
                         "source": f"{src}.{mode}",
                         "evidence": {"name": c.get("name"), "repos": c.get("repos"),
                                      "note": "unauthenticated git author e-mail"}})
    elif mode == "git_code":
        for f in res.get("files") or []:
            if not f.get("repo"):
                continue
            if f.get("verified"):
                rows.append({"type": "string", "value": f["repo"], "rung_class": "git.code",
                             "source": f"{src}.{mode}",
                             "evidence": {"path": f.get("path"), "link": f.get("link"), "token": res.get("token")}})
            else:
                mention(f["repo"], kind="git_code_unverified", path=f.get("path"), link=f.get("link"))
    elif mode == "git_secrets":
        for f in res.get("files") or []:
            mention(f.get("link") or f.get("path"), kind="git_secret_file", tags=f.get("tags"),
                    commits=(f.get("commits") or [])[:5])
    return rows[:int(_lim("ingest_rows"))]


LOOKUPS = {
    "buckets": lambda s, a: buckets(s, limit=a.get("limit") or 20),
    "files": lambda s, a: files(s, limit=a.get("limit") or 20),
    "short_subdomains": lambda s, a: short_subdomains(s, limit=a.get("limit")),
    "short_urls": lambda s, a: short_urls(s, limit=a.get("limit"), ext=a.get("ext")),
    "short_handle": lambda s, a: short_handle(s, limit=a.get("limit")),
    "git_committers": lambda s, a: git_committers(s, limit=a.get("limit")),
    "git_code": lambda s, a: git_code(s, limit=a.get("limit") or 20),
    "git_secrets": lambda s, a: git_secrets(s),
}


def lookup(mode, selector, **kw):
    """Dispatch one on-demand lookup by mode name (see LOOKUPS)."""
    fn = LOOKUPS.get(str(mode or "").replace("-", "_"))
    if fn is None:
        return {"mode": mode, "error": f"unknown mode {mode!r}; one of {', '.join(LOOKUPS)}"}
    return fn(selector, kw)


__all__ = ["ghw_key", "ghw_configured", "dork", "account", "buckets", "files", "short_subdomains",
           "short_urls", "short_handle", "git_committers", "git_code", "git_secrets", "exposure",
           "rows_for", "lookup", "is_managed_mail", "LOOKUPS"]


def main():
    ap = argparse.ArgumentParser(
        description="GrayHatWarfare: open buckets, shortener corpus, git corpus (+ keyless dork fallback)")
    ap.add_argument("mode", choices=["account", "exposure", *[m.replace("_", "-") for m in LOOKUPS]],
                    help="what to search")
    ap.add_argument("selector", nargs="?", default="",
                    help="keyword / apex / comma-separated hosts / handle / e-mail or mail domain / token / owner/repo")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--ext", default=None, help="short-urls: comma list of file extensions (pdf,xlsx)")
    ap.add_argument("--exact", action="store_true", help="buckets: exact name match")
    args = ap.parse_args()
    mode = args.mode.replace("-", "_")
    if mode == "account":
        res = account() or {"skipped": "no GRAYHATWARFARE_API_KEY configured"}
    elif mode == "exposure":
        res = exposure(args.selector)
    elif mode == "buckets" and args.exact:
        res = buckets(args.selector, limit=args.limit or 20, exact=True)
    else:
        res = lookup(mode, args.selector, limit=args.limit, ext=args.ext)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
