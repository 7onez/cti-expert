"""wp_cld — ChongLuaDao first-party reputation layer for the deterministic collector.

Thin wrapper over `scripts/cld/cld_api.py` (RULE 4: ONE implementation — this reuses that module's
`_request` core, `_api_key` resolver and `FEEDS`/`TI` bases; it does not fork them). It queries
both ChongLuaDao APIs for one host — Feeds cannot answer the Shield questions, and
Shield cannot answer the denylist — and returns a compact `live_results["cld"]` block:

  * checkurl       — Feeds: verdict against CLD's denylist/allowlist
  * ioc_url        — Shield: IoC analyzer (registration, reputation, threat matches)
  * ransomware     — Shield victims whose website host is this host
  * clickfix       — Shield ClickFix lures whose domain/url host is this host
  * phaas          — Shield phishing-kit rows, same host match
  * internal_leaks — Shield leaked documents whose url host is this host
  * denylist       — Feeds: brand-label denylist search — estate hits + name-similar leads (#14)
  * whois          — Feeds WHOIS, requested ONLY for `.vn` hosts

Tri-state, never raises: each sub-call is a dict, or `{"skipped": …}` / `{"error": …}`. METERED —
gated `and not free_only` by the caller (a no_spend / --free-only run skips it). The verdict is a
REPUTATION FACT, never a same-operator edge: a denylist hit clusters nothing, and CLD's own
`malicious` label can be internally inconsistent (empty evidence), which the ingest records verbatim
for the analyst to weigh rather than adopting.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# scripts/cld/cld_api.py — the single implementation this reuses
_CLD_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "..", "scripts", "cld"))
_cld_api = None

from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

# DATA (RULE 3): the brand-label denylist search (#14) — minimum length for a title-derived
# product-label token, words that are decoration rather than a wordmark, how many extra title
# labels get their own call, and the request shape for GET /external/denylists/search. The
# fallback below is the conservative minimum: it still derives the registrable-apex label (the
# search always has at least that one label) even if this file is missing or malformed.
_DENYLIST_FALLBACK = {
    "brand_labels": {"min_title_token_length": 3, "max_title_labels": 2,
                     "title_stopwords": ["home", "login", "welcome", "official"]},
    "denylist_search": {"page": 1, "limit": 20},
}
_DENYLIST_REFS = load_ref(ref_path(__file__, "cld_denylist.json"), _DENYLIST_FALLBACK)
_BRAND_LABEL_CFG = _DENYLIST_REFS["brand_labels"]
_DENYLIST_SEARCH_CFG = _DENYLIST_REFS["denylist_search"]


def _api():
    """Lazy import of the CLD connector. Deferred because importing cld_api installs the process
    proxy (cti_proxy.install()) — we don't want that as a side effect of merely importing wp_cld
    into wp_analyze; it happens only when a CLD call is actually made. None if unavailable."""
    global _cld_api
    if _cld_api is None:
        if _CLD_DIR not in sys.path:
            sys.path.insert(0, _CLD_DIR)
        try:
            import cld_api  # noqa: E402
            _cld_api = cld_api
        except Exception:  # pragma: no cover — connector missing → layer disabled, never fatal
            _cld_api = False
    return _cld_api or None

try:
    import api_usage  # noqa: E402  — licensed-credit ledger
except Exception:  # pragma: no cover
    api_usage = None

_DEFAULT_TIMEOUT = 30


_KEY_NAMES = ("CHONGLUADAO_API_KEY", "CLD_API_KEY", "CHONGLUADAO_KEY", "BURNER_API_KEY")


def cld_configured() -> bool:
    """True when a ChongLuaDao key is in the PROCESS env AND the connector is importable.

    Env-FIRST on purpose: `wp_common` loads .env into os.environ at import, so a real key is present
    in production, while a test that pops the env var genuinely disables the layer — unlike
    `cld_api._api_key()`, which re-reads .env on every call and would resurrect a popped key
    (that reload once made enrich_live fire a live CLD call inside the offline gate)."""
    if not any(os.environ.get(n) for n in _KEY_NAMES):
        return False
    return _api() is not None


_SHIELD_MEMO = {}


def _apex_of(host):
    host = (host or "").lower().split(":")[0]
    try:
        from wp_common import _registrable
        return (_registrable(host) or host).lower()
    except Exception:
        parts = [p for p in host.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

def _apex_label(apex):
    """The wordmark inside a registrable apex — `apex` minus its public suffix, e.g. 'brandsite'
    from 'brandsite.example'. Falls back to the apex itself when the suffix cannot be isolated (a bare
    TLD, or wp_common being unavailable) so the denylist search always has at least one label."""
    apex = (apex or "").lower()
    if not apex:
        return apex
    try:
        from wp_common import public_suffix
        suffix = public_suffix(apex)
    except Exception:
        suffix = apex.rsplit(".", 1)[-1] if "." in apex else apex
    if apex == suffix or not apex.endswith("." + suffix):
        return apex
    return apex[: -(len(suffix) + 1)]


def _title_labels(page_title):
    """Product-label tokens pulled from a page <title> — data-driven length floor and stopword
    list (references/cld_denylist.json -> brand_labels), so 'ACME | Trang chu' yields 'acme' and
    not the boilerplate 'trang'/'chu'. [] when no title was passed — the caller is not required to
    have one; the apex label alone is still a valid, if narrower, search."""
    if not page_title:
        return []
    min_len = int(_BRAND_LABEL_CFG.get("min_title_token_length") or 3)
    stop = {str(w).lower() for w in (_BRAND_LABEL_CFG.get("title_stopwords") or [])}
    cap = int(_BRAND_LABEL_CFG.get("max_title_labels") or 2)
    out = []
    for tok in re.split(r"[\s|:\-\u2013\u2014\u00b7\u2022_/\\]+", str(page_title).lower()):
        tok = re.sub(r"[^a-z0-9]", "", tok)
        if len(tok) >= min_len and tok not in stop and tok not in out:
            out.append(tok)
        if len(out) >= cap:
            break
    return out


def _brand_labels(host, page_title=None):
    """The label(s) to run the CLD denylist search for: the registrable apex's own wordmark, plus
    (if the caller has one) product-label tokens from the page title — the estate's real brand
    name is sometimes only visible there ('acme' on both an apex containing it and an unrelated
    apex sharing the wordmark), while the apex label alone would miss that sibling entirely."""
    apex_label = _apex_label(_apex_of(host))
    labels = [apex_label] if apex_label else []
    for tok in _title_labels(page_title):
        if tok not in labels:
            labels.append(tok)
    return labels


def _label_tokens(host):
    """Every DNS label of `host`, plus each label's own hyphen-split sub-tokens — the units a
    brand label may legitimately equal. A raw substring match is NOT here on purpose: an IPFS CID
    like 'bafyznacmeuxhm...' contains 'acme' as a substring but is a single opaque label with no
    boundary at that point, so it must never match."""
    labels = [l for l in (host or "").lower().split(".") if l]
    tokens = set(labels)
    for l in labels:
        tokens.update(t for t in l.split("-") if t)
    return tokens


def _label_boundary_match(label, host):
    """True when `label` equals a whole DNS label of `host`, or a whole hyphen-delimited token
    inside one of its labels — never a raw substring."""
    label = (label or "").lower()
    return bool(label) and label in _label_tokens(host)


def _denylist_rows(result):
    if not isinstance(result, dict):
        return []
    for k in ("items", "data", "results"):
        v = result.get(k)
        if isinstance(v, list):
            return [r for r in v if isinstance(r, dict)]
    return []


def _classify_denylist_rows(rows, label, case_apex, api):
    """Split denylist rows matching `label` on a DNS-label boundary into estate evidence (same
    apex as this case) and name-similar leads (a different apex — never a cluster member, never
    seeded, never an IOC, per the attribution rails: name-similarity is add_fact only)."""
    host_of = getattr(api, "_host_of", None) or (lambda v: str(v or "").strip().lower())
    estate, leads = [], []
    for row in rows:
        host = None
        for k in ("website", "domain", "url", "host", "hostname"):
            v = row.get(k)
            if v:
                host = host_of(v)
                if host:
                    break
        if not host or not _label_boundary_match(label, host):
            continue
        row_apex = _apex_of(host)
        entry = dict(row)
        entry["_matched_host"], entry["_matched_apex"] = host, row_apex
        (estate if row_apex == case_apex else leads).append(entry)
    return estate, leads


def _denylist_search(api, key, label, timeout):
    """One GET /external/denylists/search for `label`, memoised once per label per case
    (wp_casememo, the same memo the Shield list calls above share)."""
    def _fetch():
        params = {"search": label, "page": _DENYLIST_SEARCH_CFG.get("page", 1),
                  "limit": _DENYLIST_SEARCH_CFG.get("limit", 20)}
        s, r, e = api._request("GET", api.FEEDS, "/external/denylists/search", key,
                               params=params, timeout=timeout)
        _record("denylist", e is None and (s or 0) < 400)
        return _norm(s, r, e)
    return _memo_shield("denylist", label, _fetch)


def _memo_shield(name, apex, fn):
    """One Shield list call per apex per case. Errors are not memoised."""
    key = f"{name}|{apex}"
    if key in _SHIELD_MEMO:
        return _SHIELD_MEMO[key]
    try:
        import wp_casememo
        cached = wp_casememo.get("cld", key)
    except Exception:
        cached = None
    if cached is not None:
        _SHIELD_MEMO[key] = cached
        return cached
    val = fn()
    if isinstance(val, dict) and val.get("error"):
        return val
    _SHIELD_MEMO[key] = val
    try:
        import wp_casememo
        wp_casememo.put("cld", key, val)
    except Exception:
        pass
    return val

def _record(op: str, ok: bool):
    if api_usage is not None:
        try:
            api_usage.record("chongluadao", op, credits=1 if ok else 0, ok=ok)
        except Exception:
            pass


def _norm(status, res, err):
    """cld_api._request → a compact tri-state dict for live_results."""
    if err:
        return {"error": str(err)[:300]}
    if status and status >= 400:
        return {"error": f"HTTP {status}"}
    return res if isinstance(res, (dict, list)) else {"result": res}


def _env_key():
    """First non-empty ChongLuaDao key in the PROCESS env (never a .env re-read)."""
    for n in _KEY_NAMES:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def _checkwhois(api, key, host, timeout):
    """CLD checkwhois GET -> normalised dict, ledgered once."""
    s, r, e = api._request("GET", api.FEEDS, "/external/checkwhois", key,
                           params={"q": host}, timeout=timeout)
    _record("checkwhois", e is None and (s or 0) < 400)
    return _norm(s, r, e)

_WHOIS_SIGNAL_ATTR = "whois_has_signal"  # cld_api.whois_has_signal — canonical impl (#15)


def _whois_leg(api, key, host, timeout):
    """CLD checkwhois -> normalised dict; an all-null body (no registrar, dates, owner or name
    servers — cld_api.whois_has_signal) becomes a MISS marker instead of being handed back as a
    confirmed empty-registrant WHOIS, so both callers of this leg (cld_domain's own `.vn` block and
    the standalone `cld_whois` whois_enrich uses) fall back to RDAP/port-43 WHOIS."""
    body = _checkwhois(api, key, host, timeout)
    signal = getattr(api, _WHOIS_SIGNAL_ATTR, None)
    if callable(signal) and isinstance(body, dict) and not body.get("error") and not signal(body):
        return {"miss": True, "host": host,
                "reason": "CLD checkwhois returned an all-null body (no registrar, dates, owner, "
                          "or name servers) — a miss, not an answer; fall back to RDAP/port-43 "
                          "WHOIS for this host",
                "raw": body}
    return body


def cld_domain(host: str, timeout: int = _DEFAULT_TIMEOUT, page_title: str = None) -> dict | None:
    """CLD reputation block for one host. None when the layer is off (no key). CLD usage is
    unlimited (no per-call credit / quota), so there is NO free-only spend gate — it runs like
    Validin/Webamon, server-side, posture-safe (never touches the target directly).

    `page_title`, if the caller has it (pivot_extract's own <title> extraction), adds any
    product-label token found there to the denylist brand-label search (#14) — a shared wordmark
    is sometimes only visible on the page, not in the apex itself."""
    if not cld_configured():
        return None
    api = _api()
    key = _env_key()
    if api is None or not key:
        return None
    host = (host or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return None
    url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    out = {}
    # 1) denylist verdict (POST /external/checkurl {url})
    try:
        s, r, e = api._request("POST", api.FEEDS, "/external/checkurl", key,
                                   body={"url": url}, timeout=timeout)
        out["checkurl"] = _norm(s, r, e)
        _record("checkurl", e is None and (s or 0) < 400)
    except Exception as e:  # noqa: BLE001
        out["checkurl"] = {"error": str(e)[:200]}
    # 2) IoC analyzer (POST /api/v1/ioc/external/url) — Shield reputation
    try:
        s, r, e = api._request("POST", api.TI, "/api/v1/ioc/external/url", key,
                               body={"url": url}, timeout=timeout)
        out["ioc_url"] = _norm(s, r, e)
        _record("ioc/url", e is None and (s or 0) < 400)
    except Exception as e:  # noqa: BLE001
        out["ioc_url"] = {"error": str(e)[:200]}
    # 3) Shield list modules, once per registrable apex. A 25-subdomain estate
    # shares one victim/lure page; checkurl and ioc_url stay per-host above.
    # internal-leaks url is the paste the document was found on, not the target,
    # so that row is search-scoped and not host-filtered.
    host_q = host.split("://", 1)[-1].split("/")[0]
    apex = _apex_of(host_q)
    for name, path, params, host_filter in (
            ("ransomware", "/api/v1/ransomware/external/victims", {"q": apex}, True),
            ("clickfix", "/api/v1/threat-feeds/external/clickfix", {"q": apex}, True),
            ("phaas", "/api/v1/threat-feeds/external/phaas", {"q": apex}, True),
            ("internal_leaks", "/api/v1/data-leaks/external/internal-leaks",
             {"search": apex, "limit": 50}, False)):
        def _fetch(path=path, params=params, name=name):
            s, r, e = api._request("GET", api.TI, path, key, params=params, timeout=timeout)
            _record(name, e is None and (s or 0) < 400)
            return _norm(s, r, e)
        try:
            block = _memo_shield(name, apex, _fetch)
            filt = getattr(api, "filter_host_hits", None)
            if host_filter and filt and isinstance(block, dict) and not block.get("error"):
                block, _n = filt(block, apex)
            elif isinstance(block, dict) and not block.get("error"):
                block = dict(block)
                n = next((len(block[k]) for k in ("items", "data", "results")
                          if isinstance(block.get(k), list)), 0)
                block["matched"] = n
            out[name] = block
        except Exception as e:  # noqa: BLE001
            out[name] = {"error": str(e)[:200]}
    # 3b) Brand-label denylist search (#14): the estate's own wordmark plus any page-title
    # product label, DNS-label-boundary matched (never substring), once per label per case. Rows
    # sharing this case's apex are estate evidence; other matching apexes are name-similar LEADS —
    # never a cluster member, never seeded, never an IOC.
    labels = _brand_labels(host_q, page_title)
    if labels:
        dl_estate, dl_leads = [], []
        for label in labels:
            try:
                block = _denylist_search(api, key, label, timeout)
            except Exception as e:  # noqa: BLE001
                block = {"error": str(e)[:200]}
            if not isinstance(block, dict) or block.get("error"):
                continue
            rows = _denylist_rows(block)
            est, leads = _classify_denylist_rows(rows, label, apex, api)
            dl_estate.extend(est)
            dl_leads.extend(leads)
        out["denylist"] = {
            "labels_searched": labels,
            "estate": dl_estate,
            "leads": dl_leads,
            "note": ("ChongLuaDao denylist rows are matched on a DNS-label boundary, never a raw "
                     "substring. 'estate' rows share this case's registrable apex; 'leads' are "
                     "name-similar apexes and must never be treated as cluster members, frontier "
                     "seeds, or IOCs on their own."),
        }
    # 4) WHOIS — only for .vn
    if host.endswith(".vn"):
        try:
            out["whois"] = _whois_leg(api, key, host, timeout)
        except Exception as e:  # noqa: BLE001
            out["whois"] = {"error": str(e)[:200]}
    return out


def cld_whois(host: str, timeout: int = 25) -> dict | None:
    """CLD WHOIS (checkwhois) for one .vn host — the WHOIS leg on its own (no checkurl/ioc_url).
    None when the layer is off or host is not .vn. CLD is unlimited, so no free-only gate applies.
    Used by whois_enrich so a .vn WHOIS backfill is one call, not the three cld_domain fires."""
    if not cld_configured():
        return None
    host = (host or "").strip().lower().rstrip(".")
    if not host or not host.endswith(".vn"):
        return None
    api = _api()
    key = _env_key()
    if api is None or not key:
        return None
    try:
        return _whois_leg(api, key, host, timeout)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:200]}


def cld_email(email: str, timeout: int = 25) -> dict | None:
    """CLD IoC lookup for an e-mail (POST /api/v1/ioc/external/email). Corroborates a registrant
    address against CLD's leak/abuse index. None when the layer is off. CLD is unlimited, so no
    free-only spend gate applies. Never raises."""
    if not cld_configured():
        return None
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return None
    api = _api()
    key = _env_key()
    if api is None or not key:
        return None
    try:
        s, r, e = api._request("POST", api.TI, "/api/v1/ioc/external/email", key,
                               body={"email": email}, timeout=timeout)
        _record("ioc/email", e is None and (s or 0) < 400)
        out = _norm(s, r, e)
        if isinstance(out, dict):
            domain = email.split("@", 1)[-1]
            bs, br, be = api._request("GET", api.FEEDS, "/external/checkburneremail", key,
                                      params={"q": domain}, timeout=timeout)
            _record("burner", be is None and (bs or 0) < 400)
            out["feeds_burner"] = _norm(bs, br, be)
        return out
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:200]}


def verdict_of(cld_block: dict) -> dict | None:
    """Extract the reputation verdict + its evidence-consistency flag from a cld_domain block.

    Returns {"verdict", "score", "has_evidence", "source"} or None. `has_evidence` is False when
    CLD labels a host malicious/suspicious but every evidence field is empty — the analyst must be
    shown that so an inconsistent auto-label is never adopted as a finding."""
    if not isinstance(cld_block, dict):
        return None
    ioc = cld_block.get("ioc_url")
    data = (ioc or {}).get("data") if isinstance(ioc, dict) else None
    verdict = (ioc or {}).get("verdict") if isinstance(ioc, dict) else None
    src = "ioc_url"
    # checkurl is the denylist verdict: `result` is clean|suspicious|malicious, `details` names why
    cu = cld_block.get("checkurl") if isinstance(cld_block.get("checkurl"), dict) else {}
    cu_result = cu.get("result") or cu.get("verdict") or (cu.get("data") or {}).get("verdict")
    cu_details = str(cu.get("details") or "")
    denylisted = bool(cu_result and str(cu_result).lower() in ("malicious", "suspicious", "phishing", "scam"))
    if not verdict:
        verdict = cu_result
        src = "checkurl"
    if not verdict:
        return None
    rep = (data or {}).get("domain_reputation") or {}
    matches = (data or {}).get("threat_matches") or []
    reports = ((data or {}).get("threat_reports") or {})
    listed = rep.get("has_abuse_listing")
    n_reports = reports.get("count") if isinstance(reports, dict) else None
    # a concrete denylist LISTING (checkurl) is evidence just as much as an IoC threat match/report;
    # has_evidence is False only when the label rests on nothing (score/keyword) the analyst can see
    has_evidence = bool(matches) or bool(listed) or bool(n_reports) or denylisted
    return {"verdict": verdict, "score": rep.get("reputation_score"),
            "has_evidence": has_evidence, "denylisted": denylisted,
            "checkurl_result": cu_result, "checkurl_details": cu_details or None, "source": src}
