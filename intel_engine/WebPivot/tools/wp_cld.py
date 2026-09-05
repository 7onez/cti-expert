"""wp_cld — ChongLuaDao first-party reputation layer for the deterministic collector.

Thin wrapper over `scripts/cld/cld_api.py` (RULE 4: ONE implementation — this reuses that module's
`_request` core, `_api_key` resolver and `FEEDS`/`TI` bases; it does not fork them). It runs the
three CLD calls that describe a host without touching it — CLD fetches the target server-side, so
this is safe under any fetch posture — and returns a compact `live_results["cld"]` block:

  * checkurl   — the host's verdict against CLD's ~20M-URL denylist/allowlist
  * ioc_url    — CLD's IoC analyzer for the URL: registration, domain reputation score, threat
                 matches/reports (the field that returns `verdict` = clean|suspicious|malicious)
  * whois      — CLD's WHOIS, requested ONLY for `.vn` hosts (WhoisXML has no .vn coverage, so this
                 fills the empty Domain Summary rows the pipeline otherwise leaves blank)

Tri-state, never raises: each sub-call is a dict, or `{"skipped": …}` / `{"error": …}`. METERED —
gated `and not free_only` by the caller (a no_spend / --free-only run skips it). The verdict is a
REPUTATION FACT, never a same-operator edge: a denylist hit clusters nothing, and CLD's own
`malicious` label can be internally inconsistent (empty evidence), which the ingest records verbatim
for the analyst to weigh rather than adopting.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# scripts/cld/cld_api.py — the single implementation this reuses
_CLD_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "..", "scripts", "cld"))
_cld_api = None


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


def cld_domain(host: str, timeout: int = _DEFAULT_TIMEOUT, free_only: bool = False) -> dict | None:
    """CLD reputation block for one host. None when the layer is off (no key / free_only)."""
    if free_only or not cld_configured():
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
    # 2) IoC analyzer for the URL (POST /api/v1/ioc/external/url {url}) — registration + reputation
    try:
        s, r, e = api._request("POST", api.TI, "/api/v1/ioc/external/url", key,
                                   body={"url": url}, timeout=timeout)
        out["ioc_url"] = _norm(s, r, e)
        _record("ioc/url", e is None and (s or 0) < 400)
    except Exception as e:  # noqa: BLE001
        out["ioc_url"] = {"error": str(e)[:200]}
    # 3) WHOIS — only for .vn (WhoisXML has no .vn coverage; fills the Domain Summary gap)
    if host.endswith(".vn"):
        try:
            out["whois"] = _checkwhois(api, key, host, timeout)
        except Exception as e:  # noqa: BLE001
            out["whois"] = {"error": str(e)[:200]}
    return out


def cld_whois(host: str, timeout: int = 25, free_only: bool = False) -> dict | None:
    """CLD WHOIS (checkwhois) for one .vn host — the WHOIS leg WITHOUT the checkurl/ioc_url spend.
    None when the layer is off, free_only, or host is not .vn. Used by whois_enrich so a .vn WHOIS
    backfill costs ONE metered call, not the three cld_domain fires."""
    if free_only or not cld_configured():
        return None
    host = (host or "").strip().lower().rstrip(".")
    if not host or not host.endswith(".vn"):
        return None
    api = _api()
    key = _env_key()
    if api is None or not key:
        return None
    try:
        return _checkwhois(api, key, host, timeout)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:200]}


def cld_email(email: str, timeout: int = 25, free_only: bool = False) -> dict | None:
    """CLD IoC lookup for an e-mail (POST /api/v1/ioc/external/email). Corroborates a registrant
    address against CLD's leak/abuse index. None when the layer is off or free_only. Never raises."""
    if free_only or not cld_configured():
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
        return _norm(s, r, e)
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
