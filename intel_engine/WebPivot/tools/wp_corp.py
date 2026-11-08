#!/usr/bin/env python3
"""wp_corp — GLOBAL company + officer registry pivot.

Four modes over public company registries (endpoints, HTML id maps, jurisdiction scopes and caveats
are DATA in `references/corp_registry.json`, RULE 3):

  company <name|number> [--jurisdiction XX]   companies matching a name / registry number, with the
                                              officers + registered-address history of the top
                                              `detail_max` matches
  officer <full name>   [--jurisdiction XX]   officer-name search -> HOMONYM CANDIDATES
  company-officers <jurisdiction>:<number>    one company's officer list (GB/NO/FR/FI/US/VN, others
                                              via OpenCorporates when a token is set)
  officer-appointments <provider id | url>    a Companies House / OpenCorporates officer's other
                                              appointments

Providers: GLEIF LEI (global, keyless; legal name, LEI, registration authority id, legal/HQ address,
direct/ultimate parent, direct children), UK Companies House (keyless HTML of find-and-update, or
the REST API when COMPANIES_HOUSE_API_KEY is set), OpenCorporates (the FREE WEBSITE in one
CloakBrowser per run, signed in with the analyst's free account — OPENCORPORATES_EMAIL /
OPENCORPORATES_PASSWORD from env/.env only, session reused from ~/.config/cti-expert/sessions/;
anonymous runs get company pages without officers and searches `gated: recaptcha` = a collection
gap; the premium v0.4 API is a secondary only when OPENCORPORATES_API_TOKEN is set), France
recherche-entreprises (dirigeants inline), Norway
Brreg (roller), Finland PRH (no officers published), SEC EDGAR (CIK search + submissions; declared
UA per SEC fair-access policy). Jurisdiction VN routes to `wp_vncorp` (imported lazily), CN to a
pointer at the cn_recon tool.

Output is TRI-STATE per provider — {status: ok|empty|error|skipped|gated, url, results[]} — plus
normalised `companies[]` and `officers[]`. RULE 5: every officer row is `rung: "lead"` with a caveat
(nominee directors, formation agents, same-name strangers). Officer-search rows are `candidate`
until an analyst datum (`--corroborate birth=YYYY-MM,address=..,postcode=..,company=..`) matches on
the SAME record with none contradicting — only then `linked: true`. Nothing here becomes a KB edge
or an operator attribution. Addresses matching generic formation-agent / registered-office-provider
wording are flagged.

Egress: `urllib.request.urlopen`, i.e. the process-global cti-proxy FailoverOpener `wp_common`
installs at import (registry hosts are listed in scripts/proxy/vendor_hosts.json, so a pool that
refuses a government host falls back direct for that host only). Android UA (`wp_net.DEFAULT_UA`)
everywhere except SEC EDGAR (declared UA from $SEC_EDGAR_USER_AGENT). Never raises.

CLI:
  python3 wp_corp.py company "Example Holdings" [--jurisdiction GB] [--provider gleif,companies_house]
  python3 wp_corp.py officer "Registrant Name" --jurisdiction GB --corroborate birth=1980-01,postcode=AB1 2CD
  python3 wp_corp.py company-officers gb:00000000
  python3 wp_corp.py officer-appointments https://find-and-update.company-information.service.gov.uk/officers/<id>/appointments
  python3 wp_corp.py officer-appointments oc:<officer number>        (OpenCorporates website)
  .venv/bin/python3 wp_corp.py opencorporates-login                   (TTY only: prompts, tests the
      login live, then writes OPENCORPORATES_EMAIL/PASSWORD to the skill .env and saves the session)
"""
import argparse
import base64
import gzip
import html as _html
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import *  # noqa — installs the process-global egress proxy (FailoverOpener) at import
from wp_common import _secret  # noqa: E402 — env first, then the gitignored .env files
from wp_refs import ref_path, load_ref  # noqa: E402
try:
    from wp_net import DEFAULT_UA as _ANDROID_UA  # noqa: E402 — the repo's Android UA
except Exception:  # noqa: BLE001 — parsers stay usable offline even if the net layer cannot import
    _ANDROID_UA = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36")
try:
    import api_usage  # noqa: E402
except Exception:  # noqa: BLE001
    api_usage = None

# --- reference DATA (RULE 3): the fallback is the conservative minimum — GLEIF only (global,
#     keyless), the CH id maps and the RULE 5 caveats — so a missing JSON still answers and still
#     labels every officer a lead.
_FALLBACK = {
    "settings": {"timeout_seconds": 20, "max_results": 10, "detail_max": 2, "officer_pages": 1,
                 "verify_max": 3, "gleif_children_max": 20, "address_token_overlap": 0.7,
                 "sec_user_agent_env": "SEC_EDGAR_USER_AGENT",
                 "sec_user_agent_default": "cti-expert research contact@example.com"},
    "jurisdiction_aliases": {"UK": "GB"},
    "providers": {"gleif": {
        "label": "GLEIF LEI API", "jurisdictions": ["*"], "keyless": True,
        "search_exact": "https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]={query}&page[size]={size}",
        "search_name": "https://api.gleif.org/api/v1/lei-records?filter[fulltext]={query}&page[size]={size}",
        "search_number": "https://api.gleif.org/api/v1/lei-records?filter[entity.registeredAs]={query}&page[size]={size}",
        "jurisdiction_filter": "&filter[entity.jurisdiction]={jurisdiction}",
        "record": "https://api.gleif.org/api/v1/lei-records/{lei}",
        "public_url": "https://search.gleif.org/#/record/{lei}"}},
    "routes": {"CN": {"tool": "cn_recon", "note": "PRC registry recon is the cn_recon tool."}},
    "ch_officer_fields": {"officer-role": "role", "officer-date-of-birth": "birth_month_year",
                          "officer-appointed-on": "appointed", "officer-resigned-on": "resigned",
                          "officer-nationality": "nationality",
                          "officer-country-of-residence": "country_of_residence",
                          "officer-address-value": "correspondence_address"},
    "ch_appointment_fields": {"appointment-type-value": "role", "appointed-value": "appointed",
                              "resigned-value": "resigned",
                              "correspondence-address-value": "correspondence_address"},
    "address_change_patterns": [
        r"Registered office address changed from (?P<old>.+?) to (?P<new>.+?) on (?P<date>\d{1,2} \w+ \d{4})"],
    "formation_agent_patterns": [r"company formations?", r"registered office (ltd|limited|services?)"],
    "caveats": {
        "officer": "Registry officer = LEAD, not attribution: nominee directors, formation agents "
                   "and same-name strangers are common.",
        "officer_search": "Officer-name search returns HOMONYM CANDIDATES; linked only when a "
                          "corroborating datum matches on the same record.",
        "formation_agent": "Address matches formation-agent wording — never cluster on it."},
}
_REFS = load_ref(ref_path(__file__, "corp_registry.json"), _FALLBACK)
SETTINGS = {**_FALLBACK["settings"], **(_REFS.get("settings") or {})}
ALIASES = {str(k).upper(): str(v).upper() for k, v in (_REFS.get("jurisdiction_aliases") or {}).items()}
PROVIDERS = _REFS.get("providers") or _FALLBACK["providers"]
ROUTES = _REFS.get("routes") or {}
CH_OFFICER_FIELDS = _REFS.get("ch_officer_fields") or _FALLBACK["ch_officer_fields"]
CH_APPT_FIELDS = _REFS.get("ch_appointment_fields") or _FALLBACK["ch_appointment_fields"]
ADDR_CHANGE_RES = [re.compile(p, re.I | re.S) for p in (_REFS.get("address_change_patterns") or [])]
AGENT_RES = [(p, re.compile(p, re.I)) for p in (_REFS.get("formation_agent_patterns") or [])]
CAVEATS = {**_FALLBACK["caveats"], **(_REFS.get("caveats") or {})}
TIMEOUT = int(SETTINGS["timeout_seconds"])
UA = _ANDROID_UA
MODES = ("company", "officer", "company-officers", "officer-appointments")


# ============================================================================ small helpers
def _q(s) -> str:
    return urllib.parse.quote(str(s or ""), safe="")


def _fmt(tpl: str, **kw) -> str:
    out = tpl
    for k, v in kw.items():
        out = out.replace("{" + k + "}", _q(v) if k not in ("size", "page") else str(v))
    return out


def _txt(s) -> str:
    """HTML fragment -> clean one-line text."""
    s = re.sub(r"<script.*?</script>", " ", str(s or ""), flags=re.S | re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", _html.unescape(s)).strip()


def _fold(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or ""))
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9 ]", " ", s.lower())


def _tokens(s):
    return {t for t in _fold(s).split() if len(t) >= 2}


def _postcode(s) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(s or "").upper())


_MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august", "september",
     "october", "november", "december"], 1)}


def norm_birth(v):
    """'April 1987' | '1987-04' | '1987-04-02' | {'month':4,'year':1987} | '1987' -> 'YYYY-MM' / 'YYYY'.
    A full date is truncated to month precision — that is all the analyst needs to corroborate."""
    if not v:
        return None
    if isinstance(v, dict):
        y, m = v.get("year"), v.get("month")
        return f"{int(y):04d}-{int(m):02d}" if y and m else (f"{int(y):04d}" if y else None)
    s = str(v).strip()
    m = re.match(r"^(\d{4})-(\d{1,2})", s)
    if m:
        return f"{m.group(1)}-{int(m.group(2)):02d}"
    m = re.match(r"^([A-Za-z]+)\s+(\d{4})$", s)
    if m and m.group(1).lower() in _MONTHS:
        return f"{m.group(2)}-{_MONTHS[m.group(1).lower()]:02d}"
    m = re.match(r"^(\d{4})$", s)
    return m.group(1) if m else None


def agent_flags(addr):
    """Generic formation-agent / registered-office-provider wording found in `addr` (patterns)."""
    if not addr:
        return []
    return [p for p, rx in AGENT_RES if rx.search(str(addr))]


def _join(*parts) -> str:
    return ", ".join(str(p).strip() for p in parts if p and str(p).strip()) or None


def _period(start, end=None):
    """'2020-01-01 to 2021-05-05' / open-ended '2020-01-01 to' / None."""
    if not start and not end:
        return None
    return f"{start or '?'} to {end or ''}".strip()


def _jur(j):
    """Analyst jurisdiction -> (ISO alpha-2 for routing, OpenCorporates code)."""
    if not j:
        return None, None
    raw = str(j).strip()
    up = raw.upper()
    iso = ALIASES.get(up, up.split("_")[0][:2] if "_" in up else up)
    oc = raw.lower() if "_" in raw else iso.lower()
    return iso, oc


def _is_number_like(q) -> bool:
    q = (q or "").strip()
    return bool(q) and bool(re.search(r"\d", q)) and len(re.sub(r"[\s.\-]", "", q)) <= 20 \
        and not re.search(r"[a-z]{4,}", q, re.I)


# ============================================================================ transport
def _http(url, accept="application/json", ua=None, auth_user=None, timeout=None):
    """GET -> (status|None, text|None, error|None). Never raises. urllib (not requests) so the
    cti-proxy FailoverOpener and its vendor-host direct fallback apply."""
    headers = {"User-Agent": ua or UA, "Accept": accept, "Accept-Language": "en-GB,en;q=0.8"}
    if auth_user:
        headers["Authorization"] = "Basic " + base64.b64encode(
            (auth_user + ":").encode()).decode()
    req = urllib.request.Request(url, headers=headers)

    def _decode(raw, ctype):
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:  # noqa: BLE001
                pass
        m = re.search(r"charset=([\w-]+)", ctype or "", re.I)
        try:
            return raw.decode(m.group(1) if m else "utf-8", "replace")
        except LookupError:
            return raw.decode("utf-8", "replace")
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT) as r:
            return r.status, _decode(r.read(), r.headers.get("content-type")), None
    except urllib.error.HTTPError as e:
        try:
            body = _decode(e.read(), (e.headers or {}).get("content-type"))
        except Exception:  # noqa: BLE001
            body = None
        return e.code, body, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — DNS/timeout/proxy: tri-state, never raise
        return None, None, f"{type(e).__name__}: {e}"


def _json(url, **kw):
    """GET JSON -> (data|None, error|None, status)."""
    status, text, err = _http(url, **kw)
    if err:
        return None, err, status
    try:
        return json.loads(text or "null"), None, status
    except ValueError as e:
        return None, f"bad JSON: {e}", status


def _record(provider, action, query, results, ok, credits):
    if api_usage is not None:
        try:
            api_usage.record(provider, action, credits=credits, query=query, results=results, ok=ok)
        except Exception:  # noqa: BLE001
            pass


def _pv(status, url=None, results=None, **kw):
    d = {"status": status, "url": url, "results": results or []}
    d.update({k: v for k, v in kw.items() if v is not None})
    return d


# ============================================================================ record builders
def officer_row(name, provider, source_url=None, **f):
    row = {"name": name, "role": None, "appointed": None, "resigned": None,
           "birth_month_year": None, "nationality": None, "country_of_residence": None,
           "correspondence_address": None, "other_appointments_url": None,
           "source_url": source_url, "provider": provider}
    for k, v in f.items():
        if v not in (None, "", []):
            row[k] = v
    row["birth_month_year"] = norm_birth(row["birth_month_year"]) or row["birth_month_year"]
    row["rung"] = "lead"
    row["caveat"] = CAVEATS["officer"]
    flags = agent_flags(row.get("correspondence_address"))
    if flags:
        row["address_flags"] = flags
        row["address_caveat"] = CAVEATS["formation_agent"]
    return row


def company_row(provider, name, number, jurisdiction, source_url=None, **f):
    c = {"name": name, "number": number, "jurisdiction": jurisdiction, "status": None,
         "incorporated": None, "dissolved": None, "registered_address": None,
         "address_history": [], "officers": [], "source_url": source_url, "provider": provider}
    for k, v in f.items():
        if v not in (None, "", []):
            c[k] = v
    flags = agent_flags(c.get("registered_address"))
    if flags:
        c["address_flags"] = flags
        c["address_caveat"] = CAVEATS["formation_agent"]
    return c


def _pointer(c):
    return {"name": c.get("name"), "number": c.get("number"), "source_url": c.get("source_url")}


# ============================================================================ GLEIF
def gleif_parse_record(rec: dict) -> dict:
    a = (rec or {}).get("attributes") or {}
    e = a.get("entity") or {}
    lei = a.get("lei") or rec.get("id")
    cfg = PROVIDERS.get("gleif") or {}

    def addr(x):
        x = x or {}
        return _join(", ".join(x.get("addressLines") or []), x.get("city"), x.get("region"),
                     x.get("postalCode"), x.get("country"))
    reg = a.get("registration") or {}
    return company_row(
        "gleif", (e.get("legalName") or {}).get("name"), e.get("registeredAs"), e.get("jurisdiction"),
        _fmt(cfg.get("public_url", ""), lei=lei) if cfg.get("public_url") else None,
        status=e.get("status"), incorporated=(e.get("creationDate") or "")[:10] or None,
        dissolved=((e.get("expiration") or {}).get("date") or "")[:10] or None,
        registered_address=addr(e.get("legalAddress")), lei=lei,
        hq_address=addr(e.get("headquartersAddress")),
        registration_authority_id=(e.get("registeredAt") or {}).get("id"),
        legal_form_id=(e.get("legalForm") or {}).get("id"),
        lei_status=reg.get("status"),
        other_names=[n.get("name") for n in e.get("otherNames") or [] if n.get("name")])


def _gleif_rel(lei, key, size=None):
    cfg = PROVIDERS["gleif"]
    tpl = cfg.get(key)
    if not tpl:
        return None, "no endpoint"
    url = _fmt(tpl, lei=lei, size=size or SETTINGS["gleif_children_max"])
    data, err, status = _json(url, accept="application/vnd.api+json")
    if status == 404:
        return None, None            # no relationship reported (exception / natural person parent)
    if err:
        return None, err
    d = (data or {}).get("data")
    pick = lambda r: {"lei": r.get("id"), "name": ((r.get("attributes") or {}).get("entity") or {})
                      .get("legalName", {}).get("name"),
                      "jurisdiction": ((r.get("attributes") or {}).get("entity") or {}).get("jurisdiction")}
    if isinstance(d, list):
        return [pick(r) for r in d], None
    return (pick(d) if isinstance(d, dict) else None), None


def gleif_search(query, iso=None):
    cfg = PROVIDERS.get("gleif")
    if not cfg:
        return _pv("skipped", reason="gleif not configured"), []
    q = query.strip()
    if re.fullmatch(r"[A-Z0-9]{18}[0-9]{2}", q.upper()):
        url = _fmt(cfg["record"], lei=q.upper())
        data, err, status = _json(url, accept="application/vnd.api+json")
        if status == 404:
            return _pv("empty", url), []
        if err:
            return _pv("error", url, error=err), []
        recs = [data.get("data")] if data and data.get("data") else []
    else:
        # exact legal-name match first (fulltext ranking buries the parent under subsidiaries),
        # then the configured fulltext/number search; deduplicated by LEI.
        tpls = [cfg["search_number"]] if _is_number_like(q) else \
            [t for t in (cfg.get("search_exact"), cfg["search_name"]) if t]
        recs, seen, url, errs = [], set(), None, []
        for tpl in tpls:
            u = _fmt(tpl, query=q, size=SETTINGS["max_results"])
            if iso and cfg.get("jurisdiction_filter"):
                u += _fmt(cfg["jurisdiction_filter"], jurisdiction=iso)
            url = url or u
            data, err, _ = _json(u, accept="application/vnd.api+json")
            if err:
                errs.append(err)
                continue
            for r in (data or {}).get("data") or []:
                if r.get("id") not in seen:
                    seen.add(r.get("id"))
                    recs.append(r)
        if errs and not recs:
            return _pv("error", url, error="; ".join(errs)), []
    comps = [gleif_parse_record(r) for r in recs][:int(SETTINGS["max_results"])]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps]), comps


def gleif_detail(c):
    lei = c.get("lei")
    if not lei:
        return
    rel, errs = {}, {}
    for key in ("direct_parent", "ultimate_parent", "direct_children"):
        v, err = _gleif_rel(lei, key)
        rel[key] = v if v is not None else ([] if key == "direct_children" else None)
        if err:
            errs[key] = err
    c["relationships"] = rel
    if errs:
        c["relationship_errors"] = errs
    c["officers_note"] = "GLEIF carries legal entities and parent/child links, not officers."


# ============================================================================ Companies House
def _ch_cfg():
    return PROVIDERS.get("companies_house") or {}


def _ch_key():
    return _secret(*(_ch_cfg().get("key_env") or ["COMPANIES_HOUSE_API_KEY"]))


def _ch_site(path_key, **kw):
    cfg = _ch_cfg()
    return cfg["site"] + _fmt(cfg[path_key], **kw)


def _ch_api(path_key, **kw):
    cfg = _ch_cfg()
    url = cfg["api"] + _fmt(cfg[path_key], **kw)
    data, err, status = _json(url, auth_user=_ch_key())
    _record("companies_house", path_key, kw.get("query") or kw.get("number") or kw.get("officer_id"),
            None, err is None or status == 404, 0)
    return url, data, err, status


def _ch_results_block(html_text):
    """The live results list only — the page also embeds a mustache template with the same classes."""
    i = html_text.find("id='results'")
    if i < 0:
        i = html_text.find('id="results"')
    return html_text[i:] if i >= 0 else ""


def ch_parse_company_search(html_text):
    site = _ch_cfg().get("site", "")
    out = []
    for li in re.findall(r'<li class="type-company">(.*?)</li>', _ch_results_block(html_text), re.S):
        m = re.search(r'href="/company/([A-Z0-9]+)"[^>]*>(.*?)</a>', li, re.S)
        if not m:
            continue
        num, name = m.group(1), _txt(m.group(2))
        metas = [_txt(x) for x in re.findall(r'<p class="meta crumbtrail">(.*?)</p>', li, re.S)]
        ps = [_txt(x) for x in re.findall(r"<p>(.*?)</p>", li, re.S)]
        meta = metas[0] if metas else ""
        inc = re.search(r"Incorporated on (\d{1,2} \w+ \d{4})", meta)
        dis = re.search(r"Dissolved on (\d{1,2} \w+ \d{4})", meta)
        prev = re.search(r"Matching previous names:\s*(.*?)</p>", li, re.S)
        out.append(company_row(
            "companies_house", name, num, "GB", site + "/company/" + num,
            incorporated=inc.group(1) if inc else None, dissolved=dis.group(1) if dis else None,
            status="dissolved" if dis else None, registered_address=ps[-1] if ps else None,
            matched_previous_name=_txt(prev.group(1)) if prev else None))
    return out


def ch_parse_company_profile(html_text):
    def by_id(i):
        m = re.search(r'id="%s"[^>]*>(.*?)</(?:dd|p|span|h1|div)>' % re.escape(i), html_text, re.S)
        return _txt(m.group(1)) if m else None

    def by_dt(label):
        m = re.search(r"<dt[^>]*>\s*%s\s*</dt>\s*<dd[^>]*>(.*?)</dd>" % re.escape(label),
                      html_text, re.S | re.I)
        return _txt(m.group(1)) if m else None
    name = re.search(r'<h1 class="heading-xlarge"[^>]*>(.*?)</h1>', html_text, re.S)
    num = by_id("company-number")
    prev = []
    for n, d in re.findall(r'id="previous-name-\d+"[^>]*>(.*?)</td>\s*<td id="previous-date-\d+"[^>]*>(.*?)</td>',
                           html_text, re.S):
        prev.append({"name": _txt(n), "period": _txt(d)})
    return {"name": _txt(name.group(1)) if name else None,
            "number": re.sub(r"(?i)^company number\s*", "", num or "") or None,
            "registered_address": by_id("roa-address"), "status": by_id("company-status"),
            "company_type": by_id("company-type"),
            "incorporated": by_id("company-creation-date"),
            "dissolved": by_dt("Dissolved on") or by_id("cessation-date"),
            "previous_names": prev}


def ch_parse_officers(html_text, page_url=None):
    site = _ch_cfg().get("site", "")
    rows = []
    parts = re.split(r'<div class="appointment-(\d+)">', html_text)
    for i in range(1, len(parts) - 1, 2):
        n, chunk = parts[i], parts[i + 1]
        m = re.search(r'id="officer-name-%s"[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>' % n, chunk, re.S)
        if not m:
            continue
        f = {}
        for prefix, field in CH_OFFICER_FIELDS.items():
            mm = re.search(r'id="%s-%s"[^>]*>(.*?)</dd>' % (re.escape(prefix), n), chunk, re.S)
            if mm and _txt(mm.group(1)):
                f[field] = _txt(mm.group(1))
        st = re.search(r'id="officer-status-tag-%s"[^>]*>(.*?)</span>' % n, chunk, re.S)
        if st:
            f["status"] = _txt(st.group(1))
        href = m.group(1)
        rows.append(officer_row(_txt(m.group(2)), "companies_house", page_url,
                                other_appointments_url=site + href if href.startswith("/") else href,
                                officer_id=(re.search(r"/officers/([^/]+)/", href) or [None, None])[1],
                                **f))
    return rows


def ch_parse_address_history(html_text, source_url=None):
    hist = []
    for td in re.findall(r"<td[^>]*>(.*?)</td>", html_text, re.S):
        t = _txt(td)
        for rx in ADDR_CHANGE_RES:
            m = rx.search(t)
            if m:
                hist.append({"from": m.group("old").strip(), "to": m.group("new").strip(),
                             "date": m.group("date"), "source_url": source_url,
                             "from_flags": agent_flags(m.group("old")) or None})
                break
    return hist


def ch_parse_officer_search(html_text):
    site = _ch_cfg().get("site", "")
    out = []
    for li in re.findall(r'<li class="type-officer">(.*?)</li>', _ch_results_block(html_text), re.S):
        m = re.search(r'href="(/officers/([^/"]+)/appointments)"[^>]*>(.*?)</a>', li, re.S)
        if not m:
            continue
        meta = " ".join(_txt(x) for x in re.findall(r'<p class="meta crumbtrail">(.*?)</p>', li, re.S))
        ps = [_txt(x) for x in re.findall(r"<p>(.*?)</p>", li, re.S)]
        born = re.search(r"Born (\w+ \d{4})", meta)
        cnt = re.search(r"appointments (\d+)", meta)
        out.append({"name": _txt(m.group(3)), "officer_id": m.group(2),
                    "birth_month_year": norm_birth(born.group(1)) if born else None,
                    "address": ps[-1] if ps else None,
                    "appointment_count": int(cnt.group(1)) if cnt else None,
                    "other_appointments_url": site + m.group(1), "source_url": site + m.group(1),
                    "provider": "companies_house"})
    return out


def ch_parse_appointments(html_text, source_url=None):
    site = _ch_cfg().get("site", "")
    name = re.search(r'id="officer-name"[^>]*>(.*?)</', html_text, re.S)
    dob = re.search(r'id="officer-date-of-birth-value"[^>]*>(.*?)</', html_text, re.S)
    total = re.search(r'id="personal-appointments"[^>]*>(.*?)</', html_text, re.S)
    appts = []
    for n, inner in re.findall(r'id="company-name-(\d+)"[^>]*>(.*?)</(?:h2|span|div)>', html_text, re.S):
        a = re.search(r'href="/company/([A-Z0-9]+)"[^>]*>(.*?)</a>', inner + "</a>", re.S)
        cname = _txt(a.group(2)) if a else _txt(inner)
        cnum = a.group(1) if a else None
        if cnum:
            cname = re.sub(r"\s*\(%s\)\s*$" % re.escape(cnum), "", cname)
        ap = {"company_name": cname, "company_number": cnum,
              "company_url": site + "/company/" + cnum if cnum else None}
        for prefix, field in CH_APPT_FIELDS.items():
            mm = re.search(r'id="%s-?%s"[^>]*>(.*?)</' % (re.escape(prefix), n), html_text, re.S)
            if mm and _txt(mm.group(1)):
                ap[field] = _txt(mm.group(1))
        ap["source_url"] = source_url
        flags = agent_flags(ap.get("correspondence_address"))
        if flags:
            ap["address_flags"] = flags
        appts.append(ap)
    tot = re.search(r"(\d+)", _txt(total.group(1))) if total else None
    return {"name": _txt(name.group(1)) if name else None,
            "birth_month_year": norm_birth(_txt(dob.group(1))) if dob else None,
            "total_appointments": int(tot.group(1)) if tot else None,
            "appointments": appts}


# --- CH REST API normalisers
def _ch_api_addr(a):
    a = a or {}
    return _join(a.get("care_of") and "c/o " + a["care_of"], a.get("premises"), a.get("address_line_1"),
                 a.get("address_line_2"), a.get("locality"), a.get("region"), a.get("postal_code"),
                 a.get("country"))


def _ch_api_officer(it, company_url):
    site = _ch_cfg().get("site", "")
    link = ((it.get("links") or {}).get("officer") or {}).get("appointments")
    return officer_row(it.get("name"), "companies_house", company_url,
                       role=it.get("officer_role"), appointed=it.get("appointed_on"),
                       resigned=it.get("resigned_on"), birth_month_year=norm_birth(it.get("date_of_birth")),
                       nationality=it.get("nationality"), country_of_residence=it.get("country_of_residence"),
                       occupation=it.get("occupation"), correspondence_address=_ch_api_addr(it.get("address")),
                       other_appointments_url=site + link if link else None,
                       officer_id=(re.search(r"/officers/([^/]+)/", link or "") or [None, None])[1])


def ch_search(query, iso=None):
    cfg = _ch_cfg()
    if not cfg:
        return _pv("skipped", reason="companies_house not configured"), []
    q = query.strip()
    if _ch_key():
        num = re.sub(r"\s", "", q).upper()
        if re.fullmatch(r"[A-Z]{0,2}\d{6,8}", num):
            url, data, err, status = _ch_api("api_company", number=num.zfill(8))
            if status == 404:
                return _pv("empty", url, via="api"), []
            if err:
                return _pv("error", url, error=err, via="api"), []
            items = [data]
        else:
            url, data, err, _ = _ch_api("api_search_companies", query=q, size=SETTINGS["max_results"])
            if err:
                return _pv("error", url, error=err, via="api"), []
            items = (data or {}).get("items") or []
        comps = []
        for it in items[:int(SETTINGS["max_results"])]:
            num = it.get("company_number")
            comps.append(company_row(
                "companies_house", it.get("company_name") or it.get("title"), num, "GB",
                cfg["site"] + "/company/" + str(num), status=it.get("company_status"),
                incorporated=it.get("date_of_creation"), dissolved=it.get("date_of_cessation"),
                registered_address=_ch_api_addr(it.get("registered_office_address")) or
                it.get("address_snippet"),
                previous_names=[{"name": p.get("name"), "period": _period(p.get("effective_from"), p.get("ceased_on"))}
                                for p in it.get("previous_company_names") or []]))
        return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps], via="api"), comps
    num = re.sub(r"\s", "", q).upper()
    if re.fullmatch(r"[A-Z]{0,2}\d{6,8}", num):
        num = num.zfill(8) if num.isdigit() else num
        url = _ch_site("company", number=num)
        status, text, err = _http(url, accept="text/html")
        if status == 404:
            return _pv("empty", url, via="html"), []
        if err:
            return _pv("error", url, error=err, via="html"), []
        p = ch_parse_company_profile(text)
        if not p.get("name"):
            return _pv("empty", url, via="html"), []
        comps = [company_row("companies_house", p["name"], p.get("number") or num, "GB", url,
                             **{k: v for k, v in p.items() if k not in ("name", "number")})]
        comps[0]["_profiled"] = True
        return _pv("ok", url, [_pointer(comps[0])], via="html"), comps
    url = _ch_site("search_companies", query=q)
    status, text, err = _http(url, accept="text/html")
    if err:
        return _pv("error", url, error=err, via="html"), []
    comps = ch_parse_company_search(text)[:int(SETTINGS["max_results"])]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps], via="html"), comps


def ch_detail(c):
    """Profile (status, dissolved, previous names), officers, registered-address history."""
    num = c.get("number")
    errs = {}
    if _ch_key():
        if not c.get("_profiled"):
            url, data, err, _ = _ch_api("api_company", number=num)
            if data and not err:
                c["status"] = data.get("company_status") or c.get("status")
                c["dissolved"] = data.get("date_of_cessation") or c.get("dissolved")
                c["registered_address"] = _ch_api_addr(data.get("registered_office_address")) or c.get("registered_address")
                c["previous_names"] = [{"name": p.get("name"), "period": _period(p.get("effective_from"), p.get("ceased_on"))}
                                       for p in data.get("previous_company_names") or []]
            elif err:
                errs["profile"] = err
        url, data, err, _ = _ch_api("api_officers", number=num)
        if err:
            errs["officers"] = err
        else:
            c["officers"] = [_ch_api_officer(it, c.get("source_url")) for it in (data or {}).get("items") or []]
        url, data, err, _ = _ch_api("api_address_filings", number=num)
        if err:
            errs["address_history"] = err
        else:
            hist = []
            for it in (data or {}).get("items") or []:
                dv = it.get("description_values") or {}
                if dv.get("old_address"):
                    hist.append({"from": dv.get("old_address"), "to": dv.get("new_address"),
                                 "date": dv.get("change_date") or it.get("date"), "source_url": url,
                                 "from_flags": agent_flags(dv.get("old_address")) or None})
            c["address_history"] = hist
    else:
        if not c.get("_profiled"):
            url = _ch_site("company", number=num)
            _, text, err = _http(url, accept="text/html")
            if err:
                errs["profile"] = err
            else:
                p = ch_parse_company_profile(text)
                for k in ("status", "dissolved", "registered_address", "company_type", "incorporated"):
                    if p.get(k):
                        c[k] = p[k]
                if p.get("previous_names"):
                    c["previous_names"] = p["previous_names"]
        officers = []
        for page in range(1, int(SETTINGS["officer_pages"]) + 1):
            url = _ch_site("officers", number=num, page=page)
            _, text, err = _http(url, accept="text/html")
            if err:
                errs["officers"] = err
                break
            rows = ch_parse_officers(text, url)
            officers += rows
            if not rows or f"page={page + 1}" not in text:
                break
        c["officers"] = officers
        url = _ch_site("address_filings", number=num)
        _, text, err = _http(url, accept="text/html")
        if err:
            errs["address_history"] = err
        else:
            c["address_history"] = ch_parse_address_history(text, url)
    c.pop("_profiled", None)
    for h in c.get("address_history") or []:
        if not h.get("from_flags"):
            h.pop("from_flags", None)
    if errs:
        c["detail_errors"] = errs


def ch_officer_search(name):
    cfg = _ch_cfg()
    if not cfg:
        return _pv("skipped", reason="companies_house not configured"), []
    if _ch_key():
        url, data, err, _ = _ch_api("api_search_officers", query=name, size=SETTINGS["max_results"] * 2)
        if err:
            return _pv("error", url, error=err, via="api"), []
        cands = []
        for it in (data or {}).get("items") or []:
            link = (it.get("links") or {}).get("self")
            cands.append({"name": it.get("title"), "officer_id": (re.search(r"/officers/([^/]+)/", link or "") or [None, None])[1],
                          "birth_month_year": norm_birth(it.get("date_of_birth")),
                          "address": it.get("address_snippet"), "appointment_count": it.get("appointment_count"),
                          "other_appointments_url": cfg["site"] + link if link else None,
                          "source_url": cfg["site"] + link if link else None, "provider": "companies_house"})
        return _pv("ok" if cands else "empty", url, via="api"), cands
    url = _ch_site("search_officers", query=name)
    _, text, err = _http(url, accept="text/html")
    if err:
        return _pv("error", url, error=err, via="html"), []
    cands = ch_parse_officer_search(text)
    return _pv("ok" if cands else "empty", url, via="html"), cands


def ch_appointments(officer_id):
    cfg = _ch_cfg()
    if _ch_key():
        url, data, err, status = _ch_api("api_appointments", officer_id=officer_id)
        if err:
            return _pv("error", url, error=err, via="api"), None
        appts = []
        for it in (data or {}).get("items") or []:
            to = it.get("appointed_to") or {}
            ap = {"company_name": to.get("company_name"), "company_number": to.get("company_number"),
                  "company_status": to.get("company_status"),
                  "company_url": cfg["site"] + "/company/" + str(to.get("company_number")),
                  "role": it.get("officer_role"), "appointed": it.get("appointed_on"),
                  "resigned": it.get("resigned_on"), "nationality": it.get("nationality"),
                  "country_of_residence": it.get("country_of_residence"),
                  "correspondence_address": _ch_api_addr(it.get("address")), "source_url": url}
            if agent_flags(ap["correspondence_address"]):
                ap["address_flags"] = agent_flags(ap["correspondence_address"])
            appts.append(ap)
        card = {"name": (data or {}).get("name"), "birth_month_year": norm_birth((data or {}).get("date_of_birth")),
                "total_appointments": (data or {}).get("total_results"), "appointments": appts}
    else:
        url = cfg["site"] + _fmt(cfg["appointments"], officer_id=officer_id)
        status, text, err = _http(url, accept="text/html")
        if err:
            return _pv("error", url, error=err, via="html"), None
        card = ch_parse_appointments(text, url)
    card.update({"officer_id": officer_id, "provider": "companies_house",
                 "source_url": cfg["site"] + _fmt(cfg["appointments"], officer_id=officer_id)})
    return _pv("ok" if card.get("appointments") else "empty", url,
               [{"company_name": a["company_name"], "company_number": a["company_number"]}
                for a in card["appointments"]]), card


# ============================================================================ OpenCorporates
def _oc_cfg():
    return PROVIDERS.get("opencorporates") or {}


def _oc_token():
    return _secret(*(_oc_cfg().get("key_env") or ["OPENCORPORATES_API_TOKEN"]))


def _oc_get(path_key, extra="", **kw):
    """PREMIUM API (secondary path) -> (url_without_token, data, provider_block_on_failure|None).
    Never called without OPENCORPORATES_API_TOKEN — the free path is the website (below)."""
    cfg = _oc_cfg()
    if not cfg:
        return None, None, _pv("skipped", reason="opencorporates not configured")
    url = cfg["api"] + _fmt(cfg[path_key], **kw) + extra
    tok = _oc_token()
    if not tok:
        return url, None, _pv("skipped", url, reason="no OPENCORPORATES_API_TOKEN (premium API) set")
    full = url + ("&" if "?" in url else "?") + "api_token=" + _q(tok)
    data, err, status = _json(full)
    _record("opencorporates", path_key, kw.get("query") or kw.get("number") or kw.get("officer_id"),
            None, err is None, 1 if cfg.get("metered", True) else 0)
    if err:
        return url, None, _pv("error", url, error=err, via="api")
    return url, (data or {}).get("results") or {}, None


def _oc_company(co):
    co = co or {}
    offs = []
    for w in co.get("officers") or []:
        o = w.get("officer") or w
        offs.append(officer_row(o.get("name"), "opencorporates", co.get("opencorporates_url"),
                                role=o.get("position"), appointed=o.get("start_date"),
                                resigned=o.get("end_date"), nationality=o.get("nationality"),
                                occupation=o.get("occupation"),
                                other_appointments_url=o.get("opencorporates_url"),
                                officer_id=o.get("id")))
    hist = [{"from": a.get("registered_address_in_full") or a.get("street_address"), "to": None,
             "date": a.get("end_date"), "source_url": co.get("opencorporates_url")}
            for a in co.get("previous_registered_addresses") or [] if isinstance(a, dict)]
    return company_row("opencorporates", co.get("name"), co.get("company_number"),
                       co.get("jurisdiction_code"), co.get("opencorporates_url"),
                       status=co.get("current_status"), incorporated=co.get("incorporation_date"),
                       dissolved=co.get("dissolution_date"),
                       registered_address=co.get("registered_address_in_full"),
                       previous_names=[{"name": p.get("company_name"), "period": _period(p.get("start_date"), p.get("end_date"))}
                                       for p in co.get("previous_names") or []],
                       address_history=hist, officers=offs)


def oc_api_search(query, oc_jur=None):
    extra = _fmt(_oc_cfg().get("jurisdiction_param", ""), jurisdiction=oc_jur) if oc_jur else ""
    url, res, fail = _oc_get("search_companies", extra, query=query, size=SETTINGS["max_results"])
    if fail:
        return fail, []
    comps = [_oc_company(w.get("company")) for w in res.get("companies") or []]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps], via="api"), comps


def oc_api_company(oc_jur, number):
    url, res, fail = _oc_get("company", jurisdiction=oc_jur, number=number)
    if fail:
        return fail, []
    c = _oc_company(res.get("company"))
    return (_pv("ok" if c.get("name") else "empty", url, [_pointer(c)], via="api"),
            [c] if c.get("name") else [])


def oc_api_officer_search(name, oc_jur=None):
    extra = _fmt(_oc_cfg().get("jurisdiction_param", ""), jurisdiction=oc_jur) if oc_jur else ""
    url, res, fail = _oc_get("search_officers", extra, query=name, size=SETTINGS["max_results"] * 2)
    if fail:
        return fail, []
    cands = []
    for w in res.get("officers") or []:
        o = w.get("officer") or {}
        co = o.get("company") or {}
        cands.append({"name": o.get("name"), "officer_id": o.get("id"), "role": o.get("position"),
                      "birth_month_year": norm_birth(o.get("date_of_birth")),
                      "address": o.get("address"), "nationality": o.get("nationality"),
                      "companies": [{"name": co.get("name"), "number": co.get("company_number"),
                                     "jurisdiction": co.get("jurisdiction_code")}] if co else [],
                      "appointed": o.get("start_date"), "resigned": o.get("end_date"),
                      "other_appointments_url": o.get("opencorporates_url"),
                      "source_url": o.get("opencorporates_url"), "provider": "opencorporates"})
    return _pv("ok" if cands else "empty", url, via="api"), cands


def oc_api_officer(officer_id):
    url, res, fail = _oc_get("officer", officer_id=officer_id)
    if fail:
        return fail, None
    o = res.get("officer") or {}
    co = o.get("company") or {}
    card = {"name": o.get("name"), "officer_id": officer_id, "provider": "opencorporates",
            "birth_month_year": norm_birth(o.get("date_of_birth")), "source_url": o.get("opencorporates_url"),
            "appointments": [{"company_name": co.get("name"), "company_number": co.get("company_number"),
                              "jurisdiction": co.get("jurisdiction_code"), "role": o.get("position"),
                              "appointed": o.get("start_date"), "resigned": o.get("end_date"),
                              "correspondence_address": o.get("address"),
                              "source_url": o.get("opencorporates_url")}] if co else [],
            "note": "OpenCorporates officer records are per-appointment; search the same name for siblings."}
    return _pv("ok" if card["name"] else "empty", url, via="api"), card


# ---------------------------------------------------------------- OpenCorporates FREE WEBSITE
# One CloakBrowser per run (closed by run()'s finally), a reused storage_state session kept
# outside the repo, credentials only from env/.env. See references/corp_registry.json ->
# opencorporates_web for every tunable and the reasoning.
_OC_WEB_FALLBACK = {
    "site": "https://opencorporates.com", "signin": "/users/sign_in",
    "search_companies": "/companies{jur_path}?q={query}", "search_officers": "/officers{jur_path}?q={query}",
    "company": "/companies/{jurisdiction}/{number}", "officer": "/officers/{officer_id}",
    "email_env": "OPENCORPORATES_EMAIL", "password_env": "OPENCORPORATES_PASSWORD",
    "session_env": "OPENCORPORATES_SESSION",
    "session_path": "~/.config/cti-expert/sessions/opencorporates.json",
    "email_selector": "input[name='user[email]'], input[type=email]",
    "password_selector": "input[name='user[password]'], input[type=password]",
    "submit_selector": "button[type=submit], input[type=submit]",
    "gate_markers": ["Checking your browser"], "logged_in_markers": ["/users/sign_out"],
    "login_error_markers": ["Invalid Email or password"],
    "delay_seconds": 2.5, "captcha_wait_seconds": 20, "goto_timeout_ms": 60000, "detail_max": 2,
    "headless": True, "humanize": True, "use_process_proxy": False,
}
OC_WEB = {**_OC_WEB_FALLBACK, **(_REFS.get("opencorporates_web") or {})}
_OCW = {}


def _oc_creds():
    return _secret(OC_WEB["email_env"]), _secret(OC_WEB["password_env"])


def oc_session_path() -> str:
    return os.path.expanduser(os.environ.get(OC_WEB["session_env"]) or OC_WEB["session_path"])


def oc_web_available() -> bool:
    """cloakbrowser importable in THIS interpreter (offline check, nothing imported)."""
    import importlib.util
    try:
        return importlib.util.find_spec("cloakbrowser") is not None
    except Exception:  # noqa: BLE001
        return False


def oc_web_configured() -> bool:
    """Website mode can sign in: cloakbrowser present AND (saved session OR email+password)."""
    email, pw = _oc_creds()
    return oc_web_available() and (os.path.isfile(oc_session_path()) or bool(email and pw))


def _scrub(text) -> str:
    """Remove the credential values from any string that may reach output."""
    s = str(text or "")
    for v in _oc_creds():
        if v:
            s = s.replace(v, "***")
    return s


def _mask_email(e) -> str:
    e = str(e or "")
    if "@" not in e:
        return "***"
    user, dom = e.split("@", 1)
    return f"{user[:1]}***@{dom[:1]}***{dom[dom.rfind('.'):] if '.' in dom else ''}"


def _oc_open():
    """-> (page, None) | (None, reason). Launches once per run."""
    if _OCW.get("error"):
        return None, _OCW["error"]
    if _OCW.get("page") is not None:
        return _OCW["page"], None
    try:
        import cloakbrowser  # noqa: E402 — OPTIONAL dependency
    except ImportError:
        _OCW["error"] = ("cloakbrowser not installed in this interpreter — run with the repo "
                         ".venv/bin/python3 (or `pip install cloakbrowser` + `cloakbrowser login`)")
        return None, _OCW["error"]
    kw = {"headless": bool(OC_WEB.get("headless", True)), "humanize": bool(OC_WEB.get("humanize", True))}
    pcfg = None
    if OC_WEB.get("use_process_proxy"):
        try:
            import wp_browser
            pcfg = wp_browser.proxy_for_chromium(None)
        except Exception:  # noqa: BLE001
            pcfg = None
    if pcfg:
        kw["proxy"] = pcfg
    else:
        kw["args"] = ["--no-proxy-server"]
    if os.environ.get("CLOAKBROWSER_LICENSE_KEY"):
        kw["license_key"] = os.environ["CLOAKBROWSER_LICENSE_KEY"]
    try:
        b = cloakbrowser.launch(**kw)
        sp = oc_session_path()
        ctx_kw = {"user_agent": UA}
        if os.path.isfile(sp):
            ctx_kw["storage_state"] = sp
        ctx = b.new_context(**ctx_kw)
        _OCW.update(browser=b, ctx=ctx, page=ctx.new_page(), last=0.0)
    except Exception as e:  # noqa: BLE001
        _OCW["error"] = _scrub(f"cloakbrowser launch failed: {type(e).__name__}: {e}")
        return None, _OCW["error"]
    return _OCW["page"], None


def _oc_save_session():
    ctx = _OCW.get("ctx")
    if ctx is None or not _OCW.get("logged_in"):
        return
    sp = oc_session_path()
    try:
        os.makedirs(os.path.dirname(sp), mode=0o700, exist_ok=True)
        ctx.storage_state(path=sp)
        os.chmod(sp, 0o600)
    except Exception:  # noqa: BLE001
        pass


def _oc_close():
    b = _OCW.get("browser")
    _oc_save_session()
    _OCW.clear()
    if b is not None:
        try:
            b.close()
        except Exception:  # noqa: BLE001
            pass


def _oc_content(page):
    import time
    for _ in range(6):
        try:
            page.wait_for_load_state("domcontentloaded")
            return page.content()
        except Exception:  # noqa: BLE001 — still navigating; retry
            time.sleep(1.5)
    try:
        return page.content()
    except Exception:  # noqa: BLE001
        return ""


def _has(html_text, markers):
    return any(m in (html_text or "") for m in markers or [])


def oc_is_gated(html_text) -> bool:
    return _has(html_text, OC_WEB.get("gate_markers"))


def oc_is_logged_in(html_text) -> bool:
    return _has(html_text, OC_WEB.get("logged_in_markers"))


def _oc_goto(url):
    """Paced load -> (html, None) | (None, 'gated'|reason). A gate that does not clear within
    captcha_wait_seconds stops every further OpenCorporates load for the run."""
    import time
    if _OCW.get("stopped"):
        return None, _OCW["stopped"]
    page, err = _oc_open()
    if err:
        return None, err
    wait = float(OC_WEB.get("delay_seconds") or 0) - (time.time() - _OCW.get("last", 0.0))
    if wait > 0:
        time.sleep(wait)
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=int(OC_WEB.get("goto_timeout_ms") or 60000))
    except Exception as e:  # noqa: BLE001
        _OCW["last"] = time.time()
        return None, _scrub(f"{type(e).__name__}: {e}")
    html_text = _oc_content(page)
    deadline = time.time() + float(OC_WEB.get("captcha_wait_seconds") or 0)
    while oc_is_gated(html_text) and time.time() < deadline:
        time.sleep(2)
        html_text = _oc_content(page)
    _OCW["last"] = time.time()
    if oc_is_gated(html_text):
        _OCW["gated_url"] = url
        if _OCW.get("logged_in"):
            _OCW["stopped"] = "gated"
        return None, "gated"
    if oc_is_logged_in(html_text):
        _OCW["logged_in"] = True
    return html_text, None


def _oc_login():
    """Sign in with the env/.env credentials -> (ok, reason). Saves the session on success."""
    import time
    email, pw = _oc_creds()
    _OCW["login_tried"] = True
    if not (email and pw):
        return False, f"no {OC_WEB['email_env']} / {OC_WEB['password_env']} set"
    html_text, err = _oc_goto(OC_WEB["site"] + OC_WEB["signin"])
    if err:
        return False, f"sign-in page: {err}"
    if oc_is_logged_in(html_text):
        return True, "already signed in"
    page = _OCW["page"]
    try:
        page.fill(OC_WEB["email_selector"], email)
        page.fill(OC_WEB["password_selector"], pw)
        page.click(OC_WEB["submit_selector"])
        try:
            page.wait_for_load_state("domcontentloaded", timeout=30000)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(3)
    except Exception as e:  # noqa: BLE001
        return False, _scrub(f"sign-in form: {type(e).__name__}: {e}")
    html_text = _oc_content(page)
    if _has(html_text, OC_WEB.get("login_error_markers")):
        return False, "sign-in rejected (invalid email or password)"
    if not oc_is_logged_in(html_text):
        html_text, err = _oc_goto(OC_WEB["site"] + "/")
        if err or not oc_is_logged_in(html_text):
            return False, "sign-in did not produce a signed-in page" + (f" ({err})" if err else "")
    _OCW["logged_in"] = True
    _oc_save_session()
    return True, "signed in"


def _oc_fetch(url):
    """Load `url` signed-in when possible -> (html|None, err|None, mode 'session'|'anonymous').
    A logged-out page triggers ONE re-login when credentials exist, then the page is reloaded."""
    fresh = not os.path.isfile(oc_session_path())
    if fresh and not _OCW.get("login_tried") and all(_oc_creds()):
        ok, why = _oc_login()                      # no saved session: sign in before the first page
        _OCW["login_result"] = why
    html_text, err = _oc_goto(url)
    if not _OCW.get("logged_in") and not _OCW.get("login_tried") and all(_oc_creds()):
        ok, why = _oc_login()                      # saved session expired: one re-login
        _OCW["login_result"] = why
        if ok:
            html_text, err = _oc_goto(url)
    return html_text, err, ("session" if _OCW.get("logged_in") else "anonymous")


def _oc_web_pv(status, url, results=None, mode=None, **kw):
    pv = _pv(status, url, results, via="website", session=mode, **kw)
    if _OCW.get("login_result") and not _OCW.get("logged_in"):
        pv["login"] = _OCW["login_result"]
    return pv


def _oc_gate_pv(url, mode, err):
    if err == "gated":
        return _oc_web_pv("gated", url, mode=mode, gated="recaptcha", collection_gap=True,
                          note=("reCAPTCHA gate did not clear — a collection GAP, not a negative. "
                                + ("Run `wp_corp.py opencorporates-login` so searches run signed in."
                                   if mode == "anonymous" else "Stopped further OpenCorporates loads this run.")))
    return _oc_web_pv("error", url, mode=mode, error=_scrub(err))


_OC_COMPANY_HREF = re.compile(r"/companies/([a-z]{2}(?:_[a-z]{2})?)/([^\"/?#]+)")


def oc_web_parse_search(html_text):
    site = OC_WEB["site"]
    out = []
    for cls, li in re.findall(r'<li class="search-result company([^"]*)">(.*?)</li>', html_text or "", re.S):
        a = re.search(r'<a class="company_search_result[^"]*" href="([^"]+)"[^>]*>(.*?)</a>', li, re.S)
        if not a:
            continue
        m = _OC_COMPANY_HREF.search(a.group(1))
        start = re.search(r'class="start_date"[^>]*>(.*?)</span>', li, re.S)
        end = re.search(r'class="end_date"[^>]*>(.*?)</span>', li, re.S)
        addr = re.search(r'<span class="address">(.*?)</span>', li, re.S)
        prev = re.findall(r'Previously/Alternatively known as (.*?)</span>', li, re.S)
        label = re.search(r'<span class="status label">(.*?)</span>', li, re.S)
        status = " ".join(cls.split()) or (_txt(label.group(1)) if label else None)
        out.append(company_row("opencorporates", _txt(a.group(2)), m.group(2) if m else None,
                               m.group(1) if m else None, site + a.group(1),
                               status=status, incorporated=_txt(start.group(1)) if start else None,
                               dissolved=_txt(end.group(1)) if end else None,
                               registered_address=_txt(addr.group(1)) if addr else None,
                               previous_names=[{"name": _txt(p), "period": None} for p in prev]))
    return out


def _oc_dd(html_text, cls):
    """Inner HTML of <dd class="cls…">, or None — also None for the anonymous 'please log in to
    see this data' placeholder (absent data, never a value)."""
    m = re.search(r'<dd class="%s(?:\s[^"]*)?"[^>]*>(.*?)</dd>' % re.escape(cls), html_text or "", re.S)
    if not m or re.search(r"log in to see", _txt(m.group(1)), re.I):
        return None
    return m.group(1)


def _oc_officer_items(block, active, page_url):
    site = OC_WEB["site"]
    rows = []
    for li in re.findall(r'<li class="attribute_item">(.*?)</li>', block or "", re.S):
        a = re.search(r'<a class="officer[^"]*" href="(/officers/(\d+))"[^>]*>(.*?)</a>(.*)', li, re.S)
        if not a:
            continue
        rest = a.group(4)
        role = re.match(r"\s*,\s*([^,<]+?)\s*,", rest)
        start = re.search(r'class="start_date"[^>]*>(.*?)</span>', rest, re.S)
        end = re.search(r'class="end_date"[^>]*>(.*?)</span>', rest, re.S)
        rows.append(officer_row(_txt(a.group(3)), "opencorporates", page_url,
                                role=role.group(1).strip() if role else None,
                                appointed=_txt(start.group(1)) if start else None,
                                resigned=_txt(end.group(1)) if end else None,
                                status="active" if active else "inactive",
                                officer_id=a.group(2), other_appointments_url=site + a.group(1)))
    return rows


def oc_web_parse_company(html_text, page_url=None):
    """Company page -> company_row; officers only when signed in (anonymous pages carry a
    'N officers available, please log in' stub, reported as `officers_gated`)."""
    h1 = re.search(r'<h1 class="wrapping_heading[^"]*"[^>]*>(.*?)</h1>', html_text or "", re.S)
    m = _OC_COMPANY_HREF.search(page_url or "")
    inc = _txt(_oc_dd(html_text, "incorporation_date"))
    inc = re.sub(r"\s*\(.*?\)\s*$", "", inc) or None
    dis = _txt(_oc_dd(html_text, "dissolution_date"))
    dis = re.sub(r"\s*\(.*?\)\s*$", "", dis) or None
    prev = [_txt(x) for x in re.findall(r'<li class="name_line">(.*?)</li>', _oc_dd(html_text, "previous_names") or "", re.S)]
    act = _oc_dd(html_text, "officers")
    inact = _oc_dd(html_text, "inactive_officers")
    officers = _oc_officer_items(act, True, page_url) + _oc_officer_items(inact, False, page_url)
    gated = [_txt(x) for x in re.findall(r'href="/users/sign_in[^"]*"[^>]*>([^<]*officers available[^<]*)</a>',
                                          html_text or "")]
    c = company_row("opencorporates", _txt(h1.group(1)) if h1 else None,
                    _txt(_oc_dd(html_text, "company_number")) or (m.group(2) if m else None),
                    m.group(1) if m else None, page_url,
                    status=_txt(_oc_dd(html_text, "status")) or None, incorporated=inc, dissolved=dis,
                    registered_address=_txt(_oc_dd(html_text, "registered_address")) or None,
                    company_type=_txt(_oc_dd(html_text, "company_type")) or None,
                    other_identifiers=_txt(_oc_dd(html_text, "other_identifiers")) or None,
                    registry_source=_txt(_oc_dd(html_text, "source")) or None,
                    previous_names=[{"name": p, "period": None} for p in prev], officers=officers)
    if gated and not officers:
        c["officers_gated"] = gated
    return c


def oc_web_parse_officer_search(html_text):
    site = OC_WEB["site"]
    blk = re.search(r'<ul class="officers unstyled">(.*?)</ul>\s*(?:</div>|<div)', html_text or "", re.S)
    out = []
    for li in re.findall(r"<li[^>]*>(.*?)</li>", blk.group(1) if blk else "", re.S):
        a = re.search(r'<a class="officer[^"]*" href="(/officers/(\d+))"[^>]*>(.*?)</a>(.*)', li, re.S)
        if not a:
            continue
        rest = a.group(4)
        role = re.match(r"\s*([^,<]+?)\s*,", rest)
        co = re.search(r'<a class="company[^"]*" href="([^"]+)"[^>]*>(.*?)</a>', rest, re.S)
        cm = _OC_COMPANY_HREF.search(co.group(1)) if co else None
        start = re.search(r'class="start_date"[^>]*>(.*?)</span>', rest, re.S)
        end = re.search(r'class="end_date"[^>]*>(.*?)</span>', rest, re.S)
        addr = re.search(r'<span class="address">(.*?)</span>', rest, re.S)
        inactive = 'class="officer inactive' in li
        out.append({"name": _txt(a.group(3)), "officer_id": a.group(2),
                    "role": role.group(1).strip() if role else None,
                    "birth_month_year": None, "address": _txt(addr.group(1)) if addr else None,
                    "companies": [{"name": _txt(co.group(2)), "number": cm.group(2) if cm else None,
                                   "jurisdiction": cm.group(1) if cm else None,
                                   "url": site + co.group(1),
                                   # the listing's "(Country, start-end)" is the COMPANY's life
                                   # span, not the appointment — open the officer page for that
                                   "incorporated": _txt(start.group(1)) if start else None,
                                   "dissolved": _txt(end.group(1)) if end else None}] if co else [],
                    "appointed": None, "resigned": None,
                    "officer_status": "inactive" if inactive else "active",
                    "other_appointments_url": site + a.group(1), "source_url": site + a.group(1),
                    "provider": "opencorporates"})
    return out


def oc_web_parse_officer(html_text, page_url=None):
    site = OC_WEB["site"]
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", html_text or "", re.S)
    co = re.search(r'<a class="company[^"]*" href="([^"]+)"[^>]*>(.*?)</a>', _oc_dd(html_text, "company") or "", re.S)
    cm = _OC_COMPANY_HREF.search(co.group(1)) if co else None
    f = {k: (_txt(_oc_dd(html_text, k)) or None) for k in
         ("address", "position", "occupation", "nationality", "start_date", "end_date", "date_of_birth")}
    return {"name": _txt(h1.group(1)) if h1 else None, "provider": "opencorporates",
            "birth_month_year": norm_birth(f["date_of_birth"]) or f["date_of_birth"],
            "nationality": f["nationality"], "occupation": f["occupation"], "source_url": page_url,
            "appointments": [{"company_name": _txt(co.group(2)), "company_number": cm.group(2) if cm else None,
                              "jurisdiction": cm.group(1) if cm else None,
                              "company_url": site + co.group(1), "role": f["position"],
                              "appointed": f["start_date"], "resigned": f["end_date"],
                              "correspondence_address": f["address"], "source_url": page_url}] if co else [],
            "note": "OpenCorporates officer records are per-appointment; search the same name for siblings."}


def _oc_web_url(key, **kw):
    jur = kw.pop("jur", None)
    path = OC_WEB[key].replace("{jur_path}", "/" + _q(jur) if jur else "")
    return OC_WEB["site"] + _fmt(path, **kw)


def oc_web_search(query, oc_jur=None, detail=None):
    url = _oc_web_url("search_companies", jur=oc_jur, query=query.strip())
    html_text, err, mode = _oc_fetch(url)
    if err:
        return _oc_gate_pv(url, mode, err), []
    comps = oc_web_parse_search(html_text)
    # the site ranks by its own relevance; put exact / token name matches first so the
    # `detail_max` company pages opened are the ones the analyst asked for
    comps.sort(key=lambda c: -_MATCH_RANK.get(_name_match(query, c.get("name")) or "", 0))
    comps = comps[:int(SETTINGS["max_results"])]
    budget = int(OC_WEB.get("detail_max") or 0) if detail is None else int(detail)
    for c in comps[:budget]:
        h, e, _ = _oc_fetch(c["source_url"])
        if e:
            c["detail_errors"] = {"company_page": "gated" if e == "gated" else _scrub(e)}
            continue
        full = oc_web_parse_company(h, c["source_url"])
        for k, v in full.items():
            if v not in (None, "", []) and k not in ("provider", "source_url"):
                c[k] = v
    return _oc_web_pv("ok" if comps else "empty", url, [_pointer(c) for c in comps], mode=mode), comps


def oc_web_company(oc_jur, number):
    url = _oc_web_url("company", jurisdiction=oc_jur, number=number)
    html_text, err, mode = _oc_fetch(url)
    if err:
        return _oc_gate_pv(url, mode, err), []
    c = oc_web_parse_company(html_text, url)
    if not c.get("name"):
        return _oc_web_pv("empty", url, mode=mode), []
    return _oc_web_pv("ok", url, [_pointer(c)], mode=mode), [c]


def oc_web_officer_search(name, oc_jur=None):
    url = _oc_web_url("search_officers", jur=oc_jur, query=name.strip())
    html_text, err, mode = _oc_fetch(url)
    if err:
        return _oc_gate_pv(url, mode, err), []
    cands = oc_web_parse_officer_search(html_text)
    return _oc_web_pv("ok" if cands else "empty", url, mode=mode), cands


def oc_web_officer(officer_id):
    url = _oc_web_url("officer", officer_id=officer_id)
    html_text, err, mode = _oc_fetch(url)
    if err:
        return _oc_gate_pv(url, mode, err), None
    card = oc_web_parse_officer(html_text, url)
    card["officer_id"] = officer_id
    return _oc_web_pv("ok" if card.get("name") else "empty", url,
                      [{"company_name": a["company_name"], "company_number": a["company_number"]}
                       for a in card["appointments"]], mode=mode), card


# ---------------------------------------------------------------- OpenCorporates dispatch
def _oc_with_api(web_call, api_call):
    """Website first; the premium API only as a SECONDARY when a token is set and the website
    did not answer ok (gated / skipped / error). The website block is kept as `website`."""
    if oc_web_available():
        pv, res = web_call()
    else:
        pv, res = _pv("skipped", via="website", reason=_oc_open()[1]), ([] if api_call else None)
    if pv["status"] in ("ok", "empty") or not _oc_token() or not _OCW.get("api_ok", True):
        return pv, res
    apv, ares = api_call()
    apv["website"] = {k: pv.get(k) for k in ("status", "url", "gated", "error", "reason") if pv.get(k)}
    return apv, ares


def oc_search(query, oc_jur=None, detail=None):
    return _oc_with_api(lambda: oc_web_search(query, oc_jur, detail), lambda: oc_api_search(query, oc_jur))


def oc_company(oc_jur, number):
    return _oc_with_api(lambda: oc_web_company(oc_jur, number), lambda: oc_api_company(oc_jur, number))


def oc_officer_search(name, oc_jur=None):
    return _oc_with_api(lambda: oc_web_officer_search(name, oc_jur), lambda: oc_api_officer_search(name, oc_jur))


def oc_officer(officer_id):
    return _oc_with_api(lambda: oc_web_officer(officer_id), lambda: oc_api_officer(officer_id))


def oc_unconfigured_reason():
    """Why a DEFAULT (not explicitly requested) run skips OpenCorporates, or None if it runs."""
    if oc_web_configured() or _oc_token():
        return None
    if not oc_web_available():
        return ("cloakbrowser not installed in this interpreter (repo .venv has it); the website "
                "mode needs it")
    return ("not configured: run `wp_corp.py opencorporates-login` (free account) — or pass "
            "--provider opencorporates for an anonymous run (company pages only; searches are gated)")


def opencorporates_login() -> int:
    """Interactive (TTY only): prompt e-mail + password, test the login live, and ONLY on success
    write both to the skill .env (apikeys.write_env, chmod 600) and save the session."""
    import getpass
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(json.dumps({"tool": "corp_registry", "mode": "opencorporates-login",
                          "error": "interactive only — run it in a terminal (credentials are never "
                                   "accepted as arguments)"}))
        return 2
    if not oc_web_available():
        print(json.dumps({"error": _oc_open()[1]}))
        return 2
    email = input("OpenCorporates account e-mail: ").strip()
    pw = getpass.getpass("OpenCorporates password (not echoed): ")
    if not email or not pw:
        print(json.dumps({"error": "e-mail and password are both required; nothing written"}))
        return 1
    # The typed values live only in this process's env for the test login (so _scrub masks them
    # in any error); the process exits right after.
    os.environ[OC_WEB["email_env"]], os.environ[OC_WEB["password_env"]] = email, pw
    _OCW.clear()
    ok, why = _oc_login()
    _oc_close()
    if not ok:
        print(json.dumps({"tool": "corp_registry", "mode": "opencorporates-login", "ok": False,
                          "reason": _scrub(why), "written": False}))
        return 1
    try:
        sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "..", "scripts", "apikeys")))
        import apikeys  # noqa: E402 — the repo's .env writer (chmod 600)
        apikeys.write_env(OC_WEB["email_env"], email)
        apikeys.write_env(OC_WEB["password_env"], pw)
        env_path = apikeys.ENV_PATH
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": True, "written": False, "session": oc_session_path(),
                          "error": f"login worked but the .env write failed: {type(e).__name__}"}))
        return 1
    print(json.dumps({"tool": "corp_registry", "mode": "opencorporates-login", "ok": True,
                      "account": _mask_email(email), "written": [OC_WEB["email_env"], OC_WEB["password_env"]],
                      "env_file": env_path, "session": oc_session_path()}))
    return 0


# ============================================================================ France
def _fr_company(r):
    cfg = PROVIDERS.get("recherche_entreprises") or {}
    siren = r.get("siren")
    url = _fmt(cfg.get("public_url", ""), number=siren) if cfg.get("public_url") else None
    offs = []
    for d in r.get("dirigeants") or []:
        if d.get("type_dirigeant") == "personne morale":
            offs.append(officer_row(d.get("denomination"), "recherche_entreprises", url,
                                    role=d.get("qualite"), corporate_officer_number=d.get("siren")))
        else:
            offs.append(officer_row(_join(d.get("prenoms"), d.get("nom")).replace(",", "") if d.get("nom") else None,
                                    "recherche_entreprises", url, role=d.get("qualite"),
                                    birth_month_year=d.get("date_de_naissance") or d.get("annee_de_naissance"),
                                    nationality=d.get("nationalite")))
    siege = r.get("siege") or {}
    st = r.get("etat_administratif")
    return company_row("recherche_entreprises", r.get("nom_complet") or r.get("nom_raison_sociale"),
                       siren, "FR", url, status={"A": "active", "C": "ceased"}.get(st, st),
                       incorporated=r.get("date_creation"), dissolved=r.get("date_fermeture"),
                       registered_address=siege.get("adresse"), officers=offs,
                       legal_form_code=r.get("nature_juridique"))


def fr_search(query):
    cfg = PROVIDERS.get("recherche_entreprises")
    if not cfg:
        return _pv("skipped", reason="recherche_entreprises not configured"), []
    url = _fmt(cfg["search_name"], query=query.strip(), size=SETTINGS["max_results"])
    data, err, _ = _json(url)
    if err:
        return _pv("error", url, error=err), []
    comps = [_fr_company(r) for r in (data or {}).get("results") or []]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps]), comps


def fr_officer_search(name):
    cfg = PROVIDERS.get("recherche_entreprises")
    if not cfg:
        return _pv("skipped", reason="recherche_entreprises not configured"), []
    # French surnames are often multi-word ("de Saint X"): try "Prénom Nom..." first, then
    # "...Prénoms Nom", keeping the first split that answers.
    parts = name.split()
    splits = [(" ".join(parts[1:]), parts[0]), (parts[-1], " ".join(parts[:-1]))]
    url, data = None, None
    for last, first in dict.fromkeys(splits):
        u = _fmt(cfg["search_person"], last=last, first=first, size=SETTINGS["max_results"])
        url = url or u
        d, err, _ = _json(u)
        if err:
            return _pv("error", u, error=err), []
        if (d or {}).get("results"):
            url, data = u, d
            break
    want = _tokens(name)
    cands = []
    for r in (data or {}).get("results") or []:
        c = _fr_company(r)
        hit = False
        for o in c["officers"]:
            if o.get("name") and want <= _tokens(o["name"]):
                hit = True
                cands.append({"name": o["name"], "role": o.get("role"), "birth_month_year": o.get("birth_month_year"),
                              "nationality": o.get("nationality"), "address": None,
                              "companies": [{"name": c["name"], "number": c["number"], "jurisdiction": "FR",
                                             "registered_address": c.get("registered_address")}],
                              "source_url": c["source_url"], "provider": "recherche_entreprises"})
        if not hit and want <= _tokens(c.get("name")):
            cands.append({"name": c["name"], "role": "entrepreneur individuel (sole proprietor)",
                          "birth_month_year": None, "address": c.get("registered_address"),
                          "companies": [{"name": c["name"], "number": c["number"], "jurisdiction": "FR"}],
                          "source_url": c["source_url"], "provider": "recherche_entreprises"})
    return _pv("ok" if cands else "empty", url), cands


# ============================================================================ Norway
def _no_company(e):
    cfg = PROVIDERS.get("brreg") or {}
    a = e.get("forretningsadresse") or e.get("postadresse") or {}
    num = e.get("organisasjonsnummer")
    status = ("deleted" if e.get("slettedato") else "bankrupt" if e.get("konkurs") else
              "liquidation" if e.get("underAvvikling") or e.get("underTvangsavviklingEllerTvangsopplosning")
              else "active")
    return company_row("brreg", e.get("navn"), num, "NO",
                       _fmt(cfg.get("public_url", ""), number=num) if cfg.get("public_url") else None,
                       status=status, incorporated=e.get("stiftelsesdato") or e.get("registreringsdatoEnhetsregisteret"),
                       dissolved=e.get("slettedato"),
                       registered_address=_join(", ".join(a.get("adresse") or []), a.get("postnummer"),
                                                a.get("poststed"), a.get("land")),
                       previous_names=[{"name": h.get("navn"), "period": h.get("fraDato")}
                                       for h in e.get("historiskeNavn") or [] if isinstance(h, dict)],
                       legal_form=(e.get("organisasjonsform") or {}).get("beskrivelse"))


def no_search(query):
    cfg = PROVIDERS.get("brreg")
    if not cfg:
        return _pv("skipped", reason="brreg not configured"), []
    num = re.sub(r"\s", "", query)
    if re.fullmatch(r"\d{9}", num):
        url = _fmt(cfg["record"], number=num)
        data, err, status = _json(url)
        if status in (404, 410):
            return _pv("empty", url), []
        if err:
            return _pv("error", url, error=err), []
        recs = [data]
    else:
        url = _fmt(cfg["search_name"], query=query.strip(), size=SETTINGS["max_results"])
        data, err, _ = _json(url)
        if err:
            return _pv("error", url, error=err), []
        recs = ((data or {}).get("_embedded") or {}).get("enheter") or []
    comps = [_no_company(e) for e in recs]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps]), comps


def parse_brreg_roles(data, source_url=None):
    offs = []
    for grp in (data or {}).get("rollegrupper") or []:
        for r in grp.get("roller") or []:
            role = (r.get("type") or {}).get("beskrivelse")
            left = bool(r.get("fratraadt") or r.get("avregistrert"))
            p = r.get("person")
            if p:
                n = p.get("navn") or {}
                offs.append(officer_row(_join(n.get("fornavn"), n.get("mellomnavn"), n.get("etternavn")).replace(",", ""),
                                        "brreg", source_url, role=role,
                                        birth_month_year=p.get("fodselsdato"),
                                        resigned="yes" if left else None,
                                        deceased=True if p.get("erDoed") else None))
            elif r.get("enhet"):
                e = r["enhet"]
                offs.append(officer_row(" ".join(e.get("navn") or []) if isinstance(e.get("navn"), list) else e.get("navn"),
                                        "brreg", source_url, role=role,
                                        corporate_officer_number=e.get("organisasjonsnummer"),
                                        resigned="yes" if left else None))
    return offs


def no_detail(c):
    cfg = PROVIDERS.get("brreg") or {}
    url = _fmt(cfg["roles"], number=c["number"])
    data, err, status = _json(url)
    if err and status != 404:
        c["detail_errors"] = {"officers": err}
        return
    c["officers"] = parse_brreg_roles(data, c.get("source_url"))


# ============================================================================ Finland
def _fi_company(p):
    cfg = PROVIDERS.get("prh") or {}
    names = p.get("names") or []
    cur = [n for n in names if str(n.get("type")) == "1" and not n.get("endDate")] or \
          [n for n in names if str(n.get("type")) == "1"] or names
    bid = (p.get("businessId") or {}).get("value")

    def addr(a):
        po = a.get("postOffices") or []
        city = next((x.get("city") for x in po if str(x.get("languageCode")) == "1"), None) or (po[0].get("city") if po else None)
        street = " ".join(str(x) for x in (a.get("street"), a.get("buildingNumber"), a.get("entrance"),
                                           a.get("apartmentNumber")) if x)
        return _join(a.get("co") and "c/o " + a["co"], street, a.get("postCode"), city,
                     a.get("postOfficeBox") and "PL " + str(a["postOfficeBox"]))
    addrs = p.get("addresses") or []
    reg = next((a for a in addrs if str(a.get("type")) == "1"), addrs[0] if addrs else {})
    return company_row("prh", cur[0].get("name") if cur else None, bid, "FI",
                       _fmt(cfg.get("public_url", ""), number=bid) if cfg.get("public_url") else None,
                       status=str(p.get("status")) if p.get("status") is not None else None,
                       incorporated=(p.get("businessId") or {}).get("registrationDate"),
                       dissolved=p.get("endDate"), registered_address=addr(reg) if reg else None,
                       previous_names=[{"name": n.get("name"), "period": _period(n.get("registrationDate"), n.get("endDate"))}
                                       for n in names if n.get("endDate") and str(n.get("type")) == "1"],
                       officers_note=cfg.get("officers_note"))


def fi_search(query):
    cfg = PROVIDERS.get("prh")
    if not cfg:
        return _pv("skipped", reason="prh not configured"), []
    q = query.strip()
    tpl = cfg["record"] if re.fullmatch(r"\d{7}-\d", q) else cfg["search_name"]
    url = _fmt(tpl, query=q, number=q)
    data, err, _ = _json(url)
    if err:
        return _pv("error", url, error=err), []
    comps = [_fi_company(p) for p in ((data or {}).get("companies") or [])[:int(SETTINGS["max_results"])]]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps],
               total=(data or {}).get("totalResults")), comps


# ============================================================================ SEC EDGAR
def _sec_ua():
    return _secret(SETTINGS["sec_user_agent_env"]) or SETTINGS["sec_user_agent_default"]


def _sec_hits(query):
    cfg = PROVIDERS["sec_edgar"]
    url = _fmt(cfg["search_name"], query=query.strip())
    data, err, _ = _json(url, ua=_sec_ua())
    if err:
        return url, None, err
    hits = (((data or {}).get("hits") or {}).get("hits")) or []
    return url, [{"cik": str(h.get("_id")), "entity": (h.get("_source") or {}).get("entity"),
                  "tickers": (h.get("_source") or {}).get("tickers")} for h in hits], None


def sec_submissions(cik):
    cfg = PROVIDERS["sec_edgar"]
    url = _fmt(cfg["submissions"], cik=str(cik).zfill(10))
    data, err, _ = _json(url, ua=_sec_ua())
    return url, data, err


def _sec_addr(a):
    a = a or {}
    return _join(a.get("street1"), a.get("street2"), a.get("city"),
                 a.get("stateOrCountryDescription") or a.get("stateOrCountry"), a.get("zipCode"))


def sec_parse_submissions(d, cik):
    cfg = PROVIDERS.get("sec_edgar") or {}
    ad = (d or {}).get("addresses") or {}
    return company_row("sec_edgar", d.get("name"), str(cik).lstrip("0") or str(cik), "US",
                       _fmt(cfg.get("public_url", ""), cik=str(cik).zfill(10)),
                       entity_type=d.get("entityType"), state_of_incorporation=d.get("stateOfIncorporation"),
                       registered_address=_sec_addr(ad.get("business")), mailing_address=_sec_addr(ad.get("mailing")),
                       ein=d.get("ein"), lei=d.get("lei"), tickers=d.get("tickers"),
                       sic=_join(d.get("sic"), d.get("sicDescription")),
                       previous_names=[{"name": f.get("name"), "period": _period((f.get("from") or "")[:10], (f.get("to") or "")[:10])}
                                       for f in d.get("formerNames") or []],
                       officers_note=cfg.get("officers_note"))


def us_search(query):
    cfg = PROVIDERS.get("sec_edgar")
    if not cfg:
        return _pv("skipped", reason="sec_edgar not configured"), []
    q = query.strip()
    if re.fullmatch(r"\d{1,10}", q):
        url, d, err = sec_submissions(q)
        if err:
            return _pv("error", url, error=err), []
        c = sec_parse_submissions(d, q)
        c["_detailed"] = True
        return _pv("ok", url, [_pointer(c)]), [c]
    url, hits, err = _sec_hits(q)
    if err:
        return _pv("error", url, error=err), []
    comps = [company_row("sec_edgar", re.sub(r"\s*\([A-Z0-9.\-, ]+\)\s*$", "", h["entity"] or ""), h["cik"], "US",
                         _fmt(cfg.get("public_url", ""), cik=h["cik"].zfill(10)), tickers=h.get("tickers"))
             for h in hits][:int(SETTINGS["max_results"])]
    return _pv("ok" if comps else "empty", url, [_pointer(c) for c in comps]), comps


def us_detail(c):
    if c.pop("_detailed", None):
        return
    url, d, err = sec_submissions(c["number"])
    if err:
        c["detail_errors"] = {"submissions": err}
        return
    full = sec_parse_submissions(d, c["number"])
    for k, v in full.items():
        if v not in (None, "", []) and k not in ("officers", "address_history"):
            c[k] = v


def sec_officer_search(name):
    if not PROVIDERS.get("sec_edgar"):
        return _pv("skipped", reason="sec_edgar not configured"), []
    url, hits, err = _sec_hits(name)
    if err:
        return _pv("error", url, error=err), []
    cfg = PROVIDERS["sec_edgar"]
    want = _tokens(name)
    cands = [{"name": h["entity"], "cik": h["cik"], "birth_month_year": None, "address": None,
              "role": "EDGAR filer (insider/reporting owner)",
              "source_url": _fmt(cfg.get("public_url", ""), cik=h["cik"].zfill(10)), "provider": "sec_edgar"}
             for h in hits if not h.get("tickers") and want <= _tokens(h["entity"])]
    return _pv("ok" if cands else "empty", url), cands


# ============================================================================ routes (VN / CN)
def _vn_route(mode, query, corr):
    try:
        import wp_vncorp  # noqa: E402 — lazy: only a VN query pays its import
    except Exception as e:  # noqa: BLE001
        return _pv("error", error=f"wp_vncorp import failed: {e}"), [], []
    try:
        if mode == "officer":
            vcorr = {k: v for k, v in (("address", corr.get("address")), ("dob", corr.get("birth"))) if v}
            out = wp_vncorp.reverse_lookup("person", query, corroborate=vcorr)
            cands = []
            for r in out.get("results") or []:
                cands.append({"name": r.get("legal_representative") or query, "role": "legal representative",
                              "address": r.get("address"), "birth_month_year": norm_birth(r.get("dob")),
                              "companies": [{"name": r.get("company_name") or r.get("name"),
                                             "number": r.get("tax_code"), "jurisdiction": "VN"}],
                              "source_url": r.get("url") or r.get("source_url"), "provider": "vn_corp",
                              "vn_corp_linked": r.get("linked")})
            return _pv("ok" if cands else "empty", results=[{"name": c["name"]} for c in cands],
                       via="wp_vncorp.reverse_lookup", raw_summary=out.get("summary")), [], cands
        out = wp_vncorp.lookup(query)
        f = {k: (v or {}).get("value") for k, v in (out.get("fields") or {}).items()}
        src = next(((v or {}).get("source_url") for v in (out.get("fields") or {}).values() if v), None)
        if not f:
            return _pv("empty", via="wp_vncorp.lookup", sources={k: s.get("status") for k, s in (out.get("sources") or {}).items()}), [], []
        offs = [officer_row(f["legal_representative"], "vn_corp", src, role="legal representative")] \
            if f.get("legal_representative") else []
        c = company_row("vn_corp", f.get("company_name_vn") or f.get("company_name_intl") or f.get("company_name"),
                        f.get("tax_code"), "VN", src, status=f.get("status"),
                        incorporated=f.get("registration_date") or f.get("operating_date"),
                        registered_address=f.get("address"), officers=offs)
        return _pv("ok", src, [_pointer(c)], via="wp_vncorp.lookup"), [c], []
    except Exception as e:  # noqa: BLE001
        return _pv("error", error=f"{type(e).__name__}: {e}"), [], []


# ============================================================================ corroboration
def parse_corroborate(specs) -> dict:
    """`birth=YYYY-MM,address=..,postcode=..,company=..` (repeatable) -> dict; split on the KEYS
    because an address is itself comma-separated."""
    out = {}
    for s in specs or []:
        if isinstance(s, dict):
            out.update({k: v for k, v in s.items() if v})
            continue
        keys = list(re.finditer(r"(?:^|,)\s*(birth|dob|address|postcode|company)\s*=", s or "", re.I))
        for i, m in enumerate(keys):
            end = keys[i + 1].start() if i + 1 < len(keys) else len(s)
            val = s[m.end():end].strip()
            if val:
                k = m.group(1).lower()
                out["birth" if k == "dob" else k] = val
    return out


def corroboration(cand: dict, corr: dict) -> dict:
    """Each analyst datum vs THIS record: True (match), False (record carries it and differs),
    None (record lacks the field — no evidence either way)."""
    res = {}
    addrs = [a for a in [cand.get("address"), cand.get("correspondence_address")] +
             [a.get("correspondence_address") for a in cand.get("appointments") or []] +
             [c.get("registered_address") for c in cand.get("companies") or []] if a]
    if "birth" in corr:
        want, have = norm_birth(corr["birth"]), cand.get("birth_month_year")
        if not want or not have:
            res["birth"] = None
        else:
            n = min(len(want), len(have))
            res["birth"] = want[:n] == have[:n]
    if "address" in corr:
        want = _tokens(corr["address"])
        if not want or not addrs:
            res["address"] = None
        else:
            res["address"] = any(len(want & _tokens(a)) / len(want) >= float(SETTINGS["address_token_overlap"])
                                 for a in addrs)
    if "postcode" in corr:
        pc = _postcode(corr["postcode"])
        res["postcode"] = None if not pc or not addrs else any(pc in _postcode(a) for a in addrs)
    if "company" in corr:
        comps = list(cand.get("companies") or []) + [
            {"name": a.get("company_name"), "number": a.get("company_number")} for a in cand.get("appointments") or []]
        if not comps:
            res["company"] = None
        else:
            want = corr["company"].strip()
            wn = _postcode(want)
            res["company"] = any((c.get("number") and _postcode(c["number"]).lstrip("0") == wn.lstrip("0"))
                                 or (c.get("name") and _tokens(want) and _tokens(want) <= _tokens(c["name"]))
                                 for c in comps)
    return res


def _name_match(query, name):
    q, c = _tokens(query), _tokens(name)
    if not q or not c:
        return None
    if q == c:
        return "exact"
    if q <= c:
        return "tokens"
    if all(any(x.startswith(y) or y.startswith(x) for x in c) for y in q):
        return "partial"
    return None


_MATCH_RANK = {"exact": 3, "tokens": 2, "partial": 1}


def _finalise_candidates(query, cands, corr):
    out = []
    for c in cands:
        nm = _name_match(query, c.get("name"))
        if not nm:
            continue
        c["name_match"] = nm
        c["rung"] = "lead"
        c["caveat"] = CAVEATS["officer_search"]
        flags = agent_flags(c.get("address"))
        if flags:
            c["address_flags"] = flags
            c["address_caveat"] = CAVEATS["formation_agent"]
        cr = corroboration(c, corr) if corr else {}
        c["corroboration"] = cr
        c["corroborated_by"] = [k for k, v in cr.items() if v is True]
        c["contradicted_by"] = [k for k, v in cr.items() if v is False]
        c["linked"] = bool(c["corroborated_by"]) and not c["contradicted_by"] and nm in ("exact", "tokens")
        c["status"] = "linked" if c["linked"] else "candidate"
        out.append(c)
    out.sort(key=lambda r: (not r["linked"], -_MATCH_RANK.get(r["name_match"], 0),
                            len(r["contradicted_by"])))
    return out


# ============================================================================ modes
_SEARCHERS = {"gleif": gleif_search, "companies_house": ch_search, "recherche_entreprises": fr_search,
              "brreg": no_search, "prh": fi_search, "sec_edgar": us_search}
_DETAILERS = {"gleif": gleif_detail, "companies_house": ch_detail, "brreg": no_detail,
              "sec_edgar": us_detail}
_OFFICER_SEARCHERS = {"companies_house": ch_officer_search, "recherche_entreprises": fr_officer_search,
                      "sec_edgar": sec_officer_search}


def _selected(iso, only=None):
    names = []
    for name, cfg in PROVIDERS.items():
        if only and name not in only:
            continue
        js = [str(j).upper() for j in (cfg.get("jurisdictions") or ["*"])]
        if iso is None or "*" in js or iso in js:
            names.append(name)
    return names


def _base(mode, query, iso, corr):
    return {"tool": "corp_registry", "mode": mode, "query": query, "jurisdiction": iso,
            "rung": "lead", "caveat": CAVEATS["officer_search" if mode == "officer" else "officer"],
            "corroborate": corr or {}, "providers": {}, "companies": [], "officers": [], "notes": []}


def _route_or_none(out, mode, query, iso, corr):
    """VN / CN handled by another tool. Returns True when the route fully answered the query."""
    if not iso or iso not in ROUTES:
        return False
    r = ROUTES[iso]
    if iso == "VN" and mode in ("company", "officer", "company-officers"):
        pv, comps, cands = _vn_route("officer" if mode == "officer" else "company", query, corr or {})
        out["providers"]["vn_corp"] = pv
        out["companies"] += comps
        out["officers"] += _finalise_candidates(query, cands, corr) if mode == "officer" else []
        out["notes"].append(r.get("note"))
        return True
    out["providers"][r.get("tool") or r.get("module") or iso] = _pv("skipped", reason=r.get("note"))
    out["notes"].append(r.get("note"))
    return True


def company(query, jurisdiction=None, providers=None, detail=None, corroborate=None):
    iso, oc_jur = _jur(jurisdiction)
    out = _base("company", query, iso, corroborate)
    if not (query or "").strip():
        out["error"] = "empty query"
        return out
    if _route_or_none(out, "company", query, iso, corroborate):
        return _summarise(out)
    budget = int(SETTINGS["detail_max"] if detail is None else detail)
    for name in _selected(iso, providers):
        if name == "opencorporates":
            why = None if providers and name in providers else oc_unconfigured_reason()
            if why:
                out["providers"][name] = _pv("skipped", reason=why)
                continue
            pv, comps = oc_search(query, oc_jur, detail)
        elif name in _SEARCHERS:
            pv, comps = _SEARCHERS[name](query) if name != "gleif" else gleif_search(query, iso)
        else:
            continue
        det = _DETAILERS.get(name)
        if det:
            for c in comps[:budget]:
                det(c)
        for c in comps:
            for o in c.get("officers") or []:
                o.setdefault("company_name", c.get("name"))
                o.setdefault("company_number", c.get("number"))
        out["providers"][name] = pv
        out["companies"] += comps
    out["officers"] = [o for c in out["companies"] for o in c.get("officers") or []]
    return _summarise(out)


def officer(name, jurisdiction=None, providers=None, corroborate=None, verify=None):
    iso, oc_jur = _jur(jurisdiction)
    corr = dict(corroborate or {})
    out = _base("officer", name, iso, corr)
    if len(_tokens(name)) < 2:
        out["error"] = "give a full name (at least two words) — a single token is not a person"
        return out
    if _route_or_none(out, "officer", name, iso, corr):
        return _summarise(out)
    cands = []
    for pname in _selected(iso, providers):
        if pname == "opencorporates":
            why = None if providers and pname in providers else oc_unconfigured_reason()
            if why:
                out["providers"][pname] = _pv("skipped", reason=why)
                continue
            pv, cs = oc_officer_search(name, oc_jur)
        elif pname in _OFFICER_SEARCHERS:
            pv, cs = _OFFICER_SEARCHERS[pname](name)
        else:
            out["providers"][pname] = _pv("skipped", reason="no officer/person search on this registry")
            continue
        out["providers"][pname] = pv
        cands += cs
    # A company= (or address/postcode with only a partial address on the listing) datum needs the
    # candidate's appointments; fetch them for up to verify_max CH candidates not already
    # contradicted on birth.
    budget = int(SETTINGS["verify_max"] if verify is None else verify)
    need = bool(corr.keys() & {"company", "address", "postcode"})
    fetched = 0
    for c in cands:
        if not need or fetched >= budget or c.get("provider") != "companies_house" or not c.get("officer_id"):
            continue
        if not _name_match(name, c.get("name")):
            continue
        if "birth" in corr and corroboration(c, {"birth": corr["birth"]}).get("birth") is False:
            continue
        fetched += 1
        pv, card = ch_appointments(c["officer_id"])
        c["appointments_check"] = {"status": pv["status"], "url": pv.get("url"), "error": pv.get("error")}
        if card:
            c["appointments"] = card.get("appointments")
    out["verification"] = {"appointments_fetched": fetched, "budget": budget}
    out["officers"] = _finalise_candidates(name, cands, corr)
    return _summarise(out)


def company_officers(spec, corroborate=None):
    m = re.match(r"^\s*([A-Za-z_]{2,8})\s*:\s*(.+?)\s*$", spec or "")
    out = _base("company-officers", spec, None, corroborate)
    if not m:
        out["error"] = "expected <jurisdiction>:<number>, e.g. gb:00000000"
        return out
    iso, oc_jur = _jur(m.group(1))
    num = m.group(2)
    out["jurisdiction"] = iso
    if _route_or_none(out, "company-officers", num, iso, corroborate):
        return _summarise(out)
    local = {"GB": "companies_house", "NO": "brreg", "FR": "recherche_entreprises", "FI": "prh",
             "US": "sec_edgar"}.get(iso)
    if local and local in PROVIDERS:
        pv, comps = _SEARCHERS[local](num)
        if local == "recherche_entreprises":
            comps = [c for c in comps if c.get("number") == re.sub(r"\D", "", num)] or comps[:1]
        comps = comps[:1]
        if comps and _DETAILERS.get(local):
            _DETAILERS[local](comps[0])
        out["providers"][local] = pv
    else:
        pv, comps = oc_company(oc_jur, num)        # website (anonymous: fields only, no officers)
        out["providers"]["opencorporates"] = pv
    out["companies"] = comps
    out["officers"] = [o for c in comps for o in c.get("officers") or []]
    return _summarise(out)


def officer_appointments(ident, corroborate=None):
    s = (ident or "").strip()
    out = _base("officer-appointments", s, None, corroborate)
    oc = re.search(r"opencorporates\.com/officers/(\d+)", s) or re.match(r"^oc:(\d+)$", s, re.I)
    ch = re.search(r"/officers/([A-Za-z0-9_\-]+)/appointments", s) or \
        re.match(r"^(?:gb|ch|uk):([A-Za-z0-9_\-]+)$", s, re.I) or \
        re.fullmatch(r"([A-Za-z0-9_\-]{20,40})", s)
    if oc:
        pv, card = oc_officer(oc.group(1))
        out["providers"]["opencorporates"] = pv
    elif ch:
        out["jurisdiction"] = "GB"
        pv, card = ch_appointments(ch.group(1))
        out["providers"]["companies_house"] = pv
    else:
        out["error"] = ("unrecognised officer id: give a Companies House appointments URL / id "
                        "(gb:<id>) or an OpenCorporates officer URL / id (oc:<n>)")
        return out
    if card:
        card["rung"] = "lead"
        card["caveat"] = CAVEATS["officer"]
        if corroborate:
            cr = corroboration(card, corroborate)
            card["corroboration"] = cr
            card["linked"] = any(v is True for v in cr.values()) and not any(v is False for v in cr.values())
        out["officers"] = [card]
    return _summarise(out)


def _summarise(out):
    pv = out["providers"]
    out["summary"] = {
        "providers": {k: v["status"] for k, v in pv.items()},
        "companies": len(out["companies"]), "officers": len(out["officers"]),
        "linked": sum(1 for o in out["officers"] if o.get("linked")),
        "flagged_addresses": sum(1 for c in out["companies"] if c.get("address_flags"))
        + sum(1 for o in out["officers"] if o.get("address_flags"))}
    out["notes"] = [n for n in out["notes"] if n]
    return out


def run(mode, query, jurisdiction=None, providers=None, corroborate=None, detail=None, verify=None,
        oc_api=True):
    """Single entry point for the harness. Never raises. `oc_api=False` forbids the metered
    OpenCorporates API secondary (the free pivot route uses the website only)."""
    corr = parse_corroborate(corroborate if isinstance(corroborate, list) else
                             ([corroborate] if corroborate else []))
    only = [p.strip() for p in providers.split(",")] if isinstance(providers, str) and providers else providers
    _OCW.clear()
    _OCW["api_ok"] = bool(oc_api)
    try:
        if mode == "company":
            return company(query, jurisdiction, only, detail, corr)
        if mode == "officer":
            return officer(query, jurisdiction, only, corr, verify)
        if mode == "company-officers":
            return company_officers(query, corr)
        if mode == "officer-appointments":
            return officer_appointments(query, corr)
        return {"tool": "corp_registry", "error": f"unknown mode {mode!r}; one of {', '.join(MODES)}"}
    except Exception as e:  # noqa: BLE001 — tri-state contract: report, never raise
        return {"tool": "corp_registry", "mode": mode, "query": query,
                "error": _scrub(f"{type(e).__name__}: {e}")}
    finally:
        _oc_close()                                 # one OpenCorporates browser per run


def main():
    ap = argparse.ArgumentParser(description="Global company + officer registry pivot (GLEIF, Companies "
                                             "House, OpenCorporates, FR, NO, FI, SEC; VN->vn_corp, CN->cn_recon). "
                                             "Officers are LEADS (RULE 5).")
    ap.add_argument("mode", choices=MODES + ("opencorporates-login",))
    ap.add_argument("query", nargs="?", help="company name/number | officer full name | <jur>:<number> | "
                                             "officer id/url (not used by opencorporates-login)")
    ap.add_argument("--jurisdiction", "-j", default=None, help="ISO-2 (GB, FR, NO, FI, US, VN, CN) or OpenCorporates code (us_de)")
    ap.add_argument("--provider", default=None, help="comma list to restrict providers (gleif,companies_house,...)")
    ap.add_argument("--corroborate", action="append", default=[], metavar="K=V,...",
                    help="homonym gate: birth=YYYY-MM,address=..,postcode=..,company=<name|number>")
    ap.add_argument("--detail", type=int, default=None, help="companies to enrich with officers/history (default: reference)")
    ap.add_argument("--verify", type=int, default=None, help="officer candidates whose appointments are fetched for corroboration")
    ap.add_argument("--json", action="store_true", help="compact JSON")
    a = ap.parse_args()
    if a.mode == "opencorporates-login":
        return opencorporates_login()
    if not a.query:
        ap.error(f"{a.mode} needs a query")
    out = run(a.mode, a.query, a.jurisdiction, a.provider, a.corroborate, a.detail, a.verify)
    print(json.dumps(out, indent=None if a.json else 2, ensure_ascii=False))
    return 0 if not out.get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
