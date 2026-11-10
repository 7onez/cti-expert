#!/usr/bin/env python3
"""wp_vncorp — keyless Vietnamese business-registry lookup (#16).

Input a Vietnamese tax code (MST — Mã số thuế, 10 digits, or 13 for a branch/dependent unit) or a
company name, and query the public registry mirrors in `references/vncorp.json` (masothue.com,
hsctvn.com, doanhnghiep.biz — endpoints are DATA, not literals here, per RULE 3). Each source is a
plain HTML page: no account, no key, no JS execution. Parsing is stdlib-only (`html.parser`, no
bs4) and works two ways in combination, because the exact markup of a third-party mirror is not
something this tool controls and may drift without notice:

  1. STRUCTURED rows — `<table><tr><td>label</td><td>value</td></tr></table>` and `<dt>/<dd>` pairs.
  2. A colon-separated TEXT fallback — `Label: value` on its own line once block tags are turned
     into line breaks — for markup that does not use a table/definition-list shape at all.

Both feed the same Vietnamese-label -> canonical-field map (`references/vncorp.json -> label_map`,
diacritic-folded before matching), so the parser is exercised the same way regardless of which
mirror's markup happens to answer. Every field is TRI-STATE: present with its own `source`/
`source_url` when found, `None` when it was not — never guessed, never a placeholder ("N/A" is a
mirror's own text, not this tool's).

Egress: the shared Android UA (project decision; `wp_ua`, overridable per tool with
`references/vncorp.json -> settings.ua`) through the
shared `wp_net.fetch` (browser header profile, `--proxy` honoured, plus the process-global proxy
`wp_common` installs at import). A Cloudflare interstitial, an HTTP error, or a redirect off the
mirror's own host is reported per source as an error — never parsed as a record.

REVERSE modes (`--by-phone`, `--by-person`) search the mirrors whose RESULTS LISTING is indexed by
a contact phone or a legal-representative name (`references/vncorp.json -> reverse_sources`), cut
the listing into records with the per-mirror regexes there, and keep only rows whose phone /
representative actually matches the query (mirror search is fuzzy). Rows with a tax code are then
VERIFIED on the mirror's record page (`reverse_detail`), which carries the full phone the listing
masks. RULE 5: every row is a registry FACT about that company and a LEAD for the case — never a
KB edge, never an operator name on one signal. By-person rows are `candidate` homonyms unless a
second datum (`--corroborate address=..,province=..,dob=..,phone=..`) matches on the same record;
only those get `linked: true`.

CLI:
  python3 wp_vncorp.py 0101234567
  python3 wp_vncorp.py "Cong ty TNHH Vi Du" --json
  python3 wp_vncorp.py --by-phone "+84 90 000 0000"
  python3 wp_vncorp.py --by-person "Nguyen Van Example" --corroborate "province=Ha Noi,phone=0900000000"
  python3 wp_vncorp.py 0101234567 --solve-cf [--flaresolverr http://127.0.0.1:8191]
      (opt-in: a Cloudflare-walled mirror is retried via the OPTIONAL CloakBrowser search-box
       step where vncorp.json configures one (masothue), then FlareSolverr, then a Chromium
       render; the per-source `cf_retry: {attempted, ok, reason, via}` says what happened)
"""
import argparse
import html as _html
import html.parser
import json
import os
import re
import sys
import unicodedata
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import *  # noqa — installs the process-global egress proxy at import
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
try:
    from wp_net import fetch as _wp_fetch, detect_cloudflare_challenge as _cf_challenge  # noqa
    from wp_net import flaresolverr_get as _flaresolverr_get, render_dom as _render_dom  # noqa
except Exception:  # noqa: BLE001 — the parsers stay usable offline even if the net layer cannot import
    _wp_fetch = _cf_challenge = _flaresolverr_get = _render_dom = None

# --- reference DATA (RULE 3): the fallback is the conservative minimum — one source, the label
#     map's core fields — so the tool still answers something if the JSON goes missing.
_VNCORP_FALLBACK = {
    "settings": {"timeout_seconds": 15},
    "sources": {"masothue": {"label": "masothue.com",
                             "mst_url": "https://masothue.com/Search/?q={query}&type=auto"}},
    "label_map": {"tax_code": ["mã số thuế", "ma so thue", "mst"],
                  "company_name_vn": ["tên công ty", "ten cong ty"],
                  "address": ["địa chỉ", "dia chi"]},
    # the one trailer known to glue onto a representative cell ("Ngoài ra, <name> còn đại diện…")
    "value_trim": {"legal_representative": [r"[\s,;:.-]*Ngo(?:à|a)i ra\b.*$"]},
    # reverse modes: no mirror in the minimum (a missing file reports "no reverse source", never
    # guesses a selector); the caveats ARE in the minimum because RULE 5 output must carry them.
    "reverse_sources": {},
    "reverse_detail": {},
    "reverse_settings": {"max_rows": 50, "shared_phone_threshold": 3,
                         "address_token_overlap": 0.7, "province_prefixes": ["thanh pho", "tinh", "tp"]},
    "reverse_caveats": {
        "by_phone": "A company listing this number as its registered contact is a LEAD, not an "
                    "attribution: agents and accounting firms file one number for many clients.",
        "by_person": "Vietnamese personal names repeat at very high rates: a representative-name "
                     "hit is a CANDIDATE homonym until a second datum matches on the same record."},
}
_REFS = load_ref(ref_path(__file__, "vncorp.json"), _VNCORP_FALLBACK)
_SETTINGS = _REFS["settings"]
UA = _SETTINGS.get("ua") or DEFAULT_UA   # Android Chrome from the one source unless overridden
DEFAULT_TIMEOUT = int(_SETTINGS.get("timeout_seconds") or 15)
SOURCES = _REFS["sources"]
LABEL_MAP = _REFS["label_map"]
FIELD_ORDER = list(LABEL_MAP.keys())
REVERSE_SOURCES = _REFS.get("reverse_sources") or {}
REVERSE_DETAIL = _REFS.get("reverse_detail") or {}
REVERSE_SETTINGS = {**_VNCORP_FALLBACK["reverse_settings"], **(_REFS.get("reverse_settings") or {})}
REVERSE_CAVEATS = {**_VNCORP_FALLBACK["reverse_caveats"], **(_REFS.get("reverse_caveats") or {})}
VALUE_TRIM = {}
for _k, _pats in (_REFS.get("value_trim") or {}).items():
    try:
        VALUE_TRIM[_k] = [re.compile(p, re.I | re.S) for p in _pats or []]
    except re.error as _e:   # a bad pattern must not take the parser down: warn, skip that field
        print(f"[refs] WARNING: vncorp.json value_trim[{_k}] bad regex ({_e}); not trimmed",
              file=sys.stderr)


def _trim(key: str, value: str) -> str:
    """Cut a mirror's trailing prose off a field value (`value_trim` in vncorp.json) — e.g. the
    'Ngoài ra, <name> còn đại diện các doanh nghiệp…' list glued into a representative cell."""
    for rx in VALUE_TRIM.get(key, ()):
        value = rx.sub("", value)
    return _clean(value)


_MST_RE = re.compile(r"^\d{10}$|^\d{13}$")


def is_mst(value: str) -> bool:
    """True for a 10-digit MST (a company HQ) or 13-digit MST (a branch/dependent unit — 10 +
    a 3-digit suffix), with or without the usual '-'/'.'/space separators."""
    v = re.sub(r"[\s.\-]", "", value or "")
    return bool(_MST_RE.match(v))


def _fold(s: str) -> str:
    """Diacritic-folded, lowercased, alnum+space only — so 'Mã số thuế' and 'ma so thue' compare
    equal regardless of which one appears in a given mirror's markup."""
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9 ]", "", s.lower()).strip()


def _match_label(label: str):
    """A raw HTML label -> the canonical field key it names, or None. An EXACT fold match wins
    immediately; a substring match is kept as a fallback candidate so scanning continues for an
    exact one (a label map entry may itself be a substring of a more specific one)."""
    folded = _fold(label)
    if not folded:
        return None
    best = None
    for key, variants in LABEL_MAP.items():
        for variant in variants:
            vf = _fold(variant)
            if not vf:
                continue
            if folded == vf:
                return key
            if best is None and vf in folded:
                best = key
    return best


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


_SKIP_TAGS = frozenset({"script", "style"})


class _StructParser(html.parser.HTMLParser):
    """(label, value) pairs from `<table>` rows and `<dt>/<dd>` definition-list pairs. Stdlib
    only — no bs4 dependency for a two-column HTML shape this simple. `<script>`/`<style>` content
    is never collected as cell text."""

    def __init__(self):
        super().__init__()
        self.pairs = []
        self._row = None
        self._cell = None
        self._pending_dt = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag == "tr":
            self._row = []
        elif tag in ("td", "th", "dt", "dd"):
            self._cell = []

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
        elif tag in ("td", "th"):
            if self._cell is not None and self._row is not None:
                self._row.append(_clean("".join(self._cell)))
            self._cell = None
        elif tag == "dt":
            if self._cell is not None:
                self._pending_dt = _clean("".join(self._cell))
            self._cell = None
        elif tag == "dd":
            if self._cell is not None:
                value = _clean("".join(self._cell))
                if self._pending_dt and value:
                    self.pairs.append((self._pending_dt, value))
                self._pending_dt = None
            self._cell = None
        elif tag == "tr":
            if self._row and len(self._row) >= 2 and self._row[0]:
                self.pairs.append((self._row[0], self._row[1]))
            self._row = None

    def handle_data(self, data):
        if self._cell is not None and not self._skip:
            self._cell.append(data)


class _TextParser(html.parser.HTMLParser):
    """Every block-level tag becomes a newline; everything else is dropped. Feeds the colon-pair
    fallback for markup that carries labels as plain text rather than a table/dl. `<script>`/
    `<style>` content is never collected — a CSS `border: 1px solid #ccc` or a JS `key: value`
    literal must never be read as a business-registry label:value pair."""
    _BLOCK = frozenset({"p", "div", "tr", "li", "br", "dt", "dd", "h1", "h2", "h3", "h4",
                        "table", "section", "span"})

    def __init__(self):
        super().__init__()
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _extract_struct_pairs(html_text: str):
    p = _StructParser()
    try:
        p.feed(html_text)
    except Exception:  # noqa: BLE001 — a malformed page must degrade, never crash the lookup
        pass
    return p.pairs


def _extract_colon_pairs(html_text: str):
    p = _TextParser()
    try:
        p.feed(html_text)
    except Exception:  # noqa: BLE001
        pass
    text = "".join(p.parts)
    out = []
    for line in text.splitlines():
        line = _clean(line)
        if not line or ":" not in line:
            continue
        label, _, value = line.partition(":")
        label, value = _clean(label), _clean(value)
        if label and value and len(label) <= 60:
            out.append((label, value))
    return out


def parse_company_html(html_text: str, source_label: str, source_url: str) -> dict:
    """stdlib-only HTML -> canonical company fields. Tri-state per field: `{'value', 'source',
    'source_url'}` when found, `None` when not — table/dl rows are tried first (more reliable),
    the colon-pair text fallback fills in anything the structured pass missed."""
    pairs = _extract_struct_pairs(html_text) + _extract_colon_pairs(html_text)
    found = {}
    for label, value in pairs:
        key = _match_label(label)
        if not key or key in found or not value:
            continue
        value = _trim(key, value)
        if value:
            found[key] = value
    return {key: ({"value": found[key], "source": source_label, "source_url": source_url}
                  if key in found else None)
            for key in FIELD_ORDER}


def _host(url: str) -> str:
    h = (urllib.parse.urlparse(url or "").hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


# One CloakBrowser session per vn_corp run (the free tier allows ONE concurrent session): launched
# lazily on the first walled fetch that has a `cloakbrowser` config, reused for every later one,
# closed by `_cloak_close()` in the finally of lookup()/reverse_lookup(). A failed launch is
# remembered so a run does not relaunch per fetch.
_CLOAK = {}


def _cloak_cfg(url: str):
    """The `cloakbrowser` block of the source whose home_url host is `url`'s host, or None."""
    for spec in SOURCES.values():
        cfg = spec.get("cloakbrowser") if isinstance(spec, dict) else None
        if isinstance(cfg, dict) and cfg.get("home_url") and _host(cfg["home_url"]) == _host(url):
            return cfg
    return None


def _cloak_page(cfg: dict, proxy: str = None):
    if _CLOAK.get("error"):
        raise RuntimeError(_CLOAK["error"])
    if _CLOAK.get("page") is not None:
        return _CLOAK["page"]
    import cloakbrowser  # noqa: E402 — OPTIONAL dependency; ImportError is reported by the caller
    kw = {"headless": bool(cfg.get("headless", True)), "humanize": bool(cfg.get("humanize", True))}
    # Egress: an explicit --proxy always wins. Without one, `use_process_proxy` decides between the
    # process proxy env (the pool cti_proxy installed) and a DIRECT launch; Chromium would
    # otherwise read HTTP(S)_PROXY from the env on its own, so "direct" is forced explicitly.
    pcfg = None
    if proxy or cfg.get("use_process_proxy", False):
        try:                              # credentials split out: Chromium rejects inline user:pass@
            import wp_browser
            pcfg = wp_browser.proxy_for_chromium(proxy)
        except Exception:  # noqa: BLE001
            pcfg = proxy or None
    if pcfg:
        kw["proxy"] = pcfg
    else:
        kw["args"] = ["--no-proxy-server"]
    if os.environ.get("CLOAKBROWSER_LICENSE_KEY"):      # else the key saved by `cloakbrowser login`
        kw["license_key"] = os.environ["CLOAKBROWSER_LICENSE_KEY"]
    try:
        _CLOAK["browser"] = cloakbrowser.launch(**kw)
        _CLOAK["page"] = (_CLOAK["browser"].new_page(user_agent=UA) if cfg.get("android_ua", True)
                          else _CLOAK["browser"].new_page())
    except Exception as e:  # noqa: BLE001 — licence / binary / launch failure: remember, report
        _CLOAK["error"] = f"launch failed: {type(e).__name__}: {e}"
        raise RuntimeError(_CLOAK["error"]) from None
    return _CLOAK["page"]


def _cloak_close(keep_error: bool = False):
    """Close the run's CloakBrowser session. `keep_error` keeps a failed launch remembered (used
    before the render fallback, which runs its own sync Playwright and cannot share the loop)."""
    b, err = _CLOAK.get("browser"), _CLOAK.get("error")
    _CLOAK.clear()
    if keep_error and err:
        _CLOAK["error"] = err
    if b is not None:
        try:
            b.close()
        except Exception:  # noqa: BLE001
            pass


def _cloak_fetch(url: str, cfg: dict, proxy: str = None):
    """-> (html|None, reason). A SEARCH url is never navigated to directly: masothue answers a
    direct /Search/ URL (even with the form's token) with a DECOY record — a different, freshly
    registered company — so the query is typed into the home page's search box instead, as a
    visitor would. Any other url (a record page) is opened directly in the same session."""
    try:
        page = _cloak_page(cfg, proxy)
    except ImportError:
        return None, "cloakbrowser: not installed"
    except Exception as e:  # noqa: BLE001
        return None, f"cloakbrowser: {e}"
    goto_ms = int(cfg.get("goto_timeout_ms") or 45000)
    try:
        term = (urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                .get(cfg.get("query_param") or "q") or [None])[0]
        if term and cfg.get("search_url_re") and re.search(cfg["search_url_re"], url):
            home = cfg["home_url"].rstrip("/")
            page.goto(cfg["home_url"], timeout=goto_ms, wait_until="domcontentloaded")
            box = page.locator(cfg.get("input_selector") or "input[name='q']").first
            box.click()
            box.type(term)
            box.press("Enter")
            page.wait_for_url(lambda u: u.rstrip("/") != home,
                              timeout=int(cfg.get("result_timeout_ms") or 30000))
        else:
            page.goto(url, timeout=goto_ms, wait_until="domcontentloaded")
        page.wait_for_load_state("domcontentloaded")
        html_text, final = page.content(), page.url
    except Exception as e:  # noqa: BLE001 — selector drift / timeout: report and fall through
        return None, f"cloakbrowser: {type(e).__name__}: {str(e).splitlines()[0][:160]}"
    if not html_text or _cf_challenge(403, {}, html_text):
        return None, "cloakbrowser: still challenged/blocked"
    if _host(final) != _host(url):
        return None, f"cloakbrowser: landed off-mirror on {_host(final)}"
    _CLOAK["last_url"] = final
    return html_text, None


def _solved_url(url: str, info: dict):
    """(cite_url, search_url|None). When a CF retry produced the page, the citation must be the
    page actually parsed (the solver's final record URL), never the search URL that a direct fetch
    would answer with a decoy. Consumes `final_url` so a later fetch cannot reuse it."""
    r = info.get("cf_retry") or {}
    fu = r.pop("final_url", None)
    if r.get("ok") and fu and fu != url:
        return fu, url
    return url, None


def _solve_cf(url: str, timeout: int = None, proxy: str = None, flaresolverr: str = None):
    """Retry a Cloudflare-walled mirror. First, for a source with a `cloakbrowser` config in
    vncorp.json, the OPTIONAL CloakBrowser search-box step; then the repo's existing escalation
    (the same order pivot_extract --solve-cf uses): FlareSolverr when configured (--flaresolverr /
    $FLARESOLVERR_URL), else a Chromium render with cf_challenge=True. -> (text|None, cf_retry).
    The solved page is re-checked on its BODY (a render reports no status, and
    detect_cloudflare_challenge only reads body markers on a 403/429/503)."""
    retry = {"attempted": False, "ok": False, "reason": None}
    reasons = []
    cfg = _cloak_cfg(url)
    if cfg:
        c_html, why = _cloak_fetch(url, cfg, proxy)
        if why != "cloakbrowser: not installed":
            retry.update(attempted=True, via="cloakbrowser")
        if c_html:
            retry.update(ok=True, final_url=_CLOAK.get("last_url") or url)
            return c_html, retry
        reasons.append(why)
    _cloak_close(keep_error=True)   # render_cf runs its own sync Playwright: one loop at a time
    fs = flaresolverr or os.environ.get("FLARESOLVERR_URL")
    if fs and _flaresolverr_get:
        retry.update(attempted=True, via="flaresolverr")
        f_url, f_html, _ = _flaresolverr_get(url, fs, timeout=max(int(timeout or 0), 60), proxy=proxy)
        if f_html and not _cf_challenge(403, {}, f_html):
            retry.update(ok=True, final_url=f_url or url)
            return f_html, retry
        reasons.append("flaresolverr: no clean solution" if f_html is None else
                       "flaresolverr: still challenged")
    else:
        reasons.append("flaresolverr not configured")
    if _render_dom:
        try:
            final, r_html, _, renderer, _ = _render_dom(url, timeout=max(int(timeout or 0), 45),
                                                         ua=UA, proxy=proxy, cf_challenge=True)
            retry.update(attempted=True, via="render_cf", renderer=renderer)
            if r_html and not _cf_challenge(403, {}, r_html) and _host(final or url) == _host(url):
                retry.update(ok=True, final_url=final or url)
                return r_html, retry
            reasons.append("render: still challenged/blocked (try a residential --proxy)")
        except Exception as e:  # noqa: BLE001 — no browser engine / proxy failure: report, never raise
            reasons.append(f"render unavailable: {e}")
    else:
        reasons.append("render path unavailable")
    retry["reason"] = "; ".join(reasons)
    return None, retry


def _fetch(url: str, timeout: int = None, proxy: str = None, solve_cf: bool = False,
           flaresolverr: str = None, info: dict = None):
    """One GET -> (decoded_text, error). Never raises. Goes through the shared `wp_net.fetch`
    (browser header profile, `proxy` honoured) with this module's Android UA. A Cloudflare
    interstitial, an HTTP error status, or a redirect OFF the mirror's host (a lapsed mirror
    domain forwarding to an unrelated site) is an error — never a page to parse. On a Cloudflare
    wall, `solve_cf` (opt-in, like pivot_extract --solve-cf: FlareSolverr/a browser is slow)
    retries through `_solve_cf`; the outcome lands in `info['cf_retry']` either way."""
    if _wp_fetch is None:
        return None, "wp_net.fetch unavailable"
    try:
        final, status, headers, body = _wp_fetch(
            url, timeout=timeout or DEFAULT_TIMEOUT, ua=UA, proxy=proxy,
            extra_headers={"Accept": "text/html,application/xhtml+xml",
                           "Accept-Language": "vi,en;q=0.8"})
    except Exception as e:  # noqa: BLE001 — network/timeout/DNS: never raise out of a lookup
        return None, f"{type(e).__name__}: {e}"
    m = re.search(r"charset=([\w-]+)", str((headers or {}).get("content-type") or ""), re.I)
    try:
        text = (body or b"").decode(m.group(1) if m else "utf-8", "replace")
    except LookupError:
        text = (body or b"").decode("utf-8", "replace")
    cf = _cf_challenge(status, headers or {}, text) if _cf_challenge else None
    if cf:
        if solve_cf:
            solved, retry = _solve_cf(url, timeout, proxy, flaresolverr)
        else:
            solved, retry = None, {"attempted": False, "ok": False,
                                   "reason": "not requested (pass --solve-cf)"}
        if info is not None:
            info["cf_retry"] = retry
        if solved:
            return solved, None
        return None, f"cloudflare challenge ({cf}, HTTP {status})"
    if status >= 400:
        return None, f"HTTP {status}"
    if final and _host(final) != _host(url):
        return None, f"redirected off-mirror to {_host(final)}"
    return text, None


def _name_fold(s: str) -> str:
    """`_fold` plus đ→d (NFKD leaves đ intact) and collapsed spaces — for comparing company names."""
    return " ".join(_fold((s or "").replace("đ", "d").replace("Đ", "D")).split())


def _names_query(query: str, body: str, fields: dict) -> bool:
    """True when a name lookup's page is about the queried company: the parsed company name
    contains the query (or vice versa), or — when no name field parsed — the page text does."""
    q = _name_fold(query)
    if not q:
        return False
    name = ((fields.get("company_name_vn") or {}).get("value")) if fields else None
    if name:
        n = _name_fold(name)
        return q in n or n in q
    return q in _name_fold(re.sub(r"<[^>]+>", " ", body or ""))


def parse_page_fields(html_text: str, page: dict, source_label: str, source_url: str) -> dict:
    """A mirror whose record page defeats the generic label parser (labels and values in
    unrelated blocks, a member-signup form full of 'Điện thoại:' labels) declares `page_fields`:
    the page is cut to [scope_start, scope_end) on its TEXT, then each canonical field is read by
    its own regex. Same tri-state shape as `parse_company_html`; a value listed in `null_values`
    (the mirror's own 'not published' text) is None, not a value."""
    text = _card_text(html_text)
    try:
        s = re.search(page["scope_start"], text, re.I) if page.get("scope_start") else None
        text = text[s.start():] if s else text
        e = re.search(page["scope_end"], text, re.I) if page.get("scope_end") else None
        text = text[:e.start()] if e else text
        rx = {k: (re.compile(v["re"], re.I), v.get("on", "text"))
              for k, v in (page.get("fields") or {}).items()}
    except (KeyError, TypeError, re.error):
        rx = {}
    nulls = {_fold(v) for v in page.get("null_values") or []}
    raw = unicodedata.normalize("NFC", html_text or "")
    found = {}
    for key, (r, on) in rx.items():
        m = r.search(raw if on == "html" else text)
        val = _clean(_html.unescape(m.group(1)).replace("\ufffd", "")) if m else ""
        if val and _fold(val) not in nulls:
            found[key] = _trim(key, val)
    return {key: ({"value": found[key], "source": source_label, "source_url": source_url}
                  if key in found else None)
            for key in FIELD_ORDER}


def lookup(query: str, timeout: int = None, proxy: str = None, solve_cf: bool = False,
           flaresolverr: str = None) -> dict:
    """Forward lookup (see `_lookup`); the run's CloakBrowser session, if one was opened, is
    always closed here."""
    try:
        return _lookup(query, timeout, proxy, solve_cf, flaresolverr)
    finally:
        _cloak_close()


def _lookup(query: str, timeout: int = None, proxy: str = None, solve_cf: bool = False,
            flaresolverr: str = None) -> dict:
    """Look up a Vietnamese company by MST (10/13-digit tax code) or name across every configured
    mirror. Tri-state, never raises: each source carries its own status ('ok'|'empty'|'error'|
    'skipped'|'unmatched', plus `cf_retry` when it hit a Cloudflare wall); merged `fields` takes
    the first hit per field in source-declaration order, each still tagged with the mirror it
    actually came from. A source with a `listing` spec has its results page cut into rows; the
    row whose tax code (or name) matches the query is followed to its record page."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "error": "empty query"}
    mst = is_mst(q)
    qd = re.sub(r"\D", "", q)
    out = {"query": q, "kind": "mst" if mst else "name", "sources": {}, "fields": {}}
    for key, spec in SOURCES.items():
        tpl = (spec.get("mst_url") if mst else spec.get("name_url")) or spec.get("mst_url")
        if not tpl:
            out["sources"][key] = {"status": "skipped",
                                   "reason": "no URL template for this query kind"}
            continue
        url = tpl.replace("{query}", urllib.parse.quote(q))
        info = {}
        body, err = _fetch(url, timeout, proxy, solve_cf, flaresolverr, info)
        url, search_url = _solved_url(url, info)
        if search_url:
            info["search_url"] = search_url
        if err:
            out["sources"][key] = {"status": "error", "error": err, "url": url, **info}
            continue
        lst = spec.get("listing")
        marker = (lst or {}).get("listing_marker") or (lst or {}).get("card_start")
        if lst and lst.get("card_start") and marker and re.search(marker, body, re.I):
            rows = parse_listing(body, lst, url).get("rows") or []
            row = next((r for r in rows if (re.sub(r"\D", "", r.get("tax_code") or "") == qd if mst
                                            else _names_query(q, "", {"company_name_vn":
                                                                      {"value": r.get("name")}}))),
                       None)
            if not row:
                out["sources"][key] = {"status": "unmatched" if rows else "empty", "url": url,
                                       "note": "no listing row matches the query", **info}
                continue
            if row.get("detail_url"):
                url = row["detail_url"]
                body, err = _fetch(url, timeout, proxy, solve_cf, flaresolverr, info)
                url, _ = _solved_url(url, info)
                if err:
                    out["sources"][key] = {"status": "error", "error": err, "url": url, **info}
                    continue
        label = spec.get("label") or key
        fields = (parse_page_fields(body, spec["page_fields"], label, url) if spec.get("page_fields")
                  else parse_company_html(body, label, url))
        hit = any(fields.values())
        if hit and not mst and not _names_query(q, body, fields):
            # A NAME search returns a results/listing page; its first record is whatever company
            # the mirror lists first (live: two different names both "matched" one branch
            # registered that day). Fields only count when the queried name is on the page.
            out["sources"][key] = {"status": "unmatched", "url": url,
                                   "note": "results page does not name the queried company", **info}
            continue
        got = re.sub(r"\D", "", ((fields.get("tax_code") or {}).get("value")) or "")
        if hit and mst and got and not got.startswith(qd):
            # An unknown MST makes some mirrors fall back to their newest-registrations list
            # (live: doanhnghiep.biz) — that page's first record is a different company.
            out["sources"][key] = {"status": "unmatched", "url": url,
                                   "note": "page's tax code is not the queried MST", **info}
            continue
        out["sources"][key] = {"status": "ok" if hit else "empty", "url": url, **info}
        if hit:
            for k, v in fields.items():
                if v and k not in out["fields"]:
                    out["fields"][k] = v
    return out


# ------------------------------------------------------------------ reverse modes

def normalize_vn_phone(raw: str):
    """Any written VN form (0xxx, +84 xxx, 84xxx, 0084xxx, with or without a habitual trunk 0
    after the code) -> {'national', 'e164', 'nsn'}, or None when it is not a 9/10-digit NSN."""
    d = re.sub(r"\D", "", raw or "")
    if d.startswith("0084"):
        d = d[4:]
    elif d.startswith("84") and len(d) >= 11:
        d = d[2:]
    if d.startswith("0"):
        d = d[1:]
    if len(d) not in (9, 10):
        return None
    return {"national": "0" + d, "e164": "+84" + d, "nsn": d}


def _masked_nsn(s: str):
    """A listing phone that may carry mirror-masked digits ('09xxxxxx**') -> its NSN form with
    '*' kept, or None."""
    d = re.sub(r"[^\d*]", "", s or "")
    if d.startswith("84") and len(d) >= 11:
        d = d[2:]
    if d.startswith("0"):
        d = d[1:]
    return d or None


def _phone_basis(phones, nsn: str):
    """'exact' when a listed number equals the query NSN, 'masked' when a masked number is
    consistent with it (same length, every visible digit equal, at least 6 visible), else None."""
    best = None
    for p in phones or []:
        m = _masked_nsn(p)
        if not m or len(m) != len(nsn):
            continue
        if "*" not in m and m == nsn:
            return "exact"
        visible = [i for i, c in enumerate(m) if c != "*"]
        if len(visible) >= 6 and all(m[i] == nsn[i] for i in visible):
            best = "masked"
    return best


def _card_text(chunk: str) -> str:
    """One listing record -> text with every tag a newline, entities unescaped, NFC-normalised
    (so accented labels in the reference regexes match), blank lines dropped."""
    t = re.sub(r"(?is)<(script|style)\b.*?</\1>", "", chunk or "")
    t = re.sub(r"<[^>]+>", "\n", t)
    t = unicodedata.normalize("NFC", _html.unescape(t))
    return "\n".join(_clean(line) for line in t.splitlines() if _clean(line))


def parse_listing(html_text: str, spec: dict, base_url: str, max_rows: int = None) -> dict:
    """A mirror's results listing -> {'rows': [...]} or {'error': ...} (bad selector config).
    Records are cut at `card_start`; each field regex reads the raw record HTML or its text."""
    try:
        start = re.compile(spec["card_start"])
        fields = {k: (re.compile(v["re"], re.I), v.get("on", "text"))
                  for k, v in (spec.get("fields") or {}).items()}
        split = re.compile(spec.get("phone_split") or r"\s+-\s+|/|,")
    except (KeyError, TypeError, re.error) as e:
        return {"error": f"bad reverse_sources selector: {type(e).__name__}: {e}"}
    page = unicodedata.normalize("NFC", html_text or "")
    starts = [m.start() for m in start.finditer(page)]
    rows = []
    for i, s in enumerate(starts):
        chunk = page[s:starts[i + 1] if i + 1 < len(starts) else s + 6000]
        text = _card_text(chunk)
        row = {}
        for key, (rx, on) in fields.items():
            m = rx.search(chunk if on == "html" else text)
            if m and _clean(_html.unescape(m.group(1))):
                row[key] = _trim(key, _clean(_html.unescape(m.group(1))))
        if not row.get("name"):
            continue
        if "phones" in row:
            row["phones"] = [_clean(p) for p in split.split(row["phones"]) if _clean(p)]
        if row.get("detail_href"):
            row["detail_url"] = urllib.parse.urljoin(base_url, row.pop("detail_href"))
        rows.append(row)
        if max_rows and len(rows) >= max_rows:
            break
    return {"rows": rows}


def parse_corroborate(specs) -> dict:
    """`address=..,province=..,dob=..,phone=..` (repeatable) -> dict. Split on the KEYS, not on
    commas, because a Vietnamese address is itself comma-separated."""
    out = {}
    for s in specs or []:
        keys = list(re.finditer(r"(?:^|,)\s*(address|province|dob|phone)\s*=", s or "", re.I))
        for i, m in enumerate(keys):
            end = keys[i + 1].start() if i + 1 < len(keys) else len(s)
            val = _clean(s[m.end():end])
            if val:
                out[m.group(1).lower()] = val
    return out


def _tokens(s: str):
    return {t for t in _name_fold(s).split() if len(t) >= 2}


def _corroboration(row: dict, corr: dict) -> dict:
    """Each analyst datum vs THIS record: True (matches), False (record carries the field and it
    differs), None (the record does not carry that field — no evidence either way)."""
    res = {}
    addr = row.get("address")
    if "address" in corr:
        want = _tokens(corr["address"])
        res["address"] = (None if not addr or not want else
                          len(want & _tokens(addr)) / len(want)
                          >= float(REVERSE_SETTINGS["address_token_overlap"]))
    if "province" in corr:
        prov = _name_fold(corr["province"])
        for pre in sorted((_name_fold(p) for p in REVERSE_SETTINGS["province_prefixes"]),
                          key=len, reverse=True):
            if pre and prov.startswith(pre + " "):
                prov = prov[len(pre) + 1:]
                break
        res["province"] = None if not addr or not prov else f" {prov} " in f" {_name_fold(addr)} "
    if "phone" in corr:
        want = normalize_vn_phone(corr["phone"])
        have = [p for p in (row.get("phones") or []) if "*" not in p]
        if not want or not have:
            res["phone"] = None
        else:
            res["phone"] = any((normalize_vn_phone(p) or {}).get("nsn") == want["nsn"] for p in have)
    if "dob" in corr:
        dob = row.get("dob")
        res["dob"] = None if not dob else re.sub(r"\D", "", dob) == re.sub(r"\D", "", corr["dob"])
    return res


def _verify_row(row: dict, timeout=None, proxy=None, solve_cf=False, flaresolverr=None) -> dict:
    """Fetch the record page for the row's tax code and fold its full fields in. Tri-state:
    {'status': 'ok'|'mismatch'|'error'|'skipped', ...}."""
    tpl = REVERSE_DETAIL.get("url")
    mst = row.get("tax_code")
    if not tpl or not mst:
        return {"status": "skipped", "reason": "no record-page template" if not tpl else "no tax code"}
    url = tpl.replace("{mst}", urllib.parse.quote(mst))
    body, err = _fetch(url, timeout, proxy, solve_cf, flaresolverr)
    if err:
        return {"status": "error", "error": err, "url": url}
    f = parse_company_html(body, REVERSE_DETAIL.get("label") or "detail", url)
    rec_mst = re.sub(r"\D", "", ((f.get("tax_code") or {}).get("value")) or "")
    if not rec_mst or not rec_mst.startswith(re.sub(r"\D", "", mst)):
        return {"status": "mismatch", "url": url, "note": "record page is not this tax code"}
    rec = {k: v["value"] for k, v in f.items() if v and k in
           ("legal_representative", "address", "phone", "status", "registration_date")}
    return {"status": "ok", "url": url, "record": rec}


_BASIS_RANK = {"record_phone_exact": 5, "listing_phone_exact": 4, "rep_name_exact": 4,
               "listing_phone_masked": 2, "rep_name_contains": 2, "record_phone_differs": 0}


def reverse_lookup(mode: str, query: str, corroborate: dict = None, verify: int = None,
                   timeout: int = None, proxy: str = None, solve_cf: bool = False,
                   flaresolverr: str = None) -> dict:
    """Reverse lookup (see `_reverse_lookup`); closes the run's CloakBrowser session."""
    try:
        return _reverse_lookup(mode, query, corroborate, verify, timeout, proxy, solve_cf,
                               flaresolverr)
    finally:
        _cloak_close()


def _reverse_lookup(mode: str, query: str, corroborate: dict = None, verify: int = None,
                    timeout: int = None, proxy: str = None, solve_cf: bool = False,
                    flaresolverr: str = None) -> dict:
    """`mode` 'phone' | 'person'. Tri-state per mirror; never raises. Rows are registry FACTS and
    case LEADS (RULE 5) — `linked: true` only on an exact phone match (by-phone) or an exact
    representative name PLUS a matching second datum and no contradicting one (by-person)."""
    corr = dict(corroborate or {})
    kind = "by_phone" if mode == "phone" else "by_person"
    out = {"query": query, "mode": kind, "rung": "lead", "caveat": REVERSE_CAVEATS.get(kind),
           "corroborate": corr, "sources": {}, "results": []}
    q = (query or "").strip()
    if mode == "phone":
        norm = normalize_vn_phone(q)
        if not norm:
            out["error"] = "not a Vietnamese phone number (need a 9/10-digit NSN: 0xxx, +84xxx, 84xxx)"
            return out
        out["normalized"] = norm
        term, url_key = norm["national"], "by_phone_url"
    else:
        target = _name_fold(q)
        if len(target.split()) < 2:
            out["error"] = "give a full name (at least two words) — a single name token is not a person"
            return out
        term, url_key = q, "by_person_url"
    out["search_term"] = term
    mirrors = {k: s for k, s in REVERSE_SOURCES.items() if isinstance(s, dict) and s.get(url_key)}
    if not mirrors:
        out["error"] = f"no reverse source configured for {kind} (references/vncorp.json -> reverse_sources)"
        return out

    merged, order, discarded, by_name = {}, [], 0, {}
    for key, spec in REVERSE_SOURCES.items():
        if key not in mirrors:
            out["sources"][key] = {"status": "skipped", "reason": f"mirror has no {url_key}"}
            continue
        url = spec[url_key].replace("{query}", urllib.parse.quote(term))
        info = {}
        body, err = _fetch(url, timeout, proxy, solve_cf, flaresolverr, info)
        if err:
            out["sources"][key] = {"status": "error", "error": err, "url": url, **info}
            continue
        parsed = parse_listing(body, spec, url, int(REVERSE_SETTINGS["max_rows"]))
        if parsed.get("error"):
            out["sources"][key] = {"status": "error", "error": parsed["error"], "url": url}
            continue
        kept = 0
        for row in parsed["rows"]:
            if mode == "phone":
                b = _phone_basis(row.get("phones"), norm["nsn"])
                basis = {"exact": "listing_phone_exact", "masked": "listing_phone_masked"}.get(b)
            else:
                rf = _name_fold(row.get("legal_representative"))
                basis = ("rep_name_exact" if rf and rf == target else
                         "rep_name_contains" if rf and f" {target} " in f" {rf} " else None)
            if not basis:
                discarded += 1
                continue
            kept += 1
            label = spec.get("label") or key
            nkey = _name_fold(row.get("name"))
            ident = row.get("tax_code") or by_name.get(nkey) or "name:" + nkey
            row.update(match_basis=basis, sources=[{"source": label, "url": url}])
            if ident not in merged:
                merged[ident] = row
                order.append(ident)
                by_name.setdefault(nkey, ident)
                continue
            cur = merged[ident]
            cur["sources"] += row["sources"]
            for k, v in row.items():
                if k not in cur:
                    cur[k] = v
            if _BASIS_RANK.get(basis, 0) > _BASIS_RANK.get(cur["match_basis"], 0):
                cur["match_basis"] = basis
        out["sources"][key] = {"status": "ok" if kept else "empty", "url": url,
                               "rows_seen": len(parsed["rows"]), "kept": kept}

    rows = [merged[i] for i in order]
    # Record-page verification: the listing masks (by-phone) or omits (by-person) the phone.
    budget = int(verify if verify is not None else REVERSE_DETAIL.get("max_verify") or 0)
    need = mode == "phone" or bool(corr)
    ver = {"source": REVERSE_DETAIL.get("label"), "attempted": 0, "ok": 0, "errors": 0}
    for row in rows:
        if not need or ver["attempted"] >= budget or not row.get("tax_code"):
            continue
        ver["attempted"] += 1
        v = _verify_row(row, timeout, proxy, solve_cf, flaresolverr)
        row["verification"] = {k: v[k] for k in ("status", "url", "error", "note") if k in v}
        if v["status"] != "ok":
            ver["errors"] += v["status"] == "error"
            continue
        ver["ok"] += 1
        rec = v["record"]
        for k in ("address", "legal_representative", "registration_date", "status"):
            if rec.get(k) and not row.get(k):
                row[k] = rec[k]
        if rec.get("phone"):
            rp = rec["phone"]
            row["phones"] = [rp] + [p for p in row.get("phones") or [] if p != rp]
            if mode == "phone":
                same = (normalize_vn_phone(rp) or {}).get("nsn") == norm["nsn"]
                row["match_basis"] = "record_phone_exact" if same else "record_phone_differs"
        if mode == "person" and rec.get("legal_representative") \
                and _name_fold(rec["legal_representative"]) != _name_fold(row.get("legal_representative")):
            row["record_representative"] = rec["legal_representative"]
    out["verification"] = ver

    for row in rows:
        c = _corroboration(row, corr) if corr else {}
        row["corroboration"] = c
        row["corroborated_by"] = [k for k, v in c.items() if v is True]
        row["contradicted_by"] = [k for k, v in c.items() if v is False]
        if mode == "phone":
            linked = row["match_basis"] in ("record_phone_exact", "listing_phone_exact")
        else:
            linked = (row["match_basis"] == "rep_name_exact" and bool(row["corroborated_by"])
                      and not row["contradicted_by"])
        row["linked"] = linked
        row["status"] = "linked" if linked else "candidate"
    rows.sort(key=lambda r: (not r["linked"], -_BASIS_RANK.get(r["match_basis"], 0)))
    out["results"] = rows
    summary = {"results": len(rows), "linked": sum(r["linked"] for r in rows),
               "candidates": sum(not r["linked"] for r in rows),
               "discarded_non_matching": discarded}
    if mode == "phone":
        exact = sum(r["match_basis"] in ("record_phone_exact", "listing_phone_exact") for r in rows)
        if exact >= int(REVERSE_SETTINGS["shared_phone_threshold"]):
            summary["shared_number"] = (f"{exact} companies list this exact number — typical of a "
                                        "registration agent / accounting service; weak per company")
    if mode == "person" and not corr:
        summary["note"] = "no --corroborate datum given: every row stays a candidate homonym"
    out["summary"] = summary
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Keyless Vietnamese business-registry lookup: MST tax code / company name, "
                    "or reverse by registered contact phone / legal-representative name.")
    ap.add_argument("query", nargs="?", help="a 10 or 13-digit tax code (MST), or a company name")
    ap.add_argument("--by-phone", metavar="NUM",
                    help="companies whose registered contact phone is NUM (0xxx / +84xxx / 84xxx)")
    ap.add_argument("--by-person", metavar="NAME",
                    help="companies whose legal representative / director is NAME (accented form "
                         "searches best)")
    ap.add_argument("--corroborate", action="append", default=[], metavar="K=V,...",
                    help="second datum for the homonym gate: address=..,province=..,dob=..,phone=..")
    ap.add_argument("--verify", type=int, default=None,
                    help="max record pages fetched to verify reverse rows (default: reference)")
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--solve-cf", action="store_true",
                    help="on a Cloudflare wall, retry the mirror via FlareSolverr (--flaresolverr / "
                         "$FLARESOLVERR_URL) else a Chromium render — slow, opt-in like pivot_extract")
    ap.add_argument("--flaresolverr", default=None, metavar="URL",
                    help="FlareSolverr endpoint used by --solve-cf. Env: FLARESOLVERR_URL")
    ap.add_argument("--json", action="store_true", help="compact JSON (default: pretty-printed)")
    ap.add_argument("--timeout", type=int, default=None)
    a = ap.parse_args()
    picked = [x for x in (a.query, a.by_phone, a.by_person) if x]
    if len(picked) != 1:
        ap.error("give exactly one of: QUERY, --by-phone NUM, --by-person NAME")
    if a.by_phone or a.by_person:
        out = reverse_lookup("phone" if a.by_phone else "person", a.by_phone or a.by_person,
                             corroborate=parse_corroborate(a.corroborate), verify=a.verify,
                             timeout=a.timeout, proxy=a.proxy, solve_cf=a.solve_cf,
                             flaresolverr=a.flaresolverr)
    else:
        out = lookup(a.query, timeout=a.timeout, proxy=a.proxy, solve_cf=a.solve_cf,
                     flaresolverr=a.flaresolverr)
    print(json.dumps(out, indent=None if a.json else 2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
