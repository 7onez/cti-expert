#!/usr/bin/env python3
"""wp_appdev — keyless app-store DEVELOPER lookup (who publishes this app?).

Input a Google Play package name (`com.example.app`, or a play.google.com details URL) or an Apple
App Store numeric id / bundle id (`1234567890`, `id1234567890`, an apps.apple.com URL, or a bundle
id with `--store appstore`) and resolve the developer ACCOUNT behind it:

  Play       the public listing page (fetched with an Android UA, hl=en) → developer display name,
             the 'About the developer' LEGAL name, emails, postal address, phone, developer website, then the
             developer page the listing links to → the account's other apps.
  App Store  the iTunes lookup API (https://itunes.apple.com/lookup?id=…) → artistName, artistId,
             sellerName, sellerUrl, then `lookup?id=<artistId>&entity=software` → other apps.

Attribution rail (SKILL.md RULE 5): a developer website whose REGISTRABLE domain equals a case
domain is an owner link (rung class `app.developer_url` → owner in tools/kb/references/rungs.json).
Anything else — an unmatched website, the developer email — is returned as a seed CANDIDATE with
`auto_seed: false`; this tool never seeds or attributes on its own. A store listing is
self-declared by the developer: the legal name is who the account CLAIMS to be.

Tri-state, never raises: `play_developer()` / `appstore_developer()` return a dict when the store
answered and parsed, `None` when the app does not exist or the page carried no developer block
(malformed / changed markup), `{"error": …}` on a transport failure. Endpoints, labels and noise
hosts are reference DATA (`references/appdev.json`, RULE 3).

CLI:
  python3 wp_appdev.py com.example.app --case CASE-0001      # also saves cases/CASE-0001/appdev/
  python3 wp_appdev.py 1234567890 --case-domains example.com --json
  python3 wp_appdev.py com.example.app --store appstore      # an iOS bundle id
"""
import argparse
import glob
import html.parser
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import _registrable  # noqa: E402 — also installs the process-global egress proxy
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json

# --- reference DATA (RULE 3): the fallback is the conservative minimum — the two lookups that
#     answer "who is the developer" (no other-apps fan-out), the English labels, the store hosts.
_APPDEV_FALLBACK = {
    "settings": {"ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
                 "timeout_seconds": 20, "max_other_apps": 50, "country": "us", "about_block_max": 8},
    "endpoints": {"play_details": "https://play.google.com/store/apps/details?id={id}&hl=en&gl=US",
                  "itunes_lookup_id": "https://itunes.apple.com/lookup?id={id}&country={country}"},
    "play_labels": {"about_developer": ["About the developer"], "website": ["Website"],
                    "email": ["Email"], "block_end": ["Similar apps", "More by"],
                    "section_icon": ["arrow_forward"]},
    "noise_hosts": ["google.com", "apple.com"],
    "rung_classes": {"developer_url": "app.developer_url"},
}
_REFS = load_ref(ref_path(__file__, "appdev.json"), _APPDEV_FALLBACK)
_SETTINGS = _REFS["settings"]
UA = _SETTINGS.get("ua") or _APPDEV_FALLBACK["settings"]["ua"]
DEFAULT_TIMEOUT = int(_SETTINGS.get("timeout_seconds") or 20)
MAX_OTHER_APPS = int(_SETTINGS.get("max_other_apps") or 50)
COUNTRY = str(_SETTINGS.get("country") or "us")
ABOUT_BLOCK_MAX = int(_SETTINGS.get("about_block_max") or 8)
ENDPOINTS = _REFS["endpoints"]
PLAY_LABELS = _REFS["play_labels"]
NOISE_HOSTS = [str(h).lower() for h in _REFS["noise_hosts"]]
RUNG_CLASS_DEVELOPER_URL = (_REFS["rung_classes"] or {}).get("developer_url") or "app.developer_url"

_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_APPSTORE_ID_RE = re.compile(r"^(?:id)?(\d{6,12})$", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"^\+?[\d\s().\-]{7,}$")
_DEV_HREF_RE = re.compile(r"/store/apps/dev(?:eloper)?\?id=", re.I)
_DETAILS_HREF_RE = re.compile(r"/store/apps/details\?(?:[^\"'#]*&)?id=([A-Za-z0-9._]+)", re.I)


def _labels(key):
    return {str(x).strip().lower() for x in (PLAY_LABELS.get(key) or []) if str(x).strip()}


def _is_noise_host(host):
    h = (host or "").lower().rstrip(".")
    return not h or any(h == n or h.endswith("." + n) for n in NOISE_HOSTS)


def _unwrap_redirect(url):
    """Play sometimes wraps an external link as google.com/url?q=<target>; return the target."""
    try:
        p = urllib.parse.urlparse(url)
    except ValueError:
        return url
    if (p.hostname or "").endswith("google.com") and p.path == "/url":
        q = urllib.parse.parse_qs(p.query).get("q") or urllib.parse.parse_qs(p.query).get("url")
        if q:
            return q[0]
    return url


def _host(url):
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _clean(text):
    return re.sub(r"\s+", " ", text or "").strip()


# ---------------------------------------------------------------- HTTP seam (stubbed in tests)
def _fetch(url, timeout=None, accept="text/html,application/xhtml+xml"):
    """One GET -> (text, error, http_status). Never raises; routed through the process-global proxy
    `wp_common` installs at import (same `urllib.request.urlopen` every keyless collector uses)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept,
                                               "Accept-Language": "en-US,en;q=0.8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout or DEFAULT_TIMEOUT) as r:
            raw = r.read()
            enc = "utf-8"
            try:
                enc = r.headers.get_content_charset() or "utf-8"
            except Exception:  # noqa: BLE001
                pass
            return raw.decode(enc, "replace"), None, getattr(r, "status", 200)
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}", e.code
    except Exception as e:  # noqa: BLE001 — network/timeout/DNS: never raise out of a lookup
        return None, f"{type(e).__name__}: {e}", None


# ---------------------------------------------------------------- Play listing parser
_SKIP_TAGS = frozenset({"script", "style", "noscript", "template"})
_BLOCK_TAGS = frozenset({"div", "p", "span", "li", "td", "th", "h1", "h2", "h3", "h4", "header",
                         "section", "br", "a", "button"})


class _PlayParser(html.parser.HTMLParser):
    """Text nodes in document order + anchors with their inner text nodes. Stdlib only."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.texts = []          # [str] — whole text nodes, document order
        self.anchors = []        # [{"href", "texts": [str], "first_text": index into texts}]
        self._open = []          # stack of anchor dicts currently open
        self._skip = 0
        self._buf = []

    def _flush(self):
        t = _clean("".join(self._buf))
        self._buf = []
        if t:
            self.texts.append(t)
            for a in self._open:
                a["texts"].append(t)

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip += 1
            return
        if tag in _BLOCK_TAGS:
            self._flush()
        if tag == "a":
            href = dict(attrs).get("href") or ""
            a = {"href": href, "texts": [], "first_text": len(self.texts)}
            self.anchors.append(a)
            self._open.append(a)

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if tag in _BLOCK_TAGS:
            self._flush()
        if tag == "a" and self._open:
            self._open.pop()

    def handle_data(self, data):
        if not self._skip:
            self._buf.append(data)

    def close(self):
        super().close()
        self._flush()


def _parse_html(text):
    p = _PlayParser()
    try:
        p.feed(text or "")
        p.close()
    except Exception:  # noqa: BLE001 — malformed markup degrades to whatever parsed
        pass
    return p


def _email_ok(addr):
    dom = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
    return bool(dom) and not _is_noise_host(dom)


def parse_play_details(text, package=""):
    """Play listing HTML -> developer fields, or None when the page carries no developer link
    (not a listing, or markup this parser no longer recognises). Each field is tri-state: a value
    when found, None when not — never guessed."""
    if not isinstance(text, str) or not text.strip():
        return None
    p = _parse_html(text)
    dev_anchor = next((a for a in p.anchors
                       if _DEV_HREF_RE.search(a["href"]) and _clean(" ".join(a["texts"]))), None)
    if dev_anchor is None:
        return None
    name = _clean(" ".join(dev_anchor["texts"]))
    dev_href = dev_anchor["href"]
    dev_id = (urllib.parse.parse_qs(urllib.parse.urlparse(dev_href).query).get("id") or [None])[0]

    about, web_lbl, mail_lbl = _labels("about_developer"), _labels("website"), _labels("email")
    ends, icons = _labels("block_end"), _labels("section_icon")
    all_labels = about | web_lbl | mail_lbl

    # The 'About the developer' block: the text nodes after its heading, up to the next section —
    # a block_end heading (prefix match: 'More by <dev>') or any node followed by a section_icon
    # glyph (that node is the next section's heading). Play renders the block as legal name, email,
    # postal address, phone; each is optional, so every node is typed, never taken by position.
    block = []
    about_idx = next((i for i, t in enumerate(p.texts) if t.lower() in about), None)
    if about_idx is not None:
        window = p.texts[about_idx + 1: about_idx + 1 + ABOUT_BLOCK_MAX]
        for j, t in enumerate(window):
            nxt = window[j + 1].lower() if j + 1 < len(window) else ""
            if t.lower() in icons or any(t.lower().startswith(e) for e in ends) or nxt in icons:
                break
            block.append(t)

    def _plain(t):
        tl = t.lower()
        return not (tl in all_labels or _EMAIL_RE.fullmatch(t) or "://" in t
                    or tl.startswith("www.") or _PHONE_RE.match(t))

    # Legal name: the first plain node of the block. Address: the next plain node — the block
    # holds nothing else plain, and a lone legal name (no address published) leaves it None.
    plain = [t for t in block if _plain(t)]
    legal = plain[0] if plain else None
    address = plain[1] if len(plain) > 1 else None
    phone = next((t for t in block if _PHONE_RE.match(t) and sum(c.isdigit() for c in t) >= 7), None)
    block_email = next((t for t in block if _EMAIL_RE.fullmatch(t) and _email_ok(t)), None)

    # Email: a mailto: link off the store's own domains; else an email-shaped text node right after
    # an Email label or inside the About-the-developer block.
    email = None
    for a in p.anchors:
        if a["href"].lower().startswith("mailto:"):
            addr = urllib.parse.unquote(a["href"][7:].split("?", 1)[0]).strip()
            if _EMAIL_RE.fullmatch(addr) and _email_ok(addr):
                email = addr
                break
    if email is None:
        starts = [i for i, t in enumerate(p.texts) if t.lower() in mail_lbl]
        if about_idx is not None:
            starts.append(about_idx)
        for s in starts:
            for t in p.texts[s + 1: s + 8]:
                m = _EMAIL_RE.search(t)
                if m and _email_ok(m.group(0)):
                    email = m.group(0)
                    break
            if email:
                break

    # Website: an external http(s) link whose own text carries a Website label.
    website = None
    for a in p.anchors:
        href = _unwrap_redirect(a["href"])
        if not href.lower().startswith(("http://", "https://")) or _is_noise_host(_host(href)):
            continue
        if any(t.lower() in web_lbl for t in a["texts"]):
            website = href
            break

    base = ENDPOINTS.get("play_base") or "https://play.google.com"
    return {"name": name or None, "legal_name": legal, "email": email,
            "developer_email": block_email if block_email and block_email != email else None,
            "address": address, "phone": phone, "website": website,
            "developer_id": dev_id, "developer_page": urllib.parse.urljoin(base, dev_href)}


def parse_play_developer_page(text, exclude=""):
    """Play developer page HTML -> the account's app package names (deduped, in page order, minus
    `exclude`), or None when no app link parsed at all."""
    if not isinstance(text, str) or not text.strip():
        return None
    seen = []
    for m in _DETAILS_HREF_RE.finditer(text):
        pkg = m.group(1)
        if pkg and pkg != exclude and pkg not in seen:
            seen.append(pkg)
    if not seen and not _DEV_HREF_RE.search(text) and "/store/apps/details" not in text:
        return None
    return [{"package": p} for p in seen[:MAX_OTHER_APPS]]


# ---------------------------------------------------------------- iTunes lookup parser
def parse_itunes_lookup(text):
    """iTunes lookup JSON -> its `results` list, or None when unparseable / empty."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    res = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(res, list) or not res or not isinstance(res[0], dict):
        return None
    return res


# ---------------------------------------------------------------- attribution rail
def _rung(rung_class):
    """owner|kit|neighbour from rungs.json via tools/selector_types; 'kit' if unavailable."""
    try:
        tools_dir = os.path.join(ENGINE, "tools")
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
        import selector_types  # noqa: E402
        return selector_types.rung_for(rung_class)
    except Exception:  # noqa: BLE001
        return "kit"


def classify_links(dev, case_domains, source):
    """(owner_links, seed_candidates) for one developer record. The website is an owner link only
    when its registrable domain equals a case domain's registrable domain; otherwise it and the
    email are candidates the analyst may seed — never auto-seeded."""
    case_regs = {}
    for d in case_domains or ():
        d = str(d or "").strip().lower().rstrip(".")
        if d and "." in d:
            case_regs.setdefault(_registrable(d), d)
    owners, cands = [], []
    site = dev.get("website")
    if site:
        h = _host(site)
        reg = _registrable(h) if h else ""
        if reg and not _is_noise_host(h) and reg in case_regs:
            owners.append({"type": "domain", "value": reg, "url": site,
                           "matched_case_domain": case_regs[reg],
                           "rung_class": RUNG_CLASS_DEVELOPER_URL,
                           "rung": _rung(RUNG_CLASS_DEVELOPER_URL), "owner_link": True,
                           "source": f"{source}.developer_url"})
        elif reg and not _is_noise_host(h):
            cands.append({"type": "domain", "value": reg, "url": site, "owner_link": False,
                          "auto_seed": False, "source": f"{source}.developer_url",
                          "note": "developer website outside the case — a lead, not an owner link"})
    for key, typ in (("email", "email"), ("developer_email", "email"), ("phone", "phone")):
        if dev.get(key):
            cands.append({"type": typ, "value": dev[key], "auto_seed": False,
                          "source": f"{source}.{key}",
                          "note": "self-declared store contact — seed only on analyst decision"})
    return owners, cands


# ---------------------------------------------------------------- lookups
def _fill(tpl, **kw):
    out = tpl
    for k, v in kw.items():
        out = out.replace("{" + k + "}", urllib.parse.quote(str(v), safe=""))
    return out


def play_developer(package, case_domains=None, timeout=None):
    """Play package -> developer record dict | None (no such app / no developer block) |
    {"error": …}. Never raises."""
    pkg = (package or "").strip()
    if not _PKG_RE.match(pkg):
        return {"error": f"not a Play package name: {package!r}"}
    url = _fill(ENDPOINTS["play_details"], id=pkg)
    body, err, status = _fetch(url, timeout)
    if err:
        return None if status == 404 else {"error": err, "url": url}
    dev = parse_play_details(body, pkg)
    if dev is None:
        return None
    sources = [url]
    other = None
    if ENDPOINTS.get("play_base") and dev.get("developer_page"):
        dpage = dev["developer_page"]
        dpage += ("&" if "?" in dpage else "?") + "hl=en"
        dbody, derr, _ = _fetch(dpage, timeout)
        if not derr:
            other = parse_play_developer_page(dbody, exclude=pkg)
            sources.append(dpage)
    owners, cands = classify_links(dev, case_domains, "play")
    return {"store": "play", "query": pkg, "developer": dev, "other_apps": other,
            "owner_links": owners, "seed_candidates": cands, "source_urls": sources}


def appstore_developer(ident, case_domains=None, timeout=None, bundle=False):
    """App Store numeric id (or bundle id with bundle=True) -> developer record dict | None (no
    such app) | {"error": …}. Never raises."""
    q = (ident or "").strip()
    if bundle:
        if not _PKG_RE.match(q):
            return {"error": f"not a bundle id: {ident!r}"}
        tpl = ENDPOINTS.get("itunes_lookup_bundle")
        if not tpl:
            return {"error": "no itunes_lookup_bundle endpoint configured"}
        url = _fill(tpl, id=q, country=COUNTRY)
    else:
        m = _APPSTORE_ID_RE.match(q)
        if not m:
            return {"error": f"not an App Store id: {ident!r}"}
        q = m.group(1)
        url = _fill(ENDPOINTS["itunes_lookup_id"], id=q, country=COUNTRY)
    body, err, status = _fetch(url, timeout, accept="application/json")
    if err:
        return None if status == 404 else {"error": err, "url": url}
    res = parse_itunes_lookup(body)
    if res is None:
        return None
    app = res[0]
    if not app.get("artistName") and not app.get("sellerName"):
        return None
    dev = {"name": app.get("artistName"), "artist_id": app.get("artistId"),
           "seller_name": app.get("sellerName"), "website": app.get("sellerUrl"),
           "developer_page": app.get("artistViewUrl"), "email": None,
           "app": {"track_id": app.get("trackId"), "bundle_id": app.get("bundleId"),
                   "name": app.get("trackName")}}
    sources = [url]
    other = None
    if dev["artist_id"] and ENDPOINTS.get("itunes_artist_apps"):
        aurl = _fill(ENDPOINTS["itunes_artist_apps"], id=dev["artist_id"], country=COUNTRY)
        abody, aerr, _ = _fetch(aurl, timeout, accept="application/json")
        ares = None if aerr else parse_itunes_lookup(abody)
        if ares is not None:
            sources.append(aurl)
            other = [{"track_id": r.get("trackId"), "bundle_id": r.get("bundleId"),
                      "name": r.get("trackName")}
                     for r in ares
                     if r.get("wrapperType") == "software" and r.get("trackId") != app.get("trackId")
                     ][:MAX_OTHER_APPS]
    owners, cands = classify_links(dev, case_domains, "appstore")
    return {"store": "appstore", "query": q, "developer": dev, "other_apps": other,
            "owner_links": owners, "seed_candidates": cands, "source_urls": sources}


def normalise_query(raw, store="auto"):
    """(store, ident, bundle) from a raw query: store URLs are unwrapped; a numeric / idNNN value
    is an App Store id; anything else is a Play package unless store == 'appstore' (bundle id)."""
    q = (raw or "").strip()
    if q.lower().startswith(("http://", "https://")):
        p = urllib.parse.urlparse(q)
        host = (p.hostname or "").lower()
        if host.endswith("play.google.com"):
            pid = (urllib.parse.parse_qs(p.query).get("id") or [""])[0]
            return "play", pid, False
        if host.endswith("apple.com"):
            m = re.search(r"/id(\d{6,12})", p.path)
            return "appstore", (m.group(1) if m else ""), False
    if store == "appstore":
        return "appstore", q, not _APPSTORE_ID_RE.match(q)
    if store == "play":
        return "play", q, False
    if _APPSTORE_ID_RE.match(q):
        return "appstore", q, False
    return "play", q, False


def lookup(raw, store="auto", case_domains=None, timeout=None):
    """Dispatch to the store lookup. Same tri-state as the store functions."""
    st, ident, bundle = normalise_query(raw, store)
    if not ident:
        return {"error": f"could not read an app id from {raw!r}"}
    if st == "appstore":
        return appstore_developer(ident, case_domains, timeout, bundle=bundle)
    return play_developer(ident, case_domains, timeout)


def case_domains_for(case_id):
    """The hosts a case has collected (cases/<id>/raw/<host>.json stems) — the owner-link scope."""
    home = os.environ.get("INTEL_HOME") or ENGINE
    raw = os.path.join(home, "cases", case_id, "raw")
    out = []
    for p in sorted(glob.glob(os.path.join(raw, "*.json"))):
        stem = os.path.basename(p)[:-5].lower()
        if stem.endswith(".impersonation") or "." not in stem:
            continue
        out.append(stem)
    return out


def save_to_case(case_id, res):
    """Persist a resolved developer record as cases/<id>/appdev/<store>_<query>.json so the report
    bridge (scripts/build_report_data.py) can carry it into the narrative. Only a parsed record is
    stored — never an error or a no-such-app answer. Returns the path, or None."""
    if not case_id or not isinstance(res, dict) or res.get("error") or not res.get("developer"):
        return None
    home = os.environ.get("INTEL_HOME") or ENGINE
    case_dir = os.path.join(home, "cases", case_id)
    if not os.path.isdir(case_dir):
        return None
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{res.get('store') or 'app'}_{res.get('query') or 'query'}")
    out_dir = os.path.join(case_dir, "appdev")
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, slug + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        return path
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Keyless app-store developer lookup (Play / App Store).")
    ap.add_argument("query", help="Play package / play.google.com URL, or App Store id / URL / bundle id")
    ap.add_argument("--store", choices=("auto", "play", "appstore"), default="auto")
    ap.add_argument("--case", help="case id — its collected domains scope the owner-link check; "
                    "a resolved record is saved to cases/<id>/appdev/ for the report")
    ap.add_argument("--case-domains", default="", help="comma-separated extra case domains")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--json", action="store_true", help="compact JSON (default: pretty-printed)")
    a = ap.parse_args()
    domains = [d.strip() for d in a.case_domains.split(",") if d.strip()]
    if a.case:
        domains += case_domains_for(a.case)
    res = lookup(a.query, a.store, domains, a.timeout)
    if res is None:
        res = {"query": a.query, "result": None,
               "note": "no such app, or the store page carried no developer block"}
    elif a.case:
        save_to_case(a.case, res)
    print(json.dumps(res, indent=None if a.json else 2, ensure_ascii=False))
    return 1 if isinstance(res, dict) and res.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
