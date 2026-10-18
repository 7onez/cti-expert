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

Egress: an Android UA (project decision; `references/vncorp.json -> settings.ua`) and the shared
process-global proxy `wp_common` installs at import — this module does not open its own socket
path, it goes through the same `urllib.request.urlopen` every keyless wp_* collector uses.

CLI:
  python3 wp_vncorp.py 0101234567
  python3 wp_vncorp.py "Cong ty TNHH Vi Du" --json
"""
import argparse
import html.parser
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
from wp_common import *  # noqa — installs the process-global egress proxy at import
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

# --- reference DATA (RULE 3): the fallback is the conservative minimum — one source, the label
#     map's core fields — so the tool still answers something if the JSON goes missing.
_VNCORP_FALLBACK = {
    "settings": {"ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
                 "timeout_seconds": 15},
    "sources": {"masothue": {"label": "masothue.com",
                             "mst_url": "https://masothue.com/Search/?q={query}&type=auto"}},
    "label_map": {"tax_code": ["mã số thuế", "ma so thue", "mst"],
                  "company_name_vn": ["tên công ty", "ten cong ty"],
                  "address": ["địa chỉ", "dia chi"]},
}
_REFS = load_ref(ref_path(__file__, "vncorp.json"), _VNCORP_FALLBACK)
_SETTINGS = _REFS["settings"]
UA = _SETTINGS.get("ua") or _VNCORP_FALLBACK["settings"]["ua"]
DEFAULT_TIMEOUT = int(_SETTINGS.get("timeout_seconds") or 15)
SOURCES = _REFS["sources"]
LABEL_MAP = _REFS["label_map"]
FIELD_ORDER = list(LABEL_MAP.keys())

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
        found[key] = value
    return {key: ({"value": found[key], "source": source_label, "source_url": source_url}
                  if key in found else None)
            for key in FIELD_ORDER}


def _fetch(url: str, timeout: int = None):
    """One GET -> (decoded_text, error). Never raises. Routed through the same process-global
    proxy every keyless wp_* collector uses (installed by `wp_common` at import)."""
    timeout = timeout or DEFAULT_TIMEOUT
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "text/html,application/xhtml+xml",
                                               "Accept-Language": "vi,en;q=0.8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            enc = "utf-8"
            try:
                enc = r.headers.get_content_charset() or "utf-8"
            except Exception:  # noqa: BLE001
                pass
            return raw.decode(enc, "replace"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — network/timeout/DNS: never raise out of a lookup
        return None, f"{type(e).__name__}: {e}"

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



def lookup(query: str, timeout: int = None) -> dict:
    """Look up a Vietnamese company by MST (10/13-digit tax code) or name across every configured
    mirror. Tri-state, never raises: each source carries its own status ('ok'|'empty'|'error'|
    'skipped'); merged `fields` takes the first hit per field in source-declaration order, each
    still tagged with the mirror it actually came from."""
    q = (query or "").strip()
    if not q:
        return {"query": query, "error": "empty query"}
    mst = is_mst(q)
    out = {"query": q, "kind": "mst" if mst else "name", "sources": {}, "fields": {}}
    for key, spec in SOURCES.items():
        tpl = (spec.get("mst_url") if mst else spec.get("name_url")) or spec.get("mst_url")
        if not tpl:
            out["sources"][key] = {"status": "skipped",
                                   "reason": "no URL template for this query kind"}
            continue
        url = tpl.replace("{query}", urllib.parse.quote(q))
        body, err = _fetch(url, timeout)
        if err:
            out["sources"][key] = {"status": "error", "error": err, "url": url}
            continue
        fields = parse_company_html(body, spec.get("label") or key, url)
        hit = any(fields.values())
        if hit and not mst and not _names_query(q, body, fields):
            # A NAME search returns a results/listing page; its first record is whatever company
            # the mirror lists first (live: two different names both "matched" one branch
            # registered that day). Fields only count when the queried name is on the page.
            out["sources"][key] = {"status": "unmatched", "url": url,
                                   "note": "results page does not name the queried company"}
            continue
        out["sources"][key] = {"status": "ok" if hit else "empty", "url": url}
        if hit:
            for k, v in fields.items():
                if v and k not in out["fields"]:
                    out["fields"][k] = v
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Keyless Vietnamese business-registry (MST tax-code / company-name) lookup.")
    ap.add_argument("query", help="a 10 or 13-digit tax code (MST), or a company name")
    ap.add_argument("--json", action="store_true", help="compact JSON (default: pretty-printed)")
    ap.add_argument("--timeout", type=int, default=None)
    a = ap.parse_args()
    out = lookup(a.query, timeout=a.timeout)
    print(json.dumps(out, indent=None if a.json else 2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
