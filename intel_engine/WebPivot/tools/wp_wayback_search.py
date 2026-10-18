#!/usr/bin/env python3
"""wp_wayback_search — Wayback Machine COLLECTION search (undocumented __wb/search/*).

Verified live 2026-10-03:
  GET /__wb/search/waybacksearch?q=&size=&page=&collection= → {total, hits:[…]} (empty may be [])
  GET /__wb/search/collectioninfo?collection= → {count,…} or {} when unknown

Latency 13–50s → default timeout 60s from references/wayback_endpoints.json collection_search.
Routes every request through wp_wayback's request helper so proxy, Android UA, guard/pacer and
retry rules apply. Stdlib only. Never raises — tri-state dict | {"error"} | {"skipped"}.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:  # noqa: BLE001
    def load_ref(path, fallback):
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.normpath(os.path.join(os.path.dirname(module_file), os.pardir,
                                             "references", name))

try:
    import wp_wayback as WB  # noqa: E402 — request helper + Android UA + guard
except Exception:  # noqa: BLE001
    WB = None

try:
    from wp_common import DEFAULT_UA  # noqa: E402
except Exception:  # noqa: BLE001
    DEFAULT_UA = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36")

_FALLBACK = {
    "collection_search": {
        "search_url": "https://web.archive.org/__wb/search/waybacksearch",
        "info_url": "https://web.archive.org/__wb/search/collectioninfo",
        "timeout": 60,
        "page_size": 50,
        "max_pages": 3,
        "collections": {
            "telegram": {"tier": "high", "mention_only": False},
            "pdf": {"tier": "medium", "mention_only": False},
            "mediacloud": {"tier": "low", "mention_only": True},
        },
    }
}

_REFS = load_ref(ref_path(__file__, "wayback_endpoints.json"), _FALLBACK)
_CS = _REFS.get("collection_search") or _FALLBACK["collection_search"]
if not isinstance(_CS, dict):
    _CS = _FALLBACK["collection_search"]

SEARCH_URL = str(_CS.get("search_url") or _FALLBACK["collection_search"]["search_url"])
INFO_URL = str(_CS.get("info_url") or _FALLBACK["collection_search"]["info_url"])
TIMEOUT = max(60, int(_CS.get("timeout") or 60))
PAGE_SIZE = max(1, int(_CS.get("page_size") or 50))
MAX_PAGES = max(1, int(_CS.get("max_pages") or 3))
COLLECTIONS = dict(_CS.get("collections") or {})

# In-process health cache: collection → True (ok) | False (unavailable) | None (unprobed)
_HEALTH: dict = {}

_TG_HANDLE_RE = re.compile(
    r"(?:https?://)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z0-9_]{3,})(?:/\d+)?", re.I)


def collection_meta(name: str) -> dict:
    """Return the reference entry for a collection name, or {}."""
    c = COLLECTIONS.get(name) or COLLECTIONS.get(str(name or "").strip())
    return dict(c) if isinstance(c, dict) else {}


def _get_json(url: str, timeout: int = None):
    """One GET via wp_wayback._request → (parsed, err). Never raises."""
    to = float(timeout if timeout is not None else TIMEOUT)
    if WB is None:
        # Degraded path: bare urllib (no guard), still the archive's honest client UA. Never raises.
        try:
            import urllib.request
            req = urllib.request.Request(url)
            try:
                from wp_wayback_guard import scope_ua
                scope_ua(req, DEFAULT_UA)        # archive.org UA, re-scoped per redirect hop
            except Exception:  # noqa: BLE001
                req.add_header("User-Agent", DEFAULT_UA)
            with urllib.request.urlopen(req, timeout=to) as r:
                raw = r.read()
            text = raw.decode("utf-8", "ignore").strip()
            if not text:
                return None, "empty body"
            return json.loads(text), None
        except Exception as e:  # noqa: BLE001
            return None, str(e)

    def _valid(resp):
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        text = resp.body.decode("utf-8", "ignore").strip()
        if not text:
            return None  # distinguish empty from unparseable
        try:
            return json.loads(text)
        except ValueError as e:
            raise ValueError(f"non-JSON body ({text[:60]!r})") from e

    try:
        val, err = WB._request(url, ua=DEFAULT_UA, timeout=to, valid=_valid, attempts=2)
    except Exception as e:  # noqa: BLE001
        return None, str(e)
    if err:
        return None, err
    return val, None


def collection_info(collection: str, timeout: int = None):
    """Probe one collection. Returns the info dict, {} when unknown, or {"error":…}.

    Caches the health decision in-process so a dead collection is not re-probed every page."""
    c = str(collection or "").strip()
    if not c:
        return {"error": "empty collection"}
    url = f"{INFO_URL}?{urllib.parse.urlencode({'collection': c})}"
    data, err = _get_json(url, timeout=timeout)
    if err:
        _HEALTH[c] = False
        return {"error": err, "collection": c}
    if data is None or data == {} or data == []:
        _HEALTH[c] = False
        return {}
    if not isinstance(data, dict):
        _HEALTH[c] = False
        return {"error": f"unexpected collectioninfo shape: {type(data).__name__}", "collection": c}
    # A usable info payload names the collection or carries a count.
    if not (data.get("collection") or data.get("title") or "count" in data):
        _HEALTH[c] = False
        return {}
    _HEALTH[c] = True
    return data


def collection_available(collection: str, timeout: int = None) -> bool:
    """True when the collection answered a non-empty collectioninfo this process."""
    c = str(collection or "").strip()
    if c in _HEALTH:
        return bool(_HEALTH[c])
    info = collection_info(c, timeout=timeout)
    if isinstance(info, dict) and info.get("error"):
        return False
    return bool(info)


def search(q: str, collection: str, size: int = None, page: int = 0, timeout: int = None):
    """One page of collection search → {total, hits, collection, q, page} | {error}.

    Unavailable collection → {"error": "collection unavailable"} (never empty-as-success)."""
    query = str(q or "").strip()
    c = str(collection or "").strip()
    if not query:
        return {"error": "empty query"}
    if not c:
        return {"error": "empty collection"}
    if not collection_available(c, timeout=timeout):
        return {"error": "collection unavailable", "collection": c}
    sz = max(1, int(size if size is not None else PAGE_SIZE))
    pg = max(0, int(page or 0))
    params = {"q": query, "size": sz, "page": pg, "collection": c}
    url = f"{SEARCH_URL}?{urllib.parse.urlencode(params)}"
    data, err = _get_json(url, timeout=timeout)
    if err:
        return {"error": err, "collection": c, "q": query}
    # Empty result may be a bare list [].
    if data is None or data == []:
        return {"total": 0, "hits": [], "collection": c, "q": query, "page": pg}
    if isinstance(data, list):
        return {"total": len(data), "hits": data, "collection": c, "q": query, "page": pg}
    if not isinstance(data, dict):
        return {"error": f"unexpected search shape: {type(data).__name__}", "collection": c}
    if data.get("error"):
        return {"error": str(data.get("error")), "collection": c, "q": query}
    hits = data.get("hits")
    if hits is None and isinstance(data.get("results"), list):
        hits = data["results"]
    if not isinstance(hits, list):
        hits = []
    total = data.get("total")
    if not isinstance(total, int):
        try:
            total = int(total)
        except (TypeError, ValueError):
            total = len(hits)
    return {"total": total, "hits": hits, "collection": c, "q": query, "page": pg}


def count(q: str, collection: str, timeout: int = None):
    """Hit-count probe (size=1). Returns int or None. Unavailable → None (caller sees error via search)."""
    res = search(q, collection, size=1, page=0, timeout=timeout)
    if not isinstance(res, dict) or res.get("error"):
        return None
    t = res.get("total")
    return t if isinstance(t, int) else None


def search_all(q: str, collection: str, max_pages: int = None, size: int = None, timeout: int = None):
    """Paginate up to max_pages. Returns {total, hits, collection, q, pages} | {error}."""
    pages_cap = max(1, int(max_pages if max_pages is not None else MAX_PAGES))
    sz = max(1, int(size if size is not None else PAGE_SIZE))
    first = search(q, collection, size=sz, page=0, timeout=timeout)
    if first.get("error"):
        return first
    hits = list(first.get("hits") or [])
    total = first.get("total") if isinstance(first.get("total"), int) else len(hits)
    pages = 1
    while pages < pages_cap and len(hits) < (total or 0) and len(first.get("hits") or []) >= sz:
        nxt = search(q, collection, size=sz, page=pages, timeout=timeout)
        pages += 1
        if nxt.get("error"):
            break
        batch = nxt.get("hits") or []
        if not batch:
            break
        hits.extend(batch)
        if isinstance(nxt.get("total"), int):
            total = nxt["total"]
    return {"total": total, "hits": hits, "collection": collection, "q": q, "pages": pages}


def telegram_handle(url: str):
    """Extract a t.me / telegram.me channel handle from a capture URL, or None."""
    if not url:
        return None
    m = _TG_HANDLE_RE.search(str(url))
    if not m:
        return None
    h = m.group(1)
    # drop pure-numeric (joinchat invite style left as-is only if alphanumeric)
    if h.lower() in ("s", "c", "joinchat", "addstickers", "share"):
        return None
    return h


def _plain(text: str) -> str:
    """Snippet text without highlight markup, lowercased, for literal-term matching."""
    return re.sub(r"<[^>]+>", "", str(text or "")).lower()


def hits_to_rows(hits, collection: str, *, rung_class_host: str = "string", require_term: str = ""):
    """Normalise raw wayback hits → typed pivot rows for ingest_typed / pivot_routes.

    telegram → type telegram (handle), rung telegram.username
    pdf → type domain, rung string/filename
    mention_only collections → type mention

    `require_term`: the collection search is full-text and TOKENISES the query (`c50_vietnam`
    matches any post mentioning "vietnam"), so a hit is kept only when its url/title/snippet
    contains the searched term literally — otherwise unrelated channels become case nodes.
    """
    meta = collection_meta(collection)
    mention_only = bool(meta.get("mention_only"))
    term = str(require_term or "").strip().strip('"').strip().lower()
    rows = []
    for h in hits or []:
        if not isinstance(h, dict):
            continue
        if term and term not in " ".join(_plain(h.get(k)) for k in ("url", "title", "snippet")):
            continue
        url = h.get("url") or h.get("surt_url") or ""
        host = (h.get("host") or h.get("domain") or "").strip().lower().rstrip(".")
        snippet = h.get("snippet") or h.get("title") or ""
        first = h.get("first_captured") or h.get("timestamp") or ""
        evidence = {"url": url, "snippet": snippet, "first_captured": first,
                    "collection": collection}
        if collection == "telegram" or (not mention_only and "telegram" in collection.lower()):
            handle = telegram_handle(url) or telegram_handle(snippet or "")
            if handle:
                rows.append({"type": "telegram", "value": handle,
                             "rung_class": "telegram.username",
                             "source": "wayback.telegram", "evidence": evidence})
            elif host:
                rows.append({"type": "domain", "value": host, "rung_class": "string",
                             "source": "wayback.telegram", "evidence": evidence})
            continue
        if mention_only:
            # Prefer a readable mention key: host, else title, else url tail.
            val = host or (h.get("title") or "").strip() or url
            if val:
                rows.append({"type": "mention", "value": str(val)[:240],
                             "rung_class": "string",
                             "source": f"wayback.{collection}", "evidence": evidence})
            continue
        # pdf / other non-mention host rows
        if host:
            rows.append({"type": "domain", "value": host,
                         "rung_class": rung_class_host or "string",
                         "source": f"wayback.{collection}", "evidence": evidence})
    return rows


__all__ = [
    "SEARCH_URL", "INFO_URL", "TIMEOUT", "PAGE_SIZE", "MAX_PAGES", "COLLECTIONS",
    "collection_meta", "collection_info", "collection_available",
    "search", "count", "search_all", "telegram_handle", "hits_to_rows",
]
