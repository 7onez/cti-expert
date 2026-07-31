"""wp_crawl — same-site crawl frontier + per-page result merge."""
import sys
import os
import re
import json
import base64
import hashlib
import argparse
import collections
import functools
import gzip
import itertools
import zlib
import socket
import ssl
import datetime
import shutil
import subprocess
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, quote, parse_qsl, unquote
# ------------------------------------------------------------------ optional deps
try:
    import requests  # noqa
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

import urllib.request
import urllib.error
from wp_common import *  # noqa
from wp_extract import *  # noqa

def same_site(host: str, seed_reg: str) -> bool:
    """True if `host` shares the seed's registrable domain (same host or a subdomain)."""
    if not host or not seed_reg:
        return False
    return _registrable(host) == seed_reg


# Containers whose links are site navigation / tabs / panels — crawled first.

_NAV_CONTAINER_RE = re.compile(r"<(nav|header|aside)\b[^>]*>(.*?)</\1>", re.I | re.S)

_NAV_ATTR_RE = re.compile(
    r"<[a-z][a-z0-9]*\b[^>]*(?:class|id|role|data-role)=[\"'][^\"']*"
    r"(?:nav|menu|tab|panel|sidebar|drawer|topbar|header)[^\"']*[\"'][^>]*>",
    re.I)

def extract_nav_links(html: str, base_url: str, seed_reg: str):
    """Same-site links to crawl, navigation/tab/panel links first.

    Returns a de-duplicated, absolute-URL list restricted to the seed's registrable
    domain. Priority frontier = hrefs inside <nav>/<header>/<aside> and elements whose
    class/id/role names a menu/tab/panel/sidebar; the rest of the same-site links follow.
    """
    def _anchors(chunk):
        return ANCHOR_HREF_RE.findall(chunk)

    priority, rest = [], []
    # 1) anchors inside explicit nav/header/aside containers
    for _tag, inner in _NAV_CONTAINER_RE.findall(html):
        priority.extend(_anchors(inner))
    # 2) anchors in a window after a menu/tab/panel-classed element
    for m in _NAV_ATTR_RE.finditer(html):
        priority.extend(_anchors(html[m.start():m.start() + 3000]))
    # 3) every other same-site anchor (asset/resource <link> tags are excluded by design)
    rest.extend(ANCHOR_HREF_RE.findall(html))

    def _norm(hrefs):
        out = []
        for href in hrefs:
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                continue
            try:
                absu = urljoin(base_url or "", unwrap_wayback(href))
                pr = urlparse(absu)
            except Exception:
                continue
            if pr.scheme not in ("http", "https"):
                continue
            if _ASSET_EXT_RE.search(pr.path):   # skip favicon/css/js/images/etc.
                continue
            if not same_site(strip_www(pr.netloc), seed_reg):
                continue
            out.append(absu.split("#", 1)[0])  # drop fragment
        return out

    # normalize once over priority-then-rest; uniq keeps first occurrence, so nav/tab/panel
    # links stay ahead of the rest and each href is resolved/scoped a single time.
    return uniq(_norm(priority + rest))

def _hashable(x):
    """Return x if hashable, else a stable string key (so dict list-items can be de-duped)."""
    try:
        hash(x)
        return x
    except TypeError:
        return json.dumps(x, sort_keys=True, ensure_ascii=False, default=str)

def _merge_lists(a, b):
    """Union two lists preserving order, de-duping even unhashable (dict) elements."""
    out, seen = list(a), {_hashable(x) for x in a}
    for x in b:
        h = _hashable(x)
        if h not in seen:
            seen.add(h)
            out.append(x)
    return out

def merge_result(base: dict, extra: dict) -> dict:
    """Fold a crawled page's artifacts + pivots into the seed result, in place.

    List artifacts are unioned; dict artifacts are merged (seed value wins on key clash);
    scalar seed fields (title, favicon, dom_skeleton) are preserved. Pivots are appended
    only when their (kind, value) pair is new — so the crawl broadens coverage without
    duplicating leads.
    """
    ba, ea = base.get("artifacts", {}), extra.get("artifacts", {})
    for k, ev in ea.items():
        if k not in ba or ba[k] in (None, "", [], {}):
            ba[k] = ev
        elif isinstance(ba[k], list) and isinstance(ev, list):
            ba[k] = _merge_lists(ba[k], ev)
        elif isinstance(ba[k], dict) and isinstance(ev, dict):
            for ik, iv in ev.items():
                if ik not in ba[k]:
                    ba[k][ik] = iv
                elif isinstance(ba[k][ik], list) and isinstance(iv, list):
                    ba[k][ik] = _merge_lists(ba[k][ik], iv)
        # scalars: keep the seed's value
    base["artifacts"] = ba

    seen = {(p.get("kind"), str(p.get("value"))) for p in base.get("pivots", [])}
    for p in extra.get("pivots", []):
        key = (p.get("kind"), str(p.get("value")))
        if key not in seen:
            seen.add(key)
            base.setdefault("pivots", []).append(p)
    return base


__all__ = [_n for _n in dir() if not _n.startswith("__")]
