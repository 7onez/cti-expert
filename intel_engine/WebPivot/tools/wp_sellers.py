#!/usr/bin/env python3
"""wp_sellers — AdSense publisher id -> legal payee via Google's public sellers.json.

Google publishes one public sellers.json (IAB Tech Lab spec) for its ad exchange: every AdSense /
AdX seller account as `{"seller_id": "pub-…", "name": …, "domain": …, "seller_type": …}`. The
`name` is the legal entity Google PAYS for that publisher id (unless the account is flagged
confidential, in which case the row carries no name). A named payee behind a pub id found on a
page is an OWNER-rung signal (`kb/references/rungs.json -> ads.payee`): the pub id itself is kit
(templates copy it), but the entity paid for its impressions is who monetises the site.

The file is ~110 MB and changes slowly, so it is downloaded ONCE into a gitignored cache
(`references/sellers_lookup.json -> settings.cache_path`, relative to the engine root) and reused
until it is older than `settings.ttl_days`. The download is keyless and ledgered through
`api_usage.record` as a FREE call (credits=0). A corrupt / truncated cache is never trusted: it is
re-downloaded once, and if that fails too the lookup answers None — tri-state, never raises.

API:
  lookup(pub_id) -> {"seller_id", "name", "domain", "seller_type"} | None

CLI:
  python3 wp_sellers.py ca-pub-0000000000000000 [--json] [--refresh]
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(os.path.dirname(HERE))          # WebPivot/tools -> intel_engine
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import *  # noqa — installs the process-global egress proxy at import
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json
import api_usage  # noqa: E402

# --- reference DATA (RULE 3): the fallback is the conservative minimum — the public URL, the
#     default cache location, a one-week TTL and the Android UA (project decision).
_SELLERS_FALLBACK = {
    "settings": {"url": "https://storage.googleapis.com/adx-rtb-dictionaries/sellers.json",
                 "cache_path": "cache/sellers.json",
                 "ttl_days": 7,
                 "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"},
}
_REFS = load_ref(ref_path(__file__, "sellers_lookup.json"), _SELLERS_FALLBACK)
SETTINGS = _REFS["settings"]
_FB = _SELLERS_FALLBACK["settings"]
URL = SETTINGS.get("url") or _FB["url"]
UA = SETTINGS.get("ua") or _FB["ua"]
TTL_DAYS = float(SETTINGS.get("ttl_days") or _FB["ttl_days"])
TIMEOUT = int(SETTINGS.get("timeout_seconds") or 120)
_cp = SETTINGS.get("cache_path") or _FB["cache_path"]
CACHE_PATH = _cp if os.path.isabs(_cp) else os.path.join(ENGINE, _cp)

_PUB_RE = re.compile(r"(?:ca-)?pub-(\d{10,20})", re.I)
_INDEX_CACHE = {}          # cache path -> {seller_id: row}; one parse per process


def normalize(pub_id):
    """'ca-pub-123…' / 'pub-123…' / bare digits -> 'pub-123…'; anything else -> None."""
    s = str(pub_id or "").strip()
    m = _PUB_RE.search(s)
    if m:
        return "pub-" + m.group(1)
    if re.fullmatch(r"\d{10,20}", s):
        return "pub-" + s
    return None


def _download(url, dest, timeout):
    """Stream `url` to `dest` atomically (tmp + replace). Returns bytes written; raises on error —
    the caller turns every failure into a tri-state answer. Tests stub this seam."""
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    n = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
            n += len(chunk)
    os.replace(tmp, dest)
    return n


def _fetch(path):
    """Download once, ledgered as a free call. True on success, never raises."""
    try:
        n = _download(URL, path, TIMEOUT)
        api_usage.record("google_sellers", "sellers_json_download", credits=0, query=URL,
                         results=n)
        return True
    except Exception as exc:
        api_usage.record("google_sellers", "sellers_json_download", credits=0, query=URL,
                         ok=False)
        print(f"[sellers] download failed: {exc}", file=sys.stderr)
        return False


def _stale(path):
    try:
        return (time.time() - os.path.getmtime(path)) > TTL_DAYS * 86400
    except OSError:
        return True


def _parse(path):
    """sellers.json -> {seller_id: row}. Raises on a corrupt / wrong-shape file."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    sellers = doc.get("sellers") if isinstance(doc, dict) else None
    if not isinstance(sellers, list):
        raise ValueError("no 'sellers' array")
    idx = {}
    for row in sellers:
        if not isinstance(row, dict):
            continue
        sid = normalize(row.get("seller_id"))
        if sid:
            idx[sid] = {"seller_id": sid, "name": row.get("name") or None,
                        "domain": row.get("domain") or None,
                        "seller_type": row.get("seller_type") or None}
    return idx


def load_index(refresh=False, path=None):
    """{seller_id: row} or None when sellers.json is unavailable. Fresh cache -> parse it; stale,
    missing or corrupt -> (re-)download once. A stale cache that cannot be refreshed is still
    used (old payee data beats none). Never raises."""
    path = path or CACHE_PATH
    if not refresh and path in _INDEX_CACHE:
        return _INDEX_CACHE[path]
    have = os.path.exists(path)
    if refresh or not have or _stale(path):
        if not _fetch(path) and not have:
            return None
    try:
        idx = _parse(path)
    except Exception as exc:
        print(f"[sellers] cache unreadable ({exc}); re-downloading", file=sys.stderr)
        try:
            os.remove(path)
        except OSError:
            pass
        if not _fetch(path):
            return None
        try:
            idx = _parse(path)
        except Exception as exc2:
            print(f"[sellers] re-download unreadable too ({exc2})", file=sys.stderr)
            return None
    _INDEX_CACHE[path] = idx
    return idx


def lookup(pub_id, refresh=False):
    """AdSense pub id -> {"seller_id", "name", "domain", "seller_type"} or None (unknown id,
    malformed id, or sellers.json unavailable). Never raises."""
    try:
        sid = normalize(pub_id)
        if not sid:
            return None
        idx = load_index(refresh=refresh)
        if not idx:
            return None
        row = idx.get(sid)
        return dict(row) if row else None
    except Exception as exc:
        print(f"[sellers] lookup failed: {exc}", file=sys.stderr)
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="AdSense pub id -> legal payee (Google sellers.json)")
    ap.add_argument("pub_ids", nargs="+", help="ca-pub-… / pub-… / bare digits")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--refresh", action="store_true", help="force a re-download of the cache")
    a = ap.parse_args(argv)
    idx = load_index(refresh=a.refresh)
    if idx is None:
        out = {"error": "sellers.json unavailable (download failed and no usable cache)"}
        print(json.dumps(out) if a.json else out["error"])
        return 1
    results = {}
    for p in a.pub_ids:
        sid = normalize(p)
        row = idx.get(sid) if sid else None
        results[p] = dict(row, rung="owner" if row.get("name") else "kit") if row else None
    if a.json:
        print(json.dumps({"source": URL, "results": results}, ensure_ascii=False, indent=2))
    else:
        for p, row in results.items():
            if not row:
                print(f"{p}: not in sellers.json")
            else:
                print(f"{p}: {row['name'] or '(confidential)'} | {row['domain'] or '-'} | "
                      f"{row['seller_type'] or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
