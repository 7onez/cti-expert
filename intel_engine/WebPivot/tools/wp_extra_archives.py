#!/usr/bin/env python3
# Part of the cti-expert WebPivot toolkit.
"""wp_extra_archives.py — archival corpora beyond the Wayback Machine.

Two passive, keyless sources that hold captures Wayback often does not:

  * CommonCrawl — a monthly web-scale crawl. Its CDX-style index lists every URL it
    captured for a domain (URL discovery), and each row carries the WARC file + byte
    range so the *stored response body* can be range-fetched and mined for selectors.
  * archive.today (archive.ph / .is / .li / .md / .vn) — an on-demand archive that
    frequently holds scam/phishing pages Wayback refused or that were taken down.
    A TimeMap lists every memento; each memento page can be fetched (best-effort —
    archive.today fronts with Cloudflare and may block automated fetches).

Everything here is passive (touches only the archives, never the target), keyless, and
degrades to empty on any error — a collector that raises would abort the deep pass.
FOR AUTHORIZED INVESTIGATIONS ONLY.
"""
from __future__ import annotations

import gzip
import io
import json
import re
import sys
import urllib.request
import urllib.parse

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

CC_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
CC_DATA = "https://data.commoncrawl.org/"
# archive.today load-balances across these mirrors; try them in order.
AT_MIRRORS = ("archive.ph", "archive.today", "archive.is", "archive.li", "archive.md")


def _get(url, ua=DEFAULT_UA, timeout=45, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if raw else data.decode("utf-8", "ignore")


# --------------------------------------------------------------------------- CommonCrawl
def cc_indexes(limit=2, ua=DEFAULT_UA):
    """The `limit` most recent CommonCrawl index ids (e.g. 'CC-MAIN-2024-33'). []
    on failure — the caller then simply skips CommonCrawl."""
    try:
        info = json.loads(_get(CC_COLLINFO, ua=ua, timeout=20))
    except Exception as e:
        print(f"  commoncrawl collinfo error: {e}", file=sys.stderr)
        return []
    ids = [c.get("id") for c in info if c.get("id")]
    return ids[:max(1, limit)]


def commoncrawl_index(domain, indexes=None, limit=1000, index_count=2, ua=DEFAULT_UA):
    """List CommonCrawl captures for a whole domain (matchType=domain → subdomains +
    subpaths). Returns [{url,timestamp,digest,mime,status,filename,offset,length}].
    Deduped by content digest across the queried indexes."""
    host = _cc_host(domain)
    idxs = indexes if indexes is not None else cc_indexes(index_count, ua=ua)
    seen_digest: set[str] = set()
    rows = []
    import time as _t
    for idx in idxs:
        api = (f"https://index.commoncrawl.org/{idx}-index?"
               f"url={urllib.parse.quote(host, safe='')}&matchType=domain"
               f"&output=json&limit={int(limit)}")
        body = None
        for _try in range(3):        # index.commoncrawl.org 502s / times out transiently
            try:
                body = _get(api, ua=ua, timeout=40)
                break
            except Exception as e:
                if _try == 2:
                    print(f"  commoncrawl {idx} error: {e}", file=sys.stderr)
                else:
                    _t.sleep(1.5 * (_try + 1))
        if body is None:
            continue
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("status") not in (None, "200", 200):
                continue
            dg = rec.get("digest")
            if dg and dg in seen_digest:
                continue
            if dg:
                seen_digest.add(dg)
            rows.append({
                "url": rec.get("url"), "timestamp": rec.get("timestamp"),
                "digest": dg, "mime": rec.get("mime") or rec.get("mime-detected"),
                "status": rec.get("status"), "filename": rec.get("filename"),
                "offset": rec.get("offset"), "length": rec.get("length"),
            })
    return rows


def commoncrawl_fetch(rec, ua=DEFAULT_UA, timeout=40):
    """Range-fetch one CommonCrawl record's WARC bytes and return the stored HTTP
    response body (HTML/text), or '' on failure. Each CC record is an independent
    gzip member, so a Range over [offset, offset+length) decompresses cleanly."""
    fn, off, length = rec.get("filename"), rec.get("offset"), rec.get("length")
    if not (fn and off is not None and length):
        return ""
    try:
        off = int(off)
        length = int(length)
        req = urllib.request.Request(
            CC_DATA + fn,
            headers={"User-Agent": ua, "Range": f"bytes={off}-{off + length - 1}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            comp = r.read()
        warc = gzip.GzipFile(fileobj=io.BytesIO(comp)).read().decode("utf-8", "ignore")
    except Exception:
        return ""
    # WARC record = WARC headers \r\n\r\n  HTTP headers \r\n\r\n  body
    parts = warc.split("\r\n\r\n", 2)
    if len(parts) < 3:
        return ""
    return parts[2]


def _cc_host(domain):
    d = (domain or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].strip().lower()
    return d[4:] if d.startswith("www.") else d


# --------------------------------------------------------------------------- archive.today
_AT_MEMENTO_RE = re.compile(
    r'<(?P<url>https?://[^>]+)>;\s*rel="memento"[^,]*?datetime="(?P<dt>[^"]+)"', re.I)


def archive_today_timemap(url, ua=DEFAULT_UA, timeout=15):
    """Every archive.today memento of `url`: [{'datetime','url'}], oldest→newest.
    Tries each mirror until one answers; [] if none do."""
    target = url if url.startswith("http") else "http://" + url
    for host in AT_MIRRORS:
        try:
            body = _get(f"https://{host}/timemap/{target}", ua=ua, timeout=timeout)
        except Exception:
            continue
        mems = [{"datetime": m.group("dt"), "url": m.group("url")}
                for m in _AT_MEMENTO_RE.finditer(body)]
        if mems:
            return mems
    return []


def archive_today_fetch(memento_url, ua=DEFAULT_UA, timeout=20):
    """Best-effort fetch of one archive.today memento's HTML ('' if blocked/failed)."""
    try:
        html = _get(memento_url, ua=ua, timeout=timeout)
    except Exception:
        return ""
    return html if html and len(html) > 200 else ""


# --------------------------------------------------------------------------- cli
def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="CommonCrawl + archive.today enumeration.")
    ap.add_argument("domain")
    ap.add_argument("--source", choices=["cc", "at", "both"], default="both")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args(argv)
    out = {}
    if a.source in ("cc", "both"):
        out["commoncrawl"] = commoncrawl_index(a.domain, limit=a.limit)
    if a.source in ("at", "both"):
        out["archive_today"] = archive_today_timemap(a.domain)
    print(json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
