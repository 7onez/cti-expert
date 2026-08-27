#!/usr/bin/env python3
"""wp_buckets — GrayHatWarfare open-bucket / exposed-file search for WebPivot.

GrayHatWarfare indexes publicly readable object storage (Amazon S3, Azure Blob, Google Cloud
Storage, DigitalOcean Spaces) and the files inside them. This is an EXPOSURE-discovery layer for
/secrets and /docleak — NOT a same-operator pivot: a bucket named for the target is attribution,
a co-listed bucket is not, so its hits are graded EXPOSURE and never become a cluster edge.

API facts verified live against buckets.grayhatwarfare.com/api/v2 (2026-08):
  * auth via `Authorization: Bearer <GRAYHATWARFARE_API_KEY>`; a bad/absent key -> HTTP 401;
  * `GET /api/v2/buckets?keywords=<kw>&limit=N` -> {query, meta:{results}, buckets:[{id,bucket,
    fileCount,type}]};
  * `GET /api/v2/files?keywords=<kw>&limit=N` -> exposed files matching the term.

Keyless fallback is the `site:buckets.grayhatwarfare.com` dork (see handbook/discovery-paths.md).
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402 — shared skill-root .env loader + UA

try:
    import api_usage                        # licensed-API credit ledger (optional)
except Exception:
    api_usage = None

API_BASE = "https://buckets.grayhatwarfare.com/api/v2"
UI_URL = "https://buckets.grayhatwarfare.com/buckets/keywords/any/"

# Master off switch (e.g. --no-buckets). Only the NETWORK call honours it; the dork is free.
ENABLED = True


def ghw_key():
    """The GrayHatWarfare API key, or None."""
    return _secret("GRAYHATWARFARE_API_KEY", "GRAYHAT_API_KEY", "GHW_API_KEY")


def ghw_configured():
    """True when a key is available and GrayHatWarfare isn't switched off."""
    return ENABLED and bool(ghw_key())


def dork(keyword):
    """The keyless Google/Bing dork that substitutes for the API when no key is set."""
    return f'site:buckets.grayhatwarfare.com "{keyword}"'


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("grayhatwarfare", action, credits=1, query=None,
                             results=results, ok=ok)
        except Exception:
            pass


def _call(path, params, timeout=25):
    """One GrayHatWarfare API call -> (data, error). Never raises."""
    url = f"{API_BASE}/{path}?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": DEFAULT_UA, "Accept": "application/json",
            "Authorization": f"Bearer {ghw_key()}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None, {"error": "HTTP 401 — GrayHatWarfare rejected the key"}
        return None, {"error": f"HTTP {e.code}"}
    except Exception as e:
        return None, {"error": str(e)}


def buckets(keyword, limit=20, exact=False, timeout=25):
    """Open buckets whose name matches `keyword` -> {keyword, results, buckets:[...], ui}.
    Keyless -> {keyword, skipped, dork, ui}."""
    out = {"keyword": keyword, "ui": UI_URL + urllib.parse.quote(keyword or "")}
    if not ghw_configured():
        out["skipped"] = "no GRAYHATWARFARE_API_KEY configured — use the dork (see 'dork')"
        out["dork"] = dork(keyword)
        return out
    params = {"keywords": keyword, "limit": limit}
    if exact:
        params["exact"] = "true"
    data, err = _call("buckets", params, timeout)
    if err:
        out.update(err)
        return out
    rows = [{"id": b.get("id"), "bucket": b.get("bucket"), "fileCount": b.get("fileCount"),
             "type": b.get("type")} for b in (data.get("buckets") or [])]
    out["results"] = (data.get("meta") or {}).get("results")
    out["buckets"] = rows
    _record("buckets", len(rows), ok=True)
    return out


def files(keyword, limit=20, timeout=25):
    """Exposed files matching `keyword` -> {keyword, results, files:[...], ui}. Keyless ->
    {keyword, skipped, dork}."""
    out = {"keyword": keyword}
    if not ghw_configured():
        out["skipped"] = "no GRAYHATWARFARE_API_KEY configured — use the dork (see 'dork')"
        out["dork"] = dork(keyword)
        return out
    data, err = _call("files", {"keywords": keyword, "limit": limit}, timeout)
    if err:
        out.update(err)
        return out
    rows = []
    for f in (data.get("files") or []):
        rows.append({"filename": f.get("filename") or f.get("fullPath"),
                     "bucket": f.get("bucket"), "size": f.get("size"), "url": f.get("url")})
    out["results"] = (data.get("meta") or {}).get("results")
    out["files"] = rows
    _record("files", len(rows), ok=True)
    return out


__all__ = ["ghw_key", "ghw_configured", "dork", "buckets", "files"]


def main():
    ap = argparse.ArgumentParser(
        description="GrayHatWarfare open-bucket / exposed-file search (+ keyless dork fallback)")
    ap.add_argument("mode", choices=["buckets", "files"], help="what to search")
    ap.add_argument("keyword", help="domain/keyword to match against bucket names or file paths")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--exact", action="store_true", help="buckets: exact name match")
    args = ap.parse_args()
    if args.mode == "buckets":
        res = buckets(args.keyword, limit=args.limit, exact=args.exact)
    else:
        res = files(args.keyword, limit=args.limit)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
