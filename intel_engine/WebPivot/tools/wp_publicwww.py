#!/usr/bin/env python3
"""wp_publicwww — PublicWWW HTML source-code reverse-search client.

Metered, keyed. No key → {"skipped": "PUBLICWWW_API_KEY not set"} (never empty-as-success).
Tri-state: normalised dict | {"skipped":…} | {"error":…}. Never raises.
Every successful/failed spend is ledgered via api_usage.

API (export=csvu): GET https://publicwww.com/websites/<urlencoded-query>/?export=csvu&key=KEY
CSV rows: url, ranking snip… We take the registrable host from each URL.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402

try:
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:  # noqa: BLE001
    def load_ref(path, fallback):
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.normpath(os.path.join(os.path.dirname(module_file), os.pardir,
                                             "references", name))

try:
    import api_usage  # noqa: E402
except Exception:  # noqa: BLE001
    api_usage = None

_CFG = {
    "base": "https://publicwww.com/websites/",
    "export": "csvu",
    "timeout": 45,
    "max_rows": 200,
}
# Optional override file (absent on purpose today — knobs live in the embedded minimum).
_override_path = ref_path(__file__, "publicwww_endpoints.json")
if os.path.isfile(_override_path):
    try:
        _override = load_ref(_override_path, {"publicwww": dict(_CFG)})
        if isinstance(_override.get("publicwww"), dict) and _override["publicwww"]:
            _CFG = {**_CFG, **{k: v for k, v in _override["publicwww"].items()
                               if not str(k).startswith("_")}}
    except Exception:  # noqa: BLE001
        pass
BASE = str(_CFG.get("base") or "https://publicwww.com/websites/")
EXPORT = str(_CFG.get("export") or "csvu")
TIMEOUT = int(_CFG.get("timeout") or 45)
MAX_ROWS = int(_CFG.get("max_rows") or 200)


def publicwww_key():
    return _secret("PUBLICWWW_API_KEY", "PUBLICWWW_KEY")


def publicwww_configured() -> bool:
    return bool(publicwww_key())


def _host_of(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        host = (p.hostname or "").lower().rstrip(".")
        return host
    except Exception:  # noqa: BLE001
        return ""


def _record(op: str, credits: int, query: str, *, ok: bool = True, results: int = 0):
    if api_usage:
        try:
            api_usage.record("publicwww", op, credits=credits, query=query, ok=ok, results=results)
        except Exception:  # noqa: BLE001
            pass


def search(query: str, timeout: int = None, max_rows: int = None):
    """Source-code search → {query, total, domains, rows} | {skipped}|{error}. Never raises."""
    q = str(query or "").strip()
    if not q:
        return {"error": "empty query"}
    key = publicwww_key()
    if not key:
        return {"skipped": "PUBLICWWW_API_KEY not set"}
    # PublicWWW wants the query URL-path-encoded; quotes around a phrase are conventional.
    path_q = urllib.parse.quote(q, safe="")
    url = f"{BASE}{path_q}/?{urllib.parse.urlencode({'export': EXPORT, 'key': key})}"
    to = int(timeout if timeout is not None else TIMEOUT)
    cap = int(max_rows if max_rows is not None else MAX_ROWS)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Accept": "text/csv,*/*"})
        with urllib.request.urlopen(req, timeout=to) as r:
            raw = r.read()
            status = getattr(r, "status", 200) or 200
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        _record("search", 0, q, ok=False)
        if e.code in (401, 403):
            return {"skipped": f"PublicWWW rejected the key (HTTP {e.code})", "query": q}
        if e.code == 429:
            return {"skipped": "PublicWWW quota reached", "query": q}
        return {"error": f"HTTP {e.code}: {body or e.reason}", "query": q}
    except Exception as e:  # noqa: BLE001
        _record("search", 0, q, ok=False)
        return {"error": str(e), "query": q}

    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    # CSVU: url, rank, snip — or sometimes just bare URLs.
    domains, rows, seen = [], [], set()
    try:
        reader = csv.reader(io.StringIO(text))
        for i, cols in enumerate(reader):
            if i >= cap:
                break
            if not cols:
                continue
            # Skip header-ish first row
            if i == 0 and cols and cols[0].lower() in ("url", "website", "site", "domain"):
                continue
            u = cols[0].strip().strip('"')
            if not u or u.startswith("#"):
                continue
            host = _host_of(u)
            snip = cols[2].strip() if len(cols) > 2 else (cols[1].strip() if len(cols) > 1 else "")
            rows.append({"url": u, "host": host, "snippet": snip})
            if host and host not in seen:
                seen.add(host)
                domains.append(host)
    except Exception as e:  # noqa: BLE001
        _record("search", 1, q, ok=False)
        return {"error": f"csv parse failed: {e}", "query": q}

    _record("search", 1, q, ok=True, results=len(domains))
    return {"query": q, "total": len(domains), "domains": domains, "rows": rows, "http": status}


__all__ = ["publicwww_key", "publicwww_configured", "search"]
