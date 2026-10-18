#!/usr/bin/env python3
"""Offline unit gate for wp_sellers (AdSense pub id -> legal payee via Google's sellers.json).

The downloader seam (`wp_sellers._download`) is stubbed with a tiny synthetic sellers.json and the
cache is pointed at a TemporaryDirectory, so nothing reaches the network or the real cache. Rails:
a known pub id (any spelling) resolves to its payee name+domain; an unknown id is None; a corrupt
cache is re-downloaded instead of raising; a dead download with no usable cache is None, never an
exception; a stale cache is refreshed; the download is ledgered as a FREE call; and the rung table
classes a named payee as owner.
"""
import json
import os
import sys
import tempfile
import time

_ENGINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_WP_TOOLS = os.path.join(_ENGINE, "WebPivot", "tools")
_TOOLS = os.path.join(_ENGINE, "tools")
for _p in (_WP_TOOLS, _TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import wp_sellers as W  # noqa: E402
import api_usage  # noqa: E402

_SYNTH = {
    "contact_email": "ads@example.com",
    "version": "1.0",
    "sellers": [
        {"seller_id": "pub-0000000000000001", "name": "Example Payee LLC",
         "domain": "example.com", "seller_type": "PUBLISHER"},
        {"seller_id": "pub-0000000000000002", "is_confidential": 1,
         "seller_type": "PUBLISHER"},
        "not-a-row",
    ],
}


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    calls = []
    mode = {"payload": json.dumps(_SYNTH), "fail": False}

    def fake_download(url, dest, timeout):
        calls.append(url)
        if mode["fail"]:
            raise OSError("synthetic network failure")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(mode["payload"])
        return len(mode["payload"])

    saved = (W._download, W.CACHE_PATH, dict(W._INDEX_CACHE), os.environ.get("API_USAGE_LOG"))
    with tempfile.TemporaryDirectory() as tmp:
        ledger = os.path.join(tmp, "api_usage.jsonl")
        os.environ["API_USAGE_LOG"] = ledger
        W._download = fake_download
        W.CACHE_PATH = os.path.join(tmp, "cache", "sellers.json")
        W._INDEX_CACHE.clear()
        try:
            # 1. first lookup downloads once and resolves every pub-id spelling
            row = W.lookup("ca-pub-0000000000000001")
            ok(row is not None and row["name"] == "Example Payee LLC" and row["domain"] == "example.com",
               "known pub id -> payee name + domain")
            ok(len(calls) == 1 and os.path.exists(W.CACHE_PATH), "first lookup downloads once into the cache")
            ok((W.lookup("pub-0000000000000001") or {}).get("seller_type") == "PUBLISHER"
               and (W.lookup("0000000000000001") or {}).get("name") == "Example Payee LLC",
               "pub-… and bare-digit spellings resolve the same row")
            ok(len(calls) == 1, "repeat lookups reuse the parsed index (no re-download)")

            # 2. unknown / malformed ids -> None
            ok(W.lookup("ca-pub-9999999999999999") is None, "unknown pub id -> None")
            ok(W.lookup("not a pub id") is None and W.lookup(None) is None, "malformed id -> None")
            conf = W.lookup("pub-0000000000000002")
            ok(conf is not None and conf["name"] is None, "confidential row -> no payee name")

            # 3. free-call ledger
            rows = [json.loads(l) for l in open(ledger, encoding="utf-8") if l.strip()]
            ok(len(rows) == 1 and rows[0]["provider"] == "google_sellers"
               and rows[0]["credits"] == 0 and rows[0]["ok"] is True,
               "download ledgered through api_usage as a free (0-credit) call")

            # 4. a corrupt cache is re-downloaded, never raised
            with open(W.CACHE_PATH, "w", encoding="utf-8") as fh:
                fh.write("{ truncated sellers")
            W._INDEX_CACHE.clear()
            n0 = len(calls)
            try:
                row = W.lookup("ca-pub-0000000000000001")
                raised = False
            except Exception:
                row, raised = None, True
            ok(not raised and row is not None and row["name"] == "Example Payee LLC",
               "corrupt cache -> re-download -> lookup still answers")
            ok(len(calls) == n0 + 1, "corrupt cache triggered exactly one re-download")

            # 5. corrupt cache AND a dead download -> None, no exception
            with open(W.CACHE_PATH, "w", encoding="utf-8") as fh:
                fh.write("[]")
            W._INDEX_CACHE.clear()
            mode["fail"] = True
            try:
                row = W.lookup("ca-pub-0000000000000001")
                raised = False
            except Exception:
                row, raised = None, True
            ok(not raised and row is None, "corrupt cache + failed download -> None (never raises)")
            ok(W.load_index() is None, "load_index -> None when nothing usable exists")

            # 6. a stale cache is refreshed after the TTL; a failed refresh keeps the old data
            mode["fail"] = False
            fake_download(W.URL, W.CACHE_PATH, 1)
            old = time.time() - (W.TTL_DAYS + 1) * 86400
            os.utime(W.CACHE_PATH, (old, old))
            W._INDEX_CACHE.clear()
            n0 = len(calls)
            ok(W.lookup("pub-0000000000000001") is not None and len(calls) == n0 + 1,
               "cache older than ttl_days -> re-downloaded")
            os.utime(W.CACHE_PATH, (old, old))
            W._INDEX_CACHE.clear()
            mode["fail"] = True
            ok((W.lookup("pub-0000000000000001") or {}).get("name") == "Example Payee LLC",
               "stale cache + failed refresh -> stale data still answers")
        finally:
            W._download, W.CACHE_PATH = saved[0], saved[1]
            W._INDEX_CACHE.clear()
            W._INDEX_CACHE.update(saved[2])
            if saved[3] is None:
                os.environ.pop("API_USAGE_LOG", None)
            else:
                os.environ["API_USAGE_LOG"] = saved[3]
            api_usage._session.clear()

    # 7. a named payee is an owner-rung class
    import selector_types  # noqa: E402
    ok(selector_types.rung_for("ads.payee") == "owner", "rungs.json: ads.payee -> owner")
    ok(selector_types.rung_for("ads.adsense") == "kit", "rungs.json: the pub id itself stays kit")
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    print(f"{p} passed, {f} failed")
    raise SystemExit(bool(f))
