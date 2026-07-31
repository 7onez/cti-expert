#!/usr/bin/env python3
"""Offline unit gate for the urlscan resource-reverse logic in pivot_extract.

The urlscan reverses themselves are LIVE (network) and can't run in the offline
harness, but the logic that decides WHICH resource to reverse is pure and must be
gated: `_is_distinctive_basename` (skip generic gtm.js/jquery, keep build/token
files) and `_resource_filename_for` (pick the external SaaS script tied to a
third-party host / saas token, never the seed's own asset). Run standalone or via
run_eval.py (which imports and executes check()).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "WebPivot", "tools"))
import pivot_extract as p  # noqa: E402


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- distinctiveness filter ------------------------------------------------
    keep = ["project_100200_300400_1234567890.js", "index-B3GD2NjP.js",
            "app.7f3c9a2b.chunk.js", "widget-v2-Cok29e2F.css"]
    drop = ["gtm.js", "app.js", "jquery.min.js", "analytics.js", "style.css",
            "main.js", "bundle.js", "index.js", "install.js"]
    for b in keep:
        ok(p._is_distinctive_basename(b), f"distinctive keeps {b}")
    for b in drop:
        ok(not p._is_distinctive_basename(b), f"distinctive drops generic {b}")

    # --- resource resolution ---------------------------------------------------
    result = {
        "meta": {"host": "example.com"},
        "artifacts": {
            "script_srcs": [
                "https://plugin-code.salesmartly.com/js/project_100200_300400_1234567890.js",
                "https://www.googletagmanager.com/gtm.js?id=GTM-TEST",
                "/assets/index-B3GD2NjP.js",              # seed's own (relative) — must be ignored
                "https://example.com/assets/app.js",     # seed's own (absolute) — must be ignored
            ],
            "stylesheets": [],
        },
    }
    # third-party host → its distinctive script basename
    ok(p._resource_filename_for(result, "third_party_host", "plugin-code.salesmartly.com",
                                "example.com") == "project_100200_300400_1234567890.js",
       "resolves salesmartly script for its third_party_host")
    # a CDN host with only a generic script → nothing distinctive to reverse
    ok(p._resource_filename_for(result, "third_party_host", "www.googletagmanager.com",
                                "example.com") is None,
       "no reverse for generic CDN (gtm.js) host")
    # saas token embedded in the script URL → the carrying script
    ok(p._resource_filename_for(result, "saas:salesmartly", "100200_300400",
                                "example.com") == "project_100200_300400_1234567890.js",
       "resolves script carrying a saas token")
    # the seed's own asset is never returned as a cross-site link
    ok(p._resource_filename_for(result, "third_party_host", "example.com",
                                "example.com") is None,
       "never reverses the seed's own host")
    return passed, failed, out


if __name__ == "__main__":
    ps, fs, lines = check()
    for status, label in lines:
        mark = "\033[32m✔\033[0m" if status == "ok" else "\033[31mx\033[0m"
        print(f"  {mark} {label}")
    print(f"\n{ps}/{ps+fs} assertions passed" + ("" if not fs else f" — {fs} FAILED"))
    sys.exit(1 if fs else 0)
