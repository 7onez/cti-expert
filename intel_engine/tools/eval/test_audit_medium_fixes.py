#!/usr/bin/env python3
"""Regression gate for the MEDIUM correctness bugs fixed in the 2026-07-31 audit.

  M1 wp_net.detect_cloudflare_challenge — cf-signalled 403/429/503 no longer silently dropped
  M2 fallback_probe SAN-sibling basis   — registrable-domain compare (fakesite.com ≠ site.com)
  M4 convergence._indicators_from_raw   — social key uses KB's last-path-segment form

(M3 aggregate_case2 CF-range and M5/M6 atomic-writes/timeouts are exercised by a functional
smoke in the audit run, not here. aggregate_case2 IS import-safe as of the __main__ guard — before
that, importing it ran the aggregation and wrote to a real case.) Pure stdlib, deterministic.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
import wp_net                       # noqa: E402
import fallback_probe as fp         # noqa: E402
import convergence as cv            # noqa: E402


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    d = wp_net.detect_cloudflare_challenge
    # --- M1: cf-signalled denials are classified, not dropped ---
    ok(d(503, {}, "Just a moment...") == "cloudflare_challenge", "M1 503 + interstitial body → challenge")
    ok(d(403, {"cf-ray": "abc123"}, "access denied") == "cloudflare_block", "M1 403 + cf-ray, no body → block")
    ok(d(429, {"cf-ray": "abc123"}, "") == "cloudflare_block", "M1 429 + cf-ray → block (was dropped)")
    ok(d(200, {"cf-ray": "abc123"}, "hi") is None, "M1 200 → not a CF interstitial")
    ok(d(403, {}, "plain forbidden") is None, "M1 403, no cf + no marker → None")

    # --- M2: SAN-sibling classification basis (registrable-domain compare) ---
    ok(fp._reg("fakesite.com") != fp._reg("site.com"), "M2 fakesite.com is a DIFFERENT registrable (sibling)")
    ok(fp._reg("mail.site.com") == fp._reg("site.com"), "M2 mail.site.com shares registrable (subdomain)")
    ok(fp._reg("site.com") == fp._reg("site.com"), "M2 self is same registrable")

    # --- M4: convergence social key matches the KB's stored last-segment form ---
    inds = cv._indicators_from_raw({"artifacts": {"socials": {"telegram": ["https://t.me/joinchat/ABC123"]}}})
    ok("social:telegram:ABC123" in inds, "M4 social key = last path segment (matches KB)")
    ok("social:telegram:https://t.me/joinchat/ABC123" not in inds, "M4 full-URL social key gone")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
