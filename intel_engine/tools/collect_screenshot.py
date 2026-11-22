#!/usr/bin/env python3
"""collect_screenshot — the per-host screenshot step of a collection, run as a CHILD process.

collect_core.collect_host (stdlib-only) launches this under the render interpreter after a host
was collected, so the browser, Playwright and the proxy pool stay out of the stdlib layer. It
takes ONE full-page PNG through wp_screenshot — the same store, format and custody chain as the
`capture_screenshot` tool: cases/<case>/evidence/screenshots/<host>/<UTC>.png, a manifest row
with sha256, a `capture` custody line, then `wp_screenshot.verify` hashes it again, seals it
read-only and logs the `verify` line (seal_status).

Egress: a HOSTILE host is shot only through the pool exit its fetch used (`--exit`, the masked
host:port pivot_extract recorded in meta.hostile_fetch), resolved against the same pool the
collector drew from (`--proxy-range`, else the cti_proxy pool) and pinned no-direct. No match —
no shot; direct is never an option. A non-hostile host takes the collector's first pool proxy or
the process proxy env, as its fetch did.

Prints ONE JSON line: {status: ok | failed | unavailable | skipped, reason, path, sha256,
seal_status, custody_head, url}. Never raises; exit 0 unless argparse rejects the call.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WP = os.path.join(os.path.dirname(HERE), "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)


def _pick_proxy(hostile: bool, exit_masked: str | None, proxy_range: str | None):
    """(proxy or None, refusal or None). Hostile: only the exit the fetch used, never direct."""
    explicit = None
    if proxy_range:
        from wp_common import parse_proxies
        explicit = parse_proxies(proxy_range) or None
    if not hostile:
        return (explicit[0] if explicit else None), None
    if not exit_masked:
        return None, "no pool exit recorded for the fetch (a hostile host is never shot direct)"
    import wp_net
    for p in wp_net.hostile_exits(explicit):
        if p and wp_net.mask_exit(p) == exit_masked:
            return p, None
    return None, f"pool exit {exit_masked} not in the current pool (never shot direct)"


def shoot(url: str, case: str, root: str, *, host: str | None = None, hostile: bool = False,
          exit_masked: str | None = None, proxy_range: str | None = None,
          timeout: int | None = None, extra: dict | None = None, label: str | None = None) -> dict:
    """One custody-tracked screenshot; returns the status dict. Never raises."""
    out = {"status": "failed", "reason": None, "url": url, "path": None, "sha256": None,
           "seal_status": None, "custody_head": None}
    try:
        import wp_browser
        if not wp_browser.chromium_available():
            print(f"[!] screenshot unavailable: {wp_browser.chromium_missing_note()}", file=sys.stderr)
            return {**out, "status": "unavailable", "reason": "no browser"}
        proxy, refusal = _pick_proxy(hostile, exit_masked, proxy_range)
        if refusal:
            return {**out, "status": "skipped", "reason": refusal}
        if hostile:
            os.environ["CTI_PROXY_ALLOW_DIRECT"] = "0"
        import wp_screenshot
        e = wp_screenshot.capture_screenshot(url, case=case, root=root, proxy=proxy, timeout=timeout,
                                             host=host, extra=extra, label=label)
        v = wp_screenshot.verify(e["path"])
        return {**out, "status": "ok", "path": e["path"], "sha256": e["sha256"],
                "proxy": bool(proxy), "seal_status": v.get("seal_status"),
                "custody_head": v.get("custody_head") or e.get("custody_head")}
    except Exception as exc:  # noqa: BLE001 — a screenshot never fails the collection
        msg = (str(exc).strip().splitlines() or [type(exc).__name__])[0][:200]
        return {**out, "reason": f"{type(exc).__name__}: {msg}"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Per-host collection screenshot into case custody.")
    ap.add_argument("url")
    ap.add_argument("--case", required=True)
    ap.add_argument("--root", required=True, help="directory holding cases/")
    ap.add_argument("--host", default=None, help="subject host (an archive URL is not the host)")
    ap.add_argument("--hostile", action="store_true")
    ap.add_argument("--exit", dest="exit_masked", default=None, help="masked host:port of the fetch exit")
    ap.add_argument("--proxy-range", dest="proxy_range", default=None)
    ap.add_argument("--timeout", type=int, default=None, help="navigation timeout, seconds")
    ap.add_argument("--label", default=None)
    ap.add_argument("--extra", default=None, help="JSON object merged into the manifest entry")
    a = ap.parse_args(argv)
    try:
        extra = json.loads(a.extra) if a.extra else None
    except ValueError:
        extra = None
    r = shoot(a.url, a.case, a.root, host=a.host, hostile=a.hostile, exit_masked=a.exit_masked,
              proxy_range=a.proxy_range, timeout=a.timeout, extra=extra, label=a.label)
    print(json.dumps(r, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
