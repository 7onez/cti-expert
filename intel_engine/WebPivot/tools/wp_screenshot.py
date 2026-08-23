#!/usr/bin/env python3
"""wp_screenshot — capture a rendered full-page PNG of a live page as EVIDENCE.

Everything else this toolkit stores is bytes or text; a screenshot is the page as a HUMAN
SEES IT — a Telegram channel bio naming the admins, a crew card, a members-area panel, a
deposit page. That view is real, contemporaneous evidence, but it is only usable in a report
if it is captured the way the rest of the evidence chain is: rendered post-JS (so it shows
what the page actually displays, not the empty SPA shell), written to the case evidence store
with a UTC timestamp, and HASHED so its integrity can be re-verified and cited.

This wraps `wp_net.render_dom` (Playwright/Chromium) to save the PNG, then does the evidence
part `render_dom` does not: sha256 the image, record its pixel dimensions and the page title,
and append a per-case manifest row — mirroring wp_capture's model so a screenshot cites the
SAME WAY a DOM capture does (cite the sha256, not the path). Captures are timestamped and
never overwritten, so re-capturing a page dates any change between the two.

OPSEC: this is an OUTBOUND, attributable fetch — a real browser hits the target from your
egress. On hostile infrastructure pass `--proxy` so the request does not carry the analyst's
own IP. Requires Playwright (the WebPivot venv / `RENDER_PY`).

CLI:
    python3 wp_screenshot.py <url> --case <ID> [--proxy URL] [--label "..."] [--json]
    python3 wp_screenshot.py --verify <png|manifest.json>      # re-hash, detect tampering
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # import wp_net / wp_refs standalone

try:
    from wp_refs import load_ref, ref_path                       # shared RULE 3 loader
except Exception:                                                # noqa: BLE001 — degrade, never block
    def load_ref(path, fallback):
        print("[wp_screenshot] WARNING: wp_refs unavailable; screenshot.json not read — "
              "using the minimal embedded defaults.", file=sys.stderr)
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.normpath(os.path.join(os.path.dirname(module_file), os.pardir,
                                             "references", name))

_FALLBACK = {
    "capture": {"timeout_seconds": 45,
                "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                               "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")},
    "layout": {"dir": "screenshots", "manifest_filename": "manifest.json"},
}
_REFS = load_ref(ref_path(__file__, "screenshot.json"), _FALLBACK)
CAP = _REFS["capture"]
LAYOUT = _REFS["layout"]


def _utc_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_slug(url: str) -> str:
    """Filesystem-safe host fragment; the manifest keeps the real URL."""
    from urllib.parse import urlsplit
    host = urlsplit(url if "://" in url else "http://" + url).netloc or url
    return re.sub(r"[^A-Za-z0-9._-]", "_", host).strip("_") or "host"


def _png_dims(data: bytes):
    """(width, height) from a PNG's IHDR, or (None, None) if it is not a PNG."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        return struct.unpack(">II", data[16:24])
    return (None, None)


def _title(html: str):
    if not html:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else None


def capture_screenshot(url: str, case: str = None, outdir: str = None, root: str = ".",
                       proxy: str = None, timeout: int = None, ua: str = None,
                       label: str = None, click: str = None, wait_selector: str = None,
                       wait_after: float = None, full_page: bool = True) -> dict:
    """Render `url` to a full-page PNG and record it as evidence. Returns the manifest entry.

    Many evidence pages sit behind ONE interaction — a splash/"enter" gate, a cookie wall, a
    lazy-loaded card grid. `click` clicks the first element whose visible text contains that
    string (e.g. "ENTER NETWORK") and re-waits; `wait_selector` waits for a CSS selector to
    appear; `wait_after` is a final settle in seconds. Every action taken is recorded in the
    manifest entry (`actions`), because a capture that clicked through a gate must SAY it did.
    """
    from playwright.sync_api import sync_playwright              # lazy: playwright only needed here

    host = _host_slug(url)
    if outdir:
        base = outdir
        man_dir = outdir
    elif case:
        man_dir = os.path.join(root, "cases", case, "evidence", LAYOUT["dir"])
        base = os.path.join(man_dir, host)
    else:
        base = man_dir = os.path.join(root, LAYOUT["dir"], host)
    os.makedirs(base, exist_ok=True)
    png = os.path.join(base, f"{_utc_stamp()}.png")

    to_ms = (timeout or CAP["timeout_seconds"]) * 1000
    actions: list[str] = []
    with sync_playwright() as p:
        launch = {"headless": True}
        if proxy:
            launch["proxy"] = {"server": proxy}
        browser = p.chromium.launch(**launch)
        ctx = browser.new_context(user_agent=ua or CAP["user_agent"],
                                  viewport={"width": 1280, "height": 800})
        page = ctx.new_page()
        page.goto(url, timeout=to_ms, wait_until="networkidle")
        if click:
            try:
                page.get_by_text(click, exact=False).first.click(timeout=8000)
                page.wait_for_load_state("networkidle", timeout=to_ms)
                actions.append(f"clicked text '{click}'")
            except Exception as e:                               # noqa: BLE001
                actions.append(f"click '{click}' FAILED ({str(e).splitlines()[0][:80]})")
        if wait_selector:
            try:
                page.wait_for_selector(wait_selector, timeout=10000)
                actions.append(f"waited for selector {wait_selector}")
            except Exception:                                    # noqa: BLE001
                actions.append(f"selector {wait_selector} NOT seen")
        if wait_after:
            page.wait_for_timeout(int(float(wait_after) * 1000))
            actions.append(f"settled {wait_after}s")
        final_url = page.url
        html = page.content()
        page.screenshot(path=png, full_page=full_page)
        browser.close()

    if not os.path.exists(png):
        raise RuntimeError("screenshot was not written — the render produced no image "
                           "(the target may have blocked the browser or timed out)")
    data = open(png, "rb").read()
    w, h = _png_dims(data)
    entry = {
        "url": url,
        "final_url": final_url,
        "captured_at": _utc_iso(),
        "path": png,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "width": w,
        "height": h,
        "title": _title(html),
        "proxy": bool(proxy),
        "label": label,
        "actions": actions,
        "full_page": full_page,
        "tool": "wp_screenshot",
    }
    # Append to the per-case manifest (one file listing every capture in the case).
    os.makedirs(man_dir, exist_ok=True)
    man = os.path.join(man_dir, LAYOUT["manifest_filename"])
    arr = []
    if os.path.exists(man):
        try:
            arr = json.load(open(man, encoding="utf-8"))
            if not isinstance(arr, list):
                arr = []
        except Exception:                                        # noqa: BLE001
            arr = []
    arr.append(entry)
    json.dump(arr, open(man, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    entry["manifest"] = man
    return entry


def verify(path: str) -> dict:
    """Re-hash a stored PNG (or every PNG a manifest lists) and report match/mismatch."""
    if os.path.isdir(path):
        path = os.path.join(path, LAYOUT["manifest_filename"])
    if path.endswith(".json"):
        arr = json.load(open(path, encoding="utf-8"))
        out = []
        for e in arr:
            p = e.get("path")
            ok = os.path.exists(p) and hashlib.sha256(open(p, "rb").read()).hexdigest() == e.get("sha256")
            out.append({"path": p, "sha256": e.get("sha256"),
                        "status": "MATCH" if ok else ("MISSING" if not (p and os.path.exists(p)) else "TAMPERED")})
        return {"manifest": path, "checked": len(out), "results": out,
                "all_ok": all(r["status"] == "MATCH" for r in out)}
    got = hashlib.sha256(open(path, "rb").read()).hexdigest()
    return {"path": path, "sha256": got}


def _main() -> None:
    ap = argparse.ArgumentParser(description="Capture a rendered full-page PNG of a page as hashed evidence.")
    ap.add_argument("url", nargs="?", help="URL (or host) to screenshot")
    ap.add_argument("--case", help="write into cases/<case>/evidence/screenshots/ with a manifest")
    ap.add_argument("--outdir", help="explicit output directory (overrides --case layout)")
    ap.add_argument("--root", default=".", help="repo root that holds cases/ (default: .)")
    ap.add_argument("--proxy", help="research egress (http://host:port) — use on hostile infra")
    ap.add_argument("--timeout", type=int, help="navigation timeout, seconds")
    ap.add_argument("--ua", help="override the browser User-Agent")
    ap.add_argument("--label", help="a short caption stored with the capture")
    ap.add_argument("--click", metavar="TEXT",
                    help="before capturing, click the first element whose text contains TEXT "
                         "(e.g. 'ENTER NETWORK') and re-wait — for splash/enter gates")
    ap.add_argument("--wait-selector", dest="wait_selector", metavar="CSS",
                    help="wait for this CSS selector to appear before capturing")
    ap.add_argument("--wait-after", dest="wait_after", type=float, metavar="SEC",
                    help="final settle time in seconds after load/click before the shot")
    ap.add_argument("--no-full-page", dest="full_page", action="store_false",
                    help="capture only the viewport, not the whole scrolled page")
    ap.add_argument("--verify", metavar="PNG|MANIFEST", help="re-hash a stored capture and exit")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.set_defaults(full_page=True)
    a = ap.parse_args()

    if a.verify:
        r = verify(a.verify)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        sys.exit(0 if r.get("all_ok", True) else 1)
    if not a.url:
        ap.error("a url is required (or use --verify)")
    try:
        e = capture_screenshot(a.url, case=a.case, outdir=a.outdir, root=a.root, proxy=a.proxy,
                               timeout=a.timeout, ua=a.ua, label=a.label, click=a.click,
                               wait_selector=a.wait_selector, wait_after=a.wait_after,
                               full_page=a.full_page)
    except Exception as exc:                                     # noqa: BLE001
        print(f"[wp_screenshot] capture failed: {exc}", file=sys.stderr)
        sys.exit(2)
    if a.json:
        print(json.dumps(e, ensure_ascii=False, indent=2))
    else:
        print(f"screenshot: {e['path']}\n  sha256 {e['sha256']}  ({e['width']}x{e['height']}px, "
              f"{e['bytes']} bytes)\n  url {e['url']}  ->  {e['final_url']}\n  captured {e['captured_at']}"
              + (f"\n  manifest {e['manifest']}" if e.get('manifest') else ""))


if __name__ == "__main__":
    _main()
