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

Each manifest entry also carries the collection context (wp_custody, handbook §5): `collector`,
`persona`, `egress_ip` (or null plus `egress_note`), the local `clock_sync` state at collection
start, and the tool and browser versions (`tool_version`, `browser`, `browser_version`,
`playwright_version`). Inside a case store the capture and every verify append to the custody log
`cases/<case>/evidence/custody.jsonl`, and a PNG that verifies is made read-only. The per-case
manifest itself stays writable — it is appended on every capture — and is never what a report
cites; the PNG's sha256 is.

OPSEC: this is an OUTBOUND, attributable fetch — a real browser hits the target from your
egress. On hostile infrastructure pass `--proxy` so the request does not carry the analyst's
own IP. Requires Playwright (the WebPivot venv / `RENDER_PY`).

CLI:
    python3 wp_screenshot.py <url> --case <ID> [--proxy URL] [--label "..."] [--json]
                             [--persona P] [--egress-ip IP] [--collector NAME]
    python3 wp_screenshot.py --verify <png|manifest.json> [--no-seal]   # re-hash, detect tampering
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

# Per-call ceiling — ONE resolver (wp_timeouts: env → .env → references/timeouts.json → 18000s / 5 h).
# Applied to the Playwright page.goto timeout below.
from wp_timeouts import CALL_TIMEOUT, floor as _floor  # noqa: E402
from wp_ua import DEFAULT_UA  # noqa: E402 — the one User-Agent source (Android Chrome)
import wp_custody  # noqa: E402 — collection context, custody log, seal

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
    "capture": {"timeout_seconds": 45},
    "layout": {"dir": "screenshots", "manifest_filename": "manifest.json"},
}
_REFS = load_ref(ref_path(__file__, "screenshot.json"), _FALLBACK)
CAP = _REFS["capture"]
LAYOUT = _REFS["layout"]
# The browser UA sent to the target: the shared Android default unless screenshot.json overrides it.
CAPTURE_UA = CAP.get("user_agent") or DEFAULT_UA
SCREENSHOT_VERSION = "wp_screenshot/2"   # /2: collection context, browser versions, custody + seal
_ENGINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def case_home(root: str = None) -> str:
    """The directory holding cases/: an explicit `root` (--root), else $INTEL_HOME, else the
    vendored intel_engine/ — never the caller's cwd (AGENTS.md: cases live under
    $INTEL_HOME/cases/<id>/ only; a cwd default split one case across two stores)."""
    return root or os.environ.get("INTEL_HOME") or _ENGINE


def _playwright_version():
    try:
        from importlib.metadata import version
        return version("playwright")
    except Exception:                                            # noqa: BLE001
        return None


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


def capture_screenshot(url: str, case: str = None, outdir: str = None, root: str = None,
                       proxy: str = None, timeout: int = None, ua: str = None,
                       label: str = None, click: str = None, wait_selector: str = None,
                       wait_after: float = None, full_page: bool = True,
                       extra: dict = None, host: str = None, collector: str = None,
                       persona: str = None, egress_ip: str = None) -> dict:
    """Render `url` to a full-page PNG and record it as evidence. Returns the manifest entry.

    Many evidence pages sit behind ONE interaction — a splash/"enter" gate, a cookie wall, a
    lazy-loaded card grid. `click` clicks the first element whose visible text contains that
    string (e.g. "ENTER NETWORK") and re-waits; `wait_selector` waits for a CSS selector to
    appear; `wait_after` is a final settle in seconds. Every action taken is recorded in the
    manifest entry (`actions`), because a capture that clicked through a gate must SAY it did.

    `extra` is merged into the manifest entry (provenance such as source="wayback", the archive
    URL and its archived_at) and `host` files the capture under the SUBJECT host when `url` is a
    third-party copy of it (a web-archive snapshot URL is not the host it shows).
    """
    import wp_browser
    if not wp_browser.chromium_available():
        # Evidence pixels are Chromium-only by design: a Moli software-paint PNG is not what a
        # victim's browser showed, so there is no fallback engine here.
        raise RuntimeError(wp_browser.chromium_missing_note())
    from playwright.sync_api import sync_playwright              # lazy: playwright only needed here

    root = case_home(root) if case else (root or ".")
    proxy_used = wp_browser.resolve_proxy(proxy)
    context_ev = (wp_custody.evidence_root(outdir) if outdir else
                  wp_custody.case_evidence_dir(case, root) if case else None)
    context = wp_custody.collection_context(proxy_used, collector, persona, egress_ip,
                                            evidence_dir=context_ev)
    host = _host_slug(host) if host else _host_slug(url)
    if outdir:
        base = outdir
        man_dir = outdir
    elif case:
        man_dir = os.path.join(root, "cases", case, "evidence", LAYOUT["dir"])
        base = os.path.join(man_dir, host)
    else:
        base = man_dir = os.path.join(root, LAYOUT["dir"], host)
    os.makedirs(base, exist_ok=True)
    stamp = _utc_stamp()
    png = os.path.join(base, f"{stamp}.png")
    to_ms = _floor(timeout or CAP["timeout_seconds"]) * 1000
    actions: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(**wp_browser.chromium_launch_kwargs(proxy))
        try:
            browser_version = browser.version
        except Exception:                                        # noqa: BLE001
            browser_version = None
        ctx = browser.new_context(user_agent=ua or CAPTURE_UA,
                                  viewport={"width": 1280, "height": 800})
        page = ctx.new_page()
        try:
            page.goto(url, timeout=to_ms, wait_until="networkidle")
        except Exception as e:                                   # noqa: BLE001
            m = re.search(r"net::(ERR_CERT_[A-Z_]+)", str(e))
            if not m:
                browser.close()
                raise
            # A certificate that does not match the hostname is itself evidence (a shared or
            # mis-provisioned cert). Render anyway and SAY so in the manifest, never silently.
            ctx.close()
            ctx = browser.new_context(user_agent=ua or CAPTURE_UA,
                                      viewport={"width": 1280, "height": 800}, ignore_https_errors=True)
            page = ctx.new_page()
            page.goto(url, timeout=to_ms, wait_until="networkidle")
            actions.append(f"TLS certificate error ignored ({m.group(1)})")
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
        data = page.screenshot(full_page=full_page)
        browser.close()

    n = 2
    while True:
        try:
            fd = os.open(png, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            break
        except FileExistsError:
            png = os.path.join(base, f"{stamp}-{n}.png")
            n += 1
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
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
        "proxy": bool(proxy_used),
        "label": label,
        "actions": actions,
        "full_page": full_page,
        "tool": "wp_screenshot",
        "tool_version": SCREENSHOT_VERSION,
        "browser": "chromium",
        "browser_version": browser_version,
        "playwright_version": _playwright_version(),
        "host": host,
        **context,
    }
    if extra:
        entry.update(extra)
    # Append to the per-case manifest (one file listing every capture in the case).
    os.makedirs(man_dir, exist_ok=True)
    man = os.path.join(man_dir, LAYOUT["manifest_filename"])
    # Serialise read/append/write together, so concurrent exclusive PNGs retain both records.
    with open(man, "a+", encoding="utf-8") as fh:
        if wp_custody.fcntl:
            wp_custody.fcntl.flock(fh.fileno(), wp_custody.fcntl.LOCK_EX)
        fh.seek(0)
        try:
            arr = json.load(fh)
            if not isinstance(arr, list):
                arr = []
        except ValueError:
            arr = []
        entry["manifest"] = man
        ev = wp_custody.evidence_root(png)
        if ev:
            entry["custody"] = wp_custody.append(
                ev, "capture", wp_custody.item_ref(ev, png), entry["sha256"],
                f"rendered screenshot {url}" + (f" ({label})" if label else ""), context.get("collector"))
        entry["custody_head"] = entry["custody"]["head"] if ev else None
        arr.append(entry)
        fh.seek(0)
        fh.truncate()
        json.dump(arr, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    return entry


def _check(p: str, expected: str, seal: bool = None, actor: str = None,
           case_dir: str = None, log: bool = True) -> dict:
    """Hash and seal the same no-follow descriptor; manifest entries stay inside their case.

    Every result carries `seal_status`: `sealed`, `not_sealed` (not requested, or the content did
    not match), `unavailable_on_platform` (no `fchmod`) or `failed` (the chmod itself raised after
    the content matched — the PNG is intact, only unsealed). `seal_reason` explains the last two."""
    ev = wp_custody.evidence_root(p) if p else None
    if case_dir is not None and (not p or wp_custody.contained_ref(
            case_dir, os.path.relpath(os.path.abspath(p), os.path.abspath(case_dir))) is None):
        return {"path": p, "sha256": expected, "status": "REJECTED", "sealed": False,
                "seal_status": "not_sealed", "custody_head": None}
    logged = wp_custody.first_capture_digest(ev, wp_custody.item_ref(ev, p)) if ev else None
    expected = logged if logged is not None else expected
    sealed = False
    seal_state = {"seal_status": "not_sealed"}
    try:
        with wp_custody.pinned(p) as fd:
            before = os.fstat(fd)
            got = wp_custody.fd_sha256(fd)
            ok = got == expected and wp_custody.inode_state(before) == wp_custody.inode_state(os.fstat(fd))
            status = "MATCH" if ok else "TAMPERED"
            if ok and (seal if seal is not None else bool(ev)):
                if hasattr(os, "fchmod"):
                    try:
                        wp_custody.seal(p, [(p, fd, before)])
                        sealed = True
                        seal_state = {"seal_status": "sealed"}
                    except wp_custody.SealError as exc:
                        seal_state = {"seal_status": "failed", "seal_reason": str(exc)}
                else:
                    seal_state = {"seal_status": "unavailable_on_platform",
                                  "seal_reason": "os.fchmod unavailable; pathname chmod is unsafe"}
    except FileNotFoundError:
        status = "MISSING"
    except (OSError, ValueError, TypeError):
        status = "TAMPERED"
    if status != "MATCH":
        sealed, seal_state = False, {"seal_status": "not_sealed"}
    custody = None
    if ev and log:
        custody = wp_custody.append(ev, "verify", wp_custody.item_ref(ev, p), expected,
                                     status + ("; sealed read-only" if sealed else "")
                                     + (f"; seal {seal_state['seal_status']}: {seal_state['seal_reason']}"
                                        if seal_state.get("seal_reason") else ""), actor)
    return {"path": p, "sha256": expected, "status": status, "sealed": sealed, **seal_state,
            "custody_head": custody["head"] if custody else None}


def verify(path: str, seal: bool = None, actor: str = None) -> dict:
    """Re-hash a stored PNG (or every PNG a manifest lists) and report match/mismatch. Only reads
    the PNGs and the manifest, so it works on sealed (read-only) files."""
    if os.path.isdir(path):
        path = os.path.join(path, LAYOUT["manifest_filename"])
    if path.endswith(".json"):
        with wp_custody.pinned(path) as fd, os.fdopen(os.dup(fd), encoding="utf-8") as fh:
            arr = json.load(fh)
        ev = wp_custody.evidence_root(path)
        case_dir = os.path.dirname(os.path.abspath(ev)) if ev else os.path.dirname(os.path.abspath(path))
        out = [_check(e.get("path"), e.get("sha256"), seal, actor, case_dir) for e in arr]
        return {"manifest": path, "checked": len(out), "results": out,
                "custody_head": wp_custody.check_log(ev).get("head") if ev else None,
                "all_ok": all(r["status"] == "MATCH" for r in out)}
    # A lone PNG: compare against the case manifest entry that recorded it, when there is one.
    ev = wp_custody.evidence_root(path)
    man = os.path.join(ev, LAYOUT["dir"], LAYOUT["manifest_filename"]) if ev else None
    if man and os.path.isfile(man):
        for e in json.load(open(man, encoding="utf-8")):
            p = e.get("path")
            if p and os.path.exists(p) and os.path.exists(path) and os.path.samefile(p, path):
                r = _check(path, e.get("sha256"), seal, actor)
                return dict(r, all_ok=r["status"] == "MATCH")
    if ev and wp_custody.first_capture_digest(ev, wp_custody.item_ref(ev, path)) is not None:
        r = _check(path, None, seal, actor)
        return dict(r, all_ok=r["status"] == "MATCH")
    got = wp_custody.file_sha256(path)
    return {"path": path, "sha256": got, "custody_head": None, "sealed": False,
            "seal_status": "not_sealed", "note": "no manifest entry found — digest only, not compared"}


def _main() -> None:
    ap = argparse.ArgumentParser(description="Capture a rendered full-page PNG of a page as hashed evidence.")
    ap.add_argument("url", nargs="?", help="URL (or host) to screenshot")
    ap.add_argument("--case", help="write into cases/<case>/evidence/screenshots/ with a manifest")
    ap.add_argument("--outdir", help="explicit output directory (overrides --case layout)")
    ap.add_argument("--root", default=None,
                    help="directory holding cases/ (default: $INTEL_HOME, else intel_engine/)")
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
    ap.add_argument("--no-seal", dest="seal", action="store_false", default=None,
                    help="with --verify: do not make a matching case PNG read-only")
    ap.add_argument("--collector", help="who collects (default: $CTI_COLLECTOR, else a case pseudonym)")
    ap.add_argument("--persona", help="virtual identity in use (default: $CTI_PERSONA)")
    ap.add_argument("--egress-ip", dest="egress_ip",
                    help="egress IP confirmed with `proxy.py test` (default: $CTI_EGRESS_IP)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.set_defaults(full_page=True)
    a = ap.parse_args()

    if a.verify:
        r = verify(a.verify, seal=a.seal, actor=a.collector)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        sys.exit(0 if r.get("all_ok", True) else 1)
    if not a.url:
        ap.error("a url is required (or use --verify)")
    try:
        e = capture_screenshot(a.url, case=a.case, outdir=a.outdir, root=a.root, proxy=a.proxy,
                               timeout=a.timeout, ua=a.ua, label=a.label, click=a.click,
                               wait_selector=a.wait_selector, wait_after=a.wait_after,
                               full_page=a.full_page, collector=a.collector, persona=a.persona,
                               egress_ip=a.egress_ip)
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
