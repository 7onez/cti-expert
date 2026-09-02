#!/usr/bin/env python3
"""
house_report_captures.py — landing-page captures for the deterministic house report.

IntelReport Rule 15a: a rendered screenshot of every estate host sits INLINE in the cluster
section, captioned with what/when; the full sha256 goes to the evidence ledger (Rule 21).
Existing PNGs are reused (cases/<case>/screenshots/<host>.png from the pipeline's --screenshots,
cases/<case>/evidence/screenshots/<host>/<UTC>.png from wp_screenshot); missing ones are captured
through the research-egress proxy policy exactly as a pipeline fetch is — skipped and stated,
never forced, when that policy blocks. Deterministic; PIL (optional) fits captures to a page.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP_TOOLS = os.path.join(ROOT, "WebPivot", "tools")
PROXY_DIR = os.path.join(os.path.dirname(ROOT), "scripts", "proxy")

MAX_PX = 4000          # xelatex \includegraphics limit (see house_report._MAX_PX)
SHOWN_ASPECT = 0.8     # a full-page capture is cropped to width×0.8 — the first screen a visitor sees;
                       # at text-block width that prints ~13 cm tall, so two captures share a page

# --------------------------------------------------------------------------- captures
def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    return (urlsplit(url if "://" in url else "http://" + url).hostname or url).lower()


def _mtime_utc(path: str) -> str:
    return dt.datetime.fromtimestamp(os.path.getmtime(path), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def existing_screenshots(case_dir: str) -> dict:
    """host -> {host, path, url, captured_at, sha256, title, actions} for every capture on disk.
    The wp_screenshot manifest wins over the bare pipeline PNG (it carries provenance)."""
    out: dict = {}
    shots = os.path.join(case_dir, "screenshots")
    if os.path.isdir(shots):
        for fn in sorted(os.listdir(shots)):
            if fn.endswith(".png"):
                host = fn[:-4].lower()
                out[host] = {"host": host, "path": os.path.join(shots, fn), "url": f"https://{host}/",
                             "captured_at": _mtime_utc(os.path.join(shots, fn)), "sha256": None,
                             "title": None, "actions": []}
    man_jsonl = os.path.join(case_dir, "evidence", "manifest.jsonl")
    if os.path.exists(man_jsonl):
        for ln in open(man_jsonl, encoding="utf-8"):
            try:
                e = json.loads(ln)
            except ValueError:
                continue
            sp = e.get("screenshot_path")
            host = (e.get("host") or "").lower()
            if sp and host in out and os.path.exists(sp) and e.get("collected_at"):
                out[host]["captured_at"] = e["collected_at"]
    man = os.path.join(case_dir, "evidence", "screenshots", "manifest.json")
    if os.path.exists(man):
        try:
            arr = json.load(open(man, encoding="utf-8"))
        except ValueError:
            arr = []
        for e in arr if isinstance(arr, list) else []:
            p = e.get("path") or ""
            # wp_screenshot stores the path relative to the --root it was given; try the roots we know
            cands = [p] if os.path.isabs(p) else [p, os.path.join(os.path.dirname(ROOT), p), os.path.join(ROOT, p),
                                                  os.path.join(os.path.dirname(man), os.path.basename(os.path.dirname(p)), os.path.basename(p))]
            p = next((x for x in cands if x and os.path.exists(x)), None)
            if not p:
                continue
            host = _host_of(e.get("url") or "")
            prev = out.get(host)
            if prev and prev.get("sha256") and (prev.get("captured_at") or "") > (e.get("captured_at") or ""):
                continue   # keep the newer capture
            out[host] = {"host": host, "path": p, "url": e.get("url") or f"https://{host}/",
                         "captured_at": e.get("captured_at") or _mtime_utc(p), "sha256": e.get("sha256"),
                         "title": e.get("title"), "actions": e.get("actions") or [],
                         "final_url": e.get("final_url")}
    for e in out.values():
        if not e.get("sha256"):
            e["sha256"] = _sha256(e["path"])
    return out


def egress_policy() -> dict:
    """The research-egress decision the pipeline applies to a live fetch, reused verbatim:
    proxied when the proxy pool is enabled and non-empty; direct only when the store allows it;
    otherwise blocked (a report build must never touch hostile infra from the analyst's IP)."""
    try:
        sys.path.insert(0, PROXY_DIR)
        import cti_proxy  # noqa: E402
    except Exception:  # noqa: BLE001
        return {"mode": "blocked", "proxy": None, "why": "proxy policy module unavailable"}
    cti_proxy.load_env_file()
    cfg = cti_proxy.load_store()
    if cti_proxy.is_enabled(cfg):
        pool = cti_proxy.build_pool(cfg)
        if pool:
            start = cti_proxy.pick_start(pool, cti_proxy.rotation_mode(cfg))
            return {"mode": "proxied", "proxy": pool[start], "pool": pool[start:] + pool[:start], "why": ""}
    if cti_proxy.allow_direct(cfg):
        return {"mode": "direct", "proxy": None, "pool": [None], "why": ""}
    return {"mode": "blocked", "proxy": None, "pool": [], "why": "no research-egress proxy configured and direct fetches are not allowed"}


_PROXY_FAULT = re.compile(r"net::ERR_(TUNNEL_CONNECTION_FAILED|PROXY_[A-Z_]+|CONNECTION_(RESET|CLOSED|TIMED_OUT|REFUSED))")


# Reader-facing wording for a failed render (Rule 12: never the raw browser/tool message).
_NET_WORDS = [
    (r"ERR_NAME_NOT_RESOLVED|ERR_DNS", "DNS did not resolve"),
    (r"ERR_CONNECTION_REFUSED", "connection refused"),
    (r"ERR_CONNECTION_(RESET|CLOSED)", "connection dropped"),
    (r"ERR_CONNECTION_TIMED_OUT", "connection timed out"),
    (r"ERR_CERT_|ERR_SSL_", "TLS error"),
    (r"ERR_TUNNEL_|ERR_PROXY_", "not reachable through the research egress"),
    (r"ERR_HTTP2_|ERR_EMPTY_RESPONSE|ERR_INVALID_RESPONSE", "server returned no usable response"),
    (r"ERR_BLOCKED|ERR_ACCESS_DENIED", "blocked"),
]


def _reason(ex: Exception) -> str:
    msg = str(ex).splitlines()[0] if str(ex).strip() else type(ex).__name__
    sys.stderr.write(f"capture failure detail: {msg[:300]}\n")
    for rx, word in _NET_WORDS:
        if re.search(rx, msg):
            return word
    if "imeout" in msg:
        return "timed out"
    return "browser error"


def _near_empty(path: str) -> bool:
    """A capture that is (almost) a blank sheet — an error line on white, an interstitial that never
    painted — is recorded, but not presented as 'the landing page'."""
    try:
        from PIL import Image, ImageStat
        Image.MAX_IMAGE_PIXELS = None
        im = Image.open(path).convert("L")
        im.thumbnail((400, 400))
        return ImageStat.Stat(im).stddev[0] < 10
    except Exception:  # noqa: BLE001
        return False


def _caption_safe(s: str) -> str:
    """Alt text lives inside `![...]`; brackets or a stray backslash would break the image syntax."""
    return re.sub(r"[\[\]\\]", " ", s).strip()


def capture_missing(case_dir: str, hosts: list, existing: dict, *, max_hosts: int = 40,
                    timeout: int = 30, budget_s: int = 600) -> tuple:
    """Render every host without a capture. Returns (new_entries: dict, skipped: list[(host, why)])."""
    todo = [h for h in hosts if h not in existing][:max_hosts]
    skipped = [(h, "capture cap reached") for h in hosts[max_hosts:] if h not in existing]
    if not todo:
        return {}, skipped
    try:
        import playwright  # noqa: F401
    except Exception:  # noqa: BLE001
        return {}, skipped + [(h, "no browser runtime (playwright) in this interpreter") for h in todo]
    pol = egress_policy()
    if pol["mode"] == "blocked":
        return {}, skipped + [(h, pol["why"]) for h in todo]
    sys.path.insert(0, WP_TOOLS)
    import wp_screenshot  # noqa: E402
    case = os.path.basename(case_dir.rstrip("/"))
    root = os.path.dirname(os.path.dirname(case_dir.rstrip("/")))
    new, deadline = {}, time.monotonic() + budget_s
    pool = pol["pool"] or [None]
    for h in todo:
        if time.monotonic() > deadline:
            skipped.append((h, "capture time budget exhausted"))
            continue
        # One retry through the NEXT egress on a proxy-side fault (tunnel refused/reset) — a proxy
        # hiccup must not read as "the page did not render".
        for attempt, proxy in enumerate(pool[:2]):
            try:
                e = wp_screenshot.capture_screenshot(f"https://{h}/", case=case, root=root, proxy=proxy,
                                                     timeout=timeout, label="landing page")
                new[h] = {"host": h, "path": e["path"], "url": e["url"], "captured_at": e["captured_at"],
                          "sha256": e["sha256"], "title": e.get("title"), "actions": e.get("actions") or [],
                          "final_url": e.get("final_url")}
                break
            except Exception as ex:  # noqa: BLE001
                if attempt == 0 and len(pool) > 1 and _PROXY_FAULT.search(str(ex)):
                    continue
                skipped.append((h, f"page did not render ({_reason(ex)})"))
                break
    return new, skipped


def page_fit_png(entry: dict, rep_dir: str) -> tuple:
    """Copy a capture into report/ as shot_<host>.png sized for a page: cropped to the upper
    width×SHOWN_ASPECT band (a full-page doorway can run 10 000 px tall and would print as a sliver)
    and bounded to MAX_PX. Returns (path, cropped: bool). The ledger keeps the untouched original's hash."""
    dst = os.path.join(rep_dir, "shot_" + re.sub(r"[^A-Za-z0-9.-]", "_", entry["host"]) + ".png")
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = None
        im = Image.open(entry["path"])
        w, h = im.size
        cropped = False
        cap_h = int(w * SHOWN_ASPECT)
        if h > cap_h:
            im = im.crop((0, 0, w, cap_h))
            h, cropped = cap_h, True
        if max(w, h) > MAX_PX:
            k = MAX_PX / max(w, h)
            im = im.resize((max(1, int(w * k)), max(1, int(h * k))), Image.LANCZOS)
        im.convert("RGB").save(dst, optimize=True, dpi=(150, 150))   # dpi: Word sizes the inline image from it
        return dst, cropped
    except Exception:  # noqa: BLE001 — no PIL: embed as-is
        shutil.copyfile(entry["path"], dst)
        return dst, False


def landing_pages_md(entries: dict, hosts: list, seed: str, skipped: list, rep_dir: str,
                     sector_of, escape) -> str:
    """The per-host figure blocks for §V, seed first, then the estate alphabetically."""
    order = [h for h in dict.fromkeys([seed] + sorted(hosts)) if h in entries]
    shown = [h for h in order if not _near_empty(entries[h]["path"])]
    empty = [h for h in order if h not in shown]
    L = ["## Landing pages", ""]
    if shown:
        L += [f"Each estate host below was rendered in a headless desktop browser and captured as evidence; "
              f"{len(shown)} of {len(hosts)} pages rendered with content. The capture time (UTC) is in each "
              f"caption and the full-page SHA-256 in the evidence ledger (Appendix B).", ""]
    else:
        L += ["No landing page with content could be captured for this build; the reasons are recorded "
              "below so the absence is a stated result, not a silent one.", ""]
    for h in shown:
        e = entries[h]
        png, cropped = page_fit_png(e, rep_dir)
        when = (e.get("captured_at") or "")[:16].replace("T", " ") + " UTC"
        title = _caption_safe((e.get("title") or "").strip())
        cap = f"Landing page of `{h}`" + (" (the seed)" if h == seed else "") + f", captured {when}."
        if title:
            cap += f" Page title: \u201c{escape(title[:90])}\u201d."
        cap += f" Sector by domain label: {sector_of(h)}."
        if cropped:
            cap += " First screen of the full-page capture shown."
        if e.get("actions"):
            cap += " Interaction before capture: " + _caption_safe("; ".join(e["actions"])) + "."
        # Host headings are navigation inside this section, not TOC entries (32 of them would be a
        # page of domain names); 70 % of the text block ≈ 9 cm tall, so two figures share a page.
        L += [f"### {h} {{.unnumbered .unlisted}}", "", f"![{cap}]({os.path.basename(png)}){{width=70%}}", ""]
    notes = []
    if empty:
        notes.append("Rendered but near-empty at capture time (an error line or an interstitial on a blank page; "
                     "the capture is hashed in Appendix B): " + ", ".join(f"`{h}`" for h in empty) + ".")
    if skipped:
        by_why: dict = {}
        for h, why in skipped:
            by_why.setdefault(why, []).append(h)
        notes.append("Not captured: " + " ".join(
            f"{', '.join('`' + h + '`' for h in sorted(hs))} — {why}." for why, hs in by_why.items()))
    if notes:
        L += notes + [""]
    return "\n".join(L)


def captures_ledger_md(entries: dict) -> str:
    if not entries:
        return ""
    rows = ["| When (UTC) | Host | Capture | SHA-256 (full-page PNG) |", "|:--:|:------------|:--------|:------------------|"]
    for h in sorted(entries):
        e = entries[h]
        what = "rendered landing page" + (", " + "; ".join(e["actions"]) if e.get("actions") else "")
        rows.append(f"| {(e.get('captured_at') or '')[:19].replace('T', ' ')} | `{h}` | {what} | `{e['sha256']}` |")
    return "\n".join(rows)


