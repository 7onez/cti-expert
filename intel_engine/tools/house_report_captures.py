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
            host = (e.get("host") or "").lower() or _host_of(e.get("url") or "")
            src = e.get("source") or "live"
            # an archive copy is dated by the ARCHIVE (when the page looked like this), the file by our fetch
            cand = {"host": host, "path": p, "url": e.get("url") or f"https://{host}/",
                    "captured_at": (e.get("archived_at") if src != "live" else None) or e.get("captured_at") or _mtime_utc(p),
                    "retrieved_at": e.get("retrieved_at") or e.get("captured_at"), "sha256": e.get("sha256"),
                    "title": e.get("title"), "actions": e.get("actions") or [],
                    "final_url": e.get("final_url"), "source": src,
                    "source_url": e.get("source_url"), "archived_at": e.get("archived_at")}
            prev = out.get(host)
            if prev and prev.get("sha256"):
                # a live render outranks an archive copy; among equals the newer capture wins. The best
                # archive copy is kept under "archive" so a near-empty live render can fall back to it.
                rank = {"live": 2, "urlscan": 1, "wayback": 1}
                if (rank.get(prev.get("source") or "live", 0), prev.get("captured_at") or "") > \
                        (rank.get(src, 0), cand["captured_at"] or ""):
                    if src != "live" and (not prev.get("archive") or (prev["archive"].get("captured_at") or "") < cand["captured_at"]):
                        prev["archive"] = cand
                    continue
                if (prev.get("source") or "live") != "live":
                    cand["archive"] = prev
            out[host] = cand
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


def _entry(h: str, e: dict) -> dict:
    return {"host": h, "path": e["path"], "url": e["url"], "captured_at": e["captured_at"],
            "sha256": e["sha256"], "title": e.get("title"), "actions": e.get("actions") or [],
            "final_url": e.get("final_url"), "source": e.get("source") or "live",
            "source_url": e.get("source_url"), "archived_at": e.get("archived_at")}


# --------------------------------------------------------------------------- archive fallback
# When the live page will not render (host offline, DNS gone, TLS dead) the site is still on record
# at two public archives. Both are third parties, not the target, so they are fetched through the
# research proxy when one is configured and directly otherwise — the egress policy guards the
# analyst's IP against the OPERATOR's infrastructure, not against archive.org.
_ARCHIVE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"


def _http_get(url: str, proxy: str | None, timeout: int = 30) -> bytes:
    import urllib.request
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": _ARCHIVE_UA})
    with opener.open(req, timeout=timeout) as r:
        return r.read()


def _append_manifest(case_dir: str, entry: dict) -> None:
    man_dir = os.path.join(case_dir, "evidence", "screenshots")
    os.makedirs(man_dir, exist_ok=True)
    man = os.path.join(man_dir, "manifest.json")
    arr = []
    if os.path.exists(man):
        try:
            arr = json.load(open(man, encoding="utf-8"))
        except ValueError:
            arr = []
    arr = arr if isinstance(arr, list) else []
    arr.append(entry)
    json.dump(arr, open(man, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def _same_host(url: str, h: str) -> bool:
    n = _host_of(url or "")
    return n == h or n == "www." + h



def _urlscan_capture(h: str, case_dir: str, proxy: str | None, timeout: int, created: str | None = None) -> dict | None:
    """Newest public web-scan screenshot of the host itself (never a subdomain's), preferring scans
    made after the current registration."""
    import wp_net  # noqa: E402  (WP_TOOLS already on sys.path)
    intel = wp_net.urlscan_intel(h, limit=10, max_pages=1)
    if not intel or intel.get("error") or not intel.get("pages"):
        raise _Transient("web-scan index did not answer")       # not a 'no copy' — never cache it
    scans = [s for s in intel.get("all_scans") or [] if s.get("uuid") and _same_host(s.get("url") or "", h)]
    if not scans:
        return None
    scans.sort(key=lambda s: s.get("time") or "", reverse=True)
    cut = (created or "")[:10]
    after = [s for s in scans if cut and (s.get("time") or "")[:10] >= cut]
    for s in (after or scans)[:3]:
        try:
            png = _http_get(f"https://urlscan.io/screenshots/{s['uuid']}.png", proxy, timeout)
        except Exception:  # noqa: BLE001
            continue
        if len(png) < 1000:
            continue
        out_dir = os.path.join(case_dir, "evidence", "screenshots", re.sub(r"[^A-Za-z0-9._-]", "_", h))
        os.makedirs(out_dir, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(out_dir, f"{stamp}_urlscan.png")
        open(path, "wb").write(png)
        w, hgt = (None, None)
        if png[:8] == b"\x89PNG\r\n\x1a\n":
            import struct
            w, hgt = struct.unpack(">II", png[16:24])
        scan_time = (s.get("time") or "")[:19].replace(" ", "T")
        scan_time = scan_time + ("Z" if scan_time and not scan_time.endswith("Z") else "")
        entry = {"url": f"https://{h}/", "final_url": None, "captured_at": scan_time,
                 "path": path, "sha256": hashlib.sha256(png).hexdigest(), "bytes": len(png),
                 "width": w, "height": hgt, "title": None, "proxy": bool(proxy), "label": "landing page (public web-scan capture)",
                 "actions": [], "full_page": False, "tool": "house_report_captures", "host": h,
                 "source": "urlscan", "source_url": s.get("result"), "archived_at": scan_time,
                 "retrieved_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        _append_manifest(case_dir, entry)
        return entry
    return None


class _Transient(Exception):
    """An archive did not answer (throttled, proxy fault, timeout): the negative is NOT definitive."""


def _wayback_after(h: str, created: str | None) -> tuple:
    """(snapshot_ts, note). The newest 200-OK snapshot on/after the registration date via the CDX API;
    else the nearest snapshot of any date (the previous owner's page, flagged by the caller)."""
    import wp_net  # noqa: E402
    cut = re.sub(r"\D", "", (created or "")[:10])
    if cut:
        import urllib.request
        cdx = (f"http://web.archive.org/cdx/search/cdx?url={h}&output=json&filter=statuscode:200"
               f"&from={cut}&limit=-1")
        try:
            req = urllib.request.Request(cdx, headers={"User-Agent": _ARCHIVE_UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                rows = json.load(r)
            if rows and len(rows) > 1:
                return rows[-1][1], ""
        except Exception as ex:  # noqa: BLE001
            if "429" in str(ex):
                return None, "rate-limited"
    snap, ts = wp_net.wayback_closest(f"https://{h}/")
    if not snap:
        time.sleep(6)                     # archive.org throttles bursts (HTTP 429): one spaced retry
        snap, ts = wp_net.wayback_closest(f"https://{h}/")
    if not snap or not ts:
        return None, ""
    m = re.search(r"/web/(\d{14})", snap)
    return (m.group(1) if m else str(ts)), ""


def _wayback_capture(h: str, case: str, root: str, proxy: str | None, timeout: int, created: str | None = None) -> dict | None:
    """Render a web-archive snapshot of the host (toolbar-free `if_` view) in Chromium."""
    import wp_screenshot  # noqa: E402
    ts, note = _wayback_after(h, created)
    if not ts:
        if note:
            raise _Transient(f"web archive {note}")
        return None
    render_url = f"https://web.archive.org/web/{ts}if_/https://{h}/"
    archived_at = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"
    e = wp_screenshot.capture_screenshot(render_url, case=case, root=root, proxy=proxy, timeout=timeout,
                                         label="landing page (web-archive snapshot)", host=h,
                                         extra={"source": "wayback", "source_url": f"https://web.archive.org/web/{ts}/https://{h}/",
                                                "archived_at": archived_at,
                                                "retrieved_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    # the ARCHIVE date is when the page looked like this; the render time is kept as retrieved_at
    e["retrieved_at"] = e["captured_at"]
    e["captured_at"] = archived_at
    e["url"] = f"https://{h}/"
    return e


# Negative results are remembered so a "regenerate the PDF" does not re-ask both archives for hosts
# that have no copy anywhere; a check older than this is repeated (archives grow).
_NEGATIVE_TTL_DAYS = 7


def _archive_checks_path(case_dir: str) -> str:
    return os.path.join(case_dir, "evidence", "screenshots", "archive_checks.json")


def _recent_negative(case_dir: str, h: str) -> bool:
    try:
        d = json.load(open(_archive_checks_path(case_dir), encoding="utf-8"))
    except (OSError, ValueError):
        return False
    when = (d.get(h) or {}).get("checked_at")
    if not when:
        return False
    try:
        t = dt.datetime.strptime(when[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return False
    return (dt.datetime.now(dt.timezone.utc) - t).days < _NEGATIVE_TTL_DAYS


def _record_negative(case_dir: str, h: str) -> None:
    p = _archive_checks_path(case_dir)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        d = json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    d[h] = {"source": "none", "checked_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def _archive_copy(h: str, case_dir: str, case: str, root: str, proxy, timeout: int, created: str | None = None) -> dict | None:
    """Public web-scan screenshot first (an actual capture), then a rendered web-archive snapshot;
    both prefer a copy made after the current registration. Negative results are cached."""
    if _recent_negative(case_dir, h):
        return None
    definitive = True
    for fetch in (lambda: _urlscan_capture(h, case_dir, proxy, timeout, created),
                  lambda: _wayback_capture(h, case, root, proxy, timeout, created)):
        try:
            got = fetch()
        except Exception as ex:  # noqa: BLE001 — any failure to ASK is transient; only an answered
            definitive = False                                   # "no copy" from both sources is cached
            sys.stderr.write(f"archive fallback detail ({h}): {str(ex).splitlines()[0][:200]}\n")
            got = None
        if got:
            return got
    if definitive:
        _record_negative(case_dir, h)
    time.sleep(2)                          # pace the next host's archive lookups
    return None


def capture_missing(case_dir: str, hosts: list, existing: dict, *, max_hosts: int = 40,
                    timeout: int = 30, budget_s: int = 600, archives: bool = True, created_of=None) -> tuple:
    """Render every host without a capture; fall back to a public web-scan / web-archive copy when the
    live page will not render — or rendered near-empty (an error line, an interstitial), which shows the
    server's state, not the page. Returns (new_entries: dict, skipped: list[(host, why)])."""
    created_of = created_of or (lambda h: None)
    todo = [h for h in hosts if h not in existing][:max_hosts]
    skipped = [(h, "capture cap reached") for h in hosts[max_hosts:] if h not in existing]
    # live captures that are near-empty get an archive attempt (never a live re-render: same server)
    empties = [h for h in hosts if h in existing and (existing[h].get("source") or "live") == "live"
               and _near_empty(existing[h]["path"])] if archives else []
    if not todo and not empties:
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
        live_why = None
        for attempt, proxy in enumerate(pool[:2]):
            try:
                e = wp_screenshot.capture_screenshot(f"https://{h}/", case=case, root=root, proxy=proxy,
                                                     timeout=timeout, label="landing page")
                new[h] = _entry(h, e)
                break
            except Exception as ex:  # noqa: BLE001
                if attempt == 0 and len(pool) > 1 and _PROXY_FAULT.search(str(ex)):
                    continue
                live_why = _reason(ex)
                break
        if h in new or live_why is None:
            continue
        if not archives:
            skipped.append((h, f"page did not render ({live_why})"))
            continue
        # Live render failed: the archives are the record of what the page showed.
        got = _archive_copy(h, case_dir, case, root, pool[0], max(timeout, 60), created_of(h))   # archives are slow
        if got:
            new[h] = _entry(h, got)
        else:
            skipped.append((h, f"page did not render ({live_why}); no public web-scan or web-archive copy either"))
    for h in empties:
        held = existing[h].get("archive")                 # an archive copy already on disk from an earlier build
        if held and not _near_empty(held["path"]):
            new[h] = dict(held)
            continue
        if time.monotonic() > deadline:
            break
        got = _archive_copy(h, case_dir, case, root, pool[0], max(timeout, 60), created_of(h))
        if got and not _near_empty(got["path"]):
            new[h] = _entry(h, got)          # replaces the near-empty live capture in the report
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


def predates_registration(entry: dict, created: str | None) -> bool:
    """An archive copy taken BEFORE the current WHOIS creation date shows a previous owner's page,
    not this operator's — it is drop-catch evidence and must never be captioned as the landing page."""
    if (entry.get("source") or "live") == "live" or not created:
        return False
    when = (entry.get("archived_at") or entry.get("captured_at") or "")[:10]
    return bool(when) and when < created[:10]


def landing_pages_md(entries: dict, hosts: list, seed: str, skipped: list, rep_dir: str,
                     sector_of, escape, created_of=None) -> str:
    """The per-host figure blocks for §V, seed first, then the estate alphabetically. `created_of(host)`
    returns the WHOIS creation date so a pre-registration archive copy is labelled as a prior owner's."""
    created_of = created_of or (lambda h: None)
    order = [h for h in dict.fromkeys([seed] + sorted(hosts)) if h in entries]
    shown = [h for h in order if not _near_empty(entries[h]["path"])]
    empty = [h for h in order if h not in shown]
    L = ["## Landing pages", ""]
    prior = [h for h in shown if predates_registration(entries[h], created_of(h))]
    current = [h for h in shown if h not in prior]
    n_arch = sum(1 for h in current if (entries[h].get("source") or "live") != "live")
    if shown:
        L += [f"Each estate host below was rendered in a headless desktop browser and captured as evidence; "
              f"{len(current)} of {len(hosts)} pages rendered with content"
              + (f", {n_arch} of them from a public web-scan or web-archive copy because the live page would "
                 f"not render or rendered empty (each such caption says so and dates the copy)" if n_arch else "")
              + (f". A further {len(prior)} archive cop{'y' if len(prior) == 1 else 'ies'} predate{'s' if len(prior) == 1 else ''} the "
                 f"current registration and show{'s' if len(prior) == 1 else ''} a previous owner's site — evidence for drop-catching, not this "
                 f"operator's content; {'it is' if len(prior) == 1 else 'they are'} shown last and not counted above" if prior else "")
              + ". The capture time (UTC) is in each caption and the full-page SHA-256 in the evidence ledger "
              "(Appendix B).", ""]
    else:
        L += ["No landing page with content could be captured for this build; the reasons are recorded "
              "below so the absence is a stated result, not a silent one.", ""]
    for h in current + prior:
        e = entries[h]
        png, cropped = page_fit_png(e, rep_dir)
        when = (e.get("captured_at") or "")[:16].replace("T", " ") + " UTC"
        title = _caption_safe((e.get("title") or "").strip())
        src = e.get("source") or "live"
        who = " (the seed)" if h == seed else ""
        created = created_of(h)
        if predates_registration(e, created):
            where = "public web-scan service" if src == "urlscan" else "web archive"
            cap = (f"`{h}`{who} as held by the {where} on {when} — BEFORE the current registration "
                   f"({created[:10]}): a previous owner's page, not this operator's. The live page did not render "
                   f"with content at build time.")
        elif src == "urlscan":
            cap = f"Landing page of `{h}`{who} as recorded by a public web-scan service, scanned {when}; the live page did not render with content at build time."
        elif src == "wayback":
            cap = f"Landing page of `{h}`{who} as archived by the web archive, snapshot {when}; the live page did not render with content at build time."
        else:
            cap = f"Landing page of `{h}`{who}, captured {when}."
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


def captures_ledger_md(entries: dict, created_of=None) -> str:
    """Appendix B rows: one per capture, with the frozen public link for archive copies (Rule 21)."""
    if not entries:
        return ""
    rows = ["| When (UTC) | Host | Capture | Evidence link | SHA-256 (PNG) |",
            "|:--:|:------------|:--------|:----------|:------------------|"]
    for h in sorted(entries):
        e = entries[h]
        src = e.get("source") or "live"
        what = {"urlscan": "public web-scan capture", "wayback": "web-archive snapshot, rendered"}.get(src, "rendered landing page")
        if predates_registration(e, (created_of or (lambda h: None))(h)):
            what += " — predates current registration (previous owner)"
        if e.get("actions"):
            what += ", " + "; ".join(e["actions"])
        link = e.get("source_url") or "—"
        rows.append(f"| {(e.get('captured_at') or '')[:19].replace('T', ' ')} | `{h}` | {what} | {link} | `{e['sha256']}` |")
    return "\n".join(rows)


