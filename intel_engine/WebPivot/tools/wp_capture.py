#!/usr/bin/env python3
"""wp_capture — the RAW EVIDENCE bundle: the bytes the host actually served.

WHY RAW BYTES, WHEN WE ALREADY EXTRACT EVERYTHING
--------------------------------------------------
Everything else WebPivot produces is DERIVED — a favicon hash, a DOM-skeleton fingerprint, an
extracted wallet address, a tracker id. Derived data is an assertion about a page, and scam
infrastructure is torn down in days. Once the host is gone, nobody can check the assertion: not a
reviewer, not a court, not us in six months when the same kit reappears and we want to diff it.
Wayback and urlscan help, but they capture what THEY saw, from their egress, sometimes not at all,
and they can drop a capture on request.

So the capture is the primary source and everything else is a reading of it:

  - **the DOM**, exactly as received (or as rendered — the manifest says which);
  - **every JavaScript** the page references, because the operator's application logic is where
    the backend hosts, the API prefixes and the build identity live;
  - **every stylesheet**, because a shared theme is same-kit evidence and CSS is otherwise the one
    artifact class WebPivot never retained at all;
  - **source maps**, when a captured bundle points at one — developer paths and usernames.

Each file gets its own sha256. The bundle gets a `capture_sha256` computed over the sorted
`sha256  path` lines, so the whole capture has one citable digest and any later edit to any file
changes it. That is what makes a captured file quotable in a report rather than just stored.

WHAT IT WILL NOT PRETEND
-------------------------
A capture is BUDGETED (`references/capture.json`): same-site assets get the generous allowance
because they are the operator's own code; third-party CDN libraries get a small one because they
describe the library, not the operator. Anything dropped is listed in `skipped_for_budget` on the
manifest — a bundle that quietly omitted half the page would be worse than no bundle at all,
because it reads as complete. Same rule as every other layer here: an absence must be labelled.

Captures are TIMESTAMPED and never overwritten. Re-collecting the same page next week is a new
observation, not a correction — and the diff between the two is how you date a re-skin.

CLI:
  python3 wp_capture.py https://host.example/kit-x/ --case <case>
  python3 wp_capture.py https://host.example/kit-x/ --outdir /tmp/cap --no-third-party
  python3 wp_capture.py verify cases/<case>/evidence/captures/<host>/<kit>/<ts>
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

from wp_common import *      # noqa — DEFAULT_UA, strip_www, uniq
from wp_net import fetch     # noqa
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

try:
    import wp_paths
except Exception:            # pragma: no cover — capture still works without the path layer
    wp_paths = None

# --- reference DATA (RULE 3). The fallback is deliberately the SMALLER budget: a broken data file
#     must not silently authorise a bigger download than the analyst signed up for.
_CAP_FALLBACK = {
    "budgets": {"same_site_total_bytes": 20971520, "third_party_total_bytes": 4194304,
                "max_asset_bytes": 4194304, "max_assets": 150, "max_third_party_assets": 30,
                "timeout_seconds": 20, "dom_max_bytes": 8388608},
    "capture_kinds": {"dom": {"fetch": True}, "js": {"fetch": True}, "css": {"fetch": True},
                      "sourcemap": {"fetch": True}},
    "manifest": {"per_file": ["url", "sha256", "bytes", "fetched_at"]},
    "layout": {"root": "evidence/captures", "dir_template": "{host}/{kit}/{timestamp}",
               "root_kit_label": "_root", "dom_filename": "dom.html", "assets_dir": "assets",
               "third_party_dir": "third_party", "manifest_filename": "manifest.json"},
}
_REFS = load_ref(ref_path(__file__, "capture.json"), _CAP_FALLBACK)
BUDGETS = _REFS["budgets"]
CAPTURE_KINDS = _REFS["capture_kinds"]
MANIFEST_FIELDS = _REFS["manifest"]
LAYOUT = _REFS["layout"]

CAPTURE_VERSION = "wp_capture/1"

_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)
_LINK_HREF_RE = re.compile(r"<link\b[^>]*>", re.I)
_HREF_RE = re.compile(r"\bhref=[\"']([^\"']+)[\"']", re.I)
_REL_RE = re.compile(r"\brel=[\"']?([a-z \-]+)", re.I)
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _b(key, default=0):
    try:
        return int(BUDGETS.get(key, default))
    except (TypeError, ValueError):
        return default


def _wants(kind: str) -> bool:
    spec = (CAPTURE_KINDS or {}).get(kind)
    return bool(spec.get("fetch")) if isinstance(spec, dict) else False


def _utc():
    return datetime.datetime.now(datetime.timezone.utc)


def _safe(name: str, fallback: str = "x") -> str:
    """A filesystem-safe fragment. Deliberately lossy — the manifest holds the real URL, so a
    stored filename only has to be unique and readable, never round-trippable."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "")).strip("-.")
    return (s[:60] or fallback)


# --------------------------------------------------------------------------- reference discovery
def referenced_assets(html: str, base_url: str) -> list:
    """[{'url','role'}] for every JS and CSS the page references, absolutised against `base_url`.

    Parsed from the served HTML rather than taken from the pivot layer's curated lists, because
    those lists are deliberately FILTERED — third-party libraries are dropped, bundles are ranked
    and truncated. That is right for analysis and wrong for evidence: a capture has to record what
    the page loaded, including the boring parts, or it cannot answer "what did this page do"."""
    out, seen = [], set()

    def _add(u, role):
        if not u or u.startswith(("data:", "javascript:", "about:", "#")):
            return
        full = urljoin(base_url or "", u.strip())
        if not full.startswith(("http://", "https://")) or full in seen:
            return
        seen.add(full)
        out.append({"url": full, "role": role})

    if _wants("js"):
        for m in _SCRIPT_SRC_RE.finditer(html or ""):
            _add(m.group(1), "js")
    if _wants("css"):
        for tag in _LINK_HREF_RE.findall(html or ""):
            rel = (_REL_RE.search(tag) or [None, ""])[1].lower() if _REL_RE.search(tag) else ""
            href = _HREF_RE.search(tag)
            if not href:
                continue
            if "stylesheet" in rel or href.group(1).split("?")[0].lower().endswith(".css"):
                _add(href.group(1), "css")
    return out


def _same_site(url: str, seed_host: str) -> bool:
    try:
        h = strip_www(urlparse(url).netloc).split(":")[0].lower()
    except Exception:
        return False
    s = strip_www(seed_host or "").split(":")[0].lower()
    if not h or not s:
        return False
    return h == s or h.endswith("." + s) or s.endswith("." + h)


# --------------------------------------------------------------------------- the capture
def capture(url: str, html: str = None, case: str = None, outdir: str = None,
            ua: str = DEFAULT_UA, proxy: str = None, third_party: bool = True,
            rendered: bool = False, root: str = ".", timeout: int = None) -> dict:
    """Capture one page's raw bytes -> the manifest dict (also written to disk).

    `html` is the already-fetched DOM when the caller has one (pivot_extract always does — passing
    it avoids a second request to the operator's server, which is both politer and quieter). Omit
    it and the page is fetched here.

    Returns {'dir', 'manifest', ...}. Never raises on a per-asset failure: a capture that aborted
    because one CDN 404'd would lose the twenty files that did come back, so failures are recorded
    in `errors` and the bundle is still written."""
    timeout = int(timeout or _b("timeout_seconds", 20))
    ua = ua or DEFAULT_UA          # a caller passing an unresolved None must not break every fetch
    seed_host = strip_www(urlparse(url).netloc).split(":")[0].lower()
    final_url, status, headers, body = url, None, {}, b""

    if html is None:
        try:
            final_url, status, headers, body = fetch(url, timeout=timeout, ua=ua, proxy=proxy)
            html = (body or b"").decode("utf-8", "replace")
        except Exception as exc:
            return {"error": f"could not fetch {url}: {exc}", "url": url}
    else:
        body = html.encode("utf-8", "replace")

    dom_cap = _b("dom_max_bytes", 16777216)
    if len(body) > dom_cap:
        body = body[:dom_cap]

    # --- where it goes -------------------------------------------------------------------
    pa = wp_paths.analyse(final_url or url, seed_host) if wp_paths else {}
    kit = pa.get("kit") or LAYOUT.get("root_kit_label", "_root")
    ts = _utc().strftime("%Y%m%dT%H%M%SZ")
    if outdir:
        capdir = outdir
    else:
        base = os.path.join(root, "cases", case) if case else root
        rel = (LAYOUT.get("dir_template") or "{host}/{kit}/{timestamp}").format(
            host=_safe(seed_host, "host"), kit=_safe(kit, "_root"), timestamp=ts)
        capdir = os.path.join(base, LAYOUT.get("root", "evidence/captures"), *rel.split("/"))
    assets_dir = os.path.join(capdir, LAYOUT.get("assets_dir", "assets"))
    tp_dir = os.path.join(capdir, LAYOUT.get("third_party_dir", "third_party"))
    os.makedirs(capdir, exist_ok=True)

    files, errors, skipped = [], [], []

    def _write(relative_dir, name, data):
        d = os.path.join(capdir, relative_dir) if relative_dir else capdir
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return os.path.relpath(p, capdir).replace(os.sep, "/")

    # --- 1) the DOM ----------------------------------------------------------------------
    dom_name = LAYOUT.get("dom_filename", "dom.html")
    files.append({
        "url": url, "final_url": final_url, "http_status": status,
        "content_type": (headers or {}).get("content-type", "text/html"),
        "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
        "fetched_at": _utc().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "role": "dom", "same_site": True, "stored_as": _write("", dom_name, body),
    })

    # --- 2) every referenced JS + CSS ------------------------------------------------------
    ss_budget = _b("same_site_total_bytes", 41943040)
    tp_budget = _b("third_party_total_bytes", 8388608) if third_party else 0
    per_file_cap = _b("max_asset_bytes", 8388608)
    max_assets = _b("max_assets", 300)
    max_tp = _b("max_third_party_assets", 60)
    ss_spent = tp_spent = tp_count = 0
    sourcemap_targets = []

    for ref in referenced_assets(html, final_url or url):
        if len(files) - 1 >= max_assets:
            skipped.append({"url": ref["url"], "reason": f"asset count cap ({max_assets})"})
            continue
        mine = _same_site(ref["url"], seed_host)
        if not mine and not third_party:
            skipped.append({"url": ref["url"], "reason": "third-party capture disabled"})
            continue
        if not mine and tp_count >= max_tp:
            skipped.append({"url": ref["url"], "reason": f"third-party count cap ({max_tp})"})
            continue
        room = (ss_budget - ss_spent) if mine else (tp_budget - tp_spent)
        if room <= 0:
            skipped.append({"url": ref["url"],
                            "reason": ("same-site" if mine else "third-party") + " byte budget spent"})
            continue
        try:
            f_url, st, hd, data = fetch(ref["url"], timeout=timeout, ua=ua, proxy=proxy)
        except Exception as exc:
            errors.append({"url": ref["url"], "error": str(exc)})
            continue
        if st and st >= 400:
            errors.append({"url": ref["url"], "http_status": st,
                           "error": "server returned an error — recorded, not stored"})
            continue
        data = data or b""
        truncated = False
        cap = min(per_file_cap, room)
        if len(data) > cap:
            data, truncated = data[:cap], True
        digest = hashlib.sha256(data).hexdigest()
        name = f"{digest[:12]}_{_safe(os.path.basename(urlparse(ref['url']).path) or ref['role'])}"
        entry = {
            "url": ref["url"], "final_url": f_url, "http_status": st,
            "content_type": (hd or {}).get("content-type", ""),
            "sha256": digest, "bytes": len(data),
            "fetched_at": _utc().isoformat(timespec="seconds").replace("+00:00", "Z"),
            "role": ref["role"], "same_site": mine,
            "stored_as": _write(LAYOUT.get("assets_dir", "assets") if mine
                                else LAYOUT.get("third_party_dir", "third_party"), name, data),
        }
        if truncated:
            # Stated on the FILE, because a truncated bundle whose hash is quoted as "the file"
            # would be a false citation — the digest covers what we stored, not what was served.
            entry["truncated"] = True
            entry["note"] = ("truncated to the byte cap — this sha256 covers the STORED prefix, "
                             "not the full served file")
        files.append(entry)
        if mine:
            ss_spent += len(data)
        else:
            tp_spent += len(data)
            tp_count += 1
        if ref["role"] == "js" and _wants("sourcemap"):
            m = _SOURCEMAP_RE.search(data.decode("utf-8", "ignore")[-2048:])
            if m and not m.group(1).startswith("data:"):
                sourcemap_targets.append(urljoin(f_url or ref["url"], m.group(1)))

    # --- 3) source maps beside the captured bundles ----------------------------------------
    for murl in uniq(sourcemap_targets)[:20]:
        try:
            f_url, st, hd, data = fetch(murl, timeout=timeout, ua=ua, proxy=proxy)
        except Exception as exc:
            errors.append({"url": murl, "error": str(exc)})
            continue
        if not data or (st and st >= 400):
            continue
        data = data[:min(per_file_cap, max(0, ss_budget - ss_spent))]
        if not data:
            skipped.append({"url": murl, "reason": "same-site byte budget spent"})
            continue
        ss_spent += len(data)
        digest = hashlib.sha256(data).hexdigest()
        files.append({
            "url": murl, "final_url": f_url, "http_status": st,
            "content_type": (hd or {}).get("content-type", ""),
            "sha256": digest, "bytes": len(data),
            "fetched_at": _utc().isoformat(timespec="seconds").replace("+00:00", "Z"),
            "role": "sourcemap", "same_site": _same_site(murl, seed_host),
            "stored_as": _write(LAYOUT.get("assets_dir", "assets"),
                                f"{digest[:12]}_{_safe(os.path.basename(urlparse(murl).path))}",
                                data),
        })

    # --- 4) the manifest, and the digest that makes the bundle citable ----------------------
    manifest = {
        "capture_version": CAPTURE_VERSION,
        "case": case or "",
        "seed_url": url,
        "final_url": final_url,
        "host": seed_host,
        "url_path": pa.get("url_path"),
        "path_template": pa.get("path_template"),
        "kit": pa.get("kit"),
        "captured_at": _utc().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "rendered": bool(rendered),
        "fetched_with": "headless browser (rendered DOM)" if rendered else "HTTP GET",
        "third_party_captured": bool(third_party),
        "files": files,
        "counts": {"total": len(files),
                   "js": sum(1 for f in files if f["role"] == "js"),
                   "css": sum(1 for f in files if f["role"] == "css"),
                   "sourcemap": sum(1 for f in files if f["role"] == "sourcemap"),
                   "third_party": sum(1 for f in files if not f.get("same_site"))},
        "bytes": {"same_site": ss_spent, "third_party": tp_spent, "dom": len(body)},
        # Never silently complete: a bundle that dropped half the page must SAY so, or a reader
        # will take it as the whole page.
        "skipped_for_budget": skipped,
        "errors": errors,
    }
    if skipped:
        manifest["completeness"] = (
            f"INCOMPLETE — {len(skipped)} referenced asset(s) were not stored (budget or cap). "
            f"This bundle is what the budget allowed, not everything the page loaded. Raise the "
            f"budgets in WebPivot/references/capture.json for a capture that must be exhaustive.")
    manifest["capture_sha256"] = bundle_digest(files)
    mpath = os.path.join(capdir, LAYOUT.get("manifest_filename", "manifest.json"))
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    return {"dir": capdir, "manifest_path": mpath, "manifest": manifest,
            "capture_sha256": manifest["capture_sha256"]}


def bundle_digest(files) -> str:
    """One digest over the whole capture: sha256 of the sorted `<sha256>  <stored_as>` lines.

    Order-independent by construction (the lines are sorted), so the same bytes always give the
    same digest — and any edit, addition or removal changes it. This is the value to cite in a
    report when the claim is "this is the page as served", rather than citing a directory path
    that says nothing about its contents."""
    lines = sorted(f"{f.get('sha256','')}  {f.get('stored_as','')}" for f in files or [])
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def verify(capdir: str) -> dict:
    """Re-hash a stored capture and compare against its manifest — the check that makes the bundle
    evidence rather than a folder. Reports per-file mismatches and whether `capture_sha256` still
    holds."""
    mpath = os.path.join(capdir, LAYOUT.get("manifest_filename", "manifest.json"))
    try:
        with open(mpath, encoding="utf-8") as fh:
            man = json.load(fh)
    except Exception as exc:
        return {"ok": False, "error": f"no readable manifest at {mpath}: {exc}"}
    bad, missing = [], []
    for f in man.get("files") or []:
        p = os.path.join(capdir, f.get("stored_as") or "")
        if not os.path.isfile(p):
            missing.append(f.get("stored_as"))
            continue
        with open(p, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        if got != f.get("sha256"):
            bad.append({"file": f.get("stored_as"), "manifest": f.get("sha256"), "on_disk": got})
    recomputed = bundle_digest(man.get("files") or [])
    ok = not bad and not missing and recomputed == man.get("capture_sha256")
    return {"ok": ok, "dir": capdir, "files": len(man.get("files") or []),
            "altered": bad, "missing": missing,
            "capture_sha256": man.get("capture_sha256"), "recomputed": recomputed,
            "verdict": ("intact — every stored file matches its manifest digest" if ok else
                        "MISMATCH — this capture no longer matches its manifest; do not cite it "
                        "until the discrepancy is explained")}


__all__ = ["capture", "verify", "bundle_digest", "referenced_assets",
           "BUDGETS", "CAPTURE_KINDS", "LAYOUT", "CAPTURE_VERSION"]


def main():
    ap = argparse.ArgumentParser(description="capture a page's raw DOM + JS + CSS as evidence")
    ap.add_argument("target", help="URL to capture, or a capture directory with `verify`")
    ap.add_argument("--verify", action="store_true", help="re-hash a stored capture instead")
    ap.add_argument("--case", default=None, help="write under cases/<case>/evidence/captures/")
    ap.add_argument("--outdir", default=None, help="explicit output directory (overrides --case)")
    ap.add_argument("--root", default=".", help="repo root holding cases/ (default: cwd)")
    ap.add_argument("--no-third-party", dest="third_party", action="store_false",
                    help="record third-party URLs in the manifest but do not download them")
    ap.add_argument("--ua", default=DEFAULT_UA)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--timeout", type=int, default=None)
    args = ap.parse_args()

    if args.verify or os.path.isdir(args.target):
        out = verify(args.target)
    else:
        out = capture(args.target, case=args.case, outdir=args.outdir, ua=args.ua,
                      proxy=args.proxy, third_party=args.third_party, root=args.root,
                      timeout=args.timeout)
        m = out.get("manifest") or {}
        print(f"[+] captured {m.get('counts', {}).get('total', 0)} file(s) -> {out.get('dir')}",
              file=sys.stderr)
        print(f"    capture_sha256 {out.get('capture_sha256')}", file=sys.stderr)
        if m.get("skipped_for_budget"):
            print(f"    [!] {len(m['skipped_for_budget'])} asset(s) skipped for budget — the "
                  f"manifest says so; this bundle is NOT the whole page.", file=sys.stderr)
        out = m
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out.get("ok", True) and not out.get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
