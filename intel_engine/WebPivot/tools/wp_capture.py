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

CHAIN OF CUSTODY (wp_custody, handbook/collection-preservation.md §5–§6)
--------------------------------------------------------------------------
Every manifest records WHO collected it (`collector`), AS WHOM (`persona`), FROM WHERE (`egress_ip`,
or null plus `egress_note` saying why) and the local `clock_sync` state at collection start. Inside a
case store, capture and verify each append a line to the append-only
`cases/<case>/evidence/custody.jsonl`; a capture that VERIFIES is sealed read-only (permission bits
only, so every digest still matches). Analyse a `--working-copy` under `evidence/work/`, never the
original. `--fixity N` re-hashes a seeded random sample of the case's stored captures and screenshots.

CLI:
  python3 wp_capture.py https://host.example/kit-x/ --case <case> [--persona P] [--egress-ip IP]
  python3 wp_capture.py https://host.example/kit-x/ --outdir /tmp/cap --no-third-party
  python3 wp_capture.py --verify cases/<case>/evidence/captures/<host>/<kit>/<ts> [--no-seal]
  python3 wp_capture.py cases/<case>/evidence/captures/<host>/<kit>/<ts>   # a directory implies --verify
  python3 wp_capture.py --working-copy cases/<case>/evidence/captures/<host>/<kit>/<ts>
  python3 wp_capture.py --fixity 5 --case <case> [--seed 42]
  python3 wp_capture.py --custody transfer --case <case> --item evidence/captures/<...> \\
          --digest <capture_sha256> --note "to reviewer-02" [--collector analyst-07]
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
from urllib.parse import urljoin, urlparse

from wp_common import *      # noqa — DEFAULT_UA, strip_www, uniq
from wp_net import fetch     # noqa
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
import wp_custody            # noqa: E402 — collection context, custody log, seal, fixity draw

try:
    import wp_paths
except Exception:            # pragma: no cover — capture still works without the path layer
    wp_paths = None

_ENGINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def case_home(case: str = None, root: str = None) -> str:
    """The directory holding cases/ for `case`: an explicit `root` (--root); else the home of the
    case dir the collector named in $WP_CASE_DIR (pivot_extract derives it from `-o
    <home>/cases/<id>/raw/…`, so a capture lands beside its raw); else $INTEL_HOME; else the
    vendored intel_engine/ — never the caller's cwd (AGENTS.md: cases live under
    $INTEL_HOME/cases/<id>/ only)."""
    if root:
        return root
    wcd = os.environ.get("WP_CASE_DIR")
    if case and wcd and os.path.basename(os.path.normpath(wcd)) == case:
        return os.path.dirname(os.path.dirname(os.path.abspath(wcd)))
    return os.environ.get("INTEL_HOME") or _ENGINE

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

CAPTURE_VERSION = "wp_capture/2"     # /2: collector, persona, egress_ip, clock_sync; custody + seal

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
def _proxy_used(proxy: str = None):
    """The proxy this process actually egresses through — the shared resolver wp_browser uses
    (explicit, else the /cti-proxy pool exported into the environment), so the manifest names the
    same egress the fetch took."""
    try:
        import wp_browser
        return wp_browser.resolve_proxy(proxy)
    except Exception:        # noqa: BLE001 — the egress note then says direct/unknown, never fails
        return proxy


def capture(url: str, html: str = None, case: str = None, outdir: str = None,
            ua: str = DEFAULT_UA, proxy: str = None, third_party: bool = True,
            rendered: bool = False, root: str = None, timeout: int = None,
            collector: str = None, persona: str = None, egress_ip: str = None) -> dict:
    """Capture one page's raw bytes -> the manifest dict (also written to disk).

    `html` is the already-fetched DOM when the caller has one (pivot_extract always does — passing
    it avoids a second request to the operator's server, which is both politer and quieter). Omit
    it and the page is fetched here.

    `collector` / `persona` / `egress_ip` override the collection context wp_custody derives
    (environment, the proxy actually used); the clock-sync state is read here, at collection start.

    Returns {'dir', 'manifest', ...}. Never raises on a per-asset failure: a capture that aborted
    because one CDN 404'd would lose the twenty files that did come back, so failures are recorded
    in `errors` and the bundle is still written. A failure to WRITE (full disk, EPERM) returns
    {'ok': False, 'error', 'dir', 'cleanup'} instead of raising — see `_abandon` for `cleanup`."""
    timeout = int(timeout or _b("timeout_seconds", 20))
    ua = ua or DEFAULT_UA          # a caller passing an unresolved None must not break every fetch
    seed_host = strip_www(urlparse(url).netloc).split(":")[0].lower()
    final_url, status, headers, body = url, None, {}, b""
    root = case_home(case, root) if case else (root or ".")
    context_ev = (wp_custody.evidence_root(outdir) if outdir else
                  wp_custody.case_evidence_dir(case, root) if case else None)
    context = wp_custody.collection_context(_proxy_used(proxy), collector, persona, egress_ip,
                                             evidence_dir=context_ev)

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
    # Exclusive reservation, including explicit outdirs: no check-then-create race.
    try:
        os.makedirs(os.path.dirname(os.path.abspath(capdir)), exist_ok=True)
        candidate, n = capdir, 2
        while True:
            try:
                os.mkdir(candidate)
                capdir = candidate
                break
            except FileExistsError:
                candidate, n = f"{capdir}-{n}", n + 1
    except OSError as exc:
        return {"ok": False, "url": url, "dir": None, "cleanup": None,
                "error": f"could not reserve a capture directory at {capdir}: {exc}"}
    state = {"logged": False}
    try:
        return _fill(capdir, state, url, html, case, ua, proxy, third_party, rendered, timeout,
                     context, final_url, status, headers, body, seed_host, pa)
    except Exception as exc:  # noqa: BLE001 — a failed write must not raise or leave a fake original
        return _abandon(capdir, url, exc, state["logged"])


def _abandon(capdir: str, url: str, exc: Exception, logged: bool) -> dict:
    """Result for a capture whose writing failed after its directory was reserved. `cleanup` is
    tri-state: `removed` (nothing was logged, so the reservation and any partial files are gone),
    `retained_logged` (custody already names it, so nothing is deleted; it has no manifest and
    verifies as MISSING) or `cleanup_failed` (unlogged, but removal raised; `cleanup_error` says
    why)."""
    out = {"ok": False, "url": url, "dir": capdir,
           "error": f"capture write failed in {capdir}: {type(exc).__name__}: {exc}"}
    if logged or _named_in_custody(capdir):
        return dict(out, cleanup="retained_logged")
    try:
        shutil.rmtree(capdir)
        return dict(out, cleanup="removed")
    except OSError as rm_exc:
        return dict(out, cleanup="cleanup_failed", cleanup_error=str(rm_exc))


def _named_in_custody(capdir: str) -> bool:
    """True when any custody line — a torn one included — names `capdir`, or when that cannot be
    ruled out: deleting something the log may reference would break custody, keeping it does not."""
    try:
        ev = wp_custody.evidence_root(capdir)
        if not ev:
            return False
        ref = wp_custody.item_ref(ev, capdir)
        return any(e.get("item") == ref or f'"{ref}"' in e.get("_unparseable", "")
                   for e in wp_custody.read_log(ev))
    except Exception:  # noqa: BLE001 — unknown means keep
        return True


def _fill(capdir, state, url, html, case, ua, proxy, third_party, rendered, timeout,
          context, final_url, status, headers, body, seed_host, pa) -> dict:
    """Write the DOM, assets and manifest into the freshly reserved `capdir`; `state['logged']`
    turns True once the custody line exists, after which nothing here may be deleted."""
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
        # ¶155(g) collection data: collector, persona, egress_ip (+ egress_note / egress_proxy) and
        # clock_sync — read at collection start, before the first request.
        **context,
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
    out = {"dir": capdir, "manifest_path": mpath, "manifest": manifest,
           "capture_sha256": manifest["capture_sha256"]}
    ev = wp_custody.evidence_root(capdir)
    if ev:
        out["custody"] = wp_custody.append(
            ev, "capture", wp_custody.item_ref(ev, capdir), manifest["capture_sha256"],
            f"{manifest['fetched_with']} {url}; {len(files)} file(s)"
            + (f"; {len(skipped)} skipped for budget" if skipped else ""), context.get("collector"))
        state["logged"] = True
    manifest["custody_head"] = out["custody"]["head"] if ev else None
    # Written beside, then renamed: a full disk leaves no half-written manifest.json that a reader
    # could take for a complete capture.
    partial = mpath + ".partial"
    try:
        with open(partial, "x", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
        os.replace(partial, mpath)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(partial)
        raise
    return out


def bundle_digest(files) -> str:
    """One digest over the whole capture: sha256 of the sorted `<sha256>  <stored_as>` lines.

    Order-independent by construction (the lines are sorted), so the same bytes always give the
    same digest — and any edit, addition or removal changes it. This is the value to cite in a
    report when the claim is "this is the page as served", rather than citing a directory path
    that says nothing about its contents."""
    lines = sorted(f"{f.get('sha256','')}  {f.get('stored_as','')}" for f in files or [])
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def verify(capdir: str, seal: bool = None, actor: str = None, note: str = None) -> dict:
    with wp_custody.ExitStack() as stack:
        try:
            return _verify(capdir, seal, actor, note, stack)
        except (OSError, ValueError, TypeError) as exc:
            return {"ok": False, "dir": capdir, "missing": [], "altered": [{"file": capdir}],
                    "verdict": f"TAMPERED — unsafe or changed capture: {exc}"}


def _verify(capdir, seal, actor, note, stack):
    """Re-hash a stored capture and compare against its manifest — the check that makes the bundle
    evidence rather than a folder. Reports per-file mismatches and whether `capture_sha256` still
    holds.

    Read-only: it works on a sealed capture (files 0444, dirs 0555, manifest included). Inside a
    case store it appends a `verify` line to the custody log and, when the capture is intact, seals
    it (`seal=None` → seal only inside a case store; True/False force it). A mismatched capture is
    never sealed — sealing would dress a damaged original up as a protected one."""
    mpath = os.path.join(capdir, LAYOUT.get("manifest_filename", "manifest.json"))
    ev = wp_custody.evidence_root(capdir)
    handles = []
    def hold(p, directory=False):
        fd = stack.enter_context(wp_custody.pinned(p, directory))
        handles.append((p, fd, os.fstat(fd)))
        return fd
    try:
        hold(capdir, True)
        mfd = hold(mpath)
        with os.fdopen(os.dup(mfd), encoding="utf-8") as fh:
            man = json.load(fh)
    except Exception as exc:
        out = {"ok": False, "dir": capdir, "missing": [LAYOUT.get("manifest_filename", "manifest.json")],
               "altered": [], "error": f"no readable manifest at {mpath}: {exc}"}
        if ev:
            out["custody"] = wp_custody.append(
                ev, "verify", wp_custody.item_ref(ev, capdir), None,
                ((note + "; ") if note else "") + "MISSING — no readable manifest", actor)
        out["custody_head"] = out["custody"]["head"] if ev else None
        return out
    bad, missing = [], []
    listed = {f.get("stored_as") for f in man.get("files") or []}
    allowed = listed | {LAYOUT.get("manifest_filename", "manifest.json")}
    for d, dirs, names in os.walk(capdir, followlinks=False):
        for name in dirs + names:
            p = os.path.join(d, name)
            rel = os.path.relpath(p, capdir).replace(os.sep, "/")
            if os.path.islink(p) or wp_custody.contained_ref(capdir, rel) is None:
                bad.append({"file": rel, "reason": "symlink or outside capture"})
            elif name in dirs:
                if rel not in (LAYOUT.get("assets_dir", "assets"), LAYOUT.get("third_party_dir", "third_party")) and not any(
                        isinstance(f, str) and f.startswith(rel + "/") for f in listed):
                    bad.append({"file": rel, "reason": "unlisted directory"})
                hold(p, True)
            elif rel not in allowed:
                bad.append({"file": rel, "reason": "unlisted member"})
    for f in man.get("files") or []:
        rel = f.get("stored_as") or ""
        p = os.path.join(capdir, rel)
        if wp_custody.contained_ref(capdir, rel) is None:
            bad.append({"file": rel, "reason": "outside capture"})
            continue
        try:
            fd = hold(p)
            got = wp_custody.fd_sha256(fd)
            if wp_custody.inode_state(os.fstat(fd)) != wp_custody.inode_state(handles[-1][2]):
                raise ValueError("changed during hashing")
            if got != f.get("sha256"):
                bad.append({"file": rel, "manifest": f.get("sha256"), "on_disk": got})
        except FileNotFoundError:
            missing.append(rel)
        except (OSError, ValueError) as exc:
            bad.append({"file": rel, "reason": str(exc)})
    expected = (wp_custody.first_capture_digest(ev, wp_custody.item_ref(ev, capdir))
                if ev else None)
    if expected is not None and man.get("capture_sha256") != expected:
        bad.append({"file": LAYOUT.get("manifest_filename", "manifest.json"),
                    "manifest": man.get("capture_sha256"), "logged_capture": expected})
    recomputed = bundle_digest(man.get("files") or [])
    ok = not bad and not missing and recomputed == man.get("capture_sha256")
    out = {"ok": ok, "dir": capdir, "files": len(man.get("files") or []),
           "altered": bad, "missing": missing,
           "capture_sha256": man.get("capture_sha256"), "recomputed": recomputed,
           "logged_capture_sha256": expected,
           "verdict": ("intact — every stored file matches its manifest digest" if ok else
                       "TAMPERED — MISMATCH against the recorded digest; do not cite this capture "
                       "until the discrepancy is explained")}
    wants_seal = seal if seal is not None else bool(ev)
    if ok and wants_seal and not hasattr(os, "fchmod"):
        out.update(sealed=False, seal_status="unavailable_on_platform",
                   seal_reason="os.fchmod unavailable; pathname chmod is unsafe")
    if ok and wants_seal and hasattr(os, "fchmod"):
        try:
            wp_custody.seal(capdir, handles)
            out["sealed"] = True
        except wp_custody.SealError as exc:
            # The content check already passed: a read-only mount or EPERM leaves an intact,
            # unsealed original — reported as a seal failure, never as tampering.
            out.update(sealed=False, seal_status="failed", seal_reason=str(exc),
                       verdict=out["verdict"] + "; NOT sealed — the permission change failed")
        except (OSError, ValueError) as exc:
            ok = out["ok"] = False
            bad.append({"file": capdir, "reason": str(exc)})
            out["verdict"] = f"TAMPERED — changed before sealing: {exc}"
    if ev:
        status = ("ok" if ok else f"TAMPERED: {len(bad)} altered, {len(missing)} missing")
        out["custody"] = wp_custody.append(
            ev, "verify", wp_custody.item_ref(ev, capdir), man.get("capture_sha256"),
            ((note + "; ") if note else "") + status + ("; sealed read-only" if out.get("sealed") else "")
            + (f"; seal {out['seal_status']}: {out['seal_reason']}" if out.get("seal_status") else ""),
            actor)
    out["custody_head"] = out["custody"]["head"] if ev else None
    return out


def working_copy(path: str, actor: str = None, note: str = None) -> dict:
    """Analysis copy of an original under `evidence/work/`. A capture directory is verified first
    (and so sealed and logged): copying a damaged original would launder it into the work store."""
    if os.path.isdir(path):
        v = verify(path, actor=actor)
        if not v.get("ok"):
            return {"ok": False, "error": "original failed verification — not copied", "verify": v}
    return wp_custody.working_copy(path, actor=actor, note=note)


def _stored_items(ev: str) -> dict:
    """{item_ref: (kind, expected_sha256 or None)} — every capture and screenshot this case holds,
    from the DISK and from the custody log. The log half is what lets fixity report a capture whose
    whole directory has gone, which a disk walk alone cannot see."""
    items = {}
    cap_root = os.path.join(ev, *(LAYOUT.get("root", "evidence/captures").split("/")[1:]
                                  or ["captures"]))
    mname = LAYOUT.get("manifest_filename", "manifest.json")
    for d, dirs, files in os.walk(cap_root):
        if mname in files:
            items[wp_custody.item_ref(ev, d)] = ("capture", None)
            dirs[:] = []
    shots = os.path.join(ev, "screenshots", mname)
    if os.path.isfile(shots):
        try:
            with open(shots, encoding="utf-8") as fh:
                arr = json.load(fh)
        except Exception:    # noqa: BLE001 — the custody log still lists the screenshots
            arr = []
        for e in arr if isinstance(arr, list) else []:
            p = e.get("path") if isinstance(e, dict) else None
            if p and wp_custody.evidence_root(p) and os.path.samefile(
                    wp_custody.evidence_root(p), ev):
                items[wp_custody.item_ref(ev, p)] = ("screenshot", e.get("sha256"))
    logged = set()
    for e in wp_custody.read_log(ev):
        if e.get("action") != "capture" or not e.get("item"):
            continue
        kind = "screenshot" if str(e["item"]).lower().endswith(".png") else "capture"
        # First capture wins, even when a writable screenshot manifest names another digest.
        if e["item"] not in logged:
            items[e["item"]] = (kind, e.get("sha256"))
            logged.add(e["item"])
    return items


def fixity(case: str, n: int = None, seed: int = None, root: str = None, actor: str = None,
           expected_head=None) -> dict:
    """Re-hash a seeded random sample of a case's stored captures and screenshots (R01 ¶172).

    Every sampled item gets a `verify` custody line naming the seed; the report lists each
    altered or missing file and the custody-log chain check. Same seed + same store = same sample."""
    root = case_home(case, root)
    ev = wp_custody.case_evidence_dir(case, root)
    items = _stored_items(ev)
    seed, chosen = wp_custody.sample(list(items), n, seed)
    tag = f"fixity sample seed={seed}"
    results = []
    for ref in chosen:
        kind, expected = items[ref]
        if wp_custody.contained_ref(os.path.dirname(os.path.abspath(ev)), ref) is None:
            wp_custody.append(ev, "verify", ref, expected, f"{tag}; REJECTED — outside case", actor)
            results.append({"item": ref, "kind": kind, "status": "REJECTED",
                            "altered": [], "missing": []})
            continue
        path = os.path.join(os.path.dirname(os.path.abspath(ev)), *ref.split("/"))
        if kind == "capture":
            v = verify(path, actor=actor, note=tag)
            status = ("MATCH" if v.get("ok") else
                      "MISSING" if v.get("error") or (v.get("missing") and not v.get("altered"))
                      else "TAMPERED")
            results.append({"item": ref, "kind": kind, "status": status,
                            **{k: v[k] for k in ("sealed", "seal_status", "seal_reason") if k in v},
                            "altered": [a["file"] for a in v.get("altered") or []],
                            "missing": v.get("missing") or []})
            continue
        from wp_screenshot import _check
        checked = _check(path, expected, case_dir=os.path.dirname(os.path.abspath(ev)), log=False)
        status = checked["status"]
        seal_note = (f"; seal {checked['seal_status']}: {checked['seal_reason']}"
                     if checked.get("seal_reason") else "")
        wp_custody.append(ev, "verify", ref, expected, f"{tag}; {status}{seal_note}", actor)
        results.append({"item": ref, "kind": kind, "status": status,
                        **{k: checked[k] for k in ("sealed", "seal_status", "seal_reason") if k in checked},
                        "altered": [ref] if status == "TAMPERED" else [],
                        "missing": [ref] if status == "MISSING" else []})
    chain = wp_custody.check_log(ev, expected_head=expected_head)
    bad = [r for r in results if r["status"] != "MATCH"]
    return {"ok": not bad and chain["ok"], "case": case, "seed": seed, "population": len(items),
            "sampled": len(chosen), "results": results,
            "altered": [r["item"] for r in results if r["status"] == "TAMPERED"],
            "missing": [r["item"] for r in results if r["status"] == "MISSING"],
            "custody_log": chain,
            "custody_head": chain.get("head"),
            "verdict": ("nothing stored for this case — no item was re-hashed" if not chosen else
                        "intact — every sampled item matches its recorded digest" if not bad else
                        f"FIXITY FAILURE — {len(bad)} of {len(chosen)} sampled item(s) altered or "
                        f"missing; do not cite them until explained")
                       + ("" if chain["ok"] else f"; {chain['note']}")}


__all__ = ["capture", "verify", "bundle_digest", "referenced_assets", "working_copy", "fixity",
           "BUDGETS", "CAPTURE_KINDS", "LAYOUT", "CAPTURE_VERSION"]


def main(argv=None):
    ap = argparse.ArgumentParser(description="capture a page's raw DOM + JS + CSS as evidence")
    ap.add_argument("target", nargs="?", default=None,
                    help="URL to capture, or a capture directory with --verify / --working-copy")
    ap.add_argument("--verify", action="store_true", help="re-hash a stored capture instead")
    ap.add_argument("--no-seal", dest="seal", action="store_false", default=None,
                    help="with --verify: do not make an intact case capture read-only")
    ap.add_argument("--working-copy", dest="working_copy", action="store_true",
                    help="copy the target capture dir / screenshot PNG to evidence/work/ and log it")
    ap.add_argument("--fixity", type=int, metavar="N", default=None,
                    help="re-hash a random sample of N stored captures/screenshots of --case")
    ap.add_argument("--seed", type=int, default=None, help="with --fixity: reproducible sample")
    ap.add_argument("--check-log", action="store_true", help="check --case's custody chain")
    ap.add_argument("--expected-head", default=None, metavar="SHA256:COUNT",
                    help="with --check-log / --fixity: compare against a previously recorded head")
    ap.add_argument("--custody", metavar="ACTION", choices=wp_custody.MANUAL_ACTIONS, default=None,
                    help="append a manual custody line to --case's log: "
                         + ", ".join(wp_custody.MANUAL_ACTIONS))
    ap.add_argument("--item", default=None, help="with --custody: the item (path relative to the case)")
    ap.add_argument("--digest", default=None, help="with --custody: the item's sha256 / capture_sha256")
    ap.add_argument("--note", default=None, help="with --custody / --working-copy: free-text note")
    ap.add_argument("--case", default=None, help="write under cases/<case>/evidence/captures/")
    ap.add_argument("--outdir", default=None, help="explicit output directory (overrides --case)")
    ap.add_argument("--root", default=None,
                    help="directory holding cases/ (default: $INTEL_HOME, else intel_engine/)")
    ap.add_argument("--no-third-party", dest="third_party", action="store_false",
                    help="record third-party URLs in the manifest but do not download them")
    ap.add_argument("--ua", default=DEFAULT_UA)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--collector", default=None,
                    help="who collects / acts (default: $CTI_COLLECTOR, else a case pseudonym)")
    ap.add_argument("--persona", default=None, help="virtual identity in use (default: $CTI_PERSONA)")
    ap.add_argument("--egress-ip", dest="egress_ip", default=None,
                    help="egress IP confirmed with `proxy.py test` (default: $CTI_EGRESS_IP)")
    args = ap.parse_args(argv)

    if args.custody or args.fixity is not None or args.check_log:
        if not args.case:
            ap.error("--custody, --fixity and --check-log need --case")
        args.root = case_home(args.case, args.root)
        ev = wp_custody.case_evidence_dir(args.case, args.root)
        if args.custody:
            item = wp_custody.contained_ref(os.path.dirname(os.path.abspath(ev)), args.item)
            if item is None:
                ap.error("--custody needs --item with a realpath inside the case directory")
            out = wp_custody.append(ev, args.custody, item, args.digest, args.note, args.collector)
        elif args.check_log:
            out = wp_custody.check_log(ev, expected_head=args.expected_head)
        else:
            out = fixity(args.case, args.fixity, args.seed, root=args.root, actor=args.collector,
                         expected_head=args.expected_head)
    elif not args.target:
        ap.error("a URL or capture directory is required (or --fixity / --custody with --case)")
    elif args.working_copy:
        out = working_copy(args.target, actor=args.collector, note=args.note)
    elif args.verify or os.path.isdir(args.target):
        out = verify(args.target, seal=args.seal, actor=args.collector)
    else:
        out = capture(args.target, case=args.case, outdir=args.outdir, ua=args.ua,
                      proxy=args.proxy, third_party=args.third_party, root=args.root,
                      timeout=args.timeout, collector=args.collector, persona=args.persona,
                      egress_ip=args.egress_ip)
        m = out.get("manifest") or {}
        print(f"[+] captured {m.get('counts', {}).get('total', 0)} file(s) -> {out.get('dir')}",
              file=sys.stderr)
        print(f"    capture_sha256 {out.get('capture_sha256')}", file=sys.stderr)
        if m.get("skipped_for_budget"):
            print(f"    [!] {len(m['skipped_for_budget'])} asset(s) skipped for budget — the "
                  f"manifest says so; this bundle is NOT the whole page.", file=sys.stderr)
        out = m or out
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out.get("ok", True) and not out.get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
