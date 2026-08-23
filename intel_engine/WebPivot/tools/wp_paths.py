#!/usr/bin/env python3
"""wp_paths — the URL PATH as a campaign identifier.

THE TECHNIQUE THIS EXISTS TO DEFEAT
------------------------------------
Every other layer in WebPivot answers "who else owns this HOST". Favicon hashes, TLS certificates,
registrant records, nameservers, JARM — all of them hang off the hostname. A kit operator who has
noticed that inverts the whole model:

    host-a.example/<kit-x>/      host-b.example/<kit-x>/      host-c.example/<kit-y>/

The hosts are disposable — numeric labels on cheap TLDs, rotated weekly, each with its own
certificate and its own registration. Nothing at host level connects them. What connects them is
the PATH: the operator keeps one directory per branded template on a shared back end, and selects
which victim sees which brand by the URL they are sent. The path outlives the host, because the
path is the product and the host is packaging.

Collect path-blind and you get N unrelated one-domain cases. Keep the path and the same N rows
collapse into "one operator, two kits, three hosts" — and the kit directory becomes a pivot you can
hunt with (`urlscan page.url`, a search-engine `inurl:`, FOFA), which finds the NEXT host before it
is reported anywhere.

WHAT THIS MODULE PRODUCES
-------------------------
  normalise_path()  – one canonical form, so `/kit/`, `/kit/index.php` and `/KIT` are one location
  path_template()   – the SKELETON: variable segments (session ids, build hashes, dates, locales)
                      replaced by placeholders, so per-victim URLs collapse to one template
  kit_segment()     – the first DISTINCTIVE segment: the template directory, i.e. the kit name
  path_tokens()     – every distinctive segment, for vocabulary comparison between hosts
  path_pivots()     – ready-to-run reverse queries for the kit and the template
  path_patterns()   – across many collected pages: which templates recur, on how many hosts

BASE RATES, OR THIS LAYER MANUFACTURES CLUSTERS
-----------------------------------------------
`/login`, `/assets`, `/api/v1` and `/wp-admin` appear on millions of unrelated sites. Clustering on
one of those would fuse the internet into a single operator, which is the exact failure the KB's
noise filters exist to prevent — so a segment on the `generic_segments` denylist is never a kit and
never a pivot, and a path with no distinctive segment emits NOTHING. That list is the base-rate
control and it is DATA (`references/url_paths.json`): when a run produces a cluster joined only by
a path segment, the fix is to add the segment there, not to edit this file.

Equally: a shared kit directory is a SAME-KIT claim, not a same-operator one, exactly like a shared
phishing-kit template or a shared white-label platform. Two resellers of the same kit have the same
directory names. It is a strong lead and a legitimate collection pivot; it becomes attribution only
when a second, independent artifact class agrees. `clusterable()` says so on every value.

CLI:
  python3 wp_paths.py analyze https://host.example/kit-x/step2/9f3a1c
  python3 wp_paths.py patterns cases/<case>/raw/*.json     # which templates recur, on how many hosts
"""
import argparse
import glob
import json
import os
import re
import sys
from urllib.parse import urlparse, unquote

from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

# --- reference DATA (RULE 3). The fallback is the minimum that keeps the BASE-RATE control alive
#     if the JSON goes missing: without a generic-segment denylist this layer would start emitting
#     `/login` as an operator fingerprint, so the fallback carries the highest-frequency segments
#     rather than an empty list. load_ref warns loudly.
_PATH_FALLBACK = {
    "variable_patterns": {
        "uuid": {"regex": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                 "placeholder": "{uuid}"},
        "hex": {"regex": r"^[0-9a-f]{8,}$", "placeholder": "{hex}"},
        "digits": {"regex": r"^\d{2,}$", "placeholder": "{n}"},
        "base64ish": {"regex": r"^[A-Za-z0-9_-]{16,}$", "placeholder": "{token}"},
    },
    "generic_segments": ["index", "index.php", "index.html", "home", "login", "signin", "admin",
                         "api", "static", "assets", "public", "img", "images", "css", "js",
                         "app", "web", "about", "contact", "search", "wp-admin", "wp-content"],
    "locale_segments": ["en", "vi", "vn", "zh", "cn", "th", "id", "ru", "de", "fr", "es", "pt"],
    "kit_thresholds": {"min_kit_len": 3, "max_kit_len": 48, "max_segments": 6,
                       "min_hosts_for_pattern": 2},
    "asset_extensions": ["js", "mjs", "css", "map", "json", "png", "jpg", "jpeg", "gif", "svg",
                         "webp", "ico", "woff", "woff2", "ttf"],
    "index_files": ["index.html", "index.htm", "index.php"],
}
_REFS = load_ref(ref_path(__file__, "url_paths.json"), _PATH_FALLBACK)
VARIABLE_PATTERNS = _REFS["variable_patterns"]
GENERIC_SEGMENTS = frozenset(s.lower() for s in _REFS["generic_segments"])
LOCALE_SEGMENTS = frozenset(s.lower() for s in _REFS["locale_segments"])
KIT_THRESHOLDS = _REFS["kit_thresholds"]
ASSET_EXTENSIONS = frozenset(s.lower().lstrip(".") for s in _REFS["asset_extensions"])
INDEX_FILES = frozenset(s.lower() for s in _REFS["index_files"])

_LOCALE_PLACEHOLDER = "{locale}"


def _thr(key, default):
    try:
        return int(KIT_THRESHOLDS.get(key, default))
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- normalisation
def split_path(url_or_path: str):
    """The path of a URL (or a bare path) as a list of decoded, lowercased segments.

    Percent-decoded first, because `/%6B%69%74/` and `/kit/` are the same directory and an operator
    who encodes one is hiding it from exactly this kind of string comparison."""
    raw = url_or_path or ""
    path = urlparse(raw).path if "://" in raw else raw
    try:
        path = unquote(path)
    except Exception:
        pass
    segs = [s.strip().lower() for s in path.split("/")]
    return [s for s in segs if s and s != "."]


def normalise_path(url_or_path: str) -> str:
    """One canonical `/a/b` form for a URL or path — the key everything else is stored under.

    Strips a directory-index filename, so `/kit/`, `/kit/index.php` and `/kit/index.html` are ONE
    location. Without this a single template is counted as three, and the recurrence count that
    makes a pattern visible is diluted by exactly the sites that prove it."""
    segs = split_path(url_or_path)
    if segs and segs[-1] in INDEX_FILES:
        segs = segs[:-1]
    return "/" + "/".join(segs) if segs else "/"


def _classify_segment(seg: str):
    """(placeholder_or_None, reason) for one segment. A placeholder means the segment is VARIABLE
    and must not be compared literally."""
    if seg in LOCALE_SEGMENTS:
        return _LOCALE_PLACEHOLDER, "locale"
    for name, spec in (VARIABLE_PATTERNS or {}).items():
        if not isinstance(spec, dict) or not spec.get("regex"):
            continue
        try:
            if re.match(spec["regex"], seg, re.I):
                return spec.get("placeholder") or "{%s}" % name, name
        except re.error as exc:
            print(f"[paths] WARNING: variable pattern {name!r} is not a valid regex ({exc}); "
                  f"skipping it.", file=sys.stderr)
    return None, ""


def path_template(url_or_path: str) -> str:
    """The path SKELETON — variable segments replaced by placeholders.

    This is what makes per-victim URLs comparable. A kit that hands each target
    `/<kit>/<random>/step2` produces a different path every time; the template is the same string
    for all of them, so recurrence becomes countable. Bounded by `max_segments` so a deep CMS URL
    cannot become a 'unique fingerprint' that only ever matches itself."""
    segs = split_path(url_or_path)
    if segs and segs[-1] in INDEX_FILES:
        segs = segs[:-1]
    segs = segs[:_thr("max_segments", 6)]
    out = []
    for seg in segs:
        ph, _ = _classify_segment(seg)
        out.append(ph or seg)
    return "/" + "/".join(out) if out else "/"


def is_generic_segment(seg: str) -> bool:
    """True when a segment is too common to carry any operator signal.

    Length and shape count too: a 1-2 character segment is routing, and a segment that is entirely
    variable (a hash, a token) says nothing about WHO — only that something was randomised."""
    s = (seg or "").strip().lower()
    if not s or s in GENERIC_SEGMENTS or s in LOCALE_SEGMENTS:
        return True
    if len(s) < _thr("min_kit_len", 3) or len(s) > _thr("max_kit_len", 48):
        return True
    # A static-asset FILE is never a template directory. `app.js` survives the word denylist
    # (it is not a common word) but fingerprinting it would cluster on a filename every bundler
    # in the world emits. Page extensions (.php/.html) are deliberately not listed — a kit's
    # entry point is often exactly `/<brand>.html`.
    if "." in s and s.rsplit(".", 1)[-1] in ASSET_EXTENSIONS:
        return True
    ph, _ = _classify_segment(s)
    return bool(ph)


def path_tokens(url_or_path: str) -> list:
    """Every DISTINCTIVE segment of a path, in order — the path's vocabulary.

    Two hosts whose paths share a distinctive vocabulary are running the same kit family even when
    the directory order differs. Generic and variable segments are dropped, because they are shared
    by everyone and by no one respectively."""
    return [s for s in split_path(url_or_path) if not is_generic_segment(s)]


def kit_segment(url_or_path: str):
    """The TEMPLATE DIRECTORY — the first distinctive segment, i.e. the kit selector. None when the
    path carries no distinctive segment at all (a bare `/`, `/login`, `/en/`).

    This is the single most useful field this module produces. On a host pool where every hostname
    is disposable, the kit directory is the one string the operator cannot randomise without
    rebuilding their own routing — so it survives the host rotation that breaks every other pivot.
    Returning None is the common and correct outcome for an ordinary site; a kit pivot on `/login`
    would be a manufactured cluster."""
    toks = path_tokens(url_or_path)
    return toks[0] if toks else None


def locale_of(url_or_path: str):
    """The concrete locale segment in a path, if any (`vi`, `au`, `pl`).

    Normalised AWAY in the template so one kit in five markets reads as one kit — but kept here,
    because which market a template was localised for is target-selection evidence and feeds the
    victim/demographic layer."""
    for seg in split_path(url_or_path):
        if seg in LOCALE_SEGMENTS:
            return seg
    return None


def clusterable(url_or_path: str) -> bool:
    """True when this path may support a SAME-KIT lead. Never a same-operator claim on its own —
    two resellers of one kit share directory names, exactly as two tenants of a white-label
    platform share its artifacts. Fails closed on a path with no distinctive segment."""
    return kit_segment(url_or_path) is not None


# --------------------------------------------------------------------------- the analysed record
def analyse(url: str, host: str = "") -> dict:
    """Everything this layer knows about one collected URL. Cheap, offline, no network."""
    h = host or (urlparse(url).netloc if "://" in url else "")
    norm = normalise_path(url)
    kit = kit_segment(url)
    rec = {
        "url_path": norm,
        "path_template": path_template(url),
        "path_tokens": path_tokens(url),
        "kit": kit,
        "locale": locale_of(url),
        "depth": len([s for s in norm.split("/") if s]),
        "clusterable": kit is not None,
        # host+path, because on a path-routed estate this pair is the unit of investigation and the
        # host alone is not. Two rows with the same key are the same page; two rows with the same
        # kit and different hosts are the finding.
        "location": f"{h.lower()}{norm}" if h else norm,
    }
    if not kit:
        rec["note"] = ("no distinctive path segment — this path is generic (base-rate control), so "
                       "it is deliberately NOT emitted as a pivot. Absence of a kit here is normal "
                       "for an ordinary site, not a negative finding.")
    return rec


# --------------------------------------------------------------------------- pivots
def path_pivots(url: str, host: str = "") -> list:
    """Ready-to-run reverse queries for a path — [] when the path carries nothing distinctive.

    The queries matter as much as the artifact: a kit directory is searchable in indexes that store
    the full URL (urlscan, the search engines, FOFA), and those indexes are how you find the NEXT
    host serving the same kit — usually before it has been reported anywhere."""
    rec = analyse(url, host)
    kit = rec["kit"]
    if not kit:
        return []
    tpl = rec["path_template"]
    out = [{
        "kind": "path:kit", "value": kit, "confidence": "medium",
        "note": ("Template directory — the operator selects which branded kit to serve by URL "
                 "PATH, not by hostname, so this string survives the host rotation that breaks "
                 "favicon / TLS / registrant pivots. SAME-KIT evidence: strong as a collection "
                 "lead, not a same-operator claim until a second artifact class agrees."),
        "queries": [
            {"service": "urlscan.io", "query": f'page.url:"/{kit}/"'},
            {"service": "urlscan.io (task URL)", "query": f'task.url:"/{kit}/"'},
            {"service": "Google/Bing/DDG dork", "query": f'inurl:"/{kit}/"'},
            {"service": "FOFA", "query": f'body="/{kit}/"'},
            {"service": "PublicWWW", "query": f'"/{kit}/"'},
            {"service": "Wayback CDX (any host, this path)",
             "query": f"https://web.archive.org/cdx/search/cdx?url=*/{kit}/*&output=json&collapse=urlkey&limit=200"},
        ],
    }]
    if tpl and tpl != "/" + kit:
        out.append({
            "kind": "path:template", "value": tpl, "confidence": "low",
            "note": ("Full path skeleton with variable segments (session ids, build hashes, dates, "
                     "locales) normalised out. Two hosts serving the identical skeleton are running "
                     "the same build of the same kit."),
            "queries": [{"service": "urlscan.io", "query": f'page.url:"{tpl.split("{")[0]}"'}],
        })
    return out


# --------------------------------------------------------------------------- cross-page patterns
def path_patterns(records, min_hosts: int = None) -> dict:
    """Across many collected pages -> which kits/templates RECUR, and on how many distinct hosts.

    `records` is any iterable of dicts carrying a url/host (a WebPivot result, a raw JSON file, or
    a bare {"url": ...}). This is the function that turns a pile of one-domain cases into the
    finding: *the same kit directory on N unrelated hosts*.

    `min_hosts` (default from `kit_thresholds.min_hosts_for_pattern`) is the honesty threshold —
    one host serving a kit is an observation; the pattern claim starts when the same kit appears on
    hosts that share nothing else. Everything below the threshold is still returned, under
    `single_host`, so a one-off is visible as a lead rather than silently dropped."""
    floor = int(min_hosts if min_hosts is not None else _thr("min_hosts_for_pattern", 2))
    kits, templates, by_host = {}, {}, {}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        meta = rec.get("meta") or {}
        url = rec.get("url") or meta.get("final_url") or meta.get("source_url") or rec.get("final_url")
        host = (rec.get("host") or meta.get("host") or
                (urlparse(url).netloc if url and "://" in url else "")).lower()
        if not url and not rec.get("url_path"):
            continue
        a = analyse(url or rec.get("url_path"), host)
        by_host.setdefault(host, []).append(a["url_path"])
        if a["kit"]:
            kits.setdefault(a["kit"], set()).add(host)
        if a["path_template"] and a["path_template"] != "/":
            templates.setdefault(a["path_template"], set()).add(host)

    def _rank(d):
        return sorted(({"value": k, "hosts": sorted(h), "host_count": len(h)}
                       for k, h in d.items()),
                      key=lambda r: (-r["host_count"], r["value"]))

    ranked_kits = _rank(kits)
    return {
        "min_hosts_for_pattern": floor,
        # The finding: one kit directory, several hosts that share nothing at host level.
        "recurring_kits": [r for r in ranked_kits if r["host_count"] >= floor],
        "single_host_kits": [r for r in ranked_kits if r["host_count"] < floor],
        "recurring_templates": [r for r in _rank(templates) if r["host_count"] >= floor],
        # A host serving SEVERAL distinct kits is the other half of the same technique: one back
        # end, many brands. Worth as much as one kit on many hosts.
        "multi_kit_hosts": sorted(
            ({"host": h, "paths": sorted(set(p))} for h, p in by_host.items()
             if len({kit_segment(p) for p in p if kit_segment(p)}) > 1),
            key=lambda r: (-len(r["paths"]), r["host"])),
        "hosts_seen": len(by_host),
        "note": ("A shared kit directory is SAME-KIT evidence. It is a strong collection lead — "
                 "hunt the next host with the emitted urlscan/inurl queries — but it becomes a "
                 "same-OPERATOR claim only when an independent artifact class (registrant, TLS, "
                 "hosting window, tracker, wallet) agrees. Two resellers of one kit share these "
                 "strings."),
    }


__all__ = ["split_path", "normalise_path", "path_template", "path_tokens", "kit_segment",
           "locale_of", "is_generic_segment", "clusterable", "analyse", "path_pivots",
           "path_patterns", "VARIABLE_PATTERNS", "GENERIC_SEGMENTS", "LOCALE_SEGMENTS",
           "KIT_THRESHOLDS", "ASSET_EXTENSIONS", "INDEX_FILES"]


def _load_records(paths):
    recs = []
    for pat in paths:
        for p in sorted(glob.glob(pat)) or ([pat] if os.path.exists(pat) else []):
            try:
                with open(p, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except Exception as exc:
                print(f"[paths] skipping {p}: {exc}", file=sys.stderr)
                continue
            recs.extend(doc if isinstance(doc, list) else [doc])
    return recs


def main():
    ap = argparse.ArgumentParser(description="URL path as a campaign identifier")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze", help="one URL -> normalised path, template, kit, pivots")
    p.add_argument("url")
    p = sub.add_parser("patterns", help="many collected results -> which kits recur, on how many hosts")
    p.add_argument("paths", nargs="+", help="WebPivot result JSON files or globs")
    p.add_argument("--min-hosts", type=int, default=None)
    args = ap.parse_args()

    if args.cmd == "analyze":
        out = analyse(args.url)
        out["pivots"] = path_pivots(args.url)
    else:
        out = path_patterns(_load_records(args.paths), min_hosts=args.min_hosts)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
