#!/usr/bin/env python3
# cti-expert skill — ported from the Quarry OSINT toolkit (github.com/7onez/quarry): sensitive_path_classifier.py
"""sensitive_paths.py — classify a URL / Wayback-index list against sensitive-path patterns.

Pure post-processing — NO network at all. Reads inputs (a bare URL, a
"timestamp url" pair, or a full CDX / waymore index row) from positional args,
--file, or --stdin; matches each URL's path against the ported Quarry
SENSITIVE_PATH_RULES rule set; and emits severity-annotated hits
(CRITICAL/HIGH/MEDIUM/LOW) plus a per-year timeline derived from the 14-digit
Wayback timestamp when present. A malformed input line is skipped, never fatal.

Usage:
  uv run sensitive_paths.py https://x.com/.git/config https://x.com/.env
  uv run sensitive_paths.py --file waymore_index.txt --severity HIGH --pretty
  waymore -i example.com -mode U | uv run sensitive_paths.py --stdin -o hits.json
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

import re
import json
import argparse
from collections import defaultdict
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Rule set — (compiled_pattern, path_type, severity)      [ported VERBATIM]
# Patterns match against the lowercased URL *path component only* (no query
# string). Each is anchored to a path boundary + end so partial matches inside
# legitimate filenames are rejected (e.g. /assets/env-banner.png is NOT .env).
#
# Boundary anchors used:
#   (^|/)  — must be immediately after a slash or at the start of the path
#   (\.|$) — must be followed by a dot or end of string
# ---------------------------------------------------------------------------

# Helper to build a word-boundary-anchored pattern for a plain name
def _pat(name):
    """Anchor ``name`` so it only matches as a full path segment or filename.

    Matches: /secret/.env  /foo/.env.local  but NOT /foo/env-banner.png
    """
    return re.compile(r"(^|/)" + re.escape(name) + r"(\.|$)")


def _prefix_pat(prefix):
    """Match paths that start with ``prefix`` (after a slash or at root)."""
    return re.compile(r"(^|/)" + re.escape(prefix))


def _suffix_pat(suffix):
    """Match filenames that end with ``suffix``."""
    return re.compile(r"(^|/)[^/]+" + re.escape(suffix) + r"$")


# Rule list: (compiled_regex, path_type, severity)
# Order matters only for display; first match per URL wins.
_RAW_RULES = [
    # ── CRITICAL ──────────────────────────────────────────────────────────
    (_pat(".git/config"),           ".git/config",          "critical"),
    (_pat(".git-credentials"),      ".git-credentials",     "critical"),
    (_pat(".npmrc"),                ".npmrc",               "critical"),
    (_pat("wp-config.php"),         "wp-config.php",        "critical"),
    (_pat(".htpasswd"),             ".htpasswd",            "critical"),
    # id_rsa / id_dsa — bare filenames (no extension anchor needed, they have none)
    (re.compile(r"(^|/)id_rsa$"),   "id_rsa",               "critical"),
    (re.compile(r"(^|/)id_dsa$"),   "id_dsa",               "critical"),
    # *.pem / *.key — any filename ending with these extensions
    (_suffix_pat(".pem"),           "*.pem",                "critical"),
    (_suffix_pat(".key"),           "*.key",                "critical"),
    (_pat(".aws/credentials"),      ".aws/credentials",     "critical"),
    # SQL dumps
    (_pat("dump.sql"),              "dump.sql",             "critical"),
    (_suffix_pat(".sql"),           "*.sql",                "critical"),

    # ── HIGH ──────────────────────────────────────────────────────────────
    # .env and .env.* (e.g. .env.local, .env.production)
    (re.compile(r"(^|/)\.env(\.|$)"), ".env",              "high"),
    (_pat("docker-compose.yml"),    "docker-compose.yml",   "high"),
    (_pat("web.config"),            "web.config",           "high"),
    (_pat("config.php"),            "config.php",           "high"),
    (_pat("settings.py"),           "settings.py",          "high"),
    (_pat(".dockercfg"),            ".dockercfg",           "high"),

    # ── MEDIUM ────────────────────────────────────────────────────────────
    # .git/HEAD (less severe than config — no credential exposure)
    (_pat(".git/HEAD"),             ".git/HEAD",            "medium"),
    # SVN metadata directory
    (_prefix_pat(".svn/"),          ".svn/",                "medium"),
    # Backup extensions — anchor end-of-path
    (_suffix_pat(".bak"),           "*.bak",                "medium"),
    (_suffix_pat(".old"),           "*.old",                "medium"),
    (_suffix_pat(".swp"),           "*.swp",                "medium"),
    (_suffix_pat("~"),              "*~",                   "medium"),
    (_suffix_pat(".orig"),          "*.orig",               "medium"),
    (_suffix_pat(".zip"),           "*.zip",                "medium"),
    (_suffix_pat(".tar.gz"),        "*.tar.gz",             "medium"),
    (_suffix_pat(".tgz"),           "*.tgz",                "medium"),
    (_pat(".DS_Store"),             ".DS_Store",            "medium"),

    # ── LOW ───────────────────────────────────────────────────────────────
    (_suffix_pat(".log"),           "*.log",                "low"),
    (_pat("phpinfo.php"),           "phpinfo.php",          "low"),
    # backup keyword in path segment — e.g. /backup/, /backup.tar
    (re.compile(r"(^|/)backup(\.|/|$)"), "backup",         "low"),
]

# Public: compiled rule set as (pattern, path_type, severity)
SENSITIVE_PATH_RULES = _RAW_RULES

# Severity ordering (ported verbatim). Lower rank = higher severity.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Fixed output labels, most-severe first (the JSON contract uses upper-case).
_SEV_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------------
# Path classifier      [ported VERBATIM]
# ---------------------------------------------------------------------------

def _parse_year(timestamp):
    """Extract 4-digit year from Wayback timestamp (YYYYMMDDhhmmss).

    Returns the integer year if parseable, otherwise the string "unknown".
    Never calls int('') — handles empty/short/non-numeric safely.
    """
    ts = (timestamp or "").strip()
    if len(ts) >= 4:
        try:
            return int(ts[:4])
        except ValueError:
            pass
    return "unknown"


def _classify_path(path):
    """Return (path_type, severity) for the first matching rule, or None."""
    lpath = path.lower()
    for pattern, path_type, severity in SENSITIVE_PATH_RULES:
        if pattern.search(lpath):
            return path_type, severity
    return None


def _extract_target_url(archive_url):
    """Reconstruct the original target URL from a Wayback Machine URL.

    Wayback format: http://web.archive.org/web/<timestamp>/<original_url>
    If not a Wayback URL, returns the raw URL unchanged.
    """
    try:
        parts = urlsplit(archive_url)
        # path looks like /web/20190103120000/http://example.com/path
        if parts.netloc in ("web.archive.org", "timetravel.mementoweb.org"):
            path = parts.path  # /web/20190103.../http://...
            # Remove /web/<timestamp>/ prefix
            idx = path.find("/", 5)  # skip "/web/"
            if idx != -1:
                rest = path[idx + 1:]
                # rest starts with the original scheme://...
                return rest
    except Exception:
        pass
    return archive_url


def classify_archive_urls(urls_with_ts):
    """Classify a list of (archive_url, timestamp) pairs against sensitive-path rules.

    Args:
        urls_with_ts: Each item is (url, timestamp) where timestamp may be ''
                      (empty = unknown year; never raises ValueError).

    Returns:
        {
          "paths": [{url, target_url, path_type, severity, year, timestamp}],
          "timeline": {year: {total, by_severity, by_type}},
          "stats": {urls_scanned, flagged, unique_paths, year_range},
        }
    """
    urls_scanned = 0
    # Dedupe by target_url — keep earliest + latest snapshot
    seen = {}  # target_url → hit record

    for archive_url, timestamp in urls_with_ts:
        urls_scanned += 1
        try:
            target_url = _extract_target_url(archive_url)
            parsed_path = urlsplit(target_url).path
        except Exception:
            continue

        result = _classify_path(parsed_path)
        if result is None:
            continue

        path_type, severity = result
        year = _parse_year(timestamp)

        if target_url not in seen:
            seen[target_url] = {
                "url": archive_url,
                "target_url": target_url,
                "path_type": path_type,
                "severity": severity,
                "year": year,
                "timestamp": timestamp,
                # Track earliest/latest for dedup logic
                "_earliest_ts": timestamp,
                "_latest_ts": timestamp,
            }
        else:
            existing = seen[target_url]
            # Update URL to the earliest snapshot (better historical evidence)
            if timestamp and (not existing["_earliest_ts"] or timestamp < existing["_earliest_ts"]):
                existing["_earliest_ts"] = timestamp
                existing["url"] = archive_url
                existing["year"] = year
                existing["timestamp"] = timestamp
            if timestamp and timestamp > existing.get("_latest_ts", ""):
                existing["_latest_ts"] = timestamp

    # Build paths list (strip internal tracking keys)
    paths = []
    for hit in seen.values():
        paths.append({
            "url": hit["url"],
            "target_url": hit["target_url"],
            "path_type": hit["path_type"],
            "severity": hit["severity"],
            "year": hit["year"],
            "timestamp": hit["timestamp"],
        })

    # Sort by severity (critical first), then year
    paths.sort(key=lambda p: (_SEV_ORDER.get(p["severity"], 9),
                              p["year"] if isinstance(p["year"], int) else 9999))

    # Build per-year timeline (numeric years only; "unknown" excluded from chart)
    timeline = defaultdict(
        lambda: {"total": 0, "by_severity": defaultdict(int), "by_type": defaultdict(int)}
    )
    numeric_years = set()

    for hit in paths:
        yr = hit["year"]
        yr_key = str(yr)
        timeline[yr_key]["total"] += 1
        timeline[yr_key]["by_severity"][hit["severity"]] += 1
        timeline[yr_key]["by_type"][hit["path_type"]] += 1
        if isinstance(yr, int):
            numeric_years.add(yr)

    # Serialize defaultdicts to plain dicts
    serialized_timeline = {
        yr_key: {
            "total": data["total"],
            "by_severity": dict(data["by_severity"]),
            "by_type": dict(data["by_type"]),
        }
        for yr_key, data in timeline.items()
    }

    year_range = sorted(numeric_years)[:2] if numeric_years else []
    if numeric_years:
        year_range = [min(numeric_years), max(numeric_years)]

    return {
        "paths": paths,
        "timeline": serialized_timeline,
        "stats": {
            "urls_scanned": urls_scanned,
            "flagged": len(paths),
            "unique_paths": len(paths),
            "year_range": year_range,
        },
    }


# ---------------------------------------------------------------------------
# Input parsing — robust; never raises on a malformed line, just skips it
# ---------------------------------------------------------------------------

_TS_RE = re.compile(r"^\d{14}$")  # 14-digit Wayback timestamp column


def parse_input_line(line):
    """Extract (url, timestamp) from one input line, or None if no URL present.

    Accepts, from whitespace-separated columns:
      - a bare URL                       -> (url, "")
      - a "timestamp url" pair           -> (url, "YYYYMMDDhhmmss")   (order-free)
      - a full CDX/waymore index row     -> first http(s) token + first 14-digit token
    Lines that are blank, comments (#...), or contain no http(s) token are skipped.
    """
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    url = None
    ts = ""
    for tok in line.split():
        if url is None and (tok.lower().startswith("http://") or tok.lower().startswith("https://")):
            url = tok
        elif not ts and _TS_RE.match(tok):
            ts = tok
    if url is None:
        return None
    return (url, ts)


def gather_inputs(positional, file_path, use_stdin):
    """Collect raw input lines from args / --file / --stdin (in that order)."""
    lines = list(positional or [])
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                lines += fh.read().splitlines()
        except OSError as e:
            print(f"[!] could not read {file_path}: {e}", file=sys.stderr)
            sys.exit(2)
    if use_stdin:
        try:
            lines += sys.stdin.read().splitlines()
        except Exception:
            pass
    return lines


# ---------------------------------------------------------------------------
# Output shaping — reshape the ported classification into the CLI JSON contract
# ---------------------------------------------------------------------------

def build_output(classification, severity_filter=None):
    """Reshape classify_archive_urls() output into the tool's JSON contract.

    Applies an optional severity floor (>= severity_filter), upper-cases the
    severity labels, and aggregates by_severity / by_type / per-year timeline.
    """
    threshold = _SEV_ORDER[severity_filter.lower()] if severity_filter else None

    hits = []
    for p in classification["paths"]:
        sev_lc = p["severity"]
        if threshold is not None and _SEV_ORDER.get(sev_lc, 9) > threshold:
            continue
        ts = p.get("timestamp") or ""
        yr = p.get("year")
        hits.append({
            "url": p["url"],
            "path_type": p["path_type"],
            "severity": sev_lc.upper(),
            "timestamp": ts if ts else None,
            "year": yr if isinstance(yr, int) else None,
        })

    # Sort hits by severity (CRITICAL first) then url
    hits.sort(key=lambda h: (_SEV_ORDER.get(h["severity"].lower(), 9), h["url"]))

    by_severity = {lab: 0 for lab in _SEV_LABELS}
    by_type = {}
    timeline_counts = {}
    for h in hits:
        by_severity[h["severity"]] = by_severity.get(h["severity"], 0) + 1
        by_type[h["path_type"]] = by_type.get(h["path_type"], 0) + 1
        if h["year"] is not None:
            k = str(h["year"])
            timeline_counts[k] = timeline_counts.get(k, 0) + 1
    timeline = {k: timeline_counts[k] for k in sorted(timeline_counts)}

    return {
        "hits": hits,
        "by_severity": by_severity,
        "by_type": by_type,
        "timeline": timeline,
        "summary": {
            "urls_scanned": classification["stats"]["urls_scanned"],
            "hits": len(hits),
        },
    }


def main():
    ap = argparse.ArgumentParser(
        description="Classify URLs / Wayback-index rows against sensitive-path patterns "
                    "(Quarry port; pure, no network).")
    ap.add_argument("urls", nargs="*",
                    help="URLs or index rows (bare URL, 'timestamp url', or CDX/waymore row)")
    ap.add_argument("--file", help="file of inputs, one entry per line")
    ap.add_argument("--stdin", action="store_true",
                    help="also read inputs from stdin, one entry per line")
    ap.add_argument("--severity", choices=_SEV_LABELS,
                    help="only report hits at or above this severity")
    ap.add_argument("--pretty", action="store_true", help="pretty-print the JSON output")
    ap.add_argument("-o", "--out", help="write JSON to FILE instead of stdout")
    args = ap.parse_args()

    if not args.urls and not args.file and not args.stdin:
        ap.error("provide URLs positionally, or --file PATH, or --stdin")

    raw_lines = gather_inputs(args.urls, args.file, args.stdin)
    urls_with_ts = []
    for line in raw_lines:
        parsed = parse_input_line(line)
        if parsed is not None:
            urls_with_ts.append(parsed)

    classification = classify_archive_urls(urls_with_ts)
    out = build_output(classification, args.severity)

    out_json = json.dumps(out, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(out_json + "\n")
        except Exception as e:
            print(f"[!] could not write {args.out}: {e}", file=sys.stderr)
            print(out_json)
    else:
        print(out_json)

    bs = out["by_severity"]
    print(f"{out['summary']['urls_scanned']} urls → {out['summary']['hits']} sensitive hits "
          f"({bs['CRITICAL']} crit / {bs['HIGH']} high / {bs['MEDIUM']} medium / {bs['LOW']} low)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
