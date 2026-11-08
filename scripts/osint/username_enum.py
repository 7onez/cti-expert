#!/usr/bin/env python3
"""username_enum.py — does this handle exist on these platforms?

SKILL.md advertised "3000+ platforms". That number is a liability, not a feature: most such lists
are stale, and a stale entry produces a CONFIDENT WRONG answer (a redirect or a soft-404 read as
"account exists"). This checks a small, curated set whose detection method is verified, and says
what it did not check.

The output is HYPOTHESES, never findings. A handle existing on two platforms is not evidence they
are the same person — handles are re-registered, squatted and coincidental. Corroborate with
content before linking identities, and never write a hypothesis into a case as a fact.

Trailing numeric suffixes produce configurable birth-year/date-fragment hints with
explicit ambiguity caveats, never DOB facts. --offline computes hints without requests.

Usage:
  username_enum.py operator90 --offline --pretty
  username_enum.py operator --platforms github,gitlab --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import concurrent.futures
import json
import re
import sys
import os
import datetime
import urllib.parse

WP = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..",
                                   "intel_engine", "WebPivot", "tools"))
if WP not in sys.path:
    sys.path.insert(0, WP)
from wp_refs import load_ref, ref_path

_FALLBACK = {"platforms": [], "patterns": {"valid": r"^[A-Za-z0-9._-]{1,64}$",
             "suffix": r"([0-9]+)$"},
             "numeric_suffix": {"two_digit_windows": [], "year_min": 1940,
                                "year_max": 2015, "date_formats": [],
                                "calendar_validation_year": 2000},
             "network": {"timeout": 12, "workers": 8},
             "telegram_markers": []}
_REFS = load_ref(ref_path(__file__, "username_enum.json"), _FALLBACK)
PLATFORMS = _REFS["platforms"]
VALID = re.compile(_REFS["patterns"]["valid"])


def numeric_suffix_hints(username):
    """Return ambiguous number interpretations, never a DOB assertion."""
    match = re.search(_REFS["patterns"]["suffix"], username)
    if not match:
        return []
    suffix = match.group(1)
    cfg = _REFS["numeric_suffix"]
    caveat = ("Ambiguous number: may be a jersey number, graduation year, "
              "account-creation year or lucky number. Never record as DOB; "
              "independent public evidence is required.")
    hints = []

    def add(kind, interpretation, pattern):
        hints.append({"suffix": suffix, "kind": kind, "pattern": pattern,
                      "interpretation": interpretation, "rung": "hint", "caveat": caveat})

    if len(suffix) == 2:
        for start, end, century in cfg["two_digit_windows"]:
            if start <= int(suffix) <= end:
                add("possible_birth_year", int(century) + int(suffix), "YY")
    if len(suffix) == 4 and cfg["year_min"] <= int(suffix) <= cfg["year_max"]:
        add("possible_birth_year", int(suffix), "YYYY")
    for fmt in cfg["date_formats"]:
        try:
            if len(suffix) == 4 and fmt in ("DDMM", "MMDD"):
                first, second = int(suffix[:2]), int(suffix[2:])
                month, day = (second, first) if fmt == "DDMM" else (first, second)
                datetime.date(cfg["calendar_validation_year"], month, day)
                add("possible_dob_fragment", {"month": month, "day": day}, fmt)
            elif len(suffix) == 8 and fmt == "YYYYMMDD":
                year, month, day = int(suffix[:4]), int(suffix[4:6]), int(suffix[6:])
                if cfg["year_min"] <= year <= cfg["year_max"]:
                    datetime.date(year, month, day)
                    add("possible_dob_fragment", {"year": year, "month": month, "day": day}, fmt)
        except ValueError:
            continue
    return hints


def _fetch(url, timeout=None, proxy=None):
    try:
        from wp_net import fetch
        _, status, _, body = fetch(url, timeout=timeout or _REFS["network"]["timeout"],
                                   proxy=proxy)
        return status, body.decode("utf-8", "replace")
    except Exception as exc:
        return None, type(exc).__name__


def check(name, tmpl, method, user, timeout=None, proxy=None):
    url = tmpl.format(u=urllib.parse.quote(user))
    code, body = _fetch(url, timeout=timeout, proxy=proxy)
    if code is None:
        return {"platform": name, "exists": None, "url": url, "note": f"unreachable ({body})"}
    if code not in (200, 404):
        return {"platform": name, "exists": None, "url": url, "http": code,
                "note": "Challenge, rate limit or unexpected response; presence unknown."}
    if method == "api":
        ex = code == 200
    elif method == "api_list":
        ex = code == 200 and body.strip() not in ("[]", "")
    elif method == "keybase":
        ex = code == 200 and '"them":[' in body.replace(" ", "") and '"them":[null]' not in body.replace(" ", "")
    elif method == "hn":
        ex = code == 200 and body.strip() not in ("null", "")
    elif method == "telegram":
        # t.me always returns 200; the absent case renders a generic page with no user block.
        ex = code == 200 and any(marker in body for marker in _REFS["telegram_markers"])
    else:
        ex = code == 200
    return {"platform": name, "exists": ex, "url": url, "http": code}


def main():
    # Offline mode derives hints without making any provider requests.
    ap = argparse.ArgumentParser(description="Check handle presence across curated platforms.")
    ap.add_argument("username")
    ap.add_argument("--platforms", help="comma-separated subset")
    ap.add_argument("--timeout", type=int, default=_REFS["network"]["timeout"])
    ap.add_argument("--offline", action="store_true", help="numeric hints only; no network")
    ap.add_argument("--proxy", help="HTTP proxy URL; proxy port must be 80")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    if a.proxy:
        try:
            proxy = urllib.parse.urlsplit(a.proxy)
            if proxy.scheme not in ("http", "https") or not proxy.hostname or proxy.port not in (None, 80):
                ap.error("proxy must be an HTTP(S) URL using port 80")
            if proxy.scheme == "https" and proxy.port is None:
                ap.error("HTTPS proxy must specify port 80")
        except ValueError:
            ap.error("invalid proxy URL")

    u = a.username.strip().lstrip("@")
    if not VALID.match(u):
        ap.error("username has characters no listed platform allows")

    sel = PLATFORMS
    if a.platforms:
        want = {p.strip().lower() for p in a.platforms.split(",")}
        sel = [p for p in PLATFORMS if p[0] in want]
        if not sel:
            ap.error(f"no known platform in {sorted(want)}; known: "
                     f"{', '.join(p[0] for p in PLATFORMS)}")

    rows = []
    if not a.offline:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_REFS["network"]["workers"]) as pool:
            rows = list(pool.map(lambda p: check(p[0], p[1], p[2], u, a.timeout, a.proxy), sel))
    for row in rows:
        row["rung"] = "lead"
        row["caveat"] = ("Account presence is a lead only, not an identity or operator link; "
                         "never create a KB identity edge from this result.")

    found = [r for r in rows if r.get("exists") is True]
    unknown = [r for r in rows if r.get("exists") is None]
    out = {
        "username": u,
        "results": rows,
        "numeric_suffix_hints": numeric_suffix_hints(u),
        "offline": a.offline,
        "summary": {"checked": len(rows), "present": len(found), "unreachable": len(unknown)},
        "classification": "HYPOTHESES — not findings",
        "caveat": ("A handle existing on a platform does NOT establish it is the same person as "
                   "the same handle elsewhere; handles are squatted, recycled and coincidental. "
                   "Corroborate with profile content, timing or a shared artifact before linking "
                   "identities. Absence is also weak: this checks "
                   f"{len(PLATFORMS)} platforms, not the whole internet."),
    }
    print(f"@{u}: present on {len(found)}/{len(rows)} checked "
          f"({', '.join(r['platform'] for r in found) or 'none'})"
          + (f"; {len(unknown)} unreachable" if unknown else ""), file=sys.stderr)
    print("  hypotheses only — corroborate before linking identities", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    # Network imports remain lazy so offline hints need only the standard library.
    sys.exit(main())
