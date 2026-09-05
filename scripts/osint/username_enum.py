#!/usr/bin/env python3
"""username_enum.py — does this handle exist on these platforms?

SKILL.md advertised "3000+ platforms". That number is a liability, not a feature: most such lists
are stale, and a stale entry produces a CONFIDENT WRONG answer (a redirect or a soft-404 read as
"account exists"). This checks a small, curated set whose detection method is verified, and says
what it did not check.

The output is HYPOTHESES, never findings. A handle existing on two platforms is not evidence they
are the same person — handles are re-registered, squatted and coincidental. Corroborate with
content before linking identities, and never write a hypothesis into a case as a fact.

Usage:
  username_enum.py johndoe
  username_enum.py johndoe --platforms github,gitlab --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import concurrent.futures
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; cti-expert/username_enum; OSINT research)"

# (name, url, method) — method 'api' = JSON endpoint whose 404 is authoritative;
# 'status' = HTML page where 404 means absent. Only entries verified to distinguish
# present/absent are listed; a platform that soft-404s is worse than no platform.
PLATFORMS = [
    ("github",      "https://api.github.com/users/{u}",                 "api"),
    ("gitlab",      "https://gitlab.com/api/v4/users?username={u}",     "api_list"),
    ("keybase",     "https://keybase.io/_/api/1.0/user/lookup.json?username={u}", "keybase"),
    ("npm",         "https://registry.npmjs.org/-/user/org.couchdb.user:{u}", "api"),
    ("hackernews",  "https://hacker-news.firebaseio.com/v0/user/{u}.json", "hn"),
    ("telegram",    "https://t.me/{u}",                                 "telegram"),
    ("dev.to",      "https://dev.to/{u}",                               "status"),
    # Removed after testing, NOT for brevity: pypi returns 200 and replit 302 for ANY handle, and
    # medium blocks the request outright — none can tell present from absent. A detector that
    # always answers "present" is worse than no detector: it manufactures a link that isn't there.
]

VALID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _fetch(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def check(name, tmpl, method, user):
    url = tmpl.format(u=urllib.parse.quote(user))
    code, body = _fetch(url)
    if code is None:
        return {"platform": name, "exists": None, "url": url, "note": f"unreachable ({body})"}
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
        ex = code == 200 and ("tgme_page_title" in body or "tgme_page_extra" in body)
    else:
        ex = code == 200
    return {"platform": name, "exists": ex, "url": url, "http": code}


def main():
    import urllib.parse as _up  # noqa: F401  (quote used above)
    ap = argparse.ArgumentParser(description="Check handle presence across curated platforms.")
    ap.add_argument("username")
    ap.add_argument("--platforms", help="comma-separated subset")
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda p: check(p[0], p[1], p[2], u), sel))

    found = [r for r in rows if r.get("exists") is True]
    unknown = [r for r in rows if r.get("exists") is None]
    out = {
        "username": u,
        "results": rows,
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
    import urllib.parse
    sys.exit(main())
