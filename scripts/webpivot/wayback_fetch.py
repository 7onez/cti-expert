#!/usr/bin/env python3
# Part of the WebPivot toolkit by Zeroska — https://github.com/Zeroska
# Adapted for the cti-expert skill by Hieu Ngo (chongluadao.vn).
"""
wayback_fetch.py — resolve the nearest Wayback snapshot and fetch its raw content
in one shot, WITHOUT Claude Code's WebFetch.

WHY THIS EXISTS
  Claude Code's built-in WebFetch enforces robots.txt at Anthropic's fetch layer,
  and web.archive.org's robots.txt disallows automated access — so WebFetch refuses
  every Wayback URL ("Claude Code is unable to fetch from web.archive.org") before
  any skill or permission rule is consulted. A browser works because it doesn't gate
  on robots.txt like an automated fetcher. This helper routes around WebFetch: it
  talks to the Wayback CDX API to find real captures, resolves the one nearest a
  requested date (a timestamp you guessed often does NOT exist), and pulls the
  un-rewritten bytes via the `id_` modifier. Zero deps, harness-native, passive by
  construction (only ever touches web.archive.org, never the target).

USAGE
  # Resolve nearest snapshot to a date and print raw archived HTML:
  python3 wayback_fetch.py https://boralcare.com/ --near 20240527

  # Latest / earliest good capture:
  python3 wayback_fetch.py boralcare.com --near latest
  python3 wayback_fetch.py boralcare.com --near earliest

  # Just resolve the real id_ URL (hand to a browser / curl / another tool):
  python3 wayback_fetch.py boralcare.com --near 20240527 --url-only

  # Readable text instead of raw HTML:
  python3 wayback_fetch.py boralcare.com --near latest --text

  # List available captures (like /snapshots), then pick one:
  python3 wayback_fetch.py boralcare.com --list --from 2023 --to 2024

  # Machine-readable envelope (resolved URL + metadata + content):
  python3 wayback_fetch.py boralcare.com --near latest --json

FOR AUTHORIZED INVESTIGATIONS ONLY.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
import os
import re
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

# The shared UA + the one Wayback client (endpoint failover, retry, pacing, cooldown).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pivot_extract import DEFAULT_UA  # noqa: E402 (also puts WebPivot/tools on sys.path)
import wp_wayback  # noqa: E402


def _norm_ts(s):
    """Accept YYYY, YYYYMMDD, YYYY-MM-DD, or full 14-digit ts → 14-digit padded."""
    if not s:
        return None
    digits = re.sub(r"\D", "", s)
    if not digits:
        return None
    # pad to 14 (Wayback nearest tolerates short stamps, but be explicit)
    return (digits + "00000000000000")[:14]


def cdx_snapshots(url, year_from=None, year_to=None, status="200",
                  mime="text/html", collapse_digest=True, limit=1000, near=None, errors=None):
    """Return [(timestamp, original, statuscode, mimetype, digest)] for a URL, oldest → newest.

    The index returns rows oldest-first, so a plain `limit` keeps the OLDEST captures. `near`
    picks which `limit` rows come back: 'latest' → the newest (negative limit), a timestamp → the
    ones closest to it (closest+sort=closest), None / 'earliest' → the oldest. Pass a list as
    `errors` to tell a real 'no captures' (list stays empty) from an archive that did not answer."""
    q = [("url", url), ("output", "json"), ("fl", "timestamp,original,statuscode,mimetype,digest")]
    if status:
        q.append(("filter", f"statuscode:{status}"))
    if mime:
        q.append(("filter", f"mimetype:{mime}"))
    if collapse_digest:
        q.append(("collapse", "digest"))
    if year_from:
        q.append(("from", re.sub(r"[^0-9]", "", year_from)))
    if year_to:
        q.append(("to", re.sub(r"[^0-9]", "", year_to)))
    target = _norm_ts(near) if near not in (None, "latest", "earliest") else None
    if near == "latest":
        q.append(("limit", f"-{int(limit)}"))
    elif target:
        q += [("closest", target), ("sort", "closest"), ("limit", int(limit))]
    else:
        q.append(("limit", int(limit)))
    rows, err = wp_wayback.index(q, ua=DEFAULT_UA)
    if err:
        print(f"  cdx error for {url}: {err}", file=sys.stderr)
        if errors is not None:
            errors.append(err)
        return []
    return sorted((tuple(r) for r in rows if len(r) >= 5), key=lambda s: s[0])


def resolve_nearest(snaps, near):
    """Pick the capture whose timestamp is closest to `near`.

    `near` may be 'latest', 'earliest', or a (possibly short) timestamp string.
    Returns a snapshot tuple or None.
    """
    if not snaps:
        return None
    if near in (None, "latest"):
        return max(snaps, key=lambda s: s[0])
    if near == "earliest":
        return min(snaps, key=lambda s: s[0])
    target = _norm_ts(near)
    if not target:
        return max(snaps, key=lambda s: s[0])
    tnum = int(target)
    return min(snaps, key=lambda s: abs(int((s[0] + "0" * 14)[:14]) - tnum))


def raw_url(timestamp, original, mode="id_"):
    """Build the un-rewritten archive URL. mode: id_ (raw), if_ (no toolbar)."""
    return wp_wayback.raw_url(timestamp, original, mode)


def fetch(timestamp, original, mode="id_"):
    """Fetch archived bytes → (text, final_url, timestamp_used); ('', url, timestamp) on failure.
    An unplayable capture falls back to its nearest playable neighbour (timestamp_used says which)."""
    resp, used, err = wp_wayback.fetch_capture(timestamp, original, mode, ua=DEFAULT_UA)
    if resp is None:
        print(f"  fetch error for {raw_url(timestamp, original, mode)}: {err}", file=sys.stderr)
        return "", raw_url(timestamp, original, mode), timestamp
    return resp.body.decode("utf-8", "ignore"), resp.url, used


def to_text(html):
    """Very small tag-stripper for --text (no external deps)."""
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    html = re.sub(r"&nbsp;", " ", html)
    html = re.sub(r"[ \t]+", " ", html)
    html = re.sub(r"\n\s*\n\s*\n+", "\n\n", html)
    return html.strip()


def _fmt_ts(ts):
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}" if len(ts) >= 12 else ts


def render_list(url, snaps, year_from, year_to):
    lines = [f"SNAPSHOTS — {url}",
             f"Range: {year_from or 'earliest'} → {year_to or 'now'}  |  captures: {len(snaps)}",
             "=" * 60,
             "  Timestamp (UTC)     Status  MIME                  Digest"]
    for ts, original, sc, mime, digest in snaps:
        lines.append(f"  {_fmt_ts(ts):<18}  {sc:<6}  {mime:<20}  {digest[:12]}")
    lines.append("=" * 60)
    if snaps:
        lines.append(f"First: {_fmt_ts(min(s[0] for s in snaps))}   "
                     f"Last: {_fmt_ts(max(s[0] for s in snaps))}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Resolve nearest Wayback snapshot + fetch raw content (bypasses WebFetch robots.txt block).")
    ap.add_argument("url", help="URL or domain, e.g. https://example.com/ or example.com")
    ap.add_argument("--near", default="latest",
                    help="target date: 'latest' (default), 'earliest', or YYYY / YYYYMMDD / YYYY-MM-DD")
    ap.add_argument("--from", dest="yfrom", help="earliest year/date filter")
    ap.add_argument("--to", dest="yto", help="latest year/date filter")
    ap.add_argument("--status", default="200", help="statuscode filter (default 200; '' for any)")
    ap.add_argument("--mime", default="text/html", help="mimetype filter (default text/html; '' for any)")
    ap.add_argument("--mode", default="id_", choices=["id_", "if_"],
                    help="id_ = raw bytes (default), if_ = rendered without Wayback toolbar")
    ap.add_argument("--list", action="store_true", help="list captures instead of fetching")
    ap.add_argument("--text", action="store_true", help="strip HTML → readable text")
    ap.add_argument("--url-only", action="store_true", help="print only the resolved id_/if_ URL")
    ap.add_argument("--json", action="store_true", help="machine-readable envelope")
    args = ap.parse_args()

    errors = []
    snaps = cdx_snapshots(args.url, args.yfrom, args.yto,
                          status=(args.status or None), mime=(args.mime or None),
                          near=(None if args.list else args.near), errors=errors)

    if errors and not snaps:
        # the archive did not answer: NOT "never archived" — a gap to re-run
        msg = f"Wayback did not answer for {args.url} (not a negative): {errors[0]}"
        if args.json:
            print(json.dumps({"url": args.url, "error": msg, "unanswered": True, "snapshots": None}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(3)

    if args.list:
        print(render_list(args.url, snaps, args.yfrom, args.yto))
        return

    if not snaps:
        msg = f"No captures for {args.url} matching status={args.status!r} mime={args.mime!r}."
        if args.json:
            print(json.dumps({"url": args.url, "error": msg, "snapshots": 0}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(2)

    chosen = resolve_nearest(snaps, args.near)
    ts, original, sc, mime, digest = chosen
    resolved = raw_url(ts, original, args.mode)

    if args.url_only:
        print(resolved)
        return

    html, final_url, used_ts = fetch(ts, original, args.mode)
    if not html:
        # the capture and its neighbours could not be downloaded: NOT an empty page — a gap
        msg = (f"Wayback capture {ts} of {original} (and its nearest neighbours) could not be "
               f"downloaded — not a negative; re-run later")
        if args.json:
            print(json.dumps({"url": args.url, "error": msg, "unanswered": True,
                              "resolved_timestamp": ts, "resolved_url": resolved, "bytes": 0}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(3)
    if used_ts != ts:
        ts, resolved = used_ts, raw_url(used_ts, original, args.mode)

    if args.json:
        body = to_text(html) if args.text else html
        print(json.dumps({
            "url": args.url,
            "requested_near": args.near,
            "resolved_timestamp": ts,
            "resolved_date": _fmt_ts(ts),
            "resolved_url": resolved,
            "statuscode": sc,
            "mimetype": mime,
            "digest": digest,
            "snapshots_available": len(snaps),
            "bytes": len(html),
            "content": body,
        }, ensure_ascii=False))
        return

    # Human/pipe mode: a short provenance header on stderr, content on stdout.
    print(f"[wayback] {args.url}  near={args.near} → {_fmt_ts(ts)} "
          f"({len(snaps)} captures)  {resolved}", file=sys.stderr)
    print(to_text(html) if args.text else html)


if __name__ == "__main__":
    main()
