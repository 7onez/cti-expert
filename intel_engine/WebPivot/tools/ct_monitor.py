#!/usr/bin/env python3
"""ct_monitor — near-real-time Certificate Transparency monitor (zero-dependency).

A poll-based stand-in for certstream: certstream is a websocket firehose (needs a
websocket client library), which breaks the WebPivot "core needs nothing beyond the
Python 3 stdlib" contract. Instead we POLL Certificate Transparency via crt.sh (with a
Certspotter fallback), remember which certs we've already seen in a state file, and on
each run report only the NEWLY-ISSUED certs for a brand keyword or domain. Run it on a
loop or cron for continuous brand monitoring — the fresh SANs become new WebPivot seeds.

    # establish a baseline (first run never alerts), then poll on a schedule
    python3 tools/ct_monitor.py watch example-brand --state cases/<case>/ct_state.json
    python3 tools/ct_monitor.py watch -f brands.txt --state ct_state.json --json
    # a keyword matches substrings (crt.sh %kw%); a dotted value is treated as a domain
    watch -c '*/15 * * * *'  via cron, or:  while :; do python3 ct_monitor.py watch … ; sleep 900; done

New SANs printed by a run are ready to feed straight into pivot_extract / intel.py.
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

DEFAULT_UA = "Mozilla/5.0 (WebPivot ct_monitor)"


def _get_json(url: str, timeout: int = 45):
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def crtsh(pattern: str, timeout: int = 45):
    """crt.sh issuances for a domain or %keyword%. Returns (certs, error)."""
    q = pattern if any(c in pattern for c in "%.") else f"%{pattern}%"
    # keep the SQL-LIKE '%' wildcard literal — urlencoding it to %25 breaks keyword search
    url = f"https://crt.sh/?q={urllib.parse.quote(q, safe='%.*-_')}&output=json"
    try:
        data = _get_json(url, timeout)
    except Exception as e:
        return None, str(e)
    certs = []
    for row in data if isinstance(data, list) else []:
        names = sorted({n.strip().lstrip("*.").lower()
                        for n in str(row.get("name_value", "")).splitlines()
                        if n.strip() and "@" not in n})
        certs.append({"id": str(row.get("id")), "names": names,
                      "not_before": row.get("not_before"),
                      "issuer": row.get("issuer_name", "")})
    return certs, None


def certspotter(pattern: str, timeout: int = 45):
    """Certspotter fallback (domains only; crt.sh is frequently overloaded)."""
    if "%" in pattern:
        return None, "certspotter needs a domain, not a keyword"
    dom = pattern.strip(".%")
    url = ("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(dom)
           + "&include_subdomains=true&expand=dns_names&expand=not_before&expand=issuer")
    try:
        data = _get_json(url, timeout)
    except Exception as e:
        return None, str(e)
    certs = []
    for row in data if isinstance(data, list) else []:
        names = sorted({n.lstrip("*.").lower() for n in row.get("dns_names", [])})
        certs.append({"id": str(row.get("id")), "names": names,
                      "not_before": row.get("not_before"),
                      "issuer": (row.get("issuer") or {}).get("name", "")})
    return certs, None


def load_state(path: str) -> dict:
    if path and os.path.isfile(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(path: str, state: dict) -> None:
    if not path:
        return
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def watch(patterns, state_path):
    """Poll each pattern; return (new_certs, baselined) where new_certs excludes those
    already seen. On a pattern's first-ever run we baseline (record ids) and DON'T alert."""
    state = load_state(state_path)
    new_certs, baselined = [], []
    for pat in patterns:
        seen = set(state.get(pat, []))
        certs, err = crtsh(pat)
        source = "crt.sh"
        if certs is None:
            certs, err2 = certspotter(pat)
            source = "certspotter"
            if certs is None:
                print(f"[!] {pat}: both CT sources failed (crt.sh: {err}; certspotter: {err2})",
                      file=sys.stderr)
                continue
        first_run = pat not in state
        fresh = [c for c in certs if c["id"] not in seen]
        # keep the most recent 5000 ids per pattern so state doesn't grow unbounded
        state[pat] = sorted(set(seen) | {c["id"] for c in certs})[-5000:]
        if first_run:
            baselined.append((pat, len(certs)))
        else:
            for c in fresh:
                new_certs.append({"pattern": pat, "source": source, **c})
    save_state(state_path, state)
    return new_certs, baselined


def main():
    ap = argparse.ArgumentParser(description="Poll-based CT monitor (certstream alternative).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch", help="poll CT for new certs matching brand/domain patterns")
    w.add_argument("patterns", nargs="*", help="brand keyword(s) or domain(s)")
    w.add_argument("-f", "--file", help="file with one pattern per line")
    w.add_argument("--state", required=True, help="JSON state file (tracks seen cert ids)")
    w.add_argument("--json", action="store_true", help="emit new certs as JSON")
    a = ap.parse_args()

    patterns = list(a.patterns)
    if a.file and os.path.isfile(a.file):
        patterns += [ln.strip() for ln in open(a.file, encoding="utf-8")
                     if ln.strip() and not ln.startswith("#")]
    patterns = list(dict.fromkeys(patterns))
    if not patterns:
        sys.exit("no patterns given (positional or -f FILE)")

    new_certs, baselined = watch(patterns, a.state)

    for pat, n in baselined:
        print(f"[baseline] {pat}: recorded {n} existing cert(s) — will alert on new ones next run",
              file=sys.stderr)

    if a.json:
        print(json.dumps(new_certs, indent=2, ensure_ascii=False))
        return

    if not new_certs:
        print(f"[=] no new certificates ({len(patterns)} pattern(s) polled).")
        return

    seeds = set()
    print(f"[+] {len(new_certs)} NEW certificate(s):\n")
    for c in new_certs:
        print(f"  • [{c['pattern']}] crt id {c['id']}  {c.get('not_before','')}  {c.get('issuer','')[:48]}")
        for n in c["names"]:
            print(f"      SAN: {n}")
            seeds.add(n)
    print("\n[+] new seed domains (feed to pivot_extract / intel.py):")
    for s in sorted(seeds):
        print(f"  {s}")


if __name__ == "__main__":
    main()
