#!/usr/bin/env python3
"""ct_monitor — near-real-time Certificate Transparency monitor (zero-dependency).

A poll-based stand-in for certstream: certstream is a websocket firehose (needs a
websocket client library), which breaks the WebPivot "core needs nothing beyond the
Python 3 stdlib" contract. Instead we POLL Certificate Transparency through the shared wp_ct
client (crt.sh → PostgreSQL → keyless backups for a domain; crt.sh LIKE for a keyword),
remember which certs we've already seen in a state file, and on
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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wp_ct  # noqa: E402 — the one CT client (loads the skill .env, installs cti-proxy)


def _identities(cert):
    """Every identity a cert can be recognised by across sources and runs. The bare crt.sh id is
    kept unprefixed so state files written before the shared client still match."""
    keys = []
    if cert.get("crtsh_id"):
        keys.append(str(cert["crtsh_id"]))
    if cert.get("serial"):
        keys.append("serial:" + cert["serial"])
    if cert.get("sha256"):
        keys.append("sha256:" + cert["sha256"])
    return keys or [str(cert.get("id"))]


def poll(pattern: str):
    """One pattern → (certs, status, completeness_line, sources). A dotted value without '%' is a
    DOMAIN (full fallback chain); anything else is a crt.sh LIKE keyword ('%kw%'), web only."""
    if "." in pattern and "%" not in pattern:
        r = wp_ct.ct_search(pattern.strip(".").lower(), max_certs=None, max_subdomains=None)
        crt = r["ct_status"].get("crt.sh", {}).get("status")
        return r["certs"], crt, r["completeness_line"], r.get("sources") or []
    q = pattern if "%" in pattern else f"%{pattern}%"
    r = wp_ct.crtsh_keyword(q)
    line = ("crt.sh unreachable — keyword poll incomplete" if r["status"] == "degraded"
            else "crt.sh keyword search")
    return r["rows"], r["status"], line, ["crt.sh"] if r["status"] != "degraded" else []


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
    """Poll each pattern; return (new_certs, baselined) where new_certs excludes those already
    seen. A pattern's first-ever run baselines and does NOT alert — but never on a degraded crt.sh:
    a partial baseline would make the certs it missed alert as "new" once crt.sh is back. A later
    degraded run still alerts on (and records) what the backups saw; a cert nobody saw stays unseen
    and alerts when crt.sh returns."""
    state = load_state(state_path)
    new_certs, baselined = [], []
    for pat in patterns:
        seen = set(state.get(pat, []))
        certs, crt_status, line, sources = poll(pat)
        first_run = pat not in state
        if crt_status == "degraded":
            print(f"[!] {pat}: {line}", file=sys.stderr)
            if first_run:
                print(f"[!] {pat}: baseline postponed until crt.sh answers", file=sys.stderr)
                continue
        fresh = [c for c in certs if not any(k in seen for k in _identities(c))]
        # keep the most recent 5000 ids per pattern so state doesn't grow unbounded
        state[pat] = sorted(seen | {k for c in certs for k in _identities(c)})[-5000:]
        if first_run:
            baselined.append((pat, len(certs)))
        else:
            for c in fresh:
                new_certs.append({"pattern": pat, "source": "+".join(c.get("sources") or sources),
                                  "id": c.get("id"), "names": [n.lstrip("*.") for n in c["names"]],
                                  "not_before": c.get("not_before"), "issuer": c.get("issuer") or "",
                                  "ct_status": crt_status})
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
        print(f"  • [{c['pattern']}] {c['source']} {c['id']}  {c.get('not_before') or ''}  {c.get('issuer','')[:48]}")
        for n in c["names"]:
            print(f"      SAN: {n}")
            seeds.add(n)
    print("\n[+] new seed domains (feed to pivot_extract / intel.py):")
    for s in sorted(seeds):
        print(f"  {s}")


if __name__ == "__main__":
    main()
