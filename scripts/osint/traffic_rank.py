#!/usr/bin/env python3
"""traffic_rank.py — popularity rank for a domain, and what a rank actually tells you.

Backs /traffic. SKILL.md promised "traffic estimation, ranking, audience data". Estimation and
audience demographics come only from paid panels (SimilarWeb, Semrush) and their numbers for
low-traffic domains are modelled guesses, not measurements — reporting them as fact about a scam
site would be inventing evidence. So this returns the one figure that is free and real: the Tranco
rank, a research list aggregating several popularity sources.

THE ANALYTIC POINT IS USUALLY THE ABSENCE. A funnel domain that has been "operating for years"
according to its own copy, and is unranked in a 1M-entry list, is contradicting itself. That
inference is what this supports.

Keyless. Passive — Tranco is queried, never the target.

Usage:
  traffic_rank.py example.com
  traffic_rank.py a.example b.example --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "cti-expert/traffic_rank (OSINT research)"


def _get(url, timeout=20):
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def tranco(domain):
    d, err = _get("https://tranco-list.eu/api/ranks/domain/" + urllib.parse.quote(domain))
    if err or d is None:
        return {"status": f"unavailable ({err})"}
    ranks = d.get("ranks") or []
    if not ranks:
        return {"status": "ok", "ranked": False, "latest_rank": None,
                "meaning": ("not in the Tranco list. The list covers roughly the top 1M domains, "
                            "so this means low or no measurable popularity — NOT that the domain "
                            "is malicious, and not that it has no visitors.")}
    latest = ranks[0]
    hist = [{"date": r.get("date"), "rank": r.get("rank")} for r in ranks[:10]]
    return {"status": "ok", "ranked": True, "latest_rank": latest.get("rank"),
            "latest_date": latest.get("date"), "history": hist,
            "meaning": "present in the Tranco top-1M; lower number = more popular"}


def main():
    ap = argparse.ArgumentParser(description="Free popularity rank (Tranco) for a domain.")
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    rows = []
    for raw in a.domains:
        dom = raw.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        t = tranco(dom)
        rows.append({"domain": dom, "tranco": t})
        if t.get("status") != "ok":
            print(f"{dom}: rank UNAVAILABLE ({t['status']}) — absence of collection", file=sys.stderr)
        elif t.get("ranked"):
            print(f"{dom}: Tranco #{t['latest_rank']} ({t['latest_date']})", file=sys.stderr)
        else:
            print(f"{dom}: UNRANKED in the Tranco top-1M", file=sys.stderr)

    out = {"results": rows,
           "not_collected": {
               "traffic_estimate": "paid panels only (SimilarWeb/Semrush); their low-traffic "
                                   "figures are modelled, not measured — not reported here",
               "audience_demographics": "paid panels only; same reason"}}
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
