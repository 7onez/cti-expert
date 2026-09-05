#!/usr/bin/env python3
"""subdomain_enum.py — enumerate a domain's subdomains from independent public sources.

MULTI-SOURCE ON PURPOSE. crt.sh is the name everyone reaches for and it is down or 502-ing a
large fraction of the time (it was unreachable while this was written). A tool that queries only
crt.sh reports "no subdomains" when the truth is "the source was down" — an absence of collection
presented as a fact about the target, which is the single most expensive error this toolkit can
make. Every source's status is returned, and a result with dead sources says so.

Sources, all keyless: Certificate Transparency via certspotter (primary — reliable, JSON API),
hackertarget hostsearch (passive DNS, rate-limited but honest), crt.sh (fallback when it is up).

Flags admin / sensitive labels on the way out — `admin`, `adm`, `panel`, `kef`, `ador`, `backend`,
`api`, `staging`, `dev` — because on a fraud estate those are the hosts that carry the operator's
own back-office rather than the victim-facing funnel.

PASSIVE: every query goes to a third-party index. No DNS brute force, nothing touches the target.

Usage:
  subdomain_enum.py example.com
  subdomain_enum.py example.com --sensitive-only --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "cti-expert/subdomain_enum (OSINT research)"

# Leftmost labels that mark an operator-facing host. `kef` / `ador` are CJK back-office
# conventions (客服 = customer service) seen across SEA/PRC scam estates.
SENSITIVE = {"admin", "adm", "administrator", "panel", "cp", "cpanel", "manage", "manager",
             "backend", "back", "bo", "kef", "kefu", "ador", "agent", "staff", "internal",
             "staging", "stage", "dev", "test", "uat", "api", "vpn", "mail", "webmail",
             "ftp", "db", "sql", "phpmyadmin", "pma", "git", "jenkins", "grafana", "kibana"}


def _get(url, timeout=25, as_json=True):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        return (json.loads(raw) if as_json else raw), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def src_certspotter(domain):
    url = ("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(domain)
           + "&include_subdomains=true&expand=dns_names")
    d, err = _get(url)
    if err or d is None:
        return set(), f"unavailable ({err})"
    names = set()
    for row in d if isinstance(d, list) else []:
        for n in row.get("dns_names") or []:
            names.add(n.lower().lstrip("*."))
    return names, "ok"


def src_hackertarget(domain):
    d, err = _get("https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain),
                  as_json=False)
    if err or not d:
        return set(), f"unavailable ({err})"
    if "error" in d.lower() or "api count exceeded" in d.lower():
        return set(), "rate-limited"
    names = {ln.split(",", 1)[0].strip().lower() for ln in d.splitlines() if "," in ln}
    return {n for n in names if n}, "ok"


def src_crtsh(domain):
    d, err = _get("https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json")
    if err or d is None:
        return set(), f"unavailable ({err})"
    names = set()
    for row in d if isinstance(d, list) else []:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n:
                names.add(n)
    return names, "ok"


SOURCES = [("certspotter", src_certspotter), ("hackertarget", src_hackertarget),
           ("crtsh", src_crtsh)]


def main():
    ap = argparse.ArgumentParser(description="Passive subdomain enumeration, multi-source.")
    ap.add_argument("domain")
    ap.add_argument("--sensitive-only", action="store_true")
    ap.add_argument("--sources", help="comma-separated subset of: "
                                      + ", ".join(n for n, _ in SOURCES))
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    dom = a.domain.strip().lower().lstrip("*.").replace("https://", "").replace("http://", "")
    dom = dom.split("/")[0]
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", dom):
        ap.error(f"not a domain: {dom!r}")

    use = SOURCES
    if a.sources:
        want = {s.strip().lower() for s in a.sources.split(",")}
        use = [s for s in SOURCES if s[0] in want] or SOURCES

    all_names, status = set(), {}
    for name, fn in use:
        got, st = fn(dom)
        status[name] = {"status": st, "found": len(got)}
        all_names |= got

    # keep only names actually under the queried apex
    subs = sorted(n for n in all_names if n == dom or n.endswith("." + dom))
    flagged = []
    for s in subs:
        label = s[: -(len(dom) + 1)] if s != dom else ""
        first = label.split(".")[-1] if label else ""
        if first in SENSITIVE or any(p in first for p in ("admin", "panel", "kef")):
            flagged.append({"host": s, "label": first,
                            "why": "leftmost label marks an operator/back-office host"})

    live = [n for n, v in status.items() if v["status"] == "ok"]
    dead = [n for n, v in status.items() if v["status"] != "ok"]
    out = {"domain": dom, "subdomains": flagged if a.sensitive_only else subs,
           "count": len(subs), "sensitive": flagged, "sources": status,
           "sources_ok": live, "sources_unavailable": dead}
    if not live:
        out["verdict"] = ("NO SOURCE ANSWERED — this is an absence of COLLECTION, not evidence "
                          "the domain has no subdomains. Re-run, or query a keyed source.")
    elif not subs:
        out["verdict"] = (f"{len(live)} source(s) answered and hold no subdomain for this apex. "
                          f"Freshly-registered infrastructure is routinely absent from CT and "
                          f"passive DNS for days.")
    else:
        out["verdict"] = f"{len(subs)} subdomain(s) from {len(live)} source(s)"
    if dead:
        out["collection_gap"] = f"source(s) unavailable: {', '.join(dead)} — coverage is partial"

    srcline = ", ".join("%s=%s" % (k, v["status"]) for k, v in status.items())
    print(f"{dom}: {len(subs)} subdomain(s), {len(flagged)} sensitive  [{srcline}]",
          file=sys.stderr)
    for f in flagged[:10]:
        print(f"  ⚠ {f['host']}  ({f['label']})", file=sys.stderr)
    if dead:
        print(f"  collection gap: {', '.join(dead)} unavailable", file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
