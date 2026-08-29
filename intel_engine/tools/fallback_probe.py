#!/usr/bin/env python3
"""Last-resort pivot probe — run when the primary enrichment (WHOIS + FOFA + urlscan)
comes back EMPTY on a domain (parked page, empty favicon hash, NXDOMAIN, brand-new NRD).

The point is to never end a seed on a silent "nothing found". Instead we sweep the
keyless, always-available corners that survive a dead/parked front page:

  1. crt.sh        — CT/SSL certs. A cert whose SAN list covers OTHER domains is the
                     single strongest operator link there is (issued together = same owner).
                     When crt.sh + Shodan CTL both come up empty, falls back to the keyless
                     AGGREGATED indexes crt.name + agniops (names only, not CT-attributable).
  2. Wayback CDX   — the full capture TIMELINE, not just today. Parked-today is routinely
                     a domain that served a live scam last year — the history is the pivot.
  3. archive.is    — the mirror analysts use when Wayback has nothing (operators often
                     evade web.archive.org but get caught by archive.today).
  4. Search dorks  — ready-to-run Google/Bing queries (automated SERP scraping is bot-walled;
                     WebPivot's contract is to hand back runnable queries, so we do that).
  5. Local KB      — is any part of this domain ALREADY known/attributed? A hit here means
                     "don't re-investigate, show the prior verdict".

Then it renders a VERDICT: PIVOTABLE (a lead survived) or NO-PIVOT-YET (genuinely cold —
here are the explicit next moves). Keyless throughout, so it works even when the paid
APIs are out of credits.

Usage:
  python3 tools/fallback_probe.py example.com --kb knowledge [--json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _host(s: str) -> str:
    s = s.strip()
    if "://" in s:
        s = urllib.parse.urlparse(s).hostname or s
    return s.split("/")[0].lower()


def _get(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def _ct_hostlist(url: str, domain: str) -> set:
    """Fetch a keyless AGGREGATED subdomain index that replies with a plaintext,
    newline-delimited host list (crt.name, agniops). Returns in-scope hosts only,
    lowercased, apex excluded. Stdlib-only; never raises."""
    out: set = set()
    try:
        body = _get(url, timeout=20).strip()
    except Exception:
        return out
    if not body or body[0] == "<":            # empty or an HTML error page, not a host list
        return out
    dom = domain.lower()
    for line in body.splitlines():
        name = line.strip().lower().lstrip("*.")   # tolerate '*.' / leading-'.' artifacts
        if not name or " " in name or "@" in name:
            continue
        if name != dom and not name.endswith("." + dom):   # in-scope hosts only
            continue
        if name != dom:
            out.add(name)
    return out


# ------------------------------------------------------------------ 1. CT logs
def _reg(name: str) -> str:
    return ".".join(name.split(".")[-2:])


def crtsh(domain: str) -> dict:
    """CT certs for the domain, from TWO keyless CT indexes merged — crt.sh and Shodan's
    CTL mirror (ctl.shodan.io) of the same DB. crt.sh alone 502s often; Shodan covers the
    gap. The prize is SAN-sibling domains: a single cert covering this domain AND an
    unrelated-looking one binds them to one owner. If BOTH CT indexes yield no names, sweeps
    the keyless AGGREGATED indexes crt.name + agniops as a last resort — their hits are NOT
    CT-log-attributable (returned under `aggregated_subdomains`, tagged, verify before use)."""
    subs, siblings, issuers, cert_n, srcs = set(), set(), set(), 0, []

    def _sort_name(name: str):
        name = name.strip().lower().lstrip("*.")
        if not name or "@" in name:
            return
        # Group by REGISTRABLE domain, not a bare endswith: `fakesite.com`.endswith("site.com")
        # is True yet it's a different owner — an unanchored test buried the strongest pivot
        # (a SAN sibling) in the subdomain bucket. Match cert_overlap's _reg-based comparison.
        if _reg(name) == _reg(domain):
            subs.add(name)
        else:
            siblings.add(name)          # a DIFFERENT registrable domain on the same cert


    # (a) crt.sh — ?q= 502s a lot; ?identity= is steadier
    rows = []
    for q in (f"%.{domain}", domain):
        for param in ("q", "identity"):
            try:
                data = json.loads(_get("https://crt.sh/?" + urllib.parse.urlencode(
                    {param: q, "output": "json"})))
                if isinstance(data, list):
                    rows.extend(data)
                    break
            except Exception:
                continue
    if rows:
        srcs.append("crt.sh")
        cert_n += len(rows)
        for row in rows:
            issuers.add(str(row.get("issuer_name", ""))[:60])
            for name in str(row.get("name_value", "")).splitlines():
                _sort_name(name)

    # (b) Shodan CTL mirror — flat hostnames + cert objects (san_dns_names, issuer_cn)
    base = f"https://ctl.shodan.io/api/v1/domain/{urllib.parse.quote(domain)}"
    try:
        for name in json.loads(_get(base + "/hostnames", timeout=20)):
            _sort_name(str(name))
        srcs.append("shodan-ctl")
    except Exception:
        pass
    try:
        certs = json.loads(_get(base, timeout=20))
        cert_n += len(certs)
        if "shodan-ctl" not in srcs:
            srcs.append("shodan-ctl")
        for row in certs:
            issuers.add(str(row.get("issuer_cn", ""))[:60])
            _sort_name(str(row.get("subject_cn", "")))
            for n in (row.get("san_dns_names") or []):
                _sort_name(str(n))
    except Exception:
        pass

    # (c) AGGREGATED fallback — only when the CT logs yielded NO names (both peers down or
    # empty). crt.name (CT + Common Crawl/CZDS/Chaos/HaGeZi) and agniops are keyless
    # aggregated indexes: NOT CT-log-attributable, so they are tagged and ranked below crt.sh,
    # and querying them discloses the apex to a third-party operator — hence gated to the
    # cold case where they are the difference between a lead and a silent "nothing found".
    agg_subs, agg_srcs = set(), []
    if not subs and not siblings:
        for label, url in (
            ("crt.name(aggregated)",
             "https://crt.name/v1/search?" + urllib.parse.urlencode({"apex": domain})),
            ("agniops(aggregated)",
             "https://app.agniops.in/v1/search?" + urllib.parse.urlencode({"domain": domain})),
        ):
            hits = _ct_hostlist(url, domain)
            if hits:
                agg_subs |= hits
                agg_srcs.append(label)

    if not srcs and not agg_srcs:
        return {"ok": False,
                "error": "no CT/subdomain source reachable (crt.sh + shodan-ctl + crt.name + agniops all failed)"}
    out = {"ok": True, "sources": srcs, "certs": cert_n, "subdomains": sorted(subs)[:40],
           "san_siblings": sorted(siblings)[:40], "issuers": sorted(i for i in issuers if i)[:8]}
    if agg_srcs:
        out["aggregated_sources"] = agg_srcs
        out["aggregated_subdomains"] = sorted(agg_subs)[:80]
    return out


# ---------------------------------------------------------------- 2. Wayback CDX
def wayback(domain: str) -> dict:
    """Full capture timeline from the Wayback CDX API — first seen, last seen, count.
    A parked domain with 400 captures over 3 years had content worth pivoting on."""
    try:
        body = _get("http://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode({
            "url": domain, "matchType": "domain", "output": "json",
            "fl": "timestamp,original,statuscode", "collapse": "timestamp:6", "limit": "500"}))
        rows = json.loads(body)
    except Exception as e:
        return {"ok": False, "error": f"wayback CDX: {e}"}
    rows = rows[1:] if rows and rows[0] and rows[0][0] == "timestamp" else rows
    if not rows:
        return {"ok": True, "captures": 0, "note": "never archived"}
    stamps = sorted(r[0] for r in rows if r and r[0])
    def fmt(ts): return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return {"ok": True, "captures": len(rows), "first": fmt(stamps[0]), "last": fmt(stamps[-1]),
            "sample": [f"http://web.archive.org/web/{r[0]}/{r[1]}" for r in rows[:3]]}


# ------------------------------------------------------------------ 3. archive.is
def archive_is(domain: str) -> dict:
    """archive.today mirror — the fallback when Wayback is empty. TimeMap is a plain
    link list; presence of any memento = a stored copy to pull the DOM from."""
    for base in ("https://archive.ph", "https://archive.is"):
        try:
            body = _get(f"{base}/timemap/https://{domain}", timeout=20)
            mementos = [ln for ln in body.splitlines() if "rel=\"memento\"" in ln or "/http" in ln]
            if mementos:
                return {"ok": True, "mementos": len(mementos), "newest": f"{base}/newest/https://{domain}"}
        except Exception:
            continue
    return {"ok": True, "mementos": 0, "note": "no archive.today capture"}


# --------------------------------------------------------------------- 4. dorks
def dorks(domain: str) -> list[str]:
    """Ready-to-run search-engine queries. We do NOT scrape SERPs (bot-walled); WebPivot's
    contract is runnable pivot queries, so the analyst (or the model's own web search) fires these."""
    d = domain
    return [
        f'site:{d}',
        f'"{d}" -site:{d}',                       # who links to / mentions it off-site
        f'intext:"{d}" (scam OR phishing OR fake OR fraud OR lừa đảo)',
        f'"{d}" (telegram OR zalo OR whatsapp OR t.me)',
        f'site:pastebin.com OR site:github.com "{d}"',
        f'related:{d}',
    ]


# ----------------------------------------------------------------------- 5. KB
def kb_lookup(domain: str, kb_dir: str) -> dict:
    """Is this already in our own store? A hit = prior verdict, don't re-investigate."""
    def run(cmd):
        try:
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
            return (r.stdout or "").strip()
        except Exception as e:
            return f"(error: {e})"
    ent = run([sys.executable, os.path.join("tools", "kb", "query.py"),
               "--kb", kb_dir, "--entity", domain])
    op = run([sys.executable, os.path.join("tools", "kb", "operator_registry.py"), "find", domain])
    known = bool(ent) and "no record" not in ent.lower() and "not found" not in ent.lower()
    attributed = bool(op) and "not attributed" not in op.lower()
    return {"known": known, "attributed": attributed,
            "operator": op[:400] if attributed else None,
            "kb_facts": ent[:600] if known else None}


def probe(domain: str, kb_dir: str) -> dict:
    domain = _host(domain)
    # crt.sh / wayback / archive.is are independent network I/O — run them concurrently.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        f = {"crtsh": ex.submit(crtsh, domain),
             "wayback": ex.submit(wayback, domain),
             "archive_is": ex.submit(archive_is, domain)}
        res = {k: v.result() for k, v in f.items()}
    res["dorks"] = dorks(domain)
    res["kb"] = kb_lookup(domain, kb_dir)

    # ---- verdict: did ANY corner survive? ----
    leads = []
    if res["crtsh"].get("san_siblings"):
        leads.append(f"crt.sh: {len(res['crtsh']['san_siblings'])} SAN-sibling domain(s) — "
                     "strong same-owner link, pivot these first")
    elif res["crtsh"].get("subdomains"):
        leads.append(f"crt.sh: {len(res['crtsh']['subdomains'])} subdomain(s) on cert")
    elif res["crtsh"].get("aggregated_subdomains"):
        leads.append(f"{'+'.join(res['crtsh'].get('aggregated_sources', ['aggregated']))}: "
                     f"{len(res['crtsh']['aggregated_subdomains'])} AGGREGATED subdomain(s) — "
                     "not CT-log-attributable, verify before pivoting")
    if res["wayback"].get("captures"):
        leads.append(f"wayback: {res['wayback']['captures']} captures "
                     f"{res['wayback'].get('first')}→{res['wayback'].get('last')} — pull an old DOM")
    if res["archive_is"].get("mementos"):
        leads.append(f"archive.is: {res['archive_is']['mementos']} memento(s)")
    if res["kb"].get("attributed"):
        leads.append("KB: ALREADY ATTRIBUTED — show the prior verdict, do not re-investigate")
    elif res["kb"].get("known"):
        leads.append("KB: indicator(s) already on file — check the existing cluster")

    if leads:
        res["verdict"] = "PIVOTABLE"
        res["leads"] = leads
    else:
        res["verdict"] = "NO-PIVOT-YET"
        res["leads"] = []
        res["next_steps"] = [
            "Front page is cold AND every keyless corner is empty — likely a fresh NRD not yet weaponized.",
            "Re-run fallback_probe after a few days (certs/archives lag first live use).",
            "Run the emitted search dorks manually / via web search for off-site mentions.",
            "If a registrant email/name leaked in partial WHOIS, reverse-WHOIS it in the correlate phase.",
        ]
    return {"domain": domain, **res}


def _human(r: dict) -> str:
    out = [f"FALLBACK PROBE · {r['domain']} · VERDICT: {r['verdict']}"]
    c = r["crtsh"]
    out.append(f"  CT logs    : {'%d certs, %d subdomains, %d SAN-siblings  [%s]' % (c.get('certs',0), len(c.get('subdomains',[])), len(c.get('san_siblings',[])), '+'.join(c.get('sources',[]))) if c.get('ok') else c.get('error')}")
    if c.get("san_siblings"):
        out.append("     └ SAN-siblings (same-owner pivot): " + ", ".join(c["san_siblings"][:10]))
    if c.get("aggregated_subdomains"):
        out.append(f"     └ aggregated subdomains ({'+'.join(c.get('aggregated_sources', []))}, verify before pivoting): "
                   + ", ".join(c["aggregated_subdomains"][:10]))
    w = r["wayback"]
    out.append(f"  wayback    : {('%d captures %s→%s' % (w.get('captures',0), w.get('first','?'), w.get('last','?'))) if w.get('captures') else w.get('note', w.get('error','—'))}")
    a = r["archive_is"]
    out.append(f"  archive.is : {('%d mementos → %s' % (a['mementos'], a.get('newest'))) if a.get('mementos') else a.get('note','—')}")
    k = r["kb"]
    out.append(f"  local KB   : {'ATTRIBUTED — '+ (k.get('operator') or '').splitlines()[0] if k.get('attributed') else ('known indicators on file' if k.get('known') else 'not in KB')}")
    out.append("  dorks      : " + " | ".join(r["dorks"][:3]) + " …")
    if r.get("leads"):
        out.append("  LEADS:")
        out += [f"    • {l}" for l in r["leads"]]
    if r.get("next_steps"):
        out.append("  NEXT:")
        out += [f"    • {s}" for s in r["next_steps"]]
    return "\n".join(out)


def _main() -> None:
    ap = argparse.ArgumentParser(description="last-resort keyless pivot probe for empty domains")
    ap.add_argument("domain")
    ap.add_argument("--kb", default=os.environ.get("HARNESS_KB", "knowledge"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = probe(a.domain, a.kb)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))


if __name__ == "__main__":
    _main()
