#!/usr/bin/env python3
"""Last-resort pivot probe — run when the primary enrichment (WHOIS + FOFA + urlscan)
comes back EMPTY on a domain (parked page, empty favicon hash, NXDOMAIN, brand-new NRD).

The point is to never end a seed on a silent "nothing found". Instead we sweep the
keyless, always-available corners that survive a dead/parked front page:

  1. CT logs       — certificate history through the shared client (wp_ct: crt.sh → PostgreSQL
                     → Shodan CTL + CertSpotter → AGGREGATED crt.name + agniops names last). A
                     cert whose SAN list covers OTHER domains is the single strongest operator
                     link there is (issued together = same owner).
  2. Wayback CDX   — the full capture TIMELINE, not just today. Parked-today is routinely
                     a domain that served a live scam last year — the history is the pivot.
  3. archive.is    — the mirror analysts use when Wayback has nothing (operators often
                     evade web.archive.org but get caught by archive.today).
  4. Search dorks  — ready-to-run Google/Bing queries (automated SERP scraping is bot-walled;
                     WebPivot's contract is to hand back runnable queries, so we do that).
  5. Local KB      — is any part of this domain ALREADY known/attributed? A hit here means
                     "don't re-investigate, show the prior verdict".

Then it renders a VERDICT: PIVOTABLE (a lead survived), NO-PIVOT-YET (genuinely cold — here are
the explicit next moves) or INCONCLUSIVE-CT-DEGRADED (cold, but crt.sh was unreachable or its leg
timed out, so the CT corner was not really swept). Keyless throughout, so it works even when the
paid APIs are out of credits.

Every leg runs under its OWN wall-clock bound (references/timeouts.json → fallback_probe_legs),
never the per-call ceiling: a leg that overruns is reported as {"timed_out": True} and listed in
`timed_out`, while the other legs' findings are returned as usual. (Seen live: an archive.today
TimeMap request that never answered held the whole probe — and its collect phase — for hours.)

Usage:
  python3 tools/fallback_probe.py example.com --kb knowledge [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Per-call ceiling — ONE resolver (WebPivot/tools/wp_timeouts: env CTI_CALL_TIMEOUT → .env →
# references/timeouts.json → 18000s). The legs below do NOT use it: each has its own bound.
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from wp_timeouts import CALL_TIMEOUT, floor as _floor  # noqa: E402,F401
import wp_ct  # noqa: E402 — the one CT client
from wp_ua import DEFAULT_UA as UA  # noqa: E402 — the one User-Agent source (Android Chrome)
import wp_http  # noqa: E402 — the one transport
from wp_refs import load_ref, ref_path  # noqa: E402 — the RULE 3 loader
import collect_core  # noqa: E402 — the one bounded subprocess runner (process-group kill)

_LEG_FALLBACK = {"fallback_probe_legs": {"crtsh": 120, "wayback": 120, "archive_is": 90,
                                         "archive_is_request": 40, "kb": 60}}
LEGS = load_ref(ref_path(os.path.join(ROOT, "WebPivot", "tools", "wp_timeouts.py"), "timeouts.json"),
                _LEG_FALLBACK)["fallback_probe_legs"]


def _host(s: str) -> str:
    s = s.strip()
    if "://" in s:
        s = urllib.parse.urlparse(s).hostname or s
    return s.split("/")[0].lower()


def _get(url: str, timeout: float) -> str:
    """One bounded GET: `timeout` is honoured exactly (bounded=True — the unfloored urlopen, still
    through the proxy opener). Raises on any failure, as before."""
    r = wp_http.request(url, timeout=timeout, bounded=True)
    return r.raise_for_status().body.decode("utf-8", "ignore")


def _legs(jobs: dict, bounds: dict) -> tuple[dict, list]:
    """Run each leg in its own daemon thread and wait at most its own bound (all concurrently).
    Returns ({leg: result | {"ok": False, "timed_out": True, ...}}, [timed-out legs]). A leg that
    overruns is abandoned — a daemon thread never holds the process at exit."""
    box: dict = {}

    def _go(name, fn):
        try:
            box[name] = fn()
        except Exception as e:  # noqa: BLE001 — one broken leg never sinks the probe
            box[name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    threads = {n: threading.Thread(target=_go, args=(n, fn), daemon=True, name=f"leg-{n}")
               for n, fn in jobs.items()}
    t0 = time.monotonic()
    for t in threads.values():
        t.start()
    out, late = {}, []
    for n, t in threads.items():
        t.join(max(0.0, float(bounds[n]) - (time.monotonic() - t0)))
        if n in box:
            out[n] = box[n]
        else:
            late.append(n)
            out[n] = {"ok": False, "timed_out": True,
                      "error": f"{n} leg timed out after {float(bounds[n]):g}s",
                      "note": f"NOT swept (leg timed out after {float(bounds[n]):g}s) — re-run"}
    return out, late


# ------------------------------------------------------------------ 1. CT logs
def _reg(name: str) -> str:
    return ".".join(name.split(".")[-2:])


def crtsh(domain: str) -> dict:
    """CT certs for the domain through wp_ct. The prize is SAN-sibling domains: a single cert
    covering this domain AND an unrelated-looking one binds them to one owner. Names grouped by
    REGISTRABLE domain, not a bare endswith (`fakesite.com`.endswith("site.com") is a different
    owner). Aggregated names (crt.name + agniops, asked only when CT left no name) stay separate:
    not CT-log-attributable, verify before use."""
    r = wp_ct.ct_search(domain, max_certs=None, max_subdomains=None)
    subs, siblings, issuers = set(), set(), set()
    for c in r.get("certs") or []:
        if c.get("issuer_cn"):
            issuers.add(c["issuer_cn"][:60])
    for name in r.get("subdomains") or []:
        (subs if _reg(name) == _reg(domain) else siblings).add(name)
    crt = (r.get("ct_status") or {}).get("crt.sh", {}).get("status")
    out = {"ok": not r.get("error"), "sources": r.get("sources") or [],
           "crtsh_status": crt, "completeness_line": r.get("completeness_line"),
           "certs": r.get("cert_total", 0), "subdomains": sorted(subs)[:40],
           "subdomain_total": len(subs), "san_siblings": sorted(siblings)[:40],
           "san_sibling_total": len(siblings), "issuers": sorted(issuers)[:8]}
    if r.get("error"):
        out["error"] = r["error"]
    if r.get("aggregated_subdomains"):
        out["aggregated_sources"] = r.get("aggregated_sources") or []
        out["aggregated_subdomains"] = r["aggregated_subdomains"][:80]
    return out


# ---------------------------------------------------------------- 2. Wayback CDX
def wayback(domain: str) -> dict:
    """Full capture timeline from the Wayback index — first seen, last seen, count.
    A parked domain with 400 captures over 3 years had content worth pivoting on. Each attempt is
    bounded by the leg bound; the shared Wayback breaker (wayback_guard.json fail_limit, 20)
    skips the archive once it has failed more than its limit — reported as a gap below."""
    import wp_wayback  # noqa: E402 (WebPivot/tools already on sys.path)
    rows, err = wp_wayback.index([
        ("url", domain), ("matchType", "domain"), ("output", "json"),
        ("fl", "timestamp,original,statuscode"), ("collapse", "timestamp:6"), ("limit", "500")],
        ua=UA, timeout=float(LEGS["wayback"]))
    if err:
        # a skip/non-answer is a GAP, never "never archived"
        return {"ok": False, "skipped": err, "skipped_kind": "breaker",
                "note": f"NOT queried (gap, re-run) — {err}"}
    if not rows:
        return {"ok": True, "captures": 0, "note": "never archived"}
    stamps = sorted(r[0] for r in rows if r and r[0])
    def fmt(ts): return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return {"ok": True, "captures": len(rows), "first": fmt(stamps[0]), "last": fmt(stamps[-1]),
            "sample": [f"http://web.archive.org/web/{r[0]}/{r[1]}" for r in rows[:3]]}


# ------------------------------------------------------------------ 3. archive.is
def archive_is(domain: str) -> dict:
    """archive.today mirror — the fallback when Wayback is empty. TimeMap is a plain
    link list; presence of any memento = a stored copy to pull the DOM from. Each request is
    bounded by fallback_probe_legs.archive_is_request (the mirrors are known to hang)."""
    per = float(LEGS["archive_is_request"])
    for base in ("https://archive.ph", "https://archive.is"):
        try:
            body = _get(f"{base}/timemap/https://{domain}", timeout=per)
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
    """Is this already in our own store? A hit = prior verdict, don't re-investigate. Each KB
    subprocess is bounded by fallback_probe_legs.kb (process group killed on overrun)."""
    late = []

    def run(cmd):
        r = collect_core.run(cmd, ROOT, LEGS["kb"], exact=True)
        if r.timed_out:
            late.append(os.path.basename(cmd[1]))
            return ""
        return (r.stdout or "").strip()
    ent = run([sys.executable, os.path.join("tools", "kb", "query.py"),
               "--kb", kb_dir, "--entity", domain])
    op = run([sys.executable, os.path.join("tools", "kb", "operator_registry.py"), "find", domain])
    known = bool(ent) and "no record" not in ent.lower() and "not found" not in ent.lower()
    attributed = bool(op) and "not attributed" not in op.lower()
    out = {"known": known, "attributed": attributed,
           "operator": op[:400] if attributed else None,
           "kb_facts": ent[:600] if known else None}
    if late:
        out.update(timed_out=True, error=f"kb lookup timed out after {LEGS['kb']}s: {', '.join(late)}")
    return out


def probe(domain: str, kb_dir: str) -> dict:
    domain = _host(domain)
    # crt.sh / wayback / archive.is are independent network I/O — run concurrently, each under
    # its own bound; an overrunning leg is reported as timed out, never waited for.
    res, late = _legs({"crtsh": lambda: crtsh(domain), "wayback": lambda: wayback(domain),
                       "archive_is": lambda: archive_is(domain)}, LEGS)
    res["kb"] = kb_lookup(domain, kb_dir)
    if res["kb"].get("timed_out"):
        late.append("kb")
    res["timed_out"] = late
    res["dorks"] = dorks(domain)

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
    elif res["crtsh"].get("crtsh_status") == "degraded" or res["crtsh"].get("timed_out"):
        res["verdict"] = "INCONCLUSIVE-CT-DEGRADED"
        res["leads"] = []
        res["next_steps"] = [
            f"CT was not fully swept — {res['crtsh'].get('completeness_line') or res['crtsh'].get('error')}. "
            "Older certificates (and their SAN siblings) are invisible until crt.sh answers: this is "
            "not a cold seed yet.",
            "Re-run fallback_probe when crt.sh is reachable (or install psycopg for its PostgreSQL fallback).",
            "Run the emitted search dorks manually / via web search for off-site mentions.",
        ]
    else:
        res["verdict"] = "NO-PIVOT-YET"
        res["leads"] = []
        res["next_steps"] = [
            "Front page is cold AND every keyless corner is empty — likely a fresh NRD not yet weaponized.",
            "Re-run fallback_probe after a few days (certs/archives lag first live use).",
            "Run the emitted search dorks manually / via web search for off-site mentions.",
            "If a registrant email/name leaked in partial WHOIS, reverse-WHOIS it in the correlate phase.",
        ]
    if late and not leads:
        res["next_steps"].insert(0, f"Leg(s) timed out — NOT swept, so not evidence of absence: "
                                    f"{', '.join(late)}. Re-run fallback_probe for them.")
    return {"domain": domain, **res}


def _human(r: dict) -> str:
    out = [f"FALLBACK PROBE · {r['domain']} · VERDICT: {r['verdict']}"]
    c = r["crtsh"]
    out.append(f"  CT logs    : {'%d certs, %d subdomains, %d SAN-siblings  [%s]' % (c.get('certs',0), c.get('subdomain_total',0), c.get('san_sibling_total',0), '+'.join(c.get('sources',[]))) if c.get('ok') else c.get('error')}")
    if c.get("completeness_line"):
        out.append(f"     └ {c['completeness_line']}")
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
    out.append(f"  local KB   : {'ATTRIBUTED — '+ (k.get('operator') or '').splitlines()[0] if k.get('attributed') else ('known indicators on file' if k.get('known') else (k.get('error') or 'not in KB'))}")
    if r.get("timed_out"):
        out.append("  TIMED OUT  : " + ", ".join(r["timed_out"]) + " (not swept — re-run)")
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
