#!/usr/bin/env python3
"""reputation_check.py — is this indicator known-bad? One engine, two commands.

Backs BOTH `/threat-check` (any indicator: ip / domain / url / hash) and `/scam-check` (the
phishing-and-fraud reading of the same evidence). They were specified as separate tools; they ask
one question of one set of feeds, so building two would have reproduced exactly the drifted-
duplicate problem this repo already had.

KEYLESS by default and honest about it. Verified 2026-08-28: AlienVault OTX, urlscan.io search and
Ransomware.live all answer without a key; abuse.ch (URLhaus/ThreatFox) and PhishDestroy now return
401/403 despite techniques/threat-intel.md and scam-check.md still describing them as open. Feeds
that need a key are queried only when it is set and are otherwise reported as NOT CONSULTED — an
unqueried feed is never silently counted as a clean result.

Absence of record is reported as absence of record. Nothing here proves an indicator is benign.

Usage:
  reputation_check.py example.com
  reputation_check.py 185.199.108.153 --mode scam
  reputation_check.py <sha256> --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "cti-expert/reputation_check (OSINT research)"
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _get(url, timeout=18, headers=None):
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def classify(ind):
    s = ind.strip()
    if s.lower().startswith(("http://", "https://")):
        return "url"
    if IPV4.match(s):
        return "ip"
    if HASH.match(s):
        return "hash"
    return "domain"


def otx(ind, kind):
    """AlienVault OTX — keyless.

    Two traps here, both verified 2026-08-28:
      1. `pulse_info.count` is PAGE-CAPPED at 50 and equals len(pulses); it is "at least N", not a
         total. Reporting it as an exact count invents precision.
      2. Appearing in pulses is NOT adverse on its own. Popular infrastructure is cited in pulses
         as context — example.com returns 50 pulses. OTX marks such indicators in `validation`
         (e.g. 'whitelist', 'akamai', 'majestic'); when that is present the pulse count says
         nothing about maliciousness and must not be scored.
    """
    seg = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[kind]
    key = urllib.parse.quote(ind, safe="")
    d, err = _get(f"https://otx.alienvault.com/api/v1/indicators/{seg}/{key}/general")
    if err or not d:
        return {"status": f"unavailable ({err})"}
    pi = d.get("pulse_info") or {}
    pulses = pi.get("pulses") or []
    n = pi.get("count", 0)
    whitelisted = [v.get("source") for v in (d.get("validation") or []) if v.get("source")]
    return {"status": "ok", "pulse_count": n,
            "pulse_count_is_capped": len(pulses) >= 50,
            "whitelisted_by": whitelisted,
            "pulses": [{"name": p.get("name"), "created": p.get("created"),
                        "tags": (p.get("tags") or [])[:6]} for p in pulses[:8]],
            "validation": [v.get("source") for v in (d.get("validation") or [])],
            "reputation": d.get("reputation")}


def urlscan(ind, kind):
    q = {"ip": f"ip:{ind}", "domain": f"domain:{ind}", "url": f"page.url:\"{ind}\"",
         "hash": f"hash:{ind}"}[kind]
    d, err = _get("https://urlscan.io/api/v1/search/?size=5&q=" + urllib.parse.quote(q))
    if err or not d:
        return {"status": f"unavailable ({err})"}
    res = d.get("results") or []
    return {"status": "ok", "sightings": d.get("total", len(res)),
            "recent": [{"url": (r.get("page") or {}).get("url"),
                        "date": (r.get("task") or {}).get("time"),
                        "verdict_malicious": (r.get("verdicts") or {}).get("overall", {}).get("malicious")}
                       for r in res[:5]]}


def ransomware_live(ind, kind):
    if kind not in ("domain",):
        return {"status": "n/a for this indicator type"}
    d, err = _get(f"https://api.ransomware.live/v2/searchvictims/{urllib.parse.quote(ind)}")
    if err or not d:
        return {"status": f"unavailable ({err})"}
    rows = d if isinstance(d, list) else d.get("victims") or []
    return {"status": "ok", "hits": len(rows),
            "victims": [{"group": r.get("group_name") or r.get("group"),
                         "date": r.get("attackdate") or r.get("published")} for r in rows[:5]]}


def virustotal(ind, kind):
    k = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    if not k:
        return {"status": "NOT CONSULTED — no VIRUSTOTAL_API_KEY set"}
    seg = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}[kind]
    val = ind
    if kind == "url":
        import base64
        val = base64.urlsafe_b64encode(ind.encode()).decode().strip("=")
    d, err = _get(f"https://www.virustotal.com/api/v3/{seg}/{urllib.parse.quote(val, safe='')}",
                  headers={"x-apikey": k})
    if err or not d:
        return {"status": f"unavailable ({err})"}
    st = ((d.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    return {"status": "ok", "malicious": st.get("malicious"), "suspicious": st.get("suspicious"),
            "harmless": st.get("harmless"), "undetected": st.get("undetected")}


def abuseipdb(ind, kind):
    if kind != "ip":
        return {"status": "n/a for this indicator type"}
    k = os.environ.get("ABUSEIPDB_API_KEY")
    if not k:
        return {"status": "NOT CONSULTED — no ABUSEIPDB_API_KEY set"}
    d, err = _get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ind)}"
                  "&maxAgeInDays=90", headers={"Key": k})
    if err or not d:
        return {"status": f"unavailable ({err})"}
    x = d.get("data") or {}
    return {"status": "ok", "abuse_confidence": x.get("abuseConfidenceScore"),
            "total_reports": x.get("totalReports"), "country": x.get("countryCode"),
            "isp": x.get("isp")}


def verdict(res, mode):
    """Turn feed output into a defensible verdict — and refuse to overclaim in either direction."""
    signals, consulted, unavailable = [], 0, []
    o = res["sources"].get("otx", {})
    if o.get("status") == "ok":
        consulted += 1
        wl = o.get("whitelisted_by") or []
        n = o.get("pulse_count") or 0
        if wl:
            # On OTX's own allowlist — pulse membership here is context, not an accusation.
            res.setdefault("notes", []).append(
                f"OTX whitelists this indicator ({', '.join(wl)}); pulse count not scored")
        elif n >= 3:
            approx = "at least " if o.get("pulse_count_is_capped") else ""
            signals.append(f"OTX: named in {approx}{n} threat-intel pulse(s)")
    else:
        unavailable.append("otx")
    u = res["sources"].get("urlscan", {})
    if u.get("status") == "ok":
        consulted += 1
        mal = [r for r in u.get("recent", []) if r.get("verdict_malicious")]
        if mal:
            signals.append(f"urlscan: {len(mal)} recent scan(s) verdicted malicious")
    else:
        unavailable.append("urlscan")
    v = res["sources"].get("virustotal", {})
    if v.get("status") == "ok":
        consulted += 1
        if (v.get("malicious") or 0) > 0:
            signals.append(f"VirusTotal: {v['malicious']} engine(s) flag it")
    a = res["sources"].get("abuseipdb", {})
    if a.get("status") == "ok":
        consulted += 1
        if (a.get("abuse_confidence") or 0) >= 25:
            signals.append(f"AbuseIPDB: {a['abuse_confidence']}% abuse confidence")
    r = res["sources"].get("ransomware_live", {})
    if r.get("status") == "ok" and r.get("hits"):
        signals.append(f"Ransomware.live: {r['hits']} victim record(s)")

    if consulted == 0:
        return {"verdict": "UNKNOWN", "confidence": "none",
                "reason": "no feed answered — this is an absence of collection, not a clean result",
                "signals": signals, "unavailable": unavailable}
    if len(signals) >= 2:
        return {"verdict": "MALICIOUS", "confidence": "high" if len(signals) > 2 else "moderate",
                "reason": f"{len(signals)} independent feeds agree", "signals": signals,
                "unavailable": unavailable}
    if signals:
        return {"verdict": "SUSPICIOUS", "confidence": "low",
                "reason": "a single feed flags it — corroborate before acting", "signals": signals,
                "unavailable": unavailable}
    return {"verdict": "NO ADVERSE RECORD", "confidence": "low",
            "reason": (f"{consulted} feed(s) hold nothing adverse. This is NOT a clean bill: "
                       f"freshly-registered scam infrastructure is routinely absent from every "
                       f"reputation feed for weeks. Judge it on its own artifacts."),
            "signals": [], "unavailable": unavailable}


def main():
    ap = argparse.ArgumentParser(description="Keyless-first reputation check for any indicator.")
    ap.add_argument("indicator")
    ap.add_argument("--mode", choices=["threat", "scam"], default="threat",
                    help="scam adds the fraud-oriented feeds; both share the same engine")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    ind = a.indicator.strip()
    kind = classify(ind)
    res = {"indicator": ind, "type": kind, "mode": a.mode, "sources": {}}
    res["sources"]["otx"] = otx(ind, kind)
    res["sources"]["urlscan"] = urlscan(ind, kind)
    res["sources"]["virustotal"] = virustotal(ind, kind)
    if kind == "ip":
        res["sources"]["abuseipdb"] = abuseipdb(ind, kind)
    if a.mode == "scam":
        res["sources"]["ransomware_live"] = ransomware_live(ind, kind)
    res.update(verdict(res, a.mode))

    print(f"{ind} [{kind}] → {res['verdict']} ({res['confidence']}) — {res['reason'][:90]}",
          file=sys.stderr)
    for s in res["signals"]:
        print(f"  • {s}", file=sys.stderr)
    txt = json.dumps(res, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
