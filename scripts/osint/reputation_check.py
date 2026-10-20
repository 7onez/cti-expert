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

Spamhaus Intelligence API is the FALLBACK: queried only when the primary feeds above did not
already corroborate a MALICIOUS verdict (no answer, nothing adverse, or a single uncorroborated
feed), so its monthly query quota is spent where it can change the verdict. IP -> XBL/CSS/BCL
listing (active = signal, expired history = note); domain -> current DBL listing or an adverse
reputation tag (signal), compromised-legitimate flag (note).

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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keyed_feeds  # noqa: E402 — sibling; attaches Auth-Key when ABUSE_CH_API_KEY is set

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



def _apex(host):
    host = (host or "").lower().split(":")[0]
    try:
        eng = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "..", "intel_engine", "WebPivot", "tools"))
        if eng not in sys.path:
            sys.path.insert(0, eng)
        from wp_common import _registrable
        return (_registrable(host) or host).lower()
    except Exception:
        parts = [p for p in host.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

def chongluadao(ind, kind):
    """The keyed first-party source. No key → NOT CONSULTED, never a silent clean."""
    keyed_feeds.load_keys()
    if not any(os.environ.get(n) for n in (
            "CHONGLUADAO_API_KEY", "CLD_API_KEY", "CHONGLUADAO_KEY", "BURNER_API_KEY")):
        return {"status": "NOT CONSULTED — no CHONGLUADAO_API_KEY set"}
    if (os.environ.get("CTI_FREE_ONLY") or "").strip().lower() in ("1", "true", "yes"):
        return {"status": "HELD — --free-only"}
    try:
        cld_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cld")
        if cld_dir not in sys.path:
            sys.path.insert(0, cld_dir)
        import cld_api
    except Exception as e:
        return {"status": f"unavailable ({type(e).__name__})"}
    a = argparse.Namespace(timeout=25, ai=False, lang="en", fresh=False, limit=50, offset=0)
    out = {"status": "ok"}
    try:
        if kind in ("domain", "url"):
            a.url = ind if "://" in ind else "https://" + ind
            a.q = ind.split("://", 1)[-1].split("/")[0]
            apex = _apex(a.q)
            a.q = apex
            st, res, err = cld_api.op_checkurl(cld_api._api_key(), a)
            out["checkurl"] = res if err is None else {"error": err}
            a.type, a.value = "url", ind if "://" in ind else "https://" + ind
            st, res, err = cld_api.op_ioc(cld_api._api_key(), a)
            out["ioc"] = res if err is None else {"error": err}
            st, res, err = cld_api.op_catalog(cld_api._api_key(), a, "ransomware")
            _filtered, n = cld_api.filter_host_hits(res if err is None else {}, apex)
            out["ransomware_matched"] = n
            st, res, err = cld_api.op_catalog(cld_api._api_key(), a, "clickfix")
            _filtered, n = cld_api.filter_host_hits(res if err is None else {}, apex)
            out["clickfix_matched"] = n
        elif kind == "email":
            a.type, a.value, a.q = "email", ind, ind.split("@", 1)[-1]
            st, res, err = cld_api.op_ioc(cld_api._api_key(), a)
            out["ioc"] = res if err is None else {"error": err}
            st, res, err = cld_api.op_burner(cld_api._api_key(), a)
            out["burner"] = res if err is None else {"error": err}
        elif kind == "phone":
            a.type, a.value, a.q = "phone", ind, ind
            st, res, err = cld_api.op_checkphone(cld_api._api_key(), a)
            out["checkphone"] = res if err is None else {"error": err}
            st, res, err = cld_api.op_ioc(cld_api._api_key(), a)
            out["ioc"] = res if err is None else {"error": err}
        elif kind in ("ip", "hash"):
            a.type = "ip" if kind == "ip" else "hash"
            a.value = ind
            st, res, err = cld_api.op_ioc(cld_api._api_key(), a)
            out["ioc"] = res if err is None else {"error": err}
        else:
            return {"status": "n/a for this indicator type"}
    except Exception as e:
        return {"status": f"unavailable ({type(e).__name__})"}
    return out


# Spamhaus domain-tag classes are reference DATA (references/spamhaus_tags.json, names from the
# official /api/intel/v2/domains/tags list). Fallback = conservative minimum from the docs page.
_SPAMHAUS_TAGS_FALLBACK = {"adverse_tags": ["botnet", "botnetcc", "malware", "phish", "spam"],
                           "abusech_derived_tags": ["botnet", "botnetcc", "malware"],
                           "override_tags": ["sinkhole", "neverlist"],
                           "victim_tags": ["abused", "compromised"]}


def _load_spamhaus_tags():
    try:
        eng = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "..", "intel_engine", "WebPivot", "tools"))
        if eng not in sys.path:
            sys.path.insert(0, eng)
        from wp_refs import load_ref, ref_path
        return load_ref(ref_path(__file__, "spamhaus_tags.json"), _SPAMHAUS_TAGS_FALLBACK)
    except Exception:  # noqa: BLE001 — loader missing: the conservative minimum, loudly
        print("[!] spamhaus_tags.json not loaded — using the embedded minimum", file=sys.stderr)
        return dict(_SPAMHAUS_TAGS_FALLBACK)


_SH_TAGS = _load_spamhaus_tags()
_SPAMHAUS_ADVERSE_TAGS = set(_SH_TAGS["adverse_tags"])
_SPAMHAUS_ABUSECH_DERIVED = set(_SH_TAGS["abusech_derived_tags"])
_SPAMHAUS_VICTIM_TAGS = set(_SH_TAGS["victim_tags"])
_SPAMHAUS_OVERRIDE_TAGS = set(_SH_TAGS["override_tags"])


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
    ab = res["sources"].get("abusech", {})
    if ab.get("status") == "ok":
        consulted += 1
        if ab.get("listed"):
            where = ", ".join(ab.get("listed_on") or []) or "a feed"
            signals.append(f"abuse.ch: listed on {where}")
    elif ab:
        unavailable.append("abuse.ch")
    r = res["sources"].get("ransomware_live", {})
    if r.get("status") == "ok" and r.get("hits"):
        signals.append(f"Ransomware.live: {r['hits']} victim record(s)")
    cld = res["sources"].get("chongluadao", {})
    if cld.get("status") == "ok":
        consulted += 1
        cu = cld.get("checkurl") if isinstance(cld.get("checkurl"), dict) else {}
        listed = str(cu.get("result") or "").lower() in ("malicious", "phishing", "scam")
        ioc = cld.get("ioc") if isinstance(cld.get("ioc"), dict) else {}
        data = ioc.get("data") if isinstance(ioc.get("data"), dict) else {}
        matches = data.get("threat_matches") or []
        reports = data.get("threat_reports") if isinstance(data.get("threat_reports"), dict) else {}
        label = str(ioc.get("verdict") or "").lower()
        if listed or matches or reports.get("count"):
            signals.append("ChongLuaDao: denylist listing or threat report")
        elif label in ("malicious", "suspicious"):
            res.setdefault("notes", []).append(
                "ChongLuaDao labelled this without a listing or threat report — not scored")
        if cld.get("ransomware_matched") or cld.get("clickfix_matched"):
            res.setdefault("notes", []).append(
                "ChongLuaDao host-matched ransomware/ClickFix row — a victim or lure fact, not an operator verdict")
    elif str(cld.get("status") or "").startswith("NOT CONSULTED"):
        unavailable.append("chongluadao")
    sh = res["sources"].get("spamhaus", {})
    if sh.get("status") == "ok":
        consulted += 1
        if sh.get("kind") == "ip":
            if sh.get("active_datasets"):
                signals.append(f"Spamhaus: currently listed on {', '.join(sh['active_datasets'])}")
            elif sh.get("history_count"):
                res.setdefault("notes", []).append(
                    f"Spamhaus: {sh['history_count']} expired listing(s) in the last 12 months — "
                    "history, not scored (residential/dynamic IPs churn through XBL)")
        else:
            tags = {str(t).lower() for t in sh.get("tags") or []}
            bad_tags = sorted(_SPAMHAUS_ADVERSE_TAGS & tags)
            override = sorted(_SPAMHAUS_OVERRIDE_TAGS & tags)
            score = sh.get("score")
            if sh.get("listed"):
                signals.append("Spamhaus DBL: domain currently listed")
            elif override:
                # sinkhole = defender-controlled; neverlist = protected. Their abuse tags describe
                # what the domain CATCHES, not what it does — never scored.
                res.setdefault("notes", []).append(
                    f"Spamhaus marks this {', '.join(override)}"
                    + (f"; its {', '.join(bad_tags)} tag(s) describe captured traffic" if bad_tags else "")
                    + " — not scored")
            elif bad_tags and isinstance(score, (int, float)) and score < 0:
                if set(bad_tags) <= _SPAMHAUS_ABUSECH_DERIVED and ab.get("listed"):
                    # Spamhaus builds its malware dimension partly FROM abuse.ch — not independent
                    res.setdefault("notes", []).append(
                        f"Spamhaus tags {', '.join(bad_tags)} corroborate abuse.ch but are partly "
                        "derived from it — not counted as a second independent feed")
                else:
                    signals.append(f"Spamhaus: domain tagged {', '.join(bad_tags)} with negative "
                                   f"reputation ({score})")
            elif bad_tags:
                # Measured live: example.com carries phish/spam tags (it is NAMED in phish and spam)
                # at score +34.3. A tag without a negative score is context, never a verdict.
                res.setdefault("notes", []).append(
                    f"Spamhaus tags {', '.join(bad_tags)} but reputation score is {score} "
                    "(not negative) — the domain appears in that traffic, not scored")
            victim = sorted(_SPAMHAUS_VICTIM_TAGS & tags)
            if sh.get("abused") or victim:
                res.setdefault("notes", []).append(
                    "Spamhaus flags this as a COMPROMISED/abused legitimate or defensive domain "
                    f"({', '.join(victim) or 'abused'}) — the owner is not the operator")
    elif str(sh.get("status") or "").startswith(("NOT CONSULTED", "unavailable")):
        unavailable.append("spamhaus")

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
    res["sources"]["abusech"] = keyed_feeds.abusech_lookup(ind, kind)
    res["sources"]["urlscan"] = urlscan(ind, kind)
    res["sources"]["virustotal"] = virustotal(ind, kind)
    if kind == "ip":
        res["sources"]["abuseipdb"] = abuseipdb(ind, kind)
    if a.mode == "scam":
        res["sources"]["ransomware_live"] = ransomware_live(ind, kind)
    res["sources"]["chongluadao"] = chongluadao(ind, kind)
    res.update(verdict(res, a.mode))
    # Spamhaus is the fallback: spend a SIA query only when the primary feeds did not already
    # corroborate the indicator as malicious.
    if res["verdict"] != "MALICIOUS" and kind in ("ip", "domain", "url"):
        target = ind if kind == "ip" else _apex(ind.split("://", 1)[-1].split("/")[0])
        res["sources"]["spamhaus"] = keyed_feeds.spamhaus_lookup(target, "ip" if kind == "ip" else "domain")
        res["spamhaus_fallback"] = f"primary verdict was {res['verdict']}"
        res.pop("notes", None)                 # verdict() re-derives every note from sources
        res.update(verdict(res, a.mode))
    elif kind in ("ip", "domain", "url"):
        res["sources"]["spamhaus"] = {"status": "NOT NEEDED — primary feeds already corroborate MALICIOUS"}

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
