#!/usr/bin/env python3
"""
risk_signals.py — scam/fraud red-flag scorer over pivot-extract JSON. Zero web I/O.

Turns raw artifacts (WHOIS, wallets, contacts, hosting) into the three signals an analyst
triages first on a suspected scam:

  * NRD  — newly-registered domain (age from WHOIS creation date). Scam infra is young.
  * BPH  — bulletproof / abuse-tolerant hosting (registrar / nameserver / provider match
           against IntelAnalysis/references/risk_indicators.json — a LEAD, never proof).
  * MONEY — the money trail: crypto wallets, payment/contact handles, registrant phone/email.
           The crucial category — how the operator gets paid and who to trace for it.

Deterministic (this file) computes the flags; IntelAnalysis (the model) decides what they mean.

Usage:
  python3 tools/kb/risk_signals.py --file cases/x/raw/site.example.json
  python3 tools/kb/risk_signals.py --case x                 # every raw/*.json in a case
  python3 tools/kb/risk_signals.py --case x --json          # machine-readable
"""
import argparse
import datetime as _dt
import glob
import json
import os
import re
import sys

if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_refs import load_ref  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _ref_file():
    """Where `risk_indicators.json` lives. It is IntelAnalysis's data (risk scoring is the analyst
    layer) read by a tools/kb scorer, so it cannot be resolved by `ref_path(__file__, …)` — that
    helper only looks beside the CALLING module. Both layouts are tried because the skills are
    imported standalone onto other machines as often as they are run from the repo."""
    for cand in (os.path.join(ROOT, "IntelAnalysis", "references", "risk_indicators.json"),
                 os.path.expanduser("~/.claude/skills/IntelAnalysis/references/"
                                    "risk_indicators.json")):
        if os.path.exists(cand):
            return cand
    return os.path.join(ROOT, "IntelAnalysis", "references", "risk_indicators.json")


REF = _ref_file()

# RULE 3. This module used to hand-roll its own loader with a bare `except: return {…}`, which
# FAILED OPEN SILENTLY: a missing or malformed file left `bph` and `money_trail` as empty dicts,
# so every bulletproof-hosting and money-trail check quietly matched nothing and a domain on known
# BPH scored clean. The shared loader keeps the same fallback shape but WARNS on stderr and fills
# in only the groups that are actually broken. The fallback below is the conservative minimum —
# NRD day-thresholds only, because a date comparison still works with no reference data while a
# denylist match cannot.
_RISK_FALLBACK = {
    "nrd": {"critical_days": 30, "high_days": 90, "watch_days": 180},
    "bph": {}, "money_trail": {},
}
RISK_INDICATORS = load_ref(REF, _RISK_FALLBACK)


def _load_ref():
    """The loaded reference. Kept as a function so the existing call sites are unchanged."""
    return RISK_INDICATORS


def _parse_date(s):
    """Best-effort parse of a WHOIS date string → date, or None (never raises)."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d",
                "%Y.%m.%d", "%d.%m.%Y"):
        try:
            return _dt.datetime.strptime(s[:len(fmt) + 4].strip(), fmt).date()
        except Exception:
            continue
    m = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", s)
    if m:
        try:
            return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except Exception:
            return None
    return None


def _nrd(whois, ref, today):
    created = _parse_date((whois or {}).get("created"))
    if not created:
        return {"age_days": None, "tier": "unknown", "created": (whois or {}).get("created")}
    age = (today - created).days
    t = ref.get("nrd", {})
    if age < t.get("critical_days", 30):
        tier = "critical"
    elif age < t.get("high_days", 90):
        tier = "high"
    elif age < t.get("watch_days", 180):
        tier = "watch"
    else:
        tier = "aged"
    return {"age_days": age, "tier": tier, "created": created.isoformat()}


def _bph(whois, artifacts, pivots, ref):
    b = ref.get("bph", {})
    prov = [p.lower() for p in b.get("provider_substrings", [])]
    regs = [r.lower() for r in b.get("abuse_tolerant_registrars", []) if not r.startswith("_")]
    off_ns = [n.lower() for n in b.get("offshore_privacy_ns", [])]
    hits = []
    registrar = ((whois or {}).get("registrar") or "").lower()
    for r in regs:
        if r and r in registrar:
            hits.append(f"registrar~{r}")
    ns = [n.lower() for n in ((whois or {}).get("name_servers") or [])]
    hosts = [h.lower() for h in (artifacts.get("third_party_hosts") or [])]
    for pool, label in ((ns, "ns"), (hosts, "host")):
        for val in pool:
            for p in prov + off_ns:
                if p and p in val:
                    hits.append(f"{label}~{p}:{val}")
    return {"flagged": bool(hits), "hits": sorted(set(hits))}


def _money(whois, artifacts, ref):
    m = ref.get("money_trail", {})
    crypto = artifacts.get("crypto") or {}
    wallets = []
    if isinstance(crypto, dict):
        for kind, vals in crypto.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                wallets.append(f"{kind}:{v}")
    socials = artifacts.get("socials") or {}
    pay_socials = [k for k in m.get("payment_contact_socials", []) if socials.get(k)]
    emails = artifacts.get("emails") or []
    phone = (whois or {}).get("registrant_phone")
    reg_email = (whois or {}).get("registrant_email")
    trail = {"wallets": wallets, "contact_channels": pay_socials,
             "page_emails": list(emails), "registrant_phone": phone,
             "registrant_email": reg_email}
    trail["has_money_trail"] = bool(wallets or pay_socials or emails or phone)
    # the classic funnel: a wallet AND an off-platform contact handle
    trail["payment_funnel"] = bool(wallets and pay_socials)
    return trail


def _verdict(raw):
    """urlscan verdict/brand (from urlscan_intel; richer on a Pro key) as a triage signal.
    Returns {'present','malicious','score','brands'} — a LEAD (external scanner opinion), not proof."""
    v = (raw.get("related_urlscan") or {}).get("verdict") or {}
    if not v:
        return {"present": False, "malicious": False, "score": None, "brands": []}
    return {"present": True, "malicious": bool(v.get("malicious")),
            "score": v.get("score"), "brands": v.get("brands") or [],
            "categories": v.get("categories") or []}


_REP_RISK_RE = re.compile(
    r"malicious|phish|scam|spam|malware|suspicious|botnet|c2|command.and.control|"
    r"high.?risk|threat|fraud|abuse", re.I)


def _reputation(raw):
    """Validin quick-reputation annotations attached to live_results (domain + origin IP) during
    enrichment, folded here as a CORROBORATING exposure signal — never the sole verdict. Read
    OFFLINE (no network), so a captured fixture drives the test."""
    anns = []
    for piv in raw.get("pivots") or []:
        lr = piv.get("live_results") or {}
        for a in (lr.get("validin_reputation") or {}).get("annotations") or []:
            anns.append(a)
        for _ip, ipblk in (lr.get("validin_ip_reputation") or {}).items():
            for a in (ipblk or {}).get("annotations") or []:
                anns.append(a)
    risky = any(_REP_RISK_RE.search(a if isinstance(a, str) else str(a)) for a in anns)
    return {"present": bool(anns), "risky": risky, "annotations": anns[:6]}


def score_domain(raw, today=None, ref=None):
    """Score one pivot-extract JSON dict. Returns structured flags (no exceptions)."""
    ref = ref or _load_ref()
    today = today or _dt.date.today()
    artifacts = raw.get("artifacts") or {}
    whois = artifacts.get("whois") or {}
    pivots = raw.get("pivots") or []
    host = (raw.get("meta") or {}).get("host") or artifacts.get("domain") or "?"
    nrd = _nrd(whois, ref, today)
    bph = _bph(whois, artifacts, pivots, ref)
    money = _money(whois, artifacts, ref)
    verdict = _verdict(raw)
    rep = _reputation(raw)
    # a compact escalation verdict
    escalate = []
    if nrd["tier"] in ("critical", "high"):
        escalate.append(f"NRD:{nrd['tier']}({nrd['age_days']}d)")
    if bph["flagged"]:
        escalate.append("BPH")
    if money["payment_funnel"]:
        escalate.append("payment-funnel")
    if verdict["malicious"] or (isinstance(verdict["score"], (int, float)) and verdict["score"]):
        escalate.append("urlscan-malicious")
    if verdict["brands"]:
        escalate.append("brand:" + ",".join(verdict["brands"][:2]))
    # reputation is CORROBORATION only — it may sharpen an existing escalation but never trip one
    # on its own (guarded by `and escalate`), keeping estimative discipline (analytic-standards.md).
    if rep["risky"] and escalate:
        escalate.append("validin-reputation")
    return {"host": host, "nrd": nrd, "bph": bph, "money": money,
            "verdict": verdict, "reputation": rep, "escalate": escalate}


def _fmt(s):
    n, b, m = s["nrd"], s["bph"], s["money"]
    v = s.get("verdict") or {}
    age = f"{n['age_days']}d" if n["age_days"] is not None else "age?"
    line = [f"  {s['host']}"]
    line.append(f"NRD={n['tier']}({age})")
    if b["flagged"]:
        line.append(f"BPH!={','.join(b['hits'][:2])}" + (" …" if len(b["hits"]) > 2 else ""))
    if m["wallets"]:
        line.append(f"💰wallets={len(m['wallets'])}")
    if m["contact_channels"]:
        line.append(f"contact={','.join(m['contact_channels'])}")
    if m["payment_funnel"]:
        line.append("⚠PAYMENT-FUNNEL")
    if v.get("malicious") or v.get("score"):
        line.append(f"urlscan={v.get('score') if v.get('score') is not None else 'malicious'}")
    if v.get("brands"):
        line.append(f"brand={','.join(v['brands'][:2])}")
    if (s.get("reputation") or {}).get("risky"):
        line.append("validin-rep!")
    return "  ".join(line)


def _iter_files(a):
    if a.file:
        return [a.file]
    if a.case:
        cd = a.case if os.path.isdir(a.case) else os.path.join(ROOT, "cases", a.case)
        return sorted(glob.glob(os.path.join(cd, "raw", "*.json")))
    return []


def main():
    ap = argparse.ArgumentParser(description="Scam red-flag scorer (NRD / BPH / money-trail).")
    ap.add_argument("--file", help="one pivot-extract JSON")
    ap.add_argument("--case", help="a case name or dir — scores every raw/*.json")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()
    files = _iter_files(a)
    if not files:
        ap.error("give --file or --case")
    ref = _load_ref()
    today = _dt.date.today()
    out = []
    for f in files:
        try:
            s = score_domain(json.load(open(f, encoding="utf-8")), today, ref)
        except Exception as e:
            s = {"host": os.path.basename(f), "error": str(e)}
        out.append(s)
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    print("== risk signals (NRD / bulletproof-hosting / money-trail) ==")
    esc = [s for s in out if s.get("escalate")]
    for s in out:
        if "error" in s:
            print(f"  {s['host']}: (skipped: {s['error']})")
        else:
            print(_fmt(s))
    if esc:
        print(f"\n  ⚠ escalate {len(esc)}: " +
              "; ".join(f"{s['host']}[{','.join(s['escalate'])}]" for s in esc[:10]))


if __name__ == "__main__":
    main()
