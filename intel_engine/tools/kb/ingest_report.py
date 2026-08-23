#!/usr/bin/env python3
"""
ingest_report.py — fold an analyst's free-text report/notes into the same KB. Zero web I/O.

You've already done investigations; those write-ups hold IOCs the KB has never seen. This
pulls domains / emails / crypto wallets / phones / messenger handles out of a Markdown or text
report and emits **pivot-extract-shaped JSON** (one file per domain) so the SAME ingester folds
them in — your prior conclusions become KB edges the next case can cluster against.

Co-mention in one report = your assertion that these IOCs belong together, so every IOC in the
file is attached to every domain in it at source="analyst_report" (medium confidence). Keep it to
**one report = one cluster/case**; splitting mixed reports keeps the links honest.

Usage:
  python3 tools/kb/ingest_report.py cases/mycase/report.md --case mycase
  python3 tools/kb/ingest_report.py notes.md --case mycase --dry-run     # preview IOCs, write nothing
  # then, as usual:
  python3 tools/kb/ingest_webpivot.py --kb knowledge cases/mycase/raw/*.json
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

sys.path.insert(0, HERE)
import kb_refs  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)

_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_BTC = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_PHONE = re.compile(r"(?<![\w.])(\+\d[\d\s().\-]{7,16}\d)(?![\w.])")
_TG = re.compile(r"(?:https?://)?t\.me/([A-Za-z0-9_]{4,})", re.I)
_WA = re.compile(r"(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send\?phone=)/?(\+?\d{7,15})", re.I)

# never treat these as investigation targets, and never mistake a filename for a domain
# DATA: references/registrant_noise.json -> report_noise_domains / report_filename_suffixes
_IR_FALLBACK = {
    "report_noise_domains": ("example.com", "google.com", "gmail.com", "facebook.com", "t.me",
                             "wa.me", "cloudflare.com", "github.com", "schema.org", "w3.org"),
    "report_filename_suffixes": (".md", ".txt", ".json", ".html", ".png", ".jpg", ".py", ".js",
                                 ".css"),
}
_IR_REF = kb_refs.load_ref(kb_refs.ref_path(__file__, "registrant_noise.json"), _IR_FALLBACK)
_NOISE_DOMAINS = tuple(_IR_REF["report_noise_domains"])
_TLD_STOP = tuple(_IR_REF["report_filename_suffixes"])


def extract(text):
    emails = sorted({e.lower() for e in _EMAIL.findall(text)})
    email_domains = {e.split("@", 1)[1] for e in emails}
    domains = set()
    for d in _DOMAIN.findall(text):
        d = d.lower().rstrip(".")
        if d in email_domains or d.endswith(_TLD_STOP):
            continue
        if any(d == n or d.endswith("." + n) for n in _NOISE_DOMAINS):
            continue
        domains.add(d)
    wallets = {}
    for kind, rx in (("btc", _BTC), ("eth", _ETH), ("tron", _TRON)):
        vals = sorted(set(rx.findall(text)))
        if vals:
            wallets[kind] = vals
    socials = {}
    tg = sorted(set(_TG.findall(text)))
    wa = sorted(set(_WA.findall(text)))
    if tg:
        socials["telegram"] = [f"https://t.me/{h}" for h in tg]
    if wa:
        socials["whatsapp"] = [f"https://wa.me/{h}" for h in wa]
    phones = sorted({re.sub(r"[\s().\-]", "", p) for p in _PHONE.findall(text)})
    return {"domains": sorted(domains), "emails": emails, "wallets": wallets,
            "socials": socials, "phones": phones}


def to_pivot_json(host, ioc, report_name):
    """One pivot-extract-shaped record: this report's IOCs attached to `host`."""
    return {
        "meta": {"source": f"analyst_report:{report_name}", "final_url": None,
                 "host": host, "fetched_with": "analyst_report",
                 "enriched_with": ["analyst_report"]},
        "artifacts": {
            "title": "", "emails": ioc["emails"], "crypto": ioc["wallets"],
            "socials": ioc["socials"],
            "whois": ({"registrant_phone": ioc["phones"][0]} if ioc["phones"] else {}),
        },
        "pivots": [],
    }


def main():
    ap = argparse.ArgumentParser(description="Ingest an analyst report's IOCs into the KB.")
    ap.add_argument("report", help="a .md / .txt report or notes file")
    ap.add_argument("--case", required=True, help="case name — raw JSON lands in cases/<case>/raw/")
    ap.add_argument("--dry-run", action="store_true", help="print IOCs, write nothing")
    a = ap.parse_args()
    if not os.path.isfile(a.report):
        ap.error(f"no such file: {a.report}")
    text = open(a.report, encoding="utf-8", errors="ignore").read()
    ioc = extract(text)
    print(f"# extracted from {a.report}:")
    print(f"   domains : {len(ioc['domains'])}  {', '.join(ioc['domains'][:8])}"
          + (" …" if len(ioc['domains']) > 8 else ""))
    print(f"   emails  : {len(ioc['emails'])}  {', '.join(ioc['emails'][:5])}")
    print(f"   wallets : {sum(len(v) for v in ioc['wallets'].values())}  {ioc['wallets']}")
    print(f"   socials : {ioc['socials']}")
    print(f"   phones  : {ioc['phones']}")
    if not ioc["domains"]:
        print("   (no target domains found — nothing to attach IOCs to; add the domains to the report.)")
        return
    if a.dry_run:
        print("\n   dry-run: no files written.")
        return
    raw_dir = os.path.join(ROOT, "cases", a.case, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    report_name = os.path.splitext(os.path.basename(a.report))[0]
    for host in ioc["domains"]:
        p = os.path.join(raw_dir, f"{host}.report.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(to_pivot_json(host, ioc, report_name), fh, indent=2, ensure_ascii=False)
    print(f"\n   wrote {len(ioc['domains'])} raw record(s) -> cases/{a.case}/raw/*.report.json")
    print(f"   next: python3 tools/kb/ingest_webpivot.py --kb knowledge cases/{a.case}/raw/*.json")


if __name__ == "__main__":
    main()
