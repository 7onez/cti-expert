#!/usr/bin/env python3
"""
victim_profile.py — profile the VICTIMS of a hostname-hijack campaign to infer the operator's
ACCESS VECTOR.

WHY THIS EXISTS
---------------
When an operator serves their content from hostnames they do not own — a phishing page on
`login.<someone-elses-domain>`, a dangling CNAME, a compromised CMS — the usual analysis chases
the operator's infrastructure and stops. That leaves the most operationally useful question
unasked:

    To obtain these hostnames, what did the operator have to be able to DO?

The victim set answers it, because the victims are a SAMPLE OF THE OPERATOR'S CAPABILITY:

  * victims all on ONE provider .................. that provider is breached, or an insider
  * victims all on ONE control panel, many hosts . the operator has a panel exploit or default creds
  * victims all on ONE CMS ....................... a CMS/plugin vulnerability
  * victims share a small DNS operator / agency .. a reseller or IT contractor was compromised
  * victims share NOTHING technical .............. stolen or purchased credentials

That last line is the one analysts get wrong. Dispersion reads like a dead end — "no pattern" —
when it is in fact a positive finding with a name: a credential LIST has no technical common
factor, because it was assembled by infostealer malware or an access broker across whatever
machines happened to be infected. Absence of a shared platform is the signature.

This matters operationally: the remediation differs completely. A panel exploit is fixed by a
vendor patch. A provider breach is fixed by that provider. A credential supply is fixed only by
per-victim credential resets, and until they happen the operator simply moves to the next name on
their list — which is why taking down the page achieves close to nothing.

WHAT IT DOES NOT DO
-------------------
It does not attribute, and it does not touch the victims. Victims are not the target: everything
here is PASSIVE (DNS records and, if already collected, WHOIS). We never scan or probe a victim's
infrastructure. The panel is identified from the subdomains a panel creates in its customer's own
zone, which is public DNS.

It also does not decide. It reports the victim set's SHAPE and which hypothesis that shape
supports under thresholds an analyst can edit in
`IntelAnalysis/references/victim_profile.json`. The judgment stays with the analyst.

Reference data: RULE 3 — see that JSON. Loader: kb_refs.load_ref (RULE 3 failure contract).
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_refs import load_ref, ref_path  # noqa: E402

# --- reference data (RULE 3): minimal embedded fallback, real values live in the JSON ----------
_VP_FALLBACK = {
    "panel_dns_signatures": {"cpanel": ["cpanel", "webdisk"], "plesk": ["plesk"]},
    "panel_host_signatures": {"cpanel": [".cprapid.com"], "plesk": [".plesk.page"]},
    "managed_dns_operators": ["cloudflare.com", "awsdns-"],
    "hypotheses": {},
    "thresholds": {"min_victims_for_any_call": 4, "onset_tight_days": 30,
                   "high_concentration": 0.8, "moderate_concentration": 0.6},
    "victim_sectors": {"real_estate": ["realit"], "health": ["clinic"]},
    "generic_two_letter_tlds": ["co", "io"],
    "country_names": {"SLOVAKIA": "SK"},
    "demographics": {"min_coverage": 0.5, "concentration": 0.6, "readings": {}},
}
_REF = load_ref(ref_path(__file__, "victim_profile.json"), _VP_FALLBACK)

PANEL_DNS = _REF["panel_dns_signatures"]
PANEL_HOST = _REF["panel_host_signatures"]
MANAGED_DNS = _REF["managed_dns_operators"]
HYPOTHESES = _REF["hypotheses"]
THRESHOLDS = _REF["thresholds"]
SECTORS = _REF["victim_sectors"]
GENERIC_TLDS = set(_REF["generic_two_letter_tlds"])
COUNTRY_NAMES = _REF["country_names"]
DEMOGRAPHICS = _REF["demographics"]

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --------------------------------------------------------------------------- passive DNS helpers
def _dig(name: str, rtype: str) -> list[str]:
    """One passive `dig +short` lookup. Never raises; returns [] on any failure."""
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", name, rtype],
                           capture_output=True, text=True, timeout=12)
        return [ln.strip().rstrip(".") for ln in r.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def _apex(host: str) -> str:
    """Best-effort registrable domain. Handles the common two-label public suffixes we meet."""
    host = host.strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = {"co.uk", "co.za", "com.eg", "com.ng", "co.il", "com.au", "com.br", "com.tr",
           "com.vn", "net.au", "org.uk", "ac.uk", "gov.uk", "com.mx", "co.nz", "com.sg"}
    if ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _origin(ip: str) -> tuple[str, str]:
    """(ASN, country) via Team Cymru's DNS interface — keyless, passive, no account.

    The TXT record is `ASN | prefix | CC | registry | date`, so one lookup gives us both the
    network and the country the address is REGISTERED in."""
    if not _IPV4.match(ip or ""):
        return ("", "")
    rev = ".".join(reversed(ip.split(".")))
    for txt in _dig(f"{rev}.origin.asn.cymru.com", "TXT"):
        parts = [p.strip().strip('"') for p in txt.strip('"').split("|")]
        if len(parts) >= 3 and parts[0].strip().isdigit():
            return ("AS" + parts[0].strip(), parts[2].strip().upper())
    return ("", "")


def _country_from_tld(apex: str) -> str:
    """Country from the ccTLD, or "" when the TLD carries no country meaning.

    Any two-letter TLD is treated as a country code EXCEPT those marketed generically (.io, .co,
    .me …) — that avoids shipping a 250-row table while refusing to read `.io` as a country. The
    exception list is reference DATA so an analyst can extend it without touching this file."""
    tld = apex.rsplit(".", 1)[-1].lower()
    if len(tld) == 2 and tld not in GENERIC_TLDS:
        return tld.upper()
    return ""


def _is_managed(ns_suffix: str) -> bool:
    return any(m in ns_suffix for m in MANAGED_DNS)


# ------------------------------------------------------------------------------ victim profiling
def profile_victim(apex: str, hijacked: list[str] | None = None,
                   registrant_org: str = "", registrant_country: str = "") -> dict:
    """Passively profile ONE victim apex. DNS + records we already hold — the victim is never
    probed or scanned, and its own website is deliberately not fetched."""
    prof: dict = {"apex": apex, "hijacked_labels": sorted(hijacked or [])}

    ips = [x for x in _dig(apex, "A") if _IPV4.match(x)]
    prof["apex_ip"] = ips[0] if ips else None
    asn, host_cc = _origin(ips[0]) if ips else ("", "")
    prof["apex_asn"] = asn

    ns = [n.lower() for n in _dig(apex, "NS")]
    prof["nameservers"] = ns
    # The DNS OPERATOR is the registrable domain of the nameservers — that is the account the
    # attacker needed to write into, so it is the dimension a provider breach concentrates on.
    prof["dns_operator"] = _apex(ns[0]) if ns else ""
    prof["dns_managed"] = _is_managed(prof["dns_operator"])

    mx = [m.split()[-1].lower() for m in _dig(apex, "MX") if m.split()]
    prof["mx_operator"] = _apex(mx[0]) if mx else ""

    # PANEL — identified from the subdomains a control panel creates in its OWN customer's zone.
    # Public DNS, no contact with the victim's server.
    panel_hits: dict[str, list[str]] = {}
    for panel, labels in PANEL_DNS.items():
        for label in labels:
            if _dig(f"{label}.{apex}", "A"):
                panel_hits.setdefault(panel, []).append(label)
    # cPanel's autodiscover/webmail labels are also created by mail providers; require a
    # panel-exclusive label before naming cPanel, so Microsoft 365 tenants aren't miscounted.
    if "cpanel" in panel_hits:
        exclusive = {"cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts"}
        if not (set(panel_hits["cpanel"]) & exclusive):
            panel_hits.pop("cpanel")
    prof["panel_evidence"] = {k: sorted(v) for k, v in panel_hits.items()}
    prof["panel"] = max(panel_hits, key=lambda k: len(panel_hits[k])) if panel_hits else "unknown"

    # COUNTRY — we want where the BUSINESS is, so: WHOIS registrant country first, then ccTLD.
    # Hosting country is recorded as a HINT ONLY and never counted: it measures where the victim's
    # hosting company is, not the victim. Counting it turns any Cloudflare-fronted set into a US
    # cluster, and a set of foreign SMBs on one UK reseller into a British one — both false.
    whois_cc = COUNTRY_NAMES.get((registrant_country or "").strip().upper(),
                                 (registrant_country or "").strip().upper())
    tld_cc = _country_from_tld(apex)
    prof["country"] = whois_cc or tld_cc or ""
    prof["country_basis"] = "whois" if whois_cc else ("cctld" if tld_cc else "")
    prof["country_counted"] = bool(prof["country"])          # hosting never reaches this
    prof["hosting_country_hint"] = host_cc

    # SECTOR — from the domain NAME plus the WHOIS registrant organisation we already hold.
    # The victim's own homepage is not fetched: victims are not the target.
    hay = " ".join(apex.split(".")[:-1]) + " " + (registrant_org or "").lower()
    prof["registrant_org"] = registrant_org or ""
    prof["sector"] = next((s for s, kws in SECTORS.items()
                           if any(k in hay for k in kws)), "unknown")
    prof["tld"] = apex.rsplit(".", 1)[-1]
    return prof


# ----------------------------------------------------------------------------------- the analysis
def _concentration(values: list[str], ignore=("", "unknown")) -> tuple[str, float, int]:
    """Largest share of one value in a dimension -> (value, share, n_known)."""
    known = [v for v in values if v not in ignore]
    if not known:
        return ("", 0.0, 0)
    top, count = collections.Counter(known).most_common(1)[0]
    return (top, count / len(known), len(known))


def assess(profiles: list[dict]) -> dict:
    """Score the victim set against every hypothesis in the reference file."""
    n = len(profiles)
    dims = {
        "dns_operator": [p.get("dns_operator", "") for p in profiles],
        "panel": [p.get("panel", "unknown") for p in profiles],
        "cms": [p.get("cms", "unknown") for p in profiles],
        "registrar": [p.get("registrar", "") for p in profiles],
        "apex_asn": [p.get("apex_asn", "") for p in profiles],
        "tld": [p.get("tld", "") for p in profiles],
        "country": [p.get("country", "") for p in profiles],
        "sector": [p.get("sector", "unknown") for p in profiles],
        "mx_operator": [p.get("mx_operator", "") for p in profiles],
    }
    shape = {}
    for dim, vals in dims.items():
        top, share, known = _concentration(vals)
        shape[dim] = {"top": top, "concentration": round(share, 3),
                      "known": known, "distinct": len({v for v in vals if v not in ("", "unknown")})}

    providers = {p.get("dns_operator", "") for p in profiles if p.get("dns_operator")}
    n_providers = len(providers)

    # --- DEMOGRAPHY: country x sector. These answer what the platform dimensions cannot — was the
    # victim list SELECTED (for a region, for a vertical) or was it whatever the dump contained?
    dcfg = DEMOGRAPHICS if isinstance(DEMOGRAPHICS, dict) else {}
    dconc = dcfg.get("concentration", 0.6)
    dcov = dcfg.get("min_coverage", 0.5)
    readings = dcfg.get("readings") or {}
    demo = {}
    for dim in ("country", "sector"):
        vals = dims[dim]
        top, share, known = _concentration(vals)
        demo[dim] = {
            "top": top, "concentration": round(share, 3),
            "coverage": round(known / n, 3) if n else 0.0,
            "distribution": dict(collections.Counter(
                v for v in vals if v not in ("", "unknown")).most_common()),
            # A dimension we could only resolve for a minority of victims cannot carry a
            # conclusion — say so rather than letting a 2-of-13 sample look like a pattern.
            "sufficient": (known / n if n else 0) >= dcov,
        }
    # Non-managed DNS concentration: a shared HYPERSCALER means nothing, a shared small host means
    # a great deal, so the regional reading is computed on non-managed operators only.
    nonmanaged = [p.get("dns_operator", "") for p in profiles
                  if p.get("dns_operator") and not p.get("dns_managed")]
    nm_top, nm_share, nm_known = _concentration(nonmanaged)
    demo["nonmanaged_dns"] = {"top": nm_top, "concentration": round(nm_share, 3),
                              "of_victims": round(nm_known / n, 3) if n else 0.0}

    cc_ok = demo["country"]["sufficient"] and demo["country"]["concentration"] >= dconc
    sec_ok = demo["sector"]["sufficient"] and demo["sector"]["concentration"] >= dconc
    if cc_ok and nm_share >= dconc:
        demo["reading"], demo["key"] = readings.get("regional_platform", ""), "regional_platform"
    elif cc_ok:
        demo["reading"], demo["key"] = readings.get("geo_targeted_list", ""), "geo_targeted_list"
    elif sec_ok:
        demo["reading"], demo["key"] = readings.get("vertical_targeted", ""), "vertical_targeted"
    elif demo["country"]["sufficient"] or demo["sector"]["sufficient"]:
        demo["reading"], demo["key"] = readings.get("indiscriminate", ""), "indiscriminate"
    else:
        demo["reading"], demo["key"] = (
            "country and sector could not be resolved for enough victims to read the "
            "demography — treat targeting as UNKNOWN, not as absent.", "insufficient")

    # A country+provider sub-cluster can hide inside an otherwise dispersed set, and it is the
    # shortest path to victims we have not found. Surface it even when the overall verdict is
    # dispersion.
    by_op = collections.defaultdict(list)
    for p in profiles:
        if p.get("dns_operator") and not p.get("dns_managed"):
            by_op[p["dns_operator"]].append(p)
    subs = []
    for op, members in by_op.items():
        if len(members) < 3:
            continue
        ccs = [m.get("country", "") for m in members if m.get("country")]
        top_cc, cc_share, _ = _concentration(ccs)
        if cc_share >= dconc:
            subs.append({"dns_operator": op, "country": top_cc, "victims": len(members),
                         "apexes": sorted(m["apex"] for m in members)})
    demo["regional_subclusters"] = subs

    min_n = THRESHOLDS.get("min_victims_for_any_call", 4)
    if n < min_n:
        return {"victims": n, "shape": shape, "distinct_dns_operators": n_providers,
                "demographics": {}, "supported": [],
                "verdict": f"INSUFFICIENT VICTIMS — {n} profiled, {min_n} needed. With a set this "
                           f"small every dimension looks concentrated by chance. Widen the victim "
                           f"sweep before drawing an access-vector conclusion."}

    # A dimension whose dominant value is the world's default (e.g. cPanel) is CONFOUNDED: it looks
    # concentrated in any victim set, related or not. Such a dimension must not be allowed to mask
    # genuine dispersion, so it is excluded from the dispersion test and reported separately.
    base_rate = set()
    for h in HYPOTHESES.values():
        if isinstance(h, dict):
            base_rate.update(h.get("high_base_rate_values") or [])
    confounded = [d for d, s in shape.items() if s["top"] in base_rate and s["known"]]

    supported = []
    for name, h in HYPOTHESES.items():
        if not isinstance(h, dict):
            continue
        if n < h.get("min_victims", min_n):
            continue
        dim = h.get("dimension", "*")
        if dim == "*":                                     # dispersion hypothesis
            testable = [d for d in ("dns_operator", "panel", "cms", "registrar", "apex_asn")
                        if d not in confounded]
            worst = max((shape[d]["concentration"] for d in testable), default=1.0)
            if (worst <= h.get("max_concentration", 0.6)
                    and n_providers >= h.get("min_distinct_providers", 3)):
                entry = {"hypothesis": name, "basis":
                         f"no discriminating dimension exceeds {worst:.0%} concentration across "
                         f"{n_providers} distinct DNS operators"}
                if confounded:
                    entry["caution"] = (
                        f"excluded from this test as base-rate confounded: "
                        f"{', '.join(confounded)}")
                supported.append(entry)
            continue
        s = shape.get(dim)
        if not s:
            continue
        if s["concentration"] < h.get("min_concentration", 0.8):
            continue
        if h.get("exclude_managed") and _is_managed(s["top"]):
            continue
        if n_providers < h.get("min_distinct_providers", 0):
            continue
        if h.get("requires_sector_or_country_concentration"):
            mod = THRESHOLDS.get("moderate_concentration", 0.6)
            if max(shape["sector"]["concentration"], shape["country"]["concentration"]) < mod:
                continue
        if h.get("requires_nonmanaged_dns_concentration"):
            if nm_share < h["requires_nonmanaged_dns_concentration"]:
                continue
        # A demographic dimension resolved for only a minority of victims cannot support a call.
        if dim in ("country", "sector") and not demo[dim]["sufficient"]:
            continue
        entry = {"hypothesis": name, "basis":
                 f"{dim} concentrated at {s['concentration']:.0%} on '{s['top']}' "
                 f"across {n_providers} DNS operators"}
        # A concentration on a value that is ALREADY the world's default is close to what you get
        # by sampling at random — flag it rather than letting it read as a finding.
        if s["top"] in (h.get("high_base_rate_values") or []):
            entry["caution"] = (
                f"BASE RATE — '{s['top']}' is the default for most hosting, so this concentration "
                f"is expected even in an unrelated victim set. Do NOT report this as support "
                f"unless you can also show a shared VERSION or vulnerable component.")
        supported.append(entry)

    if supported:
        verdict = "SUPPORTED: " + ", ".join(x["hypothesis"] for x in supported)
    else:
        verdict = ("NO HYPOTHESIS MET ITS THRESHOLD — the victim set is neither concentrated "
                   "enough for a shared-platform explanation nor dispersed across enough "
                   "providers to call credential supply. Collect more victims.")
    return {"victims": n, "shape": shape, "distinct_dns_operators": n_providers,
            "demographics": demo, "supported": supported, "verdict": verdict}


# ------------------------------------------------------------------------------------------- I/O
def victims_from_case(case_dir: str) -> dict[str, dict]:
    """Derive {victim apex: [hijacked labels]} from a case's collected hosts.

    A collected host is treated as a hijacked label on a victim apex when the host is a SUBDOMAIN
    (not the apex itself) — the apex is the victim's own name, the label is what the operator
    added. Hosts the operator registered outright have no victim and are skipped.
    """
    out: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:
            continue
        host = ((doc.get("meta") or {}).get("host") or "").lower().rstrip(".")
        if not host:
            continue
        apex = _apex(host)
        if host == apex:
            continue                                        # operator-registered, no victim
        rec = out.setdefault(apex, {"labels": [], "org": "", "cc": ""})
        rec["labels"].append(host[: -(len(apex) + 1)])
        # WHOIS on a hijacked host resolves to the APEX's registration — i.e. the victim's own
        # org, which is the only sector signal we can read without touching the victim.
        w = (doc.get("artifacts") or {}).get("whois") or {}
        org = (w.get("registrant_org") or w.get("registrant_name") or "").strip()
        if org and not rec["org"]:
            rec["org"] = org
        cc = (w.get("registrant_country") or "").strip()
        if cc and not rec["cc"]:
            rec["cc"] = cc
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Profile hijack VICTIMS to infer the operator's access vector.")
    ap.add_argument("victims", nargs="*",
                    help="victim apex domains (or hijacked hostnames — the apex is derived)")
    ap.add_argument("--case", help="derive the victim set from a case folder's collected hosts")
    ap.add_argument("--exclude", default="",
                    help="comma list of apexes the OPERATOR registered themselves. A domain the "
                         "operator bought has no victim and must not be counted as one — it would "
                         "otherwise inflate provider diversity and skew every concentration. The "
                         "tool cannot detect this: only you know which names the operator owns.")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("-o", "--out", help="write JSON here as well")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))

    victims: dict[str, dict] = {}
    if args.case:
        case_dir = args.case if os.path.isdir(args.case) else os.path.join(root, "cases", args.case)
        if not os.path.isdir(case_dir):
            print(f"no such case: {case_dir}", file=sys.stderr)
            return 2
        victims = victims_from_case(case_dir)
    for v in args.victims:
        a = _apex(v)
        rec = victims.setdefault(a, {"labels": [], "org": "", "cc": ""})
        if a != v.strip().lower().rstrip("."):
            rec["labels"].append(v.strip().lower().rstrip(".")[: -(len(a) + 1)])
    for ex in (x.strip().lower() for x in args.exclude.split(",") if x.strip()):
        victims.pop(_apex(ex), None)
    if not victims:
        print("no victims given (pass apexes, or --case <name>)", file=sys.stderr)
        return 2

    profiles = [profile_victim(a, rec["labels"], rec.get("org", ""), rec.get("cc", ""))
                for a, rec in sorted(victims.items())]
    result = {"victims": profiles, "assessment": assess(profiles)}

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    a = result["assessment"]
    print(f"\nVICTIM PROFILE — {a['victims']} victim domain(s), "
          f"{a['distinct_dns_operators']} distinct DNS operator(s)\n")
    print(f"{'victim':30s} {'cc':4s} {'host':5s} {'dns operator':19s} {'panel':10s} {'sector':14s}")
    print("-" * 88)
    for p in profiles:
        cc = p.get("country") or "??"
        hint = p.get("hosting_country_hint") or "-"
        print(f"{p['apex'][:29]:30s} {cc:4s} {hint:5s} {(p['dns_operator'] or '?')[:18]:19s} "
              f"{p['panel'][:9]:10s} {p['sector'][:13]:14s}")
    print("  cc = victim country (WHOIS registrant, else ccTLD).  host = where the HOSTING is —")
    print("  shown for context only, never counted: it is the provider's country, not the victim's.")
    print("\nDIMENSION CONCENTRATION (largest share on one value):")
    for dim, s in a["shape"].items():
        if s["known"]:
            print(f"  {dim:14s} {s['concentration']:5.0%} on '{s['top'][:26]}' "
                  f"({s['distinct']} distinct / {s['known']} known)")
    d = a.get("demographics") or {}
    if d:
        print("\nVICTIM DEMOGRAPHY:")
        for dim in ("country", "sector"):
            s_ = d.get(dim) or {}
            dist = ", ".join(f"{k}×{v}" for k, v in list(s_.get("distribution", {}).items())[:8])
            flag = "" if s_.get("sufficient") else "   [COVERAGE TOO LOW — not read]"
            print(f"  {dim:8s} {s_.get('concentration', 0):5.0%} top '{s_.get('top') or '?'}'  "
                  f"(resolved for {s_.get('coverage', 0):.0%} of victims){flag}")
            if dist:
                print(f"           {dist}")
        nm = d.get("nonmanaged_dns") or {}
        if nm.get("top"):
            print(f"  non-managed DNS: {nm['concentration']:.0%} on '{nm['top']}' "
                  f"({nm.get('of_victims', 0):.0%} of victims are on a non-hyperscale operator)")
        print(f"  READING [{d.get('key')}]: {d.get('reading')}")
        for sc in d.get("regional_subclusters") or []:
            print(f"  ! REGIONAL SUB-CLUSTER: {sc['victims']} victims in {sc['country']} all on "
                  f"'{sc['dns_operator']}' -> {', '.join(sc['apexes'])}")
            print(f"    Notify that provider directly — shortest path to victims not yet found.")
    print(f"\nVERDICT: {a['verdict']}")
    for s in a["supported"]:
        print(f"  - {s['hypothesis']}: {s['basis']}")
        if s.get("caution"):
            print(f"      ! {s['caution']}")
    print("\nThis is a decision aid. Thresholds live in "
          "IntelAnalysis/references/victim_profile.json — tune them, then write the judgment "
          "yourself.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
