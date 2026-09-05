#!/usr/bin/env python3
"""Regression checks for the Phase 2 scripts/osint tools that are PURE (no network).

Each check is one property the tool must not lose. Network-dependent behaviour is deliberately
not asserted here — a test that fails when a third-party feed is down teaches people to ignore
the suite.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    p = ROOT / "scripts" / "osint" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


FAIL = []


def check(cond, msg):
    if not cond:
        FAIL.append(msg)


# ── hash_id: the whole point is refusing to guess on 32 hex ────────────────────────────
h = load("hash_id")
md5 = "5d41402abc4b2a76b9719d911017c592"
r = h.identify(md5)
check(r["verdict"] == "AMBIGUOUS", "bare 32-hex must be AMBIGUOUS (MD5 vs NTLM)")
check(r["safe_to_submit"] is False, "an ambiguous hash must never be marked safe to submit")
check(h.identify(md5, "file")["safe_to_submit"] is True,
      "--context file must resolve 32-hex to a submittable file hash")
check(h.identify(md5, "credential")["verdict"] == "CREDENTIAL",
      "--context credential must resolve 32-hex to CREDENTIAL")
check(h.identify(md5, "credential")["safe_to_submit"] is False,
      "credential material must never be submittable")
check(h.identify("$2b$12$" + "a" * 53)["verdict"] == "CREDENTIAL", "bcrypt must be CREDENTIAL")
check(h.identify("e3b0c442" * 8)["safe_to_submit"] is True, "SHA-256 must be submittable")
check(h.identify("not-a-hash")["verdict"] == "UNKNOWN", "a non-hash must be UNKNOWN")

# ── exposure_score: bounds, and coverage honesty ──────────────────────────────────────
e = load("exposure_score")
check(all(w > 0 for _, _, w, _, _ in e.WEIGHTS), "every weight must be positive")
check(len(e.WEIGHTS) == 11, "the weight-engine table has 11 indicators")
allmax = {k: hi for k, _, _, _, hi in e.WEIGHTS}
allmin = {k: lo for k, _, _, lo, _ in e.WEIGHTS}
check(e.score(allmax)["score"] == 100.0, "all indicators at max must score exactly 100")
check(e.score(allmin)["score"] == 0.0, "all indicators at min must score exactly 0")
part = e.score({"breach_count": 5})
check(part["coverage"] < 1.0, "a partial score must report coverage below 1.0")
check("comparable" in part["verdict"], "a partial score must warn it is not comparable")
check(e.score({})["score"] is None, "no indicators must yield no score, not zero")
# min-max must clamp, so an out-of-range raw cannot push the composite past 100
check(e.score({k: hi * 10 for k, _, _, _, hi in e.WEIGHTS})["score"] == 100.0,
      "raw values above max must clamp, not overflow the 0-100 range")

# ── phone_osint: E.164 decomposition, longest-prefix country match ─────────────────────
p = load("phone_osint")
vn = p.analyse("+84901234567")
check(vn["valid"] is True and vn["country_code"] == "84", "+84… must resolve to Vietnam")
check(vn["national_number"] == "901234567", "NSN must exclude the calling code")
# '1' must not shadow '1xx', and '8' must not shadow '84'/'86'
check(p.analyse("+8613800138000")["country_code"] == "86", "longest-prefix match must pick 86")
check(p.analyse("+12125551234")["country_code"] == "1", "NANP must resolve to 1")
check(p.analyse("+1555")["valid"] is False, "a too-short NANP number must be invalid")
check("carrier" in vn["not_determined"], "carrier must be declared not-determined, not guessed")

# ── username_enum: every listed platform must have a verified detection method ─────────
u = load("username_enum")
check(len(u.PLATFORMS) > 0, "at least one platform must be configured")
for name, tmpl, method in u.PLATFORMS:
    check("{u}" in tmpl, f"{name}: url template must interpolate the username")
check(not any(n in ("pypi", "replit", "medium") for n, _, _ in u.PLATFORMS),
      "platforms proven unable to distinguish present/absent must stay removed")

if FAIL:
    for f in FAIL:
        print(f"FAIL: {f}", file=sys.stderr)
    sys.exit(1)
print("scripts/osint pure tools: all checks passed")

# ── Phase 3 tools: the pure ones, and the honesty properties of the networked ones ─────
sig = load("signature_scan")
check(len(sig.RULES) >= 8, "the signature catalogue exposes at least 8 evaluable observations")
cat = sig.catalog_families()
check(cat.get("status") == "ok", "analysis/signature-catalog.md is readable")
check("TEMPORAL_SIGNATURES" in (cat.get("families") or []), "the TEMPORAL family is parsed")
_ev = {k: (sid, ev) for k, sid, _f, ev, _d in sig.RULES}
check("automation" in _ev["posting_interval_variance_min"][1](2).lower(),
      "a 2-minute posting variance must read as automation (catalogue T-01)")
check("manual" in _ev["posting_interval_variance_min"][1](30).lower(),
      "a 30-minute variance must read as manual, not automation")

dk = load("dork_builder")
check(len(dk.PLATFORMS) >= 18, "the doc-leak sweep covers at least 18 platforms as documented")
check(all(s in dk.ORDER for _, _, s, _ in dk.PLATFORMS), "every platform has a valid severity")
check(any(s == "CRITICAL" for _, _, s, _ in dk.PLATFORMS), "paste/object-store hosts rate CRITICAL")

sd = load("subdomain_enum")
check(len(sd.SOURCES) >= 3, "subdomain enumeration uses at least 3 independent sources")
check("admin" in sd.SENSITIVE and "kef" in sd.SENSITIVE,
      "the sensitive-label set covers both western and CJK back-office conventions")

cd_ = load("case_drift")
check(cd_.diff({}, {"h": {"ip": "1"}})[0]["change"] == "APPEARED", "a new host reads as APPEARED")
check(cd_.diff({"h": {"ip": "1"}}, {})[0]["change"] == "DISAPPEARED", "a lost host reads as DISAPPEARED")
_d = cd_.diff({"h": {"ip": "1"}}, {"h": {"ip": "2"}})
check(_d and _d[0]["change"] == "CHANGED" and _d[0]["before"] == "1",
      "a changed field reports both before and after")
check(cd_.diff({"h": {"ip": "1"}}, {"h": {"ip": "1"}}) == [], "an unchanged case yields no diff")

cn = load("cn_recon")
_m = cn.SERIAL.search("苏ICP备12345678号-3")
check(_m and _m.group(2) == "12345678", "the ICP licence serial parses out of a full filing string")
check(_m and _m.group(1) == "苏" and _m.group(3) == "3",
      "province prefix and site suffix parse separately — the serial is the pivot, not the province")
check(set(cn.GATED) >= {"beian.miit.gov.cn", "GSXT", "TianYanCha"},
      "every CAPTCHA/geo-gated source is named rather than silently skipped")

ph = load("phone_osint")
check(ph.split_cc("8613800138000")[0] == "86", "longest-prefix match resolves 86 over 8")
