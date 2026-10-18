"""Regression: build_report_data.py report hygiene on one synthetic case (five observed defects).

  1. a collected IP is typed `ip` (subject) / `ipv4`|`ipv6` (indicator) — never `domain`;
  2. dotted tokens in evidence PROSE (sellers.json, ads.txt, com.vendor, com.vendor.app, a quoted
     store URL) never become indicators; a real registrable domain named there still does;
  3. the case's own seed is hop 0 and never ioc_exclude'd, even when clusters.json lists it as a
     related host and state.json hops omit it;
  4. the attributed operator's label (operators.jsonl) never lands in ioc_exclude;
  5. a shared-hosting / historical / previous-owner IP never gets an `operates` link — only a
     dedicated CURRENT origin may.

Synthetic data only: .example hosts, RFC 5737 / RFC 3849 addresses, CASE-0001, a temp knowledge dir."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import build_report_data as brd  # noqa: E402

SEED = "seed-brand.example"
SIBLING = "sibling.example"
OPERATOR = "Example Persona (Example Co)"
DEDICATED, DEDICATED6 = "203.0.113.10", "2001:db8::5"
SHARED, HISTORICAL, PRIOR_OWNER = "198.51.100.20", "192.0.2.30", "192.0.2.40"

_WHOIS = {"registrant_name": "REDACTED FOR PRIVACY", "registrant_email": None, "registrant_phone": None,
          "registrar": "Example Registrar LLC", "created": "2020-05-01 00:00:00 UTC",
          "name_servers": ["ns1.example.net"]}


def _ip_raw(ip, era, last_seen, live=False, noise=False):
    return {"meta": {"host": ip, "kind": "ip", "final_url": ip,
                     "origin_context": {"hosts": [SEED], "sources": ["passivedns"], "first_seen": "2018-01-01",
                                        "last_seen": last_seen, "live": live, "era": era,
                                        "stale": era not in ("current", "recent"), "ambiguous": False,
                                        "hold_cotenants": era not in ("current", "recent")}},
            "artifacts": {"ip_intel": {"classification": {"ip": ip, "cdn": False, "provider": None,
                                                          "kind": "origin_candidate"},
                                       "noise": noise,
                                       "noise_reason": "~500 sites resolve to this IP — shared host" if noise else ""}},
            "pivots": []}


def _case(tmp):
    engine = os.path.join(tmp, "engine")
    case = os.path.join(engine, "cases", "CASE-0001")
    for d in ("raw", "whois"):
        os.makedirs(os.path.join(case, d))
    kb = os.path.join(engine, "knowledge")
    os.makedirs(kb)
    for h in (SEED, SIBLING):
        json.dump({"meta": {"host": h, "fetched_with": "urllib", "collected_at": "2026-01-01T00:00:00Z"},
                   "artifacts": {"title": h, "http": {"status": 200}}, "pivots": []},
                  open(os.path.join(case, "raw", h + ".json"), "w"))
        json.dump(dict(_WHOIS, domain=h), open(os.path.join(case, "whois", h + ".json"), "w"))
    ips = {DEDICATED: _ip_raw(DEDICATED, "current", "2026-01-01", live=True),
           DEDICATED6: _ip_raw(DEDICATED6, "current", "2026-01-01", live=True),
           SHARED: _ip_raw(SHARED, "current", "2026-01-01", live=True, noise=True),
           HISTORICAL: _ip_raw(HISTORICAL, "historical", "2021-03-01"),
           PRIOR_OWNER: _ip_raw(PRIOR_OWNER, "recent", "2019-06-01")}   # last seen before 2020-05-01
    for n, (ip, raw) in enumerate(ips.items()):
        stem = ip if "." in ip else f"ipv6-{n}"                        # IPPivot names v6 raws by prefix
        json.dump(raw, open(os.path.join(case, "raw", stem + ".json"), "w"))
    json.dump({"seed": SEED, "target_class": "benign_check"}, open(os.path.join(case, "scope.json"), "w"))
    # the observed shape: seed missing from hops and listed as a related host -> was hop 2 + excluded
    json.dump({"hops": {SIBLING: 1, **{ip: 1 for ip in ips}}, "expansion_depth": 2},
              open(os.path.join(case, "state.json"), "w"))
    json.dump({"related_hosts": [SEED]}, open(os.path.join(case, "clusters.json"), "w"))
    json.dump({
        "attribution_level": "same-operator estate (rung 1)",
        "evidence": [
            "E1 [A1] Google sellers.json lists the payee; the site's ads.txt carries that pub id.",
            "E2 [A1] Play listing com.brandapp (https://store.example.com/details?id=com.brandapp) — the "
            "same developer publishes com.brandapp.app, whose site partner-real.example shares the kit.",
        ],
        "cluster": [{"domain": SEED, "shared_artifacts": ["org:Example Co", "domain:203.0.113.77",
                                                          "ip:2001:db8::9"]}],
    }, open(os.path.join(case, "assessment.json"), "w"))
    open(os.path.join(case, "assessment.md"), "w", encoding="utf-8").write(
        "# Analyst Assessment (ICD-203) — synthetic\n\n## Bottom Line Up Front\n\ntext\n")
    with open(os.path.join(kb, "operators.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"operator": OPERATOR, "domains": [SEED, SIBLING], "case": "CASE-0001",
                             "confidence": "likely", "basis": "synthetic", "added": "2026-01-01"}) + "\n")
    return case, kb


def _build():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp)
        return brd.build(case, kb)


_R = None


def _r():
    global _R
    if _R is None:
        _R = _build()
    return _R


def _subject(r, label):
    return next(s for s in r["subjects"] if s["label"] == label)


def _link(r, label):
    sid = _subject(r, label)["id"]
    return [c["relationship"] for c in r["connections"] if c["from_id"] == "SUB-001" and c["to_id"] == sid]


def test_ip_values_are_typed_ip_never_domain():
    r = _r()
    for ip in (DEDICATED, DEDICATED6, SHARED, HISTORICAL, PRIOR_OWNER):
        assert _subject(r, ip)["type"] == "ip", _subject(r, ip)
    types = {i["value"]: i["type"] for i in r["indicators"]}
    assert types.get(DEDICATED) == "ipv4", types
    assert types.get(DEDICATED6) == "ipv6", types
    assert types.get("203.0.113.77") == "ipv4", types              # cluster-asserted `domain:<ip>`
    assert types.get("2001:db8::9") == "ipv6", types
    bad = [i for i in r["indicators"] if i["type"] == "domain" and brd._ip_version(i["value"])]
    assert not bad, bad


def test_prose_tokens_are_not_domain_indicators():
    values = {str(i["value"]).lower() for i in _r()["indicators"]}
    for junk in ("sellers.json", "ads.txt", "com.brandapp", "com.brandapp.app",
                 "https://store.example.com/details?id=com.brandapp"):
        assert junk not in values, (junk, sorted(values))
    assert "partner-real.example" in values, sorted(values)        # a real domain in prose still counts


def test_seed_is_hop_zero_and_never_excluded():
    r = _r()
    s = _subject(r, SEED)
    assert s.get("hop") == 0 and not s.get("ioc_exclude") and s["role"] == "infrastructure", s
    assert "NOT to the operator" not in s["notes"], s["notes"]
    assert SEED not in r["ioc_exclude"], r["ioc_exclude"]
    assert any(i["value"] == SEED and i["type"] == "domain" for i in r["indicators"]), r["indicators"]
    assert _link(r, SEED) == ["operates"], _link(r, SEED)


def test_operator_label_is_not_ioc_excluded():
    excl = {str(x).strip().lower() for x in _r()["ioc_exclude"]}
    assert OPERATOR.lower() not in excl, sorted(excl)


def test_only_dedicated_current_origins_operate():
    r = _r()
    assert _link(r, DEDICATED) == ["operates"], _link(r, DEDICATED)
    assert _link(r, DEDICATED6) == ["operates"], _link(r, DEDICATED6)
    values = {i["value"] for i in r["indicators"]}
    for ip in (SHARED, HISTORICAL, PRIOR_OWNER):
        assert "operates" not in _link(r, ip), (ip, _link(r, ip))
        assert ip not in values, (ip, "a shared / historical address is not an operator IOC")
        assert ip in r["ioc_exclude"], (ip, r["ioc_exclude"])
    assert "previous owner" in _subject(r, PRIOR_OWNER)["notes"], _subject(r, PRIOR_OWNER)["notes"]
    assert "shared hosting" in _subject(r, SHARED)["notes"], _subject(r, SHARED)["notes"]


_TESTS = [
    test_ip_values_are_typed_ip_never_domain,
    test_prose_tokens_are_not_domain_indicators,
    test_seed_is_hop_zero_and_never_excluded,
    test_operator_label_is_not_ioc_excluded,
    test_only_dedicated_current_origins_operate,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001 — report every independent contract
            failed += 1
            lines.append(("FAIL", f"{label}: {exc!r}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
