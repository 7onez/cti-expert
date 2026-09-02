"""Regression: the deterministic house-report composer (intel_engine/tools/house_report.py) must
produce the IntelReport structure from a synthetic case dir — decision statement first, Methodology
with both confidence scales, Roman-level sections in order, a raw \\appendix marker followed by the
four evidence appendices — while scrubbing internal tool / vendor / path names (Rule 12), keeping
indicator values (Rule 12a), and never listing the impersonated brand's genuine domain as an
artifact. Synthetic data only: example.com / .invalid domains, CASE-0001, RFC 5737 addresses."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))

import house_report as hr

_WHOIS = {"registrant_name": "Test Persona", "registrant_email": "persona@example.com",
          "registrant_phone": "+1.2025550100", "registrar": "Example Registrar LLC",
          "created": "2025-01-05 00:00:00 UTC", "expires": "2026-01-05 00:00:00 UTC",
          "name_servers": ["ns1.example.net", "ns2.example.net"]}


def _synthetic_case(tmp):
    case = os.path.join(tmp, "CASE-0001")
    for d in ("raw", "whois"):
        os.makedirs(os.path.join(case, d))
    hosts = ["seed-brand.example.com", "sibling-a.example.com", "sibling-b.example.com"]
    for h in hosts:
        json.dump({"meta": {"host": h, "fetched_with": "urllib"}, "artifacts": {}, "pivots": []},
                  open(os.path.join(case, "raw", h + ".json"), "w"))
        json.dump(_WHOIS, open(os.path.join(case, "whois", h + ".json"), "w"))
    json.dump({"claim": "seed-brand.example.com impersonates Example Brand", "brand": "Example Brand",
               "target_class": "suspected_scam", "purpose": "attribution"},
              open(os.path.join(case, "scope.json"), "w"))
    json.dump({"bluf": "seed-brand.example.com is one of 3 domains under one registrant record.",
               "decision_supported": "Supports an abuse referral.",
               "attribution_level": "same-operator estate (rung 1)", "confidence": "high",
               "premise": "impersonation", "premise_verdict": "supported",
               "evidence": ["E1 [A1, rung 1] Registrant e-mail persona@example.com on 3/3 domains — WhoisXML lookup",
                            "E2 [B2] Page is a link farm — see evidence/cld-analyze.json [cld]"],
               "alternatives": ["Genuine brand property — REJECTED: registered via personal mailbox",
                                "Nominee registrant — CANNOT RULE OUT: no KYC corroboration"],
               "gaps": ["No residential vantage"], "next_pivots": ["Watch renewals"]},
              open(os.path.join(case, "assessment.json"), "w"))
    open(os.path.join(case, "assessment.md"), "w", encoding="utf-8").write(
        "# Analyst Assessment (ICD-203) — synthetic\n\n## BLUF\n\ntext\n\n## Key judgments\n\n"
        "1. **Impersonation of Example Brand — assessed / high.** Body text `[search]` (A2)\n\n"
        "2. **One operator across 3 domains — assessed / high.** Reverse-WHOIS via WhoisXML = 3; IntelX empty; "
        "urlscan saw the link farm. `[whois-api][intelx]` (A1)\n\n"
        "## Excluded\n\n- scraped contacts thirdparty@example.org, phone 0987654321, persona of CASE-0002 — not operator.\n\n"
        "## Recommendation\n\n1. Refer for takedown.\n\n## Collection gaps\n\n- ran `/intelx --phonebook` (3 × 5 units) — see evidence/x.json\n")
    json.dump({"n_clusters": 2, "clusters": [
        {"id": 1, "size": 3, "domains": hosts, "singleton": False, "binding_indicators": [], "binding_total": 1},
        {"id": 2, "size": 1, "domains": ["harvest.indicators"], "singleton": True}]},
        open(os.path.join(case, "clusters.json"), "w"))
    open(os.path.join(case, "shared.txt"), "w", encoding="utf-8").write(
        "# Shared indicators\n\n[3] email:persona@example.com  (registered_by)  [KB-wide: 3 domains]\n"
        "     " + ", ".join(hosts) + "\n"
        "[2] indicator:ip:192.0.2.10  (hosted_on)  [KB-wide: 900 domains]\n     " + ", ".join(hosts[:2]) + "\n")
    return case


def _compose(case):
    hr.KB = os.path.join(os.path.dirname(case), "kb-empty")   # hermetic: never read the live ledgers
    os.makedirs(hr.KB, exist_ok=True)
    c = hr.load_case(case)
    return c, hr.compose(c, {}, "TLP:AMBER", "2026-01-01")


def test_structure_is_the_house_order_with_appendix_marker():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    heads = [l[2:] for l in md.splitlines() if l.startswith("# ")]
    assert heads[:4] == ["Executive Summary — Key Judgments", "Methodology", "Scope and the seed", "Findings"]
    assert "\\appendix" in md
    tail = heads[heads.index("Artifact register"):]
    assert tail == ["Artifact register", "Evidence ledger", "Domain and infrastructure profiles",
                    "Cluster enumeration", "Glossary"]
    assert md.index("Supports an abuse referral.") < md.index("> **Bottom line.**")  # decision statement first
    assert md.index("| # | Key judgment |") < md.index("> **Bottom line.**")           # table, then the callout
    assert "| A | Completely reliable |" in md and "almost certain" in md  # both scales present


def test_seed_comes_from_scope_claim_not_alphabetical_order():
    with tempfile.TemporaryDirectory() as tmp:
        c, md = _compose(_synthetic_case(tmp))
    assert c["seed"] == "seed-brand.example.com"
    assert "| Seed | `seed-brand.example.com` |" in md


def test_rule12_scrubs_internal_working_but_keeps_evidence_values():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    body = md.split("\\appendix")[0]
    for leak in ("WhoisXML", "IntelX", "urlscan", "[cld]", "[whois-api]", "evidence/x.json", "/intelx", "5 units"):
        assert leak not in body, f"internal working leaked: {leak}"
    for keep in ("persona@example.com", "seed-brand.example.com", "192.0.2.10", "Example Registrar LLC"):
        assert keep in md, f"evidence value lost: {keep}"


def test_prevalent_indicator_is_marked_excluded_and_sidecar_not_enumerated():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    reg = md.split("# Artifact register")[1].split("# Evidence ledger")[0]
    assert "`192.0.2.10`" in reg and "excluded" in [l for l in reg.splitlines() if "192.0.2.10" in l][0]
    assert "join key" in [l for l in reg.splitlines() if "persona@example.com" in l][0]
    assert "harvest.indicators" not in md.split("# Cluster enumeration")[1]


def test_third_parties_are_masked_but_operator_join_key_is_kept():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        json.dump(["Some Third Party"], open(os.path.join(case, "report_mask.json"), "w"))
        _, md = _compose(case)
    assert "thirdparty@example.org" not in md and "t***@example.org" in md
    assert "0987654321" not in md and "09********" in md
    assert "CASE-0002" not in md and "a related case" in md
    assert "persona@example.com" in md          # operator join key stays in clear
    assert "CASE-0001" in md                     # this case's own id is not masked


def test_composer_degrades_without_assessment_json():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        os.remove(os.path.join(case, "assessment.json"))
        c, md = _compose(case)
        rep = os.path.join(case, "report"); os.makedirs(rep)
        assert hr.fig_attribution_chain(c, rep) is None   # no evidence -> no chain figure, no crash
    assert "# Executive Summary — Key Judgments" in md and "\\appendix" in md
    assert "Impersonation of Example Brand" in md          # judgments still come from assessment.md


def test_sector_typology_from_domain_tokens():
    assert hr._sector("benhvienbachmai.example.com") == "Medical"
    assert hr._sector("tuyendungaeon-vn.example.com").startswith("Recruitment")
    assert hr._sector("hrvincom.example.com").startswith("Recruitment")
    assert hr._sector("pnjvn.example.com").startswith("Corporate")


def test_alternatives_table_parses_status_with_digits_and_words():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    alt = md.split("# Alternative analysis")[1].split("# Gaps")[0]
    assert "| **rejected** |" in alt and "| **cannot rule out** |" in alt


def test_glossary_lists_only_terms_the_report_uses():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    gl = md.split("# Glossary")[1]
    assert "| WHOIS / RDAP |" in gl and "| NATO Admiralty code |" in gl and "| TLP |" in gl
    assert "JARM" not in gl and "Headless browser" not in gl      # never mentioned -> never defined


def test_domain_dossiers_are_one_field_value_table_per_domain():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    prof = md.split("# Domain and infrastructure profiles")[1].split("# Cluster enumeration")[0]
    assert prof.count("### ") == 3 and prof.count("| Field | Value |") == 3
    assert prof.count("{.unnumbered .unlisted}") == 3                  # dossiers never flood the TOC
    assert "| Registrar · created | Example Registrar LLC · 2025-01-05 |" in prof
    assert "| Nameservers | ns1.example.net, ns2.example.net |" in prof


def test_registrant_country_drops_the_namibia_placeholder():
    import house_report_dossier as hre
    assert hre.registrant_country({"registrant_country": "VN"}) == "VN"
    assert hre.registrant_country({"registrant_country": "NAMIBIA"}) == ""          # WhoisXML 'NA' placeholder
    assert hre.registrant_country({"registrant_country": "NAMIBIA",
                                   "_raw": {"WhoisRecord": {"registrant": {"country": "NAMIBIA", "countryCode": "NA",
                                                                           "telephone": "84987654321"}}}}) == "VN"


_TIMELINE_MD = """## Evidence ledger

| When (UTC) | Host | What | Source |
|---|---|---|---|
| 2026-01-01 | a.example.com | registered — via registrar | WHOIS (A1) |

## Temporal correlations

### Registration cohorts (one provisioning sitting)

- **2026-01-01** — a.example.com, b.example.com
  - registrars: ['Example Registrar']
  - _registered on one day = one sitting; guidance text_

### Expiry / renewal cohorts (one payer)

- **2027-01-01** — a.example.com, b.example.com
  - independent_signal: False
  - distinct_creation_days: ['2026-01-01']
  - term_days: [365]
  - _same expiry only because they share a creation date + term_

### IP tenancy overlap

_Nothing found. That is a finding only if the inputs carried the dates to find it in._
"""


def test_temporal_correlations_are_tables_not_field_dumps():
    body, ledger = hr.condense_timeline_ledger(_TIMELINE_MD)
    assert "| 2026-01-01 | `a.example.com`, `b.example.com` | Example Registrar |" in body
    assert "mirror the registration cohorts exactly (same creation day, same 365-day term)" in body
    assert "No IP tenancy overlap could be derived" in body
    for raw in ("registrars: [", "independent_signal", "distinct_creation_days", "term_days", "guidance text"):
        assert raw not in body, f"raw tool field leaked: {raw}"
    assert "| 2026-01-01 | a.example.com | registered | WHOIS (A1) |" in ledger


def test_temporal_correlations_prefer_structured_events_and_survive_scrub():
    events = {"correlations": {
        "registration_cohorts": [{"date": "2026-01-01", "hosts": ["a.example.com", "b.example.com"],
                                  "registrars": ["Example Registrar"], "reading": "guidance"}],
        "expiry_cohorts": [{"expires": "2027-01-01", "hosts": ["a.example.com", "b.example.com"],
                            "distinct_creation_days": ["2026-01-01"], "independent_signal": False, "term_days": [365]}],
        "ip_tenancy": [], "shared_artifact_windows": [], "lapse_cohorts": []}}
    body, _ = hr.condense_timeline_ledger("", events)
    assert "| 2026-01-01 | `a.example.com`, `b.example.com` | Example Registrar |" in body
    assert "same 365-day term" in body and "guidance" not in body
    assert "No IP tenancy overlap, shared artifacts or abandonment cohorts could be derived" in body
    # fallback path, through the Rule-12 scrubber that eats trailing `[tag]`s (it took `[365]` before)
    body2, _ = hr.condense_timeline_ledger(hr.scrub(_TIMELINE_MD))
    assert "same creation day, same" in body2 and "same - -day" not in body2


def _png(width, height, rows):
    """Minimal stdlib PNG writer (8-bit RGB): `rows(y)` -> bytes of width*3 for scanline y."""
    import struct
    import zlib
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + rows(y) for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def test_landing_pages_section_and_capture_ledger():
    import house_report_captures as hre
    try:
        from PIL import Image
    except ImportError:          # zero-dep runner: the fit/near-empty branches are PIL-only by design
        Image = None
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        rep = os.path.join(case, "report")
        os.makedirs(rep)
        shots_dir = os.path.join(case, "screenshots")
        os.makedirs(shots_dir)
        w = 64
        # a page with content: top half black, bottom half white; and an (almost) blank sheet
        open(os.path.join(shots_dir, "seed-brand.example.com.png"), "wb").write(
            _png(w, 90, lambda y: (b"\x00\x00\x00" if y < 45 else b"\xff\xff\xff") * w))
        open(os.path.join(shots_dir, "sibling-b.example.com.png"), "wb").write(
            _png(w, 40, lambda y: (b"\x00\x00\x00" * 2 + b"\xff\xff\xff" * (w - 2)) if y == 2 else b"\xff\xff\xff" * w))
        shots = hre.existing_screenshots(case)
        assert sorted(shots) == ["seed-brand.example.com", "sibling-b.example.com"]
        assert all(len(s["sha256"]) == 64 for s in shots.values())
        hr.KB = os.path.join(tmp, "kb-empty")
        os.makedirs(hr.KB, exist_ok=True)
        c = hr.load_case(case)
        figs = {"captures": shots, "captures_skipped": [("sibling-a.example.com", "page did not render (timed out)")],
                "capture_hosts": c["hosts"], "rep_dir": rep}
        md = hr.compose(c, figs, "TLP:AMBER", "2026-01-01")
        assert os.path.exists(os.path.join(rep, "shot_seed-brand.example.com.png"))
        if Image is not None:
            assert not os.path.exists(os.path.join(rep, "shot_sibling-b.example.com.png"))   # near-empty: not a figure
            fitted = Image.open(os.path.join(rep, "shot_seed-brand.example.com.png"))
            assert fitted.size == (w, int(w * hre.SHOWN_ASPECT))                             # first-screen crop
            assert round(fitted.info.get("dpi", (0,))[0]) == 150                              # dpi so Word sizes it
    sec = md.split("## Landing pages")[1].split("# Infrastructure and lifecycle")[0]
    assert "![Landing page of `seed-brand.example.com` (the seed), captured" in sec
    assert "### seed-brand.example.com {.unnumbered .unlisted}" in sec               # never a TOC entry
    if Image is not None:
        assert "1 of 3 pages rendered with content" in sec
        assert "near-empty at capture time" in sec and "`sibling-b.example.com`" in sec
    else:
        assert "2 of 3 pages rendered with content" in sec
    assert "`sibling-a.example.com` — page did not render (timed out)." in sec
    assert md.index("## Landing pages") < md.index("# Infrastructure and lifecycle")   # inline in §V (Rule 15a)
    ledger = md.split("## Captured pages")[1].split("# Domain and infrastructure profiles")[0]
    for s in shots.values():
        assert f"`{s['sha256']}`" in ledger                                             # full hash, Rule 21, blank included


def test_archive_copies_are_captioned_as_such_and_outranked_by_live():
    import house_report_captures as hre
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        rep = os.path.join(case, "report")
        os.makedirs(rep)
        sd = os.path.join(case, "evidence", "screenshots", "sibling-a.example.com")
        os.makedirs(sd)
        w = 64
        content = _png(w, 90, lambda y: (b"\x00\x00\x00" if y < 45 else b"\xff\xff\xff") * w)
        open(os.path.join(sd, "a_urlscan.png"), "wb").write(content)
        open(os.path.join(sd, "b_live.png"), "wb").write(content)
        json.dump([
            {"url": "https://sibling-a.example.com/", "path": os.path.join(sd, "a_urlscan.png"), "host": "sibling-a.example.com",
             "captured_at": "2026-06-28T15:14:00Z", "sha256": "a" * 64, "source": "urlscan",
             "source_url": "https://urlscan.io/result/0000/", "archived_at": "2026-06-28T15:14:00Z"},
            {"url": "https://sibling-a.example.com/", "path": os.path.join(sd, "b_live.png"), "host": "sibling-a.example.com",
             "captured_at": "2026-01-01T00:00:00Z", "sha256": "b" * 64},
        ], open(os.path.join(case, "evidence", "screenshots", "manifest.json"), "w"))
        shots = hre.existing_screenshots(case)
        assert shots["sibling-a.example.com"]["source"] == "live"          # older live render outranks the archive copy
        # now only the archive copy remains
        json.dump([{"url": "https://sibling-a.example.com/", "path": os.path.join(sd, "a_urlscan.png"), "host": "sibling-a.example.com",
                    "captured_at": "2026-06-28T15:14:00Z", "sha256": "a" * 64, "source": "urlscan",
                    "source_url": "https://urlscan.io/result/0000/", "archived_at": "2026-06-28T15:14:00Z"}],
                  open(os.path.join(case, "evidence", "screenshots", "manifest.json"), "w"))
        shots = hre.existing_screenshots(case)
        hr.KB = os.path.join(tmp, "kb-empty")
        os.makedirs(hr.KB, exist_ok=True)
        c = hr.load_case(case)
        md = hr.compose(c, {"captures": shots, "captures_skipped": [], "capture_hosts": c["hosts"], "rep_dir": rep},
                        "TLP:AMBER", "2026-01-01")
    sec = md.split("## Landing pages")[1].split("# Infrastructure and lifecycle")[0]
    assert "1 of them from a public web-scan or web-archive copy" in sec
    assert "as recorded by a public web-scan service, scanned 2026-06-28 15:14 UTC; the live page did not render" in sec
    ledger = md.split("## Captured pages")[1].split("# Domain and infrastructure profiles")[0]
    assert "| public web-scan capture | https://urlscan.io/result/0000/ |" in ledger      # frozen public link, Rule 21


def test_analytic_charts_embed_where_they_belong_and_absences_are_stated():
    import house_report_charts as hrg
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        rep = os.path.join(case, "report")
        os.makedirs(rep)
        for n in ("fig_confidence", "fig_entity_map", "fig_registrations"):
            open(os.path.join(rep, n + ".png"), "wb").write(_png(8, 8, lambda y: b"\xff\xff\xff" * 8))
        charts = {"fig_confidence": os.path.join(rep, "fig_confidence.png"), "fig_entity_map": os.path.join(rep, "fig_entity_map.png"),
                  "fig_registrations": os.path.join(rep, "fig_registrations.png"), "fig_cooccurrence": None,
                  "_notes": {"fig_cooccurrence": "nothing to draw"}}
        hr.KB = os.path.join(tmp, "kb-empty")
        os.makedirs(hr.KB, exist_ok=True)
        c = hr.load_case(case)
        md = hr.compose(c, {"charts": charts}, "TLP:AMBER", "2026-01-01")
    meth = md.split("# Methodology")[1].split("# Scope and the seed")[0]
    assert "(fig_confidence.png)" in meth and "placed on both scales" in meth           # §II, under the scales
    clus = md.split("# The cluster")[1].split("# Infrastructure and lifecycle")[0]
    assert "(fig_entity_map.png)" in clus                                              # §V
    infra = md.split("# Infrastructure and lifecycle")[1].split("# Attribution")[0]
    assert "(fig_registrations.png){width=85%}" in infra
    assert "Not drawn for this build: shared-indicator matrix" in infra                 # Rule 19
    assert hrg.missing_md({n: "x" for n in hrg.FIGURES}) == ""


def test_archive_copy_before_registration_is_a_previous_owner_not_the_landing_page():
    import house_report_captures as hre
    e = {"source": "wayback", "archived_at": "2025-12-30T10:00:29Z", "captured_at": "2025-12-30T10:00:29Z"}
    assert hre.predates_registration(e, "2026-05-21 03:27:49 UTC")
    assert not hre.predates_registration(e, "2025-01-01 00:00:00 UTC")
    assert not hre.predates_registration({"source": "live", "captured_at": "2020-01-01T00:00:00Z"}, "2026-05-21")
    md = hre.landing_pages_md({}, [], "seed.example.com", [], "/tmp", lambda h: "Medical", lambda s: s)
    assert "## Landing pages" in md and "No landing page with content" in md


def test_urlscan_fallback_takes_the_host_itself_and_prefers_post_registration_scans():
    import house_report_captures as hre
    assert hre._same_host("https://www.a.example.com/x", "a.example.com")
    assert not hre._same_host("https://mail.a.example.com/", "a.example.com")     # a subdomain's scan is not the landing page
    # the newest scan wins among those on/after the registration; older ones only when nothing newer exists
    scans = [{"time": "2025-01-01T00:00:00Z"}, {"time": "2026-06-28T15:14:00Z"}, {"time": "2026-03-01T00:00:00Z"}]
    cut = "2026-05-21"
    after = [s for s in sorted(scans, key=lambda s: s["time"], reverse=True) if s["time"][:10] >= cut]
    assert [s["time"][:10] for s in after] == ["2026-06-28"]
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "CASE-0001")
        os.makedirs(case)
        assert not hre._recent_negative(case, "a.example.com")
        hre._record_negative(case, "a.example.com")
        assert hre._recent_negative(case, "a.example.com")                        # no re-check inside the TTL
        assert not hre._recent_negative(case, "b.example.com")


def test_capture_failure_reasons_are_a_closed_vocabulary():
    import house_report_captures as hre
    assert hre._reason(Exception("Page.goto: net::ERR_NAME_NOT_RESOLVED at https://x.example/")) == "DNS did not resolve"
    assert hre._reason(Exception("Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://x.example/")) == "not reachable through the research egress"
    assert hre._reason(Exception("Timeout 30000ms exceeded.")) == "timed out"
    leak = hre._reason(Exception("Executable doesn't exist at /root/.cache/ms-playwright/chromium"))
    assert leak == "browser error" and "/root" not in leak                            # Rule 12: no raw tool text


_TESTS = [
    test_structure_is_the_house_order_with_appendix_marker,
    test_seed_comes_from_scope_claim_not_alphabetical_order,
    test_rule12_scrubs_internal_working_but_keeps_evidence_values,
    test_prevalent_indicator_is_marked_excluded_and_sidecar_not_enumerated,
    test_alternatives_table_parses_status_with_digits_and_words,
    test_sector_typology_from_domain_tokens,
    test_third_parties_are_masked_but_operator_join_key_is_kept,
    test_composer_degrades_without_assessment_json,
    test_glossary_lists_only_terms_the_report_uses,
    test_domain_dossiers_are_one_field_value_table_per_domain,
    test_temporal_correlations_are_tables_not_field_dumps,
    test_landing_pages_section_and_capture_ledger,
    test_registrant_country_drops_the_namibia_placeholder,
    test_temporal_correlations_prefer_structured_events_and_survive_scrub,
    test_capture_failure_reasons_are_a_closed_vocabulary,
    test_archive_copies_are_captioned_as_such_and_outranked_by_live,
    test_analytic_charts_embed_where_they_belong_and_absences_are_stated,
    test_archive_copy_before_registration_is_a_previous_owner_not_the_landing_page,
    test_urlscan_fallback_takes_the_host_itself_and_prefers_post_registration_scans,
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
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
