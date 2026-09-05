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


def test_cooccurrence_matrix_drops_excluded_indicators_and_keeps_join_keys():
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    try:
        import cti_docx_heatmaps as hm
    except ImportError:          # zero-dep runner without matplotlib/numpy: the figure path is optional there
        return
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "cases", "CASE-0001")
        os.makedirs(os.path.join(case, "whois"))
        os.makedirs(os.path.join(tmp, "knowledge"))
        hosts = ["a.example.com", "b.example.com", "c.example.com"]
        for h in hosts:
            json.dump({"registrant_email": "persona@example.com", "registrant_phone": "+1.2025550100"},
                      open(os.path.join(case, "whois", h + ".json"), "w"))
        json.dump({"edges": [{"source": h, "target": "favicon:123456789", "rel": "favicon"} for h in hosts]
                   + [{"source": h, "target": "js_bundle:abcdef", "rel": "js_bundle"} for h in hosts[:2]]},
                  open(os.path.join(case, "case_graph.json"), "w"))
        open(os.path.join(tmp, "knowledge", "reference.jsonl"), "w").write(
            json.dumps({"type": "favicon", "value": "favicon:123456789", "verdict": "benign"}) + "\n")
        data = {"subjects": [{"type": "domain", "label": h} for h in hosts], "connections": [],
                "ioc_exclude": ["abcdef"]}
        dom, shared, mat = hm.build_cooccurrence(data, case, cap=None)
    assert dom == hosts
    assert shared == ["registrant_email:persona@example.com", "registrant_phone:+1.2025550100"]   # join keys only
    assert not any("favicon" in t or "js_bundle" in t for t in shared)       # benign ledger + ioc_exclude honoured
    assert hm._domains({"subjects": [{"type": "domain", "label": f"d{i}.example.com"} for i in range(30)]}, None).__len__() == 30
    assert len(hm._domains({"subjects": [{"type": "domain", "label": f"d{i}.example.com"} for i in range(30)]})) == 24


def test_archive_negative_is_cached_only_when_both_sources_answered():
    import house_report_captures as hre
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "cases", "CASE-0001")
        os.makedirs(case)
        calls = []
        orig_u, orig_w = hre._urlscan_capture, hre._wayback_capture
        try:
            hre._urlscan_capture = lambda *a, **k: (_ for _ in ()).throw(hre._Transient("throttled"))
            hre._wayback_capture = lambda *a, **k: None
            hre.time.sleep = lambda s: calls.append(s)
            assert hre._archive_copy("x.example.com", case, "CASE-0001", tmp, None, 5) is None
            assert not hre._recent_negative(case, "x.example.com")             # transient -> not cached
            hre._urlscan_capture = lambda *a, **k: None
            assert hre._archive_copy("x.example.com", case, "CASE-0001", tmp, None, 5) is None
            assert hre._recent_negative(case, "x.example.com")                 # both answered "no copy" -> cached
        finally:
            hre._urlscan_capture, hre._wayback_capture = orig_u, orig_w
            import time as _t
            hre.time.sleep = _t.sleep


def test_capture_failure_reasons_are_a_closed_vocabulary():
    import house_report_captures as hre
    assert hre._reason(Exception("Page.goto: net::ERR_NAME_NOT_RESOLVED at https://x.example/")) == "DNS did not resolve"
    assert hre._reason(Exception("Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://x.example/")) == "not reachable through the research egress"
    assert hre._reason(Exception("Timeout 30000ms exceeded.")) == "timed out"
    leak = hre._reason(Exception("Executable doesn't exist at /root/.cache/ms-playwright/chromium"))
    assert leak == "browser error" and "/root" not in leak                            # Rule 12: no raw tool text


def test_near_empty_live_capture_is_held_provisional_then_rerendered_next_build():
    """Audit item 2 / red-team H4: a near-empty live render (server state, not the page) is NOT
    archived on sight — it is recorded provisional and re-rendered on the NEXT build; only then does
    the archive stand-in apply, and a host is never silently dropped."""
    import types
    import house_report_captures as hre
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "cases", "CASE-0001")
        shots = os.path.join(case, "evidence", "screenshots")
        os.makedirs(shots)
        empty_png = os.path.join(shots, "a_live.png")
        open(empty_png, "wb").write(b"\x89PNG-empty")
        existing = {"a.example.com": {"host": "a.example.com", "path": empty_png, "source": "live"}}
        renders = []
        fake_ws = types.SimpleNamespace(capture_screenshot=lambda url, **k: (renders.append(url), {
            "url": url, "path": os.path.join(shots, "a_fresh.png"), "host": "a.example.com",
            "captured_at": "2026-09-03T00:00:00Z", "sha256": "f" * 64})[1])
        saved = (sys.modules.get("wp_screenshot"), sys.modules.get("playwright"), hre.egress_policy,
                 hre._near_empty, hre._archive_copy, hre._entry)
        archive_calls = []
        try:
            sys.modules["wp_screenshot"] = fake_ws
            sys.modules.setdefault("playwright", types.ModuleType("playwright"))
            hre.egress_policy = lambda: {"mode": "direct", "pool": [None], "why": ""}
            hre._near_empty = lambda p: p.endswith("a_live.png")          # only the old render is empty
            hre._archive_copy = lambda *a, **k: (archive_calls.append(a[0]), None)[1]
            hre._entry = lambda h, e: dict(e, host=h)
            # build 1: first sighting -> held provisional, NO archive, NO drop
            new, skipped = hre.capture_missing(case, ["a.example.com"], existing, archives=True)
            assert new == {} and renders == [] and archive_calls == []
            assert any(h == "a.example.com" and "held provisional" in why for h, why in skipped), skipped
            prov = hre.load_provisional(case)
            assert prov["a.example.com"]["builds"] == 1
            # build 2: re-render live FIRST; a full render replaces the empty one and clears the hold
            new, skipped = hre.capture_missing(case, ["a.example.com"], existing, archives=True)
            assert renders == ["https://a.example.com/"] and archive_calls == []
            assert new["a.example.com"]["path"].endswith("a_fresh.png")
            assert "a.example.com" not in hre.load_provisional(case)
            # build 2 variant: re-render still empty -> archive fallback; archive empty too -> HELD, not dropped
            hre.save_provisional(case, {"a.example.com": {"since": "2026-09-02T00:00:00Z", "builds": 1}})
            hre._near_empty = lambda p: True
            renders.clear()
            new, skipped = hre.capture_missing(case, ["a.example.com"], existing, archives=True)
            assert renders == ["https://a.example.com/"] and archive_calls == ["a.example.com"]
            assert new == {}
            assert any(h == "a.example.com" and "held provisional" in why for h, why in skipped), skipped
            assert hre.load_provisional(case)["a.example.com"]["builds"] == 2
            # --no-archive-fallback: the hold + re-render still run (they are not archive steps); only
            # the stand-in is skipped, and the host is still surfaced as held, never dropped
            renders.clear(); archive_calls.clear()
            new, skipped = hre.capture_missing(case, ["a.example.com"], existing, archives=False)
            assert renders == ["https://a.example.com/"] and archive_calls == []
            assert any(h == "a.example.com" and "archive stand-ins disabled" in why for h, why in skipped), skipped
            assert hre.load_provisional(case)["a.example.com"]["builds"] == 3
        finally:
            (ws, pw, hre.egress_policy, hre._near_empty, hre._archive_copy, hre._entry) = saved
            if ws is not None:
                sys.modules["wp_screenshot"] = ws
            else:
                sys.modules.pop("wp_screenshot", None)
            if pw is None:
                sys.modules.pop("playwright", None)


def test_urlscan_screenshot_fetch_sends_the_key_when_present():
    import house_report_captures as hre
    import urllib.request
    seen = {}

    class _R:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"png"
    orig_build = urllib.request.build_opener

    class _Opener:
        def open(self, req, timeout=None):
            seen.update({k.lower(): v for k, v in req.headers.items()})
            return _R()
    urllib.request.build_opener = lambda *h: _Opener()
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))
    import wp_common
    orig_secret = wp_common._secret
    try:
        wp_common._secret = lambda name, *a: "deadbeef-test-key" if name == "URLSCAN_API_KEY" else None
        hre._http_get("https://urlscan.io/screenshots/0000.png", None)
        assert seen.get("api-key") == "deadbeef-test-key"
        seen.clear()
        hre._http_get("https://web.archive.org/web/2/x", None)
        assert "api-key" not in seen                                        # never leak the key elsewhere
    finally:
        urllib.request.build_opener = orig_build
        wp_common._secret = orig_secret


def test_urlscan_verdict_rows_parse_as_b2_evidence_in_the_ledger():
    """The pipeline's urlscan verdict rows (intel._urlscan_verdict_evidence) must carry the shape the
    house report's evidence ledger parses: numbered `E<n>`, a [B2] grade, ' — ' before the source."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "intel_pipeline_canon", os.path.join(ROOT, "intel_engine", "tools", "intel.py"))
    ip = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ip)
    results = [
        {"meta": {"host": "sibling-a.example.com"}, "pivots": [{"kind": "domain", "value": "sibling-a.example.com",
         "live_results": {"urlscan_verdict": {"score": 98, "malicious": True, "brands": ["Example Brand"],
                                              "engines": {"score": 98, "malicious": True, "total": 3, "malicious_total": 2},
                                              "labels": ["visual.brandai", "hosting.cdn"], "result": "https://urlscan.io/result/0000/"}}}]},
        # a BENIGN scan (the measured example.com shape: score 0, structural labels only) -> NO row
        {"meta": {"host": "sibling-b.example.com"}, "related_urlscan": {"verdict": {
            "score": 0, "malicious": False, "brands": [], "engines": None,
            "labels": ["domain.apexdomain", "content.rootdir", "hosting.cdn"]}}},
        # engine sentinel (score -99, 0 engines) but a real overall score -> row without engine text
        {"meta": {"host": "sibling-d.example.com"}, "related_urlscan": {"verdict": {
            "score": 40, "malicious": False, "brands": [],
            "engines": {"score": -99, "malicious": False, "total": 0, "malicious_total": 0}, "labels": []}}},
        {"meta": {"host": "sibling-c.example.com"}, "pivots": []},                    # no verdict -> no row
    ]
    rows = ip._urlscan_verdict_evidence(results, start=4)
    assert len(rows) == 2 and rows[0].startswith("E4 [B2] ") and rows[1].startswith("E5 [B2] ")
    assert "engine score 98/100 (2/3 engines malicious)" in rows[0] and "labels visual.brandai" in rows[0]
    assert "hosting.cdn" not in rows[0]                                    # structural label never quoted as evidence
    assert "a lead, not proof" in rows[0]
    assert not any("sibling-b" in r for r in rows)                        # benign scan: no row at all
    assert "sibling-d" in rows[1] and "overall score 40/100" in rows[1] and "-99" not in rows[1] and "engine" not in rows[1]
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        a = json.load(open(os.path.join(case, "assessment.json")))
        a["evidence"] = a["evidence"] + rows
        json.dump(a, open(os.path.join(case, "assessment.json"), "w"))
        _, md = _compose(case)
    ledger = md.split("# Evidence ledger")[1].split("\n# ")[0]
    # Rule 12 scrubs the vendor name to its public class ("web-scan index") — the row must survive that
    line = next(l for l in ledger.splitlines() if "verdict for sibling-a.example.com" in l)
    assert "| B2 |" in line, line                                          # grade extracted from the bracket
    assert "E4 [B2]" not in line and "urlscan" not in line.lower()         # prefix stripped, vendor scrubbed


_ERA_EVENTS = {"events": [
    # sibling-a changed hands: previous registrant (privacy) 2021-11 → operator 2026-05-21
    {"host": "sibling-a.example.com", "kind": "registrant_era", "start": "2021-11-02T00:00:00Z",
     "end": "2026-05-21T00:00:00Z", "label": "registrant: privacy@proxy.invalid",
     "value": {"identity": "privacy@proxy.invalid", "registrar": "Mid Registrar"}, "url": "https://rdap.org/domain/x"},
    {"host": "sibling-a.example.com", "kind": "registrant_era", "start": "2026-05-21T00:00:00Z",
     "end": "2027-05-21T00:00:00Z", "label": "registrant: persona@example.com",
     "value": {"identity": "persona@example.com", "registrar": "Example Registrar LLC"}, "url": "https://rdap.org/domain/x"},
    # the seed has ONE era — must be omitted from the table and keep its WHOIS `created` cutoff
    {"host": "seed-brand.example.com", "kind": "registrant_era", "start": "2025-02-09T00:00:00Z",
     "end": "2026-01-05T00:00:00Z", "label": "registrant: persona@example.com",
     "value": {"identity": "persona@example.com", "registrar": "Example Registrar LLC"}, "url": "https://rdap.org/domain/x"},
]}


def test_registrant_eras_table_lists_only_hosts_that_changed_hands():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        hr.KB = os.path.join(tmp, "kb-empty")
        os.makedirs(hr.KB, exist_ok=True)
        c = hr.load_case(case)
        md = hr.compose(c, {"timeline_events": _ERA_EVENTS}, "TLP:AMBER", "2026-01-01")
    assert "## Registrant eras" in md
    sec = md.split("## Registrant eras")[1].split("\n# ")[0]
    assert "| `sibling-a.example.com` | 2021-11-02 | 2026-05-21 |" in sec
    assert "| `sibling-a.example.com` | 2026-05-21 | 2027-05-21 |" in sec
    assert "reactivation" in sec                                     # the current era took over a used name
    assert "seed-brand.example.com" not in sec                      # single-era host is not a signal
    # the PREVIOUS registrant is a third party → masked; the operator's join key (>= 2 hosts) stays
    assert "privacy@proxy.invalid" not in sec and "p***@proxy.invalid" in sec
    assert "persona@example.com" in sec
    # no era data at all → the section is simply absent (Rule 19 handled by the timeline block)
    with tempfile.TemporaryDirectory() as tmp:
        _, md2 = _compose(_synthetic_case(tmp))
    assert "## Registrant eras" not in md2


def test_capture_cutoff_is_the_current_era_start_only_for_multi_era_hosts():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        hr.KB = os.path.join(tmp, "kb-empty")
        os.makedirs(hr.KB, exist_ok=True)
        c = hr.load_case(case)
        figs = {"timeline_events": _ERA_EVENTS}
        # multi-era host: cutoff moves from WHOIS `created` (2025-01-05) to the current era start
        assert hr.era_start_of(c, figs, "sibling-a.example.com") == "2026-05-21"
        # single-era host: keeps WHOIS `created`, NOT its history record's later `updated` date
        assert hr.era_start_of(c, figs, "seed-brand.example.com").startswith("2025-01-05")
        # no events at all: plain `created`
        assert hr.era_start_of(c, {}, "sibling-b.example.com").startswith("2025-01-05")
        # a `created` inside the previous era (a transfer, OR a drop-catch whose reset date sits
        # before the new identity's first WHOIS record) does NOT move the cutoff earlier — the later
        # era start is the conservative choice: never caption a previous owner's page as the operator's
        c["whois"]["sibling-a.example.com"] = dict(c["whois"]["sibling-a.example.com"], created="2026-05-10 00:00:00 UTC")
        assert hr.era_start_of(c, figs, "sibling-a.example.com") == "2026-05-21"
    import house_report_captures as hre
    # an archive copy of sibling-a taken in 2025-12 is AFTER `created` but BEFORE the current era →
    # it is a previous registrant's page under the era-aware cutoff
    e = {"source": "wayback", "archived_at": "2025-12-30T10:00:29Z", "captured_at": "2025-12-30T10:00:29Z"}
    assert hre.predates_registration(e, "2026-05-21")
    assert not hre.predates_registration(e, "2025-01-05 00:00:00 UTC")


def test_registrant_eras_fold_same_day_flaps_and_placeholders_and_current_era():
    """Real-data artefacts from the first live rebuild: WhoisXML returns several records per era
    (registrant / registry / privacy relay, same day) -> zero-length 'eras' and same-day flaps; the
    registrar's own name in the registrant field was classed `named`; the operator's current era was
    absent. The fold must yield one row per real era, class placeholders, and append the current era."""
    import house_report_correlations as hrx
    ev = {"events": [
        {"host": "drop.example.com", "kind": "registrant_era", "start": "2015-07-04T00:00:00Z", "end": "2015-07-04T00:00:00Z",
         "value": {"identity": "r@enom-role.example", "registrar": "ENOM, INC."}},
        {"host": "drop.example.com", "kind": "registrant_era", "start": "2015-07-04T00:00:00Z", "end": "2021-11-23T00:00:00Z",
         "value": {"identity": "d@whoisguard.example", "registrar": "ENOM, INC."}},
        {"host": "drop.example.com", "kind": "registrant_era", "start": "2021-11-23T00:00:00Z", "end": "2021-11-23T00:00:00Z",
         "value": {"identity": "8@withheldforprivacy.example", "registrar": "NAMECHEAP INC"}},
        {"host": "drop.example.com", "kind": "registrant_era", "start": "2021-11-23T00:00:00Z", "end": "2026-05-21T00:00:00Z",
         "value": {"identity": "NameCheap, Inc.", "registrar": "NameCheap, Inc."}},
    ]}
    eras = hrx.registrant_eras_from_events(ev)["drop.example.com"]
    assert [(e["start"], e["end"]) for e in eras] == [("2015-07-04", "2021-11-23"), ("2021-11-23", "2026-05-21")], eras
    assert not any(e["start"] == e["end"] for e in eras)                      # no zero-length rows
    assert hrx._era_class("NameCheap, Inc.", None, "NameCheap, Inc.") == "placeholder"
    assert hrx._era_class("owner@example.com", None, "NameCheap, Inc.") == "named"
    md = hrx.registrant_eras_md(ev, lambda x: x, is_privacy=lambda v: "privacy" in v or "whoisguard" in v,
                                whois={"drop.example.com": {"registrant_email": "persona@example.com",
                                                            "created": "2026-05-21 03:27:49 UTC", "registrar": "Global Registrar LLC"}})
    rows = [l for l in md.splitlines() if l.startswith("| `drop")]
    assert len(rows) == 3, md
    assert "| 2026-05-21 | current | persona@example.com | Global Registrar LLC | named · current · reactivation |" in rows[-1], rows[-1]
    assert "| privacy |" in rows[1] and "NameCheap, Inc. | NameCheap, Inc." not in md   # placeholder folded away, class honest
    # the capture CUTOFF: when history stops at the previous owner's era, the current registration's
    # `created` is later and must win — otherwise the previous owner's parking page is captioned as ours
    assert hrx.era_start_of(ev, "drop.example.com", fallback="2026-05-21 03:27:49 UTC") == "2026-05-21"
    assert hrx.era_start_of(ev, "drop.example.com", fallback="2020-01-01") == "2021-11-23"   # created earlier than the last era: era wins
    assert hrx.era_start_of(ev, "single.example.com", fallback="2025-01-05") == "2025-01-05"


def test_expansion_leaves_are_bounding_hosts_not_estate():
    """A host at the loop's expansion depth (state.json hops / clusters.json related_hosts) is
    collected to BOUND the estate: it gets no dossier and no WHOIS era, its registrant masks like any
    third party, and it is listed once under 'Bounding hosts — collected, not attributed'."""
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        leaf = "client-of-agency.example.net"
        json.dump({"meta": {"host": leaf, "fetched_with": "urllib"}, "artifacts": {}, "pivots": []},
                  open(os.path.join(case, "raw", leaf + ".json"), "w"))
        json.dump(dict(_WHOIS, registrant_email="leafowner@example.net", registrant_phone="0900000099"),
                  open(os.path.join(case, "whois", leaf + ".json"), "w"))
        json.dump({"hops": {"seed-brand.example.com": 0, "sibling-a.example.com": 1, "sibling-b.example.com": 1, leaf: 2},
                   "expansion_depth": 2}, open(os.path.join(case, "state.json"), "w"))
        cl = json.load(open(os.path.join(case, "clusters.json")))
        cl["related_hosts"] = [leaf]
        json.dump(cl, open(os.path.join(case, "clusters.json"), "w"))
        c, md = _compose(case)
    assert leaf not in c["hosts"] and c["related_hosts"] == [leaf]
    assert leaf not in c["whois"], "a leaf's WHOIS never feeds the estate identity (_KEEP)"
    assert "leafowner@example.net" not in hr._KEEP
    sec = md.split("## Bounding hosts — collected, not attributed")[1].split("\n## ")[0]
    assert "`example.net`" in sec and "| 1 | 2 |" in sec
    prof = md.split("# Domain and infrastructure profiles")[1].split("# Cluster enumeration")[0]
    assert leaf not in prof, "no dossier for a bounding host"
    assert md.count(leaf) == 0, "a leaf host name never appears (the bounding table keys on the apex)"

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
    test_cooccurrence_matrix_drops_excluded_indicators_and_keeps_join_keys,
    test_archive_negative_is_cached_only_when_both_sources_answered,
    test_registrant_eras_table_lists_only_hosts_that_changed_hands,
    test_registrant_eras_fold_same_day_flaps_and_placeholders_and_current_era,
    test_capture_cutoff_is_the_current_era_start_only_for_multi_era_hosts,
    test_near_empty_live_capture_is_held_provisional_then_rerendered_next_build,
    test_urlscan_screenshot_fetch_sends_the_key_when_present,
    test_urlscan_verdict_rows_parse_as_b2_evidence_in_the_ledger,
    test_expansion_leaves_are_bounding_hosts_not_estate,
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
