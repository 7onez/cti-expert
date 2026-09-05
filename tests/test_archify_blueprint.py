"""Regression: the HTML report's Archify Blueprint (scripts/cti_archify.py) must survive a dense
estate. Archify's architecture type draws ~12 nodes; a one-operator / hundred-host case used to be
skipped outright. Now the estate folds to apex level (hosts under their registrable domain, PSL-
aware), the long tail folds into one node, apexes carrying a finding are kept over larger silent
ones, merged edges keep the strongest strength, and a hub-and-spoke graph is placed so no route
crosses an unrelated node (the shape Archify's clean-flow gate rejects). Synthetic data only."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import cti_archify as ca  # noqa: E402

ARCHIFY = os.path.join(ROOT, "scripts", "vendor", "archify", "bin", "archify.mjs")


def _dense_case():
    """1 operator + 63 hosts over 22 apexes, every host linked to the operator."""
    subjects = [{"id": "SUB-001", "type": "person", "label": "Operator Persona", "confidence": 95}]
    connections = []
    n = 2
    # 20 apexes with 3 hosts each (brand-01.example ... brand-20.example)
    for k in range(1, 21):
        for sub in ("www", "api", "shop"):
            sid = "SUB-%03d" % n
            n += 1
            subjects.append({"id": sid, "type": "domain", "label": "%s.brand-%02d.example" % (sub, k), "confidence": 60})
            connections.append({"id": "C%d" % n, "from_id": "SUB-001", "to_id": sid,
                                "relationship": "related_to", "strength": "possible"})
    # one single-host apex on a two-label public suffix, carrying the only HIGH finding
    subjects.append({"id": "SUB-HOT", "type": "domain", "label": "pay.example.co.uk", "confidence": 90})
    connections.append({"id": "CHOT", "from_id": "SUB-001", "to_id": "SUB-HOT",
                        "relationship": "operates", "strength": "confirmed"})
    # a second, weaker edge to the same host — merged edge must keep "confirmed"
    connections.append({"id": "CHOT2", "from_id": "SUB-HOT", "to_id": "SUB-001",
                        "relationship": "related_to", "strength": "possible"})
    # VNNIC second-level suffix: two hosts under example.id.vn must fold to that apex, never to `id.vn`
    for sid, host in (("SUB-IDVN1", "example.id.vn"), ("SUB-IDVN2", "api.example.id.vn")):
        subjects.append({"id": sid, "type": "domain", "label": host, "confidence": 60})
        connections.append({"id": "C" + sid, "from_id": "SUB-001", "to_id": sid,
                            "relationship": "related_to", "strength": "possible"})
    findings = [{"id": "FND-001", "subject_id": "SUB-HOT", "weight": "HIGH", "title": "payment page"}]
    return {"case": {"id": "CASE-0001", "label": "CASE-0001", "subject": "brand-01.example"},
            "subjects": subjects, "connections": connections, "findings": findings}


def test_dense_estate_is_skipped_at_host_level_but_fits_at_apex_level():
    data = _dense_case()
    full = ca.build_architecture_ir(data)
    assert not ca.fits_blueprint(full), "65-node graph must exceed BLUEPRINT_LIMITS"
    folded, stats = ca.collapse_estate(data)
    ir = ca.build_architecture_ir(folded, collapse=stats)
    assert ca.fits_blueprint(ir), ca.density(ir)
    assert len(ir["components"]) == ca.BLUEPRINT_LIMITS["components"]
    assert stats["hosts"] == 63 and stats["apexes"] == 22 and stats["subjects"] == 64
    assert stats["shown_apexes"] + stats["folded_apexes"] == 22
    shown_hosts = sum(int(s["sublabel"].split()[-2]) if s["sublabel"].startswith("Estate") else 1
                      for s in folded["subjects"] if s["type"] == "domain" and s["id"] != ca.APEX_TAIL_ID)
    assert shown_hosts + stats["folded_hosts"] == 63
    sel, note = ca.select_ir(data, "auto")
    assert sel is not None and note.startswith("apex level:"), note


def test_force_mode_widens_to_the_grid_limit_instead_of_offering_a_dead_option():
    data = _dense_case()
    ir, note = ca.select_ir(data, "force")
    assert ir is not None and "forced" in note, note
    comps, rels, deg = ca.density(ir)
    # 1 hub + 22 apexes fit the 25-node grid, so nothing is folded into a tail node
    assert comps == 23 and not any(c["label"].startswith("+") for c in ir["components"]), comps
    assert ir["layout"]["cols"] <= ca.ARCHIFY_MAX_COLS
    assert not ca.fits_blueprint(ir), "force must actually go past BLUEPRINT_LIMITS"
    # past the grid, force folds the tail like auto does — at the wider budget
    big = _dense_case()
    for k in range(50):
        sid = "SUB-X%02d" % k
        big["subjects"].append({"id": sid, "type": "domain", "label": "x%02d.example" % k, "confidence": 50})
        big["connections"].append({"from_id": "SUB-001", "to_id": sid, "strength": "possible"})
    big_ir, big_note = ca.select_ir(big, "force")
    assert ca.density(big_ir)[0] == ca.FORCE_MAX_NODES and big_ir["layout"]["cols"] == ca.ARCHIFY_MAX_COLS, big_note
    assert any(c["label"].startswith("+") for c in big_ir["components"])
    hub = next(c for c in ir["components"] if c["label"] == "Operator Persona")
    rows = {}
    for c in ir["components"]:
        rows.setdefault(c["row"], []).append(c["id"])
    assert rows[hub["row"]] == [hub["id"]] and sorted(rows) == [hub["row"] - 1, hub["row"], hub["row"] + 1]
    small_ir, small_note = ca.select_ir({"subjects": data["subjects"][:5], "connections": data["connections"][:4]}, "force")
    assert small_ir is not None and len(small_ir["components"]) == 5 and "full graph" in small_note


def test_hosts_fold_under_their_registrable_apex_including_two_label_suffixes():
    folded, _ = ca.collapse_estate(_dense_case())
    labels = {s["label"]: s for s in folded["subjects"]}
    assert "example.co.uk" in labels, sorted(labels)          # pay.example.co.uk -> example.co.uk, not co.uk
    assert labels["example.co.uk"]["sublabel"] == "Domain"
    assert "id.vn" not in labels, "id.vn is a VNNIC public suffix, not an apex"
    tail = next(s for l, s in labels.items() if l.startswith("+"))
    assert "example.id.vn" in labels or "example.id.vn" in tail["notes"], (sorted(labels), tail["notes"])
    brand = next(s for l, s in labels.items() if l.startswith("brand-"))
    assert brand["sublabel"] == "Estate · 3 hosts"
    assert "www." + brand["label"] in brand["notes"]
    assert not any("." in l and l.count(".") > 1 for l in labels if l.startswith("brand-")), "no host survived at host level"


def test_apex_with_a_finding_outranks_larger_silent_apexes_and_keeps_its_tag():
    folded, stats = ca.collapse_estate(_dense_case())
    assert stats["folded_apexes"] > 0
    ir = ca.build_architecture_ir(folded, collapse=stats)
    hot = next(c for c in ir["components"] if c["label"] == "example.co.uk")
    assert hot.get("tag") == "HIGH"
    tail = next(c for c in ir["components"] if c["label"].startswith("+"))
    assert tail["label"] == "+%d more apexes" % stats["folded_apexes"]
    assert tail["sublabel"] == "%d hosts" % stats["folded_hosts"]


def test_merged_parallel_edges_keep_the_strongest_strength():
    folded, _ = ca.collapse_estate(_dense_case())
    hot_id = next(s["id"] for s in folded["subjects"] if s["label"] == "example.co.uk")
    edges = [c for c in folded["connections"] if {c["from_id"], c["to_id"]} == {"SUB-001", hot_id}]
    assert len(edges) == 1 and edges[0]["strength"] == "confirmed", edges
    ir = ca.build_architecture_ir(folded)
    slug = {c["label"]: c["id"] for c in ir["components"]}
    conn = next(c for c in ir["connections"] if {c["from"], c["to"]} == {slug["Operator Persona"], slug["example.co.uk"]})
    assert conn["variant"] == "emphasis"


def test_hub_sits_alone_in_its_row_with_spokes_in_one_row_above_and_below():
    folded, stats = ca.collapse_estate(_dense_case())
    ir = ca.build_architecture_ir(folded, collapse=stats)
    hub = next(c for c in ir["components"] if c["label"] == "Operator Persona")
    rows = {}
    for c in ir["components"]:
        rows.setdefault(c["row"], []).append(c["id"])
    assert rows[hub["row"]] == [hub["id"]], "hub must own its row so no vertical run crosses a spoke"
    assert sorted(rows) == [hub["row"] - 1, hub["row"], hub["row"] + 1], sorted(rows)
    assert ir["layout"]["cols"] <= ca.ARCHIFY_MAX_COLS


def test_vendored_archify_renders_the_apex_blueprint():
    node = shutil.which("node")
    if not node or not os.path.isfile(ARCHIFY):
        return  # renderer optional; the geometric contract above is the offline stand-in
    folded, stats = ca.collapse_estate(_dense_case())
    ir = ca.build_architecture_ir(folded, collapse=stats)
    tmp = tempfile.mkdtemp(prefix="cti-archify-test-")
    try:
        ir_path = os.path.join(tmp, "ir.json")
        out = os.path.join(tmp, "d.html")
        with open(ir_path, "w", encoding="utf-8") as f:
            json.dump(ir, f)
        proc = subprocess.run([node, ARCHIFY, "render", "architecture", ir_path, out],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0 and os.path.isfile(out), (proc.stderr or proc.stdout)[-600:]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_small_case_needs_no_collapse_and_no_domain_case_folds_nothing():
    small = {"subjects": [{"id": "A", "type": "person", "label": "P"},
                          {"id": "B", "type": "domain", "label": "www.example.com", "confidence": 70},
                          {"id": "C", "type": "email", "label": "persona@example.com"}],
             "connections": [{"from_id": "A", "to_id": "B", "strength": "probable"},
                             {"from_id": "A", "to_id": "C", "strength": "confirmed"}]}
    ir = ca.build_architecture_ir(small)
    assert ca.fits_blueprint(ir)
    assert {c["label"] for c in ir["components"]} == {"P", "www.example.com", "persona@example.com"}
    assert next(c for c in ir["components"] if c["label"] == "www.example.com")["sublabel"] == "Domain · 70%"
    assert ca.collapse_estate({"subjects": small["subjects"][::2], "connections": []}) == (None, None)


_TESTS = [
    test_dense_estate_is_skipped_at_host_level_but_fits_at_apex_level,
    test_hosts_fold_under_their_registrable_apex_including_two_label_suffixes,
    test_apex_with_a_finding_outranks_larger_silent_apexes_and_keeps_its_tag,
    test_merged_parallel_edges_keep_the_strongest_strength,
    test_hub_sits_alone_in_its_row_with_spokes_in_one_row_above_and_below,
    test_force_mode_widens_to_the_grid_limit_instead_of_offering_a_dead_option,
    test_vendored_archify_renders_the_apex_blueprint,
    test_small_case_needs_no_collapse_and_no_domain_case_folds_nothing,
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
