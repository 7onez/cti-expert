#!/usr/bin/env python3
"""RULE 5 classification check for cluster corroboration.

The rule this repo states everywhere: ONE shared artifact is a LEAD, TWO independent ones make a
cluster. Before this test that rule lived only in prose, so a component resting on a single
artifact was reported identically to one resting on five — and a false merge names an innocent
party.

Covers both directions plus the managed-provider noise case, per CLAUDE.md RULE 5.
Pure: no network, no KB, no case data. rank_relations is stubbed with synthetic relations.
"""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("intel", ROOT / "intel_engine" / "tools" / "intel.py")
sys.path.insert(0, str(ROOT / "intel_engine" / "tools"))
intel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intel)

FAIL = []


def check(cond, msg):
    if not cond:
        FAIL.append(msg)


def run(clusters, relations=None, with_raw=True):
    """Run _corroboration with rank_relations stubbed to return `relations`."""
    with tempfile.TemporaryDirectory() as td:
        if with_raw:
            os.makedirs(os.path.join(td, "raw"))
            for i in range(2):
                with open(os.path.join(td, "raw", f"h{i}.json"), "w") as fh:
                    json.dump({"meta": {"host": f"h{i}"}, "artifacts": {}}, fh)

        real = intel.subprocess.run

        class R:
            returncode = 0
            stdout = json.dumps({"relations": relations or []})
            stderr = ""

        intel.subprocess.run = lambda *a, **k: R()
        try:
            return intel._corroboration(td, clusters)
        finally:
            intel.subprocess.run = real


# ── 1. ONE shared artifact => LEAD, never an attributed cluster ────────────────────────
c = run([{"id": 1, "size": 2, "singleton": False, "domains": ["site-a.example", "site-b.example"],
          "binding_indicators": [{"indicator": "favicon:123456789"}]}],
        relations=[{"a": "site-a.example", "b": "site-b.example",
                    "signals": ["favicon"], "assessment": "weak_lead"}])
cor = c[0]["corroboration"]
check(cor["independent_artifacts"] == 1, "a single shared artifact must count as 1")
check(cor["verdict"].startswith("LEAD ONLY"), "a single artifact must be labelled LEAD ONLY")
check("not proof" in cor["verdict"], "the LEAD verdict must say a lead is not proof")

# ── 2. TWO independent artifacts => corroborated cluster ───────────────────────────────
c = run([{"id": 1, "size": 2, "singleton": False, "domains": ["site-a.example", "site-b.example"],
          "binding_indicators": [{"indicator": "favicon:1"}, {"indicator": "ga4:G-XXXXXXXXXX"}]}],
        relations=[{"a": "site-a.example", "b": "site-b.example",
                    "signals": ["favicon", "google_analytics_ga4"],
                    "assessment": "same_operator_likely"}])
cor = c[0]["corroboration"]
check(cor["independent_artifacts"] == 2, "two distinct signals must count as 2")
check(cor["verdict"].startswith("CORROBORATED"), "two independent artifacts must be CORROBORATED")
check(cor["assessment"] == "same_operator_likely",
      "rank_relations' own assessment must be carried through, not re-invented")

# ── 3. MANAGED-PROVIDER NOISE: shared infrastructure must not manufacture corroboration ─
# rank_relations applies the noise denylist upstream, so a pair linked only by shared managed
# DNS/CDN comes back with no surviving signals. That must read as UNCORROBORATED, not as a link.
c = run([{"id": 1, "size": 2, "singleton": False, "domains": ["site-a.example", "site-b.example"],
          "binding_indicators": []}],
        relations=[{"a": "site-a.example", "b": "site-b.example",
                    "signals": [], "assessment": "weak_lead"}])
cor = c[0]["corroboration"]
check(cor["independent_artifacts"] == 0, "a noise-only pair must corroborate nothing")
check(cor["verdict"].startswith("UNCORROBORATED"),
      "a pair surviving only on filtered noise must be UNCORROBORATED")

# ── 4. KB fallback counts indicator TYPES, not values ──────────────────────────────────
# Three GA IDs from one operator are ONE artifact class. Counting values would let a single
# artifact type masquerade as corroboration and manufacture a cluster.
c = run([{"id": 1, "size": 2, "singleton": False, "domains": ["site-a.example", "site-b.example"],
          # Three values of ONE indicator type. Favicon hashes, not GA4 ids: CLAUDE.md approves a
          # clearly-synthetic numeric favicon hash, whereas three distinct G-XXXXXXXXXX-shaped
          # strings trip the RULE 1 leak gate (correctly — they are shaped like real GA4 ids).
          "binding_indicators": [{"indicator": "favicon:111111111"},
                                 {"indicator": "favicon:222222222"},
                                 {"indicator": "favicon:333333333"}]}],
        relations=[], with_raw=False)
cor = c[0]["corroboration"]
check(cor["independent_artifacts"] == 1,
      "three values of ONE indicator type must count as 1 artifact, not 3")
check(cor["verdict"].startswith("LEAD ONLY"), "one artifact type must stay a LEAD")
check(cor["source"] == "kb_binding", "with no raw JSON the source must be kb_binding")

# ── 5. Singletons have no relation to corroborate ──────────────────────────────────────
c = run([{"id": 1, "size": 1, "singleton": True, "domains": ["site-a.example"],
          "binding_indicators": []}], relations=[])
check(c[0]["corroboration"]["assessment"] == "singleton", "a singleton must be marked singleton")

# ── 6. A broken rank_relations must NOT crash clustering ───────────────────────────────
real = intel.subprocess.run
intel.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))
try:
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "raw"))
        for i in range(2):
            open(os.path.join(td, "raw", f"h{i}.json"), "w").write("{}")
        out = intel._corroboration(td, [{"id": 1, "size": 2, "singleton": False,
                                         "domains": ["a.example", "b.example"],
                                         "binding_indicators": [{"indicator": "favicon:1"}]}])
    check(out[0]["corroboration"]["source"] == "kb_binding",
          "a crashed corroborator must fall back to KB binding, not kill the pipeline")
except Exception as e:  # noqa: BLE001
    FAIL.append(f"a broken rank_relations propagated out of _corroboration: {type(e).__name__}")
finally:
    intel.subprocess.run = real

if FAIL:
    for f in FAIL:
        print(f"FAIL: {f}", file=sys.stderr)
    sys.exit(1)
print("cluster corroboration: 15 classification checks passed")
