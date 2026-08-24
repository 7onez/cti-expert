#!/usr/bin/env python3
"""
test_exhaustion.py — the gate on the COLLECTION-EXHAUSTION checklist (WebPivot/wp_exhaust.py).

Run:  python3 tests/test_exhaustion.py
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
The checklist exists because the deep layers are opt-in flags and opt-in flags do not get typed:
measured across this repo's stored collections when the module was written, `intelx` appeared in
`enriched_with` exactly ONCE. The danger is not a thin case — it is a case that cannot tell how
thin it is, because a correlation pass over triage-depth collection reports "nothing further
found" as a finding when it is a statement about which flags were passed.

So the properties asserted here are the ones that make that visible and keep it honest:

  1. A layer counts as RUN only on positive evidence in the stored result. "Asked and found
     nothing" leaves a source name behind; "never asked" leaves nothing. If those two collapse,
     the whole module says the opposite of the truth.
  2. A missing REQUIRED layer forces the `triage` verdict, whatever else ran.
  3. Gaps come back cheapest-first, so the free ones — which have no excuse — are read first.
  4. The checklist never invents a gap that does not apply to the seed (document metadata on a
     bare IP, a sandbox lookup with no file hash).
  5. It reads stored files only: no network, no credentials, no credits.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "WebPivot", "tools"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_exhaust as X          # noqa: E402


def _result(host="site-a.example", sources=(), meta=None, pivots=(), **top):
    m = {"host": host, "fetched_with": "requests", "enriched_with": list(sources)}
    m.update(meta or {})
    doc = {"meta": m, "pivots": list(pivots)}
    doc.update(top)
    return doc


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 1. a bare triage result -----------------------------------------------------------
    triage = _result(sources=["crtsh", "whoisxml", "urlscan"],
                     meta={"archived_via_wayback": True})
    a = X.assess(triage)
    gaps = {g["layer"] for g in a["gaps"]}
    ok(a["verdict"] == "triage",
       "a first fetch plus the default enrichment is reported as TRIAGE, not as a worked seed")
    ok("intelx" in gaps,
       "IntelX is named as a gap — the leak / stealer-log corpus is the layer that in practice "
       "never runs, and its absence is the most consequential in the list")
    ok("intelx" in a["missing_required"],
       "IntelX is a REQUIRED layer, so its absence alone forces the triage verdict")
    ok("COLLECTION" in a["absence_note"],
       "the result carries the sentence that stops a gap being read as a negative finding")

    # --- 2. positive evidence only ----------------------------------------------------------
    asked = _result(sources=["crtsh", "whoisxml", "urlscan", "intelx"])
    ok("intelx" in X.assess(asked)["ran"],
       "a layer that RAN and found nothing still counts as run — it leaves its source name "
       "behind, which is the whole distinction between 'asked, nothing there' and 'never asked'")
    ok("intelx" not in X.assess(_result())["ran"],
       "a result with no enrichment recorded never has a layer counted as run on its behalf")
    ok("intelx" not in X.assess(_result(sources=["intelxyz"]))["ran"],
       "source matching is exact (or a `name-` variant) — a lookalike source name does not "
       "satisfy a different layer")
    ok("fetch" in X.assess(_result())["ran"],
       "a retrieved page counts as the fetch layer")
    ok("fetch" not in X.assess(_result(meta={"fetched_with": "", "live_error": "timeout"}))["ran"],
       "a failed fetch does NOT count as the fetch layer — the artifacts came from third parties")

    # --- 3. detection covers each shape of evidence -----------------------------------------
    ok("capture" in X.assess(_result(meta={"capture": {"capture_sha256": "abc"}}))["ran"],
       "a raw-evidence capture is detected from its meta block")
    ok("paths" in X.assess(_result(meta={"url_path": "/kit/"}))["ran"],
       "the URL-path layer is detected from meta")
    ok("advertising" in X.assess(_result(advertising={"advertisers": []}))["ran"],
       "the advertising layer is detected from its top-level block, even when it found nobody")
    ok("screenshot" in X.assess(_result(archives={"screenshot": "s.png"}))["ran"],
       "a screenshot is detected from the archives block")
    ok("docmeta" in X.assess(
        _result(pivots=[{"kind": "doc_software", "value": "Generic Tool"}]))["ran"],
       "the document-metadata layer is detected from the pivot kinds it emits")

    # --- 4. scope: never invent a gap that cannot apply --------------------------------------
    ip_gaps = {g["layer"] for g in X.assess(_result(host="198.51.100.7"))["gaps"]}
    ok("docmeta" not in ip_gaps and "advertising" not in ip_gaps,
       "a bare-IP seed is not told it skipped the document-metadata or advertising layers")
    ok("sandbox" not in {g["layer"] for g in X.assess(_result())["gaps"]},
       "the sandbox layer is not a gap when the site serves no file to look up")
    with_file = _result(pivots=[{"kind": "file:sha256", "value": "a" * 64}])
    ok("sandbox" in {g["layer"] for g in X.assess(with_file)["gaps"]},
       "the sandbox layer BECOMES a gap as soon as a served file's hash is in the case")

    # --- 5. gaps are ordered cheapest-first ---------------------------------------------------
    order = [X.COST_ORDER.get(g["cost"], 9) for g in a["gaps"] if not g["required"]]
    ok(order == sorted(order),
       "optional gaps are listed cheapest-first, so the free ones — which have no excuse — are "
       "read before the ones that cost quota")
    ok(all(g.get("how") and g.get("without_it") for g in a["gaps"]),
       "every gap says what its absence costs the case AND the exact command that closes it")

    # --- 6. an exhausted seed ------------------------------------------------------------------
    full = _result(sources=["crtsh", "whoisxml", "urlscan", "fofa", "pdns", "pssl",
                            "censys", "intelx"],
                   meta={"archived_via_wayback": True, "url_path": "/x/",
                         "capture": {"capture_sha256": "abc"}})
    fa = X.assess(full)
    ok(fa["verdict"] == "exhausted" and not fa["missing_required"],
       "with every required layer run, the seed is reported as exhausted")
    ok("exhaust" in fa["statement"].lower(),
       "the exhausted verdict carries its own statement for the assessment")

    # --- 7. the end-of-run banner ---------------------------------------------------------------
    lines = X.banner_lines(triage)
    ok(lines and "NOT EXHAUSTED" in lines[0],
       "a collection's end-of-run banner leads with the triage warning")
    ok(any("--intelx" in ln for ln in lines),
       "the banner names the flag that closes the biggest gap")
    ok(len(X.banner_lines(full)) == 1,
       "an exhausted seed gets one line, not a wall of text")
    return passed, failed, out


if __name__ == "__main__":
    _PASSED, _FAILED, _LINES = check()
    for _status, _label in _LINES:
        print(f"  {'ok  ' if _status == 'ok' else 'FAIL'} {_label}")
    print(f"\n{'PASS' if not _FAILED else 'FAIL'} — {_PASSED} passed, {_FAILED} failed")
    sys.exit(1 if _FAILED else 0)
