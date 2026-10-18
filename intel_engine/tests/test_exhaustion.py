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
  6. EXECUTION OUTCOMES: a collector that raises / times out is FAILED (re-runnable) — never
     "collected, found nothing" and never silently "never asked"; a free-only run's metered layer
     is skipped_policy and an unkeyed one skipped_no_key, so the two closures are not confused.
  7. ONION ISOLATION: a .onion seed classifies as `onion` and never reaches the clearnet collector
     (live fetch / DNS / WHOIS / CT) or the subdomain enumerators; a clearnet seed still does.
"""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "WebPivot", "tools"), os.path.join(ROOT, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_exhaust as X          # noqa: E402

ONION_V3 = "a" * 52 + "2345.onion"          # 56 base32 chars — synthetic, not a real service
ONION_V2 = "abcdefghij234567.onion"         # 16 base32 chars (legacy v2 shape)

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

    # --- 3b. WHOIS detect is source-agnostic; the ChongLuaDao layer + compound tokens ---------
    ok("whois" in X.assess(_result(artifacts={"whois": {"registrar": "iNET", "source": "chongluadao"}}))["ran"],
       "WHOIS counts as run whenever the whois artifact is present, regardless of source "
       "(whoisxml / rdap / chongluadao) — the rule can't drift as new WHOIS sources are added")
    ok("whois" not in X.assess(_result())["ran"],
       "a domain with no whois artifact is not counted as a WHOIS run")
    ok("cld" in X.assess(_result(sources=["whoisxml+chongluadao"]))["ran"],
       "the ChongLuaDao layer is detected inside a '+'-joined provenance token")
    ok("cld" not in X.assess(_result(sources=["whoisxml"]))["ran"],
       "a case with no ChongLuaDao source does not count the CLD layer as run")

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
                         "capture": {"capture_sha256": "abc"}},
                   artifacts={"whois": {"registrar": "Example Registrar"}})
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
    _outcome_checks(ok)
    _onion_checks(ok)
    return passed, failed, out


def _fake_writer(doc, calls):
    """A stand-in collector: records the command and writes `doc` to the -o path, exit 0."""
    def run(cmd, cwd, timeout=None, env=None):
        calls.append(list(cmd))
        out = cmd[cmd.index("-o") + 1]
        host = X.json.loads(X.json.dumps(doc))
        host.setdefault("meta", {})["host"] = os.path.basename(out)[:-5]
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(host, fh)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return run


def _collect(cc, url, case, root, **kw):
    return cc.collect_host(url, case, root=root, py=sys.executable,
                           collector="pivot_extract.py", **kw)


def _outcome_checks(ok):
    import collect_core as CC                                            # noqa: PLC0415
    identity = lambda py, script, cwd, args: (list(args), [])           # noqa: E731 — no --help probe
    with tempfile.TemporaryDirectory() as tmp, patch.object(CC, "filter_args", identity):
        case = "CASE-0001"
        case_dir = os.path.join(tmp, "cases", case)

        # --- a collector that RAISES ----------------------------------------------------------
        def boom(cmd, cwd, timeout=None, env=None):
            raise RuntimeError("collector exploded")
        with patch.object(CC, "run", boom):
            res = _collect(CC, "https://site-b.example", case, tmp)
        ok(res["collect_failed"] and res["outcome"]["status"] == "error",
           "a collector that raises returns collect_failed with outcome status 'error' — "
           "collect_host never raises and never reports the host as collected")
        rec = X.load_outcomes(case_dir).get("site-b.example") or {}
        ok((rec.get("collect") or {}).get("status") == "error"
           and (rec.get("layers") or {}).get("whois", {}).get("status") == "error",
           "the crash is persisted per layer in collection_outcomes.json (no raw file exists)")

        # --- a collector that TIMES OUT, on a forced re-collect over an OLD raw file ----------
        os.makedirs(os.path.join(case_dir, "raw"), exist_ok=True)
        stale = os.path.join(case_dir, "raw", "site-c.example.json")
        with open(stale, "w", encoding="utf-8") as fh:
            json.dump({"meta": {"host": "site-c.example", "fetched_with": "requests"},
                       "pivots": [{"kind": "x", "value": "y"}]}, fh)
        os.utime(stale, (1, 1))

        def slow(cmd, cwd, timeout=None, env=None):
            raise subprocess.TimeoutExpired(cmd, timeout)
        with patch.object(CC, "run", slow):
            res = _collect(CC, "https://site-c.example", case, tmp, force=True)
        ok(res["collect_failed"] and res["outcome"]["status"] == "timed_out",
           "a timed-out forced re-collect is timed_out — the previous run's file on disk is NOT "
           "read back as this run's result")

        rep = X.assess_case(case, root=tmp)
        by = {a["host"]: a for a in rep["results"]}
        ok(by.get("site-b.example", {}).get("verdict") == "failed",
           "assess_case lists the crashed host (it has no raw file) with verdict 'failed', "
           "not as a host that was never asked about")
        ok(by.get("site-c.example", {}).get("verdict") == "failed",
           "a host whose latest run timed out is 'failed' even though an older raw file exists")
        gaps = {g["layer"]: g for g in by.get("site-b.example", {}).get("gaps", [])}
        ok(gaps.get("whois", {}).get("status") == "error" and gaps["whois"]["rerunnable"],
           "each layer of the crashed run is a FAILED, re-runnable gap — not collected-empty")
        ok({r["host"] for r in rep["rerunnable"]} >= {"site-b.example", "site-c.example"},
           "both failed hosts are in the case's re-runnable list")
        # the collection_gaps @tool is a thin wrapper over this CLI
        os.makedirs(os.path.join(case_dir, "enrichment"), exist_ok=True)
        with open(os.path.join(case_dir, "enrichment", "index.json"), "w", encoding="utf-8") as fh:
            json.dump({"leads": {"phone:+18005550100": {"outcome": "retry", "status": "timed_out",
                                                        "reason": "killed", "summary": "x"}}}, fh)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            X._main([case, "--root", tmp])
        txt = buf.getvalue()
        ok("RE-RUNNABLE  site-b.example" in txt and "RE-RUNNABLE  site-c.example" in txt,
           "collection_gaps output names every failed host as RE-RUNNABLE")
        ok("RE-RUNNABLE  enrichment phone:+18005550100  [timed_out]" in txt,
           "a failed enrichment lead is surfaced as RE-RUNNABLE in collection_gaps too")

        # --- free-only vs unkeyed: two different closures --------------------------------------
        calls = []
        free_doc = {"meta": {"fetched_with": "requests", "enriched_with": ["crtsh"],
                             "capability": {"mode": "free-only", "keys_missing": [],
                                            "metered_suppressed": ["FOFA_KEY", "CENSYS_PAT"]}},
                    "pivots": [{"kind": "x", "value": "y"}]}
        with patch.object(CC, "run", _fake_writer(free_doc, calls)):
            res = _collect(CC, "https://site-d.example", case, tmp, extra_flags=["--free-only"])
        lay = X.load_outcomes(case_dir)["site-d.example"]["layers"]
        ok(res["outcome"]["status"] == "ran" and lay["crtsh"]["status"] == "ran",
           "a successful collection records collect 'ran' and the evidenced layers as ran")
        ok(lay["fofa"] == {**lay["fofa"], "status": "skipped_policy", "reason": "free_only"},
           "a free-only run's metered layer (FOFA) is skipped_policy/free_only — withheld on "
           "purpose, not a missing key")
        keyless_doc = {"meta": {"fetched_with": "requests", "enriched_with": ["crtsh"],
                                "capability": {"mode": "keyless",
                                               "keys_missing": ["FOFA_KEY", "CENSYS_PAT"],
                                               "metered_suppressed": []}},
                       "pivots": [{"kind": "x", "value": "y"}]}
        with patch.object(CC, "run", _fake_writer(keyless_doc, calls)):
            _collect(CC, "https://site-e.example", case, tmp)
        lay = X.load_outcomes(case_dir)["site-e.example"]["layers"]
        ok(lay["fofa"]["status"] == "skipped_no_key" and "FOFA_KEY" in lay["fofa"]["reason"],
           "an unkeyed run's FOFA layer is skipped_no_key and names the key that closes it")
        a = X.assess(keyless_doc | {"meta": {**keyless_doc["meta"], "host": "site-e.example"}})
        ok({g["layer"]: g["status"] for g in a["gaps"]}.get("fofa") == "skipped_no_key",
           "a stored result with no outcome file still reports skipped_no_key from meta.capability")
        smoke_doc = {"meta": {"fetched_with": "requests"}, "pivots": []}
        with patch.object(CC, "run", _fake_writer(smoke_doc, calls)):
            res = _collect(CC, "https://site-f.example", case, tmp, smoke=True)
        lay = X.load_outcomes(case_dir)["site-f.example"]["layers"]
        ok(res["outcome"]["status"] == "empty"
           and lay["whois"]["status"] == "skipped_policy" and lay["whois"]["reason"] == "no_whois",
           "a smoke run with no pivots is collect 'empty' (it RAN) and its WHOIS is skipped_policy")


def _onion_checks(ok):
    import collect_core as CC                                            # noqa: PLC0415
    import selector_types as ST                                          # noqa: PLC0415
    import intel                                                         # noqa: PLC0415
    ok(intel._ONION_RE.pattern == ST._ONION_RE.pattern == X._ONION_HOST_RE.pattern,
       "the onion pattern is identical in intel.py, selector_types and wp_exhaust")
    for raw in (ONION_V3, ONION_V2, f"http://{ONION_V3}/login", f"shop.{ONION_V3}"):
        ok(intel._classify_selector(raw) == "onion" and ST.classify(raw) == "onion",
           f"{raw[:24]}… classifies as onion in both classifiers (never domain)")
    ok(intel._classify_selector("site-a.example") == "domain" and ST.classify("site-a.example") == "domain"
       and ST.classify("a" * 55 + ".onion") != "onion",
       "a clearnet domain is still a domain, and a wrong-length .onion label is not an onion")
    ok(ST.routes_for("onion") and "enrich.host" not in ST.routes_for("onion"),
       "an onion keeps the string corpus routes and never gets the clearnet host-enrichment route")

    identity = lambda py, script, cwd, args: (list(args), [])           # noqa: E731
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}), \
            patch.object(CC, "filter_args", identity):
        case_dir = os.path.join(tmp, "CASE-0001")              # an absolute case path stays in tmp
        os.makedirs(os.path.join(case_dir, "raw"))
        seeds = os.path.join(tmp, "seeds.txt")
        with open(seeds, "w", encoding="utf-8") as fh:
            fh.write(f"{ONION_V3}\nsite-a.example\n")
        collected, subenum, dns, whois = [], [], [], []

        class _Stop(Exception):
            pass

        def _stop(*_a, **_k):
            raise _Stop()
        doc = {"meta": {"fetched_with": "requests"}, "pivots": [{"kind": "x", "value": "y"}]}
        writer = _fake_writer(doc, collected)

        def collector(cmd, cwd, timeout=None, env=None):     # the collector is where DNS+WHOIS run
            host = CC.host_of(next(c for c in cmd if str(c).startswith("https://")))
            dns.append(host)
            whois.append(host)
            return writer(cmd, cwd, timeout, env)
        args = argparse.Namespace(
            case=case_dir, domains=seeds, no_collect=False, jobs=2, whois_reverse=False,
            fofa_full=False, render_extract=False, serp=False, serp_region=None, no_pssl=False,
            free_only=True, timeout=20, force=True, archive=False, screenshots=False, min=2)
        with patch.object(CC, "run", collector), \
                patch.object(intel, "_subenum_once",
                             lambda cdir, hosts, **kw: subenum.extend(hosts)), \
                patch.object(intel, "_intelx_flag", lambda *a, **k: []), \
                patch.object(intel.binary_auto, "run", lambda *a, **k: []), \
                patch.object(intel, "_run", _stop), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                intel.cmd_open(args)
            except _Stop:
                pass
        ok(ONION_V3 not in dns and ONION_V3 not in whois and ONION_V3 not in subenum,
           "the .onion seed never reaches the collector (system DNS / WHOIS / CT) nor subenum")
        ok("site-a.example" in dns and "site-a.example" in subenum,
           "the clearnet seed in the same run still reaches the collector and subenum")
        rec = X.load_outcomes(case_dir).get(ONION_V3) or {}
        ok((rec.get("collect") or {}).get("reason") == "onion"
           and rec["layers"]["whois"]["status"] == "skipped_policy"
           and rec["stages"]["subenum"]["reason"] == "onion",
           "the onion's skipped stages are recorded as skipped_policy reason 'onion'")
        rep = X.assess({"meta": {"host": ONION_V3}, "pivots": []}, rec)
        ok("whois" in rep["not_applicable"] and "crtsh" in rep["not_applicable"]
           and "intelx" not in rep["not_applicable"],
           "for an onion, clearnet-only layers are not applicable; corpus layers stay open gaps")


if __name__ == "__main__":
    _PASSED, _FAILED, _LINES = check()
    for _status, _label in _LINES:
        print(f"  {'ok  ' if _status == 'ok' else 'FAIL'} {_label}")
    print(f"\n{'PASS' if not _FAILED else 'FAIL'} — {_PASSED} passed, {_FAILED} failed")
    sys.exit(1 if _FAILED else 0)
