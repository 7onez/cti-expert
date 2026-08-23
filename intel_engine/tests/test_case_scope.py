#!/usr/bin/env python3
"""
test_case_scope.py — the gate on the harness INTAKE layer (harness/case_scope.py).

Run:  python3 tests/test_case_scope.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
The intake decides three things the rest of a run cannot recover from, and each failure is
SILENT — the run still completes and still prints a confident assessment:

  * POSTURE. A class whose posture forbids touching the target must derive `hostile`, because
    that is what the PreToolUse gate turns into a hard denial. A posture that only reaches the
    prompt is a posture the model can talk itself out of. Equally important in the other
    direction: `passive_first` must NOT derive it. Passive-first is an ORDERING instruction, and
    conflating it with a prohibition would turn every unscoped run into a no-fetch run — gutting
    collection while looking like caution.
  * OWNERSHIP. On `victim_host` the page's own artifacts belong to the victim. That rule has to
    reach the JUDGMENT prompts too, not just collection: the collector can label them correctly
    and the correlator still cluster on them.
  * THE PREMISE, kept separate from the evidence. A defaulted value must never render back to
    the model as something the analyst said — a defaulted `time_window` reading as an incident
    date, or a defaulted `purpose` quietly instructing the run to spend nothing, is the same
    anchoring failure the layer exists to prevent, one level down.

Plus the two invariants that keep it from becoming a wall: it NEVER blocks (no scope, a corrupt
scope file, an unwritable case dir, a typo'd class → the run continues under `unknown`), and it
never fails toward a MORE permissive class.

Everything here is offline and writes only to a temp dir. No network, no case data (RULE 1).
"""
import io
import json
import os
import contextlib
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness"))

import case_scope as CS  # noqa: E402
from schemas import Assessment  # noqa: E402
import render as R  # noqa: E402


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    tmp = tempfile.mkdtemp(prefix="scope-test-")
    try:
        # --- 1. the unscoped default: honest, conservative, and NOT a refusal -----------------
        s = CS.resolve("C1", root=tmp, persist=False)
        ok(s["target_class"] == "unknown", "no context → target_class `unknown`")
        ok(s["stated"] is False, "no context → stated False (we assumed, nobody told us)")
        ok(CS.is_hostile(s) is False,
           "unknown (passive_first) does NOT derive hostile — ordering, not prohibition")
        col, jud = CS.collect_directives(s), CS.judgment_directives(s)
        ok("NO CONTEXT WAS SUPPLIED" in col and "NO CONTEXT WAS SUPPLIED" in jud,
           "an unscoped run discloses the assumption in BOTH prompts")
        ok(bool(col.strip()) and bool(jud.strip()), "an unscoped run still renders both blocks")

        # A defaulted value must never come back as an answer.
        ok("Date that matters" not in col,
           "a defaulted time_window is not rendered as a stated incident date")
        ok("requester's own falsifier" not in jud,
           "a defaulted falsifier is not rendered as one the requester asked for")
        ok(not any(k.startswith("purpose=") for k in CS._switch_keys(s)),
           "a defaulted purpose activates NO scope switch (nobody asked to stop at leads)")
        ok("DEFAULTED" in CS.banner(s), "the banner says the class was defaulted")

        # --- 2. posture → the egress constraint the GATE enforces ----------------------------
        cases = {"threat_actor_infra": True, "confirmed_scam": False, "suspected_scam": False,
                 "victim_host": False, "benign_check": False, "unknown": False}
        for cls, want in cases.items():
            sc = CS.resolve("C2", root=tmp, persist=False, target_class=cls)
            got = CS.is_hostile(sc)
            ok(got is want, f"{cls} → hostile={want} (posture "
                            f"`{CS.posture(sc).get('fetch_posture')}`)")
        sc = CS.resolve("C2", root=tmp, persist=False, target_class="threat_actor_infra")
        ok(CS.posture(sc)["fetch_posture"] == CS.NO_TOUCH,
           "threat_actor_infra keeps the never-touch posture from the reference")
        ok("DENIED by the tool gate" in CS.collect_directives(sc),
           "a no-touch class tells the collector the gate will deny outbound calls")

        # An analyst constraint overrides an otherwise-permissive class.
        sc = CS.resolve("C3", root=tmp, persist=False, target_class="benign_check",
                        no_direct_contact=True)
        ok(CS.is_hostile(sc) is True,
           "no_direct_contact derives hostile even on a direct_ok class")
        ok(CS.is_hostile(CS.resolve("C3b", root=tmp, persist=False), explicit=True) is True,
           "an explicit --hostile still forces it regardless of class")

        # --- 3. a bad class fails to the CONSERVATIVE side, loudly ---------------------------
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            sc = CS.resolve("C4", root=tmp, persist=False, target_class="benign-ish typo")
        ok(sc["target_class"] == "unknown", "an unrecognised class coerces to `unknown`")
        ok("WARNING" in err.getvalue(), "an unrecognised class warns rather than passing silently")
        ok(CS.normalise_class("Threat-Actor Infra") == "threat_actor_infra",
           "class names normalise across case/dash/space")

        # --- 4. ownership reaches BOTH halves of the run -------------------------------------
        sc = CS.resolve("C5", root=tmp, persist=False, target_class="victim_host")
        rule = CS.posture(sc)["clustering_rule"]
        ok(rule[:40] in CS.collect_directives(sc), "victim ownership rule reaches COLLECT")
        ok(rule[:40] in CS.judgment_directives(sc), "victim ownership rule reaches JUDGMENT")
        ok("victim-profile" in " ".join(CS.switches(sc)).lower()
           or "victim_profile" in " ".join(CS.switches(sc)).lower(),
           "victim_host activates its scope switch")

        # --- 5. the premise is carried as a claim with a source, and answered ----------------
        sc = CS.resolve("C6", root=tmp, persist=False, target_class="suspected_scam",
                        claim="the site is a fake exchange", basis="victim complaint",
                        falsifier="it is the genuine brand's own site")
        jud = CS.judgment_directives(sc)
        ok("the site is a fake exchange" in jud, "the claim is quoted verbatim to the judge")
        ok("victim complaint" in jud, "the claim's SOURCE travels with it")
        ok("it is the genuine brand's own site" in jud, "the requester's falsifier is passed on")
        for verdict in ("supported", "partially_supported", "not_supported",
                        "contradicted", "inconclusive"):
            ok(verdict in jud, f"the judge is given the `{verdict}` verdict definition")
        ok("hypothesis" in jud.lower(), "the judge is told the class is a hypothesis, not a fact")
        for phrase in ("raise a confidence level because the requester was certain",
                       "report 'not supported' as 'benign'"):
            ok(phrase in jud, f"prohibition carried to the judge: {phrase[:38]}…")

        # --- 6. how-encountered matches WORDS, not substrings --------------------------------
        # "download" contains "ad": a substring match would fire the advertising probe on every
        # file funnel and skip the binary hand-off.
        dl = CS.resolve("C7", root=tmp, persist=False, how_encountered="an APK download")
        ad = CS.resolve("C8", root=tmp, persist=False, how_encountered="sponsored ad")
        ok("how_encountered=file_download" in CS._switch_keys(dl),
           "a download is routed to the file hand-off")
        ok("how_encountered=ad_or_sponsored" not in CS._switch_keys(dl),
           "'download' does not fire the advertising switch (substring trap)")
        ok("how_encountered=ad_or_sponsored" in CS._switch_keys(ad),
           "an ad arrival turns on the advertising + cloaking probe")

        # --- 7. persistence: later rounds and the other front-end inherit the scope ----------
        saved = CS.resolve("C9", root=tmp, target_class="confirmed_scam", purpose="attribution",
                           claim="c")
        ok(os.path.exists(CS.path("C9", tmp)), "a stated scope persists to cases/<case>/scope.json")
        again = CS.resolve("C9", root=tmp, persist=False)
        ok(again["target_class"] == "confirmed_scam" and again["stated"] is True,
           "a resumed round reads the same class back off disk")
        ok(CS.said(again, "purpose") and again["purpose"] == "attribution",
           "stated_fields survive the round-trip, so an answer stays an answer")
        override = CS.resolve("C9", root=tmp, persist=False, target_class="victim_host")
        ok(override["target_class"] == "victim_host",
           "an explicit argument beats the persisted record")
        ok(saved["stated_at"], "a stated scope is timestamped")

        # --- 8. NEVER BLOCKS — every degradation path returns a usable scope -----------------
        with open(CS.path("C9", tmp), "w", encoding="utf-8") as f:
            f.write("{not json at all")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            broken = CS.resolve("C9", root=tmp, persist=False)
        ok(broken["target_class"] == "unknown", "a corrupt scope.json degrades to `unknown`")
        ok("WARNING" in err.getvalue(), "a corrupt scope.json warns rather than dying")
        ro = os.path.join(tmp, "readonly")
        os.makedirs(ro, exist_ok=True)
        os.chmod(ro, 0o500)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                s2 = CS.resolve("C10", root=ro, target_class="confirmed_scam")
            ok(s2["target_class"] == "confirmed_scam",
               "an unwritable case dir costs persistence, not the run")
        finally:
            os.chmod(ro, 0o700)
        ok(CS.POLICY.get("blocking") is False, "the reference itself declares the layer non-blocking")

        # --- 9. loaded from the DATA FILE, not the embedded fallback -------------------------
        ok(len(CS.CLASSES) > len(CS._INTAKE_FALLBACK["target_classes"]),
           f"target classes come from intake.json ({len(CS.CLASSES)} loaded)")
        ok(len(CS.QUESTIONS) > len(CS._INTAKE_FALLBACK["intake_questions"]),
           f"intake questions come from intake.json ({len(CS.QUESTIONS)} loaded)")
        ok(len(CS.SWITCHES) > len(CS._INTAKE_FALLBACK["scope_switches"]),
           f"scope switches come from intake.json ({len(CS.SWITCHES)} loaded)")
        ok(all(isinstance(v, dict) and v.get("fetch_posture") for v in CS.CLASSES.values()),
           "every target class declares a fetch posture")
        ok(all(v.get("clustering_rule") for v in CS.CLASSES.values()),
           "every target class declares who owns the artifacts")
        ok("What do you believe this is" in CS.questions_markdown(),
           "the question set renders for an analyst who IS in the loop")

        # --- 10. the assessment answers the premise, and defaults to the honest value --------
        a = Assessment(bluf="b", attribution_level="inconclusive", confidence="low")
        ok(a.premise_verdict == "inconclusive",
           "premise_verdict defaults to `inconclusive` — never to a claim being confirmed")
        md = R.render_markdown(a)
        ok("Premise verdict" in md, "the rendered assessment carries the premise verdict")
        a2 = Assessment(bluf="b", attribution_level="same-operator", confidence="high",
                        premise="stated: a scam site", premise_verdict="contradicted")
        ok("contradicted" in R.render_markdown(a2) and "stated: a scam site" in R.render_markdown(a2),
           "a contradicted premise is rendered with the claim it broke")
        ok("Collection verdict" in R._premise_line(a2),
           "the required output line is produced verbatim")

        # --- 11. every phase prompt actually consumes the block ------------------------------
        pdir = os.path.join(ROOT, "harness", "prompts")
        for name in ("collect", "collect_one", "correlate", "verify", "assess"):
            body = open(os.path.join(pdir, name + ".md"), encoding="utf-8").read()
            ok("{{scope}}" in body, f"prompts/{name}.md has the {{{{scope}}}} placeholder")
        sys.path.insert(0, os.path.join(ROOT, "harness"))
        import orchestrator as O  # noqa: E402 — imported late; pulls the SDK
        filled = O._prompt("correlate", scope=CS.judgment_directives(s), case="C", seed_csv="d")
        ok("{{scope}}" not in filled and "PREMISE UNDER TEST" in filled,
           "the orchestrator fills the placeholder rather than leaving it in the prompt")

        # --- 12. the CLI flags reach the record ----------------------------------------------
        argv = ["C11", "--target-class", "victim_host", "--claim", "x", "--no-spend",
                "https://a.example", "https://b.example"]
        saved_root = O.case_scope.ROOT
        try:
            O.case_scope.ROOT = tmp                      # keep the test out of the real cases/
            sc = O._scope_from_argv(argv, "C11")
        finally:
            O.case_scope.ROOT = saved_root
        ok(argv == ["C11", "https://a.example", "https://b.example"],
           "intake flags are consumed, leaving only the case and its seeds")
        ok(sc["target_class"] == "victim_host" and sc["constraints"]["no_spend"] is True,
           "the flags land in the resolved scope")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
