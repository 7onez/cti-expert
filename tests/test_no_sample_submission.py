#!/usr/bin/env python3
"""
test_no_sample_submission.py — the OPSEC gate on outbound sample submission.

Run:  python3 tests/test_no_sample_submission.py     (zero deps)
      (also runs inside tools/eval/run_eval.py)

WHY THIS EXISTS
---------------
ANY.RUN's API is, in the main, a SUBMISSION API: you upload a file, it detonates it, you read the
report. This toolkit uses the small read-only corner of it — Threat Intelligence Lookup, which
reports what OTHER people's detonations already recorded — and deliberately wires up no submit
path at all.

That distinction is the whole OPSEC posture of the file half of a case, and it is not a stylistic
preference:

  - A public ANY.RUN task is WORLD-READABLE. The file, its hash, the screenshots and the network
    log are all published. Submitting the operator's own APK or installer therefore tells the
    operator, in near real time, that someone is analysing their sample.
  - The operator watches for exactly this. The standard response is to rotate the backend, revoke
    the signing key and re-skin the front — which destroys the very infrastructure the case was
    built on, days before a takedown or a referral can land.
  - It is IRREVERSIBLE. A published task cannot be recalled. Unlike a noisy DNS query or a fetch
    from the wrong egress, there is no cleaning up afterwards.
  - It is an OUTBOUND act taken against a third party's service, and it costs a run.

So: detonation is a decision the ANALYST makes explicitly, in the sandbox UI, on a private plan,
having weighed the exposure. It is never a side effect of a pivot, never something a collector
does on its own initiative, and never something an agent arranges because it seemed helpful.

WHAT THIS TEST ASSERTS
----------------------
Documentation rots and comments do not fail builds. This converts the intention into an invariant:

  1. No submission/upload endpoint appears in the ANY.RUN reference data. (Adding one there is the
     cheapest way to accidentally enable submission, because the module reads its paths from data.)
  2. The module builds no URL that is not one of the read-only endpoints.
  3. The module contains no file-upload machinery (multipart bodies, binary file reads fed to a
     request, `files=`).
  4. If a submit path is EVER added, it must route through an explicit human-confirmation gate —
     asserted by requiring the marker `REQUIRES_ANALYST_CONFIRMATION` to be present alongside it.
     This test is what makes that non-negotiable rather than aspirational.

If this test fails, do not "fix" it by relaxing the assertion. Either the submission capability is
unwanted (remove it), or it is genuinely needed and must ship behind a confirmation gate.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")

ANYRUN_PY = os.path.join(ENGINE, "BinaryPivot", "tools", "bp_anyrun.py")
ANYRUN_JSON = os.path.join(ENGINE, "BinaryPivot", "references", "anyrun.json")

# Endpoint keys the read-only layer is allowed to reach. Anything else that looks like a write.
READ_ONLY_ENDPOINT_KEYS = {
    "api_base", "report_base", "content_base",
    "ti_search", "ti_keycheck", "yara_search", "yara_result",
    "analysis_history", "analysis_report", "report_ioc", "report_summary",
    "user_limits", "environment",
}

# Words that betray a submission/detonation capability in an endpoint name or path.
SUBMIT_TOKENS = ("submit", "upload", "detonate", "/analysis/run", "putfile", "sendfile")

# The marker a future submit path MUST carry (see docstring point 4).
CONFIRM_MARKER = "REQUIRES_ANALYST_CONFIRMATION"

# Upload machinery. These are deliberately BROAD: this module consumes JSON over HTTP and has no
# legitimate reason to touch a file in binary mode or to build a multipart body, so any hit is
# either a submission path or a refactor that deserves a human look. A narrow pattern that only
# matches the one upload spelling someone happened to use is not a guard — it is a comment that
# runs. (Verified by deliberately planting each of these and watching the gate fail.)
UPLOAD_PATTERNS = [
    (r"multipart", "multipart body/encoder"),
    (r"\bfiles\b\s*[=:]", "files= / 'files': upload payload"),
    (r"""["']rb["']""", "binary-mode file access"),
    (r"\bencode_multipart|\bMultipartEncoder\b", "multipart encoder"),
    (r"\bbase64\.b64encode\s*\(\s*open\b", "inline base64 of a file"),
]


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

    ok(os.path.exists(ANYRUN_PY), "bp_anyrun.py present")
    ok(os.path.exists(ANYRUN_JSON), "references/anyrun.json present")
    if not (os.path.exists(ANYRUN_PY) and os.path.exists(ANYRUN_JSON)):
        return passed, failed, out

    src = open(ANYRUN_PY, encoding="utf-8").read()
    doc = json.load(open(ANYRUN_JSON, encoding="utf-8"))
    has_confirm_gate = CONFIRM_MARKER in src

    # --- 1. no submission endpoint in the reference DATA -------------------------------------
    # Reference-layer groups are {_comment, entries|values}; unwrap to the payload so a submission
    # path cannot hide one level down from the check.
    grp = doc.get("endpoints") or {}
    endpoints = grp.get("entries", grp.get("values", grp))
    if isinstance(endpoints, dict):
        endpoints = {k: v for k, v in endpoints.items() if not k.startswith("_")}
    else:
        endpoints = {str(v): str(v) for v in (endpoints or [])}
    ok(bool(endpoints), "anyrun.json declares endpoints")
    for key, path in endpoints.items():
        blob = f"{key} {path}".lower()
        hit = next((t for t in SUBMIT_TOKENS if t in blob), None)
        ok(hit is None or has_confirm_gate,
           f"endpoint {key!r} is read-only"
           + (f" — SUBMIT TOKEN {hit!r} with no {CONFIRM_MARKER} gate" if hit else ""))
    unknown = sorted(set(endpoints) - READ_ONLY_ENDPOINT_KEYS)
    ok(not unknown,
       "no unrecognised endpoint keys" + (f" (new: {unknown} — review before allowing)" if unknown else ""))

    # --- 2. the module builds no URL outside the read-only set --------------------------------
    used = set(re.findall(r'ENDPOINTS\.get\(\s*["\']([a-z_]+)["\']', src))
    stray = sorted(used - READ_ONLY_ENDPOINT_KEYS)
    ok(not stray, "every URL the module builds is a read-only endpoint"
                  + (f" (stray: {stray})" if stray else ""))

    # --- 3. no file-upload machinery ----------------------------------------------------------
    for pat, desc in UPLOAD_PATTERNS:
        found = re.search(pat, src, re.M)
        ok(found is None or has_confirm_gate,
           f"no {desc} in bp_anyrun.py"
           + (f" — found at offset {found.start()} with no {CONFIRM_MARKER} gate" if found else ""))

    # --- 4. the read-only contract is stated where an analyst will meet it ---------------------
    # A guarantee nobody can see is a guarantee nobody can rely on.
    ok(re.search(r"no submit path|NEVER SUBMIT|never detonat|NO DETONATION", src, re.I) is not None,
       "bp_anyrun.py states the no-submission contract in its own docstring")
    harness = os.path.join(ENGINE, "harness", "tools.py")
    if os.path.exists(harness):
        h = open(harness, encoding="utf-8").read()
        ok("NEVER SUBMITS A SAMPLE" in h.upper() or "NOTHING IS EVER SUBMITTED" in h.upper(),
           "the anyrun_lookup MCP description carries the no-submission contract")

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_no_sample_submission():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} OPSEC check(s) failed: a sample-submission path may have appeared.")
        sys.exit(1)
    print(f"PASS — no sample-submission path ({_PASSED} checks: endpoints read-only, "
          f"no upload machinery, contract stated to the analyst)")
