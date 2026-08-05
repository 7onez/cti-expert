#!/usr/bin/env python3
"""
Golden-set regression harness for the OSINT tooling.

WHAT IT DOES
------------
Runs the REAL `pivot_extract.py` over a set of frozen HTML fixtures (offline, no
network) and checks the structured output against per-case expectations. It is a
regression gate: it proves that a change to the extractor still finds the pivots it
should (`expect_*`) AND still rejects the noise it should (`forbid_*`) — the parking
favicon, the CDN host, the false cluster. The research point behind it: harness
improvements only compound if you can *measure* them, so every tool change runs here
first.

WHY OFFLINE
-----------
Live sites change, go down, and rate-limit, so a live eval is not reproducible. Each
case is a saved DOM fixture fed to the tool with `--no-enrich --no-whois`, so the run
is deterministic and fast. That means this harness covers the HTML-derived artifacts
(trackers, crypto, QR, emails, socials, forms, app-downloads, third-party hosts) — the
surface where extraction and false-cluster regressions actually happen. Network-only
signals (favicon hash, live TLS cert, FOFA/urlscan enrichment) are out of offline scope
by design; assert those in a separate live smoke test.

USAGE
-----
    python3 tools/eval/run_eval.py                 # run every case, print a report
    python3 tools/eval/run_eval.py --case qr_funnel # run one case
    python3 tools/eval/run_eval.py --json           # machine-readable result
    python3 tools/eval/run_eval.py -v               # show every assertion, not just fails

Exit code = number of FAILED cases (0 = all green), so it gates a pre-commit hook / CI.

A CASE
------
    tools/eval/cases/<name>/
        input.html      # the frozen DOM fixture
        expected.json   # the expectations (schema documented in README.md)
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PIVOT = os.path.join(REPO, "WebPivot", "tools", "pivot_extract.py")
CASES_DIR = os.path.join(HERE, "cases")


# ---------------------------------------------------------------- running the tool
def run_pivot(input_html: str) -> dict:
    """Run the real extractor offline on a fixture; return its parsed JSON result."""
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out_path = tf.name
    try:
        proc = subprocess.run(
            [sys.executable, PIVOT, input_html,
             "-o", out_path, "--no-enrich", "--no-whois"],
            capture_output=True, text=True, timeout=120,
        )
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            raise RuntimeError(
                f"pivot_extract produced no output.\nstderr:\n{proc.stderr[-2000:]}")
        with open(out_path) as fh:
            return json.load(fh)
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


# ---------------------------------------------------------------- assertion helpers
def _dig(obj, dotted):
    """Resolve a dotted path like 'trackers.google_tag_manager' into artifacts."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _pivot_matches(p, spec):
    """Does pivot p satisfy spec? spec may use kind, value, value_contains, kind_prefix."""
    if "kind_prefix" in spec:
        if not str(p.get("kind", "")).startswith(spec["kind_prefix"]):
            return False
    if "kind" in spec and p.get("kind") != spec["kind"]:
        return False
    if "value" in spec and str(p.get("value")) != str(spec["value"]):
        return False
    if "value_contains" in spec and spec["value_contains"] not in str(p.get("value", "")):
        return False
    # a spec with only kind_prefix/kind and no value constraint still counts as a match
    return True


def evaluate(result: dict, expected: dict):
    """Return list of assertion outcomes: (ok: bool, label: str, detail: str)."""
    outcomes = []
    pivots = result.get("pivots", []) or []
    artifacts = result.get("artifacts", {}) or {}

    # expect_pivots — each spec MUST match at least one emitted pivot
    for spec in expected.get("expect_pivots", []):
        hit = any(_pivot_matches(p, spec) for p in pivots)
        outcomes.append((hit, f"expect pivot {spec}",
                         "" if hit else "no emitted pivot matched"))

    # forbid_pivots — each spec MUST NOT match any emitted pivot (noise/false-cluster guard)
    for spec in expected.get("forbid_pivots", []):
        matches = [p for p in pivots if _pivot_matches(p, spec)]
        ok = not matches
        outcomes.append((ok, f"forbid pivot {spec}",
                         "" if ok else f"regressed: {[p['kind']+'='+str(p['value']) for p in matches][:5]}"))

    # expect_artifacts — dotted path into artifacts must CONTAIN each expected value
    for path, needed in (expected.get("expect_artifacts", {}) or {}).items():
        have = _as_list(_dig(artifacts, path))
        for want in _as_list(needed):
            ok = any(want == h or (isinstance(h, str) and want in h) for h in have)
            outcomes.append((ok, f"expect artifact {path} ~ {want!r}",
                             "" if ok else f"have {have[:6]}"))

    # forbid_artifacts — dotted path must NOT contain the value
    for path, banned in (expected.get("forbid_artifacts", {}) or {}).items():
        have = _as_list(_dig(artifacts, path))
        for bad in _as_list(banned):
            ok = not any(bad == h or (isinstance(h, str) and bad in h) for h in have)
            outcomes.append((ok, f"forbid artifact {path} ~ {bad!r}",
                             "" if ok else f"regressed, found in {have[:6]}"))

    return outcomes


# ---------------------------------------------------------------- runner
def load_cases(only=None):
    cases = []
    for name in sorted(os.listdir(CASES_DIR)):
        cdir = os.path.join(CASES_DIR, name)
        exp = os.path.join(cdir, "expected.json")
        if not os.path.isdir(cdir) or not os.path.exists(exp):
            continue
        if only and name != only:
            continue
        with open(exp) as fh:
            expected = json.load(fh)
        inp = os.path.join(cdir, expected.get("input", "input.html"))
        cases.append((name, inp, expected))
    return cases


def main():
    ap = argparse.ArgumentParser(description="Golden-set regression harness for pivot_extract")
    ap.add_argument("--case", help="run a single case by directory name")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON report")
    ap.add_argument("-v", "--verbose", action="store_true", help="show passing assertions too")
    args = ap.parse_args()

    cases = load_cases(args.case)
    if not cases:
        print("no cases found under tools/eval/cases/", file=sys.stderr)
        return 1

    report, failed_cases = [], 0
    for name, inp, expected in cases:
        entry = {"case": name, "description": expected.get("description", ""),
                 "assertions": [], "error": None, "passed": True}
        if not os.path.exists(inp):
            entry.update(error=f"missing input fixture: {inp}", passed=False)
            failed_cases += 1
            report.append(entry)
            continue
        try:
            result = run_pivot(inp)
        except Exception as e:  # tool crash = case failure, surfaced with detail
            entry.update(error=str(e), passed=False)
            failed_cases += 1
            report.append(entry)
            continue
        outcomes = evaluate(result, expected)
        entry["assertions"] = [{"ok": ok, "label": lbl, "detail": d} for ok, lbl, d in outcomes]
        entry["passed"] = all(ok for ok, _, _ in outcomes)
        if not entry["passed"]:
            failed_cases += 1
        report.append(entry)

    if args.json:
        print(json.dumps({"failed_cases": failed_cases, "total": len(cases),
                          "report": report}, indent=2))
        return failed_cases

    # human report
    for e in report:
        status = "PASS" if e["passed"] else "FAIL"
        mark = "\033[32m✔\033[0m" if e["passed"] else "\033[31m✗\033[0m"
        print(f"\n{mark} [{status}] {e['case']} — {e['description']}")
        if e["error"]:
            print(f"    ⚠ error: {e['error']}")
        for a in e["assertions"]:
            if a["ok"] and not args.verbose:
                continue
            m = "  ok " if a["ok"] else "  ✗  "
            line = f"    {m} {a['label']}"
            if a["detail"]:
                line += f"  →  {a['detail']}"
            print(line)
    # Offline unit gate for the urlscan resource-reverse logic (pure functions; the
    # live reverses themselves need network and are asserted in a separate smoke test).
    unit_total = unit_failed = 0
    unit_mods = [
        ("test_urlscan_reverse", "urlscan_reverse — distinctiveness + resource resolution"),
        ("test_ippivot", "ippivot — IP detect / noise classify / registry opsec / mail parse"),
        ("test_api_usage", "api_usage — licensed-API credit ledger record/summary"),
        ("test_binarypivot_protection", "binarypivot — packer / protector / obfuscation triage"),
        ("test_audit_high_fixes", "audit HIGH fixes — managed-DNS / KB load / dig / clarity / wayback"),
        ("test_audit_medium_fixes", "audit MEDIUM fixes — CF challenge / SAN sibling / social key"),
        ("test_reverse_phone", "reverse-WHOIS phone + preview-first / confirm-if-large gate"),
        ("test_whois_parallel", "whois_summary parallelizes current+history (speed)"),
        ("test_references", "reference DATA layer — files documented, consumers not on fallback"),
        ("test_intelx_anyrun", "IntelX + ANY.RUN — selector typing, grading, keyless honesty"),
        ("test_no_sample_submission", "OPSEC — no ANY.RUN sample-submission path exists"),
    ]
    # test_references lives in the repo-root tests/ (one level above $INTEL_HOME), not in eval/.
    # Without this the gate exists but never runs in the regression suite.
    _tests_dir = os.path.join(os.path.dirname(REPO), "tests")
    if os.path.isdir(_tests_dir) and _tests_dir not in sys.path:
        sys.path.insert(0, _tests_dir)
    for modname, desc in unit_mods:
        try:
            mod = __import__(modname)
            up, uf, ulines = mod.check()
            unit_total += up + uf
            unit_failed += uf
            mark = "\033[32m✔\033[0m" if not uf else "\033[31m✗\033[0m"
            print(f"\n{mark} [UNIT] {desc}")
            for status, label in ulines:
                if status != "ok" or args.verbose:
                    print(f"    {'  ok ' if status == 'ok' else '  ✗  '} {label}")
        except Exception as e:
            unit_total += 1
            unit_failed += 1
            print(f"\n\033[31m✗\033[0m [UNIT] {desc} — harness error: {e}")

    npass = len(cases) - failed_cases
    total_failed = failed_cases + unit_failed
    print(f"\n{'='*56}\n{npass}/{len(cases)} cases + {unit_total - unit_failed}/{unit_total} unit passed"
          + (f", \033[31m{total_failed} FAILED\033[0m" if total_failed else " \033[32m(all green)\033[0m"))
    return total_failed


if __name__ == "__main__":
    sys.exit(main())
