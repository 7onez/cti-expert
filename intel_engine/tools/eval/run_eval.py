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

    # ---- METERED-SPEND GUARD -------------------------------------------------------------
    # A regression gate must cost nothing to run. It stopped being true silently: the Censys
    # layer was folded into IPPivot, test_ippivot's mock list was not updated with it, and every
    # gate run then spent 2 real credits against a documentation IP. Over a day of iterating that
    # burned a third of the 100-credit MONTHLY per-account quota and disarmed Censys for actual
    # casework — with nothing in the output to say so. Every metered call is recorded in
    # MEMORY/api_usage.jsonl by api_usage.record(), so the ledger's own length is the check: if it
    # grows across a gate run, something reached a paid API and the run is reported FAILED.
    _ledger = os.path.join(REPO, "MEMORY", "api_usage.jsonl")

    def _ledger_len():
        try:
            with open(_ledger, encoding="utf-8") as fh:
                return sum(1 for line in fh if line.strip())
        except OSError:
            return 0

    _spend_before = _ledger_len()

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
        ("test_frontier_guards", "frontier co-tenancy guards — multi-tenant cert / shared IP / bulk registrant"),
        ("test_assets_layer", "asset layer — JS bundle select / sourcemap dev-identity / API+build-env / well-known"),
        ("test_censys", "Censys layer — CenQL not Legacy Search / = vs : / MD5 favicon / "
                        "free-plan degradation / monthly credit guard"),
        ("test_capabilities", "capability layer — keyless disclosure, alias/requires presence, "
                              "free-only mode, no banner when fully keyed"),
        ("test_intelx_anyrun", "IntelX + ANY.RUN layers — keyless ~50% disclosure, strong-selector "
                               "refusal, observation-field mapping, false-cluster policy, spend guard"),
        ("test_docmeta", "document/image metadata — PDF /Info + XMP, EXIF incl. GPS, PNG chunks, "
                         "magic-byte dispatch, base-rate filter on both the pivot and ingest paths"),
        ("test_tool_registry", "tool registry (RULE 2) — every @tool served by an SDK server and "
                               "allowlisted, so Claude Code and the SDK harness cannot diverge"),
        ("test_paths_capture", "URL-path layer + raw-evidence capture — kit extraction, the "
                               "base-rate control (a generic path clusters NOTHING), template "
                               "normalisation, cross-host patterns, manifest hashing + tamper "
                               "detection"),
        ("test_references", "reference DATA layer — files documented, consumers not on fallback, no drift"),
        ("test_dashboard", "debug dashboard — exact vs estimated numbers kept apart, one API "
                            "response billed once however many records it spans, a bounded scan "
                            "reports itself bounded, an unpriced model surfaces instead of "
                            "reading as free, an absent ledger is absence of record, the trace "
                            "pairs each tool result to its call and never cuts one silently, "
                            "and the server refuses a non-loopback bind"),
        ("test_case_scope", "case intake — no-touch class derives the gate denial, passive_first "
                            "does not, victim ownership reaches the judge, a defaulted value is "
                            "never rendered as an answer, and nothing ever blocks"),
        ("test_tool_gate", "tool-call gate — hostile egress blocked above the tools, submission "
                           "needs approval, credit budget, ledger, all 3 front-ends, hand-back"),
        ("test_timeline", "temporal layer — format parsing / overlap vs shared value / expiry cohort / online citations"),
        ("test_pssl", "passive SSL — the historical cert->IP direction that recovers an origin from behind a CDN, with the base-rate rail that keeps a shared CDN certificate (915 addresses in live measurement) out of the clustering, and an empty corpus answer reported as absence of RECORD"),
        ("test_misconfig", "misconfig triage — an RFC1918/loopback/link-local address leaking into a "
                           "public FOFA banner is flagged (a dual-homed operator box), an anon-FTP "
                           "service is a lead but the row's own public IP never is, and the tool "
                           "flags only — it never auto-connects"),
        ("test_serp", "advertising layer — ad-parameter base rates (a click id is never a pivot), "
                      "the agency threshold, and the cloaking probe's falsification control "
                      "(an unstable page is never reported as evasion)"),
        ("test_liveness", "liveness guardrail — a 200 parking/default/suspended/soft-404 page is "
                          "never 'live', a 404/403/5xx/bot-wall is never 'dead', only NXDOMAIN "
                          "reports dead, and every still-controlled name sets reuse_watch"),
        ("test_context_budget", "context management — every tool's output governed by name with "
                                "head+tail kept and the cut ANNOUNCED, and the shim's transcript "
                                "trimmed by whole rounds so tool-call pairing survives"),
        ("test_openai_backend", "open-weight backend (Kimi/DeepSeek/local) — the tool loop driven "
                                "against a stubbed endpoint, optional params + enums reaching the "
                                "schema, and a denied call returning as output not an exception"),
        ("test_engage", "Engage skill — auth-surface detection classifies by FIELDS (confirm-"
                        "password = register, invite code is a pivot not an OTP), and the "
                        "engagement gate holds in code (no confirm -> preflight, non-synthetic "
                        "persona / direct egress refused, CAPTCHA stops it); the mission harvest "
                        "pulls wallets/bank/upload-path and drops a bare number with no bank context"),
    ]
    # tests/ modules follow the same check() contract; make them importable here too. cti-expert
    # nests the engine one level deeper than upstream, so BOTH suites must be on the path: the
    # vendored engine tests (intel_engine/tests) and cti-expert's own repo-root tests. Dropping
    # either leaves a gate that exists but never runs in the regression suite.
    for _tests_dir in (os.path.join(REPO, "tests"), os.path.join(os.path.dirname(REPO), "tests")):
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

    # ---- METERED-SPEND GUARD: report and fail if the gate touched a paid API ----------------
    _spent = _ledger_len() - _spend_before
    unit_total += 1
    if _spent > 0:
        unit_failed += 1
        detail = ""
        try:
            with open(_ledger, encoding="utf-8") as fh:
                rows = [json.loads(x) for x in fh if x.strip()][-_spent:]
            by = {}
            for r in rows:
                k = f"{r.get('provider')}:{r.get('action')}"
                by[k] = by.get(k, 0) + int(r.get("credits") or 1)
            detail = "  ".join(f"{k}={v}" for k, v in sorted(by.items()))
        except Exception:                                        # noqa: BLE001 — reporting only
            pass
        print(f"\n\033[31m✗\033[0m [UNIT] metered-spend guard — the gate spent {_spent} "
              f"metered call(s) on a PAID API: {detail}")
        print("      A regression gate must be free to run. Stub the new provider in the unit "
              "module that reached it (see test_ippivot's `saved`/mock block for the pattern).")
    else:
        print("\n\033[32m✔\033[0m [UNIT] metered-spend guard — the gate reached no paid API "
              "(MEMORY/api_usage.jsonl unchanged)")

    npass = len(cases) - failed_cases
    total_failed = failed_cases + unit_failed
    print(f"\n{'='*56}\n{npass}/{len(cases)} cases + {unit_total - unit_failed}/{unit_total} unit passed"
          + (f", \033[31m{total_failed} FAILED\033[0m" if total_failed else " \033[32m(all green)\033[0m"))
    return total_failed


if __name__ == "__main__":
    sys.exit(main())
