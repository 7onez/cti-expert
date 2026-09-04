#!/usr/bin/env bash
# audit.sh — structural drift + leak gate for cti-expert.
#
# Stdlib/grep only (no claude_agent_sdk, no venv), so it runs in plain CI and locally in seconds.
# Catches the failure modes CLAUDE.md's rules exist to prevent: leaked case data (RULE 1), a
# collector shim silently turned back into a copy (RULE 4), a DISPATCH op with no script behind it,
# a doc count that drifted from reality (RULE 3), and a regression in the shared collector core.
#
#   bash scripts/audit.sh          # exit 0 = clean, non-zero = a gap listed above
set -uo pipefail
root="$(git rev-parse --show-toplevel)"; cd "$root"
fail=0
note(){ printf '  %s\n' "$1"; }
bad(){ printf '  FAIL: %s\n' "$1"; fail=1; }

echo "== 1. leak check (RULE 1) =="
# Two passes, because they answer different questions.
#
# DIFF pass — what this commit ADDS. Added lines only: a `-` line is a leak leaving, and refusing
# that made the gate self-locking (the only way to remove a leaked value was --no-verify, i.e. the
# gate pushed you toward the exact bypass it exists to prevent). Locally this scans your staged
# changes; in CI it is empty (nothing staged) and the workflow's own step scans the PR diff.
if bash scripts/leakcheck.sh >/tmp/audit_lk 2>&1; then
  note "clean (staged diff)"
else
  cat /tmp/audit_lk; bad "leakcheck found newly-added case data"
fi
# TREE pass — what is ALREADY there. The diff pass can only ever see lines someone touched, so a
# leak that predates the hook lives forever in a file nobody edits. This scans every tracked text
# file. Four such values survived for months exactly this way, in usage examples nobody had reason
# to open. Skips binaries; the file mode reads whole files, not a diff.
lkfiles="$(git ls-files | grep -vE '\.(png|jpg|jpeg|gif|svg|pdf|ico|woff2?|zip|gz|tgz)$')"
if [ -n "$lkfiles" ] && bash scripts/leakcheck.sh $lkfiles >/tmp/audit_lk2 2>&1; then
  note "clean (all $(printf '%s\n' "$lkfiles" | wc -l | tr -d ' ') tracked text files)"
else
  cat /tmp/audit_lk2; bad "leakcheck found case data already present in a tracked file"
fi

echo "== 2. every DISPATCH op resolves to a script (no dangling command, RULE 3) =="
python3 - <<'PY' || fail=1
import re, os, sys
src = open("scripts/backend/intel.py").read()
m = re.search(r"DISPATCH\s*=\s*\{(.*?)\n\}", src, re.S)
ops = re.findall(r'"([a-z-]+)":\s*\("([^"]+)"', m.group(1))
miss = [(o, s) for o, s in ops if not os.path.isfile(os.path.join("intel_engine", s))]
print(f"  {len(ops)} ops, {len(ops) - len(miss)} resolve to a real script")
for o, s in miss:
    print("  FAIL missing:", o, "->", s)
sys.exit(1 if miss else 0)
PY

echo "== 3. each of the 5 collectors is ONE canonical + ONE shim (RULE 4) =="
# Checked as a PAIR, not as a fixed list of which-side-is-the-shim: whichever layer holds the
# canonical is an implementation detail that legitimately changes (pivot_extract's facade has to
# sit beside the wp_* siblings it imports by bare name, so its shim is the scripts/ copy, while
# whois_enrich's is the other way round). What must NEVER change is the invariant — exactly one
# real implementation and one re-export. Two copies is the drift RULE 4 exists to stop; two shims
# means the import chain has no implementation at all. Pinning the direction instead of the
# invariant makes this check fail on a correct refactor and stay silent on a real regression.
for name in pivot_extract cdn_ranges graph_build wayback_ga whois_enrich; do
  a="intel_engine/WebPivot/tools/$name.py"; b="scripts/webpivot/$name.py"
  if [ ! -f "$a" ] || [ ! -f "$b" ]; then bad "$name: expected a copy in BOTH layers"; continue; fi
  n_shim=0; canon=""
  for s in "$a" "$b"; do
    if [ "$(wc -l < "$s")" -lt 25 ] && grep -q spec_from_file_location "$s"; then
      n_shim=$((n_shim + 1))
    else
      canon="$s"
    fi
  done
  case "$n_shim" in
    1) note "shim ok: $name (canonical: $canon)" ;;
    0) bad "$name: BOTH layers are copies — the shim was turned back into a duplicate" ;;
    *) bad "$name: BOTH layers are shims — no implementation behind the re-export" ;;
  esac
done

echo "== 4. @tool count matches CLAUDE.md RULE 3 =="
n="$(grep -cE '^@tool\(' intel_engine/harness/tools.py)"
doc="$(grep -oE 'every .@tool. \(([0-9]+) today' CLAUDE.md | grep -oE '[0-9]+' | head -1)"
if [ "$n" = "$doc" ]; then note "@tool count $n matches CLAUDE.md"; else bad "@tool count is $n but CLAUDE.md says $doc"; fi

echo "== 5. core modules byte-compile =="
if python3 -m py_compile intel_engine/tools/collect_core.py intel_engine/tools/intel.py \
        intel_engine/harness/tools.py 2>/tmp/audit_pc; then note "compile ok"; else cat /tmp/audit_pc; bad "compile failed"; fi

echo "== 5b. no live credential in the committed tree (values, not names) =="
# A pasted key must live in .env (gitignored) only. Match common vendor key SHAPES against every
# tracked file; .env.example is allowed to carry the NAME but never a value after '='.
if git ls-files -z | xargs -0 grep -nE \
     -e '\b(sk|pk)_(live|test)_[A-Za-z0-9]{16,}' \
     -e '\bAKIA[0-9A-Z]{16}\b' \
     -e '\bghp_[A-Za-z0-9]{36}\b' \
     -e '\bxox[abpr]-[A-Za-z0-9-]{20,}' \
     -e '^[A-Z][A-Z0-9_]*(API_)?(KEY|TOKEN|PAT|SECRET|PASSWORD)=[^# ]{16,}' \
     2>/dev/null | grep -v 'scripts/audit.sh'; then
  bad "credential-shaped value in a tracked file — move it to .env"
else
  note "no credential-shaped values in tracked files"
fi

echo "== 6. zero-dep test runners =="
# Tests stub vendor HTTP but the clients still ledger the (mocked) call; that must never land in the
# real MEMORY/api_usage.jsonl — it inflates the Censys/urlscan monthly budgets with phantom credits.
export API_USAGE_LOG="$(mktemp)"   # bare mktemp: portable (BSD/macOS reject a non-X suffix)
for t in tests/test_collect_core.py tests/test_indicator_classification.py \
         tests/test_references.py tests/test_no_sample_submission.py \
         tests/test_email_permute.py tests/test_hooks.py \
         tests/test_phish_domain_survival.py tests/test_clickfix_detect.py \
         tests/test_html_visibility_analysis.py tests/test_apk_permission_scope.py \
         tests/test_kit_template_fingerprint.py tests/test_render_confirm.py \
         tests/test_phishtrace_features.py tests/test_engine_additions.py \
         tests/test_whois_phone_ingest.py tests/test_wildcard_frontier_guard.py \
         tests/test_title_pivot.py tests/test_case_pipeline_smoke.py \
         tests/test_pipeline_step_timeout.py tests/test_key_alias_registry.py \
         tests/test_house_report_compose.py tests/test_docx_timeline_chart.py \
         tests/test_deep_archive.py tests/test_house_report_mo_neighbours.py \
         tests/test_intelx_autofire.py tests/test_shodan_search.py; do
  if python3 "$t" >/tmp/audit_t 2>&1; then note "PASS $t"; else cat /tmp/audit_t; bad "$t"; fi
  # EXIT CONTRACT: a §6 file is only a gate if a failure makes it exit nonzero. A file written in the
  # run_eval tuple-`check()` style that never calls check()/exits reports PASS while testing nothing.
  if ! grep -qE 'SystemExit\(|sys\.exit\(' "$t"; then bad "$t has no nonzero-exit path (SystemExit/sys.exit) — it can never redden this gate"; fi
done
# …and prove the shape works: a deliberately failing file MUST redden the same check.
_smoke="$(mktemp)"; printf 'raise SystemExit(1)\n' > "$_smoke"
if python3 "$_smoke" >/dev/null 2>&1; then bad "§6 exit-contract smoke: a failing test file did NOT exit nonzero"; else note "§6 exit-contract smoke: a failing file reddens the gate"; fi
rm -f "$_smoke"

echo "== 7. every hook the plugin registers exists on disk (RULE 3, hook layer) =="
# A hooks.json entry pointing at a script that was moved or renamed fails SILENTLY: Claude Code
# logs it and carries on, so the rail is gone and nothing says so. Resolve each registered path.
if [ -f hooks/hooks.json ]; then
  miss=0
  for p in $(python3 - <<'PY'
import json
d = json.load(open("hooks/hooks.json"))
for groups in d.get("hooks", {}).values():
    for g in groups:
        for h in g.get("hooks", []):
            for a in h.get("args", []):
                if a.startswith("${CLAUDE_PLUGIN_ROOT}/"):
                    print(a.replace("${CLAUDE_PLUGIN_ROOT}/", ""))
PY
  ); do
    if [ -f "$p" ]; then note "hook resolves: $p"; else bad "hooks.json registers a missing script: $p"; miss=1; fi
  done
  [ "$miss" = 0 ] && note "all registered hooks resolve"
else
  bad "hooks/hooks.json missing — the RULE 1 write-time gate and the outbound gate are not wired"
fi

echo "== 8. registered command count matches commands/ across SKILL.md + the 3 READMEs (RULE 3, command layer) =="
# The drift this catches: a new commands/*.md ships but a doc still advertises the old count or never
# names it (exactly how /cti-proxy slipped past all three READMEs). Compare the architecture-tree
# count and every command basename against each README, and each /slash-name against SKILL.md.
n_cmd="$(ls commands/*.md 2>/dev/null | wc -l | tr -d ' ')"
cmd_ok=1
for f in README.md README.vi.md README.zh-CN.md; do
  d="$(grep -oE '[0-9]+ (registered slash commands|条已注册斜杠命令)' "$f" | grep -oE '^[0-9]+' | head -1)"
  if [ "$d" = "$n_cmd" ]; then note "$f tree count $d matches commands/ ($n_cmd)"; else bad "$f tree count '$d' != commands/ ($n_cmd)"; cmd_ok=0; fi
  for c in commands/*.md; do
    grep -qF "$(basename "$c")" "$f" || { bad "$f never names $(basename "$c")"; cmd_ok=0; }
  done
done
for c in commands/*.md; do
  s="/$(basename "$c" .md)"
  grep -qF "$s" SKILL.md || { bad "SKILL.md never documents $s"; cmd_ok=0; }
done
[ "$cmd_ok" = 1 ] && note "all $n_cmd commands referenced in SKILL.md + all 3 READMEs"

echo
if [ "$fail" = 0 ]; then echo "AUDIT: clean"; else echo "AUDIT: failures above"; exit 1; fi
