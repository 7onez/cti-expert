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

echo "== 1. leak check (RULE 1) on the staged diff =="
# leakcheck is DIFF-based on purpose: it flags newly-added case data, not the curated example
# values already in the docs/tests (UA-100000001, registrant@163.com fixtures, sample wallets…).
# Locally this scans your staged changes; in CI it is empty (nothing staged) and the workflow's
# own step scans the PR diff vs base instead.
if bash scripts/leakcheck.sh >/tmp/audit_lk 2>&1; then
  note "clean (staged diff)"
else
  cat /tmp/audit_lk; bad "leakcheck found newly-added case data"
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

echo "== 3. the 5 collector shims are re-exports, not copies (RULE 4) =="
for s in intel_engine/WebPivot/tools/pivot_extract.py intel_engine/WebPivot/tools/cdn_ranges.py \
         intel_engine/WebPivot/tools/graph_build.py intel_engine/WebPivot/tools/wayback_ga.py \
         scripts/webpivot/whois_enrich.py; do
  if [ "$(wc -l < "$s")" -lt 20 ] && grep -q spec_from_file_location "$s"; then
    note "shim ok: $(basename "$s")"
  else
    bad "looks like a copy, not a re-export: $s"
  fi
done

echo "== 4. @tool count matches CLAUDE.md RULE 3 =="
n="$(grep -cE '^@tool\(' intel_engine/harness/tools.py)"
doc="$(grep -oE 'every .@tool. \(([0-9]+) today' CLAUDE.md | grep -oE '[0-9]+' | head -1)"
if [ "$n" = "$doc" ]; then note "@tool count $n matches CLAUDE.md"; else bad "@tool count is $n but CLAUDE.md says $doc"; fi

echo "== 5. core modules byte-compile =="
if python3 -m py_compile intel_engine/tools/collect_core.py intel_engine/tools/intel.py \
        intel_engine/harness/tools.py 2>/tmp/audit_pc; then note "compile ok"; else cat /tmp/audit_pc; bad "compile failed"; fi

echo "== 6. zero-dep test runners =="
for t in tests/test_collect_core.py tests/test_indicator_classification.py; do
  if python3 "$t" >/tmp/audit_t 2>&1; then note "PASS $t"; else cat /tmp/audit_t; bad "$t"; fi
done

echo
if [ "$fail" = 0 ]; then echo "AUDIT: clean"; else echo "AUDIT: failures above"; exit 1; fi
