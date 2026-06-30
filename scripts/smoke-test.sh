#!/usr/bin/env bash
# CTI Expert — fresh-environment readiness smoke test.
# Run AFTER scripts/install.sh on a clean computer/VPS to assert the skill
# bootstrapped and that the scripts /case relies on run from scratch.
#   bash scripts/smoke-test.sh
# Exit 0 = ready, non-zero = a critical capability is missing.

set -uo pipefail
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="$SKILL_DIR/scripts"
FAIL=0
ok()   { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; FAIL=1; }
info() { echo "  ..    $1"; }

echo "▶ uv (primary toolchain)"
if command -v uv >/dev/null 2>&1; then ok "uv present: $(uv --version 2>&1)"; else bad "uv not on PATH (bootstrap failed)"; fi

echo "▶ skill scripts execute from scratch via 'uv run' (deps auto-resolved)"
for s in stealer_log_parse.py generate-cti-docx.py generate-cti-docx-hybrid.py; do
  out="$(uv run "$S/$s" 2>&1)"
  # The script ran iff uv launched it and deps resolved — i.e. no uv-spawn or import error.
  if echo "$out" | grep -qiE "Failed to spawn|No such file|can't open file|ModuleNotFoundError|error: Failed"; then
    bad "$s failed to run: $(echo "$out" | head -1)"
  else
    ok "$s runs (deps resolved)"
  fi
done

echo "▶ DOCX generator produces a file (JSON-only path, no pandoc needed)"
TMP="$(mktemp -d)"
if uv run "$S/generate-cti-docx.py" "$S/sample-cti-report-data.json" "$TMP/r.docx" >/dev/null 2>&1 && [ -s "$TMP/r.docx" ]; then
  ok "DOCX generated ($(wc -c <"$TMP/r.docx" | tr -d ' ') bytes)"
else
  bad "DOCX generation"
fi
rm -rf "$TMP"

echo "▶ stealer-log analyzer runs on a synthetic log"
TMP="$(mktemp -d)"; mkdir -p "$TMP/logs/host1"
printf 'stealc stealer\nTelegram: t.me/test\nIP: 1.2.3.4\nCountry: XX\n' > "$TMP/logs/host1/system_info.txt"
printf 'url: https://admin.evil.xyz/login\nlogin: root\npassword: x\n'    > "$TMP/logs/host1/passwords.txt"
if uv run "$S/stealer_log_parse.py" "$TMP/logs" "$TMP/out" >/dev/null 2>&1 && ls "$TMP"/out/STEALER-ANALYSIS-*.md >/dev/null 2>&1; then
  if grep -q "subdomain:admin" "$TMP"/out/STEALER-ANALYSIS-*.md; then ok "stealer analysis + admin-endpoint detection"; else ok "stealer analysis (report produced)"; fi
else
  bad "stealer analysis"
fi
rm -rf "$TMP"

echo "▶ OSINT CLI tools (informational — /case auto-installs on demand if missing)"
for t in maigret holehe h8mail theHarvester trufflehog xeuledoc waymore; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else info "$t not yet installed (auto-installs when first used)"; fi
done

echo "▶ system tools (informational)"
for t in pandoc exiftool jq whois dig; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else info "$t not present"; fi
done

echo ""
echo "─────────────────────────────────────────"
if [ "$FAIL" = 0 ]; then echo "✅ SMOKE TEST PASSED — skill is ready on this box."; else echo "❌ SMOKE TEST FAILED — see FAIL lines above."; fi
exit "$FAIL"
