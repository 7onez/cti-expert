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
for s in stealer_log_parse.py generate-cti-docx.py generate-cti-docx-hybrid.py \
         iban_analyze.py redact.py; do
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

echo "▶ HTML report generator builds the primary deliverable (+ optional Archify Blueprint)"
TMP="$(mktemp -d)"
out="$(uv run "$S/generate-cti-html.py" "$S/sample-cti-report-data.json" "$TMP/r.html" 2>&1)"
if [ -s "$TMP/r.html" ] && grep -q 'id="cti-data"' "$TMP/r.html"; then
  ok "HTML report built"
  if echo "$out" | grep -q "Blueprint (Archify): embedded"; then
    ok "Archify Blueprint embedded (Node.js present)"
  else
    info "Archify Blueprint skipped ($(echo "$out" | grep -o 'not embedded — .*' | head -1))"
  fi
  echo "$out" | grep -q "Editorial (Diagram Design): embedded" && ok "Diagram Design editorial figures embedded" || info "editorial figures skipped"
  echo "$out" | grep -q "Cloud arch (Diagram AI Generator): embedded" && ok "Diagram AI Generator cloud figure embedded" || info "cloud figure skipped (no cloud infra / graphviz)"
else
  bad "HTML report did not build"
fi
rm -rf "$TMP"

echo "▶ diagram engines (Diagram Design editorial raster + graphviz)"
if uv run --with cairosvg python3 -c "import sys;sys.path.insert(0,'$S');import json,cti_diagram_design as dd;d=json.load(open('$S/sample-cti-report-data.json'));assert dd.render_svg_to_png(dd.build_entity_svg(d))" 2>/dev/null; then
  ok "editorial SVG rasterizes via cairosvg (DOCX figure path)"
else
  info "cairosvg raster unavailable — DOCX falls back to matplotlib"
fi
command -v dot >/dev/null 2>&1 && ok "graphviz dot (cloud architecture figure)" || info "graphviz not installed (cloud figure auto-skips)"

echo "▶ IBAN validator: accepts a known-good account, rejects a mutated checksum"
if uv run "$S/iban_analyze.py" GB29NWBK60161331926819 2>/dev/null | grep -q "VALID" \
   && uv run "$S/iban_analyze.py" GB29NWBK60161331926818 2>/dev/null | grep -q "INVALID"; then
  ok "iban_analyze mod-97 verdicts"
else
  bad "iban_analyze mod-97 verdicts"
fi

echo "▶ redactor: round-trip restores the original byte-for-byte"
TMP="$(mktemp -d)"
printf 'Contact a@b.com and +84901234567 about GB29NWBK60161331926819.\n' > "$TMP/in.md"
if uv run "$S/redact.py" "$TMP/in.md" -o "$TMP/red.md" --map "$TMP/m.json" >/dev/null 2>&1 \
   && grep -q "EMAIL_1" "$TMP/red.md" \
   && uv run "$S/redact.py" --restore "$TMP/red.md" --map "$TMP/m.json" -o "$TMP/back.md" >/dev/null 2>&1 \
   && cmp -s "$TMP/in.md" "$TMP/back.md"; then
  ok "redact -> restore is lossless"
else
  bad "redact -> restore round-trip"
fi
rm -rf "$TMP"

echo "▶ intel-backend resolver: reports a tier (Tier 3 stateless is a valid PASS)"
bk="$(uv run "$S/backend/backend.py" status 2>&1)"
if echo "$bk" | grep -q "Intel backend: Tier"; then
  ok "backend.py resolves ($(echo "$bk" | head -1 | sed 's/^Intel backend: //'))"
else
  bad "backend.py did not report a tier: $(echo "$bk" | head -1)"
fi

echo "▶ intel dispatcher: full op map is intact (works at any tier)"
di="$(uv run "$S/backend/intel.py" list 2>&1)"
# Spot-check ops from each phase group + the meta ops (mcp/list).
if echo "$di" | grep -q "harness" && echo "$di" | grep -q "reference" \
   && echo "$di" | grep -q "cdn-ranges" && echo "$di" | grep -q "pipeline" \
   && echo "$di" | grep -q "mcp "; then
  ok "intel.py dispatcher lists engine ops ($(echo "$di" | grep -cE '^  [a-z]' ) ops)"
else
  bad "intel.py list did not enumerate the full op set: $(echo "$di" | head -1)"
fi

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
for t in node pandoc exiftool jq whois dig; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else info "$t not present"; fi
done

echo ""
echo "─────────────────────────────────────────"
if [ "$FAIL" = 0 ]; then echo "✅ SMOKE TEST PASSED — skill is ready on this box."; else echo "❌ SMOKE TEST FAILED — see FAIL lines above."; fi
exit "$FAIL"
