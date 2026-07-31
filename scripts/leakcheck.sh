#!/usr/bin/env bash
# leakcheck.sh — fail if case/investigation data is about to enter a tracked file (CLAUDE.md RULE 1).
#
# Scans the STAGED diff by default; pass file paths to scan those instead.
#   bash scripts/leakcheck.sh                 # staged diff
#   bash scripts/leakcheck.sh SKILL.md a.md   # specific files
#
# Exit 0 = clean, 1 = leak found. Wire it as a pre-commit hook to enforce rather than document.
#
# NOTE ON -i: the ID patterns run CASE-SENSITIVELY on purpose. With `grep -i`, `G-[A-Z0-9]{6}`
# matches inside ordinary hyphenated words ("findin(g-framew)ork", "GA-(GTM-AdSen)se") and the
# check produces false positives on its own docs — which teaches people to ignore it.
set -uo pipefail

if [ "$#" -gt 0 ]; then
  SRC="$(cat "$@")"
else
  SRC="$(git diff --cached)"
fi
[ -n "$SRC" ] && printf '%s' "$SRC" > /tmp/.leakcheck.$$ || : > /tmp/.leakcheck.$$
F=/tmp/.leakcheck.$$
trap 'rm -f "$F"' EXIT

# Approved placeholders from CLAUDE.md's example table — never a leak.
ALLOW='X{5,}|example\.(com|org)|CASE-0001|ExampleBitcoinAddress'

HITS="$(
  {
    # personal mail providers — case-insensitive is safe here
    grep -inE '@(gmail|yahoo|hotmail|outlook|proton|163|qq)\.(com|cn)' "$F"
    # analytics / wallets / case IDs — case-SENSITIVE, anchored on word boundaries
    grep -nE '\b(G-[A-Z0-9]{10}|GTM-[A-Z0-9]{7}|UA-[0-9]{6,}|0x[a-fA-F0-9]{40}|T[A-Za-z0-9]{33})\b' "$F"
    grep -nE '\bCASE-20[0-9]{2}' "$F"
  } 2>/dev/null | grep -viE "$ALLOW" | sort -u
)"

if [ -n "$HITS" ]; then
  echo "LEAK: case data in a tracked file (CLAUDE.md RULE 1)" >&2
  printf '%s\n' "$HITS" >&2
  echo >&2
  echo "Move it to the git-ignored stores (intel_engine/cases|knowledge|MEMORY)," >&2
  echo "or replace it with a placeholder from CLAUDE.md's example table." >&2
  exit 1
fi
echo "clean"
