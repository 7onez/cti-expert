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

# Approved placeholders from CLAUDE.md's example table — never a leak. The UA entry is the
# synthetic placeholder range from that table (e.g. UA-100000001); a real UA carries a dashed
# property suffix, which this pattern deliberately does not match.
ALLOW='X{5,}|example\.(com|org)|CASE-0001|ExampleBitcoinAddress|UA-10000000[0-9]'
# The placeholder LOCAL-PARTS from CLAUDE.md's table (`registrant@…`, `operator@…`) stay
# placeholders whichever domain follows them. The noise-filter tests need a real personal-provider
# domain — asserting that `registrant@163.com` is NOT filtered is the whole point of the case — so
# the domain cannot be swapped for example.com without deleting the test's meaning.
ALLOW="$ALLOW"'|(registrant|operator)@'

# GENERIC PUBLIC CONSTANTS — enumerated one by one, never a class-wide hole.
#
# CLAUDE.md already exempts "generic public constants … the Sedo/Wix default-favicon hashes",
# because they describe the TOOLING, not a case. These are that same class in wallet/tracker shape:
# they exist in the code precisely so the clustering logic can EXCLUDE them, and treating one as an
# operator artifact is the false-positive the lists were written to prevent.
#
# Each entry is listed literally and justified. Adding a value here is a review decision, not a
# convenience: a bare `0x[0-9a-f]{40}` escape hatch would silence every real ETH wallet too.
#   TR7NHqje…  USDT-TRC20 token contract (Tron)      — wallet_base_rate_exclude
#   0xdAC17F…  USDT ERC-20 token contract (Ethereum) — wallet_base_rate_exclude
#   0x55d398…  USDT BEP-20 token contract (BSC)      — wallet_base_rate_exclude
#   0x0000…dEaD  the burn address                    — never an operator payee
#   0x529084…  the canonical EIP-55 checksum test vector from the spec itself
#   UA-26575989-44  a template-default Analytics property shared by unrelated sites —
#                   noise_tracker_ids, the same role as the parking-favicon hashes
# Verified before allowing: the two Tron strings were base58check-decoded. The contract above is
# valid (hence real, hence a genuine public constant); the Engage test fixture TJ8y5w… fails its
# checksum, i.e. it is synthetic by construction and needs no entry here.
PUBLIC_CONST='TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t|0xdAC17F958D2ee523a2206206994597C13D831ec7'
PUBLIC_CONST="$PUBLIC_CONST"'|0x55d398326f99059fF775485246999027B3197955'
PUBLIC_CONST="$PUBLIC_CONST"'|0x0{36}dEaD|0x52908400098527886E0F7030069857D2E4169EE7'
PUBLIC_CONST="$PUBLIC_CONST"'|UA-26575989-44'
ALLOW="$ALLOW|$PUBLIC_CONST"

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
