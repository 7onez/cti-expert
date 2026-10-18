#!/usr/bin/env bash
# install-hooks.sh — (re)install this repo's git hooks.
#
# .git/hooks/ is per-clone and NOT tracked, so the hooks do not travel with the skill. Run this
# once per clone:
#
#   bash scripts/install-hooks.sh
#
# pre-commit  1. refuses staged test files (tests are LOCAL-ONLY, see .gitignore) — `git add -f`
#                cannot sneak one in;
#             2. enforces CLAUDE.md RULE 1 (no case data in tracked files) via scripts/leakcheck.sh.
# pre-push    refuses a pushed tip whose tree still contains a test file.
#
# Idempotent — safe to re-run.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
hooks="$root/.git/hooks"

# One pattern for both hooks; keep in step with the "Tests are LOCAL-ONLY" block in .gitignore.
TEST_RE='(^|/)tests/|^intel_engine/tools/eval/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$|(^|/)pytest\.ini$|smoke-test'

cat > "$hooks/pre-commit" <<EOF
#!/usr/bin/env bash
# pre-commit — tests never get committed; case data never leaks into tracked files (RULE 1).
# Re-install after a fresh clone with: bash scripts/install-hooks.sh
root="\$(git rev-parse --show-toplevel)" || exit 1
staged="\$(git diff --cached --name-only --diff-filter=ACMR | grep -E '$TEST_RE')"
if [ -n "\$staged" ]; then
  echo "pre-commit: test files are local-only and never committed. Unstage them:" >&2
  printf '  %s\n' \$staged >&2
  echo "  git restore --staged -- <path>" >&2
  exit 1
fi
exec bash "\$root/scripts/leakcheck.sh"
EOF

cat > "$hooks/pre-push" <<EOF
#!/usr/bin/env bash
# pre-push — refuse to push a tip whose tree contains a test file (tests are local-only).
zero=0000000000000000000000000000000000000000
rc=0
while read -r _lref lsha _rref _rsha; do
  [ "\$lsha" = "\$zero" ] && continue
  hits="\$(git ls-tree -r --name-only "\$lsha" | grep -E '$TEST_RE')"
  if [ -n "\$hits" ]; then
    echo "pre-push: \$lsha still tracks test files (local-only); untrack them first:" >&2
    printf '%s\n' "\$hits" | head -20 | sed 's/^/  /' >&2
    rc=1
  fi
done
exit \$rc
EOF

chmod +x "$hooks/pre-commit" "$hooks/pre-push"
echo "installed pre-commit (no tests + RULE 1 leak check) and pre-push (no tests) hooks"
