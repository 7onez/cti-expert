#!/usr/bin/env bash
# install-hooks.sh — (re)install this repo's git hooks.
#
# .git/hooks/ is per-clone and NOT tracked, so the leak-check hook does not travel with the
# skill. Run this once per clone to enforce CLAUDE.md RULE 1 (no case data in tracked files)
# on every commit:
#
#   bash scripts/install-hooks.sh
#
# Idempotent — safe to re-run. Bypass the hook for one commit with `git commit --no-verify`.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
hook="$root/.git/hooks/pre-commit"

cat > "$hook" <<'EOF'
#!/usr/bin/env bash
# pre-commit — block commits that would leak case/investigation data into tracked files.
# Enforces CLAUDE.md RULE 1 by running the tracked scanner on the STAGED diff.
# Re-install after a fresh clone with: bash scripts/install-hooks.sh
root="$(git rev-parse --show-toplevel)" || exit 1
exec bash "$root/scripts/leakcheck.sh"
EOF

chmod +x "$hook"
echo "installed pre-commit hook -> scripts/leakcheck.sh (RULE 1 leak check)"
