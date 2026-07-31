#!/usr/bin/env bash
# register.sh — register cti-expert WITH CLAUDE CODE on this machine.
#
# Distinct from install.sh, which installs the third-party OSINT *tools* (theHarvester,
# TruffleHog, …). This script only wires the skill into Claude Code:
#   1. SKILL     -> ~/.claude/skills/cti-expert       (symlink to this repo)
#   2. COMMANDS  -> ~/.claude/commands/cti*.md        (symlinks to commands/)
#   3. MCP reg   -> ./.mcp.json                       (git-ignored, per-machine)
#
# Everything is a symlink, so `git pull` updates the installed copy with no re-run.
# Idempotent — safe to run repeatedly.
#
# Usage: bash scripts/register.sh [--uninstall] [--dry-run]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SKILL_LINK="$CLAUDE_DIR/skills/cti-expert"
CMD_DIR="$CLAUDE_DIR/commands"

DRY=0; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --dry-run)   DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)   sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

run()  { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else eval "$@"; fi; }
ok()   { printf '  \033[32m*\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

if [ "$UNINSTALL" = 1 ]; then
  echo "Unregistering cti-expert..."
  run "rm -f '$SKILL_LINK'"
  for f in "$REPO"/commands/*.md; do
    [ -e "$f" ] || continue
    run "rm -f '$CMD_DIR/$(basename "$f")'"
  done
  ok "skill + command symlinks removed"
  echo "  (.mcp.json, cases/ and knowledge/ left untouched)"
  exit 0
fi

echo "Registering cti-expert from $REPO"

# -- 1. skill ---------------------------------------------------------------
run "mkdir -p '$CLAUDE_DIR/skills'"
if [ -e "$SKILL_LINK" ] && [ ! -L "$SKILL_LINK" ]; then
  warn "$SKILL_LINK exists and is NOT a symlink - left alone. Remove it and re-run."
else
  run "ln -sfn '$REPO' '$SKILL_LINK'"
  ok "skill    -> $SKILL_LINK"
fi

# -- 2. commands ------------------------------------------------------------
run "mkdir -p '$CMD_DIR'"
n=0
for f in "$REPO"/commands/*.md; do
  [ -e "$f" ] || continue
  dest="$CMD_DIR/$(basename "$f")"
  if [ -e "$dest" ] && [ ! -L "$dest" ]; then
    warn "$(basename "$f") exists as a real file - skipped (yours wins)"
    continue
  fi
  run "ln -sfn '$f' '$dest'"
  n=$((n+1))
done
ok "commands -> $CMD_DIR  ($n linked)"

# -- 3. MCP registration (git-ignored: holds an absolute path) --------------
if [ -f "$REPO/.mcp.json" ]; then
  ok ".mcp.json already present"
elif [ "$DRY" = 1 ]; then
  echo "  [dry-run] intel.py mcp --write"
else
  PY="$REPO/.venv/bin/python"; [ -x "$PY" ] || PY="$(command -v python3)"
  if ( cd "$REPO" && "$PY" scripts/backend/intel.py mcp --write >/dev/null 2>&1 ); then
    ok "wrote .mcp.json"
  else
    warn "could not write .mcp.json - run: python3 scripts/backend/intel.py mcp --write"
  fi
fi

# -- verify -----------------------------------------------------------------
echo
echo "Verifying..."
if [ -f "$SKILL_LINK/SKILL.md" ]; then ok "SKILL.md reachable"; else warn "SKILL.md NOT reachable"; fi
missing=0
for f in "$REPO"/commands/*.md; do
  [ -e "$f" ] || continue
  [ -f "$CMD_DIR/$(basename "$f")" ] || missing=$((missing+1))
done
if [ "$missing" = 0 ]; then ok "all commands resolve"; else warn "$missing command(s) did not resolve"; fi
if [ -x "$REPO/.venv/bin/python" ]; then
  ( cd "$REPO" && .venv/bin/python scripts/backend/backend.py status 2>/dev/null | head -1 | sed 's/^/  /' ) || true
else
  warn "no .venv - run: uv venv && uv pip install -r requirements.txt"
fi

cat <<'DONE'

Registered. RESTART Claude Code - skills and commands load at startup.

  /cti <target>            THE ENTRY POINT - routes any target type
  /cti-recall <seed>       have I seen this before?  (always run first)
  /cti-case <ID> <seeds>   full pipeline
  /cti-status              health check

Plain English works too: "analyze example.com and pivot the infrastructure".
DONE
