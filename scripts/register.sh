#!/usr/bin/env bash
# register.sh — register cti-expert with Claude Code AND every other coding agent on this machine.
#
# Distinct from install.sh, which installs the third-party OSINT *tools* (theHarvester,
# TruffleHog, …). This script only wires the skill into the agents:
#   1. SKILL     -> ~/.claude/skills/cti-expert       (symlink to this repo)
#   2. COMMANDS  -> ~/.claude/commands/cti*.md        (symlinks to commands/)
#   3. MCP reg   -> ./.mcp.json                       (git-ignored, per-machine)
#   4. OTHER AGENTS -> scripts/register_agents.py     (omp, pi, OpenCode, Gemini CLI, Qwen Code,
#      Factory droid, Windsurf; `cti` skill for Codex / ChatGPT desktop / Cursor / Copilot CLI)
#
# Claude gets symlinks and other agents get pointer stubs naming this repo's absolute path, so
# `git pull` updates every installed copy with no re-run. Idempotent — safe to run repeatedly.
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
err()  { printf '  \033[31mx\033[0m %s\n' "$1" >&2; FAIL=1; }
FAIL=0

# Python 3.10+: the repo venv (POSIX or Windows layout), then python3 / python / the Windows `py`
# launcher. Each candidate must actually run: on Windows `python3` is often a Microsoft Store stub.
pyok() { "$@" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; }
PYR=()
for c in "$REPO/.venv/bin/python" "$REPO/.venv/Scripts/python.exe" python3 python; do
  if pyok "$c"; then PYR=("$c"); break; fi
done
if [ ${#PYR[@]} -eq 0 ] && pyok py -3; then PYR=(py -3); fi

agents() {  # register_agents.py; nonzero when it could not run or failed
  if [ ${#PYR[@]} -eq 0 ]; then
    warn "no Python 3.10+ found (tried .venv, python3, python, py -3)"
    return 1
  fi
  if [ "$DRY" = 1 ]; then set -- --dry-run "$@"; fi
  "${PYR[@]}" "$REPO/scripts/register_agents.py" "$@"
}

# Ours = a symlink resolving to this repo's own source. A real file, or a link to anything else, is
# the user's: install skips those ("yours wins"), so uninstall must leave them too. The exception is
# a marked pointer stub (the Windows fallback below), which register_agents.py owns and removes.
ours() { [ -L "$1" ] && [ "$1" -ef "$2" ]; }
stub() { [ -f "$1" ] && [ ! -L "$1" ] && grep -qF 'cti-expert:generated' "$1"; }

# Git Bash's `ln -s` silently COPIES unless told otherwise; a copy goes stale after `git pull` and
# then reads as a user file. Ask for a real Windows symlink (needs Developer Mode or admin) and fall
# back to a marked pointer stub when Windows refuses.
WIN=0
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*)
    WIN=1
    export MSYS="${MSYS:+$MSYS }winsymlinks:nativestrict"
    export CYGWIN="${CYGWIN:+$CYGWIN }winsymlinks:nativestrict" ;;
esac

if [ "$UNINSTALL" = 1 ]; then
  echo "Unregistering cti-expert..."
  if ours "$SKILL_LINK" "$REPO"; then
    run "rm -f '$SKILL_LINK'"; ok "skill link removed"
  elif [ -e "$SKILL_LINK" ] || [ -L "$SKILL_LINK" ]; then
    warn "$SKILL_LINK is not a link to this repo - left alone"
  fi
  n=0
  for f in "$REPO"/commands/*.md; do
    [ -e "$f" ] || continue
    dest="$CMD_DIR/$(basename "$f")"
    if ours "$dest" "$f"; then
      run "rm -f '$dest'"; n=$((n+1))
    elif stub "$dest"; then
      :  # Windows fallback stub - removed by register_agents.py below
    elif [ -e "$dest" ] || [ -L "$dest" ]; then
      warn "$(basename "$f") is not a link to this repo - left alone (yours wins)"
    fi
  done
  ok "command symlinks removed ($n)"
  agents --uninstall || err "register_agents.py --uninstall failed - other agents' stubs may remain"
  echo "  (.mcp.json, cases/ and knowledge/ left untouched)"
  exit "$FAIL"
fi

echo "Registering cti-expert from $REPO"

# -- 1. skill ---------------------------------------------------------------
run "mkdir -p '$CLAUDE_DIR/skills'"
if [ "$SKILL_LINK" -ef "$REPO" ] && [ ! -L "$SKILL_LINK" ]; then
  ok "skill    -> $SKILL_LINK (this clone)"
elif [ -e "$SKILL_LINK" ] && [ ! -L "$SKILL_LINK" ]; then
  warn "$SKILL_LINK exists and is NOT a symlink - left alone. Remove it and re-run."
elif run "ln -sfn '$REPO' '$SKILL_LINK'" 2>/dev/null; then
  ok "skill    -> $SKILL_LINK"
else
  warn "could not symlink $SKILL_LINK - enable Windows Developer Mode, or clone the repo straight into it"
fi

# -- 2. commands ------------------------------------------------------------
run "mkdir -p '$CMD_DIR'"
n=0; fb=0
for f in "$REPO"/commands/*.md; do
  [ -e "$f" ] || continue
  dest="$CMD_DIR/$(basename "$f")"
  if [ -e "$dest" ] && [ ! -L "$dest" ]; then
    if stub "$dest" || { [ "$WIN" = 1 ] && cmp -s "$dest" "$f"; }; then
      run "rm -f '$dest'"  # our stub, or a copy Git Bash made instead of a link: retry the link
    else
      warn "$(basename "$f") exists as a real file - skipped (yours wins)"
      continue
    fi
  fi
  if run "ln -sfn '$f' '$dest'" 2>/dev/null && { [ "$DRY" = 1 ] || [ -L "$dest" ]; }; then
    n=$((n+1))
  else
    { [ -L "$dest" ] || [ ! -e "$dest" ]; } || run "rm -f '$dest'"  # a copy is not a link
    fb=$((fb+1))
  fi
done
ok "commands -> $CMD_DIR  ($n linked)"
if [ "$fb" -gt 0 ]; then
  warn "$fb command(s) could not be symlinked - writing pointer stubs (Windows: enable Developer Mode for real links)"
  CLAUDE_CONFIG_DIR="$CLAUDE_DIR" agents --host claude \
    || err "could not write Claude Code stubs - /cti is NOT registered (install Python 3.10+ or enable Developer Mode, then re-run)"
fi

# -- 3. MCP registration (git-ignored: holds an absolute path) --------------
if [ -f "$REPO/.mcp.json" ]; then
  ok ".mcp.json already present"
elif [ "$DRY" = 1 ]; then
  echo "  [dry-run] intel.py mcp --write"
else
  if [ ${#PYR[@]} -gt 0 ] && ( cd "$REPO" && "${PYR[@]}" scripts/backend/intel.py mcp --write >/dev/null 2>&1 ); then
    ok "wrote .mcp.json"
  else
    warn "could not write .mcp.json - run: python3 scripts/backend/intel.py mcp --write"
  fi
fi

# -- 4. other coding agents (auto-detected) --------------------------------
echo
echo "Other coding agents (pointer stubs; --list / --host all: scripts/register_agents.py):"
agents || err "other agents not registered (scripts/register_agents.py did not complete)"

# -- verify -----------------------------------------------------------------
echo
echo "Verifying..."
if [ -f "$SKILL_LINK/SKILL.md" ]; then ok "SKILL.md reachable"; else warn "SKILL.md NOT reachable"; fi
missing=0
for f in "$REPO"/commands/*.md; do
  [ -e "$f" ] || continue
  [ -f "$CMD_DIR/$(basename "$f")" ] || missing=$((missing+1))
done
if [ "$missing" = 0 ]; then ok "all commands resolve"
elif [ "$DRY" = 1 ]; then warn "$missing command(s) not linked yet (dry run)"
else err "$missing command(s) did not resolve in $CMD_DIR"; fi
if [ -x "$REPO/.venv/bin/python" ] || [ -x "$REPO/.venv/Scripts/python.exe" ]; then
  ( cd "$REPO" && "${PYR[@]}" scripts/backend/backend.py status 2>/dev/null | head -1 | sed 's/^/  /' ) || true
else
  warn "no .venv - run: uv venv && uv pip install -r requirements.txt"
fi

if [ "$FAIL" = 1 ]; then
  echo >&2
  echo "Registration INCOMPLETE - fix the x lines above and re-run." >&2
  exit 1
fi

cat <<'DONE'

Registered. RESTART each agent - skills and commands load at startup.

  /cti <target>            THE ENTRY POINT - routes any target type
                           (Codex: $cti <target> - Codex invokes skills with $, never /)
  /cti-recall <seed>       have I seen this before?  (always run first)
  /cti-case <ID> <seeds>   full pipeline
  /cti-status              health check

Plain English works too: "analyze example.com and pivot the infrastructure".
DONE
