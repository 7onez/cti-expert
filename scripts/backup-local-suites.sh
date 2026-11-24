#!/usr/bin/env bash
# backup-local-suites.sh — encrypted archive of the LOCAL-ONLY regression suites.
#
# The suites (tests/, intel_engine/tests/, intel_engine/tools/eval/, every test_*.py) are
# gitignored by rule and never committed or pushed (CLAUDE.md "Before you commit"), so they exist
# on one disk. This writes them to an encrypted archive OUTSIDE the repository and can prove the
# archive restores.
#
#   bash scripts/backup-local-suites.sh <dest-dir> [--with-labels] [--passphrase-file <path>]
#   bash scripts/backup-local-suites.sh --verify <archive.tar.gz.gpg> [--passphrase-file <path>]
#
#   <dest-dir>           must be outside this repository and outside any Git work tree; keep it on
#                        offline or removable storage, never a synced folder or a Git remote.
#   --with-labels        also archive the benchmark labels (intel_engine/cases/*/ground_truth.json)
#                        and intel_engine/MEMORY/bench/. Off by default: those files are case data.
#   --passphrase-file    read the passphrase from a file outside the repository instead of the
#                        gpg prompt. Never pass a passphrase on the command line or keep it in .env.
#
# There is no unencrypted mode: a previous QA run found tests that had written into the real
# cases/ and MEMORY/ paths, so the suites may hold residue.
# A LOST PASSPHRASE LOSES THE BACKUP. Nothing here can recover it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
die() { echo "backup-local-suites: $*" >&2; exit 1; }
usage() { sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

inside_repo() {  # true when the resolved path is the repository or below it
  local p; p="$(realpath -m -- "$1")"
  [ "$p" = "$REPO" ] || [ "${p#"$REPO"/}" != "$p" ]
}

MODE=backup DEST="" ARCHIVE="" PASSFILE="" LABELS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --verify) MODE=verify; ARCHIVE="${2:-}"; shift 2 || usage ;;
    --with-labels) LABELS=1; shift ;;
    --passphrase-file) PASSFILE="${2:-}"; shift 2 || usage ;;
    -h|--help) usage 0 ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$DEST" ] || die "one destination directory only"; DEST="$1"; shift ;;
  esac
done
command -v gpg >/dev/null || die "gpg not found"
# Resolve every path NOW, from the caller's directory: the script changes directory later, and a
# relative destination such as `.` would otherwise be checked in one place and written in another.
[ -z "$DEST" ] || DEST="$(realpath -m -- "$DEST")"
[ -z "$PASSFILE" ] || PASSFILE="$(realpath -m -- "$PASSFILE")"
[ -z "$ARCHIVE" ] || ARCHIVE="$(realpath -m -- "$ARCHIVE")"

GPG=(gpg --quiet)
if [ -n "$PASSFILE" ]; then
  [ -f "$PASSFILE" ] || die "passphrase file not found: $PASSFILE"
  inside_repo "$PASSFILE" && die "the passphrase file must live outside the repository"
  GPG+=(--batch --yes --pinentry-mode loopback --passphrase-file "$PASSFILE")
fi

if [ "$MODE" = verify ]; then
  [ -f "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
  if [ -f "$ARCHIVE.sha256" ]; then
    (cd "$(dirname "$ARCHIVE")" && sha256sum --quiet -c "$(basename "$ARCHIVE").sha256") \
      || die "checksum mismatch — the archive changed after it was written"
  else
    echo "note: no $ARCHIVE.sha256 beside the archive; checksum not verified" >&2
  fi
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  "${GPG[@]}" --decrypt --output "$TMP/suites.tar.gz" "$ARCHIVE" || die "decryption failed"
  listed="$(tar -tzf "$TMP/suites.tar.gz" | grep -vc '/$' || true)"
  mkdir "$TMP/restore" && tar -xzf "$TMP/suites.tar.gz" -C "$TMP/restore"
  restored="$(find "$TMP/restore" -type f | wc -l | tr -d ' ')"
  [ "$listed" = "$restored" ] || die "restored $restored file(s) but the archive lists $listed"
  bad=0
  while IFS= read -r -d '' f; do
    python3 -m py_compile "$f" 2>/dev/null || { echo "does not compile: ${f#"$TMP/restore/"}" >&2; bad=1; }
  done < <(find "$TMP/restore" -name '*.py' -print0)
  [ "$bad" = 0 ] || die "a restored Python file does not compile"
  echo "verified: $restored file(s) restore and every Python file compiles"
  exit 0
fi

[ -n "$DEST" ] || usage
[ -d "$DEST" ] || die "destination directory does not exist: $DEST"
inside_repo "$DEST" && die "the destination must be outside the repository ($REPO)"
git -C "$DEST" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && die "the destination is inside a Git work tree; tests must never reach a repository"

# One definition of "a test file": the pattern the pre-commit / pre-push guards enforce.
TEST_RE="$(sed -n "s/^TEST_RE='\(.*\)'$/\1/p" "$REPO/scripts/install-hooks.sh" | head -1)"
[ -n "$TEST_RE" ] || die "could not read TEST_RE from scripts/install-hooks.sh"

LIST="$(mktemp)"; trap 'rm -f "$LIST"' EXIT
cd "$REPO"
git ls-files --others --ignored --exclude-standard -- . \
    ':!.venv' ':!.agents' ':!.claude' ':!vendor' ':!scripts/vendor' \
    ':!intel_engine/cases' ':!intel_engine/knowledge' \
    ':!intel_engine/MEMORY' ':!intel_engine/cache' \
  | grep -E "$TEST_RE" | grep -vE '(^|/)(__pycache__|\.pytest_cache)/|\.pyc$' > "$LIST" || true
if [ "$LABELS" = 1 ]; then
  find intel_engine/cases -mindepth 2 -maxdepth 2 -name ground_truth.json -type f >> "$LIST" 2>/dev/null || true
  if [ -d intel_engine/MEMORY/bench ]; then find intel_engine/MEMORY/bench -type f >> "$LIST"; fi
fi
count="$(wc -l < "$LIST" | tr -d ' ')"
[ "$count" -gt 0 ] || die "no local-only suite files found — is this a checkout without them?"

OUT="$(realpath -- "$DEST")/cti-expert-suites-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.gpg"
tar -czf - -T "$LIST" | "${GPG[@]}" --symmetric --cipher-algo AES256 --output "$OUT"
[ -s "$OUT" ] || die "no archive was written"
(cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "wrote $OUT ($count file(s), $(du -h "$OUT" | cut -f1))"
echo "check it restores:  bash scripts/backup-local-suites.sh --verify '$OUT'"
echo "a lost passphrase loses this backup."
