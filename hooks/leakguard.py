#!/usr/bin/env python3
"""leakguard.py — PreToolUse hook: stop RULE 1 case data at the moment it is WRITTEN.

WHY THIS EXISTS, GIVEN leakcheck.sh ALREADY RUNS
------------------------------------------------
`scripts/leakcheck.sh` is wired as a *git* pre-commit hook. That is the wrong moment for an agent
harness. In Claude Code the model writes files continuously and commits rarely, so a leaked
operator email or case domain can sit in the working tree for an entire session — visible to
anything that reads the repo, and one `git add -A` from being staged. Worse, the git hook is a
single flag from being skipped: `git commit --no-verify` bypasses it silently, and that is not
hypothetical (it happened in this repo on 2026-08-23).

This hook closes both gaps. It runs BEFORE the write lands, and `--no-verify` does not exist at
this layer.

SINGLE SOURCE OF TRUTH (RULE 4 in spirit)
-----------------------------------------
The RULE 1 patterns are NOT reimplemented here. This writes the pending payload to a temp file and
shells out to `scripts/leakcheck.sh <file>` — the same script, the same allowlist, the same
approved placeholders. A second copy of those regexes would drift, and a drifted guard is worse
than none: it reports clean while the real gate would have failed.

SCOPE — this must not fire on the analyst's own case notes
----------------------------------------------------------
RULE 1 governs *tracked files in a cti-expert checkout*. An analyst writing genuine case data into
`intel_engine/cases/` or into a scratch file somewhere else entirely is doing the correct thing;
blocking that would train them to disable the hook. So the guard denies only when BOTH hold:

  1. the target path is inside a cti-expert checkout (identified by SKILL.md + intel_engine/), and
  2. git does NOT ignore that path (i.e. it is, or would be, a tracked file).

Everything else is allowed without comment.

CONTRACT
--------
stdin : {"tool_name": "...", "tool_input": {"file_path": "...", "content"|"new_string": "..."}}
stdout: {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                "permissionDecision": "deny"|"allow",
                                "permissionDecisionReason": "..."}}

Fails OPEN by design. A hook that crashes must not brick every write in the repo — the git
pre-commit hook and `scripts/audit.sh` remain as the backstop. Any internal error is reported on
stderr and the write proceeds.
"""
import json
import os
import subprocess
import sys
import tempfile

# tool_input keys that can carry file content, across Write / Edit / NotebookEdit.
CONTENT_KEYS = ("content", "new_string", "new_source", "replace_all_with")


def _allow(reason=""):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "allow",
                                   "permissionDecisionReason": reason}}


def _deny(reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def find_skill_root(path):
    """Walk up from `path` to the nearest cti-expert checkout, or None.

    A cti-expert checkout is identified structurally — `SKILL.md` next to `intel_engine/` — not by
    directory name, so a clone named anything still gets the guard and an unrelated repo that
    happens to be called cti-expert does not.
    """
    d = os.path.dirname(os.path.abspath(path))
    while True:
        if (os.path.isfile(os.path.join(d, "SKILL.md"))
                and os.path.isdir(os.path.join(d, "intel_engine"))):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def is_git_ignored(root, path):
    """True if git ignores `path` — i.e. it is one of the case/knowledge/MEMORY stores.

    On any git failure this returns False (treat as tracked), so an unusual environment errs
    toward CHECKING the payload rather than skipping the check.
    """
    try:
        r = subprocess.run(["git", "check-ignore", "-q", path], cwd=root,
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def scan(root, payload, file_path):
    """Run the repo's own leakcheck over the pending payload. Returns its report, or '' if clean.

    The payload is written to a temp file OUTSIDE the repo so the scan can never itself create a
    tracked file, and the filename is included in the scanned text — a case ID hidden in a path
    is a leak just as much as one in the body.
    """
    script = os.path.join(root, "scripts", "leakcheck.sh")
    if not os.path.isfile(script):
        return ""  # a checkout without the gate — nothing to enforce against
    fd, tmp = tempfile.mkstemp(prefix="leakguard-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(file_path + "\n" + payload)
        r = subprocess.run(["bash", script, tmp], cwd=root,
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return ""
        return ((r.stdout or "") + (r.stderr or "")).strip()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def main():
    try:
        ev = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        print(json.dumps(_allow()))
        return 0

    ti = ev.get("tool_input") or {}
    file_path = str(ti.get("file_path") or ti.get("notebook_path") or "").strip()
    if not file_path:
        print(json.dumps(_allow()))
        return 0

    root = find_skill_root(file_path)
    if not root:
        print(json.dumps(_allow()))          # not a cti-expert checkout — RULE 1 does not apply
        return 0
    if is_git_ignored(root, file_path):
        print(json.dumps(_allow()))          # the case/knowledge stores are where case data BELONGS
        return 0

    payload = "\n".join(str(ti[k]) for k in CONTENT_KEYS if ti.get(k))
    # Edit also carries the text being replaced; scan it too, so moving a leak around is not a
    # way through.
    if ti.get("old_string"):
        payload += "\n" + str(ti["old_string"])
    if not payload.strip():
        print(json.dumps(_allow()))
        return 0

    report = scan(root, payload, file_path)
    if report:
        rel = os.path.relpath(file_path, root)
        print(json.dumps(_deny(
            f"RULE 1 (CLAUDE.md): this write puts case data into a TRACKED file — {rel}\n\n"
            f"{report}\n\n"
            "Case data lives only in the git-ignored stores (intel_engine/cases, "
            "intel_engine/knowledge, intel_engine/MEMORY). In a tracked file use a placeholder "
            "from CLAUDE.md's example table (example.com, registrant@example.com, CASE-0001, "
            "G-XXXXXXXXXX). If this value is a generic public constant rather than case data, add "
            "it to the enumerated PUBLIC_CONST list in scripts/leakcheck.sh with a justification — "
            "one value at a time, never a class-wide pattern.")))
        return 0

    print(json.dumps(_allow()))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — fail OPEN; never brick the repo on a hook bug
        print(f"leakguard: internal error, allowing write: {e}", file=sys.stderr)
        print(json.dumps(_allow(f"leakguard error: {e}")))
        sys.exit(0)
