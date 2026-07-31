#!/usr/bin/env python3
"""
backend.py — cti-expert intelligence-backend resolver (the `/backend` command).

cti-expert is portable and stateless by default. When the optional
`intel_engine` engine (persistent KB + cross-case correlation) is
reachable, this tool resolves it and reports the strongest available tier so
the AEAD lifecycle can attach its memory hooks. When it is absent, the tool
reports Tier 3 (stateless) and everything degrades silently.

Resolution order for $INTEL_HOME (first hit wins), per connectors/intel-backend.md §1:
    1. env var  $INTEL_HOME  (also read from the skill-root .env, like /apikeys)
    2. .mcp.json exposing an `intel` server → its command locates the repo root
    3. sibling  intel_engine/  beside the cti-expert repo or $SKILL_DIR
    4. symlink   ~/.claude/skills/{WebPivot,IntelHarness,…} → follow to the engine

Tier detection (connectors/intel-backend.md §2):
    Tier 1 (MCP) — engine present AND .mcp.json + harness/mcp-server executable.
                   NOTE: a *live* MCP connection is a property of the client, not
                   the filesystem — this tool reports Tier 1 as *available* and the
                   agent confirms the `intel` server is actually connected.
    Tier 2 (CLI) — engine present (harness/cli.py + tools/kb/) but no MCP.
    Tier 3 (stateless) — no engine resolved.

Recommended runner (zero setup, any OS): `uv run backend.py [command]`
Stdlib-only — no dependencies, so plain `python3`/`py` works too.

Commands:
    uv run backend.py                 # status (default): tier + resolved path
    uv run backend.py status          # same as above
    uv run backend.py check           # verbose diagnostics: every method tried
    uv run backend.py env             # print `INTEL_HOME=<path>` (for eval/export)
    uv run backend.py path            # print just the resolved engine root
    uv run backend.py --json          # machine-readable status (works with any cmd)
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
# skill root = ../../ from scripts/backend/ — same target the webpivot/apikeys tools resolve.
SKILL_DIR = os.path.normpath(os.path.join(HERE, "..", ".."))
ENV_PATH = os.environ.get("CTI_API_KEYS_ENV") or os.path.join(SKILL_DIR, ".env")

# Skills the Claude Code installer symlinks from the engine (method 4 anchors).
ENGINE_SKILLS = ("WebPivot", "IntelHarness", "BinaryPivot",
                 "IntelAnalysis", "IntelGraph", "IntelReport")


# ─────────────────────────────────────────────────────────────────── helpers
def _read_env_file(path=ENV_PATH):
    """Parse KEY=VALUE lines from the skill-root .env (comments/blanks ignored)."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def _is_engine(root):
    """A directory is the engine iff it has harness/cli.py AND tools/kb/."""
    if not root or not os.path.isdir(root):
        return False
    return (os.path.isfile(os.path.join(root, "harness", "cli.py"))
            and os.path.isdir(os.path.join(root, "tools", "kb")))


def _norm(p):
    return os.path.normpath(os.path.abspath(os.path.expanduser(p))) if p else p


def _from_mcp_json(mcp_path):
    """Resolve the engine root from a .mcp.json exposing an `intel` server.

    The server command (e.g. `./harness/mcp-server`) locates the repo root:
    root = parent dir of the `harness/` that holds the command. Relative
    commands resolve against the .mcp.json's own directory.
    """
    try:
        with open(mcp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    servers = data.get("mcpServers", {})
    entry = servers.get("intel") or servers.get("intel-harness")
    if not entry:
        return None
    cmd = entry.get("command", "")
    if not cmd:
        return None
    base = os.path.dirname(os.path.abspath(mcp_path))
    cmd_abs = cmd if os.path.isabs(cmd) else os.path.normpath(os.path.join(base, cmd))
    # cmd is <root>/harness/mcp-server → root is two levels up.
    root = os.path.dirname(os.path.dirname(cmd_abs))
    return root if _is_engine(root) else None


# ──────────────────────────────────────────────────────────────── resolution
def resolve():
    """Return (root, method, trail) — trail lists every candidate attempted."""
    trail = []

    def record(method, cand, ok):
        trail.append({"method": method, "candidate": cand, "ok": bool(ok)})

    # 0) SELF — cti-expert vendors the engine in-repo under intel_engine/. If that subtree is a
    # complete engine (harness/cli.py + tools/kb/), it IS the backend: one self-contained skill,
    # no external dependency. An explicit $INTEL_HOME still overrides (below) for advanced setups.
    if not os.environ.get("INTEL_HOME"):
        for _cand in (os.path.join(SKILL_DIR, "intel_engine"), SKILL_DIR):  # subtree, then legacy flat
            if _is_engine(_cand):
                record("in-repo (self-contained)", _cand, True)
                return _cand, "in-repo (self-contained)", trail

    # 1) env var — process env first, then the skill-root .env
    env_val = os.environ.get("INTEL_HOME") or _read_env_file().get("INTEL_HOME")
    if env_val:
        cand = _norm(env_val)
        ok = _is_engine(cand)
        record("env $INTEL_HOME", cand, ok)
        if ok:
            return cand, "env $INTEL_HOME", trail

    # 2) .mcp.json exposing an `intel` server (search cwd + skill dir)
    for base in (os.getcwd(), SKILL_DIR):
        mcp = os.path.join(base, ".mcp.json")
        if os.path.isfile(mcp):
            root = _from_mcp_json(mcp)
            record(".mcp.json (intel server)", mcp, root)
            if root:
                return _norm(root), ".mcp.json (intel server)", trail

    # 3) sibling intel_engine/ beside the cti-expert repo or $SKILL_DIR
    seen = set()
    for base in (SKILL_DIR, os.getcwd()):
        parent = os.path.dirname(base)
        cand = _norm(os.path.join(parent, "intel_engine"))
        if cand in seen:
            continue
        seen.add(cand)
        ok = _is_engine(cand)
        record("sibling intel_engine/", cand, ok)
        if ok:
            return cand, "sibling intel_engine/", trail

    # 4) symlinked engine skills under ~/.claude/skills/
    skills_dir = os.path.expanduser("~/.claude/skills")
    for name in ENGINE_SKILLS:
        link = os.path.join(skills_dir, name)
        if os.path.islink(link) or os.path.isdir(link):
            target = _norm(os.path.realpath(link))
            root = os.path.dirname(target)  # <engine>/WebPivot → <engine>
            ok = _is_engine(root)
            record(f"symlink ~/.claude/skills/{name}", link, ok)
            if ok:
                return root, f"symlink ~/.claude/skills/{name}", trail

    return None, None, trail


def inspect(root):
    """Describe engine capabilities at `root` (assumes _is_engine(root))."""
    j = os.path.join
    mcp_json = j(root, ".mcp.json")
    mcp_srv = j(root, "harness", "mcp-server")
    has_mcp = os.path.isfile(mcp_json) and os.path.isfile(mcp_srv)
    mcp_exec = has_mcp and os.access(mcp_srv, os.X_OK)
    kb = j(root, "knowledge")
    return {
        "cli": os.path.isfile(j(root, "harness", "cli.py")),
        "kb_tools": os.path.isdir(j(root, "tools", "kb")),
        "mcp_present": has_mcp,
        "mcp_executable": mcp_exec,
        "knowledge_dir": os.path.isdir(kb),
        "binary_pivot": os.path.isdir(j(root, "BinaryPivot")),
    }


def status():
    """Return the full status dict used by every command."""
    root, method, trail = resolve()
    if not root:
        return {
            "tier": 3,
            "tier_label": "stateless — no engine",
            "intel_home": None,
            "method": None,
            "trail": trail,
            "capabilities": {},
            "line": "Intel backend: Tier 3 (stateless — no engine)",
        }
    caps = inspect(root)
    if caps["mcp_present"]:
        tier, label = 1, "MCP available (confirm `intel` server is connected)"
    else:
        tier, label = 2, "CLI"
    return {
        "tier": tier,
        "tier_label": label,
        "intel_home": root,
        "method": method,
        "trail": trail,
        "capabilities": caps,
        "line": f"Intel backend: Tier {tier} ({label}) — $INTEL_HOME={root} (via {method})",
    }


# ────────────────────────────────────────────────────────────────── commands
def cmd_status(st):
    print(st["line"])
    if st["tier"] != 3:
        caps = st["capabilities"]
        avail = []
        if st["tier"] == 1:
            avail.append("MCP (typed tools)")
        avail.append("CLI (harness/cli.py, tools/kb/*.py)")
        if caps.get("knowledge_dir"):
            avail.append("KB (knowledge/)")
        if caps.get("binary_pivot"):
            avail.append("BinaryPivot (/binary)")
        print("  available: " + ", ".join(avail))
        print("  unlocks:   /kb  /recall  /binary")
    else:
        print("  set INTEL_HOME (see .env.example / connectors/intel-backend.md) to enable")
        print("  /kb, /recall, /binary — until then cti-expert runs fully stateless.")
    return 0


def cmd_check(st):
    print(st["line"])
    print("\nresolution trail (first ok wins):")
    if not st["trail"]:
        print("  (no candidates — INTEL_HOME unset and no engine nearby)")
    for step in st["trail"]:
        mark = "✓" if step["ok"] else "·"
        print(f"  [{mark}] {step['method']}: {step['candidate']}")
    if st["tier"] != 3:
        print("\nengine components:")
        for k, v in st["capabilities"].items():
            print(f"  [{'✓' if v else '·'}] {k}")
        if st["tier"] == 1:
            print("\nTier 1 is filesystem-available. A *live* MCP connection is a")
            print("client property — confirm the `intel` server is connected, else")
            print("use Tier 2 CLI (same engine, same KB).")
    return 0


def cmd_env(st):
    # Always emit a line so `eval "$(backend.py env)"` is safe; empty when absent.
    print(f"INTEL_HOME={st['intel_home'] or ''}")
    return 0 if st["intel_home"] else 1


def cmd_path(st):
    if st["intel_home"]:
        print(st["intel_home"])
        return 0
    print("", file=sys.stderr)
    return 1


def main():
    ap = argparse.ArgumentParser(
        prog="backend.py",
        description="Resolve the optional intel_engine backend and report the tier.")
    ap.add_argument("command", nargs="?", default="status",
                    choices=["status", "check", "env", "path"],
                    help="status (default) | check | env | path")
    ap.add_argument("--json", action="store_true",
                    help="emit the full status object as JSON")
    args = ap.parse_args()

    st = status()
    if args.json:
        print(json.dumps(st, indent=2))
        return 0 if st["tier"] != 3 else 0

    return {
        "status": cmd_status,
        "check": cmd_check,
        "env": cmd_env,
        "path": cmd_path,
    }[args.command](st)


if __name__ == "__main__":
    sys.exit(main())
