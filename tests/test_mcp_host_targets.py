#!/usr/bin/env python3
"""Regression: `intel.py mcp --host claude|codex|omp|all` (integrator request).

- `codex`: merges a `[mcp_servers.intel]` table into $CODEX_HOME/config.toml, touching NO other
  table, and keeps a `.bak` of the previous file.
- `omp`: merges `{"intel": …}` into `.omp/mcp.json`'s `mcpServers` in the CWD, preserving every
  OTHER already-registered server.
- no `--host` still defaults to the pre-existing claude-only `.mcp.json` print-only behaviour.
- an unknown `--host` value is rejected, not silently ignored.
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    D = _load_module(os.path.join(ROOT, "scripts", "backend", "intel.py"),
                      "cti_mcp_host_under_test")

    with tempfile.TemporaryDirectory() as tmp:
        # ---- codex: merge into a TEMP $CODEX_HOME/config.toml -------------------------------
        codex_home = os.path.join(tmp, "codex_home")
        os.makedirs(codex_home, exist_ok=True)
        cfg = os.path.join(codex_home, "config.toml")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write('[other_table]\nfoo = "bar"\n\n[mcp_servers.something_else]\ncommand = "/bin/true"\n')

        old_codex_home = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = codex_home
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = D._cmd_mcp(["--host", "codex", "--write"])
            ok(rc == 0, "codex --write returns 0")
        finally:
            if old_codex_home is None:
                os.environ.pop("CODEX_HOME", None)
            else:
                os.environ["CODEX_HOME"] = old_codex_home

        written = open(cfg, encoding="utf-8").read()
        ok('[other_table]' in written and 'foo = "bar"' in written,
           "codex merge keeps an unrelated table untouched")
        ok('[mcp_servers.something_else]' in written and 'command = "/bin/true"' in written,
           "codex merge keeps the other registered mcp server table untouched")
        ok('[mcp_servers.intel]' in written and 'tool_timeout_sec = 1800' in written
           and 'startup_timeout_sec = 60' in written
           and 'default_tools_approval_mode = "approve"' in written,
           "codex merge writes the intel table with the required fields")
        ok(os.path.isfile(cfg + ".bak") and 'command = "/bin/true"' in open(cfg + ".bak", encoding="utf-8").read(),
           "codex merge keeps a .bak of the previous file")

        # a second write (re-registering) replaces ONLY the intel table again, still cleanly
        buf = io.StringIO()
        os.environ["CODEX_HOME"] = codex_home
        try:
            with contextlib.redirect_stdout(buf):
                D._cmd_mcp(["--host", "codex", "--write"])
        finally:
            if old_codex_home is None:
                os.environ.pop("CODEX_HOME", None)
            else:
                os.environ["CODEX_HOME"] = old_codex_home
        written2 = open(cfg, encoding="utf-8").read()
        ok(written2.count("[mcp_servers.intel]") == 1 and "[other_table]" in written2,
           "re-writing codex config replaces the intel table exactly once, other tables intact")

        # ---- omp: merge into .omp/mcp.json in a TEMP cwd ------------------------------------
        omp_dir = os.path.join(tmp, "omp_project")
        os.makedirs(os.path.join(omp_dir, ".omp"), exist_ok=True)
        with open(os.path.join(omp_dir, ".omp", "mcp.json"), "w", encoding="utf-8") as f:
            json.dump({"mcpServers": {"other": {"command": "/bin/false"}}}, f)
        old_cwd = os.getcwd()
        os.chdir(omp_dir)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = D._cmd_mcp(["--host", "omp", "--write"])
            ok(rc == 0, "omp --write returns 0")
        finally:
            os.chdir(old_cwd)
        doc = json.load(open(os.path.join(omp_dir, ".omp", "mcp.json"), encoding="utf-8"))
        ok("other" in doc.get("mcpServers", {}), "omp merge keeps the other registered server")
        ok(doc.get("mcpServers", {}).get("intel", {}).get("timeout") == 1800000,
           "omp merge adds the intel server with a 1800000ms timeout")

        # ---- misc: unknown host rejected; no --host defaults to the unchanged claude path ----
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = D._cmd_mcp(["--host", "bogus"])
        ok(rc != 0, "an unknown --host value is rejected, not silently ignored")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = D._cmd_mcp([])
        out = buf.getvalue()
        ok(rc == 0 and "mcpServers" in out and "CODEX_HOME" not in out and "mcp_servers.intel" not in out,
           "no --host still defaults to the unchanged claude-only print path")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
