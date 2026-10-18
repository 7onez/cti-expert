#!/usr/bin/env python3
"""Regression: scripts/register_agents.py — /cti on every non-Claude coding agent.

Rails defended:
- a same-named command or skill the USER wrote is never overwritten and never uninstalled;
- a re-run rewrites our own stubs (repo moved), and --uninstall leaves no empty skill dir behind;
- each host's stub carries ONLY that host's argument placeholder: omp/pi/opencode/droid expand
  `$ARGUMENTS`, Gemini/Qwen expand `{{args}}` and execute `!{…}` / inline `@{…}`, so a stray token
  in the shared wording would corrupt the prompt or run a shell command on another host;
- the Gemini TOML stays valid for a repo path containing quotes, backslashes and spaces.
Offline: a synthetic repo and HOME under a TemporaryDirectory.
"""
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None


def _load():
    name = "cti_register_agents_under_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "register_agents.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


def _repo(base: Path) -> Path:
    repo = base / 'we"ird \\ repo'
    (repo / "commands").mkdir(parents=True)
    (repo / "commands" / "cti.md").write_text(
        '---\nname: cti\ndescription: "Entry point. Usage: /cti <target>"\n'
        'argument-hint: "<target>"\n---\n\nBody $ARGUMENTS\n', encoding="utf-8")
    (repo / "commands" / "cti-status.md").write_text(
        '---\nname: cti-status\ndescription: "Health check"\n---\n\nBody\n', encoding="utf-8")
    return repo


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

    R = _load()
    old_xdg = os.environ.pop("XDG_CONFIG_HOME", None)
    old_claude = os.environ.pop("CLAUDE_CONFIG_DIR", None)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, home = _repo(base), base / "home"

            # ---- placeholder isolation per host ----------------------------------------------
            for h in R.HOSTS:
                for path, body in R.plan(h, home, repo).items():
                    if path.suffix not in (".md", ".toml"):
                        continue
                    n_dollar, n_brace = body.count("$ARGUMENTS"), body.count("{{args}}")
                    want_dollar = 1 if h.args == "$ARGUMENTS" else 0
                    want_brace = 1 if h.args == "{{args}}" else 0
                    ok(n_dollar == want_dollar and n_brace == want_brace
                       and "!{" not in body and "@{" not in body,
                       f"{h.key}:{path.name} carries only its own placeholder")
                    ok(str(repo / "commands") in body.replace("\\\\", "\\").replace('\\"', '"'),
                       f"{h.key}:{path.name} points at the canonical command file")

            # ---- Gemini TOML validity with a hostile path -------------------------------------
            if tomllib:
                g = R.BY_KEY["gemini"]
                for path, body in R.plan(g, home, repo).items():
                    try:
                        d = tomllib.loads(body)
                        good = (str(repo / "commands" / (path.stem + ".md")) in d["prompt"]
                                and "{{args}}" in d["prompt"] and d.get("description"))
                    except Exception:
                        good = False
                    ok(good, f"gemini {path.name} parses and keeps the quoted/backslashed repo path")
            else:
                lines.append(("ok", "tomllib unavailable (Python 3.10) - TOML parse check skipped"))

            # ---- user files win: install never overwrites, uninstall never removes ------------
            omp = R.BY_KEY["omp"]
            user_cmd = omp.target(home) / "cti-status.md"
            user_cmd.parent.mkdir(parents=True)
            user_cmd.write_text("my own /cti-status\n", encoding="utf-8")
            skill = R.BY_KEY["skill"]
            user_skill = skill.target(home) / "SKILL.md"
            user_skill.parent.mkdir(parents=True)
            user_skill.write_text("---\nname: cti\ndescription: mine\n---\n", encoding="utf-8")

            n, skipped = R.install(omp, home, repo=repo)
            ok(n == 1 and skipped == [str(user_cmd)], "omp: foreign cti-status.md skipped, cti.md written")
            ok(user_cmd.read_text(encoding="utf-8") == "my own /cti-status\n", "omp: user file untouched")
            n, skipped = R.install(skill, home, repo=repo)
            ok(n == 0 and not (skill.target(home) / "agents" / "openai.yaml").exists(),
               "skill: a foreign cti skill dir is left whole (no openai.yaml dropped into it)")

            # ---- re-run after a repo move rewrites our own stub -------------------------------
            moved = base / "moved"
            os.rename(repo, moved)
            R.install(omp, home, repo=moved)
            ours = (omp.target(home) / "cti.md").read_text(encoding="utf-8")
            ok(str(moved / "commands" / "cti.md") in ours, "re-run rewrites our stub to the new repo path")

            # ---- uninstall: ours removed, foreign kept, empty skill dir pruned ----------------
            removed = R.uninstall(omp, home, repo=moved)
            ok(removed == 1 and user_cmd.exists() and not (omp.target(home) / "cti.md").exists(),
               "omp uninstall removes only the marked stub")
            ok(R.uninstall(skill, home, repo=moved) == 0 and user_skill.exists(),
               "skill uninstall never removes a foreign SKILL.md")
            user_skill.unlink()
            user_skill.parent.rmdir()
            R.install(skill, home, repo=moved)
            ok((skill.target(home) / "agents" / "openai.yaml").exists(), "skill install writes openai.yaml")
            R.uninstall(skill, home, repo=moved)
            ok(not skill.target(home).exists(), "skill uninstall prunes the emptied cti/ dir")

            # ---- Claude fallback (register.sh on Windows without symlink rights) ------------
            os.environ["CLAUDE_CONFIG_DIR"] = str(base / "claude")
            claude = R.BY_KEY["claude"]
            ok(claude not in R._select("all", home) and claude not in R._select("auto", home),
               "claude stubs are never auto/all-selected (register.sh symlinks Claude Code)")
            cdir = claude.target(home)
            cdir.mkdir(parents=True)
            (cdir / "cti.md").symlink_to(moved / "commands" / "cti.md")
            n, skipped = R.install(claude, home, repo=moved)
            ok((cdir / "cti.md").is_symlink() and n == 1 and not skipped,
               "claude fallback keeps an existing link into the repo, stubs only the unlinked command")
            (cdir / "cti.md").unlink()
            R.install(claude, home, repo=moved)
            with contextlib.redirect_stdout(io.StringIO()):
                R.main(["--uninstall"], home=home)
            ok(not any(cdir.iterdir()), "default --uninstall also removes the claude fallback stubs")
    finally:
        if old_xdg is not None:
            os.environ["XDG_CONFIG_HOME"] = old_xdg
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        if old_claude is not None:
            os.environ["CLAUDE_CONFIG_DIR"] = old_claude
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for status, label in _lines:
        print(f"  [{status}] {label}")
    print(f"{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
