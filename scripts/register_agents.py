#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""register_agents.py — register the cti-expert slash commands with every other coding agent.

register.sh owns Claude Code (symlinks into ~/.claude/commands) and calls this for the rest:

  host      target                                         invoke
  omp       ~/.omp/agent/commands/<cmd>.md                 /cti
  pi        ~/.pi/agent/prompts/<cmd>.md                   /cti
  opencode  $XDG_CONFIG_HOME/opencode/commands/<cmd>.md    /cti   (default ~/.config)
  gemini    ~/.gemini/commands/<cmd>.toml                  /cti
  qwen      ~/.qwen/commands/<cmd>.md                      /cti
  factory   ~/.factory/commands/<cmd>.md                   /cti   (Factory droid)
  windsurf  ~/.codeium/windsurf/global_workflows/<cmd>.md  /cti
  skill     ~/.agents/skills/cti/SKILL.md                  Codex `$cti`, ChatGPT desktop `@cti`,
                                                           Cursor `/cti`, Copilot CLI `/cti`

Codex removed custom prompts (~/.codex/prompts) in 0.117 and invokes skills with `$`, never `/`;
the shared ~/.agents/skills directory is the one place Codex, ChatGPT desktop, Cursor and Copilot
CLI all read, so those hosts get `cti` as an explicit-only skill. Command-file hosts get all of
commands/*.md, the same set Claude Code gets.

Every written file is a thin POINTER STUB: it names the absolute paths of the canonical
commands/<cmd>.md and SKILL.md, so `git pull` changes behaviour with no re-run. Re-run after moving
the repo or adding a command. Each stub carries MARKER; re-runs overwrite and --uninstall removes
ONLY files that carry it. A same-named file without it is the user's and is never touched.

`--host claude` is register.sh's Windows fallback, never auto-selected: Git Bash cannot create a
real symlink without Developer Mode or admin rights, so the commands it could not link land in
$CLAUDE_CONFIG_DIR (default ~/.claude)/commands as stubs. Existing links into this repo are kept.

Usage: python3 scripts/register_agents.py [--host auto|all|h1,h2] [--dry-run] [--uninstall] [--list]
  --host auto (default) = hosts whose config dir or binary exists; --uninstall defaults to every
  host including claude (it only ever removes marked stubs).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MARKER = "cti-expert:generated"
SKILL_NAME = "cti"


@dataclass(frozen=True)
class Host:
    key: str
    label: str
    roots: tuple[str, ...]   # config dirs under $HOME whose presence means "installed"
    bins: tuple[str, ...]    # executables whose presence on PATH means "installed"
    kind: str                # "md" | "toml" | "skill"
    args: str                # argument placeholder the host substitutes; "" = none
    keys: tuple[str, ...]    # frontmatter keys the host documents (md only)
    invoke: str

    def target(self, home: Path) -> Path:
        if self.key == "opencode":
            xdg = os.environ.get("XDG_CONFIG_HOME")
            return (Path(xdg) if xdg else home / ".config") / "opencode" / "commands"
        if self.key == "claude":
            cfg = os.environ.get("CLAUDE_CONFIG_DIR")
            return (Path(cfg) if cfg else home / ".claude") / "commands"
        return home / _TARGETS[self.key]


_TARGETS = {
    "omp": ".omp/agent/commands",
    "pi": ".pi/agent/prompts",
    "gemini": ".gemini/commands",
    "qwen": ".qwen/commands",
    "factory": ".factory/commands",
    "windsurf": ".codeium/windsurf/global_workflows",
    "skill": f".agents/skills/{SKILL_NAME}",
}

_DESC_HINT = ("description", "argument-hint")
HOSTS = (
    Host("omp", "oh-my-pi (omp)", (".omp",), ("omp",), "md", "$ARGUMENTS", _DESC_HINT, "/cti"),
    Host("pi", "pi", (".pi",), ("pi",), "md", "$ARGUMENTS", _DESC_HINT, "/cti"),
    Host("opencode", "OpenCode", (".config/opencode",), ("opencode",), "md", "$ARGUMENTS",
         ("description",), "/cti"),
    Host("gemini", "Gemini CLI", (".gemini",), ("gemini",), "toml", "{{args}}", (), "/cti"),
    Host("qwen", "Qwen Code", (".qwen",), ("qwen",), "md", "{{args}}", ("description",), "/cti"),
    Host("factory", "Factory droid", (".factory",), ("droid",), "md", "$ARGUMENTS", _DESC_HINT,
         "/cti"),
    Host("windsurf", "Windsurf", (".codeium/windsurf",), ("windsurf",), "md", "",
         ("description",), "/cti"),
    Host("skill", "Codex · ChatGPT desktop · Cursor · Copilot CLI (agent skill)",
         (".codex", ".cursor", ".copilot", ".agents"), ("codex", "cursor-agent", "cursor", "copilot"),
         "skill", "", (), "$cti (Codex) · @cti (ChatGPT) · /cti (Cursor, Copilot)"),
)
# Not in HOSTS: register.sh symlinks Claude Code; stubs are only its Windows fallback.
CLAUDE = Host("claude", "Claude Code (register.sh symlink fallback)", (), (), "md", "$ARGUMENTS",
              _DESC_HINT, "/cti")
BY_KEY = {h.key: h for h in (*HOSTS, CLAUDE)}


# ---------------------------------------------------------------- source commands
def _frontmatter(text: str) -> dict[str, str]:
    """`key: "value"` pairs of a commands/*.md header. Values there are single-line scalars."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, sep, val = line.partition(":")
        if not sep:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out[key.strip()] = val
    return out


def load_commands(repo: Path = REPO) -> list[tuple[str, dict[str, str]]]:
    return [(p.stem, _frontmatter(p.read_text(encoding="utf-8")))
            for p in sorted((repo / "commands").glob("*.md"))]


# ---------------------------------------------------------------- rendering
def _yaml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)  # a JSON string is a valid YAML double-quoted scalar


def _toml_str(s: str) -> str:
    # JSON escapes ", \\ and C0 controls with forms TOML basic strings accept; DEL must be escaped too.
    return json.dumps(s, ensure_ascii=False).replace("\x7f", "\\u007F")


def stub_body(name: str, args: str, repo: Path = REPO) -> str:
    """The instruction every host receives. Uses no `$`, `{`, or `!` sequences of its own: hosts
    substitute those, and only the host's own `args` placeholder may be expanded."""
    if args:
        given = f"The arguments for this run are:\n\n{args}\n"
    elif name == SKILL_NAME:
        given = ("The arguments are the text the user typed after invoking this skill "
                 f"(`$cti …` in Codex, `/cti …` in Cursor or Copilot CLI).\n")
    else:
        given = f"The arguments are the text the user typed after `/{name}` in their message.\n"
    return (
        f"Run the cti-expert `/{name}` command.\n\n"
        f"1. Read `{repo / 'commands' / (name + '.md')}` and follow it exactly. Wherever it refers "
        "to its ARGUMENTS placeholder, use the arguments given below. If there are none, follow "
        "the command's no-argument behaviour, or ask for the missing input.\n"
        "2. That command expects the `cti-expert` skill to be loaded. If it is not, first read "
        f"`{repo / 'SKILL.md'}` and `{repo / 'AGENTS.md'}` and follow them. The skill directory "
        f"(SKILL_DIR) is `{repo}`: resolve its relative paths (`scripts/…`, `intel_engine/…`) "
        "against that directory, not against your working directory.\n"
        "3. Those files live outside your workspace. If your file tool refuses the path, read them "
        "with the shell instead.\n\n"
        f"{given}"
    )


def render_md(host: Host, name: str, meta: dict[str, str], repo: Path = REPO) -> str:
    head = [f"{k}: {_yaml_str(meta[k])}" for k in host.keys if meta.get(k)]
    fm = "---\n" + "".join(h + "\n" for h in head) + "---\n" if head else ""
    note = f"<!-- {MARKER}: written by scripts/register_agents.py; edit commands/{name}.md instead -->\n\n"
    return fm + note + stub_body(name, host.args, repo)


def render_toml(host: Host, name: str, meta: dict[str, str], repo: Path = REPO) -> str:
    lines = [f"# {MARKER}: written by scripts/register_agents.py; edit commands/{name}.md instead"]
    if meta.get("description"):
        lines.append(f"description = {_toml_str(meta['description'])}")
    lines.append(f"prompt = {_toml_str(stub_body(name, host.args, repo))}")
    return "\n".join(lines) + "\n"


def render_skill(meta: dict[str, str], repo: Path = REPO) -> dict[str, str]:
    """Explicit-only: `disable-model-invocation` (Cursor/Claude) and openai.yaml policy (Codex)."""
    skill = (f"---\nname: {SKILL_NAME}\ndescription: {_yaml_str(meta.get('description', ''))}\n"
             "disable-model-invocation: true\n---\n"
             f"<!-- {MARKER}: written by scripts/register_agents.py; edit commands/cti.md instead -->\n\n"
             + stub_body(SKILL_NAME, "", repo))
    openai = (f"# {MARKER}: written by scripts/register_agents.py\n"
              "interface:\n"
              f"  display_name: \"{SKILL_NAME}\"\n"
              "  short_description: \"cti-expert entry point: investigate any target\"\n"
              "policy:\n"
              "  allow_implicit_invocation: false\n")
    return {"SKILL.md": skill, "agents/openai.yaml": openai}


def plan(host: Host, home: Path, repo: Path = REPO) -> dict[Path, str]:
    """Every file this host should hold, path -> content."""
    target = host.target(home)
    cmds = load_commands(repo)
    if host.kind == "skill":
        meta = dict(cmds).get(SKILL_NAME, {})
        return {target / rel: body for rel, body in render_skill(meta, repo).items()}
    ext, render = (".toml", render_toml) if host.kind == "toml" else (".md", render_md)
    return {target / f"{name}{ext}": render(host, name, meta, repo) for name, meta in cmds}


# ---------------------------------------------------------------- filesystem
def ours(path: Path) -> bool:
    try:
        return MARKER in path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False


def detected(host: Host, home: Path) -> bool:
    return any((home / r).is_dir() for r in host.roots) or any(shutil.which(b) for b in host.bins)


def install(host: Host, home: Path, dry: bool = False, repo: Path = REPO) -> tuple[int, list[str]]:
    files = plan(host, home, repo)
    if host.kind == "skill":  # a foreign skill of the same name owns the whole directory
        skill_md = host.target(home) / "SKILL.md"
        if skill_md.exists() and not ours(skill_md):
            return 0, [str(host.target(home))]
    written, skipped = 0, []
    for path, body in files.items():
        if path.is_symlink() and path.resolve() == (repo / "commands" / path.name).resolve():
            continue  # register.sh's real link into this repo: already the command, keep it
        if path.exists() and not ours(path):
            skipped.append(str(path))
            continue
        if not dry:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        written += 1
    return written, skipped


def uninstall(host: Host, home: Path, dry: bool = False, repo: Path = REPO) -> int:
    removed = 0
    for path in plan(host, home, repo):
        if path.is_file() and ours(path):
            if not dry:
                path.unlink()
            removed += 1
    if host.kind == "skill" and not dry:
        target = host.target(home)
        for d in (target / "agents", target):  # only if now empty: a user file keeps the dir
            try:
                d.rmdir()
            except OSError:
                pass
    return removed


# ---------------------------------------------------------------- CLI
def _select(spec: str, home: Path) -> list[Host]:
    if spec == "all":
        return list(HOSTS)
    if spec == "auto":
        return [h for h in HOSTS if detected(h, home)]
    keys = [k.strip() for k in spec.split(",") if k.strip()]
    bad = [k for k in keys if k not in BY_KEY]
    if bad:
        raise SystemExit(f"register_agents: unknown --host {', '.join(bad)} "
                         f"(choose from: auto, all, {', '.join(BY_KEY)})")
    return [BY_KEY[k] for k in keys]


def main(argv: list[str] | None = None, home: Path | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default=None, help="auto (default), all, or comma list: "
                    + ",".join(BY_KEY))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--list", action="store_true", help="show hosts, detection and targets")
    a = ap.parse_args(argv)
    home = home or Path.home()

    if a.list:
        for h in HOSTS:
            mark = "detected" if detected(h, home) else "-"
            print(f"  {h.key:9} {mark:9} {h.target(home)}   {h.invoke}   [{h.label}]")
        return 0

    hosts = _select(a.host or ("all" if a.uninstall else "auto"), home)
    if a.uninstall and a.host is None:
        hosts.append(CLAUDE)  # uninstall removes only marked stubs, so the fallback dir is safe
    if not hosts:
        print("  ! no other coding agent detected (use --host all or --host <name>; --list shows them)")
        return 0
    pre = "[dry-run] " if a.dry_run else ""
    for h in hosts:
        if a.uninstall:
            n = uninstall(h, home, a.dry_run)
            print(f"  * {pre}{h.key:9} removed {n} file(s) from {h.target(home)}")
            continue
        n, skipped = install(h, home, a.dry_run)
        print(f"  * {pre}{h.key:9} {h.invoke}  ->  {h.target(home)}  ({n} written)")
        for s in skipped:
            print(f"  ! {h.key:9} {s} exists and is not ours - skipped (yours wins)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
