"""Render an Assessment as (a) a rich terminal report and (b) a Markdown file.

Keeps presentation OUT of the orchestrator: change how results look here without
touching the agent loop. Degrades gracefully to plain JSON if `rich` isn't installed.
"""
from __future__ import annotations

import os

from schemas import Assessment

# Resolve `tools/` from THIS FILE, never from a caller-supplied root: `save_markdown(root=…)` is
# the case-store root, which is not always the repo (tests and ad-hoc runs pass a temp dir).
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "tools"))
from case_state import may_overwrite_assessment, HARNESS_RENDER_MD  # noqa: E402

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except ImportError:  # rich optional — fall back to JSON
    _RICH = False

# attribution level -> colour (strongest claim = hottest)
_ATTR = {
    "same-actor": "red",
    "same-operator": "dark_orange",
    "same-kit": "yellow",
    "inconclusive": "grey58",
}
_CONF = {"high": "green", "moderate": "yellow", "low": "red"}
# premise verdict -> colour. `contradicted` is deliberately the loudest: an intake claim the
# evidence broke is the most valuable thing a run can return, and it must not read as a footnote.
_PREMISE = {
    "supported": "green",
    "partially_supported": "yellow",
    "not_supported": "grey58",
    "contradicted": "red",
    "inconclusive": "grey58",
}


def _premise_line(a: Assessment) -> str:
    """`Stated premise … Collection verdict …` — the intake's required output line, or '' when
    the schema predates it."""
    verdict = getattr(a, "premise_verdict", "") or ""
    claim = (getattr(a, "premise", "") or "").strip()
    if not verdict and not claim:
        return ""
    return f"Stated premise: {claim or '(none stated — run assumed a class)'}  ·  " \
           f"Collection verdict: {verdict.replace('_', ' ') or 'inconclusive'}"


def render_terminal(a: Assessment, table_md: str = "") -> None:
    """Print a colored, scannable report to stdout."""
    if not _RICH:
        if table_md:
            print(table_md)
        print(a.model_dump_json(indent=2))
        return
    c = Console()

    c.print(Panel(Text(a.bluf, style="bold"), title="[bold cyan]BLUF",
                  border_style="cyan", box=box.ROUNDED, padding=(1, 2)))

    badge = Text()
    badge.append(f" {a.attribution_level.upper()} ",
                 style=f"reverse bold {_ATTR.get(a.attribution_level, 'white')}")
    badge.append("    ")
    badge.append(f" CONFIDENCE · {a.confidence.upper()} ",
                 style=f"reverse bold {_CONF.get(a.confidence, 'white')}")
    pv = getattr(a, "premise_verdict", "")
    if pv:
        badge.append("    ")
        badge.append(f" PREMISE · {pv.replace('_', ' ').upper()} ",
                     style=f"reverse bold {_PREMISE.get(pv, 'white')}")
    c.print(badge, "\n")
    line = _premise_line(a)
    if line:
        c.print(Text(line, style="italic"), "\n")

    if table_md:                                   # the standard Domain Summary table
        from rich.markdown import Markdown
        c.print(Markdown(table_md))
        c.print()

    if a.cluster:
        t = Table(title="[bold]Cluster", box=box.SIMPLE_HEAVY, header_style="bold cyan",
                  expand=True, title_justify="left", padding=(0, 1))
        t.add_column("Domain", style="bold", ratio=1, no_wrap=False)
        t.add_column("Shared artifacts", ratio=3)
        for m in a.cluster:
            t.add_row(m.domain, "\n".join(f"• {s}" for s in m.shared_artifacts) or "—")
        c.print(t, "\n")

    for title, items, style in (
        ("Evidence", a.evidence, "green"),
        ("Gaps & alternatives", a.gaps, "yellow"),
        ("Next pivots", a.next_pivots, "cyan"),
    ):
        if not items:
            continue
        body = Text()
        for i, it in enumerate(items):
            if i:
                body.append("\n")
            body.append("› ", style=f"bold {style}")
            body.append(it)
        c.print(Panel(body, title=f"[bold {style}]{title}",
                      border_style=style, box=box.ROUNDED, padding=(1, 2)))


def render_markdown(a: Assessment, table_md: str = "") -> str:
    """Return a clean Markdown assessment (renders in editors / GitHub)."""
    out: list[str] = ["# Assessment", ""]
    out += [f"**BLUF —** {a.bluf}", ""]
    out += [f"- **Attribution:** `{a.attribution_level}`",
            f"- **Confidence:** `{a.confidence}`"]
    pv = getattr(a, "premise_verdict", "")
    if pv:
        out.append(f"- **Premise verdict:** `{pv}`"
                   + (f" — stated: {a.premise}" if getattr(a, "premise", "") else ""))
    out.append("")
    if table_md:
        out += [table_md.strip(), ""]
    if a.cluster:
        out += ["## Cluster", "", "| Domain | Shared artifacts |", "|---|---|"]
        for m in a.cluster:
            arts = "<br>".join(m.shared_artifacts).replace("|", "\\|")
            out.append(f"| `{m.domain}` | {arts} |")
        out.append("")
    for title, items in (("Evidence", a.evidence),
                         ("Gaps & alternatives", a.gaps),
                         ("Next pivots", a.next_pivots)):
        if items:
            out += [f"## {title}", ""]
            out += [f"- {it}" for it in items]
            out.append("")
    return "\n".join(out)


def save_markdown(a: Assessment, case: str, root: str, table_md: str = "") -> str:
    """Write the SDK front-end's assessment, WITHOUT clobbering someone else's.

    `cases/<case>/assessment.md` is also written by the analyst and by the intel.py loop, so this
    only overwrites a file it recognises as its OWN previous render; anything else keeps the path
    and this render lands in `loop_assessment.md`. Returns the path actually written."""
    path = os.path.join(root, "cases", case, "assessment.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not may_overwrite_assessment(path, HARNESS_RENDER_MD):
        path = os.path.join(root, "cases", case, "loop_assessment.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(a, table_md))
    return path
