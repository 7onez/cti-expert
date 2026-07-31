"""Render an Assessment as (a) a rich terminal report and (b) a Markdown file.

Keeps presentation OUT of the orchestrator: change how results look here without
touching the agent loop. Degrades gracefully to plain JSON if `rich` isn't installed.
"""
from __future__ import annotations

import os

from schemas import Assessment

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
    c.print(badge, "\n")

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
            f"- **Confidence:** `{a.confidence}`", ""]
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
    path = os.path.join(root, "cases", case, "assessment.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(a, table_md))
    return path
