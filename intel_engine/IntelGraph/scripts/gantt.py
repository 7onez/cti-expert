#!/usr/bin/env python3
"""
gantt.py — matplotlib-native Gantt + event timeline in the IntelGraph house style.
No browser needed; handles Vietnamese. Requires matplotlib.

  from gantt import gantt, timeline
  gantt(tasks, title=..., stem=..., lang="en"|"vi", source=..., grading=..., date=...)
  timeline([(date,label), ...], title=..., stem=...)

task dict: {"section","name","start","end","crit"?,"done"?}  (dates: YYYY-MM-DD)
"""
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from theme import apply_theme, PALETTE, caption, save_dual, title_block


def _d(s):
    return datetime.strptime(s, "%Y-%m-%d")


def gantt(tasks, title="Timeline", stem="gantt", lang="en",
          source="", grading="", date="", subtitle=None):
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    apply_theme(lang=lang)
    fig, ax = plt.subplots(figsize=(10, max(2.4, 0.5 * len(tasks) + 1.4)))
    ax.grid(axis="x")
    ax.grid(axis="y", visible=False)
    labels = []
    for i, t in enumerate(reversed(tasks)):
        y = i
        s, e = _d(t["start"]), _d(t["end"])
        span = max((e - s).days, 1)
        if t.get("crit"):
            color = PALETTE["brick"]
        elif t.get("done"):
            color = PALETTE["grid"]
        else:
            color = PALETTE["primary"]
        ax.barh(y, span, left=s, height=0.55, color=color,
                edgecolor=PALETTE["slate"], linewidth=0.5)
        labels.append(f'{t.get("section","")} · {t["name"]}'.strip(" ·"))
    ax.set_yticks(range(len(tasks)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.xaxis_date()
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    fig.autofmt_xdate(rotation=30, ha="right")
    title_block(ax, title, subtitle)
    caption(fig, source, grading, date, lang)
    return save_dual(fig, stem)


def timeline(events, title="Event timeline", stem="timeline", lang="en",
             source="", grading="", date="", subtitle=None):
    """events: list of (YYYY-MM-DD, label). Alternating above/below markers."""
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    apply_theme(lang=lang)
    ev = sorted(events, key=lambda x: _d(x[0]))
    xs = [_d(d) for d, _ in ev]
    fig, ax = plt.subplots(figsize=(11, 3.6))
    ax.axhline(0, color=PALETTE["muted"], linewidth=1)
    for i, (d, label) in enumerate(ev):
        up = 1 if i % 2 == 0 else -1
        ax.plot([xs[i], xs[i]], [0, up * 0.6], color=PALETTE["grid"], linewidth=1)
        ax.plot(xs[i], 0, "o", color=PALETTE["brick"], markersize=6)
        ax.annotate(f"{d}\n{label}", (xs[i], up * 0.65),
                    ha="center", va="bottom" if up > 0 else "top",
                    fontsize=8.5, color=PALETTE["ink"])
    ax.set_ylim(-1.4, 1.4)
    ax.get_yaxis().set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.grid(False)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    title_block(ax, title, subtitle)
    caption(fig, source, grading, date, lang)
    return save_dual(fig, stem)


if __name__ == "__main__":
    # smoke demo
    gantt([{"section": "Infra", "name": "Domain reg", "start": "2026-05-01", "end": "2026-05-07"},
           {"section": "Response", "name": "Detect & report", "start": "2026-05-16",
            "end": "2026-05-18", "crit": True}],
          title="Campaign timeline", stem="/tmp/_gantt_demo",
          source="CTI team", grading="B2", date="2026-07-08")
    print("demo written to /tmp/_gantt_demo*")
