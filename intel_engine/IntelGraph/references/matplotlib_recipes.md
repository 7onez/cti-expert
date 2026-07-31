# matplotlib recipes (data charts, house style)

Always load the theme first:
```python
import sys; sys.path.insert(0, "<skill>/scripts")
from theme import apply_theme, PALETTE, save_dual, caption, title_block
import matplotlib.pyplot as plt
apply_theme(lang="en")   # or "vi"
```

## Horizontal bar (counts over categories)
```python
fig, ax = plt.subplots(figsize=(9,5))
ax.barh(labels, values, color=PALETTE["primary"])
ax.grid(axis="x"); ax.grid(axis="y", visible=False)
title_block(ax, "Fake banking APK families observed", "Last 90 days")
caption(fig, source="CTI team", grading="B2", date="2026-07-08")
save_dual(fig, "outputs/apk_families")
```

## Line / step (trend over time)
```python
ax.plot(dates, counts, color=PALETTE["brick"], marker="o", markersize=3)
ax.plot(dates[-1], counts[-1], "o", color=PALETTE["brick"])   # emphasize endpoint
```

## Donut (proportions — never 3D pie)
```python
ax.pie(vals, labels=labels, colors=[PALETTE[k] for k in ("primary","brick","ochre","olive")],
       wedgeprops=dict(width=0.42, edgecolor="white"))
```

## Scatter (two-metric relationship)
```python
ax.scatter(x, y, color=PALETTE["slate"], s=28, alpha=0.85)
```

## Heatmap (Diamond Model / MITRE coverage / C1–C8)
```python
import numpy as np
im = ax.imshow(matrix, cmap="YlOrBr")           # warm, not neon
ax.set_xticks(range(len(cols))); ax.set_xticklabels(cols, rotation=45, ha="right")
ax.set_yticks(range(len(rows))); ax.set_yticklabels(rows)
fig.colorbar(im, ax=ax, shrink=0.8)
```

Checklist: DejaVu Sans, no default matplotlib blue, no gradients/3D, caption footer
present, numbers match the source report, both `_hires.png` and `_thumb.png` written.
