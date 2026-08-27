# Renderer-Level Confirmation (ClickFix + Visibility)

> **Module ID:** RENDER-CONF-001
> **Version:** 1.0.0
> **Phase:** Emerging Technologies of Cybercrime Defense
> **Classification:** Dynamic confirmation of static phishing-page verdicts
> **Research basis:** *"PasteJacked"* (Nabeel/Melicher/Starov, Palo Alto) + *"Visibility-Aware
> HTML Analysis through Renderer-Level Extraction"* (Betts et al., Auckland), APWG eCrime 2026.

---

## 1. Overview

Closes the evasion gap the static ClickFix and visibility analyzers explicitly flag: payloads
assembled by JavaScript at runtime, and concealment applied by computed/JS-injected styles. It
feeds **renderer-captured evidence** — the actual clipboard writes performed at runtime and the
elements hidden by computed style — back into the existing detectors, then **reconciles** the static
and rendered verdicts.

Two failure directions both matter: a static `none` that the render **promotes** to HIGH (a
JS-assembled ClickFix payload) is the key detection win; a static HIGH the render **fails to
corroborate** is a false-positive to weigh.

The reconcile logic is a **pure, offline function**; the live render is **optional** and degrades to
a note (static verdict stays authoritative) when no renderer is installed — matching the repo's
existing optional-browser convention (`agent-browser.md`).

**When to use:** when a page is suspicious but the static ClickFix/visibility pass scores low, or to
confirm a HIGH before a report.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/render_confirm.py` | Pure reconcile of static + rendered evidence | none |
| Feeds | `scripts/clickfix_detect.py` (`captured_clipboard=`) | runtime clipboard write → detector | none |
| Feeds | `scripts/html_visibility_analysis.py` (`computed_hidden=`) | computed-style hidden set → analyzer | none |
| Optional | Playwright / `agent-browser` | the live render + capture | `uv pip install playwright && playwright install chromium` |

Keyless core. The render step is the only non-pure part and is entirely optional.

---

## 3. Investigation Workflow

```
1. Run the static ClickFix / visibility analyzers first (fast, keyless)
2. If suspicious but low, run render_confirm:
     a. offline: feed --evidence '{"clipboard":[...],"computed_hidden":[...]}' captured elsewhere
     b. live:    --render --url <page>  (needs Playwright/agent-browser; degrades to a note)
3. Read the reconciliation per analyzer:
     promoted_by_render  -> the win: runtime evidence confirms/raises the verdict
     agree               -> static and rendered concur
     static_only_higher  -> render did not corroborate the static signal; weigh a false positive
4. Capture the rendered IOCs (decoded commands, C2 URLs) into the bundle
```

---

## 4. CLI Commands & Expected Output

```bash
# Offline reconcile over evidence captured by any renderer
echo '{"clipboard":["powershell -enc AAAA"],"computed_hidden":[]}' \
  | python3 scripts/render_confirm.py page.html --evidence - --origin site.com --json

# Optional live render (Playwright/agent-browser); degrades to a note if unavailable
python3 scripts/render_confirm.py --url https://suspicious.example/ --render --origin suspicious.example
```

**Output:** per-analyzer `static_verdict` / `rendered_verdict` / `final_verdict` / `reconciliation`,
the ClickFix IOCs + decoded commands captured at runtime, the visibility counts, and a note stating
whether renderer evidence was used.

---

## 5. Reconciliation Model

`final = max(static, rendered)`; the label records the direction:

| Label | Meaning |
|-------|---------|
| `promoted_by_render` | rendered evidence raised the verdict (runtime-assembled payload / computed-hidden form) |
| `agree` | static and rendered concur |
| `static_only_higher` | rendered pass did not corroborate the static signal — weigh a false positive |

Rendered evidence is authoritative when present; absent it, the static verdict is returned verbatim
(never a fabricated rendered result).

---

## 6. Output Interpretation

- A `promoted_by_render` ClickFix HIGH with a decoded C2 URL is the strongest form of this finding —
  the page provably wrote an OS command to the clipboard at runtime.
- `static_only_higher` is a prompt to re-examine the static hit (it may be a benign copy button the
  static heuristics over-weighted) before reporting.
- The live render's `render_note` states the engine used and what it captured, for auditability.

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| promoted_by_render HIGH + decoded C2 | HIGH | runtime-proven |
| agree HIGH | HIGH | static + dynamic concur |
| static_only_higher | downgrade to MEDIUM pending review | render didn't corroborate |
| no renderer evidence | = static confidence | render is an optional upgrade |

---

## 8. Limitations

- **Render is optional and best-effort.** Anti-automation, cloaking, and timeouts can prevent a
  capture — the module returns a note and the static verdict stands; it never fabricates evidence.
- **The Playwright driver hooks `clipboard.writeText` / `execCommand('copy')` and reads
  `getComputedStyle`;** deeply obfuscated interception or shadow-DOM concealment may still evade it.
- **Not CI-tested against a live browser** (by design — the repo's tests are zero-dep). The pure
  reconcile logic and the detector seams are fully covered; the driver follows the optional-tool
  convention.

---

## 9. Command Reference

### `render_confirm.py [html] [--evidence JSON] [--render --url URL]`

**Input:** an HTML file + renderer evidence (offline), or a URL to render (optional live path).
**Process:** feed captured clipboard/computed-hidden into the existing detectors → reconcile
static vs rendered verdicts.
**Output:** per-analyzer static/rendered/final verdicts + reconciliation + rendered IOCs.

Regression-tested by `tests/test_render_confirm.py` (run in `scripts/audit.sh`): rendered-clipboard
promotion, computed-hidden promotion, no-evidence-static-authoritative, reconcile directions, the
no-renderer degrade, and seam-additivity.

---

*Renderer-Level Confirmation Module v1.0.0 — for authorized threat-intelligence use.*
