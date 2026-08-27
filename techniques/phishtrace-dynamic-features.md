# PhishTrace — Dynamic-Feature Characterization

> **Module ID:** PHISHTRACE-001
> **Version:** 1.0.0
> **Phase:** Emerging Technologies of Cybercrime Defense
> **Classification:** Runtime-trace phishing characterization + exfil-IOC extraction
> **Research basis:** Ridwan Arefin Islam (McGill), Mohammad Mannan (Concordia) —
> *"PhishTrace: Characterizing Phishing Websites from Dynamic Features"*, APWG eCrime 2026.

---

## 1. Overview

Characterizes a phishing site from its **runtime behaviour** — the requests it made, the redirect
chain, the form POST targets, cloaking behaviour, and the exfil endpoints observed while the page
ran. Static HTML misses pages that look inert or cloaked until they execute; the dynamic trace is the
discriminator.

The feature extraction and verdict are a **pure, offline function over a trace dict** (CI-testable
with a synthetic/recorded trace). Capturing the trace live is the renderer's job
(`render_confirm.py` / the renderer path); this module consumes what the renderer produced, so it
stays keyless and deterministic.

Two safety rules define it: **exfil/third-party hosts are IOCs (pivot leads), not same-operator
attribution**; and an **empty/cloaked trace on a statically-suspicious page is a cloaking signal,
never a benign verdict** (the anti-false-negative rule).

**When to use:** after a render, to characterize a page the static pass couldn't judge, and to
harvest runtime exfil endpoints into the case.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/phishtrace_features.py` | Pure feature extraction + verdict over a trace | none |
| Produces the trace | `scripts/render_confirm.py` (renderer path) | live network/redirect/form capture | Playwright/agent-browser (optional) |
| Consumes IOCs | `/webpivot`, passive DNS | pivot the exfil/third-party hosts | none |

Keyless, stdlib only. No network in this module — it analyzes a supplied trace.

---

## 3. Investigation Workflow

```
1. Render the page and capture a trace (renderer path) → trace.json
2. phishtrace_features.py trace.json --origin <page-host> [--static-suspicious]
3. Read the verdict:
     phishing_likely -> off-origin credential exfil or exfil + cross-origin redirect
     cloaked         -> thin/bot-walled trace on a flagged page (NOT benign)
     suspicious      -> exfil or cross-origin redirect without a credential form
     inconclusive    -> thin trace, no static-risk flag → collect a fuller render
     benign          -> normal same-origin behaviour
4. Pivot iocs.exfil_endpoints + iocs.third_party_hosts via /webpivot + passive DNS
```

---

## 4. CLI Commands & Expected Output

```bash
# Characterize a captured trace
cat trace.json | python3 scripts/phishtrace_features.py - --origin login-bank.example

# When the static analyzers already flagged the page (affects the cloaked verdict)
python3 scripts/phishtrace_features.py trace.json --origin susp.example --static-suspicious --json
```

**Trace schema (all keys optional):** `landing_url`, `final_url`, `requests[]` (url/method/status/
type), `redirects[]` (from/to/status), `form_posts[]` (action/fields), `timing_ms`, `bot_wall`,
`cloak`, `dom_text_len`.

**Output:** `verdict`, `features` (redirect chain, cross-origin redirect, third-party host count,
off-origin credential form, exfil count, bot-wall/cloak/empty-DOM), `iocs`
(exfil_endpoints + third_party_hosts), rationale, and the IOC-not-attribution note.

---

## 5. Feature & Verdict Model

| Verdict | Condition |
|---------|-----------|
| `phishing_likely` | credential form posts off-origin, **or** exfil endpoint + cross-origin redirect |
| `cloaked` | thin/empty/bot-walled trace **and** (static-suspicious or cloak/bot-wall flag) |
| `suspicious` | exfil endpoint or cross-origin redirect, without a credential form |
| `inconclusive` | thin trace with no static-risk flag — collect a fuller render |
| `benign` | normal same-origin behaviour |

Same-site grouping uses a crude eTLD+1 (last two labels) so a page's own CDN subdomain isn't counted
as third-party.

---

## 6. Output Interpretation

- **`phishing_likely` + an exfil host** is the strongest dynamic finding — the page was observed
  posting credentials off-origin at runtime. Pivot the exfil host immediately.
- **`cloaked`** is a positive signal, not a null result — it means the site withheld its real
  behaviour (bot wall / empty DOM) on a page you already had reason to suspect.
- **`inconclusive`** explicitly asks for a better render rather than defaulting to benign.

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| phishing_likely + off-origin credential POST | HIGH | runtime-observed exfil |
| cloaked (flagged page) | MEDIUM | evasion signal; needs a determined render |
| suspicious | MEDIUM | corroborate the redirect/exfil |
| inconclusive | LOW | insufficient trace |

---

## 8. Limitations

- **Trace quality is everything.** Anti-automation / cloaking can starve the trace; the module turns
  that starvation into a `cloaked`/`inconclusive` signal rather than a false benign, but it cannot
  characterize behaviour it never observed.
- **Depends on the renderer path** for live capture (optional Playwright/agent-browser); the analysis
  itself is offline.
- **eTLD+1 is approximate** (public-suffix-free) — a multi-label ccTLD may mis-group a host; err is
  toward flagging third-party, not hiding it.

---

## 9. Command Reference

### `phishtrace_features.py <trace.json|-> [--origin H] [--static-suspicious]`

**Input:** a runtime trace JSON.
**Process:** extract dynamic features → verdict; collect exfil/third-party hosts as IOCs.
**Output:** verdict, features, IOCs, rationale (text or JSON).

Regression-tested by `tests/test_phishtrace_features.py` (run in `scripts/audit.sh`): the
off-origin-exfil phishing verdict, the cloaked-not-benign anti-false-negative rule, a benign control,
and malformed-trace degrade.

---

*PhishTrace Dynamic-Feature Module v1.0.0 — for authorized threat-intelligence use.*
