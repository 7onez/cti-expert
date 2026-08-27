# Phishing Kit-Template Attribution (Tree-Structured)

> **Module ID:** KIT-ATTR-001
> **Version:** 1.0.0
> **Phase:** Measurement, Characterization & Attribution
> **Classification:** Structural kit/template fingerprint → builder/operator lineage clustering
> **Research basis:** Unai Agirre, Jerico, Felipe Castaño, Andrea Venturi, Francesco Zola
> (Vicomtech) — *"A Tree-Structured Approach for Phishing Template and Attacker Attribution
> Analysis"*, APWG eCrime 2026.

---

## 1. Overview

Fingerprints a phishing page's **kit/template structure** — the DOM skeleton, the harvest form's
field-name set, and the shared asset paths — and measures structural similarity between pages, so
the same kit links across rotating hosts even when the brand and text are swapped. The eCrime paper's
insight is that kits are reused verbatim; the *structure*, not the swappable content, is the stable
attribution signal.

The defining constraint is **attribution safety**: a shared **commodity** template
(WordPress/Wix/Shopify theme, a popular free kit) sits on thousands of unrelated hosts, so matching
it is the §2.5 "commodity site kit" trap, not a same-operator link. The module therefore **grades**
every match and never auto-merges (see `/cti-check`, CLAUDE.md RULE 5).

**When to use:** during characterization/clustering of two or more collected phishing pages, as a
structural complement to infrastructure pivots.

---

## 2. Tool Inventory

| Priority | Tool | Purpose | Install |
|----------|------|---------|---------|
| Primary | `scripts/kit_template_fingerprint.py` | Offline structural fingerprint + similarity + grading | none |
| Integrates | `intel_engine/tools/kb/*`, `/clusters` | adds a graded lower-rung edge | none |

Keyless, stdlib `html.parser` only. No network, no render.

---

## 3. Investigation Workflow

```
1. Collect two or more candidate phishing pages (WebPivot / agent-browser / saved HTML)
2. Fingerprint each; compare pairs with --compare
3. Read the grade:
     commodity_template_noise -> a CMS/site-builder match; DO NOT cluster (noise)
     candidate_same_kit       -> lower-rung lineage edge; corroborate with a unique indicator
     weak_similarity          -> hold pending corroboration
     dissimilar               -> no signal
4. For a candidate_same_kit, corroborate with a UNIQUE indicator (tracker ID, wallet, TLS cert)
   before treating as same-operator — the kit link alone is builder-lineage, not identity
5. Feed the corroborated edge into /clusters at the documented lower rung
```

---

## 4. CLI Commands & Expected Output

```bash
# Fingerprint one page
python3 scripts/kit_template_fingerprint.py page.html --json

# Compare two pages -> similarity + grade
python3 scripts/kit_template_fingerprint.py --compare kit_a.html kit_b.html

# Add local commodity markers (e.g. an in-house CMS) so its matches grade as noise
python3 scripts/kit_template_fingerprint.py --compare a.html b.html --refs commodity.json
```

**Fingerprint output:** `structure_hash`, tag-path shingle count, `form_signature`,
`asset_skeleton`, `markers` (CMS/builder tells), `generator`.
**Compare output:** `score` (0-1) + per-component (tag-path / form / asset), `shared_features`,
`commodity` flag + marker, `grade`, `clustering_edge`, and the not-auto-merge note.

---

## 5. Similarity & Grading Model

Score = 0.6·Jaccard(tag-path shingles) + 0.3·Jaccard(form field-names) + 0.1·Jaccard(asset tails).

| Grade | Condition | Clustering edge |
|-------|-----------|-----------------|
| `commodity_template_noise` | score ≥ 0.6 **and** a commodity marker present | **none** (do not cluster) |
| `candidate_same_kit` | score ≥ 0.75 **and** no commodity marker | `lineage_low_confidence` (corroborate) |
| `weak_similarity` | score ≥ 0.5, no commodity | `hold` |
| `dissimilar` | otherwise | none |

No grade ever emits a `same_operator` edge — that promotion requires an independent unique indicator.

---

## 6. Output Interpretation

- **`candidate_same_kit`** means "same builder/kit lineage, probably" — strong enough to *investigate*
  a shared operator, not to *assert* one. Corroborate, then cluster.
- **`commodity_template_noise`** is the save that prevents naming unrelated WordPress sites as one
  operator; treat it as a hard stop on clustering, exactly as `/cti-check` prescribes.
- **`form_signature`** identity (same harvest field-names) is a strong sub-signal — kits ship a fixed
  exfil form; a verbatim field-name set across hosts is more specific than layout alone.

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| candidate_same_kit + a shared unique indicator | HIGH (same operator) | corroborated |
| candidate_same_kit alone | MEDIUM (same kit) | lineage, not identity |
| commodity_template_noise | N/A | not a finding — noise |
| weak_similarity | LOW | hold |

---

## 8. Limitations

- **Static structure only.** JS-rendered SPAs whose DOM is built at runtime need the renderer path
  (see `techniques/visibility-aware-html.md` / the renderer confirmation module) for a faithful tree.
- **Commodity seed list is small and tunable** (`--refs`); an in-house CMS not in the seed list can
  over-match until added — the fix is a marker, not a code change.
- **Kit ≠ operator.** The module is deliberate that even a strong match is lineage, not identity.

---

## 9. Command Reference

### `kit_template_fingerprint.py <html> | --compare A B`

**Input:** one HTML page (fingerprint) or two (compare).
**Process:** DOM tag-path skeleton + form + asset fingerprint → Jaccard similarity → commodity-aware
grade → clustering-edge recommendation.
**Output:** fingerprint or similarity+grade+edge (text or JSON).

Regression-tested by `tests/test_kit_template_fingerprint.py` (run in `scripts/audit.sh`), including
the sibling-kit match, the unrelated-page control, the commodity-trap RULE 5 guard, and the
never-auto-merge invariant.

---

*Phishing Kit-Template Attribution Module v1.0.0 — for authorized threat-intelligence use.*
