# Workflow: Create hypotheses, then try to break them

Attribution is a falsification game, not a similarity search. `tools/kb/hypothesize.py` hands you
a falsifiable board — candidate operator clusters, each with the check that would *disprove* it and
the open questions to answer — so you argue against your own finding before you commit to it.

```bash
python3 tools/kb/hypothesize.py --kb knowledge --min 2                 # all candidate operators
python3 tools/kb/hypothesize.py --kb knowledge --domain brand-a.example  # clusters touching one domain
python3 tools/kb/hypothesize.py --kb knowledge --show-dropped          # see what was excluded + why
```

## What it does (and the doctrine baked in)

- **Clusters only on attribution-grade identity artifacts** — registrant email/name, owner tokens
  (GA4/GTM/verification), SaaS ids, **reused wallet**. Shared *kit* (theme, CSS, favicon, comment
  hash) is reported as *supporting* evidence but **never merges operators** — same-kit ≠ same-operator
  (kits are sold and shared). This is why it produces tight real clusters instead of one giant blob.
- **Drops noise before clustering** (`--show-dropped` to audit): privacy-proxy / registrar-role emails
  (`domainabuse@…`, `…privacy…`), placeholder registrants ("Domain Admin, C/O ID#…"), empty-hash parser
  artifacts, and any *identity* artifact on more than `--max-fanout` domains (default 40 — a reseller,
  not one owner). These bridge unrelated groups; clustering on them is the #1 attribution error.
- **Distinguishes identity from shared-service tokens.** A registrant email/name or reused wallet on
  many domains = one operator (legit). But a third-party **service token** (GA/GSC/hotjar/adsense) on
  more than `--service-fanout` domains (default 15) is usually a **shared SEO/marketing agency** account
  spread across unrelated clients — it's flagged `⚠AGENCY-SUSPECT` and NOT merged (this is what stopped a
  forex cluster and a Chinese-gambling cluster fusing through one shared hotjar id). Verify operator vs
  agency before asserting on a service token alone.
- **Rates confidence** per the corroboration rule: `assessed` (≥2 attribution-grade, or 1 + a named
  identity) / `likely` (1, needs a 2nd) / `lead` (corroborating only).

## The loop (per hypothesis it prints)

1. **HYPOTHESIS** — "these N domains are one operator, bound by <artifacts>."
2. **DISCONFIRM** — run the printed checks. Look for the artifact that *shouldn't* be shared if the
   hypothesis holds: a different registrant on one member, a conflicting GA/verification property, an
   origin IP in a different ASN. Absence of disconfirming evidence ≠ proof — note what you couldn't check.
3. **OPEN QUESTIONS** — answer them with the cheapest pivot that confirms *or* kills (see `NextPivot.md`):
   one registrant or several? a reused wallet? are they NRD (run `risk_signals.py`)? shared *origin* IP?
   which single node, if removed, disconnects the cluster (that's the broker)?
4. **Decide** — promote to the assessment only at the confidence the evidence earns; record the operator
   in the registry at case close (`Learn.md`).

## Feeding it your judgment
`hypothesize.py` is a starting board, not a verdict. When you confirm or reject a cluster, that lesson
belongs in the "Captured (in-case)" blocks of `SKILL.md` and (for a confirmed operator) in the registry —
so the next run starts from your conclusion, not from scratch.
