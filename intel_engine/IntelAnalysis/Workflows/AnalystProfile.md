# Workflow: Teach the system YOUR investigation style

The bundle should reason the way *you* do, and start each case knowing what you already found.
Three channels, from lightest to heaviest.

## 1. Your priors & thresholds → `knowledge/analyst_profile.md`
A single git-ignored file the analyst layer reads at the start of a case (like a standing brief).
Put the judgment that isn't in code: which artifacts you'll assert on alone, your NRD cutoffs, the
registrar/market tells you trust, your house style for confidence words, who your typical targets are.
Copy the template below and edit it — IntelAnalysis reads it before triaging.

```bash
cp IntelAnalysis/references/analyst_profile.template.md knowledge/analyst_profile.md
$EDITOR knowledge/analyst_profile.md
```

## 2. Your past reports → the KB (`ingest_report.py`)
Your old write-ups hold IOCs (domains, emails, wallets, phones, handles) the KB has never seen.
Fold them in so a new case auto-correlates against your history and any confirmed-operator match fires:

```bash
python3 tools/kb/ingest_report.py path/to/old_report.md --case legacy_import --dry-run  # review first
python3 tools/kb/ingest_report.py path/to/old_report.md --case legacy_import           # write raw JSON
python3 tools/kb/ingest_webpivot.py --kb knowledge cases/legacy_import/raw/*.json       # ingest
```
Keep **one report = one cluster** so co-mention links stay honest. Review the `--dry-run` IOC list and
strip any false extractions before ingesting. Confirmed operators from those reports → register them
(`operator_registry.py`, see `Learn.md`).

## 3. Your recurring tradecraft → the skill
When a case teaches a *reusable* rule (a new tell, a noise pattern, a market-specific registrar quirk),
append it as a cited bullet to the **"Captured (in-case)"** blocks in `SKILL.md §1/§2`. That block is the
skill's long-term memory; every future run reads it. This is where your style compounds over time.

---

**How the three fit together:** profile = your standing priors; report-ingest = your past *facts*;
Captured blocks = your reusable *rules*. Together they make the analyst layer argue like you, over a KB
that already contains what you know. Update all three at case close (`Learn.md`).
