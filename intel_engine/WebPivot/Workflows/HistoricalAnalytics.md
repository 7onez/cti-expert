# Workflow: HistoricalAnalytics (Bellingcat / Wayback + Google Analytics method)

Find sites connected by a **shared analytics/AdSense/verification ID**, including
IDs that were **later removed** — by walking each domain's Wayback history instead
of trusting one live snapshot.

Based on Bellingcat, *"Using the Wayback Machine and Google Analytics to Uncover
Disinformation Networks"* (2024-01-09):
https://www.bellingcat.com/resources/2024/01/09/using-the-wayback-machine-and-google-analytics-to-uncover-disinformation-networks/
The classic UA-code technique traces to Lawrence Alexander's 2015 Bellingcat work.

## Why this beats a single snapshot
A network operator often reuses one Google Analytics / AdSense account across many
sites, then scrubs it once flagged. `pivot_extract.py` sees only *now*.
`wayback_ga.py` sees the **whole timeline**, so a shared ID from 2019 still surfaces.
(Note: GA `UA-` IDs were the strongest link pre-2023; GA4 `G-`, `GTM-`, and
`ca-pub-` AdSense are the live equivalents — this tool captures all of them.)

## Steps

1. **Timeline one domain** — every tracker/verification ID ever seen, with first/last dates:
   ```bash
   python3 tools/wayback_ga.py suspect.example --max 15 --timeline
   ```
   All fetches hit web.archive.org only — passive by construction. Use `--from 2016 --to 2026` to bound the window.

2. **Reverse each historical ID** to find *other* domains that used it — this is where the
   network appears. Run against `../references/PivotServices.md`:
   - **PublicWWW** `"UA-XXXX"` / `"G-XXXX"` / `"ca-pub-XXXX"` (current source)
   - **DNSlytics** reverse-analytics / reverse-adsense (includes historical)
   - **AnalyzeID**, **SpyOnWeb**, **HackerTarget** reverse-analytics
   - **urlscan.io** search for the ID across its scan corpus

3. **Batch a candidate set** — one domain per line:
   ```bash
   python3 tools/wayback_ga.py -f domains.txt --pretty > history.json
   ```

4. **Cross-reference** the `historical_ids` across every domain's JSON. Two domains that
   ever shared the same GA/AdSense/verification token are strongly the same operator —
   more so than a mere outbound link. Feed newly discovered domains back into step 1.

5. **Corroborate** with a second artifact (favicon hash, DOM template) via `AnalyzePage.md`
   before asserting the cluster, and grade confidence. Hand edges to `IntelGraph`.

## Companion tool
For larger jobs or a GUI, the Bellingcat community tool **wayback-google-analytics**
(github.com/Lyra-in-a-Bottle/wayback-google-analytics) does the same across many domains
and exports CSV/JSON. `wayback_ga.py` is the zero-dependency, harness-native version that
reuses WebPivot's own extractors so results line up with `pivot_extract.py`.
