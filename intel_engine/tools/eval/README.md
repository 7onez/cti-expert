# Golden-set eval harness — regression gate for the OSINT tooling

This is the **measurement layer** for the WebPivot / KB stack. It runs the real
`pivot_extract.py` over frozen HTML fixtures (offline, deterministic) and checks the
output against per-case expectations. Every change to an extractor runs here first.

> **Why it exists.** The whole reason to invest in the harness (tools + memory + filters)
> instead of just a bigger model is that *harness improvements compound* — but only if you
> can measure them. Without a golden set, every edit to `pivot_extract.py` is a blind
> change: it might start finding a new pivot while silently losing an old one, or let a
> parking-favicon / Cloudflare-NS false cluster creep back in. This harness makes both of
> those show up as a red `FAIL` before you commit.

---

## How it works

```
tools/eval/
  run_eval.py            # the runner
  cases/
    <case-name>/
      input.html         # a frozen DOM fixture (offline — no network)
      expected.json      # what the extractor MUST and MUST NOT produce
```

For each case the runner:
1. calls `python3 WebPivot/tools/pivot_extract.py <input.html> -o <tmp> --no-enrich --no-whois`
   — the **real** tool, offline, so the run is reproducible and fast;
2. loads the resulting JSON (`meta` / `artifacts` / `pivots`);
3. checks every assertion in `expected.json`;
4. prints `PASS`/`FAIL` per case and **exits with the number of failed cases** (0 = all green),
   so it can gate a pre-commit hook or CI.

### Offline scope (important)
Fixtures are fed as local HTML, so the harness covers the **HTML-derived** surface —
trackers, crypto, **QR codes**, emails, socials, forms, SaaS tokens, app-download links,
HTML comments, DOM skeleton. It deliberately does **not** cover network-only signals
(favicon hash, live TLS cert, FOFA/urlscan/WHOIS enrichment, live DNS) because those aren't
reproducible offline — assert those in a separate live smoke test. This is also *why the
parking-domain case expects zero pivots*: the Sedo parking noise (favicon 643372374, the
Sedo IP reverse) only appears during live enrichment; the raw parking DOM has nothing.

---

## Running it

```bash
python3 tools/eval/run_eval.py             # all cases, human report
python3 tools/eval/run_eval.py -v          # show passing assertions too
python3 tools/eval/run_eval.py --case qr_funnel
python3 tools/eval/run_eval.py --json       # machine-readable (for CI)
echo $?                                     # 0 = all passed, N = N cases failed
```

---

## Adding a case (the important part — grow this over time)

Every time you confirm a real cluster, or reject a false one, **freeze it as a case**. That
is how the harness gets smarter: today's judgment call becomes tomorrow's automatic guard.

1. Save the page's DOM to a fixture (any of these):
   ```bash
   # from a live page (post-JS DOM is best — QR/injected IDs only appear there)
   python3 WebPivot/tools/pivot_extract.py https://target.example --render \
       --save-dom tools/eval/cases/<name>/input.html -o /dev/null
   # or just reuse a DOM you already saved in a case:
   cp cases/<case>/dom/<host>.html tools/eval/cases/<name>/input.html
   ```
2. Write `tools/eval/cases/<name>/expected.json` (schema below).
3. `python3 tools/eval/run_eval.py --case <name> -v` until it's green for the *right* reasons.

### `expected.json` schema

| Key | Meaning |
|---|---|
| `description` | one line shown in the report |
| `input` | fixture filename (default `input.html`) |
| `expect_pivots` | list of specs; **each must match ≥1 emitted pivot** |
| `forbid_pivots` | list of specs; **none may match any emitted pivot** (noise / false-cluster guard) |
| `expect_artifacts` | `{"dotted.path": [values]}` — path into `artifacts` must **contain** each value |
| `forbid_artifacts` | `{"dotted.path": [values]}` — path must **not** contain the value |

A **pivot spec** matches a pivot when every field it sets agrees:
- `kind` — exact pivot kind (e.g. `qr:telegram`, `favicon_hash`)
- `kind_prefix` — kind starts with this (e.g. `crypto:` matches `crypto:btc`)
- `value` — exact value match
- `value_contains` — substring of the value

Examples:
```jsonc
// must find the wallet decoded out of a QR
{"kind": "qr:crypto:btc", "value": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"}

// must find *some* Telegram-in-QR pivot, whatever the exact URL
{"kind": "qr:telegram", "value_contains": "t.me/"}

// must NOT emit any crypto pivot on a parking page
{"kind_prefix": "crypto:"}
```

A dotted artifact path walks the `artifacts` dict, e.g.
`trackers.qr_wallet_btc`, `crypto.btc`, `app_downloads.android_packages`, `title`.

---

## Current cases

| Case | Guards |
|---|---|
| `qr_funnel` | QR extraction: wallet / Telegram / affiliate-URL / WhatsApp / undecoded-image all decode + classify correctly |
| `parking_domain` | Negative control: a Sedo/NameSilo parking DOM produces **no** operator pivots |

## Wire it into a pre-commit gate (optional)

```bash
# .git/hooks/pre-commit
#!/bin/sh
python3 tools/eval/run_eval.py --json >/dev/null || {
  echo 'eval harness FAILED — run: python3 tools/eval/run_eval.py -v'; exit 1; }
```

## Extensions worth adding next
- **Cluster-level cases** — ingest several fixtures into a throwaway KB and assert
  `expect_clusters` / `forbid_clusters` (catches KB-side false merges like the Cloudflare-NS
  bug). The per-case pivot layer here is the foundation for it.
- **Live smoke test** — a separate, non-gating script that hits 2-3 known-stable URLs to
  confirm enrichment/keys still work end-to-end.
- **Judgement calibration log** — record each IntelAnalysis confidence call + its later
  confirmed/refuted outcome, and score calibration over time.
