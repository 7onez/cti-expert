# Workflow: ParallelBatch — fan out WebPivot + analysis across many targets

**When to use multiple agents (and when NOT to).** The `pivot_extract.py` engine is
deterministic Python — a *single* page does not need agents, and `--crawl` already walks a
site's subpages in one process. Spawn parallel agents when the work is genuinely wide or
benefits from independent perspectives:

| Situation | Parallelize? | How |
|---|---|---|
| One page / one domain | **No** | run the tool directly (`pivot_extract.py <url>`) |
| A **list of domains** (a batch/cluster) | **Yes** | one agent per domain → collect → one synthesis agent |
| **Attribution/verification** of a cluster | **Yes** | N independent skeptic agents, each told to *refute* |
| CF-walled targets needing a browser each | **Yes** | one `BrowserAgent` per target (isolated sessions) |
| Correlating many clusters in the KB | **Yes** | parallel readers per cluster → synthesis |

The rule: fan out over an **independent work-list**, join on a **synthesis** step. Collection
is embarrassingly parallel (each host is independent); *judgement* wants a single agent that
sees all results so it can weigh them against each other.

## Pattern A — batch collection (a domain list)

Scout first (list the hosts), then fan out one collector per host, then synthesize. Two ways:

**A1. The deterministic orchestrator (default, no agents needed).** For pure collection over a
list, `intel.py` already does extract → ingest → cluster in one reproducible pass:
```bash
python3 tools/intel.py open <case> domains.txt --render --operator "name"
python3 tools/kb/query.py --kb knowledge --shared --min 2      # the cluster seeds
```
Prefer this when you just need the artifacts + clusters; it's reproducible and cheap.

**A2. Agent fan-out (when each target needs judgement / browser work / CF-solving).** Spawn one
agent per host **in a single message** so they run concurrently, then one analyst agent over the
results. Each collector agent runs:
```bash
python3 "$WP/tools/pivot_extract.py" https://<host> --render --solve-cf \
    -o "$CASE/raw/<host>.json" --leads
```
and returns its `raw/<host>.json` path. After all finish: ingest once, `query.py --shared`, and
hand the shared clusters to **one** IntelAnalysis pass (see IntelAnalysis SKILL.md) — that agent
sees every host at once, which is what correlation needs.

> For large batches or when you want adversarial rigor, run this as a **Workflow** (pipeline of
> collect → verify → synthesize) rather than hand-spawned agents — it fans out, verifies each
> finding with independent skeptics, and joins deterministically. Only launch a Workflow when the
> user has opted into multi-agent orchestration.

## Pattern B — adversarial verification of an attribution

A single shared artifact is a lead, not proof. Before asserting "X and Y are one operator",
spawn ≥3 independent agents, each prompted to **break** the claim (find the artifact that
*shouldn't* be shared if true — different registrant, conflicting GA4, different ASN). Keep the
attribution only if a majority fail to refute it. Log the call with
`tools/kb/calibration.py record …` and resolve it later — that keeps the confidence labels honest.

## Join discipline (don't skip)

1. **Ingest once**, after all collectors finish: `python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json`
2. **Corroborate** — `query.py --shared --min 2`; the noise filters (`noise_filters.py`) already
   drop managed-DNS / parking / registrar-email false clusters, so a surviving cluster is a real lead.
3. **Converge** — `python3 tools/kb/convergence.py snapshot <case>` each round; stop when
   `status` says CONVERGED.
4. **One assessment** — a single analyst pass writes the ICD-203 report over the whole batch.
