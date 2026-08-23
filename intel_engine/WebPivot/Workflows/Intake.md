# Workflow: Intake

Scope the run **before** collecting, and turn the requester's claim into something the
collection tests instead of something it inherits.

Runs first, every time a target arrives — a domain, an IP, a saved page, a favicon hash, a
tracking ID. Costs one question round; saves the three failures below, none of which are
visible in the output once they happen.

Tunable data: `../references/intake.json` (classes, questions, posture, verdicts, policy).
Never blocks — see step 3.

## Why (the three failures this prevents)

1. **Wrong posture.** The default profile is a direct live fetch with every layer on. For a
   threat-actor host that is an attributable probe that tells the operator they are being
   examined; for a metered run it spends shared credits nobody authorised.
2. **Wrong owner.** On a compromised third-party host, the WHOIS, favicon, certificate and
   analytics belong to the **victim**. Cluster on them and unrelated victims fuse into one
   imaginary operator estate — a result that looks like a breakthrough.
3. **Anchoring.** "This is a scam site" arrives as a premise, and every ambiguous artifact
   downstream is then read as confirming it. The requester is often right; when they are
   wrong, the cost lands on a real business.

## Steps

### 1. Ask — one grouped prompt, not an interrogation

Ask at most four at a time (`policy.max_questions_in_one_prompt`). The two that carry the
scoping are **target class** and **purpose**; the rest are best-effort.

| Ask | It changes |
|---|---|
| **What do you believe this is?** — confirmed scam · suspected scam · threat-actor infra · victim host · legitimacy check · unknown | fetch posture, opsec, which layers run, **whose artifacts these are** |
| **What is that based on?** — victim complaint · takedown/seizure · vendor report · an ad you were served · a log · a hunch | whether the class is asserted or hypothesised, and what its verdict is judged against |
| **What is the run for?** — triage · cluster expansion · attribution · takedown package · own-exposure check | depth; whether capture / ingest / assessment are mandatory; which skill runs next |
| **Is a brand or entity involved, and which side is this host?** | seeds the impersonation hunt; forces the **direction** check |
| **How did it reach you?** — ad · message · file download · redirect chain · another case | turns on the advertising + cloaking probe, or hands off to BinaryPivot |
| **Is there a date that matters?** | anchors the archive timeline on the incident, not on today |
| **Constraints?** — may we touch it · may we spend metered credits · case id | passive-only vs direct fetch · `--free-only` · where everything persists |
| **What would tell you this is *not* what you think?** | the disconfirming checks this run must report on, and the stop condition |

The last one is the highest-value answer in the list: it pre-commits both of you to an exit,
which is what stops a run spending a week confirming a premise nobody agreed to test.

### 2. Skip what is already answered

`policy.ask_once` / `skip_when_context_supplied`. If the requester already said "this
`example.com` was in a phishing report last March and I want a takedown package", the intake
is **done** — do not re-ask it back at them. Echo the scope you inferred in one line and start.

### 3. Never block

`policy.blocking: false`. If nothing is supplied, or the caller is `intel.py` /
the orchestrator / the MCP server / a batch (nobody to ask):

- proceed under `target_class: unknown` → **passive-first**, conservative posture;
- run liveness + archive timeline first, because those are what usually resolve the class;
- **state the assumption in the deliverable** — "run proceeded without stated context;
  treated as unknown/possibly-adversarial; no direct fetch; class resolved by collection".

An unanswered intake changes the posture and the disclosure. It never refuses to run.

### 4. Set the posture from the class

Read `target_classes.<class>` in the JSON and apply `fetch_posture`, `run`, and
`clustering_rule` before the first request. The two that most change behaviour:

- **`threat_actor_infra` → `never_direct_from_analyst_egress`.** Third-party scanners and
  stored captures only. No fetch, no scan, no path walk.
- **`victim_host` → the ownership boundary.** Only the **injected** content — the kit path,
  its assets, its endpoints — is the operator's. Everything the host owns is the victim's and
  is not a cluster edge. The valuable output is the access vector, not another domain.

### 5. Test the claim — the mandatory checks

Run these whatever the requester's confidence was, and especially when it was high. Each is
a way a confidently-stated class turns out wrong (`claim_verification.mandatory_checks`):

- **Liveness by reading the page**, not by status code. Parking, suspended, server-default
  and soft-404 pages all return HTTP 200 — collecting off one harvests a template shared by
  millions of domains.
- **Archive timeline.** The state at the incident date is the relevant one. Parked today ≠
  parked then; scam today may postdate the claim entirely.
- **Impersonation direction.** If a brand was named, confirm the seed is the imposter — not
  the brand's own site, a licensed reseller, or a regional property.
- **Base rate.** Count the population behind any artifact before it becomes an edge.
- **Ownership boundary.** Decide whose asset each artifact is before clustering on it.

### 6. Answer the claim explicitly in the deliverable

One line, near the top, using `claim_verification.required_output_line`:

> Stated premise: `<class>` (source: `<basis>`). Collection verdict: **supported /
> partially supported / not supported / contradicted / inconclusive** — `<one line of why>`.

Vocabulary that must not blur:

- **not supported** = the collection found nothing either way. If the run was keyless,
  free-only, passive or blocked, that is a statement about the **collection**, not the
  target — say which, and pair it with the capability disclosure.
- **inconclusive** = the target was never observed (challenge wall, blocked, unresolved).
  The claim was not tested. Do not report it as either outcome.
- **contradicted** is the most valuable result an intake produces. Lead with it.

### 7. Reclassify out loud

If the collection establishes a different class than the one stated
(`policy.reclassify_mid_run`) — the "scam site" is parked, the "operator domain" is a
compromised victim, the "imposter" is the genuine brand — **stop, say so, restate the
posture, and continue under the new class**. Do not quietly keep collecting under a premise
the evidence just broke.

## Prohibitions (`claim_verification.never`)

- Never raise a confidence level because the requester was certain.
- Never skip a disconfirming check because the class was stated as confirmed.
- Never write the stated class into the knowledge base or an assessment as a collected finding.
- Never report "not supported" as "benign" when the run was keyless, passive or blocked.
- Never let a stated class authorise a fetch its own posture forbids.

## Then

Continue with `AnalyzePage.md` (one page), `ParallelBatch.md` (a list), or
`CampaignClustering.md` (many) — under the posture this step set.
