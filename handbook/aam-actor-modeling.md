# AAM Actor-Modeling Overlay for `/threat-model`

> **Analytic note (documentation only — no collector).**
> **Research basis:** Pete Herzog (ISECOM) — *"Modeling Adversaries Through Chaos"*, APWG eCrime
> 2026 Training Day. This note encodes the framework's **structural shape** and its four **surgical
> operations** — the portable part the training teaches — not the proprietary full 240-state grid,
> which stays in ISECOM's research use.

---

## 1. Why this overlay

`/threat-model` already produces an **ACH** attribution matrix (rival hypotheses scored by
inconsistency; see `handbook/analytic-standards.md`). ACH answers *"who did this, and how sure are
we?"* — a retrospective, evidence-weighing question.

The **Adversarial Analysis Model (AAM)** answers a different, forward question: *"what state is this
actor in, and what are they in a position to do next?"* — capturing what an actor **can do next**
rather than only what they **did** (the kill-chain framing). It is an optional overlay applied
**after** ACH, when the case is about anticipating, redirecting, or interdicting an active operator
(a live phishing operator, a money-laundering cluster, a romance-scam network), not merely
attributing a past event.

Use it when: the actor is active and you need a next-move posture. Skip it when: the case is a
closed retrospective attribution or a single-artifact IOC lookup.

---

## 2. The structural shape (what you fill in)

Model the actor across **four OODA observation faces** — do not collapse to a single perspective:

| Face | Question for this actor |
|------|-------------------------|
| **Observe** | What is the actor currently seeing / monitoring (victim responses, takedowns, their own infra health)? |
| **Orient** | How are they interpreting it (are they aware of your interest? of the takedown pressure)? |
| **Decide** | What decision is pending for them right now (rotate infra, cash out, escalate, lie low)? |
| **Act** | What action are they positioned to take next, and how quickly? |

For each face, account for **multi-locus** perspective — the actor's view of **themselves**, of
their **target/victim**, and of their **context** (registrar/host/law-enforcement pressure) — because
an actor acts on their *perception*, not on ground truth.

State each face in one or two evidence-anchored sentences. Where you have no evidence for a face,
say so — an unknown face is a collection gap, not a blank.

---

## 3. The four operations (what you do with the model)

Once the actor's state is placed, apply the surgical operations to anticipate / redirect / interdict
the next move. Each operation is a lens on how to act against the modeled state:

| Operation | Meaning | Example against a phishing operator |
|-----------|---------|-------------------------------------|
| **Mirror** | Reflect the actor's own behavior/pressure back at them | Report their infra through the same abuse channels they exploit for longevity, at the cadence they rotate |
| **Twin** | Occupy an equivalent state to predict their next move | Model what *you* would do next in their position (which of N rotation domains fires next) and pre-emptively flag it |
| **Opposite** | Force a state they are not prepared for | Trigger a takedown at the moment their Observe face is looking elsewhere (mid-campaign, not post-mortem) |
| **Lever** | Apply small pressure at a load-bearing dependency | Target the single shared dependency (a reused wallet, a bulletproof upstream, one registrar) whose loss collapses the set |

The goal is not a complete state machine; it is a **posture** — a small set of anticipated next moves
and the operation best suited to each.

---

## 4. Worked example (anonymized phishing operator)

Case: an operator running ~30 combosquat domains rotating across two bulletproof hosts, harvesting
banking credentials, cashing out via one reused crypto wallet.

- **Observe** — monitors takedowns (domains re-register within hours of suspension); likely watches
  denylist inclusion. *Evidence: sub-day re-registration cadence in the case timeline.*
- **Orient** — treats takedowns as routine cost, not as targeted attention; no sign they know they're
  under investigation. *Evidence: no infra change after our passive collection.*
- **Decide** — pending decision is which host to rotate to next; the wallet is a fixed dependency they
  have **not** decided to change. *Evidence: single wallet across all 30 domains.*
- **Act** — positioned to spin up the next domain batch within hours of a takedown.

Posture:
- **Lever** on the reused **wallet** — it is the load-bearing dependency; chain-flagging / exchange
  reporting hurts more than any single-domain takedown.
- **Twin** the rotation — from the two-host pattern, pre-emptively enumerate and flag the next host's
  likely domains (kit-template fingerprint + cert pivot) *before* they go live.
- **Opposite** — coordinate the domain + host + wallet actions to land together, forcing a state
  (simultaneous loss of infra and cash-out path) they rotate-by-domain habits don't prepare for.

Deliver this as a short "next-move posture" block appended to the ACH matrix in the INTSUM.

---

## 5. Placement in the workflow

1. Run ACH first (attribution + confidence) per `handbook/analytic-standards.md`.
2. If the actor is active and interdiction is in scope, add an **AAM overlay** block: the four faces
   (evidence-anchored) + a short posture using Mirror / Twin / Opposite / Lever.
3. Keep it evidence-bounded: every face cites a finding or is marked a collection gap. Do not
   speculate an actor's internal state without a behavioral signal to anchor it.

Attribution: the AAM framework is by Pete Herzog / ISECOM (APWG eCrime 2026 training). This overlay
uses only the taught operations and structural shape; the full state grid is ISECOM's.
