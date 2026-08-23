---
name: Engage
description: Detect a scam/fraud site's AUTHENTICATION SURFACE and (gated) engage with it — find the login form, the password field and the registration page, then, only on explicit confirmation, create a SYNTHETIC-persona account and log in to see the members area (panel, deposit/withdraw flow, affiliate tree, support handles) that the public page hides. Detection is free and passive; account creation is outbound, attributable and irreversible, so it is gated exactly like a sandbox submission. USE WHEN detect the login panel, find the login form, where do you log in, registration page, signup form, does this site let you register, what fields does signup need, create an account on the scam, engage with the operator, log into the panel, see the members area, get inside the platform, deposit/withdraw flow, affiliate/referral signup, invite code, is there a captcha, does signup need OTP, mint a research persona, controlled interaction with the target.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, personas or case IDs in this file,
> its workflows, tool code, or test fixtures. Investigation data — and every persona — lives only
> in the git-ignored `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders
> (`site.example`, `registrant@example.com`, `CASE-0001`). See the repo-root `CLAUDE.md`.

# Engage — the authentication surface, and controlled interaction

## 🎯 The GOAL — get inside, to unmask the OPERATOR

Same objective as the rest of the kit (`WebPivot/SKILL.md` §*The GOAL*): the person behind the
infrastructure. A scam funnel keeps its most identity-bearing material **behind the login** — the
deposit wallet the operator actually collects on, the backend/API the panel talks to, the referral
tree that names the upline, the support Telegram/Zalo, sometimes other victims' data. The public
page is the decoy; the members area is where the operator transacts. Engage is how you read it.

Two halves, deliberately split by risk:

1. **Detect (free, passive, automated)** — `en_forms.py`. Read the page and classify its forms:
   **login** (identifier + password), **registration** (adds a confirm-password / invite code /
   terms), **password-reset**. Surface what engagement would need — the auth POST endpoint (a
   pivot, often the backend the HTML never names), whether a **CAPTCHA** or **OTP** blocks an
   automated signup, whether an **invite/referral code** is required (a closed-funnel tell + a
   clustering pivot). This touches nothing but the page and needs no account.

2. **Engage (gated, synthetic-only, human-confirmed)** — `en_persona.py` + `en_engage.py`. Mint a
   **synthetic** research identity, then — *only on explicit per-engagement confirmation* — create
   the account and log in from **non-attributable egress**, capturing the members area as evidence.

3. **Harvest the mission (post-login)** — `en_harvest.py`. Once inside, pull the material the public
   page hid: the scammer's **crypto wallet** and **bank/payee** details, the **service flow**, and
   the **credential-harvester upload path**.

### Registration, KYC, and the puppet-inbox pool

- **No KYC (the common case).** Most fraud funnels verify nothing — a made-up username + password
  registers, and you log straight in. `en_engage` does exactly that with the synthetic persona.
- **Email confirmation.** When a funnel gates on an email-confirmation click, the persona must use a
  **real mailbox you control** — one of a small **puppet-inbox pool** the analyst provisions ahead of
  time. Mint the persona `--from-pool`, run `en_engage --await-confirm`: it registers, `en_inbox`
  waits for the confirmation email in that mailbox and extracts the link, the **browser** opens it
  (so the click comes from research egress), then login proceeds. `en_inbox` only **reads** a mailbox
  you own over IMAP — it never sends mail and never touches anyone else's inbox.
- **Hard KYC (government ID / selfie / liveness) is a STOP.** The tool never fabricates or uploads
  identity documents; a human decides whether such an engagement is in scope at all.

> **The puppet-inbox pool is CASE DATA (RULE 1).** It holds real credentials to mailboxes you
> control, so it lives ONLY in the git-ignored store — default `knowledge/engage_inboxes.json`,
> referenced by `ENGAGE_INBOX_POOL` — and is **never** committed. For Gmail use an **app password**
> (IMAP enabled), not the account password. Shape: a JSON list of
> `{email, imap_host, imap_port, imap_user, imap_password, in_use}`.

### The mission — what you're inside for

The point of getting in is the operator's money and mechanics, which the login hides:

- **crypto wallet addresses** — where deposits actually go (BTC / ETH-ERC20-BEP20 / TRON-TRC20);
- **bank / payee account details** — IBAN, SWIFT/BIC, account numbers (taken only in bank context);
- **the service flow** — deposit → task/trade → withdraw-block → top-up demand; VIP tiers; the
  referral/team tree;
- **the credential-harvester upload path** — where the panel POSTs captured credentials / KYC
  uploads (the operator's own routing, which clusters the kit).

`en_harvest.py` extracts these from the captured authenticated DOM; `en_engage` runs it automatically
after login. A wallet or account the operator collects on is among the **strongest identity-bearing
artifacts in the whole kit** — reused across the estate, and where a financial-intelligence / law-
enforcement referral begins.

> 🚫 **Engagement is the most OPSEC- and legally-loaded action in this toolkit — treat it like the
> ANY.RUN submission gate, not like a page read.** It is **outbound** (a POST to the operator's own
> backend), **attributable** (they see a new member at a known time from your egress, with a
> fingerprint), and **irreversible** (you cannot un-register). So the code **never acts without
> explicit confirmation**, uses a **synthetic identity only**, **refuses direct egress** unless you
> override it knowingly, and **never solves or evades a CAPTCHA or OTP** — a human decides those.
> Do it only within your authorization for the case, and know your jurisdiction's line between OSINT
> engagement and unauthorized access. `en_forms` and the leak-corpus route (below) answer most
> questions with **no** account at all — reach for engagement last, not first.

## The scripts

Zero required dependencies (Python 3 stdlib). `requests` is used for fetching if present;
`playwright` is used to drive the browser engagement if present, else you get a manual runbook.

```bash
EN=~/.claude/skills/Engage/tools ; CASE=cases/<case>

# 1) DETECT the login / password / registration surface (the passive core)
python3 "$EN/en_forms.py" https://site.example --leads          # human-readable summary
python3 "$EN/en_forms.py" https://site.example -o "$CASE/engage/forms.json" --pretty
python3 "$EN/en_forms.py" https://site.example --proxy http://127.0.0.1:8080   # via research egress
python3 "$EN/en_forms.py" saved_page.html                        # offline, on saved HTML

# 2) MINT a synthetic persona (never real PII; one per case)
python3 "$EN/en_persona.py" --case <case> --pretty                       # placeholder email
python3 "$EN/en_persona.py" --case <case> --from-pool --pretty           # real puppet inbox (email-gated signups)

# 3) ENGAGE — gated. Without --confirm-engagement (and INTEL_ENGAGE_CONFIRM=1) you get the briefing.
python3 "$EN/en_engage.py" https://site.example/register \
    --persona "$CASE/engage/persona_*.json" --detection "$CASE/engage/forms.json" \
    --proxy http://127.0.0.1:8080 --case <case>            # ← preflight only (safe)
INTEL_ENGAGE_CONFIRM=1 python3 "$EN/en_engage.py" https://site.example/register \
    --persona ... --detection ... --proxy http://127.0.0.1:8080 --case <case> \
    --await-confirm --target-domain site.example --confirm-engagement   # ← registers, confirms, logs in, harvests

# 4) HARVEST the mission from a captured authenticated page (en_engage also does this automatically)
python3 "$EN/en_harvest.py" "$CASE/engage/session_*/authenticated_dom.html" --case <case> --pretty
```

## What detection reports

`en_forms.py` emits JSON with `auth_surface` (`login` / `register` / `password_reset`, each with its
fields, `action`, method, confidence and `signals`), the `login_links` / `register_links` it can
follow **one hop** to find the counterpart form, any `captcha` markers, the `pivots`
(`auth_endpoint`, `referral_field`), and an `engagement_plan`: `registerable`, the `required_fields`
a persona must supply, the `blockers` (captcha / OTP) that stop an automated signup, and the next step.

- **Classification is by FIELDS, not the URL.** A confirm-password field is the strongest
  registration tell; an identifier + password with no confirm is a login; an identifier with no
  password under "forgot/recover" is a reset. So a `/login` page that actually serves a signup form
  is called correctly.
- **SPA caveat.** If the form is rendered in JS and absent from static HTML, detection says so and
  points you at a rendered fetch (`WebPivot pivot_extract --render`) — "no form in static HTML" is
  never reported as "no login".

## The engagement gate (read before you confirm)

The gate is enforced in code, not just documented — mirroring `BinaryPivot`'s ANY.RUN
`submission_policy`:

- **`en_engage.engage()` refuses unless `confirm=True`** and returns the preflight briefing instead.
  `confirm` and synthetic-only are checked in the **function signature**, so editing
  `references/engage.json` can only make the policy *stricter*, never disable it.
- **A second lock at the harness:** `engage_submit` is in the audit gate's `approval_required` list,
  keyed to env `INTEL_ENGAGE_CONFIRM=1`. An agent loop cannot set that for itself — a human does.
- **Synthetic identity only** — the persona's `kind` must start with `synthetic` (i.e. come from
  `en_persona.py`); a real-PII persona is refused.
- **Non-attributable egress** — no `--proxy` and no `--allow-direct-egress` → refused. A signup from
  your own IP is a self-identifying beacon.
- **Never solves/evades a CAPTCHA or OTP** — if detection flagged one, engagement **stops** at it and
  hands back to the human. A UA swap is not a challenge bypass.
- **Everything is evidence.** The persona, the screenshots, the authenticated DOM and one line per
  engagement (`cases/<case>/engage/interactions.jsonl`) are written under the case. What the account
  reveals is sensitive case material — handle it like a stealer log.

**Try these first — they need no account** (`engagement_policy.try_first`): read the surface with
`en_forms`; search the leak corpus / stealer logs for existing panel credentials (`WebPivot` IntelX
— a recovered login answers "what's inside" without touching the box); check urlscan/Wayback for an
archived authenticated view. Reach for a fresh signup last: it is the most attributable option.

## After you're in — feed it back

The point of getting inside is the identity-bearing material the public page hid. Re-read the
captured authenticated DOM with `en_forms` / `WebPivot` and push the new pivots back into the case:
deposit **wallet** addresses, the **backend/API** host, the **referral tree**, **support handles**.
Then judge them in `IntelAnalysis` under the same rails — a members-area artifact is still base-rate
checked, still same-kit-vs-same-operator, before it names anyone.

## Authorization

Engagement is a deliberate interaction with live hostile infrastructure. Do it only when authorized
for the investigation, from egress that is not attributable to you or the client, with a synthetic
identity you will burn at case close. This skill will not create an account without your explicit,
per-engagement yes.
