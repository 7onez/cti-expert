# WebPivot — Authorization & Ethics

This skill is for **authorized** OSINT and cybercrime investigation: threat
intelligence, anti-fraud/anti-scam work, phishing takedown, brand protection,
due diligence, and defensive security research.

## Before you fetch a live target

1. **Scope & authorization.** You must have a legitimate basis: your own assets,
   an engagement with written authorization, published abuse/threat-intel work, or
   investigation of infrastructure targeting you or your constituents. When unsure, stop and confirm.
2. **Attribution risk.** `pivot_extract.py` fetches the target **directly** — the target
   sees your IP and User-Agent. For adversarial infrastructure, either:
   - use non-attributable egress (research VPS / VPN), **or**
   - stay passive: pull the DOM from **urlscan.io**, **Wayback**, or a prior scan and
     feed the saved HTML to the harness (`pivot_extract.py page.html`). Passive is the default for hostile targets.
3. **Only passive OSINT.** This skill reads publicly served content and public
   reverse-lookup indexes. It does **not** and must not be used for intrusion,
   credential access, exploitation, DoS, or evading access controls.
4. **Minimize.** Collect only what the investigation needs. Personal data
   (emails, phones, handles) is incidental to infrastructure pivoting — handle it
   under your data-protection obligations, retain minimally, don't redistribute.

## What this skill will not do

- No active scanning, fuzzing, or exploitation (that's the `Security` skill's
  authorized-pentest scope, not this one).
- No deanonymizing or harassing individuals; infrastructure/operator clustering
  is the goal, not doxxing.
- No bypassing paywalls, logins, CAPTCHAs, or rate limits to reach content.

## Reporting

Every asserted link must be **reproducible**: record the artifact value and the exact
query/service used, and grade confidence honestly (a single shared generic artifact is
a *lead*, not attribution). Distinguish "same kit" (reused code/template) from
"same operator" (shared private IDs/infra) — they are different claims.
