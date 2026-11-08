# Stealer-Log Analysis — Attribution, Actor Profiling & IOC Extraction

Triage a folder of infostealer logs (RedLine, Vidar, StealC, Lumma, Raccoon,
META, traffer-branded packs, …) to **attribute the operator, profile threat
actors, and extract IOCs**. Built for the recurring CTI question: *is this log
from a victim, or from the criminal's own machine?* — because an actor's own
infected box leaks their panels, aliases, infrastructure, and real identity.

> **Scope & ethics.** Stealer logs contain third-party victim PII. Use this only
> for authorized CTI/attribution, anti-fraud investigation, and victim
> notification — never to abuse recovered credentials. Raw artifacts are shown
> deliberately (they are the profiling evidence); handle and store output per your
> data-protection obligations.

---

## 1. Run it

```bash
# Cross-platform, zero-dependency (stdlib only) — uv run is instant on any OS.
uv run "$SKILL_DIR/scripts/stealer_log_parse.py" "<log-folder>" [out-dir]
# No-uv fallback: py (Windows) / python3 (Unix) "$SKILL_DIR/scripts/stealer_log_parse.py" "<log-folder>"
```

It auto-detects whether the folder holds one log or many per-host sub-folders,
handles mixed families and encodings (UTF-8/16, cp1252, latin-1), and writes
`STEALER-ANALYSIS-<date>.md` (human report, raw evidence shown) +
`STEALER-ANALYSIS-<date>.json` (structured, for pivoting).

---

## 2. Family fingerprinting

Identify the stealer from the **banner** (in `copyright.txt` / `system_info.txt` /
`information.txt` / `UserInformation.txt` / `System.txt` / `Environment.txt`) or,
when the banner is stripped, from the **file layout**:

| Family | Signature |
|--------|-----------|
| **StealC** | ASCII `stealc stealer` banner, "powerful native stealer", seller `t.me/…`; `cookie_list.txt`, `copyright.txt`, `soft/` |
| **Vidar** | `VIDAR STEALER` banner or `reg.vidars.su`; layout `information.txt` + `MachineID`/`GUID`/`Work Dir` + `Soft/Telegram/tdata` + `domain detect.txt` (banner often omitted in newer builds) |
| **RedLine** | boxed `REDLINE` banner, `t.me/redline_market_bot`, `Build ID: @<tag>`; `UserInformation.txt`, `Application: …_[Chrome]_…` |
| **RedLine/META reseller** | `Build`/`LID`/`Configuration:` block + reseller tag (e.g. `@BradMax_logs`) |
| **Lumma / JSON-panel** | `log_info.json` + `pc_info.json`, random 5-char filenames |
| **Traffer-branded** | team banner with `CLÓUD CHANNEL`/`SUPPORT` handles (e.g. `@forza_traffic`, `@ez_sources`), `Browser/Fingerprint`, `Wallets/`, `Notes/` |

---

## 3. What each artifact yields for profiling

| Artifact | Attribution / profiling value |
|----------|-------------------------------|
| **Banner / info file** | Stealer family, version, **build ID**, **seller/traffer Telegram & Jabber**, panel/C2/forum URLs |
| **system / pc info** | Host IOCs: HWID, MachineID/GUID, victim IP + country, OS, **dropper path** (e.g. `SysWOW32\install.exe`, `RegAsm.exe`), **random-named process** (the malware) |
| **passwords** | The actor's **own accounts**; **admin / agent / back-office logins** = their scam infrastructure (high-value IOC domains); credential-reuse patterns for pivoting |
| **autofills** | **Real identity & aliases** — names, emails, phones, addresses; fraud-tooling searches (KTP/`cek ktp`, finance, OTP) reveal the actor's operation |
| **history** | **Behavioral profile** — panels, underground forums, crypto exchanges, scam sites the subject actually uses |
| **cookies** | Active **session domains** — what services the machine is logged into |
| **wallets / Discord / Telegram tdata** | Cashout & comms tradecraft (presence flagged; pivot to blockchain/social techniques) |

**Admin / sensitive-endpoint detection.** Every recovered and browsed URL is run
through the admin-endpoint classifier (subdomain-prefix + path + CJK-keyword aware
— full vocabulary in [`handbook/admin-endpoint-indicators.md`](../handbook/admin-endpoint-indicators.md)).
Hits — `admin.`/`adm…`, `kef.`/`ador.` (客服/admin backends), `panel.`, `/admin`,
scam-TLD logins, and multi-agent domains — are tagged with their indicator (e.g.
`subdomain:kef`), shown per-log, and rolled up across the case as actor-infrastructure IOCs.

---

## 4. Victim-vs-operator triage

The analyzer scores each log for operator signals and labels it **OPERATOR /
fraud-infrastructure**, **MULE / mixed-use**, or **likely VICTIM**. Signals:

- underground forum / Telegram / Jabber logins (exploit.in, xss.is, zelenka, t.me)
- **admin/agent/back-office panel logins**, scam TLDs (`.xyz .top .vip .online …`),
  and the **multi-agent pattern** (≥3 distinct accounts on one non-mainstream domain)
- fraud-ID tooling (KTP/`cek ktp`/`kartu keluarga`/finance/OTP)
- disposable-mail accounts, many distinct identities, crypto-exchange logins

Operator-labelled logs are where the "juicy attribution" lives — profile those first.

---

## 5. Cross-log actor correlation

The analyzer clusters logs that share a **dropper filename, HWID, or autofill
email** → likely the **same operator** even across different stealer families.
(Example: two logs linked by dropper `bn5kgjsa2sf5n.exe` + 20 shared emails = one
actor.) Use clusters to merge subjects in the case workspace.

---

## 6. Pivot the output back into the skill

- Scam/admin domains & panel URLs → `/threat-check`, `/scam-check`, `/subdomain`, `/whois`
- Seller/traffer Telegram & Jabber, actor emails/aliases → `/branch`, `/username`, `/email-deep`, `/case`
- Dropper paths / random processes / hashes → `/threat-check`, `/report ioc` (STIX)
- Register operator clusters as subjects; feed IPs/domains into `/exposure`, `/timeline`, `/report`
- Victim's corporate domain → corroborate at org scale: HudsonRock `search-by-domain`/`urls-by-domain` (per-URL) + Lunar domain-exposure (`uv run "$SKILL_DIR/scripts/lunar_domain_exposure.py" <domain>`) for 12-mo trend, matching malware families/OS, and exposed VPN/SSO services. EXPOSURE evidence — corroboration, not operator attribution.

---

## 7. Manual fallback (no script)

Read the banner/info file for family + contacts; `grep`/read `passwords*` for
`admin.`/`backend`/`/login` panel URLs; scan `autofill*` for emails/phones/names
and `cek ktp`/finance keywords; extract `https?://` from `history*`; list cookie
domains. Then apply the §4 triage and §5 correlation by hand.


## 8. Corporate SaaS and machine-role additions

```bash
uv run "$SKILL_DIR/scripts/stealer_log_parse.py" /path/to/logs /path/to/output --subject-emails operator@example.com,subject@example.net
```

`--subject-emails` accepts comma/space-separated emails and flags exact, case-insensitive
username matches. It does not infer aliases, ownership or successful authentication.

## Corporate SaaS / administrative credential tagging

Every parsed credential gains `saas_tags`, `subject_login`, and `rung: lead`. The reference
`scripts/references/stealer_triage.json`
contains host suffixes and URL path patterns for:

- `sso_workspace`: Lark, Google Workspace, M365 and Okta;
- `crm_helpdesk`: CRM and support systems;
- `ecommerce_backend`: seller / merchant backends;
- `cms_admin`: WordPress and other CMS administration;
- `banking_payment`: banking and payment portals;
- `marketing_seo`: advertising, marketing and SEO tools;
- `logistics`: shipping and logistics systems.

Host matching is boundary-aware (an unrelated suffix does not match). Paths are hints, not
proof a site actually runs that product. The JSON includes per-log `saas_summary` and
`subject_logins`; the report shows categories and the subject-login flag per credential.

## Machine-role triage

Each per-log `machine_triage` block contains `classification`, `basis`, observed `counts`,
reference `thresholds`, `rung: lead`, and an attribution caveat. Rules run in this order:

1. `aggregator`: at least 3 dump/combolist-named files; OR at least 1,000 credentials,
   100 distinct email usernames/autofill emails and 50 URL domains; OR at least 20 wallet
   directories alongside 100 distinct emails.
2. `vendor_or_shared`: absent the aggregation rule, at least 30 credentials, 10 email
   identities and 10 administrative/SaaS domains. Agency/client access or a shared endpoint is
   a plausible explanation, not a finding about the machine's owner.
3. `victim_endpoint`: neither threshold reached. This is the default bucket, not proof of
   single-person use or absence of compromise elsewhere.

All numbers and filename patterns live in `scripts/references/stealer_triage.json`. Wallet
folders count storage locations, not people or on-chain owners. Many email/domain strings
are diversity proxies, not verified unrelated victims. A combolist filename can be misleading:
confirm file contents and provenance before treating a role hypothesis as established.

