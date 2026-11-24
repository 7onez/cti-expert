# Fiat Payment Rails — bank accounts as CTI selectors

Crypto wallets are already first-class selectors in this skill (`/crypto-balance`, wallet
extraction in `pivot_extract.py`). **Most scam victims never touch crypto** — they make a bank
transfer. This technique treats the receiving account with the same rigour as a wallet:
validate it, decompose it, attribute it, and export it as an indicator.

Driver: [`scripts/iban_analyze.py`](../scripts/iban_analyze.py) — offline, zero-dependency,
ISO 13616 + ISO 7064.

---

## 1. Why a bank account is a strong selector

| Property | Consequence |
|---|---|
| **Checksum-verifiable** | An IBAN either passes mod-97 or it does not. You can prove a "bank account" in a phishing page is fabricated without contacting anyone. |
| **Geographically bound** | The first two chars are the issuing jurisdiction — often contradicting the site's claimed country. |
| **Institution-bound** | The bank code identifies the receiving institution → the correct abuse/legal channel. |
| **Hard to rotate** | Opening a mule account costs far more than registering a domain. Accounts get reused across campaigns far longer than infrastructure. |
| **Actionable** | Unlike a self-custodied wallet, a bank account has a supervised operator who can freeze it. (Custodial exchange / hosted-wallet addresses also have a service controller — see `blockchain-investigation.md` §6 ladder R4.) This is the selector that actually stops losses. |

---

## 2. `/iban` — validate and decompose

```bash
S="$SKILL_DIR/scripts"
uv run "$S/iban_analyze.py" "GB29 NWBK 6016 1331 9268 19"
uv run "$S/iban_analyze.py" <iban> --expect-country VN      # flag jurisdiction mismatch
uv run "$S/iban_analyze.py" --batch ibans.txt --json -o iban.json
uv run "$S/iban_analyze.py" <iban> --bank-db banks.csv      # country,bank_code,bank_name
```

Output per account: verdict, country, check digits, length check, mod-97 result, BBAN split
(bank / branch / account / national check digits), bank code, and risk signals.

### Verdict semantics

| Verdict | Meaning | Analyst action |
|---|---|---|
| `VALID` | Structure, length and mod-97 all pass | Treat as a real account; proceed to attribution |
| `SUSPECT` | Checksum passes, country length does not | Likely truncated in transcription — recover the full string before acting |
| `INVALID` | mod-97 failed | **Fabricated, mistyped or OCR-damaged.** A fake "bank account" on a payment page is itself a finding |
| `NOT AN IBAN` | Fails the ISO shape | Non-IBAN rail — see §4 |

**Do not report `INVALID` as "the scammer's account".** It is evidence of a *decorative* payment
detail — common on fake-invoice and advance-fee pages that never intend to receive a transfer,
and a meaningful behavioural signal in its own right.

### Bank-name resolution — deliberately not bundled

National bank-code registries are large, country-specific and variously licensed, so this tool
**does not ship an invented bank table**. It prints the authoritative lookup route per country
(Bundesbank BLZ, Pay.UK sort codes, Banque de France CIB, NBU МФО …) and accepts a
user-supplied CSV via `--bank-db`. For many countries the IBAN bank code *is* the BIC prefix
(`NL…ABNA` → ABNANL2A), which resolves with a plain BIC lookup.

---

## 3. Risk signals

`iban_analyze.py` raises these automatically; treat each as a lead to verify, never a verdict.

| Signal | Why it matters |
|---|---|
| **Jurisdiction mismatch** (`--expect-country`) | A "Vietnamese company" collecting to a Lithuanian or Cypriot IBAN is the classic beneficiary-abroad mule pattern |
| **Elevated-risk jurisdiction** | FATF-listed or offshore financial centres — grounds for enhanced checks, not an accusation |
| **Checksum passes, length wrong** | Transcription truncation, or a deliberately malformed number |
| **Same account across unrelated brands** | Strongest same-operator link in this technique — see §5 |
| **EMI / neobank bank code** | Wise, Revolut, Paysera, Bunq, Zen, Payhound etc. dominate mule usage: fast onboarding, weaker KYC. Note the institution *type*, not just the name |

---

## 4. Non-IBAN rails (Vietnam and SEA)

**Vietnam is not an IBAN country** — and neither are most of the region's rails. Local formats
carry no checksum, so validation is structural and attribution comes from the bank code.

| Rail | Selector shape | Attribution route |
|---|---|---|
| **VN bank transfer** | 6–19 digit account no. + bank name/short code (VCB, TCB, MB, ACB, BIDV, VPB…) | NAPAS member list; the bank's own branch directory |
| **VN VietQR / QR code** | EMVCo TLV payload embedding the NAPAS **BIN** (6 digits) + account no. | Decode the QR payload, read tag 38 → BIN → issuing bank. A QR on a scam page is a *parseable* selector, not an opaque image |
| **Card acceptance** | first 6–8 digits (BIN/IIN) | BIN → issuer + card brand + country |
| **e-wallets** | MoMo / ZaloPay / ViettelPay handle, usually a phone number | Pivots straight into `/phone` |
| **SWIFT/BIC** | `AAAABBCCDDD` — 4 bank + 2 country + 2 location + 3 optional branch | Bank + country directly from the code; positions 5–6 are the ISO country |

**BIC sanity rule:** characters 5–6 are an ISO-3166 country code. A BIC whose country segment
disagrees with the stated bank country is malformed or invented.

VietQR payloads decode with any EMVCo TLV parser — the account number and BIN are in plain
text inside the string, so a screenshot of a QR yields a hard selector once decoded.

### The collector does this automatically

Every QR payload `pivot_extract` decodes is offered to the EMVCo parser
(`intel_engine/WebPivot/tools/wp_emvqr.py`, or `python3 wp_emvqr.py '<payload>'` by hand):

- **Structure:** 2-digit tag, 2-digit length, value; merchant-account templates (26–51) nest the
  same structure. VietQR/NAPAS is template 38 with GUID `A000000727`; inside it, sub-tag 01 is a
  nested template whose 00 is the acquirer **BIN** and whose 01 is the **account number**.
- **Checksum:** tag 63 is a CRC-16/CCITT-FALSE over the payload up to and including `6304`. A
  payload whose CRC fails is reported (`crc_ok: false`) and **never** becomes a selector — a
  damaged decode would otherwise mint a stranger's account number.
- **Output:** `artifacts.payment_accounts` = `[{rail, bank_id, bank_name, account, country,
  source}]` for CRC-valid payloads on a listed rail. The merchant (account-holder) name stays in
  the raw `artifacts.emv_qr` record only — never in the account list, a selector or a KB key.
- **Rails and banks are data:** `WebPivot/references/payment_rails.json` maps the GUID to the rail
  and where the BIN/account sit, and BIN → bank name. The bank map ships **empty** — no BIN list
  has been verified for it — so `bank_name` stays null until an analyst adds BINs from the
  scheme's own published member list. Never guess a BIN.

---

## 5. The account-reuse pivot

A reused receiving account is the fiat equivalent of a shared GA ID.

```
IBAN / account no.
   ├─▶ source search  ("<iban>" on PublicWWW, urlscan content, /dork-sweep)  ─▶ sibling sites
   ├─▶ Wayback harvest  (wayback_harvest.py --indicators)                    ─▶ historical pages
   ├─▶ scam-report corpora  (Chongluadao, local police/consumer bulletins)   ─▶ prior reports
   └─▶ bank code  ─▶ issuing institution  ─▶ abuse/legal channel
```

Search the account **with and without formatting spaces** — pages render it both ways, and
search engines index the literal string.

Confidence: an exact account match across two properties is a **high-value lead**, comparable in
investigative weight to a shared registrant email — but it is **not** an owner link. Mule
accounts are rented and resold across crews, so the engine stores a bank account at the **kit**
rung (`rungs.json` `bank_account`): two hosts sharing one account stay in different clusters
until an independent owner-rung artifact (registrant contact, analytics id, exact certificate)
joins them. Same *bank* only is worthless; do not cluster on it.

---

## 6. Case integration

- **Indicator category:** `financial` / type `iban`, `bank-account`, `bic` — flows into the
  auto-saved IOC bundle. See [`ioc-export.md`](ioc-export.md).
- **Orchestrator:** `iban` is a typed identifier with its own edges (validate → issuing bank;
  account-string reuse → domains/emails/persons). See
  [`engine/pivot-orchestration.md`](../engine/pivot-orchestration.md).
- **Typed selector:** `bank_account` (`intel_engine/tools/selector_types.py`). KB key
  `bank:<country>:<bank-id>:<account>` (VietQR: `bank:vn:<BIN>:<account>`; the account keeps its
  letters and digits, only spacing and separators are dropped), and IBANs as `bank:<cc>:iban:<IBAN>`
  — validated by `scripts/iban_analyze.py`'s own check, never a second copy, and only when the
  country's IBAN length is known and matches; a domain is never read as an IBAN. Ingest writes it
  as kit-rung **facts** (`payment_account` on the domain; `kind`, `seen_on`, `rail` on the key) —
  never an edge.
- **Across cases:** `which_cases bank:vn:<BIN>:<account>` (`tools/case_index.py`; any spacing,
  or a bare IBAN) lists every case whose collected pages carried the account.
- **Role:** an account found on a scam page is an **actor** selector; one found in a victim
  statement is a **victim** selector. Set `subjects[].role` so the report separates them.
- **Exposure scoring:** a validated receiving account on a confirmed scam property is a
  monetisation finding — weight **HIGH**, or **CRITICAL** with corroborated victim loss.

### Findings this technique produces

| Finding | Type | Weight | Trust |
|---|---|---|---|
| Validated receiving IBAN `<masked>` at `<bank>` (`<CC>`) | `infrastructure` | HIGH | 5 (checksum is deterministic) |
| Same account on N unrelated brand properties | `behavioral` | HIGH | 4 |
| Payment page displays a checksum-**invalid** IBAN | `behavioral` | MEDIUM | 5 |
| Beneficiary jurisdiction contradicts claimed operating country | `behavioral` | MEDIUM | 4 |
| Receiving institution is an EMI with expedited onboarding | `infrastructure` | MEDIUM | 3 |

---

## 7. Handling and ethics

Account numbers are **financial PII belonging to real people** — including victims, and
including mule-account holders who are frequently coerced or trafficked.

- Mask in narrative output: `GB29 NWBK **** **** **68 19`. Keep the full value in the IOC
  bundle and structured data only.
- Never attempt a transaction, balance check, or account-existence probe against a live
  account. Validation here is **arithmetic on a string** — nothing is contacted.
- Publish full account numbers only through the appropriate channel: the receiving bank's
  abuse/AML desk, a payment scheme, or law enforcement.
- Use [`/redact`](../scripts/redact.py) before sharing a report outside the handling
  organisation — `iban` is a redactor entity type.

---

## Cross-references

- [`scripts/iban_analyze.py`](../scripts/iban_analyze.py) — the validator/decomposer
- [`techniques/ioc-export.md`](ioc-export.md) — `financial` indicator category
- [`techniques/web-pivot.md`](web-pivot.md) — extracting payment details from a page
- [`handbook/pivot-artifacts.md`](../handbook/pivot-artifacts.md) — artifact confidence model
- [`scripts/redact.py`](../scripts/redact.py) — masking accounts before external sharing
