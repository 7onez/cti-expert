# Scam red-flag indicators — NRD, bulletproof hosting, money trail

Fast triage signals for a *suspected* scam, computed by `tools/kb/risk_signals.py` from data
already collected (WHOIS + on-page artifacts). None is proof alone — they raise or lower the prior
and tell you where to dig. The tunable data lives in `IntelAnalysis/references/risk_indicators.json`.

```bash
python3 tools/kb/risk_signals.py --case mycase          # score every host in a case
python3 tools/kb/risk_signals.py --file cases/x/raw/site.example.json --json
# also printed automatically inside `python3 tools/intel.py open <case> …`
```

## 1. NRD — newly-registered domain
Scam infrastructure is overwhelmingly young: registered, used for a campaign, burned. Age comes
from WHOIS `created`. Tiers (edit in the JSON): **critical < 30 d, high < 90 d, watch < 180 d.**
- A young domain wearing an established brand ("since 2009" on a 3-week-old domain) is a classic tell.
- NRD + shared kit across a set = **one batch, one operator** (same class as sequential GA/UA numbers).
- Aged ≠ clean: operators buy expired aged domains to dodge NRD filters — check WHOIS *history* for a
  registrant change / drop-catch gap, not just the creation date.

## 2. BPH — bulletproof / abuse-tolerant hosting
Hosting/registrars that ignore abuse complaints. A match is a **lead**, never attribution.
`risk_signals.py` flags on the data we capture: **registrar**, **nameserver**, and **third-party
host** substring-matched against the tunable lists in the JSON (`provider_substrings`,
`abuse_tolerant_registrars`, `offshore_privacy_ns`).
- Presence of an abuse-tolerant registrar (e.g. cheap-bulk registrars) + NRD + a money-ask raises the
  score; alone it's weak (legit sites use them too).
- **Gap — ASN classification not wired.** True BPH is best seen at the ASN/netblock level; we don't
  capture ASN yet. When you have it, add the ASN to `bph.asns` and match origin IP → ASN. Until then,
  provider/registrar/NS substrings are the proxy. Cross-check the **origin** IP (not the CDN edge —
  `WebPivot/tools/cdn_ranges.py`) before calling hosting bulletproof.
- Keep the JSON current: BPH providers rename and move constantly. Verify an entry is *still* BPH
  before asserting it in a client-facing product.

## 3. Money trail — the crucial category
How the operator gets **paid** and gets **contacted** to close the fraud — the highest-value
indicators for victim-loss cases, LE referral, and takedown. `risk_signals.py` surfaces:
- **Crypto wallets** (`btc / eth / usdt / tron …`). A **reused wallet across sites is
  attribution-grade** — the same payee. Wallets now become KB edges (`uses_wallet`), so
  `hypothesize.py` and `--shared` cluster on them. Pivot the address on Chainabuse / a chain explorer.
  **Validated at the door:** addresses are checksum-verified (base58check / bech32) before they enter
  the KB — an md5/asset hash that merely *looks* like a legacy BTC address is rejected, so the money
  trail isn't polluted by false positives. `tools/kb/clean_kb.py` sweeps any legacy bad wallets.
- **Off-platform contact handles** (Telegram / WhatsApp / Zalo / Messenger / WeChat). A **wallet + a
  contact handle = the payment funnel** (`payment_funnel` flag) — escalate.
- **Registrant + on-page phone / email.** Reverse-lookup the phone (messenger-app pivot), reverse-WHOIS
  the email. On-page emails now become KB edges (`shows_email`).
- **Trace priority** (also in the JSON): reused wallet → contact phone → contact email → payment
  processor / merchant IDs → IBAN/SWIFT/bank handles in forms or chat.

> A young (NRD), unbranded site with a crypto wallet and a Telegram handle is the archetypal
> investment/pig-butchering funnel. That combination is `escalate` in the tool output.
