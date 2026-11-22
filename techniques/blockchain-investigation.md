# Blockchain Investigation Module

> **Module ID:** BLKCHAIN-001
> **Version:** 1.1.0
> **Phase:** 5 - Enhancement Modules
> **Classification:** Cryptocurrency & Blockchain Transaction Intelligence

---

## 1. Overview

Blockchain and cryptocurrency investigation for OSINT. Covers transaction tracing, wallet analysis, scam address detection, exchange identification (off-ramp), cross-chain investigation, and visual flow mapping. All primary tools are free with no authentication required for basic use.

**Key use cases:** Ransomware payment tracking, fraud victim recovery support, darknet market wallet attribution, identifying exchange cash-out addresses, linking on-chain activity to real-world entities.

---

## 2. Tool Inventory

### 2.0 Automated — `crypto_balance.py` (keyless balance/flow)

For a wallet discovered on a page or in a case, get on-chain intel in one call — current
balance, lifetime received/sent, tx count, valued at spot (CoinGecko) — without any key.

```bash
WP="$SKILL_DIR/scripts/webpivot"
uv run "$WP/crypto_balance.py" bc1qexampleseed01 --pretty   # auto-detects chain (placeholder address)
uv run "$WP/crypto_balance.py" 0xADDR… --coin eth
```

Keyless public explorers per chain (BTC→blockstream, LTC→litecoinspace, ETH→Blockscout,
TRON→Tronscan, ADA→Koios, DOT→Subscan); `BLOCKCHAIR_API_KEY` unlocks full received/sent flows
on more chains. Never raises — a flaky explorer degrades to `supported:false` with an `error`.
Balance + first/last activity is a fast triage signal for a scam/ransom address before deeper
clustering below. See also [`techniques/web-pivot.md`](web-pivot.md) §9.

### 2.1 Blockchair — Multi-Chain Explorer
**URL:** https://blockchair.com/

Supports Bitcoin, Ethereum, Litecoin, Bitcoin Cash, Ripple, Stellar, Monero, Dogecoin, and 10+ others. Privacy-focused explorer with SQL-like query interface.

- **Usage:** Search by address, transaction hash, or block number; use advanced search for cross-chain queries
- **Strength:** Single interface across 15+ chains; supports complex data queries
- **Limitation:** API rate limits on free tier; Monero tracing is fundamentally limited by protocol privacy

### 2.2 Etherscan — Ethereum Explorer
**URL:** https://etherscan.io/

The canonical Ethereum blockchain explorer. Shows transactions, ERC-20/ERC-721 token transfers, internal transactions, contract source code, and gas usage.

- **Usage:** Paste ETH address or transaction hash → full history, token holdings, contract interactions
- **Strength:** Labeled addresses (exchanges, protocols, known scammers); token approval tracking
- **Limitation:** Ethereum only; requires API key for programmatic access beyond basic queries

### 2.3 WalletExplorer — Bitcoin Wallet Clustering
**URL:** https://www.walletexplorer.com/

Groups Bitcoin addresses by common ownership using change address heuristics. Identifies if an address belongs to a known exchange, service, or wallet cluster.

- **Usage:** Paste BTC address → see full wallet cluster, labeled entity name if known
- **Strength:** Identifies exchange deposit addresses and mixing services by cluster label
- **Limitation:** Heuristics can be defeated by CoinJoin and careful UTXO management

### 2.4 OXT.me — Bitcoin Visual Analysis
**URL:** https://oxt.me/

Bitcoin blockchain visualization and analysis platform. Provides transaction flow graphs, wallet clustering, and path-finding between addresses.

- **Usage:** Paste BTC address → interactive transaction flow graph showing funds in/out
- **Strength:** Visual representation makes fund flow immediately readable; path-finding between two addresses
- **Limitation:** Bitcoin only; graph rendering slow for high-volume addresses

### 2.5 Chainabuse — Scam Address Database
**URL:** https://www.chainabuse.com/

Community-driven database of cryptocurrency addresses flagged for fraud, scams, ransomware, and theft. Multi-chain. Submit reports and search existing ones.

- **Usage:** Search any address → see scam reports, category (phishing/ransomware/rug pull), victim count
- **Strength:** First-stop check before deeper analysis; reveals known bad actors instantly
- **Limitation:** Only covers reported addresses; new or unreported scam addresses return no results

### 2.6 Breadcrumbs — Multi-Chain Investigation Platform
**URL:** https://www.breadcrumbs.app/

Multi-chain visual investigation tool with entity labels and transaction graph mapping. Free tier supports basic tracing.

- **Usage:** Paste address → visual graph of transaction flows with labeled entities (exchanges, DeFi protocols)
- **Strength:** Cross-chain visibility; entity labeling simplifies off-ramp identification
- **Limitation:** Free tier limits graph depth; advanced features require paid subscription

---

## 3. Chain-Specific Explorers

| Chain | Explorer | URL |
|-------|---------|-----|
| Ethereum | Etherscan | https://etherscan.io/ |
| Bitcoin | Blockchain.com | https://www.blockchain.com/explorer |
| Solana | Solscan | https://solscan.io/ |
| BNB Chain | BSCScan | https://bscscan.com/ |
| Polygon | Polygonscan | https://polygonscan.com/ |
| Avalanche | Snowtrace | https://snowtrace.io/ |
| Tron | Tronscan | https://tronscan.org/ |
| Multi-chain | Blockchair | https://blockchair.com/ |
| Multi-chain EVM | Breadcrumbs | https://www.breadcrumbs.app/ |

---

## 4. Investigation Workflow

```
Step 1: Identify blockchain from address format
  └─ BTC: starts with 1 (P2PKH), 3 (P2SH), or bc1 (Bech32/Taproot)
  └─ ETH/EVM: starts with 0x, 42 hex characters total
  └─ SOL: base58 encoded, 32–44 characters
  └─ XRP: starts with r, ~34 alphanumeric characters
  └─ If unsure: paste into Blockchair — it auto-detects chain

Step 2: Scam database check (Chainabuse)
  └─ Search address before spending time on deeper analysis
  └─ If flagged → document report count, category, and first report date
  └─ Note: absence of report does NOT clear the address

Step 3: Transaction history exploration (Blockchair or chain-specific explorer)
  └─ Record: first transaction date, total received, total sent, current balance
  └─ Identify funding sources (first inbound transactions)
  └─ Identify destinations (outbound transactions, especially large ones)
  └─ Flag exchange deposit addresses — these represent fiat off-ramps

Step 4: Wallet clustering (WalletExplorer for BTC; Etherscan labels for ETH)
  └─ Find related addresses — and record WHICH heuristic linked each one (H1 / H2, §6 Clustering)
  └─ Note any labeled clusters (Binance, Coinbase, known mixers) WITH labeller + retrieval date
  └─ Calculate total funds across full cluster, not just target address
  └─ Account-model chains (ETH/TRX/EVM) have no H1/H2; Etherscan name tags are labels, not clusters
  └─ Grade every claim on the Evidence Ladder (§6) before it enters the INTSUM

Step 5: Visual flow mapping (OXT.me for BTC; Breadcrumbs for multi-chain)
  └─ Generate transaction flow graph
  └─ Identify patterns: peel chains, consolidation, mixing service usage
  └─ Use path-finding between suspect address and known exchange address

Step 6: Cross-reference with external OSINT
  └─ Google the address in quotes — check forum posts, Pastebin, GitHub issues
  └─ Search address in ransomware payment trackers (ransomwhe.re)
  └─ Check if address appears in darknet market references
  └─ Link to domain/email if found in phishing kit source or scam page HTML
```

---

## 5. CLI Commands & Expected Output

```bash
# Blockchair API — Bitcoin address summary (free, no key required)
curl -s "https://api.blockchair.com/bitcoin/dashboards/address/<BTC_ADDRESS>" \
  | jq '.data["<BTC_ADDRESS>"].address | {balance, received: .received, spent: .spent, transaction_count}'

# Expected output:
# {
#   "balance": 150000,
#   "received": 5000000,
#   "spent": 4850000,
#   "transaction_count": 47
# }
# Note: values in satoshis (divide by 100000000 for BTC)

# Blockchain.com API — BTC address details (free, no key)
curl -s "https://blockchain.info/rawaddr/<BTC_ADDRESS>?limit=5" \
  | jq '{balance: .final_balance, n_tx: .n_tx, total_received: .total_received}'

# Expected output:
# {
#   "balance": 150000,
#   "n_tx": 47,
#   "total_received": 5000000
# }

# Blockchair — Ethereum address summary
curl -s "https://api.blockchair.com/ethereum/dashboards/address/<ETH_ADDRESS>" \
  | jq '.data["<ETH_ADDRESS>"].address | {balance, transaction_count}'

# Blockchair — multi-chain address search (auto-detects chain)
curl -s "https://api.blockchair.com/search?q=<ADDRESS>" | jq '.data'

# Ransomware address lookup (ransomwhe.re — free, no key)
curl -s "https://api.ransomwhe.re/export" \
  | jq --arg addr "<BTC_ADDRESS>" '.result[] | select(.address == $addr)'

# Expected output if found:
# {
#   "address": "bc1qexampleransom01",
#   "family": "LockBit",
#   "reportedAt": "2023-11-20T14:33:00Z"
# }
```

---

## 6. Analysis & Interpretation Guidance

### Address Format Quick Reference

| Format | Chain | Example Prefix | Length |
|--------|-------|---------------|--------|
| P2PKH | Bitcoin | `1` | 26–34 chars |
| P2SH | Bitcoin | `3` | 34 chars |
| Bech32 | Bitcoin SegWit | `bc1q` | 42 chars |
| Taproot | Bitcoin | `bc1p` | 62 chars |
| EVM | Ethereum/BSC/Polygon | `0x` | 42 chars |
| Base58 | Solana | varies | 32–44 chars |
| Base58 | Ripple XRP | `r` | ~34 chars |

### Transaction Pattern Recognition

| Pattern | Description | Significance |
|---------|-------------|-------------|
| Peel chain | Long chain of single-output transactions, each peeling off a small amount | Layering; funds moving through intermediary wallets |
| Fan-out | One address sending to many addresses simultaneously | Distribution to victims (airdrop scam) or layering |
| Consolidation | Many addresses sending to one | Aggregating funds before exchange deposit |
| Round numbers | Transactions in exactly 1.0 BTC, 10 ETH, etc. | Often OTC trades or structured payments |
| Mixer usage | Funds enter/exit CoinJoin or Tornado Cash | Deliberate obfuscation; note entry and exit addresses |
| Exchange deposit | Outbound tx to known exchange cluster | Off-ramp attempt; document exchange name and deposit address |

### Exchange Identification

Deposits to centralized exchanges (Binance, Coinbase, Kraken, etc.) represent the most actionable off-ramp intelligence. Identified exchange addresses can support legal requests for KYC data.

- WalletExplorer and Breadcrumbs label known exchange deposit addresses
- Exchange addresses typically receive from many senders (aggregation pattern)
- Confirm via Etherscan "Name Tag" on ETH addresses

### Mixer & Privacy Tool Detection

| Tool | Chain | Detection |
|------|-------|-----------|
| CoinJoin | BTC | Many equal-value inputs and outputs in one tx |
| Wasabi Wallet | BTC | Characteristic CoinJoin structure with 0.1 BTC outputs |
| Tornado Cash | ETH | Transactions to/from known Tornado Cash contract addresses |
| Monero | XMR | All transactions are private by protocol; tracing not feasible |
| Zcash shielded | ZEC | Transactions to/from shielded pool (z-addresses); entry/exit is a chain break — see Privacy Coins below |

### Evidence Ladder for On-Chain Claims

Every on-chain statement in a case climbs this ladder one rung at a time. A rung is reached only
with the evidence named for it; a higher rung never inherits from a lower one by default. State
the rung in the INTSUM line itself. The rungs synthesize P15's distinction between key
knowledge, address control and account ownership [P15 Meiklejohn et al., IMC 2013]; the
five-rung layout and wording are an (adaptation).

| Rung | Claim | Evidence required | Typical source | Does NOT establish |
|------|-------|-------------------|----------------|--------------------|
| **R1 Transfer observed** | Value V moved from A to B in tx T at block height H | Confirmed tx in a block, read from ≥1 explorer | `crypto_balance`, Esplora/Blockchair tx view | Who controls A or B |
| **R2 Address control** | Whoever spent from A held its signing key or custody at time T | A appears as an **input** (it has signed a spend) | tx inputs | Who that controller is; an address that only ever received has no R2 |
| **R3 Cluster** | A and C share a controller | A named heuristic (H1 or H2 below) with its tx IDs, breaker checks passed | your own walk, or a tool's cluster **with its method** | That the controller is a person; a service controls many customers' addresses |
| **R4 Service label** | Cluster K is operated by service S (exchange, processor, mixer) | Label + **who** labelled it, **how** (own interaction / vendor / self-claimed / community), **when** retrieved | WalletExplorer, Etherscan name tag, Breadcrumbs, vendor API | Which customer of S sent or received |
| **R5 Customer identity** | Natural/legal person P owns the account at S that sent/received | Off-chain: legal process to S, KYC disclosure, or a self-identification bound to the address by other evidence | law-enforcement return, court record | — (top rung) |

Rules:
- **Service control ≠ customer identity.** P15 explicitly treats a wallet service as the
  *controller* of every address it generates "even though the funds in these addresses are owned
  by a wide variety of distinct users" [P15 Meiklejohn et al., IMC 2013]. An exchange hot wallet,
  deposit address or payment-processor address is R4 about the service, never R5 about a customer.
- **Key knowledge ≠ control.** P15's physical-coin example shows a private key can be known to the
  minter, the buyer and the redeeming service at once [P15 Meiklejohn et al., IMC 2013]. R2 says
  "a key holder spent", not "the page operator spent".
- **An address printed on a scam page is R1-adjacent, not R2.** Merchants in P15's sample often
  received through a payment gateway rather than their own wallet [P15 Meiklejohn et al., IMC 2013];
  the address may be a processor or exchange deposit address. Treat page→address as a lead until
  the address has spent into a cluster you can grade (adaptation).
- **Abstain** with "insufficient — rung Rn not reached" when the next rung's evidence is missing.
  An unspent address stops at R1. A label without labeller/date stops at R3. No legal return →
  R5 is "not assessable from chain data", never "probably".
- Same infrastructure / same operator / named person stay separate: R3 supports *same
  controller* (which may be a service), R4 names a *service*, only R5 names a *person*.

### Clustering Heuristics (UTXO chains only)

These apply to UTXO chains (BTC, LTC, BCH, DOGE, DASH, Zcash **transparent** addresses), where a
transaction consumes whole previous outputs and returns the excess to a change output.

**H1 — multi-input heuristic.** P15: "If two (or more) addresses are inputs to the same
transaction, they are controlled by the same user" [P15 Meiklejohn et al., IMC 2013]. It rests on a
protocol property (each input needs its own signature) and is transitive across transactions. P16
uses the same rule as the "co-spending heuristic" and stresses it is void for CoinJoin
[P16 Huang et al., IEEE S&P 2018].
- *Inputs:* tx IDs where the address appears as an input; input address list per tx.
- *Steps:* (1) list every tx where the seed is an input; (2) collect co-inputs; (3) screen each tx
  for breakers; (4) recurse on accepted co-inputs; (5) log `addr ← H1 ← txid` for each edge.
- *Output:* R3 cluster with per-edge tx provenance.
- *Breakers:*
  - **CoinJoin** — inputs belong to several parties by design; many inputs and several equal-value
    outputs. Exclude the tx; P16 ran CoinJoin detection and still notes detection may miss some
    [P16 Huang et al., IEEE S&P 2018].
  - **PayJoin** (adaptation, not in P15–P17) — payee contributes an input to the payer's tx, so H1
    falsely merges sender and receiver and the tx looks ordinary. Treat a single H1 edge that is
    the *only* bridge between two otherwise separate clusters as a lead.
  - **Custodial/shared keys** — a wallet service or exchange spends many customers' coins together;
    H1 links to the service, not a customer (P15's controller definition).
  - **Exchange batching** (adaptation) — one service tx consolidating many deposit addresses is a
    correct H1 link *to the service*; it is never a link between the depositors.

**H2 — change-address heuristic.** P15 defines a *one-time change address* for tx T as an output pk
where (1) this is pk's first appearance, (2) T is not a coin generation, (3) no output is also an
input ("self-change"), and (4) pk is the **only** output meeting condition 1; H2 then links pk to
T's input controller [P15 Meiklejohn et al., IMC 2013]. P15 calls it an "idiom of use", not a
protocol property — "less robust in the face of changing (or adversarial) patterns".
- *Steps:* apply conditions 1–4; if more than one fresh output, label **nothing** (P15's rule);
  skip txs where an output was previously used as self-change or had already received once;
  re-check the candidate later — if it is reused as a receiving address, drop the link.
- *Breakers / false positives documented in P15:* change address reused within a short window;
  addresses first used as self-change then as separate change; wallets (P15 names My Wallet and
  Armory) letting users choose the change address; gambling payouts returning to the sending
  address. Even after refinements, a few false links collapsed P15's graph into a super-cluster
  holding several unrelated services [P15 Meiklejohn et al., IMC 2013].
- *Adaptation:* **address reuse**, **exchange batch payouts** (many fresh outputs → ambiguous, so
  H2 abstains), and **current wallet change behaviour** (e.g. software that varies change type or
  position) are not measured in P15; do not assume P15's era-specific idioms hold today.
- *Guard:* if a cluster suddenly contains two independently labelled services, treat it as a false
  link symptom and roll back to the last H1-only state (adaptation of P15's super-cluster finding).
- P15's false-positive rates after waiting periods were measured on its 2013 blockchain
  population; quote them only as "in P15's dataset", never as a current error rate.

**Peeling chains.** P15 followed theft proceeds hop by hop along H2 change links, recording the
non-change output ("the peel") at each hop until peels reached exchanges; the same pattern appears
in legitimate exchange withdrawals and pool payouts [P15 Meiklejohn et al., IMC 2013]. A peel chain
is therefore a *method for following value*, not evidence of criminality.

**Account-model chains (ETH, TRX, EVM L2s, BSC) — (adaptation).** H1 and H2 do **not** apply: a
transaction has one sending account, there are no multiple inputs and no change outputs, and the
balance stays in the same account. An account's history is already an address-level view. Links
between accounts rest on behavioural signals — one account funding gas for many, deposits that are
swept to the same forwarder, shared contract approvals, matching timing — each a **lead**, never an
R3 edge on its own. Contract-mediated flows (routers, bridges, multisigs, smart-contract wallets)
make `from` a contract, not a person. None of P15–P17 measured these chains.

### Ransomware Payment Tracing Procedure

Adapted from P16's end-to-end pipeline [P16 Huang et al., IEEE S&P 2018] to this skill's
`crypto_balance` triage. *Trigger:* a ransom note, leak-site payment page or victim report yields
a BTC (or other UTXO-chain) address. *Inputs:* seed addresses with provenance.

1. **Seeds.** P16 drew seed ransom addresses from real victims' public reports (ransom-note
   screenshots/text) and from "synthetic victims" — executing binaries in several sandboxes and on
   bare metal and extracting addresses, including by OCR of the note. Record per seed: source,
   family claim, and whether the family issues a unique address per victim or reuses one.
2. **Triage.** `crypto_balance.py <addr…>` for received/sent/tx count. **Unspent seed → stop at R1**:
   P16 could not cluster families whose ransom addresses never moved funds.
3. **Cluster expansion.** H1 co-spending, recursively, with CoinJoin excluded. P16 merged disjoint
   clusters only because the seeds were independently known to be the same family — log such a
   merge as "family-level merge (seed provenance)", not as a heuristic edge.
   Tx-level walk (keyless Esplora):
   ```bash
   curl -s "https://blockstream.info/api/address/<SEED>/txs" \
     | jq -r '.[] | select(any(.vin[]; .prevout.scriptpubkey_address=="<SEED>"))
              | [.txid, ([.vin[].prevout.scriptpubkey_address]|unique|join(",")), (.vout|length)] | @tsv'
   ```
4. **Inflow filtering.** An inflow is not a victim payment: P16 names other researchers' payments,
   undetected CoinJoin and ransomware-as-a-service affiliates. Keep inflows that match a known ransom
   amount or the family's observed graph pattern (e.g. victim address → single aggregation
   address); an "inflow from a labelled exchange" filter had poor recall in P16 because exchange
   labels were incomplete.
5. **Cash-out exits.** Outflows to an exchange, mixer or unknown cluster mark the *start* of a
   possible cash-out; P16 states it cannot guarantee if or when the operator converts to fiat.
   Record each exit at R4 with labeller and date; the exchange account holder stays R5.
6. **Estimate with stated limits.** Report revenue as a **lower bound** and list: seed count and
   origin, heuristics used, filters applied, label coverage, and P16's named blind spots — an
   operator switching to a fresh cluster after the known payments, families that never co-spend,
   and incomplete exchange labels.

*Not adopted:* P16's micropayments to synthetic victims' addresses. Paying an extortion address is
outside this skill's passive posture; use existing victim payments only (adaptation).
*Abstain* with "insufficient — no spend from seed" or "cluster unbounded (CoinJoin/super-cluster)".

### Privacy Coins: Shielded Pools (Zcash)

P17 studied Zcash, where t-addresses are Bitcoin-like and z-addresses live in the shielded pool;
tx types are t-to-t, t-to-z (shielding), z-to-z (private) and z-to-t (deshielding)
[P17 Kappos et al., USENIX Sec 2018].
- **Transparent side:** H1 applies to t-address inputs (P17's Heuristic 1). P17 also defined a
  change rule for shielding txs with one transparent output (its Heuristic 2) but, over safety
  concerns, left it out of its general analysis; known exception: a wallet developer-fee output.
- **Pool linkage heuristics (historical, population-specific):** founder withdrawals of an exact
  recurring value (P17's Heuristic 3), mining-pool payouts with over 100 t-address outputs that
  include a known pool address (Heuristic 4), and **round-trip transactions** — a unique value
  deposited then withdrawn within a few blocks (Heuristic 5, credited to Quesnelle). P17 states it
  cannot validate Heuristics 3–4 "short of asking" the founders or pool operators.
- **z-to-z reveals only fee, time and number of JoinSplits**; P17 could not tell few users making
  many transactions from many users making one.
- **Why it does not generalise.** These links came from specific actors' automated behaviour and
  low pool usage in P17's data (to January 2018). P17 notes its heuristics would have been far less
  effective had founders behaved less regularly, and that only all-shielded use (or much wider pool
  use) truly protects the anonymity set. They are not current guarantees or detectors.
  In P17's Shadow Brokers case study, amount-matching criteria produced candidates the authors
  explicitly called non-definitive, several of them false positives.
- *Procedure:* treat a pool entry/exit as a **chain break**. An exact-value-and-timing coincidence
  across the break is a lead below R3; record value, block gap and how many other txs share the
  value. *Abstain* when the value is not unique in your window or the gap spans other activity.
  `crypto_balance` returns `supported:false` for `zs1…` addresses; that is not an empty balance.
- Monero: no source in this module's set measures it; keep the protocol-level "not traceable"
  statement above and do not borrow P17's Zcash heuristics for it.

### Worked Example — Ladder Walk (synthetic)

CASE-0001. A scam page on `pay.example` shows `bc1qexampleseed01` (all addresses here are fake and
checksum-invalid by design). Victim report: 0.05 BTC paid in tx `example-tx-01`.

1. **R1.** `crypto_balance.py bc1qexampleseed01` → received 0.31 BTC, sent 0.31 BTC, 6 txs. The
   victim's tx is in a block. Claim: "0.05 BTC moved from victim to bc1qexampleseed01."
   Not yet claimed: that the page operator controls the address (it could be a processor).
2. **R2.** The address is an input in `example-tx-02`, so someone holding its key/custody spent it.
3. **R3.** `example-tx-02` inputs: `bc1qexampleseed01`, `bc1qexampleseed02`, `bc1qexampleagg01`;
   outputs: two addresses, unequal values. Breaker screen: 3 inputs / 2 outputs, no equal-value
   outputs → no CoinJoin indication; PayJoin not excludable, noted. H1 edges logged. H2: both
   outputs are first appearances → ambiguous → **no change label** (P15 rule).
4. **R4.** One output, `bc1qexampledep01`, sits in a cluster labelled "Exchange-X" by
   WalletExplorer, retrieved 2026-11-14, method unknown (third-party label).
5. **R5.** Not assessable from chain data. Output line:
   *"Funds paid to the address shown on pay.example (R1) were co-spent with two other addresses
   (R3, H1, example-tx-02) and 0.12 BTC reached a cluster labelled Exchange-X by WalletExplorer
   (R4, third-party, 2026-11-14). The Exchange-X account holder is unidentified; identification
   requires legal process to Exchange-X."*

---

## 7. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| Address balance and transaction count | HIGH | On-chain at query time; cite explorer and block height |
| R1 transfer observed (tx in a block) | HIGH | Cross-check a second explorer for large claims |
| R2 address control (address has spent) | HIGH that a key/custody holder spent | Says nothing about who; custodial services spend for customers [P15] |
| Address shown on a scam page = operator's own wallet | LOW until it spends into a gradable cluster | May be a processor or exchange deposit address [P15] |
| R3 cluster via H1, CoinJoin screened | MEDIUM-HIGH | Same controller, which may be a service; PayJoin not excludable [P15, P16] |
| R3 cluster via H2 change links | LOW-MEDIUM | Idiom-dependent; false links can create super-clusters [P15] |
| Cluster containing ≥2 independently labelled services | LOW | Treat as false-link symptom; roll back to H1-only |
| Account-model (ETH/TRX) address-to-address link | LOW-MEDIUM, lead only | No H1/H2; behavioural signals only (adaptation) |
| R4 service label (exchange, mixer) | MEDIUM | Record labeller, method, date; labels have incomplete coverage [P16] |
| R4 label from own authorised interaction | MEDIUM-HIGH | P15 ranked self-observed tags above public tags [P15] |
| R5 customer identity at a service | NOT ASSESSABLE from chain | Requires legal process / KYC disclosure |
| Ransomware revenue from a cluster | Lower bound only | State seeds, filters, label coverage, blind spots [P16] |
| Zcash shielded linkage (round-trip / value pattern) | LOW, lead only | Historical, population-specific heuristics [P17] |
| Chainabuse scam report | MEDIUM-HIGH | Community-sourced; verify report quality |
| Ransomwhe.re family attribution | MEDIUM-HIGH | Researcher-verified submissions |
| AI geolocation of entity from chain data | LOW | Indirect inference only |

Tags: [P15 Meiklejohn et al., IMC 2013] · [P16 Huang et al., IEEE S&P 2018] ·
[P17 Kappos et al., USENIX Sec 2018].

---

## 8. Related Techniques

- [scam-check.md](scam-check.md) — Broader fraud and scam investigation workflow
- [threat-intel.md](threat-intel.md) — Correlate wallet addresses with threat actor profiles
- [web-dns-forensics.md](web-dns-forensics.md) — Link blockchain addresses found in web/DNS artifacts
- [fiat-payment-osint.md](fiat-payment-osint.md) — Fiat off-ramps and bank receiving accounts (R5 sits off-chain)

---

*Blockchain Investigation Module v1.1.0*
*Part of CTI Expert Skill - Phase 5 Enhancement Modules*
