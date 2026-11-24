# Wallet-Drainer Investigation

> **Module ID:** DRAIN-001
> **Version:** 1.0.0
> **Phase:** Characterization
> **Classification:** Web3 page surface → suspected drainer pattern (untested heuristic) → kit-rung leads
> **Engine:** `intel_engine/WebPivot/tools/wp_extract.py` (`extract_web3`), data in
> `intel_engine/WebPivot/references/drainer_markers.json`

---

## 1. Overview

A wallet drainer is a page that connects to the victim's wallet and then asks it to sign away
control of assets: an unlimited NFT approval (`setApprovalForAll`), an allowance increase, a
Permit2 signature transfer, or a blind raw signature (`eth_sign`). The victim sees "claim your
airdrop" or "verify your wallet"; the signature hands a spender the right to move everything.

Drainers are sold as a service. The drainer operator ships the kit, the contracts and the
back-end; affiliates run the lure domains and split the take. That shapes every rule below:
**a shared drainer contract or kit is lineage, not ownership.** Two lure domains calling one
contract are customers of the same service, not one operator.

**When to use:** a collected page loads a wallet-connect library, a victim reports signing
something from a link, or a case page carries web3 copy (airdrop, mint, claim, revoke).

---

## 2. What the collector extracts

`pivot_extract` writes `artifacts.web3` for every page. It scans the page HTML and every
JavaScript file already **stored in the capture bundle** (`wp_capture.stored_js`); it makes no
request of its own, so the scan never re-contacts the host.

| Field | Meaning |
|---|---|
| `connect_libs` | wallet-connect libraries found (WalletConnect, Web3Modal, Reown AppKit, RainbowKit, wagmi, ethers, web3.js, Solana wallet adapter, an `eth_requestAccounts` call) |
| `approval_calls` | approval-harvest method names found as exact identifiers |
| `legit_markers` | SDK package scopes of established decentralised applications |
| `contracts` | EVM addresses within a window of an approval call — drainer-contract **candidates** |
| `verdict` | `none`, `web3-site` or `suspected-drainer` |
| `label` | the rendering of the verdict |
| `reasons` | each marker and the file it was found in |

Collect with `--case` (or `--capture`) so the JavaScript is stored: a drainer's harvest logic
almost always lives in a bundle, not in the HTML, and an HTML-only scan reads `web3-site`.

---

## 3. The verdict

| Verdict | Condition |
|---|---|
| `none` | no wallet-connect library |
| `web3-site` | a connect library, and either no approval-harvest call or a legitimate-application marker |
| `suspected-drainer` | a connect library **and** at least one approval-harvest call **and** no legitimate-application marker |

**This is an untested heuristic.** No evaluation card exists for it yet
(`docs/evaluation-hygiene.md`), so every rendering reads *"suspected drainer pattern (untested
heuristic)"* and it never raises a risk score on its own. Real applications request approvals
too; a full ABI bundle can define `setApprovalForAll` without ever calling it. Read the
`reasons`, open the named file in the capture bundle, and confirm the call path by hand before
writing a finding.

---

## 4. Attribution rules (SKILL.md RULE 5)

| Artifact | Rung | KB write |
|---|---|---|
| A drainer-contract candidate (`web3.contracts`) on a `suspected-drainer` page | `wallet.drainer_contract` → **kit** | domain fact `drainer_contract_candidate`; the address is **not** a `uses_wallet` edge even when the wallet extractor also found it. On a `none` / `web3-site` page the address may be the payee wallet and keeps its owner edge |
| The verdict and its reasons | kit | domain facts `web3_verdict`, `web3_reason` |
| A payee wallet with no drainer context | `wallet.operator` → owner | unchanged: a reused payee wallet still clusters |

A shared drainer contract therefore never puts two hosts in one cluster. Corroborate with an
owner-rung artifact (a shared analytics id, a registrant contact, an exact certificate, a payee
wallet outside the drainer path) before claiming one operator.

---

## 5. Workflow

```
1. Collect the page with --case so its JavaScript is captured
2. Read artifacts.web3: verdict, reasons, contracts
3. suspected-drainer? Open each file named in `reasons` under
   cases/<case>/evidence/captures/<host>/… and confirm the approval call is reached
4. Look up each contract candidate on a block explorer (read-only): deployer, verified source,
   approvals it has received. Never interact with it, never sign anything.
5. Pivot the lure domain on owner-rung artifacts only; treat other domains calling the same
   contract as kit siblings (the same drainer service), never as the same operator
6. Report the verdict with its label and the reasons, plus the explorer evidence
```

Synthetic example of a reasons list for a captured bundle:

```
wallet-connect library walletconnect (page)
approval-harvest call setApprovalForAll (https://site-a.example/assets/main.js)
```

and a contract candidate written as `0x<40 hex>` — never paste a case's real contract into a
tracked file.

---

## 6. Tuning the markers

`drainer_markers.json` is analyst data, not code:

- A legitimate application flagged `suspected-drainer` → add its SDK package scope to
  `legit_markers`.
- A drainer read as `web3-site` → add the missing approval method to `approval_calls` or the
  connect stack to `connect_libs`.
- Every entry is a public library or method name. A contract address or host from a case is
  investigation data and never goes into this file (CLAUDE.md RULE 1).

---

## 7. Limitations

- **Static text only.** Obfuscated bundles that assemble method names at runtime evade the
  identifier match; read the rendered page with the browser path when the bundle is packed.
- **Capture budget.** A capture that skipped files for budget (`manifest.skipped_for_budget`)
  was not fully scanned; the manifest says so.
- **EVM only.** Contract candidates are EVM addresses; Solana programs and other chains are not
  extracted.
- **Untested.** The verdict's false-positive and miss rates are unknown until evaluated.

---

## Cross-references

- [`techniques/blockchain-investigation.md`](blockchain-investigation.md) — tracing the funds
- [`techniques/kit-template-attribution.md`](kit-template-attribution.md) — kit lineage versus operator
- [`techniques/web-pivot.md`](web-pivot.md) — collection and the capture bundle
- `intel_engine/tools/kb/references/rungs.json` — `wallet.drainer_contract` (kit)

---

*Wallet-Drainer Investigation Module v1.0.0 — for authorized threat-intelligence use.*
