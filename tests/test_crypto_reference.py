#!/usr/bin/env python3
"""Regression: public crypto CONSTANTS never read as an operator wallet.

WHAT THIS PROTECTS
------------------
A wallet is an owner-rung join key: two sites paying out to one address are one payee. But some
addresses are printed on thousands of unrelated pages — the USDT-TRC20 token CONTRACT sits on every
site that accepts USDT, BIP-173 test vectors and the genesis address live in docs and bundled
libraries. Extracted as wallets they fuse every USDT-accepting site into one false "operator" and
send a public constant to crypto_balance. This asserts (data: WebPivot/references/
crypto_reference_addresses.json):
  1. a page with the USDT-TRC20 contract + a payout address yields ONLY the payout as a wallet,
     and the contract surfaces as a payment-method token contract;
  2. a BIP-173 test vector / the genesis address are dropped outright;
  3. two domains sharing only a token contract form no edge and no cluster — while two domains
     sharing a payout wallet still do (the control: the join key is not weakened);
  4. every wallet-classifying route agrees: reference → dropped, token contract → kit and never a
     pivot node (so no counterparty / balance lookup), anything else → wallet.operator.

Run:  python3 tests/test_crypto_reference.py   — fully offline, synthetic hosts (*.example).
"""
import hashlib
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
for p in (os.path.join(ENGINE, "tools"), os.path.join(ENGINE, "tools", "kb"),
          os.path.join(ENGINE, "WebPivot", "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import wp_extract as E            # noqa: E402
import ingest_webpivot as I       # noqa: E402
import pivot_routes as PR         # noqa: E402
import quarry_bridge as qb        # noqa: E402
import selector_types as ST       # noqa: E402
from knowledge_base import KB     # noqa: E402

USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"     # public token contract (reference data)
USDT_ERC20 = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
BIP173 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BIP-173 P2WPKH test vector
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(version: int, body: bytes) -> str:
    """A synthetic base58check address (valid checksum, made-up hash160)."""
    payload = bytes([version]) + body
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num, out = int.from_bytes(raw, "big"), ""
    while num:
        num, r = divmod(num, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


PAYOUT = _b58check(0x41, bytes(range(1, 21)))          # synthetic TRON payout wallet
PAYOUT_ETH = "0x" + "ab" * 20                          # synthetic ETH payout wallet


def _raw(host, crypto, token_contracts):
    return {"meta": {"host": host, "kind": "domain", "fetched_at": "2026-01-01T00:00:00+00:00"},
            "pivots": [{"kind": "domain", "value": host, "live_results": {}}],
            "artifacts": {"crypto": crypto, "crypto_token_contracts": token_contracts}}


def _ingest(tmp, raws):
    kb = KB(os.path.join(tmp, "knowledge"))
    for host, raw in raws:
        p = os.path.join(tmp, host + ".json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        I.ingest_file(kb, p)
    return kb


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    # 1. payout kept, contract demoted to a payment-method record
    ok(PAYOUT.startswith("T") and E.valid_crypto_address("tron", PAYOUT), "synthetic payout is a valid TRON address")
    page = (f"<p>Deposit USDT (TRC20) — token {USDT_TRC20}</p><p>Send to {PAYOUT}</p>"
            f"<script>var usdt='{USDT_ERC20}'</script>")
    got = E.extract_crypto(page)
    ok(got == {"tron": [PAYOUT]}, f"only the payout is an operator wallet ({got})")
    tcs = E.extract_token_contracts(page)
    ok(sorted((t["label"], t["chain"]) for t in tcs) == [("USDT-ERC20", "eth"), ("USDT-TRC20", "tron")],
       f"both USDT contracts surface as token contracts ({tcs})")
    ok(not any(t["address"] == PAYOUT for t in tcs), "the payout is never mistaken for a token contract")
    ok(E.extract_token_contracts(page.replace(USDT_ERC20, USDT_ERC20.lower()))
       and not E.extract_crypto(f"x {USDT_ERC20.lower()} y"),
       "a lower-cased 0x contract still matches (hex compares case-insensitively)")

    # 2. reference constants are dropped outright
    ok(E._address_checksum_ok("btc", BIP173), "the BIP-173 vector is checksum-valid (so only the ref list stops it)")
    ok(not E.valid_crypto_address("btc", BIP173), "BIP-173 test vector is not a wallet")
    ok(E.extract_crypto(f"docs: {BIP173} and {GENESIS}") == {}, "BIP-173 vector + genesis dropped from extraction")
    ok(E.extract_token_contracts(f"{BIP173} {GENESIS}") == [], "reference vectors are not token contracts either")

    # 3. sharing only a token contract never clusters; sharing a payout wallet still does
    with tempfile.TemporaryDirectory() as tmp:
        tc = [{"address": USDT_TRC20, "chain": "tron", "label": "USDT-TRC20"}]
        # stale raws that still carry the contract under `crypto` must be gated at ingest too
        kb = _ingest(tmp, [(h, _raw(h, {"tron": [USDT_TRC20]}, tc)) for h in ("a.example", "b.example")])
        wallet_edges = [e for e in kb.edges() if e["rel"] == "uses_wallet"]
        ok(wallet_edges == [], f"a token contract writes no uses_wallet edge ({wallet_edges})")
        shared = [s for s in kb.shared_indicators(min_domains=2)
                  if {"a.example", "b.example"} <= set(s["domains"])]
        ok(shared == [], f"two domains sharing only USDT-TRC20 form no edge/cluster ({shared})")
        facts = [f for h in ("a.example", "b.example") for f in kb.entity("domain", h)["facts"]
                 if f["attribute"] == "payment_token_contract"]
        ok(len(facts) == 2 and all(USDT_TRC20 in str(f["value"]) for f in facts),
           f"the contract is kept as a per-domain payment-method fact ({facts})")
    with tempfile.TemporaryDirectory() as tmp:
        kb = _ingest(tmp, [(h, _raw(h, {"tron": [PAYOUT]}, [])) for h in ("a.example", "b.example")])
        shared = [s["indicator"] for s in kb.shared_indicators(min_domains=2)]
        ok(f"wallet:tron:{PAYOUT}" in shared, f"control: a shared payout wallet still clusters ({shared})")

    # 4. every wallet-classifying consumer agrees
    ok(PR.wallet_rung(BIP173) is None and PR.wallet_rung(GENESIS) is None, "wallet_rung drops reference vectors")
    ok(PR.wallet_rung(USDT_TRC20) == "wallet.token_contract", "wallet_rung: USDT-TRC20 → wallet.token_contract")
    ok(PR.wallet_rung(USDT_ERC20.lower()) == "wallet.token_contract", "wallet_rung: lower-case USDT-ERC20 too")
    ok(PR.wallet_rung(PAYOUT) == "wallet.operator", "wallet_rung: a payout stays wallet.operator")
    ok(ST.rung_for("wallet.token_contract") == "kit", "rungs: wallet.token_contract → kit (fact only)")
    ok(ST.rung_for("wallet.operator") == "owner", "rungs: wallet.operator still owner")
    for route in ("crypto.counterparties", "quarry.page", "binary.analyze", "urlscan.identifier"):
        ok("wallet.token_contract" in ST.fact_only_classes(route),
           f"{route}: a token contract is never a pivot node (no balance/counterparty lookup)")
    ok("wallet.operator" not in ST.fact_only_classes("crypto.counterparties"),
       "a payout wallet remains a pivot node")
    ok(PR.identifier_rung("wallet.ethereum", USDT_ERC20) == "wallet.token_contract",
       "urlscan identifier on a token contract is not an owner link")
    ok(PR.identifier_rung("wallet.bitcoin", BIP173) == "string",
       "urlscan identifier on a test vector binds nobody")

    groups, notes = qb.build_row_groups({
        "export": {"content": {"findings": {"crypto": [
            {"value": USDT_TRC20, "subtype": "tron"},
            {"value": BIP173, "subtype": "bitcoin_bech32"},
            {"value": PAYOUT_ETH, "subtype": "ethereum"}]}, "whois": {"whois_history": []}}},
        "connected": {"connections": []}}, target="site-a.example")
    rungs = {(r["type"], r["value"]): r["rung_class"] for g in groups for r in g["rows"]}
    ok(rungs.get(("wallet", PAYOUT_ETH)) == "wallet.operator", "quarry: payout wallet stays operator")
    ok(rungs.get(("wallet", USDT_TRC20)) == "wallet.token_contract", "quarry: USDT-TRC20 → wallet.token_contract")
    ok(("wallet", BIP173) not in rungs and notes["dropped_noise"] >= 1, "quarry: BIP-173 vector dropped and counted")
    return passed, failed, lines


if __name__ == "__main__":
    _p, _f, _lines = check()
    for _s, _l in _lines:
        print(("ok  " if _s == "ok" else "FAIL") + "  " + _l)
    print(f"{_p} passed, {_f} failed")
    raise SystemExit(bool(_f))
