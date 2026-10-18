"""wp_crypto_refs — public crypto constants that must never read as an operator wallet.

Two classes, both DATA in references/crypto_reference_addresses.json (RULE 3):

* reference_crypto_addresses — spec test vectors, genesis, burn and system-program addresses.
  Printed in docs, tutorials and bundled libraries; a match is dropped outright.
* token_contracts — stablecoin/token CONTRACT addresses (USDT-TRC20, USDT-ERC20, USDC …). Every
  site that accepts the token embeds the same constant, so it is a payment-method fact, never a
  payee: it must not edge or cluster two domains and must not be balance-looked-up.

Stdlib-only, never raises. The fallback is the conservative minimum (genesis + one BIP-173 vector,
the two USDT contracts) so a broken file still keeps the commonest constants out of the KB.
"""
from wp_refs import ref_path, load_ref

__all__ = ["REFERENCE_ADDRESSES", "TOKEN_CONTRACTS", "norm", "reference_label", "token_contract"]

_CRYPTO_REF_FALLBACK = {
    "reference_crypto_addresses": {
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Bitcoin genesis coinbase reward address",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": "BIP-173 bech32 P2WPKH test vector",
    },
    "token_contracts": {
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {"chain": "tron", "label": "USDT-TRC20"},
        "0xdAC17F958D2ee523a2206206994597C13D831ec7": {"chain": "eth", "label": "USDT-ERC20"},
    },
}
_REF = load_ref(ref_path(__file__, "crypto_reference_addresses.json"), _CRYPTO_REF_FALLBACK)


def norm(addr) -> str:
    """Comparison key: hex (0x…) and bech32 are case-insensitive; base58 is case-significant."""
    a = str(addr or "").strip()
    return a.lower() if a.lower().startswith(("0x", "bc1", "ltc1", "tb1")) else a


def _table(group):
    raw = _REF.get(group)
    if not isinstance(raw, dict):
        raw = _CRYPTO_REF_FALLBACK[group]
    return {norm(k): v for k, v in raw.items() if k and not str(k).startswith("_")}


# DATA: references/crypto_reference_addresses.json -> reference_crypto_addresses / token_contracts
REFERENCE_ADDRESSES = _table("reference_crypto_addresses")
TOKEN_CONTRACTS = _table("token_contracts")


def reference_label(addr) -> str:
    """Provenance note when addr is a documentation/test-vector/burn constant, else ''."""
    key = norm(addr)
    if not key or key not in REFERENCE_ADDRESSES:
        return ""
    return str(REFERENCE_ADDRESSES[key] or "reference address")


def token_contract(addr):
    """{'address','chain','label'} when addr is a known token contract, else None."""
    meta = TOKEN_CONTRACTS.get(norm(addr)) if addr else None
    if meta is None:
        return None
    meta = meta if isinstance(meta, dict) else {"label": str(meta)}
    return {"address": str(addr).strip(), "chain": str(meta.get("chain") or ""),
            "label": str(meta.get("label") or "token contract")}
