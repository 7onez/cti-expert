#!/usr/bin/env python3
# cti-expert skill — ported from the Quarry OSINT toolkit (github.com/7onez/quarry): crypto_balance_runner.py
"""On-chain balance + lifetime-flow enrichment for crypto wallet addresses.

Given one or more wallet addresses, this looks up the current balance, lifetime
received/sent, and tx count from the appropriate public block explorer, then
values the balance at the current spot price (CoinGecko). The coin/chain is
auto-detected from each address's format (Quarry's CRYPTO_PATTERNS precedence)
unless a --coin hint is given. Every call is a read-only public API; the tool
never raises — each failure degrades to an ``error``/``supported=False`` result
so one flaky explorer can't crash the batch. Keyless-first: BTC→blockstream.info,
LTC→litecoinspace.org, ETH→Blockscout, TRON→Tronscan, ADA→Koios, DOT→Subscan.
Optional BLOCKCHAIR_API_KEY unlocks full received/sent flows for every chain it
covers (incl. BCH/DASH/DOGE/ZEC-transparent); SUBSCAN_API_KEY lifts DOT limits.

Usage:
  uv run crypto_balance.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  uv run crypto_balance.py 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 -c eth --pretty
  uv run crypto_balance.py --stdin -o balances.json < wallets.txt

FOR AUTHORIZED INVESTIGATIONS ONLY. All lookups hit public explorers, never the
subject — this is passive by construction.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys
import os
import re
import json
import time
import argparse
import urllib.request
import urllib.error
from urllib.parse import urlencode

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

DEFAULT_UA = "cti-expert/1.0"

# API keys: environment first, then the unified skill-root .env managed by
# /apikeys (../../ from scripts/webpivot/), overridable via CTI_API_KEYS_ENV.
# Env always wins. (Shared helper — verbatim across the webpivot scripts.)
_CUSTOMIZATION_ENV = (os.environ.get("CTI_API_KEYS_ENV")
                      or os.environ.get("CTI_WEBPIVOT_ENV")
                      or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env"))
def _load_customization_env(path=_CUSTOMIZATION_ENV):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass
_load_customization_env()
def _secret(*names):
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


# ---------------------------------------------------------------------------
# Timing knobs (faithful to Quarry's crypto_balance_runner env vars)
# ---------------------------------------------------------------------------
def _timeout():
    try:
        return int(os.getenv("CRYPTO_BALANCE_TIMEOUT", "20"))
    except ValueError:
        return 20


def _pacing():
    try:
        return float(os.getenv("CRYPTO_BALANCE_PACING_SECONDS", "1.0"))
    except ValueError:
        return 1.0


# ---------------------------------------------------------------------------
# Address format detection — ported verbatim from Quarry regex_patterns.py
# (CRYPTO_PATTERNS). Dict-insertion order is load-bearing: it is the precedence
# that resolves overlapping forms (e.g. bitcoin_p2pkh "1{25,34}" is tried before
# polkadot "1{47}"; zcash_t "t1…" vs tron "T…" differ only by case). Detection
# picks the FIRST pattern that spans the whole address — the same first-match
# precedence extract_crypto() relies on. Quarry's scan-time noise filters
# (is_reference_crypto / context-based _is_false_positive_crypto / CSS-source
# guards) are part of the free-text scanning front-end, need scan context absent
# from an explicit CLI address, and are NOT applied by crypto_balance_runner —
# so they are intentionally not ported here (applying the reference allowlist
# would refuse well-known addresses the user explicitly asks to check).
CRYPTO_PATTERNS = {
    'bitcoin_p2pkh': re.compile(r'\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    'bitcoin_p2sh': re.compile(r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    'bitcoin_bech32': re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,62}\b', re.IGNORECASE),
    'ethereum': re.compile(r'\b0x[0-9a-fA-F]{40}\b'),
    'litecoin_bech32': re.compile(r'\bltc1[a-zA-HJ-NP-Z0-9]{25,62}\b', re.IGNORECASE),
    'monero': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
    'dogecoin': re.compile(r'\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b'),
    'bitcoin_cash': re.compile(r'\bbitcoincash:q[a-z0-9]{41}\b', re.IGNORECASE),
    'dash': re.compile(r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b'),
    'zcash_t': re.compile(r'\bt1[a-km-zA-HJ-NP-Z1-9]{33}\b'),
    'zcash_z': re.compile(r'\bzs1[a-z0-9]{76}\b', re.IGNORECASE),
    'tron': re.compile(r'\bT[a-km-zA-HJ-NP-Z1-9]{33}\b'),
    'cardano': re.compile(r'\baddr1[a-z0-9]{58,}\b', re.IGNORECASE),
    'polkadot': re.compile(r'\b1[a-km-zA-HJ-NP-Z1-9]{47}\b'),
}


def detect_subtype(address):
    """Return the Quarry subtype for an address by CRYPTO_PATTERNS precedence.

    First pattern (in dict order) whose match spans the whole address wins.
    Returns None when no pattern matches the address as a standalone token.
    """
    addr = (address or "").strip()
    if not addr:
        return None
    for subtype, pattern in CRYPTO_PATTERNS.items():
        m = pattern.search(addr)
        if m and m.group() == addr:
            return subtype
    return None


# ---------------------------------------------------------------------------
# Provider tables — ported verbatim from crypto_balance_runner.py
# ---------------------------------------------------------------------------
# subtype → (blockchair_chain, symbol, decimals_divisor, coingecko_id)
_BLOCKCHAIR = {
    "bitcoin_p2pkh": ("bitcoin", "BTC", 1e8, "bitcoin"),
    "bitcoin_p2sh": ("bitcoin", "BTC", 1e8, "bitcoin"),
    "bitcoin_bech32": ("bitcoin", "BTC", 1e8, "bitcoin"),
    "bitcoin_cash": ("bitcoin-cash", "BCH", 1e8, "bitcoin-cash"),
    "litecoin_bech32": ("litecoin", "LTC", 1e8, "litecoin"),
    "dogecoin": ("dogecoin", "DOGE", 1e8, "dogecoin"),
    "dash": ("dash", "DASH", 1e8, "dash"),
    "zcash_t": ("zcash", "ZEC", 1e8, "zcash"),
    "ethereum": ("ethereum", "ETH", 1e18, "ethereum"),
}

# subtype → (symbol, decimals_divisor, coingecko_id) for the per-chain providers
_TRON = ("TRX", 1e6, "tron")
_CARDANO = ("ADA", 1e6, "cardano")
_POLKADOT = ("DOT", 1e10, "polkadot")

# Keyless Esplora-API explorers (same JSON shape as blockstream.info). Reliable
# without a key from shared server IPs, unlike Blockchair (HTTP 430 keyless).
# subtype → (api_base, web_base, chain, symbol)
_ESPLORA = {
    "bitcoin_p2pkh": ("https://blockstream.info/api", "https://blockstream.info", "bitcoin", "BTC"),
    "bitcoin_p2sh": ("https://blockstream.info/api", "https://blockstream.info", "bitcoin", "BTC"),
    "bitcoin_bech32": ("https://blockstream.info/api", "https://blockstream.info", "bitcoin", "BTC"),
    "litecoin_bech32": ("https://litecoinspace.org/api", "https://litecoinspace.org", "litecoin", "LTC"),
}

# Chains with no reliable keyless explorer wired — only Blockchair covers them.
# Without BLOCKCHAIR_API_KEY they degrade to a clear "needs key" result.
_BLOCKCHAIR_ONLY = {"dogecoin", "dash", "bitcoin_cash", "zcash_t"}

# subtypes we can never resolve — private or shielded.
_UNSUPPORTED = {
    "monero": "Monero is a private chain — balances are cryptographically unknowable",
    "zcash_z": "Zcash shielded (zs1…) addresses have no publicly queryable balance",
}

# Friendly coin hints (--coin) → subtype. Raw subtypes are also accepted as-is.
_COIN_HINTS = {
    "btc": "bitcoin_p2pkh", "bitcoin": "bitcoin_p2pkh", "xbt": "bitcoin_p2pkh",
    "bch": "bitcoin_cash", "bitcoincash": "bitcoin_cash", "bitcoin-cash": "bitcoin_cash",
    "ltc": "litecoin_bech32", "litecoin": "litecoin_bech32",
    "eth": "ethereum", "ethereum": "ethereum",
    "doge": "dogecoin", "dogecoin": "dogecoin",
    "dash": "dash",
    "zec": "zcash_t", "zcash": "zcash_t",
    "trx": "tron", "tron": "tron",
    "ada": "cardano", "cardano": "cardano",
    "dot": "polkadot", "polkadot": "polkadot",
    "xmr": "monero", "monero": "monero",
}

_KNOWN_SUBTYPES = set(CRYPTO_PATTERNS) | {"tron", "cardano", "polkadot"} | set(_UNSUPPORTED)

COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"


def coingecko_id_for(subtype):
    """Return the CoinGecko price id for a subtype, or None."""
    if subtype in _BLOCKCHAIR:
        return _BLOCKCHAIR[subtype][3]
    return {"tron": _TRON[2], "cardano": _CARDANO[2], "polkadot": _POLKADOT[2]}.get(subtype)


def symbol_for(subtype):
    """Ticker symbol (the ``coin`` output field) for a subtype, or None."""
    if subtype in _BLOCKCHAIR:
        return _BLOCKCHAIR[subtype][1]
    return {"tron": "TRX", "cardano": "ADA", "polkadot": "DOT",
            "monero": "XMR", "zcash_z": "ZEC"}.get(subtype)


def resolve_hint(hint, address=""):
    """Map a --coin hint (friendly name, ticker, or raw subtype) to a subtype.

    For a bitcoin hint, refine to the exact form (p2pkh/p2sh/bech32) from the
    address prefix when possible. Returns None for an unrecognized hint.
    """
    if not hint:
        return None
    h = hint.strip().lower()
    subtype = h if h in _KNOWN_SUBTYPES else _COIN_HINTS.get(h)
    if subtype and subtype.startswith("bitcoin_") and subtype != "bitcoin_cash":
        a = (address or "").strip().lower()
        if a.startswith("bc1"):
            subtype = "bitcoin_bech32"
        elif a.startswith("3"):
            subtype = "bitcoin_p2sh"
        elif a.startswith("1"):
            subtype = "bitcoin_p2pkh"
    return subtype


# ---------------------------------------------------------------------------
# HTTP — stdlib only, never raises. Returns (status, parsed_json, error).
# status is the HTTP code (0 on transport failure) so callers can branch on it
# exactly like the source did on resp.status_code.
# ---------------------------------------------------------------------------
def _request(url, params=None, json_body=None, headers=None, timeout=None):
    to = timeout or _timeout()
    hdrs = {"User-Agent": DEFAULT_UA}
    if headers:
        hdrs.update(headers)
    if params:
        url = url + "?" + urlencode(params)
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs,
                                     method="POST" if data is not None else "GET")
        with urllib.request.urlopen(req, timeout=to) as r:
            raw = r.read()
            status = getattr(r, "status", None) or r.getcode() or 200
            try:
                return status, json.loads(raw.decode("utf-8", "ignore")), None
            except ValueError as exc:
                return status, None, f"parse_error: {exc}"
    except urllib.error.HTTPError as exc:
        # Surface the status code (err stays None) so provider code can branch
        # on 402/404/429 the way the source read resp.status_code.
        body = None
        try:
            body = json.loads(exc.read().decode("utf-8", "ignore"))
        except Exception:
            body = None
        return exc.code, body, None
    except Exception as exc:
        return 0, None, f"request_failed: {exc}"


def get_prices(coingecko_ids):
    """Batch-fetch current USD spot prices for coingecko_ids (keyless). Never raises."""
    ids = sorted({i for i in coingecko_ids if i})
    if not ids:
        return {}
    status, data, err = _request(COINGECKO_URL,
                                 params={"ids": ",".join(ids), "vs_currencies": "usd"})
    if err or status != 200 or not isinstance(data, dict):
        return {}
    out = {}
    for cid, block in data.items():
        usd = block.get("usd") if isinstance(block, dict) else None
        if isinstance(usd, (int, float)):
            out[cid] = float(usd)
    return out


def _to_float(value):
    """Coerce an explorer int/str amount to float; None on junk."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _usd(native, price):
    if native is None or price is None:
        return None
    return round(native * price, 2)


def _envelope(address, coin, provider):
    """Base result envelope in the CLI output shape."""
    return {
        "address": address,
        "coin": coin,
        "supported": True,
        "balance": None,
        "received": None,
        "sent": None,
        "tx_count": None,
        "currency_value_usd": None,
        "spot_price_usd": None,
        "provider": provider,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Per-provider checks — faithful ports of crypto_balance_runner._check_* .
# Each returns a filled envelope; never raises.
# ---------------------------------------------------------------------------
def _check_blockchair(address, subtype, price):
    chain, unit, divisor, _cid = _BLOCKCHAIR[subtype]
    out = _envelope(address, unit, "blockchair")
    # bitcoin-cash addresses carry a "bitcoincash:" prefix in the value;
    # Blockchair accepts the bare cashaddr.
    query_addr = address.split(":", 1)[1] if address.lower().startswith("bitcoincash:") else address

    params = {}
    key = _secret("BLOCKCHAIR_API_KEY")
    if key:
        params["key"] = key
    status, data, err = _request(
        f"https://api.blockchair.com/{chain}/dashboards/address/{query_addr}",
        params=params or None)
    if err:
        out["error"] = err
        return out
    if status in (402, 429):
        out["error"] = "rate_limited"
        return out
    if status != 200:
        out["error"] = f"http_{status}"
        return out

    # Blockchair keys the data map by address, but normalizes case for some
    # chains (e.g. lowercased checksummed Ethereum) — try exact, then lower,
    # then fall back to the sole entry (single-address dashboard).
    data_map = (data or {}).get("data") or {}
    entry = (
        data_map.get(query_addr)
        or data_map.get(query_addr.lower())
        or (next(iter(data_map.values())) if len(data_map) == 1 else None)
    )
    addr_block = (entry or {}).get("address") if isinstance(entry, dict) else None
    if not isinstance(addr_block, dict) or not addr_block:
        out["error"] = "no_data"
        return out

    balance = _to_float(addr_block.get("balance"))
    received = _to_float(addr_block.get("received"))
    if received is None:
        received = _to_float(addr_block.get("received_approximate"))  # ethereum
    sent = _to_float(addr_block.get("spent"))
    if sent is None:
        sent = _to_float(addr_block.get("spent_approximate"))  # ethereum

    out["balance"] = round(balance / divisor, 8) if balance is not None else None
    out["received"] = round(received / divisor, 8) if received is not None else None
    out["sent"] = round(sent / divisor, 8) if sent is not None else None
    out["tx_count"] = addr_block.get("transaction_count") or addr_block.get("call_count")
    out["spot_price_usd"] = price
    out["currency_value_usd"] = _usd(out["balance"], price)
    return out


def _check_esplora(address, subtype, price):
    """Keyless Esplora explorer (blockstream.info / litecoinspace.org).

    chain_stats + mempool_stats give the FULL balance/received/sent/tx picture.
    """
    api_base, web_base, chain, unit = _ESPLORA[subtype]
    provider = "blockstream.info" if chain == "bitcoin" else "litecoinspace.org"
    out = _envelope(address, unit, provider)
    status, data, err = _request(f"{api_base}/address/{address}")
    if err:
        out["error"] = err
        return out
    if status != 200:
        out["error"] = f"http_{status}"
        return out
    cs = data.get("chain_stats", {}) if isinstance(data, dict) else {}
    ms = data.get("mempool_stats", {}) if isinstance(data, dict) else {}
    funded = (cs.get("funded_txo_sum") or 0) + (ms.get("funded_txo_sum") or 0)
    spent = (cs.get("spent_txo_sum") or 0) + (ms.get("spent_txo_sum") or 0)
    out["received"] = round(funded / 1e8, 8)
    out["sent"] = round(spent / 1e8, 8)
    out["balance"] = round((funded - spent) / 1e8, 8)
    out["tx_count"] = (cs.get("tx_count") or 0) + (ms.get("tx_count") or 0)
    out["spot_price_usd"] = price
    out["currency_value_usd"] = _usd(out["balance"], price)
    return out


def _check_blockscout_eth(address, price):
    """Keyless Blockscout (eth.blockscout.com) for Ethereum — balance + tx count.

    Lifetime received/sent *value* needs BLOCKCHAIR_API_KEY, so they stay None.
    """
    out = _envelope(address, "ETH", "blockscout")
    status, data, err = _request(f"https://eth.blockscout.com/api/v2/addresses/{address}")
    if err:
        out["error"] = err
        return out
    if status == 404:
        # Address Blockscout has never indexed → no activity; report zeroes.
        out["balance"] = 0.0
        out["tx_count"] = 0
        out["spot_price_usd"] = price
        out["currency_value_usd"] = 0.0
        return out
    if status != 200:
        out["error"] = f"http_{status}"
        return out
    bal = _to_float((data or {}).get("coin_balance"))
    out["balance"] = round(bal / 1e18, 8) if bal is not None else None
    out["spot_price_usd"] = price
    out["currency_value_usd"] = _usd(out["balance"], price)
    # tx count — best-effort second call; never fails the result.
    c_status, c_data, c_err = _request(
        f"https://eth.blockscout.com/api/v2/addresses/{address}/counters")
    if not c_err and c_status == 200:
        n = _to_float((c_data or {}).get("transactions_count"))
        out["tx_count"] = int(n) if n is not None else None
    return out


def _check_tron(address, price):
    out = _envelope(address, "TRX", "tronscan")
    status, data, err = _request("https://apilist.tronscanapi.com/api/account",
                                 params={"address": address})
    if err:
        out["error"] = err
        return out
    if status != 200:
        out["error"] = f"http_{status}"
        return out
    bal = _to_float((data or {}).get("balance"))
    out["balance"] = round(bal / _TRON[1], 6) if bal is not None else None
    out["tx_count"] = (data or {}).get("totalTransactionCount") or (data or {}).get("transactions")
    out["spot_price_usd"] = price
    out["currency_value_usd"] = _usd(out["balance"], price)
    # Tronscan's account endpoint doesn't expose lifetime received/sent totals.
    return out


def _check_cardano(address, price):
    out = _envelope(address, "ADA", "koios")
    status, rows, err = _request(
        "https://api.koios.rest/api/v1/address_info",
        json_body={"_addresses": [address]},
        headers={"Accept": "application/json"})
    if err:
        out["error"] = err
        return out
    if status != 200:
        out["error"] = f"http_{status}"
        return out
    row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}
    bal = _to_float(row.get("balance"))
    out["balance"] = round(bal / _CARDANO[1], 6) if bal is not None else None
    utxos = row.get("utxo_set")
    out["tx_count"] = len(utxos) if isinstance(utxos, list) else None
    out["spot_price_usd"] = price
    out["currency_value_usd"] = _usd(out["balance"], price)
    return out


def _check_polkadot(address, price):
    out = _envelope(address, "DOT", "subscan")
    headers = {}
    key = _secret("SUBSCAN_API_KEY")
    if key:
        headers["X-API-Key"] = key
    status, data, err = _request(
        "https://polkadot.api.subscan.io/api/v2/scan/search",
        json_body={"key": address}, headers=headers or None)
    if err:
        out["error"] = err
        return out
    if status == 429:
        out["error"] = "rate_limited"
        return out
    if status != 200:
        out["error"] = f"http_{status}"
        return out
    account = (((data or {}).get("data") or {}).get("account") or {})
    bal = _to_float(account.get("balance"))  # Subscan returns DOT (already divided)
    # Subscan's search returns human-readable DOT already; if it ever returns
    # planck, the divisor guards against a wildly large value.
    if bal is not None and bal > 1e9:
        bal = bal / _POLKADOT[1]
    out["balance"] = round(bal, 6) if bal is not None else None
    out["tx_count"] = account.get("count_extrinsic")
    out["spot_price_usd"] = price
    out["currency_value_usd"] = _usd(out["balance"], price)
    return out


def check_wallet(address, subtype, price_usd=None):
    """Look up balance + lifetime flow + USD value for one wallet address.

    price_usd may be passed in (batched) to avoid a per-call CoinGecko hit; when
    None it is fetched on demand. Returns a result envelope; never raises.
    """
    address = (address or "").strip()
    if subtype in _UNSUPPORTED:
        out = _envelope(address, symbol_for(subtype), None)
        out["supported"] = False
        out["error"] = _UNSUPPORTED[subtype]
        return out

    cid = coingecko_id_for(subtype)
    if cid is None:
        out = _envelope(address, symbol_for(subtype), None)
        out["supported"] = False
        out["error"] = f"unsupported subtype: {subtype}"
        return out

    if price_usd is None:
        price_usd = get_prices({cid}).get(cid)

    # Blockchair (keyed) is the preferred unified provider — it returns full
    # received/sent for every chain it covers, including BCH/DASH/DOGE/ZEC that
    # have no reliable keyless explorer. Only attempt it WITH a key: keyless
    # Blockchair is HTTP-430 blocked from shared server IPs. On a keyed error,
    # fall through to a keyless fallback where one exists.
    if subtype in _BLOCKCHAIR and _secret("BLOCKCHAIR_API_KEY"):
        r = _check_blockchair(address, subtype, price_usd)
        if not r.get("error"):
            return r

    if subtype in _ESPLORA:
        return _check_esplora(address, subtype, price_usd)
    if subtype == "ethereum":
        return _check_blockscout_eth(address, price_usd)
    if subtype == "tron":
        return _check_tron(address, price_usd)
    if subtype == "cardano":
        return _check_cardano(address, price_usd)
    if subtype == "polkadot":
        return _check_polkadot(address, price_usd)
    if subtype in _BLOCKCHAIR_ONLY:
        # Reached only when BLOCKCHAIR_API_KEY is unset (or the keyed call errored).
        out = _envelope(address, _BLOCKCHAIR[subtype][1], "blockchair")
        out["error"] = "needs BLOCKCHAIR_API_KEY (no keyless explorer for this chain)"
        return out

    out = _envelope(address, symbol_for(subtype), None)
    out["supported"] = False
    out["error"] = f"unsupported subtype: {subtype}"
    return out


def enrich_wallets(addresses, coin_hint=None):
    """Resolve + look up many addresses, batching the price lookup.

    Prices for every needed coin are fetched in ONE CoinGecko call, then each
    wallet is looked up with inter-request pacing (so a big batch can't hammer
    an explorer into a ban). Returns (results, summary); never raises.
    """
    # 1. Resolve each address to a subtype (hint wins, else auto-detect).
    resolved = []  # (address, subtype_or_None)
    for raw in addresses:
        addr = (raw or "").strip()
        if not addr:
            continue
        subtype = resolve_hint(coin_hint, addr) if coin_hint else detect_subtype(addr)
        resolved.append((addr, subtype))

    # 2. Batch price lookup for all distinct coins present.
    needed = {coingecko_id_for(st) for _, st in resolved if st}
    prices = get_prices({i for i in needed if i})

    # 3. Per-wallet lookup with pacing between real network calls.
    results = []
    pacing = _pacing()
    last = len(resolved) - 1
    for i, (addr, subtype) in enumerate(resolved):
        if subtype is None:
            out = _envelope(addr, None, None)
            out["supported"] = False
            out["error"] = "could not detect coin/chain from address format (pass --coin)"
            results.append(out)
            continue
        cid = coingecko_id_for(subtype)
        price = prices.get(cid) if cid else None
        out = check_wallet(addr, subtype, price_usd=price)
        results.append(out)
        # Pace only between calls that actually hit the network.
        if i < last and out.get("supported") and not out.get("error"):
            time.sleep(pacing)

    total = round(sum(r["currency_value_usd"] for r in results
                      if isinstance(r.get("currency_value_usd"), (int, float))), 2)
    summary = {
        "checked": len(results),
        "supported": sum(1 for r in results if r.get("supported")),
        "total_usd": total,
    }
    return results, summary


# ----------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(
        description="On-chain balance/flow enrichment for crypto wallet addresses "
                    "(ported from the Quarry OSINT toolkit).")
    ap.add_argument("addresses", nargs="*", help="one or more wallet addresses")
    ap.add_argument("-c", "--coin", help="coin hint (btc/eth/ltc/trx/ada/dot/bch/doge/dash/zec/xmr "
                                         "or a raw subtype); default: auto-detect per address")
    ap.add_argument("--stdin", action="store_true", help="read addresses (one per line) from stdin")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON (indent=2)")
    ap.add_argument("-o", "--out", help="write JSON to FILE instead of stdout")
    args = ap.parse_args()

    addresses = list(args.addresses)
    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                addresses.append(line)
    if not addresses:
        ap.error("provide one or more addresses (positional) or --stdin")

    results, summary = enrich_wallets(addresses, coin_hint=args.coin)
    payload = {"results": results, "summary": summary}
    text = json.dumps(payload, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except Exception as exc:
            print(f"[!] could not write {args.out}: {exc}", file=sys.stderr)
            print(text)
    else:
        print(text)

    print(f"checked {summary['checked']} addresses, {summary['supported']} supported, "
          f"${summary['total_usd']:.2f} total", file=sys.stderr)


if __name__ == "__main__":
    main()
