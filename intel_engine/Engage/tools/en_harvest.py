#!/usr/bin/env python3
"""
en_harvest.py — the post-login MISSION: read the authenticated members-area page for the operator's
money and mechanics — the material the public page hid behind the login.

WHAT IT PULLS
-------------
Run this over the authenticated DOM en_engage captured (or any saved authenticated HTML):

  * WALLET addresses     — the crypto addresses deposits actually go to (BTC / ETH-BEP20-ERC20 /
                           TRON). The scammer's collection wallets: reused across the estate and
                           where a financial-intelligence / LE referral begins.
  * BANK / payee details — IBAN, SWIFT/BIC, and account numbers sitting next to bank keywords (a
                           bare number is taken ONLY in bank context, never as a blind regex).
  * SERVICE FLOW         — which mechanics the panel runs: deposit → task/trade → withdraw-block →
                           top-up demand; VIP levels; referral/team tree. Reported as the sections
                           present, so the analyst can describe the scam's shape.
  * CREDENTIAL-HARVESTER — the UPLOAD PATH where the panel POSTs captured credentials / KYC: a form
    UPLOAD PATH            whose action is a collector, a file-upload endpoint, or a page collecting
                           THIRD-PARTY credentials (card/CVV/seed-phrase/bank login). That path is
                           the operator's own routing and it clusters the kit.

DISCIPLINE
----------
This EXTRACTS; it does not attribute. Every wallet/account is a lead that goes back into WebPivot +
IntelAnalysis and is base-rate checked there — a shared payment-processor address is infrastructure,
not the operator's wallet. A bank number without bank context is dropped, not guessed.

USAGE
-----
    en_harvest.py authenticated_dom.html --pretty
    en_harvest.py authenticated_dom.html --case <case>     # also append to the evidence ledger
    cat page.html | en_harvest.py -
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from en_refs import load_ref, ref_path  # noqa: E402

_FALLBACK = {
    "harvest_targets": {
        "deposit_flow": ["deposit", "recharge", "top up"], "withdraw_flow": ["withdraw", "payout"],
        "wallet_context": ["wallet", "address", "usdt"], "bank_context": ["bank", "iban", "swift"],
        "kyc_upload": ["upload", "id card", "kyc"], "service_flow": ["task", "commission", "vip"],
    },
    "credential_harvester_markers": {
        "upload_path_hints": ["/upload", "/gate", "/save", "/log", "/collect"],
        "harvester_field_markers": ["cardnumber", "cvv", "seedphrase", "private_key", "otp"],
    },
    "wallet_patterns": [r"\b(0x[a-fA-F0-9]{40})\b", r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b",
                        r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", r"\b(bc1[0-9ac-hj-np-z]{11,71})\b"],
    "bank_patterns": [r"\b([A-Z]{2}[0-9]{2}[A-Z0-9]{11,30})\b",
                      r"\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"],
}
_FALLBACK["wallet_base_rate_exclude"] = ["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                                         "0xdAC17F958D2ee523a2206206994597C13D831ec7"]
_FALLBACK["api_wallet_fields"] = {
    "operator_wallet": ["wallet", "address", "deposit_address", "walletaddress"],
    "excluded_contract": ["contract", "token", "tokenaddress"]}
_REF = load_ref(ref_path(__file__, "engage.json"), _FALLBACK)
HT = _REF["harvest_targets"]
CH = _REF["credential_harvester_markers"]
WALLET_RE = [re.compile(p) for p in _REF["wallet_patterns"]]
BANK_RE = [re.compile(p) for p in _REF["bank_patterns"]]
UPLOAD_HINTS = [h.lower() for h in CH["upload_path_hints"]]
HARVEST_FIELDS = [h.lower() for h in CH["harvester_field_markers"]]
WALLET_EXCLUDE = set(_REF["wallet_base_rate_exclude"])
_AWF = _REF["api_wallet_fields"]
API_WALLET_FIELDS = [f.lower() for f in _AWF["operator_wallet"]]
API_CONTRACT_FIELDS = [f.lower() for f in _AWF["excluded_contract"]]


class _Strip(HTMLParser):
    """Collect visible text + forms (action/method/field names) + file inputs."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.forms = []
        self._form = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "fields": [], "file_inputs": False}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            nm = (a.get("name") or a.get("id") or "").lower()
            if nm:
                self._form["fields"].append(nm)
            if a.get("type", "").lower() == "file":
                self._form["file_inputs"] = True

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.text.append(data.strip())


def _context_hits(text_lower, buckets):
    return {name: True for name, toks in buckets.items()
            if any(t.lower() in text_lower for t in toks)}


def _near_bank_context(text: str) -> bool:
    tl = text.lower()
    return any(t.lower() in tl for t in HT.get("bank_context", []))


def harvest(html_text: str, base_url: str = "") -> dict:
    p = _Strip()
    try:
        p.feed(html_text or "")
    except Exception as exc:
        print(f"[en_harvest] parse error: {exc}", file=sys.stderr)
    text = "\n".join(p.text)
    tl = text.lower()

    # wallets (excluding base-rate token contracts / burn addresses)
    wallets = []
    for rx in WALLET_RE:
        for m in rx.findall(text):
            val = m if isinstance(m, str) else m[0]
            if val in WALLET_EXCLUDE:
                continue  # token contract / router / burn — infrastructure, not the operator
            if val not in [w["value"] for w in wallets]:
                wallets.append({"value": val, "kind": _wallet_kind(val)})

    # bank: IBAN/SWIFT anywhere; a plain number only in bank context
    banks = []
    if _near_bank_context(text):
        for rx in BANK_RE:
            for m in rx.findall(text):
                val = m if isinstance(m, str) else m[0]
                if val not in [b["value"] for b in banks]:
                    banks.append({"value": val, "note": "found in bank context"})
        for num in re.findall(r"\b\d{8,20}\b", text):
            if num not in [b["value"] for b in banks]:
                banks.append({"value": num, "note": "bare account-like number near bank keywords — verify"})

    # service flow present
    flow = _context_hits(tl, HT)

    # credential-harvester upload path
    harvester = []
    for f in p.forms:
        action_abs = urljoin(base_url, f["action"]) if base_url and f["action"] else f["action"]
        la = (action_abs or "").lower()
        collects_creds = any(m in " ".join(f["fields"]) for m in HARVEST_FIELDS)
        upload_pathy = any(h in la for h in UPLOAD_HINTS)
        if collects_creds or upload_pathy or f["file_inputs"]:
            harvester.append({
                "upload_path": action_abs or "(same page)", "method": f["method"].upper(),
                "collects_credentials": collects_creds, "file_upload": f["file_inputs"],
                "fields": [x for x in f["fields"] if x],
                "why": ("collects third-party credentials/KYC" if collects_creds else
                        "file upload endpoint" if f["file_inputs"] else "collector-style path"),
            })

    pivots = []
    for w in wallets:
        pivots.append({"kind": "wallet", "value": w["value"], "note": w["kind"]})
    for b in banks:
        pivots.append({"kind": "bank_account", "value": b["value"], "note": b["note"]})
    for h in harvester:
        if h["upload_path"] and h["upload_path"] != "(same page)":
            pivots.append({"kind": "harvester_upload_path", "value": h["upload_path"],
                           "note": h["why"]})

    return {
        "wallets": wallets,
        "bank_details": banks,
        "service_flow": sorted(flow.keys()),
        "credential_harvester": harvester,
        "pivots": pivots,
        "note": ("Mission material — feed wallets/accounts/upload-paths back into WebPivot + "
                 "IntelAnalysis; each is base-rate checked before it attributes anyone. A shared "
                 "processor wallet is infrastructure, not the operator's."),
    }


def harvest_api(bodies) -> dict:
    """Mine captured API JSON responses (an API-driven SPA keeps the money in XHR, not the DOM).
    `bodies` is a list of JSON strings (or already-parsed objects). Walks each for operator
    wallet/bank fields by NAME, applying the base-rate exclusion: a value under a `contract`/
    `token` field, or on the exclude list, is recorded as EXCLUDED, never as the operator's."""
    wallets, excluded, banks, telegram = [], [], [], []

    def walk(o, parent_key=""):
        if isinstance(o, dict):
            for k, v in o.items():
                lk = str(k).lower()
                if isinstance(v, str):
                    is_addr = any(rx.fullmatch(v) or rx.match(v) for rx in WALLET_RE)
                    if is_addr:
                        if v in WALLET_EXCLUDE or any(c in lk for c in API_CONTRACT_FIELDS):
                            if v not in [e["value"] for e in excluded]:
                                excluded.append({"value": v, "field": k, "why": "token contract / base-rate"})
                        elif any(f in lk for f in API_WALLET_FIELDS):
                            if v not in [w["value"] for w in wallets]:
                                wallets.append({"value": v, "field": k, "kind": _wallet_kind(v)})
                    if "t.me/" in v or (lk in ("telegram", "telegram_url", "support") and "t.me" in v):
                        for t in re.findall(r't\.me/[A-Za-z0-9_]+', v):
                            if t not in telegram:
                                telegram.append(t)
                    if lk in ("accountnumber", "account_number") and v:
                        banks.append({"account_number": v})
                    if lk in ("accountname", "account_name") and v and banks:
                        banks[-1]["account_name"] = v
                    if lk in ("bankname", "bank_name") and v and banks:
                        banks[-1]["bank"] = v
                walk(v, lk)
        elif isinstance(o, list):
            for x in o:
                walk(x, parent_key)

    for body in (bodies or []):
        try:
            obj = body if not isinstance(body, str) else json.loads(body)
        except Exception:
            continue
        walk(obj)

    # dedup banks by account number (an endpoint may repeat across polls)
    seen_acct, uniq_banks = set(), []
    for bk in banks:
        key = bk.get("account_number")
        if key and key not in seen_acct:
            seen_acct.add(key)
            uniq_banks.append(bk)
    banks = uniq_banks

    pivots = [{"kind": "wallet", "value": w["value"], "note": f"{w['kind']} (api field '{w['field']}')"}
              for w in wallets]
    for bk in banks:
        if bk.get("account_number"):
            pivots.append({"kind": "bank_account",
                           "value": f"{bk.get('bank','?')} {bk['account_number']} {bk.get('account_name','')}".strip(),
                           "note": "from API"})
    return {"wallets": wallets, "excluded_base_rate": excluded, "bank_details": banks,
            "telegram": telegram, "pivots": pivots,
            "note": ("Mined from captured API responses. `excluded_base_rate` are token-contract / "
                     "infrastructure addresses deliberately NOT treated as the operator's wallet.")}


def _wallet_kind(v: str) -> str:
    if v.startswith("0x"):
        return "ETH/ERC20/BEP20 (0x)"
    if v.startswith("T"):
        return "TRON/TRC20 (often USDT-TRC20)"
    if v.startswith("bc1"):
        return "BTC bech32"
    return "BTC legacy/segwit"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Harvest wallets/bank/flow/harvester-path from an authenticated page.")
    ap.add_argument("target", nargs="?", help="path to authenticated HTML, or - for stdin")
    ap.add_argument("--api-log", help="path to a JSON file of captured API responses (list of "
                                      "bodies, or {label: body}) — mine these too (SPA money is in XHR)")
    ap.add_argument("--base-url", default="", help="resolve relative form actions against this")
    ap.add_argument("--case", help="append findings to cases/<case>/engage/interactions.jsonl")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args(argv)

    result = {}
    if args.target:
        html_text = sys.stdin.read() if args.target == "-" else open(
            args.target, encoding="utf-8", errors="replace").read()
        result = harvest(html_text, args.base_url)
    if args.api_log:
        raw = json.load(open(args.api_log, encoding="utf-8"))
        bodies = list(raw.values()) if isinstance(raw, dict) else raw
        # entries may be {"b": "<json str>"} rows or bare strings
        bodies = [x.get("b") if isinstance(x, dict) and "b" in x else x for x in bodies]
        result["api_mission"] = harvest_api(bodies)

    if args.case:
        import datetime
        root = os.environ.get("INTEL_ROOT") or os.getcwd()
        d = os.path.join(root, "cases", args.case, "engage")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "interactions.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"event": "harvest", "source": args.target,
                                 "found": {k: len(result[k]) for k in
                                           ("wallets", "bank_details", "credential_harvester")},
                                 "ts": datetime.datetime.now(datetime.timezone.utc).strftime(
                                     "%Y-%m-%dT%H:%M:%SZ")}, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
