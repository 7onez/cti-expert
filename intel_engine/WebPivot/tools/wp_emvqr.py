#!/usr/bin/env python3
"""wp_emvqr — parse an EMVCo merchant-presented QR payload (VietQR and its siblings).

A payment QR on a scam page is not an opaque image: the payload is plain text in the EMVCo
tag-length-value format, and the receiving bank and account number sit inside it. WebPivot already
decodes QR payloads (wp_extract.extract_qr); this module reads them:

    parse(payload) -> {payload_format, crc_ok, rail, acquirer_id, account, amount, currency,
                       purpose, merchant_name, merchant_city, country, raw_tags} | None

FORMAT. Each field is a 2-digit tag, a 2-digit length and the value. Merchant-account templates
(tags 26-51), the additional-data template (62), the language template (64) and the unreserved
templates (80-99) nest the same structure. Tag 63 is the CRC: CRC-16/CCITT-FALSE (polynomial
0x1021, initial 0xFFFF), computed over the payload up to and including `6304`. The rail is named
by the GUID in sub-tag 00 of a merchant-account template and looked up in
`references/payment_rails.json`, which also says where the acquirer id and the account number sit
(VietQR/NAPAS: template 38, GUID A000000727, sub-tag 01 -> nested 00 = BIN, 01 = account).

RAILS. A payload whose CRC fails is reported with `crc_ok: False` and must never become a
selector — a damaged decode would otherwise mint a stranger's account number. A rail this file
does not list yields no account. `merchant_name` may be a real person's name (the account holder,
often a mule or a victim): callers keep it in the raw artifact only, never in a selector, a KB key
or a fixture.

Stdlib only; never raises.

CLI:  python3 wp_emvqr.py '<payload>'
"""
import json
import sys

from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

# DATA: references/payment_rails.json. Conservative fallback: no rail, no bank — a payload still
# parses, but nothing becomes an account selector without the data file.
_RAILS_FALLBACK = {"rails": {}, "acquirer_bins": {}}
_RAILS_REF = load_ref(ref_path(__file__, "payment_rails.json"), _RAILS_FALLBACK)
RAILS = {str(k).upper(): v for k, v in (_RAILS_REF.get("rails") or {}).items()
         if isinstance(v, dict)}
ACQUIRER_BINS = {str(k): v for k, v in (_RAILS_REF.get("acquirer_bins") or {}).items()
                 if isinstance(v, dict)}

_ACCOUNT_TEMPLATES = tuple(f"{t:02d}" for t in range(26, 52))
_NESTED = set(_ACCOUNT_TEMPLATES) | {"62", "64"} | {f"{t:02d}" for t in range(80, 100)}


def crc16_ccitt_false(data: str) -> str:
    """CRC-16/CCITT-FALSE of `data` (UTF-8) as 4 upper-case hex digits."""
    crc = 0xFFFF
    for byte in data.encode("utf-8"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return f"{crc:04X}"


def tlv(s: str):
    """[(tag, value, offset)] for one TLV level, or None when the structure does not hold."""
    out, i = [], 0
    while i < len(s):
        tag, ln = s[i:i + 2], s[i + 2:i + 4]
        if len(tag) < 2 or len(ln) < 2 or not (tag.isdigit() and ln.isdigit()):
            return None
        n = int(ln)
        val = s[i + 4:i + 4 + n]
        if len(val) != n:
            return None
        out.append((tag, val, i))
        i += 4 + n
    return out


def _tree(s: str, nested=True) -> dict:
    d = {}
    for tag, val, _ in tlv(s) or []:
        sub = tlv(val) if nested and tag in _NESTED else None
        d[tag] = ({t: v for t, v, _ in sub} if sub else val)
    return d


def _dig(node, path):
    """Follow sub-tags through nested TLV; a string at an intermediate step is parsed on demand."""
    for step in path or []:
        if isinstance(node, str):
            parts = tlv(node)
            if not parts:
                return None
            node = {t: v for t, v, _ in parts}
        if not isinstance(node, dict) or step not in node:
            return None
        node = node[step]
    return node if isinstance(node, str) else None


def bank_name(rail: str, acquirer_id: str):
    """The bank a rail's acquirer id names, from payment_rails.json — None when not listed."""
    return (ACQUIRER_BINS.get(rail or "") or {}).get(str(acquirer_id or "")) or None


def parse(payload):
    """Parse one EMVCo merchant-presented payload; None when it is not one."""
    try:
        return _parse(payload)
    except Exception:  # noqa: BLE001 — a decoder feeding garbage must never break extraction
        return None


def _parse(payload):
    p = str(payload or "").strip()
    if not p.startswith("000201"):
        return None
    top = tlv(p)
    if not top:
        return None
    raw = _tree(p)
    crc_ok = False
    last_tag, last_val, last_off = top[-1]
    if last_tag == "63" and len(last_val) == 4:
        crc_ok = crc16_ccitt_false(p[:last_off + 4]) == last_val.upper()
    rail = acquirer = account = None
    country = raw.get("58") if isinstance(raw.get("58"), str) else None
    for tag in _ACCOUNT_TEMPLATES:
        tmpl = raw.get(tag)
        if not isinstance(tmpl, dict):
            continue
        spec = RAILS.get(str(tmpl.get("00") or "").upper())
        if not spec:
            continue
        rail = spec.get("rail")
        acquirer = _dig(tmpl, spec.get("acquirer_path"))
        account = _dig(tmpl, spec.get("account_path"))
        country = country or spec.get("country")
        break
    add = raw.get("62") if isinstance(raw.get("62"), dict) else {}
    return {
        "payload_format": raw.get("00"),
        "crc_ok": crc_ok,
        "rail": rail,
        "acquirer_id": acquirer,
        "account": account,
        "amount": raw.get("54") if isinstance(raw.get("54"), str) else None,
        "currency": raw.get("53") if isinstance(raw.get("53"), str) else None,
        "purpose": add.get("08"),
        "merchant_name": raw.get("59") if isinstance(raw.get("59"), str) else None,
        "merchant_city": raw.get("60") if isinstance(raw.get("60"), str) else None,
        "country": country,
        "raw_tags": raw,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: wp_emvqr.py '<EMVCo payload>'", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(parse(sys.argv[1]), indent=2, ensure_ascii=False))
