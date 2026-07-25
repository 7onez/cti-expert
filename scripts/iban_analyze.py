#!/usr/bin/env python3
# cti-expert skill — fiat payment-rail selector analysis.
# Technique/spec reimplemented from the published ISO 13616 / ISO 7064 standards.
# No third-party source was copied.
"""iban_analyze.py — validate and decompose IBANs so a bank account becomes a usable
CTI selector, the way a wallet address already is.

What it does, entirely offline and deterministic:
  * ISO 7064 MOD 97-10 checksum  -> is this a real account number or fabricated/typo'd?
  * ISO 13616 country length      -> country + expected length agreement
  * BBAN decomposition            -> bank code / branch code / account number
  * risk signals                  -> jurisdiction mismatch, high-risk-for-mule geographies

What it deliberately does NOT do: ship an invented bank-name registry. National bank-code
registries are large, licensed and country-specific, so the tool prints the authoritative
lookup route per country and accepts a user-supplied table via --bank-db.

Usage:
  uv run iban_analyze.py GB29NWBK60161331926819
  uv run iban_analyze.py "DE89 3704 0044 0532 0130 00" --json
  uv run iban_analyze.py --batch ibans.txt --json -o out.json
  uv run iban_analyze.py <iban> --expect-country VN     # flag jurisdiction mismatch
  uv run iban_analyze.py <iban> --bank-db banks.csv     # CSV: country,bank_code,bank_name
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import re
import csv
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# ----------------------------------------------------------------- ISO 13616 registry
# Total IBAN length per country. Countries absent here still get a mod-97 verdict; only the
# length cross-check is reported as unavailable (safe failure mode, never a false "invalid").
IBAN_LENGTH = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}

# BBAN layout: ordered (label, width) after the 4-char "CCkk" prefix. Only countries whose
# published structure is mapped appear here; the rest report "structure not mapped".
BBAN_LAYOUT = {
    "AD": [("bank", 4), ("branch", 4), ("account", 12)],
    "AT": [("bank", 5), ("account", 11)],
    "BA": [("bank", 3), ("branch", 3), ("account", 8), ("check", 2)],
    "BE": [("bank", 3), ("account", 7), ("check", 2)],
    "BG": [("bank", 4), ("branch", 4), ("account_type", 2), ("account", 8)],
    "CH": [("bank", 5), ("account", 12)],
    "CY": [("bank", 3), ("branch", 5), ("account", 16)],
    "CZ": [("bank", 4), ("account", 16)],
    "DE": [("bank", 8), ("account", 10)],
    "DK": [("bank", 4), ("account", 10)],
    "EE": [("bank", 2), ("branch", 2), ("account", 11), ("check", 1)],
    "ES": [("bank", 4), ("branch", 4), ("check", 2), ("account", 10)],
    "FI": [("bank", 6), ("account", 8)],
    "FR": [("bank", 5), ("branch", 5), ("account", 11), ("check", 2)],
    "GB": [("bank", 4), ("sort_code", 6), ("account", 8)],
    "GI": [("bank", 4), ("account", 15)],
    "GR": [("bank", 3), ("branch", 4), ("account", 16)],
    "HR": [("bank", 7), ("account", 10)],
    "HU": [("bank", 3), ("branch", 4), ("check", 1), ("account", 15), ("check2", 1)],
    "IE": [("bank", 4), ("sort_code", 6), ("account", 8)],
    "IL": [("bank", 3), ("branch", 3), ("account", 13)],
    "IS": [("bank", 4), ("branch", 2), ("account", 6), ("kennitala", 10)],
    "IT": [("check", 1), ("bank", 5), ("branch", 5), ("account", 12)],
    "LI": [("bank", 5), ("account", 12)],
    "LT": [("bank", 5), ("account", 11)],
    "LU": [("bank", 3), ("account", 13)],
    "LV": [("bank", 4), ("account", 13)],
    "MC": [("bank", 5), ("branch", 5), ("account", 11), ("check", 2)],
    "MD": [("bank", 2), ("account", 18)],
    "ME": [("bank", 3), ("account", 13), ("check", 2)],
    "MK": [("bank", 3), ("account", 10), ("check", 2)],
    "MT": [("bank", 4), ("sort_code", 5), ("account", 18)],
    "MU": [("bank", 6), ("branch", 2), ("account", 12), ("reserved", 3), ("currency", 3)],
    "NL": [("bank", 4), ("account", 10)],
    "NO": [("bank", 4), ("account", 6), ("check", 1)],
    "PL": [("bank", 3), ("branch", 4), ("check", 1), ("account", 16)],
    "PT": [("bank", 4), ("branch", 4), ("account", 11), ("check", 2)],
    "RO": [("bank", 4), ("account", 16)],
    "RS": [("bank", 3), ("account", 13), ("check", 2)],
    "SA": [("bank", 2), ("account", 18)],
    "SE": [("bank", 3), ("account", 16), ("check", 1)],
    "SI": [("bank", 2), ("branch", 3), ("account", 8), ("check", 2)],
    "SK": [("bank", 4), ("account", 16)],
    "SM": [("check", 1), ("bank", 5), ("branch", 5), ("account", 12)],
    "TR": [("bank", 5), ("reserved", 1), ("account", 16)],
    "UA": [("bank", 6), ("account", 19)],
    "AE": [("bank", 3), ("account", 16)],
    "VG": [("bank", 4), ("account", 16)],
    "XK": [("bank", 2), ("branch", 2), ("account", 10), ("check", 2)],
}

# Authoritative route to resolve a bank code -> institution name, per country. Printed
# instead of guessing a bank name.
BANK_REGISTRY_HINT = {
    "GB": "UK sort code: Bank of England / Pay.UK sort-code directory, or a BIC lookup on the 4-char bank prefix",
    "IE": "Irish sort code: BPFI directory / BIC lookup",
    "DE": "Bundesbank Bankleitzahl (BLZ) directory — free download",
    "AT": "OeNB Bankleitzahl directory",
    "CH": "SIX Interbank Clearing bank master (IID/BC-Nr)",
    "FR": "Banque de France CIB / FIBEN directory",
    "IT": "Banca d'Italia ABI/CAB register",
    "ES": "Banco de España registro de entidades (código de entidad)",
    "NL": "Dutch bank code = 4-letter BIC prefix (e.g. INGB, ABNA, RABO)",
    "BE": "NBB protocol list (3-digit bank identifier)",
    "PL": "NBP numer rozliczeniowy directory",
    "PT": "Banco de Portugal SICOI institution codes",
    "SE": "Bankgirot / Riksbank clearing-number ranges",
    "DK": "Finans Danmark registreringsnummer list",
    "NO": "Bits AS clearing-number register",
    "FI": "Finnish bank code = first digits, maps to BIC via Finanssiala table",
    "TR": "TCMB / TBB bank EFT codes",
    "UA": "NBU МФО directory",
    "AE": "CBUAE bank routing codes",
    "SA": "SAMA bank codes (2-digit)",
    "RO": "BNR / TransFonD 4-letter bank code = BIC prefix",
    "CZ": "CNB kód banky list",
    "SK": "NBS kód banky list",
    "HU": "MNB GIRO bank code list",
    "BG": "BNB bank code = BIC prefix",
    "HR": "HNB VBDI directory",
    "GR": "Bank of Greece 3-digit bank code",
    "MT": "CBM institution + sort-code register",
    "LT": "Lietuvos bankas bank codes",
    "LV": "Latvijas Banka bank code = BIC prefix",
    "EE": "Eesti Pank 2-digit bank code",
    "SI": "Banka Slovenije bank code list",
    "LU": "BCL IBAN/BIC correspondence table",
    "CY": "CBC bank + branch code register",
}

# FATF/EU-listed and commonly abused-for-mule jurisdictions. Presence is a *signal to check*,
# never a conclusion — legitimate accounts exist everywhere.
ELEVATED_RISK_CC = {
    "AL": "FATF/EU enhanced monitoring history",
    "BA": "EU high-risk third country list history",
    "BY": "sanctions exposure",
    "LB": "FATF grey list",
    "MU": "offshore financial centre",
    "PS": "limited correspondent banking oversight",
    "RU": "sanctions exposure",
    "SC": "offshore financial centre",
    "SY": "sanctions exposure",
    "TR": "FATF grey list history",
    "VG": "offshore financial centre",
    "XK": "limited AML supervision history",
    "YE": "FATF high-risk",
    "GI": "offshore financial centre",
    "LC": "offshore financial centre",
    "MT": "EU AML enforcement history",
}

_IBAN_SHAPE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{9,30}$")


def canonical(raw):
    """Strip formatting whitespace/punctuation and upper-case."""
    return re.sub(r"[\s\-.]", "", (raw or "")).upper()


def mod97(iban):
    """ISO 7064 MOD 97-10: move the first four chars to the end, letters -> digits, %97."""
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(c, 36)) if c.isalpha() else c for c in rearranged)
    # streaming remainder keeps the integer small and avoids a huge int conversion
    rem = 0
    for ch in digits:
        rem = (rem * 10 + int(ch)) % 97
    return rem


def decompose(iban, cc):
    """Split the BBAN into its published fields. Returns (fields, mapped?)."""
    bban = iban[4:]
    layout = BBAN_LAYOUT.get(cc)
    if not layout:
        return {"bban": bban}, False
    out, pos = {}, 0
    for label, width in layout:
        out[label] = bban[pos:pos + width]
        pos += width
    if pos < len(bban):
        out["unparsed_tail"] = bban[pos:]
    out["bban"] = bban
    return out, True


def load_bank_db(path):
    """CSV: country,bank_code,bank_name -> {(cc, code): name}."""
    db = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cc = (row.get("country") or "").strip().upper()
            code = (row.get("bank_code") or "").strip().upper()
            name = (row.get("bank_name") or "").strip()
            if cc and code and name:
                db[(cc, code)] = name
    return db


def analyze(raw, bank_db=None, expect_country=None):
    iban = canonical(raw)
    r = {"input": raw, "iban": iban, "valid": False, "checks": {}, "risk_signals": []}

    if not _IBAN_SHAPE.match(iban):
        r["checks"]["structure"] = "fail — not CC + 2 check digits + 9-30 alphanumerics"
        r["verdict"] = "NOT AN IBAN"
        return r
    r["checks"]["structure"] = "pass"

    cc = iban[:2]
    r["country"] = cc
    r["check_digits"] = iban[2:4]
    r["length"] = len(iban)

    expected = IBAN_LENGTH.get(cc)
    if expected is None:
        r["checks"]["length"] = f"unverified — {cc} not in the bundled ISO 13616 length table"
    elif expected == len(iban):
        r["checks"]["length"] = f"pass — {len(iban)} chars, correct for {cc}"
    else:
        r["checks"]["length"] = f"fail — {len(iban)} chars, {cc} requires {expected}"

    rem = mod97(iban)
    r["checks"]["mod97"] = "pass" if rem == 1 else f"fail — remainder {rem}, must be 1"
    checksum_ok = rem == 1
    length_bad = expected is not None and expected != len(iban)
    r["valid"] = checksum_ok and not length_bad

    fields, mapped = decompose(iban, cc)
    r["bban_fields"] = fields
    r["bban_mapped"] = mapped
    if not mapped:
        r["bban_note"] = (f"BBAN structure for {cc} is not mapped in this build — checksum is "
                          f"still authoritative; decomposition unavailable")

    bank_code = fields.get("bank") or fields.get("sort_code")
    if bank_code:
        r["bank_code"] = bank_code
        name = (bank_db or {}).get((cc, bank_code.upper()))
        if name:
            r["bank_name"] = name
            r["bank_name_source"] = "--bank-db"
        else:
            r["bank_name"] = None
            r["bank_lookup"] = BANK_REGISTRY_HINT.get(
                cc, "national central-bank routing-code register, or a BIC directory lookup")

    if cc in ELEVATED_RISK_CC:
        r["risk_signals"].append(f"issuing jurisdiction {cc}: {ELEVATED_RISK_CC[cc]}")
    if expect_country and cc != expect_country.strip().upper():
        r["risk_signals"].append(
            f"jurisdiction mismatch — account issued in {cc}, subject/site presents as "
            f"{expect_country.strip().upper()} (classic mule/beneficiary-abroad pattern)")
    if checksum_ok and length_bad:
        r["risk_signals"].append(
            "checksum passes but length is wrong for the country — likely truncated in "
            "transcription, or a deliberately malformed number")

    if not checksum_ok:
        r["verdict"] = "INVALID — checksum failed; fabricated, mistyped or OCR-damaged"
    elif length_bad:
        r["verdict"] = "SUSPECT — checksum passes, country length does not"
    else:
        r["verdict"] = "VALID"
    return r


def render(r):
    L = []
    # verdicts carry an explanatory suffix, so key the icon on the leading word
    tick = {"VALID": "✅", "SUSPECT": "⚠️", "INVALID": "❌", "NOT": "❌"}
    L.append(f"{tick.get(r['verdict'].split()[0], '•')} {r['verdict']}   "
             f"{r.get('iban', r['input'])}")
    if r["verdict"] == "NOT AN IBAN":
        L.append(f"   structure : {r['checks']['structure']}")
        return "\n".join(L)
    L.append(f"   country   : {r['country']}    check digits: {r['check_digits']}    "
             f"length: {r['length']}")
    for k in ("structure", "length", "mod97"):
        L.append(f"   {k:<10}: {r['checks'][k]}")
    if r.get("bban_mapped"):
        parts = [f"{k}={v}" for k, v in r["bban_fields"].items() if k != "bban" and v]
        L.append(f"   BBAN      : {'  '.join(parts)}")
    else:
        L.append(f"   BBAN      : {r['bban_fields']['bban']}  ({r.get('bban_note', '')})")
    if r.get("bank_code"):
        if r.get("bank_name"):
            L.append(f"   bank      : {r['bank_name']}  (code {r['bank_code']}, "
                     f"via {r['bank_name_source']})")
        else:
            L.append(f"   bank code : {r['bank_code']}  — resolve via: {r['bank_lookup']}")
    for s in r["risk_signals"]:
        L.append(f"   ⚠ signal  : {s}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        description="Validate and decompose IBANs into CTI selectors (offline, ISO 13616/7064).")
    ap.add_argument("iban", nargs="*", help="one or more IBANs (spaces inside quotes are fine)")
    ap.add_argument("--batch", help="file with one IBAN per line")
    ap.add_argument("--bank-db", help="CSV country,bank_code,bank_name for bank-name resolution")
    ap.add_argument("--expect-country", help="ISO-3166 alpha-2 the subject claims — "
                                             "mismatch is flagged as a risk signal")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("-o", "--out", help="write output to a file")
    args = ap.parse_args()

    values = list(args.iban)
    if args.batch:
        with open(args.batch, encoding="utf-8") as f:
            values += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not values:
        ap.error("no IBAN given — pass values or --batch FILE")

    bank_db = load_bank_db(args.bank_db) if args.bank_db else None
    results = [analyze(v, bank_db, args.expect_country) for v in values]

    if args.json:
        text = json.dumps(results if len(results) > 1 else results[0],
                          ensure_ascii=False, indent=2)
    else:
        text = "\n\n".join(render(r) for r in results)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)

    n_bad = sum(1 for r in results if not r["valid"])
    print(f"iban_analyze: {len(results)} checked, {len(results) - n_bad} valid, {n_bad} not",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
