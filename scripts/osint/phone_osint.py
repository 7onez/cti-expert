#!/usr/bin/env python3
"""phone_osint.py — decompose a phone number into the parts that are actually pivotable.

SKILL.md promised "carrier, line type, reputation, public associations". Carrier and line type
cannot be obtained for free: HLR/number-portability lookups are all metered, and a *guess* from a
prefix table is wrong often enough to mislead an investigation — Vietnamese, UK and US numbers
have all been ported across carriers for years. So this does the part that is deterministic and
free, and names the part that is not, rather than inventing it.

What it gives you: E.164 validation, country and region from the calling code, national-format
split, the messaging-app deep links a handle-hunt starts from (plus per-country ones such as Zalo
for +84, from `references/phone_osint.json -> messaging_extra`), the ORIGINAL prefix allocation
where the numbering plan is curated (`prefix_allocation`: the network a block was first assigned
to, always with a `ported_caveat` — it is NOT the carrier, which stays in `not_determined`), and
the ready-to-run source-search queries for finding the number quoted in a page (which is how a
phone actually clusters scam infrastructure — an operator reuses a contact number across a whole
estate).

Offline and deterministic unless --enrich is passed with a key.

Usage:
  phone_osint.py +84901234567
  phone_osint.py +442071838750 --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WP = os.path.normpath(os.path.join(HERE, "..", "..", "intel_engine", "WebPivot", "tools"))

# --- reference DATA (RULE 3): the conservative minimum is NO extra links and NO allocation table —
#     a missing file never invents an allocation, it just omits the block (loudly, on stderr).
_PO_FALLBACK = {"messaging_extra": {}, "messaging_notes": {}, "prefix_allocation": {}}


def _load_refs():
    try:
        if WP not in sys.path:
            sys.path.insert(0, WP)
        from wp_refs import load_ref, ref_path  # noqa: E402
        return load_ref(ref_path(__file__, "phone_osint.json"), _PO_FALLBACK)
    except Exception:  # noqa: BLE001 — loader missing: the conservative minimum, loudly
        print("[!] phone_osint.json not loaded — no extra links / prefix allocation", file=sys.stderr)
        return dict(_PO_FALLBACK)


_REFS = _load_refs()
MESSAGING_EXTRA = _REFS.get("messaging_extra") or {}
MESSAGING_NOTES = _REFS.get("messaging_notes") or {}
PREFIX_ALLOCATION = _REFS.get("prefix_allocation") or {}

# calling code -> (territory, national significant number length range)
CC = {
    "1": ("US/Canada (NANP)", (10, 10)), "7": ("Russia/Kazakhstan", (10, 10)),
    "20": ("Egypt", (9, 10)), "27": ("South Africa", (9, 9)),
    "30": ("Greece", (10, 10)), "31": ("Netherlands", (9, 9)), "32": ("Belgium", (8, 9)),
    "33": ("France", (9, 9)), "34": ("Spain", (9, 9)), "36": ("Hungary", (8, 9)),
    "39": ("Italy", (9, 11)), "40": ("Romania", (9, 9)), "41": ("Switzerland", (9, 9)),
    "43": ("Austria", (10, 13)), "44": ("United Kingdom", (10, 10)), "45": ("Denmark", (8, 8)),
    "46": ("Sweden", (7, 13)), "47": ("Norway", (8, 8)), "48": ("Poland", (9, 9)),
    "49": ("Germany", (10, 11)), "52": ("Mexico", (10, 10)), "55": ("Brazil", (10, 11)),
    "60": ("Malaysia", (9, 10)), "61": ("Australia", (9, 9)), "62": ("Indonesia", (9, 12)),
    "63": ("Philippines", (10, 10)), "64": ("New Zealand", (8, 10)), "65": ("Singapore", (8, 8)),
    "66": ("Thailand", (9, 9)), "81": ("Japan", (10, 10)), "82": ("South Korea", (9, 10)),
    "84": ("Vietnam", (9, 10)), "86": ("China", (11, 11)), "90": ("Turkey", (10, 10)),
    "91": ("India", (10, 10)), "92": ("Pakistan", (10, 10)), "95": ("Myanmar", (8, 10)),
    "212": ("Morocco", (9, 9)), "234": ("Nigeria", (10, 10)), "254": ("Kenya", (9, 9)),
    "351": ("Portugal", (9, 9)), "352": ("Luxembourg", (9, 9)), "353": ("Ireland", (9, 9)),
    "355": ("Albania", (9, 9)), "358": ("Finland", (9, 10)), "359": ("Bulgaria", (8, 9)),
    "370": ("Lithuania", (8, 8)), "371": ("Latvia", (8, 8)), "372": ("Estonia", (7, 8)),
    "380": ("Ukraine", (9, 9)), "385": ("Croatia", (8, 9)), "420": ("Czechia", (9, 9)),
    "421": ("Slovakia", (9, 9)), "852": ("Hong Kong", (8, 8)), "853": ("Macau", (8, 8)),
    "855": ("Cambodia", (8, 9)), "856": ("Laos", (9, 10)), "886": ("Taiwan", (9, 9)),
    "971": ("UAE", (9, 9)), "972": ("Israel", (9, 9)), "977": ("Nepal", (10, 10)),
}

# Calling codes whose leading 0 is PART of the national number (Italian landlines keep it in
# E.164: +39 06 …). Everywhere else in the table a leading 0 after the code is the domestic trunk
# prefix written by habit (+84 0912 …, +44 (0)20 …) and is dropped.
KEEPS_LEADING_ZERO = {"39"}


def split_cc(digits):
    """Longest-prefix match — 1 must not shadow 1xx, and 8 must not shadow 84/86."""
    for n in (3, 2, 1):
        if digits[:n] in CC:
            return digits[:n], CC[digits[:n]]
    return None, (None, None)


def prefix_allocation(cc, nsn):
    """The block this NSN falls in per the curated numbering plan (`prefix_allocation` in
    references/phone_osint.json) — the network the prefix was ORIGINALLY allocated to, never the
    current carrier. None when the country is not curated. Longest written prefix wins."""
    spec = PREFIX_ALLOCATION.get(cc)
    if not isinstance(spec, dict) or not nsn:
        return None
    written = str(spec.get("trunk") or "") + nsn
    lengths = spec.get("nsn_length") or {}
    best = None
    for net, prefixes in (spec.get("mobile") or {}).items():
        for p in prefixes or []:
            if written.startswith(p) and (best is None or len(p) > len(best[0])):
                best = (p, net)
    caveat = spec.get("ported_caveat")
    if best:
        p, net = best
        exp = lengths.get("mobile")
        return {"allocated_block": "mobile", "prefix": p, "originally_allocated_to": net,
                "mvno_host": (spec.get("mvno_host") or {}).get(net),
                "nsn_length_matches_block": (len(nsn) == exp) if exp else None,
                "ported_caveat": caveat}
    flp = spec.get("fixed_line_prefix")
    if flp and written.startswith(flp):
        area_code, area = None, None
        for code, name in (spec.get("fixed_line") or {}).items():
            if written.startswith(code) and (area_code is None or len(code) > len(area_code)):
                area_code, area = code, name
        exp = lengths.get("fixed_line")
        return {"allocated_block": "fixed_line", "prefix": area_code or written[:len(flp) + 1],
                "area": area, "originally_allocated_to": None,
                "nsn_length_matches_block": (len(nsn) == exp) if exp else None,
                "ported_caveat": spec.get("fixed_line_caveat") or caveat}
    return {"allocated_block": None, "prefix": written[:3], "originally_allocated_to": None,
            "note": "prefix not in the curated allocation table — unallocated, new, or "
                    "special-service; not evidence of invalidity",
            "ported_caveat": caveat}


def analyse(raw):
    s = raw.strip()
    had_plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)
    if not digits:
        return {"input": raw, "valid": False, "reason": "no digits"}
    if digits.startswith("00"):
        digits, had_plus = digits[2:], True
    if not had_plus:
        # No '+' or '00': the leading digits are a national number, not a calling code — reading
        # `469-555-1234` as +46 (Sweden) is a guess that misattributes the number.
        return {"input": raw, "e164": None, "digits": digits, "had_plus": False,
                "national_number": digits, "valid": None,
                "reason": "national number, country unknown — supply it in E.164 (+CC…) or "
                          "with the 00 international prefix"}

    cc, (territory, rng) = split_cc(digits)
    out = {"input": raw, "e164": "+" + digits, "digits": digits, "had_plus": had_plus}
    if not cc:
        out.update(valid=None,
                   reason="calling code not in this tool's table — territory and length "
                          "unchecked, not necessarily invalid")
        return out

    nsn = digits[len(cc):]
    if nsn.startswith("0") and cc not in KEEPS_LEADING_ZERO:
        # One trunk 0 — whether written bare (+84 0912 …) or bracketed (+44 (0)20 …).
        nsn = nsn[1:]
        digits = cc + nsn
        out.update(e164="+" + digits, digits=digits, trunk_prefix_stripped=True)
    lo, hi = rng
    length_ok = lo <= len(nsn) <= hi
    out.update(country_code=cc, territory=territory, national_number=nsn,
               national_length=len(nsn), expected_length=[lo, hi], valid=length_ok)
    if not length_ok:
        out["reason"] = (f"national number is {len(nsn)} digits; {territory} uses {lo}-{hi}. "
                         f"Either a typo, or not a {territory} number.")

    # What is NOT knowable for free — stated, not guessed.
    out["not_determined"] = {
        "carrier": "requires a metered HLR/portability lookup; a prefix guess is unreliable "
                   "because numbers are ported between carriers",
        "line_type": "same — mobile/landline/VoIP cannot be inferred safely from the prefix alone",
    }
    e = out["e164"]
    bare = digits
    out["messaging_links"] = {
        "whatsapp": f"https://wa.me/{bare}",
        "telegram": f"https://t.me/+{bare}",
        "viber": f"viber://chat?number=%2B{bare}",
    }
    trunk = str((PREFIX_ALLOCATION.get(cc) or {}).get("trunk") or "0")
    for name, tpl in (MESSAGING_EXTRA.get(cc) or {}).items():
        out["messaging_links"][name] = (str(tpl).replace("{digits}", bare)
                                        .replace("{national}", trunk + nsn).replace("{nsn}", nsn))
    if MESSAGING_NOTES.get(cc):
        out["messaging_note"] = MESSAGING_NOTES[cc]
    alloc = prefix_allocation(cc, nsn)
    if alloc:
        out["prefix_allocation"] = alloc
    # The real pivot: an operator reuses one contact number across an estate, so finding the
    # number quoted in page source clusters the estate.
    forms = {e, bare, nsn, f"{cc} {nsn}", f"0{nsn}"}
    out["source_search_queries"] = {
        "publicwww": [f'"{f}"' for f in sorted(forms) if len(f) >= 8][:5],
        "fofa": [f'body="{f}"' for f in sorted(forms) if len(f) >= 8][:5],
        "google": [f'"{f}"' for f in sorted(forms) if len(f) >= 8][:5],
        "note": ("search every written form — operators format the same number differently "
                 "across their sites, and matching only E.164 misses most of the estate"),
    }
    out["next"] = ["reverse-WHOIS by registrant phone (whois_enrich --reverse-phone)",
                   "search_pivot the number as a selector",
                   "intelx_search the number against leak corpora"]
    if cc == "84":
        out["next"].append(f"vn_corp --by-phone {trunk}{nsn} — companies registering this contact "
                           "number (a LEAD: accounting/agent numbers are shared across clients)")
    return out


def main():
    ap = argparse.ArgumentParser(description="Deterministic phone-number decomposition for OSINT.")
    ap.add_argument("numbers", nargs="+")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    res = [analyse(n) for n in a.numbers]
    out = {"results": res,
           "summary": {"total": len(res), "valid": sum(1 for r in res if r.get("valid"))}}
    for r in res:
        if r.get("valid"):
            print(f"{r['e164']}: {r['territory']} — NSN {r['national_number']} "
                  f"({r['national_length']} digits)", file=sys.stderr)
        elif r.get("valid") is None:
            print(f"{r.get('e164') or r['input']}: UNVERIFIED — {r.get('reason')}", file=sys.stderr)
        else:
            print(f"{r.get('e164') or r['input']}: INVALID — {r.get('reason')}", file=sys.stderr)
    print("  carrier / line type NOT determined (needs a metered lookup) — see not_determined",
          file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
