#!/usr/bin/env python3
"""phone_osint.py — decompose a phone number into the parts that are actually pivotable.

SKILL.md promised "carrier, line type, reputation, public associations". Carrier and line type
cannot be obtained for free: HLR/number-portability lookups are all metered, and a *guess* from a
prefix table is wrong often enough to mislead an investigation — Vietnamese, UK and US numbers
have all been ported across carriers for years. So this does the part that is deterministic and
free, and names the part that is not, rather than inventing it.

What it gives you: E.164 validation, country and region from the calling code, national-format
split, the messaging-app deep links a handle-hunt starts from, and the ready-to-run source-search
queries for finding the number quoted in a page (which is how a phone actually clusters scam
infrastructure — an operator reuses a contact number across a whole estate).

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
    "84": ("Vietnam", (9, 9)), "86": ("China", (11, 11)), "90": ("Turkey", (10, 10)),
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


def split_cc(digits):
    """Longest-prefix match — 1 must not shadow 1xx, and 8 must not shadow 84/86."""
    for n in (3, 2, 1):
        if digits[:n] in CC:
            return digits[:n], CC[digits[:n]]
    return None, (None, None)


def analyse(raw):
    s = raw.strip()
    had_plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)
    if not digits:
        return {"input": raw, "valid": False, "reason": "no digits"}
    if digits.startswith("00"):
        digits, had_plus = digits[2:], True

    cc, (territory, rng) = split_cc(digits)
    out = {"input": raw, "e164": "+" + digits, "digits": digits, "had_plus": had_plus}
    if not cc:
        out.update(valid=False,
                   reason="no recognised country calling code — supply the number in E.164 (+CC…)")
        return out

    nsn = digits[len(cc):]
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
        else:
            print(f"{r.get('e164', r['input'])}: INVALID — {r.get('reason')}", file=sys.stderr)
    print("  carrier / line type NOT determined (needs a metered lookup) — see not_determined",
          file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
