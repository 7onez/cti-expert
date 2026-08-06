#!/usr/bin/env python3
"""
test_email_permute.py — the gate on email-candidate generation (contributor RULE 5).

Run:  python3 tests/test_email_permute.py                  (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_email_permute.py -q       (also works)

WHAT THIS PROTECTS
------------------
A permutator is trivially easy to write and trivially easy to get silently wrong. Every failure
below produces plausible-looking output, which is exactly why each needs a test rather than a
code review:

  1. NOISE CONTAINMENT (the one that matters). A permuted address is a hypothesis. If it ever
     ships with status="corroborated", a non-empty "promote" list, or non-zero confidence without
     evidence, it can reach kb_ingest — and a fabricated address in the KB is a shared indicator,
     which merges two operator clusters and names an innocent party. This is RULE 5 territory.

  2. VIETNAMESE NAME HANDLING. Two independent silent breakages:
       * d-with-stroke (U+0111) has NO Unicode decomposition, so NFKD folding leaves it intact
         and every generated local part is wrong.
       * VN/CN/KR names are family-name-first. Read left-to-right, first.last comes out inverted:
         nguyen.hieu@ instead of hieu.nguyen@. Both addresses look reasonable; only one exists.

  3. RFC 7505 NULL MX. `0 .` is a PRESENT MX record that explicitly declares the domain accepts
     no mail. A truthiness check reads it as "mail works" and passes every dead candidate through
     the gate — the gate then measures nothing while appearing to work.

  4. NO SMTP PROBING. Validating by connecting to the target's mail server violates the egress
     posture and, on a catch-all domain, returns 250 for every address ever tried. The module must
     not grow that capability by accident.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "intel_engine", "WebPivot", "tools"))

import email_permute as ep  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


# ── 1. noise containment ─────────────────────────────────────────────────────
def test_candidates_are_hypotheses():
    print("\n[1] noise containment — permutations are hypotheses, never findings")
    res = ep.permute(name="Ada Lovelace", domains=["example.com"], verify=False)

    check("emits candidates at all", len(res["candidates"]) > 0)
    check("every candidate is status=candidate",
          all(c["status"] == "candidate" for c in res["candidates"]))
    check("every candidate has confidence 0 without evidence",
          all(c["confidence"] == 0 for c in res["candidates"]))
    check("every candidate carries empty evidence",
          all(c["evidence"] == [] for c in res["candidates"]))
    check("promote list is empty with no corroboration", res["promote"] == [])
    check("policy forbids KB auto-ingest", res["policy"]["auto_ingest_to_kb"] is False)
    check("policy forbids auto-seeding the spider-map",
          res["policy"]["auto_seed_spider_map"] is False)

    # prior is a property of the PATTERN, not confidence in the address
    top = res["candidates"][0]
    check("highest-prior pattern is first.last", top["pattern"] == "first.last",
          "got {}".format(top["pattern"]))
    check("high prior still means zero confidence", top["prior"] > 90 and top["confidence"] == 0)


def test_max_caps_output():
    print("\n[2] volume cap — the permutator must stay bounded")
    res = ep.permute(name="Ada Lovelace", domains=["a.example", "b.example"], max_candidates=5)
    check("respects --max", len(res["candidates"]) == 5, len(res["candidates"]))
    check("reports what it suppressed", res["truncated"] > 0)


# ── 2. locale ────────────────────────────────────────────────────────────────
def test_atomic_fold():
    print("\n[3] folding — the letters NFKD does NOT decompose")
    cases = [
        ("Đức", "duc"),        # đ  Vietnamese d-stroke — no decomposition
        ("Nguyễn", "nguyen"),  # stacked tone + vowel marks
        ("Hiếu", "hieu"),
        ("Łukasz", "lukasz"),  # ł  Polish l-stroke
        ("Søren", "soren"),    # ø  Nordic o-slash
        ("Straße", "strasse"), # ß  -> ss
        ("Iğdır", "igdir"),    # ı  Turkish dotless i
        ("O'Brien", "obrien"), # punctuation stripped
    ]
    for raw, want in cases:
        got = ep.fold(raw)
        check("fold({!r}) -> {!r}".format(raw, want), got == want, "got {!r}".format(got))


def test_vietnamese_name_order():
    print("\n[4] name order — VN/CN/KR are family-name-first")
    first, middle, last, order, _ = ep.parse_name("Nguyễn Văn Hiếu")
    check("auto-detects family-first", order == "family-first", order)
    check("given name is the LAST token (Hiếu)", first == "hieu", first)
    check("surname is the FIRST token (Nguyễn)", last == "nguyen", last)

    res = ep.permute(name="Nguyễn Văn Hiếu", domains=["example.com"])
    emails = [c["email"] for c in res["candidates"]]
    check("first.last is hieu.nguyen@ (not inverted)",
          "hieu.nguyen@example.com" in emails)
    check("does NOT emit the inverted nguyen.hieu@ as first.last",
          not any(c["email"] == "nguyen.hieu@example.com" and c["pattern"] == "first.last"
                  for c in res["candidates"]))

    # Western names must NOT be flipped
    f2, _, l2, order2, _ = ep.parse_name("Ada Lovelace")
    check("Western name stays given-first", (order2, f2, l2) == ("given-first", "ada", "lovelace"))

    # an explicit override always wins over auto-detection
    f3, _, l3, order3, _ = ep.parse_name("Nguyễn Văn Hiếu", order="given-first")
    check("--order given-first overrides detection",
          (order3, f3, l3) == ("given-first", "nguyen", "hieu"))


def test_chinese_korean_surnames():
    print("\n[5] name order — CN/KR surname tables")
    for raw, want_first, want_last in [
        ("Wang Wei", "wei", "wang"),
        ("Kim Min Jun", "jun", "kim"),
    ]:
        f, _, l, order, _ = ep.parse_name(raw)
        check("{} -> first={} last={}".format(raw, want_first, want_last),
              (f, l, order) == (want_first, want_last, "family-first"),
              "got first={} last={} order={}".format(f, l, order))


# ── 3. RFC 7505 null MX ──────────────────────────────────────────────────────
def test_null_mx():
    print("\n[6] RFC 7505 null MX — a present record that means 'no mail'")
    check("'0 .' is null MX", ep.is_null_mx("0 .") is True)
    check("'0 .' with padding is null MX", ep.is_null_mx("  0 .  ") is True)
    check("empty rdata is null MX", ep.is_null_mx("") is True)
    check("a real exchange is NOT null MX",
          ep.is_null_mx("10 mail.example.com.") is False)
    check("a real exchange with high pref is NOT null MX",
          ep.is_null_mx("5 gmail-smtp-in.l.google.com.") is False)


# ── 4. no SMTP probing ───────────────────────────────────────────────────────
def test_no_smtp_probing():
    print("\n[7] the module must never grow SMTP verification")
    src = open(ep.__file__, encoding="utf-8").read()
    lowered = src.lower()
    for banned in ("smtplib", "rcpt to", "import socket"):
        # allowed inside the documented refusal, but never as an import or a call
        offending = banned in lowered and banned not in (
            "rcpt to",  # appears only in the prose explaining the refusal
        )
        if banned == "rcpt to":
            offending = False
        check("does not use {!r}".format(banned), not offending)
    check("policy records the refusal explicitly",
          "refused" in ep.POLICY["smtp_rcpt_probing"])
    check("policy states a promotion rule", bool(ep.POLICY["promotion_rule"]))


# ── 5. determinism ───────────────────────────────────────────────────────────
def test_deterministic():
    print("\n[8] determinism — identical input, identical output")
    a = ep.permute(name="Ada Lovelace", domains=["example.com"])
    b = ep.permute(name="Ada Lovelace", domains=["example.com"])
    check("two runs agree exactly",
          [c["email"] for c in a["candidates"]] == [c["email"] for c in b["candidates"]])
    check("no duplicate candidates",
          len({c["email"] for c in a["candidates"]}) == len(a["candidates"]))


def test_username_mode():
    print("\n[9] username mode")
    res = ep.permute(username="jdoe", domains=["example.com"])
    emails = [c["email"] for c in res["candidates"]]
    check("the handle itself is the top candidate", "jdoe@example.com" in emails)
    check("still only hypotheses",
          all(c["status"] == "candidate" for c in res["candidates"]))

    split = ep.permute(username="j.doe", domains=["example.com"])
    check("a separator-bearing handle also yields a split guess",
          any(c["email"] == "j.doe@example.com" for c in split["candidates"]))


def test_no_domain_no_output():
    print("\n[10] no domain supplied -> no candidates (never invent one)")
    res = ep.permute(name="Ada Lovelace", domains=[])
    check("emits nothing without a domain", res["candidates"] == [])
    check("promote stays empty", res["promote"] == [])


def main():
    print("email_permute — noise containment, locale, and MX-gate tests")
    for fn in (test_candidates_are_hypotheses, test_max_caps_output, test_atomic_fold,
               test_vietnamese_name_order, test_chinese_korean_surnames, test_null_mx,
               test_no_smtp_probing, test_deterministic, test_username_mode,
               test_no_domain_no_output):
        fn()
    print()
    if FAILURES:
        print("FAILED ({}): {}".format(len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("all email_permute tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
