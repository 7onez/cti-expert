#!/usr/bin/env python3
"""Regression: `reference check <value>` without --type must find an entry that was `add`ed with
an EXPLICIT --type (#24).

WHAT THIS PROTECTS
------------------
`reference add --type email --value x@example.com --verdict signal` stores type="email". Before
this fix, `_infer_type()` only recognised a colon-prefixed synthetic indicator ('favicon:123') and
fell back to the literal string "keyword" for everything else — so `reference check x@example.com`
(no --type) inferred type="keyword", `check()` required an exact (value, type) match, and the
stored "email" entry never matched: a fresh, just-added entry read back UNKNOWN. The same bug hid
phone/domain/IP/hash lookups behind the same wall. This exercises every kind named in the ticket:
email, phone, domain, IP (v4 and v6, which also contains ':' — must not be misread as a
colon-prefixed indicator prefix), hash, and the pre-existing colon-prefixed shape ('favicon:123').
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools", "kb"))
import reference as R  # noqa: E402


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

    with tempfile.TemporaryDirectory() as kb:
        cases = [
            ("email", "x@example.com"),
            ("phone", "+18005550100"),
            ("domain", "sibling.example"),
            ("ip", "203.0.113.7"),
            ("ip", "2001:db8::1"),
            ("hash", "d41d8cd98f00b204e9800998ecf8427e"),
            ("favicon", "favicon:123456789"),
        ]
        for explicit_type, value in cases:
            R.upsert(kb, value, "signal", type_=explicit_type, label="test")
            inferred = R._infer_type(value)
            ok(inferred == explicit_type,
               f"_infer_type({value!r}) == {explicit_type!r} (got {inferred!r})")
            r = R.check(kb, value)   # no --type — must resolve to the SAME stored entry
            ok(r["known"] and r["verdict"] == "signal",
               f"reference check {value!r} (no --type) finds the {explicit_type} entry just added")

        # an unrelated value never becomes a false hit
        miss = R.check(kb, "totally-unseen-value-xyz")
        ok(not miss["known"], "an unseen value stays UNKNOWN")

        # explicit --type still overrides inference when the caller passes one
        r_explicit = R.check(kb, "x@example.com", type_="email")
        ok(r_explicit["known"], "an explicit --type still matches the stored entry")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
