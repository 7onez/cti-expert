#!/usr/bin/env python3
"""Regression: `query.py --entity` reports an explicit miss and normalises the lookup (#25).

WHAT THIS PROTECTS
------------------
Before this fix, `--entity` did an exact string match against KB entity values and printed
NOTHING on a miss — a typo'd case, a leading `https://`, a trailing dot, or a `www.` prefix the KB
never stored made the command silently produce zero output, indistinguishable from a slow tool or
a broken pipe. This exercises: (1) an explicit "not in KB: <value> (KB has N entities)" line on a
genuine miss, (2) a scheme/path/trailing-dot/case variant of an entity the KB DOES hold resolves to
it, (3) a bare-apex value still resolves an entity the KB stored under `www.<apex>` and vice versa.
"""
import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
sys.path.insert(0, os.path.join(ENGINE, "tools", "kb"))
import query as Q  # noqa: E402
from knowledge_base import KB  # noqa: E402


def _argv_entity(value, kbdir):
    return ["query.py", "--kb", kbdir, "--entity", value]


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

    with tempfile.TemporaryDirectory() as tmp:
        kbdir = os.path.join(tmp, "knowledge")
        kb = KB(kbdir)
        kb.add_fact("domain", "seed.example", "title", "Example", "webpivot", "webpivot",
                    "2026-01-01T00:00:00+00:00", "high")
        kb.add_fact("domain", "www.other.example", "title", "Other", "webpivot", "webpivot",
                    "2026-01-01T00:00:00+00:00", "high")

        # 1) normalisation helpers directly
        ok(Q._normalize_entity_value("HTTPS://Seed.Example/path?q=1.") == "seed.example",
           "scheme/path/case/trailing-dot stripped")
        variants = Q._entity_variants("https://WWW.Other.Example/")
        ok("other.example" in variants and "www.other.example" in variants,
           "www./bare-apex variants both offered")

        # 2) an exact-miss value reports the explicit not-in-KB line, not silence
        buf = io.StringIO()
        old_argv = sys.argv
        n_entities = len(list(kb.all_entities()))
        try:
            sys.argv = _argv_entity("nothing-like-this.invalid", kbdir)
            with redirect_stdout(buf):
                Q.main()
        finally:
            sys.argv = old_argv
        out = buf.getvalue()
        ok(f"not in KB: nothing-like-this.invalid (KB has {n_entities} entities)" in out,
           "an explicit miss line is printed with the KB size")

        # 3) a scheme+trailing-dot+case variant of a KB entity resolves via normalisation
        buf = io.StringIO()
        try:
            sys.argv = _argv_entity("HTTPS://Seed.Example./", kbdir)
            with redirect_stdout(buf):
                Q.main()
        finally:
            sys.argv = old_argv
        out = buf.getvalue()
        ok("# domain: seed.example" in out, "normalised scheme/case/trailing-dot variant resolves")
        ok("not in KB" not in out, "a resolved entity does not ALSO print the miss line")

        # 4) a bare apex resolves an entity the KB stored under www.<apex>
        buf = io.StringIO()
        try:
            sys.argv = _argv_entity("other.example", kbdir)
            with redirect_stdout(buf):
                Q.main()
        finally:
            sys.argv = old_argv
        out = buf.getvalue()
        ok("# domain: www.other.example" in out,
           "bare apex resolves the KB's www.-prefixed entity via the www./apex variant")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
