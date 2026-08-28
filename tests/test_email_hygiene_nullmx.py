#!/usr/bin/env python3
"""RFC 7505 null MX must NOT count as a deliverable MX.

A domain publishing a single `0 .` MX record is stating that it accepts no mail.
Counting it as "has MX" inverts the signal: the domain that explicitly refuses
mail would grade A, the best score the tool can give. Pure/offline — the DoH
answer is supplied directly, so this never touches the network.
"""
import importlib.util
import pathlib
import sys

_p = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "webpivot" / "email_hygiene.py"
_s = importlib.util.spec_from_file_location("email_hygiene", _p)
eh = importlib.util.module_from_spec(_s)
_s.loader.exec_module(eh)


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def read(self):
        import json
        return json.dumps(self._p).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _lookup_with(answers, monkey_target=eh):
    """Run mx_lookup against a canned NOERROR DoH answer set."""
    import urllib.request
    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda *a, **k: _Resp({"Status": 0, "Answer": answers})
    try:
        return monkey_target.mx_lookup("d.example")
    finally:
        urllib.request.urlopen = orig


FAIL = []

# 1. RFC 7505 null MX — a PRESENT record meaning "no mail". Must be False.
if _lookup_with([{"type": 15, "data": "0 ."}]) is not False:
    FAIL.append("null MX '0 .' was treated as a deliverable MX")

# 2. A real MX must still be True — a fix that breaks this is worse than the bug.
if _lookup_with([{"type": 15, "data": "10 mail.d.example."}]) is not True:
    FAIL.append("a real MX record was not recognised")

# 3. Null MX alongside a real one: mail IS deliverable.
if _lookup_with([{"type": 15, "data": "0 ."},
                 {"type": 15, "data": "10 mail.d.example."}]) is not True:
    FAIL.append("a real MX was discarded because a null MX sat beside it")

# 4. NOERROR with no MX at all stays False.
if _lookup_with([]) is not False:
    FAIL.append("an empty answer set was not reported as 'no MX'")

# 5. The penalty actually reaches the score: no MX costs 30 points.
if eh.score_domain(False, True, False) - eh.score_domain(False, False, False) != 30:
    FAIL.append("mx_valid=False no longer carries the -30 penalty")

if FAIL:
    for f in FAIL:
        print(f"FAIL: {f}", file=sys.stderr)
    sys.exit(1)
print("email_hygiene null-MX: 5 checks passed")
