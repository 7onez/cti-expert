#!/usr/bin/env python3
"""Gate for reverse-WHOIS-by-PHONE + the preview-first / confirm-if-large behavior.

  L1 whois_enrich.reverse_whois  — kind='phone' builds the right API payload (term + mode)
  L2 ingest_reverse_whois        — PREVIEWS first; a > --max-domains phone trips the bulk guard
                                   and NEVER purchases; a small count previews THEN purchases+links
  L3 tools._reverse_gate         — the 'preview first, ask if it's a lot' decision (venv-only:
                                   needs claude_agent_sdk; skipped under system python3)
Deterministic — all network/API calls are monkeypatched. Run standalone or via run_eval.py.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
import whois_enrich as we          # noqa: E402
import ingest_reverse_whois as ing  # noqa: E402


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    # --- L1: kind='phone' produces a correct reverse-WHOIS API call ---
    cap = {}
    _key0, _post0 = we._key, we._post_json
    try:
        we._key = lambda: "FAKEKEY"
        we._post_json = lambda url, payload, timeout=40: (
            cap.update(url=url, payload=payload)
            or {"domainsCount": 3, "domainsList": [{"domainName": "a.example"}, {"domainName": "b.example"}]})
        r = we.reverse_whois("+15551234567", "phone", mode="preview")
        ok(cap["payload"]["basicSearchTerms"]["include"] == ["+15551234567"], "L1 phone term in payload")
        ok(cap["payload"]["mode"] == "preview", "L1 preview mode forwarded")
        ok(r and r.get("kind") == "phone" and r.get("count") == 3, "L1 phone result parsed")
    finally:
        we._key, we._post_json = _key0, _post0

    # --- L2: ingest previews first; bulk phone trips the guard and never purchases ---
    calls = []

    def fake_rev(term, kind, search_type="historic", mode="purchase", **kw):
        calls.append((mode, kind))
        if mode == "preview":
            return {"count": 9999, "domains": []}          # huge → must trip the guard
        return {"count": 9999, "domains": ["x.example"]}   # purchase MUST NOT be reached

    _rev0 = ing.whois_enrich.reverse_whois
    _argv0 = sys.argv
    try:
        ing.whois_enrich.reverse_whois = fake_rev
        sys.argv = ["ing", "--kb", tempfile.mkdtemp(), "--phone", "+15551234567", "--max-domains", "200"]
        try:
            ing.main()
        except SystemExit:
            pass
        ok(("preview", "phone") in calls, "L2 bulk: preview ran first")
        ok(("purchase", "phone") not in calls, "L2 bulk: guard blocked the purchase (no credits spent)")

        # small count → preview THEN purchase THEN link into a 'phone' entity
        calls.clear()

        def fake_rev_small(term, kind, search_type="historic", mode="purchase", **kw):
            calls.append((mode, kind))
            if mode == "preview":
                return {"count": 2, "domains": []}
            return {"count": 2, "domains": ["a.example", "b.example"]}

        ing.whois_enrich.reverse_whois = fake_rev_small
        kbdir = tempfile.mkdtemp()
        sys.argv = ["ing", "--kb", kbdir, "--phone", "+15551234567"]
        try:
            ing.main()
        except SystemExit:
            pass
        ok(calls == [("preview", "phone"), ("purchase", "phone")], "L2 small: preview then purchase")
        edges = os.path.join(kbdir, "relationships", "edges.jsonl")
        body = open(edges, encoding="utf-8").read() if os.path.exists(edges) else ""
        ok('"phone"' in body and "a.example" in body, "L2 small: linked domains → phone entity")
    finally:
        ing.whois_enrich.reverse_whois = _rev0
        sys.argv = _argv0

    # --- L3: the confirm-gate decision (harness helper; needs the SDK venv) ---
    try:
        sys.path.insert(0, os.path.join(ROOT, "harness"))
        import tools as htools        # noqa: E402  (imports claude_agent_sdk)
        g = htools._reverse_gate
        ok(g("phone", 0, 150, False)[0] == "empty", "L3 count 0 → empty")
        act, reason = g("phone", 5000, 150, False)
        ok(act == "confirm" and "5000" in reason, "L3 large + no confirm → ask (count in message)")
        ok(g("phone", 5000, 150, True)[0] == "purchase", "L3 large + confirm=true → purchase")
        ok(g("email", 12, 150, False)[0] == "purchase", "L3 small → purchase")
        ok(g("name", 151, 150, False)[0] == "confirm", "L3 just over cap → ask")
        ok(g("name", 150, 150, False)[0] == "purchase", "L3 at cap (not >) → purchase")
    except ImportError:
        out.append(("skip", "L3 _reverse_gate skipped — needs the SDK venv (verified separately)"))

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
