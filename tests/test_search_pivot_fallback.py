#!/usr/bin/env python3
"""search_pivot --run: free first, SerpApi only when the free path does not work.

Rails defended:
  1. a DuckDuckGo answer (results OR a genuine no-results page) never spends a SerpApi search;
  2. a DDG bot challenge sends THAT query to SerpApi; the next query still gets its own free try
     (DDG challenges per query — operator dorks — not per IP), so only failed queries are billed;
  3. `related:` (retired by Google) is neither fetched nor bought — reported NOT ANSWERED;
  4. free_only / no key / a SerpApi skip never spend, and the row says NOT ANSWERED (a gap, not a
     negative finding);
  5. the harness gate counts search_pivot as metered only with run=true and without free_only.
Synthetic data only: example.com / .example hosts. No network — both fetch seams are injected."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "harness"))

import search_pivot as sp  # noqa: E402

_HIT = ('<div class="result"><a rel="nofollow" class="result__a" '
        'href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fforum.example%2Ft%2F1&amp;rut=x">Forum '
        '<b>thread</b></a><a class="result__snippet" href="x">scam report about it</a></div>')
_NO_RESULTS = '<div class="no-results">No results.</div>'
_CHALLENGE = '<html><div class="anomaly-modal__title">Unfortunately, bots use DuckDuckGo too.</div></html>'


def _fetcher(pages):
    calls = []

    def fetch(url):
        calls.append(url)
        return pages[min(len(calls), len(pages)) - 1]
    return fetch, calls


def _serp(calls, out=None):
    def serp(q, num):
        calls.append(q)
        return out if out is not None else {"query": q, "results": [
            {"position": 1, "title": "t", "link": "https://paste.example/a", "host": "paste.example",
             "snippet": ""}]}
    return serp


def _keyword(n=None):
    return sp.search_pivot("ACME-PROMO-2026", kind="keyword") if n is None else \
        dict(sp.search_pivot("ACME-PROMO-2026", kind="keyword"),
             queries=sp.search_pivot("ACME-PROMO-2026", kind="keyword")["queries"][:n])


def test_ddg_answer_never_spends_serpapi():
    fetch, fcalls = _fetcher([(200, _HIT), (200, _NO_RESULTS)])
    scalls = []
    r = sp.run_queries(_keyword(2), fetch=fetch, serp=_serp(scalls), delay=0)
    assert scalls == [], scalls
    assert [x["via"] for x in r["executed"]] == ["duckduckgo", "duckduckgo"], r["executed"]
    first = r["executed"][0]["results"][0]
    assert first["link"] == "https://forum.example/t/1" and first["host"] == "forum.example", first
    assert first["snippet"] == "scam report about it", first
    assert r["executed"][1]["results"] == []           # a real no-results page is an answer
    assert r["execution_summary"]["serpapi_searches_spent"] == 0


def test_challenge_falls_back_only_for_the_challenged_query():
    fetch, fcalls = _fetcher([(202, _CHALLENGE), (200, _HIT), (202, _CHALLENGE)])
    scalls = []
    r = sp.run_queries(_keyword(3), fetch=fetch, serp=_serp(scalls), delay=0)
    assert len(fcalls) == 3, f"every query gets its own free attempt: {len(fcalls)} fetches"
    assert [x["via"] for x in r["executed"]] == ["serpapi", "duckduckgo", "serpapi"], r["executed"]
    assert len(scalls) == 2 and "challenge" in r["executed"][0]["free_failed"]
    assert r["found_hosts"] == ["forum.example", "paste.example"]
    assert r["execution_summary"]["serpapi_searches_spent"] == 2


def test_unrecognisable_page_is_a_free_failure_not_an_empty_answer():
    assert not sp.parse_ddg(200, "<html><body>changed layout</body></html>")["ok"]
    assert not sp.parse_ddg(503, _HIT)["ok"]
    # 0 hits on intext: (DDG ignores it) is a free-path failure; 0 hits on a plain string is an answer
    fetch, _ = _fetcher([(200, _NO_RESULTS)])
    scalls = []
    r0 = sp.search_pivot("site-a.example", kind="domain")
    iq = [q for q in r0["queries"] if q["q"].startswith("intext:")]
    assert iq, "domain dorks no longer carry an intext: query"
    r = sp.run_queries(dict(r0, queries=iq), fetch=fetch, serp=_serp(scalls), delay=0)
    assert r["executed"][0]["via"] == "serpapi" and "intext:" in r["executed"][0]["free_failed"]


def test_retired_related_operator_is_never_bought():
    r0 = sp.search_pivot("site-a.example", kind="domain")
    gq = [q for q in r0["queries"] if q["google_only_operator"]]
    assert gq, "domain dorks no longer carry a Google-only operator"
    fetch, fcalls = _fetcher([(200, _HIT)])
    scalls = []
    r = sp.run_queries(dict(r0, queries=gq), fetch=fetch, serp=_serp(scalls), delay=0)
    assert fcalls == [] and scalls == [], (fcalls, scalls)
    assert r["executed"][0]["via"] is None and "NOT ANSWERED" in r["executed"][0]["note"]


def test_free_only_and_skips_never_spend_and_say_not_answered():
    fetch, _ = _fetcher([(202, _CHALLENGE)])
    r = sp.run_queries(_keyword(2), free_only=True, fetch=fetch, delay=0)
    assert all(x["via"] is None and "NOT ANSWERED" in x["note"] for x in r["executed"]), r["executed"]
    assert r["executed"][0]["serpapi"] == "skipped: --free-only"
    fetch, _ = _fetcher([(202, _CHALLENGE)])
    scalls = []
    r = sp.run_queries(_keyword(1), fetch=fetch, delay=0,
                       serp=_serp(scalls, {"query": "q", "results": [], "skipped": "budget exhausted"}))
    assert r["executed"][0]["via"] is None and r["executed"][0]["serpapi"] == "budget exhausted"
    assert r["execution_summary"]["serpapi_searches_spent"] == 0


def test_gate_counts_search_pivot_as_metered_only_when_it_runs():
    import audit  # noqa: E402 — harness/audit.py, stdlib only
    assert "metered" not in audit.classify("search_pivot", {"indicator": "x"})
    assert "metered" in audit.classify("search_pivot", {"indicator": "x", "run": True})
    assert "metered" not in audit.classify("search_pivot", {"indicator": "x", "run": True,
                                                            "free_only": True})


_TESTS = [
    test_ddg_answer_never_spends_serpapi,
    test_challenge_falls_back_only_for_the_challenged_query,
    test_unrecognisable_page_is_a_free_failure_not_an_empty_answer,
    test_retired_related_operator_is_never_bought,
    test_free_only_and_skips_never_spend_and_say_not_answered,
    test_gate_counts_search_pivot_as_metered_only_when_it_runs,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001 — report every independent contract
            failed += 1
            lines.append(("FAIL", f"{label}: {exc!r}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
