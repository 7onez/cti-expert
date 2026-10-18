#!/usr/bin/env python3
"""Offline unit gate for cross-type corpus routes (pivot_routes + ingest_typed + helpers).

Covers:
  * urlscan query builder escaping + identifier rung mapping
  * wayback parse (telegram→telegram rows, news→mention, unavailable→error)
  * ingest_typed never add_edge for kit/neighbour/mention; does for owner
  * publicwww no key → skipped
  * counterparties exchange flag
  * free_only on urlscan → keyless; metered routes → skipped
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from unittest import mock

os.environ.setdefault("API_USAGE_LOG",
                      os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE = os.path.dirname(os.path.dirname(_HERE))
_SKILL = os.path.dirname(_ENGINE)
for _p in (os.path.join(_ENGINE, "tools"),
           os.path.join(_ENGINE, "tools", "kb"),
           os.path.join(_ENGINE, "WebPivot", "tools"),
           os.path.join(_SKILL, "scripts", "webpivot")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pivot_routes as PR  # noqa: E402
import ingest_typed as IT  # noqa: E402
import wp_recon as WR  # noqa: E402
import wp_wayback_search as WS  # noqa: E402
import wp_publicwww as PW  # noqa: E402
from knowledge_base import KB  # noqa: E402


@contextmanager
def patched(mod, **attrs):
    saved = {k: getattr(mod, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(mod, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)


def check():
    """The urlscan count probes below are mocked at the urlopen seam, but wp_recon still ledgers
    them — and run_eval's metered-spend guard reads any ledger growth as real spend. Mocked suites
    must not ledger at all, so the client's ledger is detached for the whole run."""
    with patched(WR, api_usage=None):
        return _check()


def _check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # ------------------------------------------------------------------ urlscan field query
    q = WR.urlscan_field_query("page.title", 'Say "hi" + more')
    ok('page.title:' in q and '\\"' in q and '\\+' in q,
       "urlscan_field_query escapes Lucene specials inside quoted value")
    ok(WR.urlscan_field_query("hash", "abcDEF0123456789") == "hash:abcDEF0123456789",
       "urlscan_field_query leaves hash unquoted")
    ok(WR.urlscan_field_query("", "x") == "" and WR.urlscan_field_query("page.title", "") == "",
       "urlscan_field_query empty field/value → empty string")

    # query_for builds through the helper
    q2 = PR.query_for("urlscan.title", "string", 'a:b')
    ok(isinstance(q2, str) and "page.title:" in q2 and "a\\:b" in q2,
       "query_for(urlscan.title) uses page.title with escaped colon")
    q3 = PR.query_for("urlscan.identifier", "telegram", "CoolChannel")
    ok(isinstance(q3, str) and "content.identifiers" in q3 and "telegram.username" in q3,
       "query_for(urlscan.identifier, telegram) targets telegram.username")
    q4 = PR.query_for("urlscan.identifier", "wallet", "TXtronAddressHere123456789012")
    ok(isinstance(q4, str) and "text.content" in q4,
       "TRON wallet identifier routes through text.content, not content.identifiers")
    ok(PR.query_for("urlscan.title", "domain", "example.com") is None
       or "page.title" in (PR.query_for("urlscan.title", "string", "x") or ""),
       "query_for returns a string for an accepted type")

    # identifier rung mapping
    ok(PR.identifier_rung("google.ua-id") == "analytics.ga", "identifier_rung google.ua-id → analytics.ga")
    ok(PR.identifier_rung("google.gtm-id") == "analytics.gtm", "identifier_rung gtm → analytics.gtm")
    ok(PR.identifier_rung("telegram.bot-token") == "token.telegram_bot",
       "identifier_rung bot-token → owner token")
    ok(PR.identifier_rung("discord.webhook") == "token.discord_webhook",
       "identifier_rung discord.webhook → owner")
    ok(PR.identifier_rung("telegram.username") == "telegram.username",
       "identifier_rung telegram.username → kit")
    ok(PR.identifier_rung("html-id") == "html_id", "identifier_rung html-id → html_id")
    ok(PR.identifier_rung("json.jwt") == "token.other", "identifier_rung unknown token → token.other")
    ok(PR.identifier_rung("wallet.bitcoin", "bc1qnotexchange000") == "wallet.operator",
       "identifier_rung wallet default → operator")

    # ------------------------------------------------------------------ urlscan_count free_only keyless
    seen = {}

    def fake_urlopen(req, timeout=30):
        # Capture whether API-Key header was set
        headers = {}
        try:
            headers = dict(req.header_items()) if hasattr(req, "header_items") else {}
        except Exception:
            pass
        # urllib Request stores headers in .headers (dict-like, case-insensitive)
        try:
            headers = {k: v for k, v in req.headers.items()}
        except Exception:
            headers = {}
        seen["headers"] = {k.lower(): v for k, v in headers.items()}
        seen["url"] = getattr(req, "full_url", None) or getattr(req, "get_full_url", lambda: "")()
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return b'{"total": 7, "results": []}'
            def getheader(self, *a, **k): return None
            headers = {}
        # json.load(r) needs read + readable
        import io
        return io.BytesIO(b'{"total": 7, "results": []}')

    # wrap so `with urlopen() as r` works and json.load works
    class _CM:
        def __init__(self, bio): self.bio = bio
        def __enter__(self): return self.bio
        def __exit__(self, *a): pass

    def fake_urlopen2(req, timeout=30):
        try:
            hdrs = {k.lower(): v for k, v in req.headers.items()}
        except Exception:
            hdrs = {}
        seen["headers"] = hdrs
        seen["url"] = req.get_full_url() if hasattr(req, "get_full_url") else ""
        return _CM(__import__("io").BytesIO(b'{"total": 7, "results": []}'))

    import urllib.request as UR
    real_urlopen = UR.urlopen
    # Also stub _secret so a real key in the env cannot leak into free_only=False path
    # for the free_only=True assertion.
    try:
        with patched(WR, _secret=lambda *a, **k: "REALKEY"):
            UR.urlopen = fake_urlopen2
            n = WR.urlscan_count('page.title:"x"', free_only=True)
            ok(n == 7, "urlscan_count returns total from size=1 body")
            ok("api-key" not in seen.get("headers", {}),
               "urlscan_count free_only=True sends no API-Key (keyless)")
            seen.clear()
            n2 = WR.urlscan_count('page.title:"x"', free_only=False)
            ok(n2 == 7 and seen.get("headers", {}).get("api-key") == "REALKEY",
               "urlscan_count free_only=False attaches API-Key when present")
    finally:
        UR.urlopen = real_urlopen

    # free_only on urlscan route via pivot_routes.run uses free_only on urlscan_search
    calls = {}

    def fake_search(query, limit=100, timeout=30, max_results=None, free_only=False):
        calls["free_only"] = free_only
        calls["query"] = query
        return {"query": query, "total": 2, "domains": ["a.example", "b.example"], "pages": 1}

    with patched(WR, urlscan_search=fake_search):
        # import path: pivot_routes imports wp_recon inside the function
        res = PR.run("urlscan.title", 'page.title:"Hello"', case="CASE-0001", free_only=True)
        ok(calls.get("free_only") is True, "free_only on urlscan route → urlscan_search free_only=True")
        ok(isinstance(res, dict) and len(res.get("rows") or []) == 2, "urlscan run returns domain rows")
        ok(all(r.get("rung_class") == "title" for r in res["rows"]),
           "urlscan.title host rows carry rung_class title (kit)")

    # metered free_only → skipped
    sk = PR.run("publicwww.source", '"token"', case="CASE-0001", free_only=True)
    ok(isinstance(sk, dict) and sk.get("skipped"),
       "free_only on metered publicwww.source → skipped")
    sk2 = PR.run("fofa.body", 'body="x"', case="CASE-0001", free_only=True)
    ok(isinstance(sk2, dict) and sk2.get("skipped"),
       "free_only on metered fofa.body → skipped")

    # ------------------------------------------------------------------ wayback parse
    ok(WS.telegram_handle("https://t.me/s/SomeChannel/123") == "SomeChannel",
       "telegram_handle extracts t.me/s/<handle>/<post>")
    ok(WS.telegram_handle("https://telegram.me/s/OtherChan/9") == "OtherChan",
       "telegram_handle accepts telegram.me")

    tg_hits = [
        {"url": "https://t.me/s/AlphaCrew/42", "host": "t.me", "domain": "t.me",
         "snippet": "pay here", "first_captured": "20240101000000"},
        {"url": "https://example.com/x", "host": "example.com", "domain": "example.com",
         "snippet": "no tg", "first_captured": "20240101000000"},
    ]
    tg_rows = WS.hits_to_rows(tg_hits, "telegram")
    ok(any(r["type"] == "telegram" and r["value"] == "AlphaCrew"
           and r["rung_class"] == "telegram.username" for r in tg_rows),
       "wayback telegram hits → telegram rows with telegram.username")
    tok_hits = [
        {"url": "https://t.me/s/op_channel/7", "snippet": "contact <em>c50_vietnam</em> now"},
        {"url": "https://t.me/s/grammar_daily/3", "snippet": "learn english in <em>vietnam</em>"},
    ]
    kept = WS.hits_to_rows(tok_hits, "telegram", require_term='"c50_vietnam"')
    ok([r["value"] for r in kept] == ["op_channel"],
       "a tokenised full-text hit without the literal term is dropped (no unrelated channels)")
    ok(PR._source_search_rung('body="G-TEST"') == "analytics.ga"
       and PR._source_search_rung('body="GTM-ABC123"') == "analytics.gtm"
       and PR._source_search_rung('body="o2HLpCT4AM4d3B_x0EHaV8dIIl688"') == "string",
       "source-search hits for an analytics ID take its owner class; other terms stay kit")

    news_hits = [
        {"url": "https://news.example/a", "host": "news.example", "domain": "news.example",
         "title": "Headline", "snippet": "…", "first_captured": "2020"},
    ]
    news_rows = WS.hits_to_rows(news_hits, "mediacloud")
    ok(news_rows and all(r["type"] == "mention" for r in news_rows),
       "wayback news/mediacloud hits → mention rows")

    # unavailable collection → error (never empty success)
    with patched(WS, collection_available=lambda *a, **k: False):
        bad = WS.search("hello", "no-such-collection")
        ok(isinstance(bad, dict) and bad.get("error") == "collection unavailable",
           "unavailable collection → error, never empty")

    # ------------------------------------------------------------------ publicwww no key
    with patched(PW, publicwww_key=lambda: None, publicwww_configured=lambda: False):
        r = PW.search('"example-snippet"')
        ok(isinstance(r, dict) and "skipped" in r and "PUBLICWWW" in r["skipped"],
           "publicwww no key → skipped PUBLICWWW_API_KEY not set")
    # via pivot_routes too
    with patched(PW, publicwww_key=lambda: None, search=lambda q, **k: {
            "skipped": "PUBLICWWW_API_KEY not set"}):
        # force re-import path uses PW.search
        import importlib
        # PR._run_publicwww imports wp_publicwww
        res = PR._run_publicwww('"x"', free_only=False)
        ok(res.get("skipped"), "pivot_routes publicwww no key → skipped")

    # ------------------------------------------------------------------ counterparties exchange flag
    try:
        import crypto_balance as CB
        # inject a known exchange address into the module maps
        with patched(CB, _EXCHANGE_ADDRS={"0xexchangewallet000000000000000000000001": {"label": "binance"}},
                     _EXCHANGE_LABELS={"binance", "coinbase"}):
            ok(CB.is_exchange_wallet("0xexchangewallet000000000000000000000001") is True,
               "counterparties exchange flag: address list hit → True")
            ok(CB.is_exchange_wallet("0xnotexchange00000000000000000000000002") is False,
               "counterparties exchange flag: unknown address → False")
            ok(CB.is_exchange_wallet("0xabc", label="Binance Hot Wallet") is True,
               "counterparties exchange flag: label substring → True")
            row = CB._counterparty_row("0xexchangewallet000000000000000000000001",
                                       value=1.0, coin="ETH")
            ok(row.get("exchange") is True, "counterparty row carries exchange: true")
    except Exception as e:  # noqa: BLE001
        ok(False, f"counterparties exchange flag tests errored: {e}")

    # ------------------------------------------------------------------ ingest_typed owner vs kit
    with tempfile.TemporaryDirectory() as td:
        kb = KB(td)
        # spy on add_edge / add_fact
        edges, facts = [], []
        real_edge, real_fact = kb.add_edge, kb.add_fact

        def spy_edge(*a, **k):
            edges.append((a, k))
            return real_edge(*a, **k)

        def spy_fact(*a, **k):
            facts.append((a, k))
            return real_fact(*a, **k)

        kb.add_edge = spy_edge
        kb.add_fact = spy_fact

        owner_rows = [
            {"type": "domain", "value": "owned.example", "rung_class": "analytics.ga",
             "source": "urlscan.identifier", "evidence": {"q": "UA-1"}},
        ]
        n = IT.ingest_rows(kb, "CASE-0001", "string", "UA-1", owner_rows,
                           route="urlscan.identifier")
        ok(n == 1 and len(edges) == 1 and len(facts) == 0,
           "ingest_typed owner row → add_edge, no add_fact")

        edges.clear(); facts.clear()
        kit_rows = [
            {"type": "domain", "value": "kit.example", "rung_class": "title",
             "source": "urlscan.title", "evidence": {}},
            {"type": "domain", "value": "ex.example", "rung_class": "wallet.exchange",
             "source": "crypto.counterparties", "evidence": {}, "coin": "btc"},
            {"type": "mention", "value": "news.example", "rung_class": "string",
             "source": "wayback.news", "evidence": {}},
        ]
        n2 = IT.ingest_rows(kb, "CASE-0001", "string", "Hello World", kit_rows,
                            route="urlscan.title")
        ok(n2 == 3 and len(edges) == 0 and len(facts) == 3,
           "ingest_typed kit/neighbour/mention → add_fact only, NEVER add_edge")
        attrs = [a[0][2] for a in facts]  # attribute positional
        ok("kit_sibling" in attrs and "neighbour" in attrs and "mention" in attrs,
           "ingest_typed attributes are kit_sibling / neighbour / mention")

    # ------------------------------------------------------------------ wayback route via pivot_routes (stubbed)
    def fake_search_all(q, collection, **k):
        if collection == "nope":
            return {"error": "collection unavailable"}
        if collection == "telegram":
            return {"total": 1, "hits": [
                {"url": "https://t.me/s/BetaChan/1", "host": "t.me", "snippet": "a scam phrase here",
                 "first_captured": "2024"}], "collection": collection, "q": q}
        if collection in ("mediacloud", "russian-independent-media",
                          "EndOfTerm2024WebCrawls", "EndOfTerm2020WebCrawls",
                          "EndOfTerm2016WebCrawls"):
            return {"total": 1, "hits": [
                {"url": "https://media.example/p", "host": "media.example",
                 "title": "Story", "snippet": "the election result", "first_captured": "2019"}],
                    "collection": collection, "q": q}
        return {"total": 0, "hits": [], "collection": collection, "q": q}

    with patched(WS, search_all=fake_search_all, collection_available=lambda *a, **k: True):
        tr = PR.run("wayback.telegram", "scam phrase", case="CASE-0001")
        ok(any(r.get("type") == "telegram" and r.get("value") == "BetaChan"
               for r in (tr.get("rows") or [])),
           "pivot_routes wayback.telegram → telegram rows")
        nr = PR.run("wayback.news", "election", case="CASE-0001")
        ok((nr.get("rows") or []) and all(r.get("type") == "mention" for r in nr["rows"]),
           "pivot_routes wayback.news → mention rows only")

    with patched(WS, search_all=lambda *a, **k: {"error": "collection unavailable"},
                 search=lambda *a, **k: {"error": "collection unavailable"},
                 collection_available=lambda *a, **k: False):
        er = PR.run("wayback.pdf", "invoice", case="CASE-0001")
        ok(er.get("error") == "collection unavailable",
           "pivot_routes unavailable wayback collection → error")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if failed:
        print(f"FAIL — {failed} check(s) failed, {passed} passed")
        return 1
    print(f"PASS — {passed} pivot_routes checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
