#!/usr/bin/env python3
"""search_pivot — multi-engine search-engine pivot queries for an indicator.

Generalizes fallback_probe.dorks() from a domain to ANY indicator (domain, slogan, tracking ID,
wallet, Telegram/Zalo handle) and from Google-only to a switchable engine set (Google / Yandex /
DuckDuckGo / Bing / Brave). It emits READY-TO-OPEN, URL-encoded result URLs plus the raw queries —
it deliberately does NOT scrape SERPs (bot-walled + fragile); the analyst, or Claude Code's own
WebSearch / WebFetch, fires them. This is the same "runnable pivot query" contract as the rest of
WebPivot.

Why multiple engines: they index DIFFERENT corners — Google for dork operators, Yandex for
Cyrillic / reverse-image / RU-CIS infra, DuckDuckGo for a fetch-friendly HTML endpoint (the one an
automated WebFetch can actually read without a bot-wall). Firing the same keyword across all of them
surfaces off-infrastructure mentions (forums, complaints, pastebin, social) that FOFA/PublicWWW —
which only see served HTML — never index.

CLI:
    python3 tools/search_pivot.py "<indicator>" [--engines google,yandex,duckduckgo,bing,brave]
                                                 [--kind domain|keyword] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse

# Result-URL bases. duckduckgo -> the HTML endpoint, which (unlike google/yandex) a plain WebFetch
# can read; the others bot-wall automated fetches, so fire those via WebSearch, not WebFetch.
ENGINES: dict[str, str] = {
    "google": "https://www.google.com/search?q=",
    "yandex": "https://yandex.com/search/?text=",
    "duckduckgo": "https://html.duckduckgo.com/html/?q=",
    "bing": "https://www.bing.com/search?q=",
    "brave": "https://search.brave.com/search?q=",
}
FETCH_FRIENDLY = {"duckduckgo"}          # engines a plain WebFetch can actually read
DEFAULT_ENGINES = ["google", "yandex", "duckduckgo"]

# Google-family operators not honored everywhere: related: is Google-only; site:/intext:/-site: are
# honored by google/bing/duckduckgo/yandex well enough to emit. We tag operator queries so a caller
# firing them on a weak engine knows why a query may return nothing.
_GOOGLE_ONLY_OP = re.compile(r"\brelated:")


def _looks_like_domain(s: str) -> bool:
    s = s.strip().strip("/").lower()
    return bool(re.match(r"^(?:https?://)?[a-z0-9.-]+\.[a-z]{2,}$", s)) and " " not in s


def _host(s: str) -> str:
    s = s.strip()
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc or s
    return s.split("/")[0].strip().lower()


def _domain_queries(d: str) -> list[tuple[str, str]]:
    """(label, query) tuned for a DOMAIN — footprint + off-site mentions + fraud context."""
    return [
        ("crawl footprint", f"site:{d}"),
        ("off-site mentions", f'"{d}" -site:{d}'),
        ("fraud context", f'intext:"{d}" (scam OR phishing OR fake OR fraud OR "lừa đảo")'),
        ("chat handles", f'"{d}" (telegram OR t.me OR zalo OR whatsapp)'),
        ("paste/code leaks", f'(site:pastebin.com OR site:github.com) "{d}"'),
        ("similar sites", f"related:{d}"),
    ]


def _keyword_queries(k: str) -> list[tuple[str, str]]:
    """(label, query) tuned for an ARBITRARY indicator — slogan, tracking ID, wallet, handle."""
    return [
        ("exact string", f'"{k}"'),
        ("fraud/review context",
         f'"{k}" (scam OR phishing OR fake OR fraud OR "lừa đảo" OR review OR complaint)'),
        ("chat handles", f'"{k}" (telegram OR t.me OR zalo OR whatsapp)'),
        ("paste/code/social", f'(site:pastebin.com OR site:github.com OR site:t.me) "{k}"'),
    ]


def _url(engine: str, query: str) -> str:
    return ENGINES[engine] + urllib.parse.quote_plus(query)


def search_pivot(indicator: str, engines: list[str] | None = None,
                 kind: str | None = None) -> dict:
    """Build the multi-engine pivot query set for `indicator`. Pure/deterministic; no network."""
    engines = [e for e in (engines or DEFAULT_ENGINES) if e in ENGINES] or DEFAULT_ENGINES
    if kind not in ("domain", "keyword"):
        kind = "domain" if _looks_like_domain(indicator) else "keyword"
    ind = _host(indicator) if kind == "domain" else indicator.strip()

    templates = _domain_queries(ind) if kind == "domain" else _keyword_queries(ind)
    queries = []
    for label, q in templates:
        google_only = bool(_GOOGLE_ONLY_OP.search(q))
        eng = ["google"] if google_only else engines           # related: -> Google only
        queries.append({
            "label": label,
            "q": q,
            "google_only_operator": google_only,
            "urls": {e: _url(e, q) for e in eng},
        })

    fetch_urls = {e: _url(e, templates[0][1]) for e in engines if e in FETCH_FRIENDLY}
    notes = [
        "Fire these with Claude Code's WebSearch (single-engine, but free) and/or WebFetch. "
        "Google/Yandex bot-wall a plain WebFetch — use WebSearch for those; WebFetch the "
        "duckduckgo html.duckduckgo.com URL for a readable SERP.",
        "Extract candidate hosts from the results and feed the NEW ones back into pivot_extract "
        "(collect) — that closes the keyword→search→infrastructure loop.",
    ]
    if "yandex" in engines:
        notes.append("Yandex is strongest for Cyrillic/RU-CIS infra and reverse-IMAGE lookups "
                     "(favicon/logo) — for an image, search images.yandex.com by image URL.")
    return {
        "indicator": ind, "kind": kind, "engines": engines,
        "queries": queries, "fetch_friendly": fetch_urls, "notes": notes,
    }


def _human(r: dict) -> str:
    out = [f"search_pivot · {r['kind']}: {r['indicator']} · engines: {', '.join(r['engines'])}"]
    for q in r["queries"]:
        out.append(f"  [{q['label']}] {q['q']}")
        for e, u in q["urls"].items():
            out.append(f"      {e:<11} {u}")
    if r["fetch_friendly"]:
        out.append("  WebFetch-friendly (readable SERP): "
                   + " | ".join(r["fetch_friendly"].values()))
    out.append("  notes:")
    out += [f"    - {n}" for n in r["notes"]]
    return "\n".join(out)


def _main() -> None:
    ap = argparse.ArgumentParser(description="Multi-engine search-engine pivot queries for an indicator.")
    ap.add_argument("indicator", help="domain, slogan, tracking ID, wallet, or handle")
    ap.add_argument("--engines", default=",".join(DEFAULT_ENGINES),
                    help=f"comma list from: {', '.join(ENGINES)} (default: {','.join(DEFAULT_ENGINES)})")
    ap.add_argument("--kind", choices=["domain", "keyword"], default=None,
                    help="override auto-detection")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the human view")
    a = ap.parse_args()
    r = search_pivot(a.indicator, [e.strip() for e in a.engines.split(",") if e.strip()], a.kind)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))


if __name__ == "__main__":
    _main()
