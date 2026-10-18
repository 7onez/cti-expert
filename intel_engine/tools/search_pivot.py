#!/usr/bin/env python3
"""search_pivot — multi-engine search-engine pivot queries for an indicator.

Generalizes fallback_probe.dorks() from a domain to ANY indicator (domain, slogan, tracking ID,
wallet, Telegram/Zalo handle, Discord id) and from Google-only to a switchable engine set (Google /
Yandex / DuckDuckGo / Bing / Brave). Four kinds, auto-detected: `domain`, `handle` (a username —
adds dox/staff/market dork context plus DIRECT Telegram profile + analytics-mirror URLs that expose
a channel's bio/admin list), `discord_id` (a numeric snowflake — decodes the account-creation date
locally and emits the user-lookup mirrors) and `keyword` (anything else). It emits READY-TO-OPEN,
URL-encoded result URLs plus the raw queries. By default it does NOT fetch SERPs; the analyst, or
the agent's own WebSearch / WebFetch, fires them. This is the same "runnable pivot query" contract
as the rest of WebPivot.

`--run` EXECUTES the dorks, free first: each query goes to the DuckDuckGo HTML endpoint, and only
when that path does not work for THAT query — a bot challenge (DDG answers 202 + an "anomaly" page;
it challenges per query, typically operator dorks), an HTTP or network error, or an unparseable
page — is it re-run through SerpApi Google (`wp_serp.web_search`, 1 metered search, ledgered and
budgeted). `related:` is never bought: Google retired it, so the row is reported NOT ANSWERED.
`--free-only` (or no SERPAPI_KEY) keeps it to DDG and says which queries went unanswered.

Why multiple engines: they index DIFFERENT corners — Google for dork operators, Yandex for
Cyrillic / reverse-image / RU-CIS infra, DuckDuckGo for a fetch-friendly HTML endpoint (the one an
automated WebFetch can actually read without a bot-wall). Firing the same keyword across all of them
surfaces off-infrastructure mentions (forums, complaints, pastebin, social) that FOFA/PublicWWW —
which only see served HTML — never index.

CLI:
    python3 tools/search_pivot.py "<indicator>" [--engines google,yandex,duckduckgo,bing,brave]
                                    [--kind domain|keyword|handle|discord_id] [--json]
                                    [--run [--free-only] [--max-queries N] [--num N]]
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import urllib.parse

# ---------------------------------------------------------------- reference data (RULE 3)
# The handle/social dork templates + directory sites are analyst-tunable DATA — a new dox index or
# Telegram mirror is added to the JSON, not to this file. Same load_ref pattern as cost_report.py.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_WP = os.path.join(_ROOT, "WebPivot", "tools")
if _WP not in sys.path:
    sys.path.append(_WP)
try:
    from wp_refs import load_ref                              # the shared RULE 3 loader
except Exception:                                             # noqa: BLE001 — degrade, never block
    def load_ref(path, fallback):
        print("[search_pivot] WARNING: wp_refs unavailable; dork_templates.json not read — "
              "running on the minimal embedded template set.", file=sys.stderr)
        return dict(fallback)

_DORK_JSON = os.path.join(_ROOT, "WebPivot", "references", "dork_templates.json")
# Minimal embedded default so the tool still emits SOMETHING standalone if the JSON is missing.
# Shape mirrors what load_ref RETURNS (groups already unwrapped): a `values` group -> a list, a
# group of named arrays -> a dict. See wp_refs.load_ref's contract.
_DORK_FALLBACK = {
    "handle_dorks": [
        {"label": "exact handle", "q": '"{h}"'},
        {"label": "cross-platform presence",
         "q": '"{h}" (telegram OR t.me OR discord OR github)'},
        {"label": "dox / leak context", "q": '"{h}" (doxbin OR dox OR leak OR pastebin)'},
    ],
    "telegram_directories": [
        {"label": "t.me profile (canonical)", "url": "https://t.me/{h}"},
        {"label": "telegram.im mirror", "url": "https://telegram.im/@{h}"},
    ],
    "discord_lookup": {
        "by_id": [{"label": "discord user (official)", "url": "https://discord.com/users/{id}"}],
        "by_name": [{"label": "discord username mention",
                     "q": '"{h}" (discord OR discord.gg OR discord.com)'}],
    },
}
_DORKS = load_ref(_DORK_JSON, _DORK_FALLBACK)

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


def _looks_like_discord_id(s: str) -> bool:
    """A Discord snowflake: a bare 17-20 digit integer."""
    return bool(re.fullmatch(r"\d{17,20}", s.strip()))


def _looks_like_handle(s: str) -> bool:
    """A username/handle: an @-prefixed token, or a single bare token of handle characters
    (letters/digits/underscore/dot/hyphen) with no spaces and no dot-TLD shape."""
    s = s.strip()
    if s.startswith("@") and len(s) > 1:
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{1,31}", s)) and not _looks_like_domain(s)


def _norm_handle(s: str) -> str:
    """Bare handle for templating: drop a leading @, a t.me/ or telegram.im/ prefix, lower-case."""
    s = s.strip()
    for pre in ("https://t.me/", "http://t.me/", "t.me/", "https://telegram.im/", "telegram.im/"):
        if s.lower().startswith(pre):
            s = s[len(pre):]
            break
    return s.lstrip("@").strip("/").lower()


# Discord snowflakes embed a millisecond timestamp: (id >> 22) + the Discord epoch. Decoded
# LOCALLY — no network — so a bare id yields the account's creation date for free.
_DISCORD_EPOCH_MS = 1420070400000


def _discord_created(snowflake: str) -> str | None:
    try:
        ms = (int(snowflake) >> 22) + _DISCORD_EPOCH_MS
        return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)\
            .strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError):
        return None


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


def _handle_queries(h: str) -> list[tuple[str, str]]:
    """(label, query) for a USERNAME/HANDLE — loaded from dork_templates.json (RULE 3)."""
    vals = _DORKS.get("handle_dorks") or []
    return [(t["label"], t["q"].format(h=h)) for t in vals if t.get("q")]


def _handle_directories(h: str) -> list[dict]:
    """Direct Telegram profile / analytics-mirror URLs for a handle (RULE 3)."""
    vals = _DORKS.get("telegram_directories") or []
    out = []
    for t in vals:
        if not t.get("url"):
            continue
        out.append({"label": t["label"],
                    "url": t["url"].replace("{h}", urllib.parse.quote(h, safe=""))})
    return out


def _discord_directories(snowflake: str) -> list[dict]:
    vals = (_DORKS.get("discord_lookup") or {}).get("by_id") or []
    return [{"label": t["label"], "url": t["url"].replace("{id}", snowflake)}
            for t in vals if t.get("url")]


def _discord_name_queries(h: str) -> list[tuple[str, str]]:
    vals = (_DORKS.get("discord_lookup") or {}).get("by_name") or []
    return [(t["label"], t["q"].format(h=h)) for t in vals if t.get("q")]


def _url(engine: str, query: str) -> str:
    return ENGINES[engine] + urllib.parse.quote_plus(query)


def _auto_kind(indicator: str) -> str:
    if _looks_like_domain(indicator):
        return "domain"
    if _looks_like_discord_id(indicator):
        return "discord_id"
    if _looks_like_handle(indicator):
        return "handle"
    return "keyword"


def search_pivot(indicator: str, engines: list[str] | None = None,
                 kind: str | None = None) -> dict:
    """Build the multi-engine pivot query set for `indicator`. Pure/deterministic; no network."""
    engines = [e for e in (engines or DEFAULT_ENGINES) if e in ENGINES] or DEFAULT_ENGINES
    if kind not in ("domain", "keyword", "handle", "discord_id"):
        kind = _auto_kind(indicator)

    directories: list[dict] = []
    extra: dict = {}
    if kind == "domain":
        ind = _host(indicator)
        templates = _domain_queries(ind)
    elif kind == "handle":
        ind = _norm_handle(indicator)
        templates = _handle_queries(ind)
        directories = _handle_directories(ind)
    elif kind == "discord_id":
        ind = indicator.strip()
        templates = _discord_name_queries(ind)          # a bare id has no username to dork on
        directories = _discord_directories(ind)
        created = _discord_created(ind)
        if created:
            extra["discord_account_created"] = created  # decoded locally from the snowflake
    else:
        kind = "keyword"
        ind = indicator.strip()
        templates = _keyword_queries(ind)

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

    fetch_urls = ({e: _url(e, templates[0][1]) for e in engines if e in FETCH_FRIENDLY}
                  if templates else {})
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
    if directories:
        notes.append("`directories` are DIRECT profile/analytics-mirror URLs (open them straight, "
                     "not a SERP) — a Telegram mirror exposes the channel bio, admin list and "
                     "first-seen date the app hides. A mirror may not have indexed a given handle.")
    if kind == "discord_id":
        notes.append("A Discord id is a snowflake: its creation timestamp is decoded locally "
                     "(discord_account_created) — an id minted just before a campaign is a tell.")
    out = {
        "indicator": ind, "kind": kind, "engines": engines,
        "queries": queries, "fetch_friendly": fetch_urls, "notes": notes,
    }
    if directories:
        out["directories"] = directories
    out.update(extra)
    return out


# ---------------------------------------------------------------- execution (--run)
_DDG_RESULT = re.compile(r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S | re.I)
_DDG_SNIPPET = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S | re.I)
_DDG_CHALLENGE = ("anomaly-modal", "anomaly.js", "bots use duckduckgo too", "challenge-form")
_DDG_NO_RESULTS = ("no-results", "no results.")
# Operators the DDG HTML endpoint ignores (fx-dork-sweep.md operator matrix: intext ❌, after/before ❌)
_DDG_WEAK_OP = re.compile(r"\b(?:intext|after|before):", re.I)
_TAG = re.compile(r"<[^>]+>")


def _strip(html_text: str) -> str:
    import html as _html
    return re.sub(r"\s+", " ", _html.unescape(_TAG.sub("", html_text or ""))).strip()


def _ddg_link(href: str) -> str:
    """DDG wraps every result as //duckduckgo.com/l/?uddg=<target>; unwrap to the real URL."""
    import html as _html
    href = _html.unescape(href or "")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
    if qs.get("uddg"):
        return qs["uddg"][0]
    return ("https:" + href) if href.startswith("//") else href


def parse_ddg(status: int, body: str) -> dict:
    """One DDG HTML response -> {ok, results, reason}. ok=False means the FREE path did not work
    (challenge / HTTP error / unrecognisable page) — not that the web holds nothing."""
    low = (body or "").lower()
    if any(m in low for m in _DDG_CHALLENGE):
        return {"ok": False, "challenge": True, "results": [],
                "reason": f"DuckDuckGo bot challenge (HTTP {status})"}
    if status != 200:
        return {"ok": False, "results": [], "reason": f"DuckDuckGo HTTP {status}"}
    matches = list(_DDG_RESULT.finditer(body))
    results = []
    for i, m in enumerate(matches):
        link = _ddg_link(m.group(1))
        if not link.startswith("http") or "duckduckgo.com/y.js" in link:   # sponsored redirects
            continue
        # the snippet lives in the same result block: between this anchor and the next one
        seg = body[m.end(): matches[i + 1].start() if i + 1 < len(matches) else len(body)]
        sn = _DDG_SNIPPET.search(seg)
        results.append({"position": len(results) + 1, "title": _strip(m.group(2)), "link": link,
                        "host": _host(urllib.parse.urlparse(link).netloc).removeprefix("www."),
                        "snippet": _strip(sn.group(1)) if sn else ""})
    if results or any(m in low for m in _DDG_NO_RESULTS):
        return {"ok": True, "results": results, "reason": None}
    return {"ok": False, "results": [], "reason": "DuckDuckGo page had neither results nor a "
                                                  "no-results marker (layout change or soft block)"}


def _ddg_fetch(url: str, timeout: int = 20):
    """(status, body_text) via WebPivot's shared browser-profile fetch, stdlib as a fallback."""
    try:
        import wp_net                                            # noqa: E402 — on sys.path via _WP
        _f, status, _h, body = wp_net.fetch(url, timeout=timeout)
    except ImportError:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                status, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read()
    return status, (body or b"").decode("utf-8", "replace")


def run_queries(result: dict, free_only: bool = False, max_queries: int | None = None,
                num: int = 10, fetch=None, serp=None, delay: float = 1.5) -> dict:
    """Execute `result['queries']` free-first. Adds `executed` (per query: via / results / why the
    free path failed / SerpApi outcome) and `found_hosts` to `result` and returns it.

    `fetch(url) -> (status, body)` and `serp(query, num) -> dict` are injectable seams; by default
    DDG via wp_net and SerpApi via wp_serp.web_search. SerpApi is never called under free_only."""
    import time
    if fetch is None:
        fetch = _ddg_fetch
    if serp is None:
        serp = None if free_only else _serp_fn()
    queries = result.get("queries") or []
    if max_queries:
        queries = queries[:max_queries]
    executed, hosts, spent = [], [], 0
    for i, q in enumerate(queries):
        row = {"label": q["label"], "q": q["q"], "via": None, "results": []}
        if q.get("google_only_operator"):
            # `related:` — Google retired it in 2023; a SerpApi search for it is billed and comes
            # back empty, so it is neither fetched free nor bought. The URL above stays for by-hand use.
            row["free_failed"] = "Google-only operator — DuckDuckGo cannot answer it"
            row["serpapi"] = "skipped: Google retired related: (2023) — a billed search returns nothing"
            row["note"] = "NOT ANSWERED — this establishes nothing about what the web holds"
            executed.append(row)
            continue
        # DDG challenges PER QUERY (measured: operator dorks like site:/-site: get the 202 anomaly
        # page while plain-string queries from the same IP in the same minute return results), so
        # every query gets its own free attempt — one challenge never writes off the rest.
        if i and delay:
            time.sleep(delay)
        try:
            status, body = fetch(_url("duckduckgo", q["q"]))
            parsed = parse_ddg(status, body)
        except Exception as e:                                       # noqa: BLE001
            parsed = {"ok": False, "results": [], "reason": f"DuckDuckGo fetch failed: {e}"}
        if parsed["ok"] and not parsed["results"] and _DDG_WEAK_OP.search(q["q"]):
            # 0 hits on an operator DDG does not honour (fx-dork-sweep.md operator matrix) is the
            # operator failing, not the web being empty — let the paid tier answer it
            parsed = {"ok": False, "results": [],
                      "reason": "DuckDuckGo returned 0 on an operator it does not honour "
                                f"({_DDG_WEAK_OP.search(q['q']).group(0)})"}
        if parsed["ok"]:
            row.update(via="duckduckgo", results=parsed["results"][:num])
        else:
            row["free_failed"] = parsed["reason"]
        if row["via"] is None:
            if serp is None:
                row["serpapi"] = ("skipped: --free-only" if free_only
                                  else "skipped: no SERPAPI_KEY configured")
                row["note"] = "NOT ANSWERED — this establishes nothing about what the web holds"
            else:
                s = serp(q["q"], num) or {}
                if s.get("skipped") or s.get("error"):
                    row["serpapi"] = s.get("skipped") or s.get("error")
                    row["note"] = "NOT ANSWERED — this establishes nothing about what the web holds"
                else:
                    spent += 1                       # a 200 is billed even when empty (wp_serp._call)
                    row.update(via="serpapi", results=(s.get("results") or [])[:num])
                    if s.get("empty"):
                        row["serpapi"] = f"empty: {s['empty']}"
        hosts += [r["host"] for r in row["results"] if r.get("host")]
        executed.append(row)
    result["executed"] = executed
    result["found_hosts"] = sorted(set(hosts))
    result["execution_summary"] = {
        "queries": len(executed),
        "via_duckduckgo": sum(1 for r in executed if r["via"] == "duckduckgo"),
        "via_serpapi": sum(1 for r in executed if r["via"] == "serpapi"),
        "unanswered": sum(1 for r in executed if r["via"] is None),
        "serpapi_searches_spent": spent,
    }
    return result


def _serp_fn():
    """wp_serp.web_search when a SerpApi key is configured, else None (free path only)."""
    try:
        import wp_serp                                           # noqa: E402 — on sys.path via _WP
    except Exception:                                            # noqa: BLE001
        return None
    return wp_serp.web_search if wp_serp.serpapi_configured() else None


def _human(r: dict) -> str:
    out = [f"search_pivot · {r['kind']}: {r['indicator']} · engines: {', '.join(r['engines'])}"]
    if r.get("discord_account_created"):
        out.append(f"  discord account created (from snowflake): {r['discord_account_created']}")
    for q in r["queries"]:
        out.append(f"  [{q['label']}] {q['q']}")
        for e, u in q["urls"].items():
            out.append(f"      {e:<11} {u}")
    if r.get("directories"):
        out.append("  directories (open directly):")
        for d in r["directories"]:
            out.append(f"      {d['label']:<28} {d['url']}")
    if r["fetch_friendly"]:
        out.append("  WebFetch-friendly (readable SERP): "
                   + " | ".join(r["fetch_friendly"].values()))
    out.append("  notes:")
    out += [f"    - {n}" for n in r["notes"]]
    if "executed" in r:
        s = r["execution_summary"]
        out.append(f"  executed: {s['queries']} quer(ies) — {s['via_duckduckgo']} via DuckDuckGo (free), "
                   f"{s['via_serpapi']} via SerpApi ({s['serpapi_searches_spent']} search(es) spent), "
                   f"{s['unanswered']} unanswered")
        for row in r["executed"]:
            out.append(f"  [{row['label']}] via {row['via'] or 'NONE'}: {len(row['results'])} result(s)"
                       + (f"  (free failed: {row['free_failed']})" if row.get("free_failed") else "")
                       + (f"  (serpapi: {row['serpapi']})" if row.get("serpapi") else ""))
            for res in row["results"][:10]:
                out.append(f"      {res['link']}")
        if r["found_hosts"]:
            out.append("  hosts seen in results (feed NEW ones to pivot_extract): "
                       + ", ".join(r["found_hosts"]))
    return "\n".join(out)


def _main() -> None:
    ap = argparse.ArgumentParser(description="Multi-engine search-engine pivot queries for an indicator.")
    ap.add_argument("indicator", help="domain, slogan, tracking ID, wallet, or handle")
    ap.add_argument("--engines", default=",".join(DEFAULT_ENGINES),
                    help=f"comma list from: {', '.join(ENGINES)} (default: {','.join(DEFAULT_ENGINES)})")
    ap.add_argument("--kind", choices=["domain", "keyword", "handle", "discord_id"], default=None,
                    help="override auto-detection (handle = username; discord_id = numeric snowflake)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the human view")
    ap.add_argument("--run", action="store_true",
                    help="EXECUTE the dorks: DuckDuckGo HTML (free) first, SerpApi Google (metered, "
                         "1 search per query) only for queries the free path could not answer")
    ap.add_argument("--free-only", action="store_true", dest="free_only",
                    help="with --run: never fall back to SerpApi")
    ap.add_argument("--max-queries", type=int, default=None, help="with --run: execute only the first N")
    ap.add_argument("--num", type=int, default=10, help="with --run: results kept per query (default 10)")
    a = ap.parse_args()
    r = search_pivot(a.indicator, [e.strip() for e in a.engines.split(",") if e.strip()], a.kind)
    if a.run:
        r = run_queries(r, free_only=a.free_only, max_queries=a.max_queries, num=a.num)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))


if __name__ == "__main__":
    _main()
