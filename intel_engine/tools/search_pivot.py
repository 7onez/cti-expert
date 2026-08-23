#!/usr/bin/env python3
"""search_pivot — multi-engine search-engine pivot queries for an indicator.

Generalizes fallback_probe.dorks() from a domain to ANY indicator (domain, slogan, tracking ID,
wallet, Telegram/Zalo handle, Discord id) and from Google-only to a switchable engine set (Google /
Yandex / DuckDuckGo / Bing / Brave). Four kinds, auto-detected: `domain`, `handle` (a username —
adds dox/staff/market dork context plus DIRECT Telegram profile + analytics-mirror URLs that expose
a channel's bio/admin list), `discord_id` (a numeric snowflake — decodes the account-creation date
locally and emits the user-lookup mirrors) and `keyword` (anything else). It emits READY-TO-OPEN,
URL-encoded result URLs plus the raw queries —
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
                                    [--kind domain|keyword|handle|discord_id] [--json]
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
    return "\n".join(out)


def _main() -> None:
    ap = argparse.ArgumentParser(description="Multi-engine search-engine pivot queries for an indicator.")
    ap.add_argument("indicator", help="domain, slogan, tracking ID, wallet, or handle")
    ap.add_argument("--engines", default=",".join(DEFAULT_ENGINES),
                    help=f"comma list from: {', '.join(ENGINES)} (default: {','.join(DEFAULT_ENGINES)})")
    ap.add_argument("--kind", choices=["domain", "keyword", "handle", "discord_id"], default=None,
                    help="override auto-detection (handle = username; discord_id = numeric snowflake)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the human view")
    a = ap.parse_args()
    r = search_pivot(a.indicator, [e.strip() for e in a.engines.split(",") if e.strip()], a.kind)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))


if __name__ == "__main__":
    _main()
