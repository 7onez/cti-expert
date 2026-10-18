#!/usr/bin/env python3
"""Typed selector model for the cross-type auto-pivot harness path.

Stdlib only. Classifies raw seeds into node types (domain|email|phone|wallet|ip|hash|
string|filename|telegram), loads pivot routes + rung table from reference JSON, and
defines the frozen Candidate record the proposer/planner exchange.

intel.py's `_classify_selector` / `_SELECTOR_OP` stay untouched — this module is the
harness-side classifier. Regex patterns are COPIED from intel.py (importing intel.py
mutates sys.path and pulls the full driver); tests/test_references.py asserts pattern
parity so the two cannot drift.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import Optional

# ---------------------------------------------------------------- reference loader (RULE 3)
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_WP = os.path.join(_ROOT, "WebPivot", "tools")
if _WP not in sys.path:
    sys.path.append(_WP)
try:
    from wp_refs import load_ref                              # the shared RULE 3 loader
except Exception:                                             # noqa: BLE001 — degrade, never block
    def load_ref(path, fallback):
        print("[selector_types] WARNING: wp_refs unavailable; reference JSON not read — "
              "running on the minimal embedded fallback.", file=sys.stderr)
        return dict(fallback)

# ---------------------------------------------------------------- regexes (parity with intel.py)
# COPIED from tools/intel.py (~1590). Do not import intel.py — it has import-time side effects.
# tests/test_references.py asserts .pattern equality against intel.py's compiled forms.
_BARE_DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.I)
_URL_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://')
_HASH_HEX_RE = re.compile(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', re.I)
_PHONE_SHAPE_RE = re.compile(r'^\+?[0-9()\-\s]{6,20}$')
_WALLET_SHAPE_RE = re.compile(
    r'^(bc1[a-z0-9]{20,}|[13][a-zA-Z0-9]{25,34}|0x[a-fA-F0-9]{40}|T[a-zA-Z0-9]{25,34})$')
# NOT in intel.py: the same shape with a punycode TLD (`xn--p1ai` = .рф). DNS / crt.sh / urlscan
# return IDN ccTLDs in this form, and `[a-z]{2,}` above rejects the digits and hyphens in it.
_PUNY_DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+xn--[a-z0-9-]{1,59}$', re.I)


def _is_domain(v: str) -> bool:
    return bool(_BARE_DOMAIN_RE.match(v) or _PUNY_DOMAIN_RE.match(v))


_KINDS = frozenset({
    "domain", "email", "phone", "wallet", "ip", "hash", "string", "filename", "telegram",
})
_RUNGS = frozenset({"owner", "kit", "neighbour"})

# ---------------------------------------------------------------- pivot_map.json
# auto_max_hits is a dict {"max": N} because load_ref's _group drops bare scalars to the
# fallback (see kb_refs._group). filename_exts is a values-list; routes is a dict of route
# specs. Fallback makes EVERYTHING need approval (max=0, no routes).
_PIVOT_JSON = os.path.join(_ROOT, "harness", "references", "pivot_map.json")
_PIVOT_FALLBACK: dict = {
    "auto_max_hits": {"max": 0},
    "filename_exts": ["zip", "exe", "apk", "pdf", "js"],
    "routes": {},
}
_PIVOT_REF = load_ref(_PIVOT_JSON, _PIVOT_FALLBACK)

# ---------------------------------------------------------------- rungs.json
# Fallback maps every known class to kit (conservative: never auto-attribute on a broken file).
_RUNG_CLASSES_KIT = {
    "analytics.ga": "kit", "analytics.gtm": "kit", "analytics.gtag": "kit",
    "analytics.fb_pixel": "kit", "analytics.tiktok": "kit", "analytics.metrica": "kit",
    "ads.adsense": "kit", "ads.affiliate": "kit", "ads.other": "kit",
    "token.telegram_bot": "kit", "token.discord_webhook": "kit", "token.other": "kit",
    "wallet.operator": "kit", "wallet.exchange": "kit",
    "whois.registrant_email": "kit", "whois.registrant_phone": "kit",
    "whois.privacy_customer": "kit", "txt.verification": "kit",
    "cert.exact": "kit", "app.developer_url": "kit", "app.apple_team": "kit",
    "page.email": "kit", "page.phone": "kit",
    "html_id": "kit", "telegram.username": "kit", "bank_account": "kit",
    "username": "kit", "string": "kit", "filename": "kit", "hash": "kit",
    "title": "kit", "favicon": "kit", "tx_id": "kit",
    "ip.cotenant": "kit",
}
_RUNGS_JSON = os.path.join(_ROOT, "tools", "kb", "references", "rungs.json")
_RUNGS_FALLBACK: dict = {"rungs": dict(_RUNG_CLASSES_KIT)}
_RUNGS_REF = load_ref(_RUNGS_JSON, _RUNGS_FALLBACK)


def load_pivot_map() -> dict:
    """Return the pivot map: auto_max_hits (int), filename_exts (list[str]), routes (dict).

    Normalises the load_ref shape so callers always see auto_max_hits as an int.
    """
    raw = _PIVOT_REF if isinstance(_PIVOT_REF, dict) else dict(_PIVOT_FALLBACK)
    am = raw.get("auto_max_hits", 0)
    if isinstance(am, dict):
        am = am.get("max", 0)
    try:
        am_i = int(am)
    except (TypeError, ValueError):
        am_i = 0
    exts = raw.get("filename_exts") or []
    if isinstance(exts, dict):  # defensive: values-wrapper leaked through
        exts = exts.get("values") or []
    routes = raw.get("routes") or {}
    if not isinstance(routes, dict):
        routes = {}
    return {
        "auto_max_hits": am_i,
        "filename_exts": [str(x).lower().lstrip(".") for x in exts if x],
        "routes": dict(routes),
    }


def max_typed_hops() -> int:
    """Hop bound for the cross-type node registry (pivot_map.json max_typed_hops.max; fallback 2)."""
    raw = _PIVOT_REF if isinstance(_PIVOT_REF, dict) else {}
    v = raw.get("max_typed_hops", {"max": 2})
    if isinstance(v, dict):
        v = v.get("max", 2)
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 2


_PAGE_SELECTOR_CAP_FALLBACK = 25


def page_selector_cap() -> int:
    """Per-type cap on kit/neighbour typed pivots propose() sizes and offers per round
    (pivot_map.json page_selector_cap.max; fallback 25). Owner-rung pivots are never capped."""
    raw = _PIVOT_REF if isinstance(_PIVOT_REF, dict) else {}
    v = raw.get("page_selector_cap", {"max": _PAGE_SELECTOR_CAP_FALLBACK})
    if isinstance(v, dict):
        v = v.get("max", _PAGE_SELECTOR_CAP_FALLBACK)
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return _PAGE_SELECTOR_CAP_FALLBACK


# Conservative fallbacks: a sandbox lookup on an IP has no ownership yield; page-scraped contacts
# from a Quarry page export are facts on the page, never pivot nodes.
_PROPOSE_TYPE_EXCLUDE_FALLBACK = {"anyrun.lookup": ["ip"]}
_FACT_ONLY_NODE_CLASSES_FALLBACK = {"quarry.page": ["page.email", "page.phone"]}


def _route_type_map(raw, fallback) -> dict:
    if not isinstance(raw, dict):
        raw = fallback
    return {str(k): {str(x).strip() for x in (v or []) if str(x).strip()}
            for k, v in raw.items() if not str(k).startswith("_") and isinstance(v, list)}


def propose_excluded(route: str, type_: str) -> bool:
    """True when propose() must not offer `route` for a `type_` selector
    (pivot_map.json propose_type_exclude; fallback {anyrun.lookup: [ip]})."""
    raw = _PIVOT_REF if isinstance(_PIVOT_REF, dict) else {}
    table = _route_type_map(raw.get("propose_type_exclude"), _PROPOSE_TYPE_EXCLUDE_FALLBACK)
    return (type_ or "").strip().lower() in table.get((route or "").strip(), set())


def fact_only_classes(route: str) -> frozenset:
    """Rung classes a corpus `route` delivers as KB facts only — never as typed nodes the proposer
    pivots on (rungs.json fact_only_node_classes; fallback {quarry.page: [page.email, page.phone]})."""
    raw = _RUNGS_REF if isinstance(_RUNGS_REF, dict) else {}
    table = _route_type_map(raw.get("fact_only_node_classes"), _FACT_ONLY_NODE_CLASSES_FALLBACK)
    return frozenset(table.get((route or "").strip(), set()))


def load_rungs() -> dict:
    """Return {rung_class: 'owner'|'kit'|'neighbour'} from rungs.json (or fallback)."""
    raw = _RUNGS_REF if isinstance(_RUNGS_REF, dict) else dict(_RUNGS_FALLBACK)
    table = raw.get("rungs")
    if not isinstance(table, dict):
        table = dict(_RUNG_CLASSES_KIT)
    out = {}
    for k, v in table.items():
        if str(k).startswith("_"):
            continue
        vs = str(v).strip().lower()
        out[str(k)] = vs if vs in _RUNGS else "kit"
    return out


def rung_for(rung_class: str) -> str:
    """Map an identifier class to owner|kit|neighbour. Unknown -> kit (conservative)."""
    rc = (rung_class or "").strip()
    if not rc:
        return "kit"
    table = load_rungs()
    if rc in table:
        return table[rc]
    # namespace defaults: ads.* is always kit unless a more specific entry existed above
    if rc.startswith("ads."):
        return "kit"
    return "kit"


def routes_for(type_: str) -> list:
    """Pivot-map route keys whose `types` list includes `type_`, in map order."""
    t = (type_ or "").strip().lower()
    if not t:
        return []
    routes = load_pivot_map().get("routes") or {}
    out = []
    for key, spec in routes.items():
        if not isinstance(spec, dict):
            continue
        types = spec.get("types") or []
        if t in types:
            out.append(key)
    return out


def _filename_exts() -> set:
    return set(load_pivot_map().get("filename_exts") or [])


def _is_filename(v: str, exts: set) -> bool:
    """Path-like value, or a single token whose final extension is in filename_exts."""
    if not v:
        return False
    if "/" in v or "\\" in v:
        return True
    # bare token with a known extension (invoice.zip, setup.app) — BEFORE bare-domain fallback
    if "." in v:
        ext = v.rsplit(".", 1)[-1].lower()
        if ext in exts:
            return True
    return False


def _is_telegram(v: str) -> bool:
    """t.me / telegram.me path forms (bare @handle only via hint)."""
    low = v.lower().strip()
    if low.startswith("t.me/") or low.startswith("telegram.me/"):
        return True
    if "://t.me/" in low or "://telegram.me/" in low:
        return True
    return False


def classify(raw, hint=None) -> str:
    """Classify a raw selector into one node type.

    Order (hint always wins; filename BEFORE bare-domain fallback; `domain:` forces domain):
      hint → domain: prefix → URL scheme → IP → email → hash → wallet → phone →
      telegram (t.me/…) → filename → bare domain → string
    """
    if hint is not None:
        h = str(hint).strip().lower()
        if h in _KINDS:
            return h

    v = (raw or "").strip()
    if not v:
        return "string"
    if v.endswith("."):          # fully-qualified `example.com.` — one root dot, never more
        v = v[:-1]

    # Analyst force-type: domain:<value> (ambiguous TLDs like .zip / .app / .mov)
    if v.lower().startswith("domain:"):
        return "domain"

    if _URL_SCHEME_RE.match(v):
        # URL whose host is telegram still counts as telegram for the harness path
        if _is_telegram(v):
            return "telegram"
        return "domain"

    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    if "@" in v and _is_domain(v.rsplit("@", 1)[-1]):
        return "email"

    if _HASH_HEX_RE.match(v):
        return "hash"

    if _WALLET_SHAPE_RE.match(v):
        return "wallet"

    if _PHONE_SHAPE_RE.match(v) and sum(c.isdigit() for c in v) >= 6:
        return "phone"

    if _is_telegram(v):
        return "telegram"

    # Filename BEFORE bare-domain fallback (invoice.zip parses as a PSL apex otherwise)
    if _is_filename(v, _filename_exts()):
        return "filename"

    if _is_domain(v):
        return "domain"

    return "string"


def candidate_id(type_: str, selector: str, tool: str, query: str) -> str:
    """Stable 10-hex id: sha1(type|selector|tool|query)[:10]."""
    blob = f"{type_}|{selector}|{tool}|{query}"
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:10]


@dataclass(frozen=True)
class Candidate:
    """One proposed pivot. Frozen + JSON-serialisable; id is stable across runs."""
    id: str
    type: str
    selector: str
    tool: str
    query: str
    metered: bool
    est_hits: Optional[int]
    rung: str
    origins: tuple = ()
    sources: tuple = ()
    why: str = ""
    by: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        # JSON-friendly: tuples → lists; keep est_hits as null when unknown
        d["origins"] = list(self.origins or ())
        d["sources"] = list(self.sources or ())
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Candidate":
        if not isinstance(d, dict):
            raise TypeError("Candidate.from_dict expects a dict")
        origins = d.get("origins") or ()
        sources = d.get("sources") or ()
        est = d.get("est_hits", None)
        if est is not None:
            try:
                est = int(est)
            except (TypeError, ValueError):
                est = None
        typ = str(d.get("type") or "")
        sel = str(d.get("selector") or "")
        tool = str(d.get("tool") or "")
        query = str(d.get("query") or "")
        cid = str(d.get("id") or "") or candidate_id(typ, sel, tool, query)
        rung = str(d.get("rung") or "kit")
        if rung not in _RUNGS:
            rung = "kit"
        return cls(
            id=cid,
            type=typ,
            selector=sel,
            tool=tool,
            query=query,
            metered=bool(d.get("metered", False)),
            est_hits=est,
            rung=rung,
            origins=tuple(origins),
            sources=tuple(sources),
            why=str(d.get("why") or ""),
            by=str(d.get("by") or ""),
        )


# ---------------------------------------------------------------- KB key mapping (shared contract)
# Typed nodes live in the EXISTING KB conventions (tools/kb/ingest_webpivot.py), so the cross-type
# loop, the legacy ingest and every KB query read one graph: domains/emails are their own entity
# types; everything else is an `indicator` with a type prefix. ingest_typed writes through kb_key();
# the proposer reads back through node_from_kb(). Tracker labels are the ingest_webpivot REL keys.
_TRACKER_RUNG = {
    "google_analytics_ua": "analytics.ga", "google_analytics_ga4": "analytics.ga",
    "google_tag_manager": "analytics.gtm", "gtag": "analytics.gtag",
    "facebook_pixel": "analytics.fb_pixel", "tiktok_pixel": "analytics.tiktok",
    "yandex_metrica": "analytics.metrica", "adsense": "ads.adsense",
}
_PREFIX_TYPE = {"ip": "ip", "phone": "phone", "hash": "hash", "string": "string",
                "filename": "filename", "title": "string"}


# urlscan identifier / explorer coin names → the wp_extract.CRYPTO_PATTERNS labels the page
# ingest writes, so one address is one KB entity whichever collector saw it.
_COIN_ALIAS = {"bitcoin": "btc", "ethereum": "eth", "litecoin": "ltc", "monero": "xmr",
               "trx": "tron", "usdt-trc20": "tron", "trc20": "tron", "erc20": "eth"}


def kb_key(type_: str, value: str, *, coin: str = "") -> tuple:
    """(entity_type, entity_value) for a typed node, in the KB's existing conventions."""
    t, v = (type_ or "").strip().lower(), str(value or "").strip()
    if t == "domain":
        return "domain", v.lower()
    if t == "email":
        return "email", v.lower()
    # (wallet labels follow wp_extract.CRYPTO_PATTERNS: btc / eth / ltc / xmr / tron)
    if t == "wallet":
        c = _COIN_ALIAS.get((coin or "").strip().lower(), (coin or "").strip().lower())
        return "indicator", f"wallet:{c or wallet_coin(v)}:{v}"
    if t == "telegram":
        return "indicator", f"social:telegram:{_telegram_handle(v)}"
    if t == "string":
        label = tracker_label(v)
        if label:                      # the SAME entity ingest_webpivot writes for this tracker
            return "indicator", f"{label}:{v}"
    return "indicator", f"{t}:{v}"


def _telegram_handle(v: str) -> str:
    """The Telegram ACCOUNT a typed selector names — the same leaf the page ingest keys socials on
    (noise_filters.social_handle): `t.me/chan/123` -> `chan`, `t.me/s/chan` -> `chan`,
    `t.me/chan?start=x` -> `chan`. Usernames are case-insensitive and lowercased; invite hashes
    (`t.me/+AbC…`, `t.me/joinchat/AbC…`) are case-sensitive and kept as-is. A bare `@handle`, or
    a t.me link social_handle declines (`t.me/c/<id>/<post>`), falls back to the last path segment."""
    handle = None
    if _is_telegram(v):
        try:
            _kb = os.path.join(_HERE, "kb")
            if _kb not in sys.path:
                sys.path.append(_kb)
            from noise_filters import social_handle
            handle = social_handle("telegram", v)
        except Exception:                                     # noqa: BLE001 — degrade to the leaf
            handle = None
    if not handle:
        handle = v.split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    handle = handle.lstrip("@")
    if handle.startswith("+") or "/joinchat/" in v.lower():
        return handle
    return handle.lower()


def wallet_coin(addr: str) -> str:
    """The ingest_webpivot / wp_extract CRYPTO_PATTERNS label for an address shape."""
    a = str(addr or "").strip()
    if a.lower().startswith("0x") and len(a) == 42:
        return "eth"
    if a.startswith("T") and len(a) == 34:
        return "tron"
    if a.lower().startswith("ltc1") or (a[:1] in ("L", "M") and 27 <= len(a) <= 34):
        return "ltc"
    if a.lower().startswith("bc1") or (a[:1] in ("1", "3") and 26 <= len(a) <= 35):
        return "btc"
    if a[:1] in ("4", "8") and len(a) == 95:
        return "xmr"
    return "unknown"


def tracker_label(v: str) -> str:
    """ingest_webpivot REL label for a tracker-shaped id, or '' (GTM-/UA-/G- are unambiguous)."""
    up = str(v or "").strip().upper()
    if up.startswith("GTM-"):
        return "google_tag_manager"
    if up.startswith("UA-"):
        return "google_analytics_ua"
    if up.startswith("G-") and len(up) > 4:
        return "google_analytics_ga4"
    return ""


def node_from_kb(etype: str, value: str):
    """Inverse of kb_key, extended to the legacy indicator forms worth pivoting.

    Returns {"type", "selector", "rung_class"} or None for entities the cross-type loop does not
    pivot (themes, css hashes, comments, verification tokens, …)."""
    et, v = (etype or "").strip().lower(), str(value or "").strip()
    if et == "domain":
        return {"type": "domain", "selector": v, "rung_class": ""}
    if et == "email":
        return {"type": "email", "selector": v, "rung_class": "page.email"}
    if et != "indicator" or ":" not in v:
        return None
    prefix, rest = v.split(":", 1)
    if prefix == "wallet" and ":" in rest:
        return {"type": "wallet", "selector": rest.split(":", 1)[1], "rung_class": "wallet.operator"}
    if prefix == "social" and rest.startswith("telegram:"):
        return {"type": "telegram", "selector": rest.split(":", 1)[1],
                "rung_class": "telegram.username"}
    if prefix in _TRACKER_RUNG:
        return {"type": "string", "selector": rest, "rung_class": _TRACKER_RUNG[prefix]}
    if prefix in _PREFIX_TYPE:
        return {"type": _PREFIX_TYPE[prefix], "selector": rest,
                "rung_class": {"ip": "", "phone": "page.phone", "hash": "hash",
                               "filename": "filename", "title": "title"}.get(prefix, "string")}
    return None


# Convenience: the auto-hit ceiling the approval gate will read.
def auto_max_hits() -> int:
    return int(load_pivot_map().get("auto_max_hits") or 0)


__all__ = [
    "Candidate",
    "auto_max_hits",
    "candidate_id",
    "classify",
    "kb_key",
    "load_pivot_map",
    "load_rungs",
    "max_typed_hops",
    "node_from_kb",
    "page_selector_cap",
    "routes_for",
    "rung_for",
]
