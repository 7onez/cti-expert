#!/usr/bin/env python3
"""pivot_routes — corpus route runner for the cross-type auto-pivot loop.

Public contract (phase 3 → phase 4):
  query_for(route, type_, selector) -> str | None
  count(route, query, *, free_only=False) -> int | None
  run(route, query, *, case, free_only=False, hostile=False) -> dict
      {"rows":[{type,value,rung_class,source,evidence,coin?}], "total":int|None}
      | {"error":…} | {"skipped":…}

Stdlib-only. Never raises. Vendor clients stay tri-state; every metered call is
ledgered by the underlying wp_* / script helpers via api_usage.record.
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE = os.path.dirname(_HERE)
_WP_TOOLS = os.path.join(_ENGINE, "WebPivot", "tools")
_SKILL = os.path.dirname(_ENGINE)
for _p in (_HERE, _WP_TOOLS, os.path.join(_HERE, "kb"),
           os.path.join(_ENGINE, "BinaryPivot", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from selector_types import load_pivot_map, rung_for, classify  # noqa: E402
except Exception:  # noqa: BLE001
    def load_pivot_map():
        return {"routes": {}, "auto_max_hits": 0}

    def rung_for(_rc):
        return "kit"

    def classify(raw, hint=None):
        return "string"

try:
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:  # noqa: BLE001
    def load_ref(path, fallback):
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.join(os.path.dirname(module_file), os.pardir, "references", name)

# --------------------------------------------------------------------------- reference: urlscan field / identifier maps
_USCAN_FALLBACK = {
    "field_search": {
        "fields": {
            "page.title": "page.title", "title": "page.title",
            "text.content": "text.content", "text_content": "text.content",
            "filename": "filename", "files.filename": "files.filename", "files": "files.filename",
            "hash": "hash", "content.identifiers": "content.identifiers",
            "identifiers": "content.identifiers", "links.domains": "links.domains",
            "links": "links.domains",
        },
        "host_rung_class": {
            "page.title": "title", "text.content": "string", "filename": "filename",
            "files.filename": "filename", "hash": "hash", "links.domains": "string",
        },
    },
    "identifier_rungs": {
        "google.ua-id": "analytics.ga", "google.gtm-id": "analytics.gtm",
        "google.gtag-id": "analytics.gtag",
        "telegram.bot-token": "token.telegram_bot",
        "telegram.bot-token-base64": "token.telegram_bot",
        "discord.webhook": "token.discord_webhook",
        "wallet.bitcoin": "wallet.operator", "wallet.ethereum": "wallet.operator",
        "wallet.litecoin": "wallet.operator",
        "telegram.username": "telegram.username", "html-id": "html_id",
        "authorization.api": "token.other", "google.api": "token.other",
        "json.jwt": "token.other", "mailgun.api-key": "token.other",
        "square.access-token": "token.other",
    },
}
_USCAN_REF = load_ref(
    os.path.join(_ENGINE, "WebPivot", "references", "urlscan_endpoints.json"),
    _USCAN_FALLBACK)
_FIELD_SEARCH = _USCAN_REF.get("field_search") or _USCAN_FALLBACK["field_search"]
_FIELD_MAP = dict(_FIELD_SEARCH.get("fields") or {})
_HOST_RUNG = dict(_FIELD_SEARCH.get("host_rung_class") or {})
_ID_RUNGS_RAW = _USCAN_REF.get("identifier_rungs") or _USCAN_FALLBACK["identifier_rungs"]
# load_ref may unwrap entries; accept either shape
if isinstance(_ID_RUNGS_RAW, dict) and "google.ua-id" not in _ID_RUNGS_RAW and isinstance(
        _ID_RUNGS_RAW.get("entries"), dict):
    _ID_RUNGS = dict(_ID_RUNGS_RAW["entries"])
else:
    _ID_RUNGS = dict(_ID_RUNGS_RAW) if isinstance(_ID_RUNGS_RAW, dict) else dict(
        _USCAN_FALLBACK["identifier_rungs"])

# exchange wallets (for wallet.* identifier + counterparties)
_EX_REF = load_ref(
    os.path.join(_ENGINE, "WebPivot", "references", "exchange_wallets.json"),
    {"labels": {"values": []}, "known_addresses": {}})
_EX_LABELS = set()
_lab = _EX_REF.get("labels")
if isinstance(_lab, list):
    _EX_LABELS = {str(x).lower() for x in _lab}
elif isinstance(_lab, dict):
    _EX_LABELS = {str(x).lower() for x in (_lab.get("values") or _lab.keys()) if x and not str(x).startswith("_")}
_EX_ADDRS = {}
_ea = _EX_REF.get("known_addresses")
if isinstance(_ea, dict):
    for k, v in (_ea.get("entries") if isinstance(_ea.get("entries"), dict) else _ea).items():
        if not str(k).startswith("_") and k not in ("values", "entries"):
            _EX_ADDRS[str(k).lower()] = v
# public crypto constants (reference vectors drop; token contracts → wallet.token_contract)
try:
    from wp_crypto_refs import reference_label as _ref_label, token_contract as _token_contract  # noqa: E402
except Exception:  # noqa: BLE001
    def _ref_label(_addr):
        return ""

    def _token_contract(_addr):
        return None
# route → urlscan field
_URLSCAN_ROUTE_FIELD = {
    "urlscan.title": "page.title",
    "urlscan.text_content": "text.content",
    "urlscan.filename": "filename",
    "urlscan.files": "files.filename",
    "urlscan.hash": "hash",
    "urlscan.identifier": "content.identifiers",
    "urlscan.links": "links.domains",
}

_WAYBACK_ROUTE_COLLECTION = {
    "wayback.telegram": "telegram",
    "wayback.pdf": "pdf",
    # wayback.news fans out across mention_only collections
}

_NEWS_COLLECTIONS = (
    "mediacloud", "russian-independent-media",
    "EndOfTerm2024WebCrawls", "EndOfTerm2020WebCrawls", "EndOfTerm2016WebCrawls",
)

_PY = sys.executable


def _is_exchange_addr(addr: str) -> bool:
    return bool(addr) and str(addr).strip().lower() in _EX_ADDRS


def wallet_rung(addr: str):
    """rung_class for a wallet address seen by any route — the one wallet classifier.

    None = public reference constant (spec test vector / genesis / burn / system program): drop it.
    wallet.token_contract (kit) = stablecoin/token contract: a payment-method fact, never a payee,
    never a pivot node. wallet.exchange (neighbour) = listed custodian. Otherwise wallet.operator."""
    if _ref_label(addr):
        return None
    if _token_contract(addr):
        return "wallet.token_contract"
    if _is_exchange_addr(addr):
        return "wallet.exchange"
    return "wallet.operator"


def identifier_rung(id_type: str, value: str = "") -> str:
    """Map a urlscan content.identifiers type to a rung_class."""
    t = (id_type or "").strip().lower()
    if t in _ID_RUNGS:
        rc = _ID_RUNGS[t]
        if rc == "wallet.operator":
            return wallet_rung(value) or "string"       # a reference constant binds nobody
        return rc
    if t.startswith("telegram.bot-token"):
        return "token.telegram_bot"
    if t.startswith("wallet."):
        return wallet_rung(value) or "string"
    if t.startswith("google.") and t.endswith("-id"):
        # unknown google.* id → kit token rather than owner analytics
        return "token.other"
    return "token.other"


def _urlscan_field_for(route: str, field_hint: str = "") -> str:
    if field_hint:
        return _FIELD_MAP.get(field_hint, field_hint)
    if route in _URLSCAN_ROUTE_FIELD:
        f = _URLSCAN_ROUTE_FIELD[route]
        return _FIELD_MAP.get(f, f)
    # pivot_map may carry field on the route spec
    routes = (load_pivot_map().get("routes") or {})
    spec = routes.get(route) or {}
    f = spec.get("field") or ""
    return _FIELD_MAP.get(f, f) if f else ""


# ---------------------------------------------------------------- route_runnable
def _fofa_configured():
    from wp_common import _secret
    return bool(_secret("FOFA_KEY", "FOFA_API_KEY"))


def _publicwww_configured():
    import wp_publicwww as PW
    return PW.publicwww_configured()


def _webamon_configured():
    import wp_webamon as W
    return W.webamon_configured()


def _anyrun_configured():
    import bp_anyrun as AR
    return AR.anyrun_configured()


def _ghw_configured():
    import wp_buckets as GB
    return GB.ghw_configured()


def _telegram_ready():
    """Telethon (or opentele2) importable, API credentials set and a session file present — the
    wp_telegram backend check, which is offline (no connection, no authorisation probe)."""
    import wp_telegram as WT
    return "skipped" not in WT._backend()


def _ghunt_ready():
    """GHunt installed and a non-empty session file present — wp_google's own dry-run check
    (no network, no session bytes read)."""
    import wp_google as WG
    return bool(WG.lookup("probe@example.com", dry_run=True).get("dry_run"))


def _opencorporates_configured():
    """OpenCorporates FREE WEBSITE mode can sign in: cloakbrowser importable AND (saved session
    file OR OPENCORPORATES_EMAIL + _PASSWORD). Offline — no browser is launched. The premium
    API token is deliberately NOT a gate: the route never spends it."""
    import wp_corp as WC
    return WC.oc_web_configured()


# GrayHatWarfare corpus route → wp_buckets lookup mode.
_GHW_ROUTE_MODE = {"ghw.git_code": "git_code", "ghw.git_committers": "git_committers",
                   "ghw.short_handle": "short_handle"}

# Single-credential / session-bound corpus routes → the collector's own configured() gate. Without
# the key or session the runner only answers `skipped`, so propose() must not offer the route at all.
_ROUTE_GATES = {
    "fofa.body": _fofa_configured,
    "publicwww.source": _publicwww_configured,
    "webamon.corpus": _webamon_configured,
    "anyrun.lookup": _anyrun_configured,
    **{r: _ghw_configured for r in _GHW_ROUTE_MODE},
    "telegram.resolve": _telegram_ready,
    "telegram.phone": _telegram_ready,
    "google.account": _ghunt_ready,
    "corp.opencorporates": _opencorporates_configured,
}


def route_runnable(route: str) -> bool:
    """False when `route` needs a credential / session that is not configured (or its client
    won't load). Routes without a gate are runnable. Every gate is offline."""
    gate = _ROUTE_GATES.get((route or "").strip())
    if gate is None:
        return True
    try:
        return bool(gate())
    except Exception:  # noqa: BLE001 — a client that won't import cannot run the route either
        return False


# ---------------------------------------------------------------- query_for
def query_for(route: str, type_: str, selector: str):
    """Build the corpus query string for (route, type, selector). None = route rejects it."""
    r = (route or "").strip()
    t = (type_ or "").strip().lower()
    sel = str(selector or "").strip()
    if not r or not sel:
        return None
    routes = (load_pivot_map().get("routes") or {})
    spec = routes.get(r)
    if spec is None:
        # still allow known hardcoded routes so unit tests don't need the full map
        if r not in _URLSCAN_ROUTE_FIELD and r not in _WAYBACK_ROUTE_COLLECTION \
                and r not in _GHW_ROUTE_MODE \
                and r not in ("wayback.news", "fofa.body", "publicwww.source", "webamon.corpus",
                              "email.deep", "phone.osint", "rwhois.purchase",
                              "crypto.counterparties", "anyrun.lookup", "binary.analyze",
                              "enrich.host"):
            return None
        spec = {}
    accepted = spec.get("types")
    if isinstance(accepted, list) and accepted and t and t not in accepted:
        return None

    if r.startswith("urlscan."):
        try:
            import wp_recon as WR  # noqa: WPS
        except Exception:  # noqa: BLE001
            WR = None
        field = _urlscan_field_for(r, spec.get("field") or "")
        if not field:
            return None
        if r == "urlscan.identifier":
            # Prefer typed identifier forms when we know the selector kind.
            if t == "telegram":
                handle = sel.rsplit("/", 1)[-1].lstrip("@")
                return (WR.urlscan_field_query("content.identifiers", f"telegram.username.{handle}")
                        if WR else f'content.identifiers:"telegram.username.{handle}"')
            if t == "wallet":
                # BTC/ETH/LTC identifier types; TRON is NOT an identifier — caller should use text.
                low = sel.lower()
                if sel.startswith("0x") and len(sel) == 42:
                    idt = "wallet.ethereum"
                elif sel.startswith(("1", "3", "bc1")):
                    idt = "wallet.bitcoin"
                elif sel.startswith(("L", "M", "ltc1")):
                    idt = "wallet.litecoin"
                elif sel.startswith("T") and len(sel) >= 26:
                    # TRON → text.content, not identifier
                    field = "text.content"
                    return WR.urlscan_field_query(field, sel) if WR else f'{field}:"{sel}"'
                else:
                    idt = "wallet.bitcoin"
                qv = f"{idt}.{sel}"
                return (WR.urlscan_field_query("content.identifiers", qv)
                        if WR else f'content.identifiers:"{qv}"')
            # content.identifiers needs `{type}.{value}`: map tracker-shaped strings to their
            # urlscan identifier type; a plain string has no identifier form (route rejects it).
            up = sel.upper()
            if up.startswith("GTM-"):
                idt = "google.gtm-id"
            elif up.startswith("UA-"):
                idt = "google.ua-id"
            elif up.startswith(("G-", "AW-", "DC-")):
                idt = "google.gtag-id"
            else:
                return None
            qv = f"{idt}.{sel}"
            return (WR.urlscan_field_query("content.identifiers", qv)
                    if WR else f'content.identifiers:"{qv}"')
        return WR.urlscan_field_query(field, sel) if WR else f'{field}:"{sel}"'

    if r in _WAYBACK_ROUTE_COLLECTION or r == "wayback.news":
        return sel

    if r == "fofa.body":
        # FOFA body="…" — escape embedded double quotes
        esc = sel.replace("\\", "\\\\").replace('"', '\\"')
        return f'body="{esc}"'

    if r == "publicwww.source":
        return f'"{sel}"' if not (sel.startswith('"') and sel.endswith('"')) else sel

    if r == "webamon.corpus":
        # Lucene: prefer hash/filename exact, else query_string on page body-ish fields
        if t == "hash":
            return f'resource.sha256:"{sel}" OR resource.md5:"{sel}"'
        if t == "filename":
            esc = sel.replace("\\", "\\\\").replace('"', '\\"')
            return f'resource.url:"{esc}" OR page_title:"{esc}"'
        esc = sel.replace("\\", "\\\\").replace('"', '\\"')
        return f'page_title:"{esc}" OR resolved_url:"{esc}"'

    if r in ("email.deep", "phone.osint", "rwhois.purchase",
             "crypto.counterparties", "anyrun.lookup", "binary.analyze", "enrich.host"):
        return sel

    if r in _GHW_ROUTE_MODE:
        if r == "ghw.git_code" and t == "string":
            # content search tokenises: only a tracker id or one distinctive token (no spaces, ≥ 10
            # chars) is worth a metered query — a page title or a word never is
            from selector_types import tracker_label
            if not (tracker_label(sel) or re.fullmatch(r"[A-Za-z0-9_.:/\-]{10,}", sel)):
                return None
        return sel

    if r in _IDENTITY_ROUTES:
        return _identity_query(r, t, sel, spec)

    return None


# ---------------------------------------------------------------- identity / estate routes
# pivot_map routes served by the identity/estate collectors (pgp_lookup, corp_registry,
# telegram_lookup, google_account, reverse_image, takedown_watch, container_registry,
# masked_hint). Every row they return is a LEAD (RULE 5): rungs.json maps each class to kit or
# neighbour, and fact_only_node_classes keeps names / ids / homonyms off the node registry.
_IDENTITY_ROUTES = ("pgp.lookup", "corp.registry", "corp.opencorporates", "telegram.resolve",
                    "telegram.phone", "google.account", "revimg.links", "takedown.watch",
                    "container.registry", "masked.hint")
_EMAIL_SHAPE = re.compile(r"^[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_REGISTRY_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{1,38}$")
_ORG_NOISE = re.compile(r"privacy|redacted|whois|proxy|guard|protected|domains by|not disclosed",
                        re.I)


def _identity_query(r, t, sel, spec):
    if r == "pgp.lookup":
        return sel.lower() if _EMAIL_SHAPE.match(sel) else None
    if r == "google.account":
        doms = {str(d).lower() for d in (spec.get("email_domains") or ("gmail.com", "googlemail.com"))}
        return sel.lower() if _EMAIL_SHAPE.match(sel) and sel.rsplit("@", 1)[-1].lower() in doms \
            else None
    if r in ("corp.registry", "corp.opencorporates"):
        name = " ".join(sel.split())
        return name if len(name) >= 3 and not _ORG_NOISE.search(name) else None
    if r == "telegram.resolve":
        if _is_tme(sel):
            return sel
        h = sel.lstrip("@")
        return f"@{h}" if re.fullmatch(r"[A-Za-z0-9_]{4,32}", h) else None
    if r == "telegram.phone":
        s = sel.strip()
        digits = re.sub(r"\D", "", s)
        if s.startswith("00"):
            digits = digits[2:]
        elif not s.startswith("+"):
            return None                   # contact import needs E.164 — never guess a country
        return f"+{digits}" if 7 <= len(digits) <= 15 else None
    if r == "revimg.links":
        return sel if re.match(r"^https?://", sel, re.I) else None
    if r == "takedown.watch":
        return sel.lower().strip(".") if t == "domain" else None
    if r == "container.registry":
        if t == "namespace":
            return sel
        slug = sel.strip().lower()
        return slug if _REGISTRY_SLUG.match(slug) else None   # an org name with spaces is no namespace
    if r == "masked.hint":
        return sel if ":" in sel else f"unknown:{sel}"
    return None


def _is_tme(v):
    low = v.lower()
    return low.startswith(("t.me/", "telegram.me/")) or "://t.me/" in low or "://telegram.me/" in low


# ---------------------------------------------------------------- count
def count(route: str, query: str, *, free_only: bool = False):
    """Cheap hit-count probe. Returns int or None (unknown → forces approval). Never raises."""
    r = (route or "").strip()
    q = str(query or "").strip()
    if not r or not q:
        return None
    routes = (load_pivot_map().get("routes") or {})
    spec = routes.get(r) or {}
    probe = spec.get("count_probe") or ""
    metered = bool(spec.get("metered"))

    if free_only and metered and r not in (
            # urlscan is quota-backed, not "metered" in pivot_map, but free_only still
            # forces the keyless path via the client flag below
    ):
        # Metered routes cannot be counted under free_only without spending — unknown.
        if r in ("fofa.body", "publicwww.source", "email.deep", "rwhois.purchase",
                 "anyrun.lookup"):
            return None

    try:
        if r.startswith("urlscan."):
            import wp_recon as WR
            return WR.urlscan_count(q, free_only=free_only)

        if r in _WAYBACK_ROUTE_COLLECTION:
            import wp_wayback_search as WS
            return WS.count(q, _WAYBACK_ROUTE_COLLECTION[r])

        if r == "wayback.news":
            import wp_wayback_search as WS
            # Sum across news collections best-effort; any failure → None if all fail
            total = 0
            any_ok = False
            for c in _NEWS_COLLECTIONS:
                n = WS.count(q, c)
                if isinstance(n, int):
                    total += n
                    any_ok = True
            return total if any_ok else None

        if r == "rwhois.purchase":
            # Free preview count via whois_enrich --reverse-mode preview
            return _rwhois_preview_count(q)

        if probe == "single":
            # one bounded lookup of one selector (keyserver, registry, resolve, status check):
            # no vendor count call exists or is needed — the pivot itself is the unit
            return 1

        # none / unknown
        return None
    except Exception:  # noqa: BLE001
        return None


def _rwhois_preview_count(term: str):
    script = os.path.join(_WP_TOOLS, "whois_enrich.py")
    if not os.path.isfile(script):
        return None
    # Guess email vs phone
    flag = "--reverse-email" if "@" in term else "--reverse-phone"
    try:
        cp = subprocess.run(
            [_PY, script, flag, term, "--search-type", "historic",
             "--reverse-mode", "preview", "--json"],
            capture_output=True, text=True, timeout=90,
            cwd=_ENGINE)
        data = json.loads(cp.stdout or "{}")
    except Exception:  # noqa: BLE001
        return None
    rec = (data.get("reverse_email") or data.get("reverse_phone")
           or data.get("reverse_name") or {})
    c = rec.get("count") if isinstance(rec, dict) else None
    return c if isinstance(c, int) else None


# ---------------------------------------------------------------- run helpers
def _row(type_, value, rung_class, source, evidence=None, coin=""):
    out = {"type": type_, "value": value, "rung_class": rung_class,
           "source": source, "evidence": evidence or {}}
    if coin:
        out["coin"] = coin
    return out


def _run_urlscan(route, query, *, free_only=False):
    import wp_recon as WR
    res = WR.urlscan_search(query, limit=100, max_results=100, free_only=free_only)
    if not isinstance(res, dict):
        return {"error": "urlscan returned nothing"}
    if res.get("error"):
        return {"error": str(res["error"])}
    field = _urlscan_field_for(route)
    # Default host rung from the field; identifier owner overrides below.
    host_rc = _HOST_RUNG.get(field, "string")
    # For identifier routes, try to infer rung from the query text.
    if route == "urlscan.identifier":
        host_rc = _infer_identifier_rung_from_query(query)
    rows = []
    for d in res.get("domains") or []:
        if not d:
            continue
        rows.append(_row("domain", str(d).lower(), host_rc, route,
                         evidence={"query": query, "field": field}))
    return {"rows": rows, "total": res.get("total")}


def _infer_identifier_rung_from_query(query: str) -> str:
    q = (query or "").replace("\\", "")      # undo Lucene escaping (google.gtm\-id → google.gtm-id)
    # content.identifiers:"telegram.bot-token.xxx" or field:type.value
    for idt, rc in _ID_RUNGS.items():
        if idt in q:
            # wallet + exchange check needs the value; best-effort extract
            if rc == "wallet.operator":
                m = re.search(r"(bc1[a-z0-9]+|[13][a-zA-Z0-9]{25,34}|0x[a-fA-F0-9]{40}"
                              r"|T[1-9A-HJ-NP-Za-km-z]{33})", q)
                if m:
                    return wallet_rung(m.group(1)) or "string"
            return rc
    if "telegram.bot-token" in q:
        return "token.telegram_bot"
    return "token.other"


def _run_wayback(route, query):
    import wp_wayback_search as WS
    if route == "wayback.news":
        all_rows, total = [], 0
        any_ok = False
        last_err = None
        for c in _NEWS_COLLECTIONS:
            res = WS.search_all(query, c)
            if res.get("error"):
                last_err = res
                continue
            any_ok = True
            hits = res.get("hits") or []
            all_rows.extend(WS.hits_to_rows(hits, c, require_term=query))
            if isinstance(res.get("total"), int):
                total += res["total"]
        if not any_ok:
            return last_err or {"error": "collection unavailable"}
        return {"rows": all_rows, "total": total}

    coll = _WAYBACK_ROUTE_COLLECTION.get(route)
    if not coll:
        return {"error": f"unknown wayback route {route}"}
    res = WS.search_all(query, coll)
    if res.get("error"):
        return res
    host_rc = "filename" if route == "wayback.pdf" else "string"
    rows = WS.hits_to_rows(res.get("hits") or [], coll, rung_class_host=host_rc,
                           require_term=query)
    return {"rows": rows, "total": res.get("total")}


def _source_search_rung(query):
    """Rung class for hosts returned by a SOURCE search (FOFA body / PublicWWW): a host embedding
    the operator's analytics ID gets that ID's owner class (rungs.json analytics.*); any other
    term (string, filename, verification token) is kit."""
    import re as _re
    from selector_types import _TRACKER_RUNG, tracker_label
    for term in _re.findall(r"[A-Za-z0-9_\-]{4,}", str(query or "")):
        label = tracker_label(term)
        if label:
            return _TRACKER_RUNG.get(label, "string")
    return "string"


def _run_fofa(query, *, free_only=False):
    if free_only:
        return {"skipped": "fofa.body is metered; free_only"}
    import wp_recon as WR
    res = WR.fofa_search(query, size=100)
    if res is None:
        return {"skipped": "FOFA_KEY not set"}
    if res.get("error"):
        return {"error": str(res["error"])}
    rows = []
    for row in res.get("results") or []:
        if not isinstance(row, dict):
            continue
        d = (row.get("domain") or row.get("host") or "").strip().lower()
        # strip URL/host:port
        if "://" in d:
            d = urllib.parse.urlparse(d).hostname or d
        d = d.split(":")[0].rstrip(".")
        if d:
            rows.append(_row("domain", d, _source_search_rung(query), "fofa.body",
                             evidence={"title": row.get("title"), "ip": row.get("ip"),
                                       "query": query}))
    return {"rows": rows, "total": res.get("total")}


def _run_publicwww(query, *, free_only=False):
    if free_only:
        return {"skipped": "publicwww.source is metered; free_only"}
    import wp_publicwww as PW
    res = PW.search(query)
    if res.get("skipped"):
        return {"skipped": res["skipped"]}
    if res.get("error"):
        return {"error": str(res["error"])}
    rows = [_row("domain", d, _source_search_rung(query), "publicwww.source",
                 evidence={"query": query}) for d in (res.get("domains") or []) if d]
    return {"rows": rows, "total": res.get("total")}


def _run_webamon(query, *, free_only=False):
    # Webamon is free-with-key (not metered credits); free_only still allows it when keyed.
    import wp_webamon as W
    if not W.webamon_configured():
        return {"skipped": "WEBAMON_API_KEY not set"}
    data, err = W.search(query, size=50)
    if err:
        if isinstance(err, dict):
            return err if (err.get("error") or err.get("skipped")) else {"error": str(err)}
        return {"error": str(err)}
    rows = []
    for hit in (data or {}).get("results") or []:
        if not isinstance(hit, dict):
            continue
        d = W._hit_domain(hit) if hasattr(W, "_hit_domain") else (
            str(hit.get("resolved_domain") or "").lower())
        if d:
            rows.append(_row("domain", d, "string", "webamon.corpus",
                             evidence={"title": hit.get("page_title"),
                                       "report_id": hit.get("report_id"),
                                       "query": query}))
    total = data.get("total_hits") if isinstance(data, dict) else len(rows)
    return {"rows": rows, "total": total if isinstance(total, int) else len(rows)}


def _run_email_deep(selector, *, free_only=False, case=""):
    script = os.path.join(_SKILL, "scripts", "osint", "deep_profile.py")
    if not os.path.isfile(script):
        return {"skipped": "no structured output"}
    cmd = [_PY, script, selector]
    if free_only:
        cmd.append("--free-only")
    if case:
        # deep_profile wants a case dir path; pass the engine cases/<id> if present
        cdir = os.path.join(_ENGINE, "cases", case)
        cmd += ["--case", cdir if os.path.isdir(cdir) else case]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=_SKILL)
        data = json.loads(cp.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    if not isinstance(data, dict):
        return {"skipped": "no structured output"}
    rows = []
    # reverse_whois domains are the structured pivot; rung owner whois.registrant_email
    rw = (data.get("ran") or {}).get("reverse_whois") or {}
    for d in rw.get("domains") or []:
        if isinstance(d, str) and d.strip():
            rows.append(_row("domain", d.strip().lower(), "whois.registrant_email",
                             "email.deep", evidence={"selector": selector,
                                                     "count": rw.get("count")}))
    # Domain of the email itself as kit context (not owner)
    dom = data.get("domain")
    if dom and not any(r["value"] == str(dom).lower() for r in rows):
        rows.append(_row("domain", str(dom).lower(), "string", "email.deep",
                         evidence={"selector": selector, "via": "email_domain"}))
    return {"rows": rows, "total": len(rows), "raw_keys": list((data.get("ran") or {}).keys())}


def _run_phone_osint(selector, *, free_only=False):
    script = os.path.join(_SKILL, "scripts", "osint", "phone_osint.py")
    if not os.path.isfile(script):
        return {"skipped": "no structured output"}
    try:
        cp = subprocess.run([_PY, script, selector], capture_output=True, text=True,
                            timeout=30, cwd=_SKILL)
        data = json.loads(cp.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    if not isinstance(data, dict) or "results" not in data:
        return {"skipped": "no structured output"}
    # Phone OSINT is decomposition + query strings — no host rows. Return empty structured.
    rows = []
    for r in data.get("results") or []:
        if not isinstance(r, dict) or not r.get("valid"):
            continue
        e164 = r.get("e164")
        if e164:
            rows.append(_row("phone", e164, "page.phone", "phone.osint",
                             evidence={"territory": r.get("territory"),
                                       "national_number": r.get("national_number")}))
    return {"rows": rows, "total": len(rows)}


def _run_rwhois_purchase(selector, *, free_only=False):
    if free_only:
        return {"skipped": "rwhois.purchase is metered; free_only"}
    script = os.path.join(_WP_TOOLS, "whois_enrich.py")
    if not os.path.isfile(script):
        return {"error": "whois_enrich.py missing"}
    flag = "--reverse-email" if "@" in selector else "--reverse-phone"
    rung = "whois.registrant_email" if flag.endswith("email") else "whois.registrant_phone"
    try:
        cp = subprocess.run(
            [_PY, script, flag, selector, "--search-type", "historic",
             "--reverse-mode", "purchase", "--json"],
            capture_output=True, text=True, timeout=150, cwd=_ENGINE)
        data = json.loads(cp.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    rec = (data.get("reverse_email") or data.get("reverse_phone")
           or data.get("reverse_name") or {})
    if not isinstance(rec, dict):
        return {"error": "unexpected reverse-whois shape"}
    if rec.get("error"):
        return {"error": str(rec["error"])}
    rows = [_row("domain", str(d).lower(), rung, "rwhois.purchase",
                 evidence={"term": selector, "count": rec.get("count")})
            for d in (rec.get("domains") or []) if isinstance(d, str) and d.strip()]
    return {"rows": rows, "total": rec.get("count", len(rows))}


def _run_counterparties(selector, *, free_only=False):
    script = os.path.join(_SKILL, "scripts", "webpivot", "crypto_balance.py")
    if not os.path.isfile(script):
        return {"error": "crypto_balance.py missing"}
    try:
        cp = subprocess.run(
            [_PY, script, selector, "--counterparties", "15"],
            capture_output=True, text=True, timeout=120, cwd=_SKILL)
        data = json.loads(cp.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or not results:
        return {"error": "no counterparties result"}
    block = results[0]
    if block.get("skipped"):
        return {"skipped": block["skipped"]}
    if block.get("error"):
        return {"error": str(block["error"])}
    coin = str(block.get("coin") or "").lower()
    rows = []
    for c in block.get("counterparties") or []:
        if not isinstance(c, dict):
            continue
        addr = str(c.get("address") or "").strip()
        if not addr:
            continue
        rc = wallet_rung(addr)
        if rc is None:                       # reference constant (burn / test vector) — not a party
            continue
        if rc == "wallet.operator" and c.get("exchange"):
            rc = "wallet.exchange"
        rows.append(_row("wallet", addr, rc, "crypto.counterparties",
                         evidence={"value": c.get("value"), "label": c.get("label"),
                                   "seed": selector},
                         coin=(c.get("coin") or coin or "").lower()))
    return {"rows": rows, "total": len(rows)}


def _run_anyrun(selector, *, free_only=False):
    if free_only:
        return {"skipped": "anyrun.lookup is metered; free_only"}
    try:
        import bp_anyrun as AR
    except Exception:  # noqa: BLE001
        return {"skipped": "no structured output"}
    # Classify selector into kind
    t = classify(selector)
    kind_map = {"hash": "sha256" if len(selector) == 64 else ("md5" if len(selector) == 32 else "sha256"),
                "domain": "domain", "ip": "ip"}
    kind = kind_map.get(t)
    if not kind:
        # try raw query
        res = AR.ti_lookup(selector) if hasattr(AR, "ti_lookup") else None
    else:
        res = AR.lookup_artifact(kind, selector) if hasattr(AR, "lookup_artifact") else None
    if res is None:
        return {"skipped": "ANYRUN_API_KEY not set"}
    if not isinstance(res, dict):
        return {"skipped": "no structured output"}
    if res.get("skipped"):
        return {"skipped": res["skipped"]}
    if res.get("error"):
        return {"error": str(res["error"])}
    # Need structured domains/ips
    if not any(k in res for k in ("domains", "ips", "urls", "related_files")):
        return {"skipped": "no structured output"}
    rows = []
    for d in res.get("domains") or []:
        if d:
            rows.append(_row("domain", str(d).lower(), "string", "anyrun.lookup",
                             evidence={"query": selector, "threat": res.get("threat_names")}))
    for ip in res.get("ips") or []:
        if ip:
            rows.append(_row("ip", str(ip), "ip.cotenant", "anyrun.lookup",
                             evidence={"query": selector}))
    for h in res.get("related_files") or []:
        if h:
            rows.append(_row("hash", str(h).lower(), "hash", "anyrun.lookup",
                             evidence={"query": selector}))
    return {"rows": rows, "total": len(rows)}


def _run_binary(selector, *, free_only=False):
    # analyze_artifact needs a file path or URL, not a bare hash — no structured pivot from hash alone
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", selector or ""):
        return {"skipped": "no structured output"}
    script = os.path.join(_ENGINE, "BinaryPivot", "tools", "analyze_artifact.py")
    if not os.path.isfile(script):
        return {"skipped": "no structured output"}
    # If selector looks like a path/URL, try running it
    if not (os.path.isfile(selector) or str(selector).startswith(("http://", "https://"))):
        return {"skipped": "no structured output"}
    try:
        cp = subprocess.run([_PY, script, selector], capture_output=True, text=True,
                            timeout=120, cwd=_ENGINE)
        data = json.loads(cp.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    if not isinstance(data, dict) or "pivots" not in data:
        return {"skipped": "no structured output"}
    rows = []
    for p in data.get("pivots") or []:
        if not isinstance(p, dict):
            continue
        # pivots are usually {kind, value, …} — map best-effort
        val = p.get("value") or p.get("indicator") or ""
        kind = (p.get("kind") or p.get("type") or "string").lower()
        if not val:
            continue
        type_map = {"domain": "domain", "host": "domain", "url": "domain",
                    "email": "email", "ip": "ip", "hash": "hash", "sha256": "hash",
                    "md5": "hash", "sha1": "hash", "wallet": "wallet",
                    "telegram": "telegram", "filename": "filename"}
        t = type_map.get(kind, "string")
        rc = {"domain": "string", "hash": "hash", "filename": "filename",
              "email": "page.email", "ip": "ip.cotenant", "wallet": "wallet.operator",
              "telegram": "telegram.username"}.get(t, "string")
        if t == "domain" and "://" in str(val):
            val = urllib.parse.urlparse(str(val)).hostname or val
        if t == "wallet":
            rc = wallet_rung(str(val))
            if rc is None:
                continue
        rows.append(_row(t, str(val), rc, "binary.analyze",
                         evidence={"source": (data.get("meta") or {}).get("source")}))
    return {"rows": rows, "total": len(rows)}


def _run_ghw(route, query, *, case="", free_only=False):
    """One GrayHatWarfare lookup as a corpus route. With a case the raw result is also persisted in
    cases/<case>/grayhatwarfare/exposure.json (lookups) for the report; ingest stays with execute()."""
    if free_only:
        return {"skipped": f"{route} is metered; free_only"}
    mode = _GHW_ROUTE_MODE.get(route)
    import wp_buckets as GB
    if case:
        import ghw_exposure as GX
        res = GX.lookup(mode, query, case=case, ingest=False)
    else:
        res = GB.lookup(mode, query)
    if not isinstance(res, dict) or res.get("error"):
        return {"error": str((res or {}).get("error") or "empty result")}
    if res.get("skipped"):
        return {"skipped": str(res["skipped"])}
    rows = GB.rows_for(res)
    return {"rows": rows, "total": res.get("results", len(rows))}


def _cdir(case):
    c = str(case or "")
    if not c:
        return ""
    if os.path.isabs(c) or os.sep in c:
        return c
    return os.path.join(_ENGINE, "cases", c)


def _norm_q(s):
    return " ".join(str(s or "").split()).lower()


def _consume_approval(case, route, query):
    """The analyst's approval of a proposal item IS the confirm for an approval:always route. True
    (and the item is marked used — single-use, the same rule audit.gate applies to metered items)
    only when cases/<case>/proposal.json is approved/running and lists an approved, unused item for
    exactly this route + query. Anything else — no case, no proposal, another query — is False."""
    cdir = _cdir(case)
    if not cdir:
        return False
    path = os.path.join(cdir, "proposal.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict) or data.get("status") not in ("approved", "running"):
        return False
    used = set(data.get("used") or [])
    approved = set(data.get("approved") or []) - used
    for item in data.get("items") or []:
        if (isinstance(item, dict) and item.get("id") in approved and item.get("tool") == route
                and _norm_q(item.get("query")) == _norm_q(query)):
            data.setdefault("used", []).append(item["id"])
            tmp = path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, ensure_ascii=False)
                os.replace(tmp, path)
            except OSError:
                return False
            return True
    return False


def _case_jurisdiction(case):
    """ISO country for a corp search: scope.json `jurisdiction` when the analyst stated one, else
    the ONE ccTLD every collected case apex shares (uk → GB), else None (global registries)."""
    cdir = _cdir(case)
    if not cdir:
        return None
    try:
        with open(os.path.join(cdir, "scope.json"), encoding="utf-8") as fh:
            j = (json.load(fh) or {}).get("jurisdiction")
        if j:
            return str(j).strip().upper()
    except (OSError, ValueError, AttributeError):
        pass
    tlds = set()
    for p in glob.glob(os.path.join(cdir, "raw", "*.json")):
        host = os.path.basename(p)[:-5].lower()
        if "." not in host or re.fullmatch(r"[\d.]+", host):
            continue
        tlds.add(host.rsplit(".", 1)[-1])
    if len(tlds) != 1:
        return None
    tld = tlds.pop()
    if len(tld) != 2 or not tld.isalpha():
        return None
    return "GB" if tld == "uk" else tld.upper()


def _run_pgp(query):
    import wp_pgp as WP
    res = WP.lookup(query)
    if not isinstance(res, dict) or res.get("error"):
        return {"error": str((res or {}).get("error") or "empty result")}
    cls = {"email": ("email", "pgp.uid_email"), "person_name": ("string", "pgp.uid_name"),
           "pgp_fingerprint": ("string", "pgp.fingerprint"),
           "pgp_certifier_keyid": ("string", "pgp.certifier")}
    rows = []
    for p in res.get("pivots") or []:
        kind = cls.get(p.get("type"))
        val = str(p.get("value") or "").strip()
        if not kind or not val:
            continue
        t, rc = kind
        if rc in ("pgp.fingerprint", "pgp.certifier"):
            val = f"pgp:{val}"
        rows.append(_row(t, val, rc, "pgp.lookup",
                         evidence={"selector": query, "fingerprint": p.get("fingerprint"),
                                   "sources": p.get("sources"), "caveat": p.get("caveat")}))
    return {"rows": rows, "total": len(res.get("keys") or [])}


def _run_corp(route, query, *, case="", free_only=False):
    import wp_corp as WC
    if route == "corp.opencorporates":
        if not WC.oc_web_configured():
            return {"skipped": "OpenCorporates website mode not configured (cloakbrowser + "
                               "`wp_corp.py opencorporates-login`)"}
        providers = ["opencorporates"]
    else:
        providers = [n for n, cfg in WC.PROVIDERS.items()
                     if not str(n).startswith("_") and isinstance(cfg, dict) and cfg.get("keyless")
                     and not cfg.get("metered")]
    jur = _case_jurisdiction(case)
    res = WC.run("company", query, jurisdiction=jur, providers=providers,
                 oc_api=False)                       # route is free: never the metered API
    if not isinstance(res, dict) or res.get("error"):
        return {"error": str((res or {}).get("error") or "empty result")}
    oc = (res.get("providers") or {}).get("opencorporates") or {}
    if route == "corp.opencorporates" and oc.get("status") in ("gated", "skipped", "error"):
        why = oc.get("gated") and f"gated: {oc['gated']} (collection gap, not a negative)"
        return {"skipped": why or oc.get("reason") or oc.get("error") or oc.get("status")}
    rows = []
    for c in res.get("companies") or []:
        ev = {"name": c.get("name"), "jurisdiction": c.get("jurisdiction"), "status": c.get("status"),
              "provider": c.get("provider"), "source_url": c.get("source_url"), "query": query}
        if c.get("number"):
            rows.append(_row("string", f"{c.get('provider') or 'registry'}:{c['number']}",
                             "corp.company_id", route, evidence=ev))
        if c.get("lei"):
            rows.append(_row("string", f"lei:{c['lei']}", "corp.company_id", route, evidence=ev))
    for o in res.get("officers") or []:
        if o.get("name"):
            rows.append(_row("string", str(o["name"]).strip(), "corp.officer", route,
                             evidence={"company_name": o.get("company_name"), "role": o.get("role"),
                                       "provider": o.get("provider"),
                                       "source_url": o.get("source_url"),
                                       "caveat": o.get("caveat")}))
    return {"rows": rows, "total": len(res.get("companies") or []), "jurisdiction": jur}


def _telegram_rows(entity, route, source_q, cls):
    rows = []
    if not isinstance(entity, dict):
        return rows
    for u in entity.get("usernames") or []:
        name = u.get("username") if isinstance(u, dict) else u
        if name:
            rows.append(_row("telegram", str(name).lower(), cls, route,
                             evidence={"query": source_q, "type": entity.get("type"),
                                       "active": u.get("active") if isinstance(u, dict) else None}))
    if entity.get("id") is not None:
        rows.append(_row("string", f"tg:{entity['id']}", "telegram.account_id", route,
                         evidence={"query": source_q, "type": entity.get("type"),
                                   "title": entity.get("title")}))
    return rows


def _run_telegram_resolve(query):
    import wp_telegram as WT
    res = WT.resolve(query)
    if not isinstance(res, dict):
        return {"error": "empty result"}
    if res.get("skipped") or res.get("error"):
        return {"skipped": str(res["skipped"])} if res.get("skipped") else {"error": str(res["error"])}
    row = (res.get("results") or [{}])[0]
    if row.get("error"):
        return {"error": str(row["error"])}
    rows = _telegram_rows(row.get("entity"), "telegram.resolve", query, "telegram.account")
    return {"rows": rows, "total": 1 if row.get("entity") else 0}


def _run_telegram_phone(query, *, case=""):
    import wp_telegram as WT
    if not _consume_approval(case, "telegram.phone", query):
        # no approved proposal item for this number → the briefing only; nothing is imported
        return {"skipped": "telegram.phone imports a contact on the research account and runs only "
                           "as an APPROVED proposal item (case_approve) — briefing returned",
                "briefing": WT.briefing([query])}
    res = WT.phone_lookup([query], confirm=True)
    if not isinstance(res, dict):
        return {"error": "empty result"}
    if res.get("skipped") or res.get("error"):
        return {"skipped": str(res["skipped"])} if res.get("skipped") else {"error": str(res["error"])}
    rows = []
    for r in res.get("results") or []:
        if r.get("found"):
            rows += _telegram_rows(r.get("account"), "telegram.phone", query, "telegram.phone_account")
    return {"rows": rows, "total": sum(1 for r in res.get("results") or [] if r.get("found"))}


def _run_google(query, *, case=""):
    import wp_google as WG
    if not _consume_approval(case, "google.account", query):
        return {"skipped": "google.account uses the analyst's GHunt session and runs only as an "
                           "APPROVED proposal item (case_approve)"}
    res = WG.lookup(query)
    if not isinstance(res, dict):
        return {"error": "empty result"}
    if res.get("skipped") or res.get("error"):
        return {"skipped": str(res["skipped"])} if res.get("skipped") else {"error": str(res["error"])}
    ev = {"query": query, "account_type": res.get("account_type")}
    rows = []
    if res.get("gaia_id"):
        rows.append(_row("string", f"gaia:{res['gaia_id']}", "google.gaia_id", "google.account", ev))
    if res.get("profile_name"):
        rows.append(_row("string", str(res["profile_name"]), "google.profile_name",
                         "google.account", ev))
    photo = res.get("profile_photo") or {}
    if isinstance(photo, dict) and photo.get("url") and not photo.get("is_default"):
        rows.append(_row("image_url", str(photo["url"]), "google.profile_photo", "google.account", ev))
    return {"rows": rows, "total": 1 if rows else 0}


def _run_revimg(query, *, case="", hostile=False):
    import wp_revimg as WRI
    if not re.match(r"^https?://", query, re.I):
        return {"skipped": "revimg.links takes a public image URL only — a local file is never uploaded"}
    if hostile and case:
        host = (urllib.parse.urlsplit(query).hostname or "").lower()
        raws = {os.path.basename(p)[:-5].lower()
                for p in glob.glob(os.path.join(_cdir(case), "raw", "*.json"))}
        if host in raws or any(host.endswith("." + h) for h in raws):
            return {"skipped": "hostile posture: the image is served by a case host — no direct fetch"}
    res = WRI.search(query, case=case or None, confirm=False, links_only=False)
    if not isinstance(res, dict) or res.get("error"):
        return {"error": str((res or {}).get("error") or "empty result")}
    rows, seen = [], set()
    for h in res.get("hits") or []:
        d = str(h.get("domain") or "").lower().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        rows.append(_row("domain", d, "revimg.hit", "revimg.links",
                         evidence={"image": query, "url": h.get("url"), "title": h.get("title"),
                                   "engine": h.get("engine"), "caveat": h.get("caveat")}))
    return {"rows": rows, "total": len(res.get("hits") or [])}


def _run_takedown(query, *, case="", hostile=False):
    import wp_takedown as WTD
    slots = {}
    cdir = _cdir(case)
    if cdir and os.path.isdir(cdir):
        try:
            slots = WTD.case_apexes(cdir) or {}
        except Exception:  # noqa: BLE001 — no case history → live RDAP/DNS + hostsearch only
            slots = {}
    # hostile posture: list co-tenants without fetching their pages from this egress
    res = WTD.watch(query, case_slot=slots.get(query), fetch_pages=not hostile)
    if not isinstance(res, dict):
        return {"error": "empty result"}
    status = {"status": res.get("status"), "held_since": res.get("held_since"),
              "signals": (res.get("signals") or [])[:6]}
    rows = []
    for s in res.get("successors") or []:
        d = str(s.get("domain") or "").lower()
        if not d:
            continue
        kit = s.get("rung") == "kit"
        rows.append(_row("domain", d, "takedown.kit_sibling" if kit else "takedown.cotenant",
                         "takedown.watch",
                         evidence=dict(status, held=query, shared_ip=s.get("shared_ip"),
                                       content_match=s.get("content_match"),
                                       caveat=s.get("caveat"))))
    return {"rows": rows, "total": len(rows), "takedown_status": status}


_GITHUB_OWNER = re.compile(r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)(?:/|$)", re.I)


def _run_container(query, *, case=""):
    import wp_container as WCT
    res = WCT.registry_osint(query, layers=False)
    if res is None:
        return {"rows": [], "total": 0}
    if not isinstance(res, dict) or res.get("error"):
        return {"error": str((res or {}).get("error") or "empty result")}
    if case:
        try:
            WCT.save_to_case(case, res)
        except Exception:  # noqa: BLE001 — persistence is best-effort; the rows still ingest
            pass
    rows, seen = [], set()

    def add(t, v, rc, ev):
        if (t, v.lower()) not in seen:
            seen.add((t, v.lower()))
            rows.append(_row(t, v, rc, "container.registry", evidence=ev))

    for i in res.get("identities") or []:
        it, val = i.get("type"), str(i.get("value") or "").strip()
        if not val:
            continue
        ev = {"namespace": query, "source": i.get("source"), "image": i.get("image")}
        if it == "email":
            add("email", val.lower(), "container.identity_email", ev)
        elif it == "name":
            add("string", val, "container.identity_name", ev)
        elif it == "org":
            add("org", val, "container.org", ev)
        elif it == "registry_namespace":
            add("string", val, "container.namespace", ev)
        elif it == "source_repo":
            m = _GITHUB_OWNER.search(val)
            ns = f"ghcr.io/{m.group(1).lower()}" if m else ""
            if ns and ns != query.lower():
                add("namespace", ns, "container.source_repo", dict(ev, repo=val))
    return {"rows": rows, "total": len(res.get("repositories") or res.get("images") or [])}


def _run_masked_hint(query, *, case=""):
    import masked_hint as MH
    provider, _, hint = query.partition(":")
    if not hint:
        provider, hint = "unknown", query
    if not case:
        return {"skipped": "masked.hint tests a hint against a case's known selectors — needs case="}
    res = MH.run([hint], case=case, provider=provider or "unknown")
    if not isinstance(res, dict) or res.get("error"):
        # "no known candidates" is an honest empty, not a failure
        err = str((res or {}).get("error") or "empty result")
        return {"rows": [], "total": 0} if "no known" in err else {"error": err}
    rows = []
    for h in res.get("hints") or []:
        if h.get("verdict") not in ("corroborates", "consistent"):
            continue
        for m in h.get("matches") or []:
            cand = str(m.get("candidate") or "").strip()
            if cand:
                rows.append(_row("email" if "@" in cand else "phone", cand, "masked_hint.match",
                                 "masked.hint",
                                 evidence={"hint": hint, "provider": provider,
                                           "verdict": h.get("verdict"), "reason": h.get("reason"),
                                           "strength": m.get("strength")}))
    return {"rows": rows, "total": len(rows)}


# ---------------------------------------------------------------- run
def run(route: str, query: str, *, case="", free_only: bool = False, hostile: bool = False):
    """Execute one corpus route. Returns {rows,total} | {error} | {skipped}. Never raises."""
    r = (route or "").strip()
    q = str(query or "").strip()
    if not r:
        return {"error": "empty route"}
    if not q:
        return {"error": "empty query"}
    # hostile: still OK for passive corpora; no special block (urlscan/wayback/fofa don't touch target)
    try:
        if r.startswith("urlscan."):
            return _run_urlscan(r, q, free_only=free_only)
        if r.startswith("wayback."):
            return _run_wayback(r, q)
        if r == "fofa.body":
            return _run_fofa(q, free_only=free_only)
        if r == "publicwww.source":
            return _run_publicwww(q, free_only=free_only)
        if r == "webamon.corpus":
            return _run_webamon(q, free_only=free_only)
        if r == "email.deep":
            return _run_email_deep(q, free_only=free_only, case=case)
        if r == "phone.osint":
            return _run_phone_osint(q, free_only=free_only)
        if r == "rwhois.purchase":
            return _run_rwhois_purchase(q, free_only=free_only)
        if r == "crypto.counterparties":
            return _run_counterparties(q, free_only=free_only)
        if r == "anyrun.lookup":
            return _run_anyrun(q, free_only=free_only)
        if r == "binary.analyze":
            return _run_binary(q, free_only=free_only)
        if r in _GHW_ROUTE_MODE:
            return _run_ghw(r, q, case=case, free_only=free_only)
        if r == "pgp.lookup":
            return _run_pgp(q)
        if r in ("corp.registry", "corp.opencorporates"):
            return _run_corp(r, q, case=case, free_only=free_only)
        if r == "telegram.resolve":
            return _run_telegram_resolve(q)
        if r == "telegram.phone":
            return _run_telegram_phone(q, case=case)
        if r == "google.account":
            return _run_google(q, case=case)
        if r == "revimg.links":
            return _run_revimg(q, case=case, hostile=hostile)
        if r == "takedown.watch":
            return _run_takedown(q, case=case, hostile=hostile)
        if r == "container.registry":
            return _run_container(q, case=case)
        if r == "masked.hint":
            return _run_masked_hint(q, case=case)
        if r == "enrich.host":
            # Full keyed collection of a host is run by the harness loop's executor (it owns the
            # collector config and the approval), never as a bare corpus query.
            return {"skipped": "enrich.host runs only through the harness loop after approval"}
        return {"error": f"unknown route: {r}"}
    except Exception as e:  # noqa: BLE001 — contract: never raise
        return {"error": f"{type(e).__name__}: {e}"}


def _case_no_spend(case: str) -> bool:
    try:
        with open(os.path.join(_ENGINE, "cases", str(case), "scope.json"), encoding="utf-8") as fh:
            return bool(((json.load(fh) or {}).get("constraints") or {}).get("no_spend"))
    except (OSError, ValueError, AttributeError):
        return False


def execute(route: str, query: str, *, case: str, origin_type: str = "string",
            origin_value: str = "", free_only: bool = False, hostile: bool = False,
            kb_root: str = "", rung_cap: str = "") -> dict:
    """Run one route, ingest its rows into the KB (rung-aware, ingest_typed) and record them as
    typed nodes in the case state — the ONE path the corpus_search tool, the CLI and the harness
    loop share. A `no_spend` case scope forces free_only. Never raises.

    `rung_cap` (kit|neighbour): the pivot's SOURCE was not owner-linked (e.g. a GA id seen only on
    a hosting co-tenant), so no hit may come back stronger than that — an owner-class row is
    downgraded to `kit_link`/`neighbour_link` BEFORE ingest, so it lands as a fact, never an owner
    edge, and never becomes owner evidence for the case."""
    if not case:
        return {"error": "execute needs case= so ingest provenance and nodes are scoped"}
    free_only = bool(free_only) or _case_no_spend(case)
    res = run(route, query, case=case, free_only=free_only, hostile=hostile)
    if not isinstance(res, dict) or res.get("error") or res.get("skipped"):
        return res if isinstance(res, dict) else {"error": "empty result"}
    rows = res.get("rows") or []
    if rung_cap in ("kit", "neighbour"):
        from selector_types import rung_for
        capped = "kit_link" if rung_cap == "kit" else "neighbour_link"
        order = {"owner": 0, "kit": 1, "neighbour": 2}
        rows = [dict(r, rung_class=capped)
                if order.get(rung_for(str(r.get("rung_class") or "")), 1) < order[rung_cap] else r
                for r in rows]
    origin_value = str(origin_value or query)
    out = {"route": route, "query": query, "case": case, "total": res.get("total"),
           "rows": len(rows), "ingested": 0, "nodes_added": 0, "sample": rows[:8]}
    try:
        import ingest_typed as _IT  # noqa: E402
        from knowledge_base import KB  # noqa: E402
        root = kb_root or os.path.join(_ENGINE, os.environ.get("HARNESS_KB", "knowledge"))
        out["ingested"] = _IT.ingest_rows(KB(root), case, origin_type, origin_value, rows,
                                          route=route)
    except Exception as e:  # noqa: BLE001
        out["ingest_error"] = f"{type(e).__name__}: {e}"
    try:
        import case_state as _cs  # noqa: E402
        out["nodes_added"] = _cs.add_nodes(case, rows, origin_type=origin_type,
                                           origin_value=origin_value, route=route)
    except Exception as e:  # noqa: BLE001
        out["nodes_error"] = f"{type(e).__name__}: {e}"
    return out


def _main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Run one cross-type corpus route (pivot_map.json) "
                                             "and ingest its typed rows into the case.")
    ap.add_argument("route", help="pivot_map route key, e.g. urlscan.filename, wayback.telegram")
    ap.add_argument("query", help="the selector or prepared query")
    ap.add_argument("--case", required=True)
    ap.add_argument("--origin-type", default="string")
    ap.add_argument("--origin-value", default="")
    ap.add_argument("--free-only", action="store_true")
    ap.add_argument("--count", action="store_true", help="only print the cheap hit-count probe")
    a = ap.parse_args(argv)
    if a.count:
        print(json.dumps({"route": a.route, "query": a.query,
                          "count": count(a.route, a.query, free_only=a.free_only)}))
        return 0
    res = execute(a.route, a.query, case=a.case, origin_type=a.origin_type,
                  origin_value=a.origin_value, free_only=a.free_only)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 1 if res.get("error") or res.get("ingest_error") or res.get("nodes_error") else 0


__all__ = [
    "query_for", "count", "run", "execute", "identifier_rung",
    "_ID_RUNGS", "_FIELD_MAP", "_HOST_RUNG",  # test surfaces
]


if __name__ == "__main__":
    sys.exit(_main())
