#!/usr/bin/env python3
"""
whois_enrich.py — WhoisXML API enrichment for WebPivot.

Adds registration-based pivots to the DOM/infra pivots from pivot_extract.py:
  * current WHOIS       — registrant email/name/org, registrar, dates, name servers
  * WHOIS history       — every registrant email/name/registrar ever seen (catches
                          pre-privacy records that name the real owner)
  * reverse WHOIS       — other domains sharing a registrant email / name

Registrant email + name are top-tier same-operator artifacts — they cluster
infrastructure the way a shared GA4 ID or favicon does, and history often exposes
an owner who later hid behind WHOIS privacy.

Keys: reads WHOISXML_API_KEY from the environment first, then the chmod-600
customization .env (env wins). No key -> every call is a no-op (returns None).

Usage:
  python3 whois_enrich.py example.com                    # current + history summary
  python3 whois_enrich.py example.com --history-mode purchase   # full history records
  python3 whois_enrich.py --reverse-email owner@x.com    # reverse WHOIS by email
  python3 whois_enrich.py --reverse-name "Some Org" --search-type historic
  python3 whois_enrich.py example.com --json             # raw JSON
"""

import os
import re
import sys
import json
import shutil
import argparse
import subprocess
import concurrent.futures
import urllib.request
import urllib.error
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # importable from anywhere
from wp_refs import ref_path, load_ref    # noqa: E402 — reference DATA in references/*.json
from wp_timeouts import floor as _floor_timeout  # noqa: E402 — per-call ceiling (CTI_CALL_TIMEOUT)
import whois_eras  # noqa: E402 — the single place that turns WHOIS history into OWNER eras (RULE 5)

try:
    import api_usage                      # licensed-API credit ledger
except Exception:
    api_usage = None

DEFAULT_UA = "WebPivot-whois/1.0"
# cti-expert: unified key store managed by /apikeys (see wp_common for the same contract).
_CUSTOMIZATION_ENV = (os.environ.get("CTI_API_KEYS_ENV")
                      or os.environ.get("CTI_WEBPIVOT_ENV")
                      or os.path.expanduser("~/.config/cti-expert/WebPivot/.env"))

WHOIS_CURRENT_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
WHOIS_HISTORY_URL = "https://whois-history.whoisxmlapi.com/api/v1"
REVERSE_WHOIS_URL = "https://reverse-whois.whoisxmlapi.com/api/v2"
BALANCE_URL = "https://user.whoisxmlapi.com/service/account-balance"

# Whois History and Reverse WHOIS are NOT part of the plain "WHOIS API" product — both bill to
# the separate "Domain Research Suite" (DRS) balance. A key with WHOIS API credits but zero DRS
# credits returns 200 for current WHOIS and 403 for both of these, which reads like a bad key.
# It is not: it is an unfunded product. _explain_403 turns that into an actionable message.
_DRS_ENDPOINTS = {WHOIS_HISTORY_URL: "Whois History API", REVERSE_WHOIS_URL: "Reverse WHOIS API"}


def _explain_403(url, raw=""):
    """Turn a bare WhoisXML 403 into the actual cause, checking the account balance to confirm."""
    product = _DRS_ENDPOINTS.get(url)
    if not product:
        return f"HTTP 403 from WhoisXML: {raw or 'access restricted'}"
    drs = None
    try:
        key = _key()
        req = urllib.request.Request(
            f"{BALANCE_URL}?{urlencode({'apiKey': key, 'output_format': 'JSON'})}",
            headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            for row in (json.load(r).get("data") or []):
                if (row.get("product") or {}).get("name") == "Domain Research Suite":
                    drs = row.get("credits")
    except Exception:  # noqa: BLE001
        pass
    if drs == 0:
        return (f"{product} unavailable: Domain Research Suite credits = 0. The API key is VALID "
                f"(plain WHOIS API still works) — this product is simply unfunded. Top up DRS at "
                f"https://user.whoisxmlapi.com/products to re-enable history/reverse-WHOIS.")
    if drs is None:
        return (f"{product} returned 403 and the account balance could not be read. Check the key "
                f"and the API IP allow-list: https://user.whoisxmlapi.com/settings/api-ip-allow-list")
    return (f"{product} returned 403 despite {drs} Domain Research Suite credits — most likely the "
            f"caller IP is not on the API IP allow-list: "
            f"https://user.whoisxmlapi.com/settings/api-ip-allow-list")


def _load_customization_env(path=_CUSTOMIZATION_ENV):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        pass
    except Exception:
        pass


_load_customization_env()

# Run STANDALONE (`intel.py whois`, or a bare `python3 whois_enrich.py`) this module only reads
# _CUSTOMIZATION_ENV, so it would miss the skill-root .env that /apikeys actually writes — the
# keys are found in-process only because pivot_extract imports wp_common first. Importing the
# sibling loader here makes the standalone path resolve the same candidate list. It is a no-op
# when wp_common already ran, and WebPivot still runs if the sibling is absent.
try:
    import wp_common  # noqa: F401 — import side effect: populates os.environ from the .env chain
except Exception:  # noqa: BLE001
    pass


def _key():
    for n in ("WHOISXML_API_KEY", "WHOISXMLAPI_KEY", "WHOIS_API_KEY"):
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def whois_configured():
    """True when a WhoisXML key is present — the spend gate every metered WHOIS caller checks
    (`… and not free_only`) before it verifies anything."""
    return bool(_key())


# Privacy-proxy / registrar-role markers — these are NOT the real owner and must
# never become a same-operator hub or trigger a reverse-WHOIS (which would return
# thousands of unrelated domains and waste credits).
# DATA: references/registrant_noise.json. Add a proxy provider THERE — it takes effect for
# every WebPivot consumer at once, and costs nothing to get wrong in the safe direction.
_WHOIS_FALLBACK = {
    "privacy_markers": ("privacy", "redacted", "whoisguard", "data protected", "withheld",
                        "not disclosed", "domains by proxy", "statutory masking"),
    "role_email_prefixes": ("abuse@", "hostmaster@", "noc@", "postmaster@"),
    "proxy_email_domains": ("godaddy.com", "namecheap.com", "domainsbyproxy.com",
                            "withheldforprivacy.com", "privacyprotect.org"),
}
_WHOIS_FALLBACK["noise_name_substrings"] = ("domain admin", "c/o id#", "reactivation period", "whois", "proxy")
_WHOIS_REF = load_ref(ref_path(__file__, "registrant_noise.json"), _WHOIS_FALLBACK)
_PRIVACY_MARKERS = tuple(_WHOIS_REF["privacy_markers"])
_ROLE_PREFIXES = tuple(_WHOIS_REF["role_email_prefixes"])
_PROXY_DOMAINS = tuple(_WHOIS_REF["proxy_email_domains"])
# registrant NAME boilerplate (role placeholders, registrar org names, WHOIS labels) — the same list
# evidence_report uses to drop a cluster row, so a name the report would refuse is never REVERSED
_NOISE_NAME_SUBSTR = tuple(_WHOIS_REF["noise_name_substrings"])


def is_privacy(value):
    """True if a registrant value is a privacy proxy / registrar role / non-identifying — i.e. a
    term that must never be reverse-WHOIS'd (10,000 strangers, credits gone) or become a hub.
    Emails: privacy markers, role local-parts (`abuse@`, `registrar@`, `expired@`, `tenmien@`…), a
    registrar/proxy domain (exact or sub-domain). Names: privacy markers + role/registrar boilerplate
    (`Domain Admin`, `C/O ID#…`, a registrar's own company name)."""
    if not value:
        return True
    s = " ".join(str(value).split()).lower()
    if s.startswith("http"):
        return True  # a URL placeholder, not a real contact
    if any(m in s for m in _PRIVACY_MARKERS):
        return True
    if "@" in s:
        local, _, dom = s.partition("@")
        if any(s.startswith(p) for p in _ROLE_PREFIXES):
            return True
        return any(dom == d or dom.endswith("." + d) for d in _PROXY_DOMAINS)
    return any(m in s for m in _NOISE_NAME_SUBSTR)


def _wx_action(url, mode=None):
    """WhoisXML endpoint → action label for the usage ledger. A `mode=preview` call (count only,
    not billed by WhoisXML) gets a `-preview` suffix so api_usage classes it as FREE
    (WebPivot/references/api_cost_classes.json) instead of reading it as a purchase."""
    suffix = "-preview" if mode == "preview" else ""
    if url == WHOIS_HISTORY_URL:
        return "whois-history" + suffix
    if url == REVERSE_WHOIS_URL:
        return "reverse-whois" + suffix
    return "whois"


def _get_json(url, params, timeout=30):
    full = url + "?" + urlencode(params)
    req = urllib.request.Request(full, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.load(r)
    if api_usage:
        api_usage.record("whoisxml", _wx_action(url, params.get("mode")), credits=1,
                         query=params.get("domainName") or params.get("terms") or params.get("q"))
    return out


def _post_json(url, payload, timeout=30):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": DEFAULT_UA,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.load(r)
    if api_usage:
        api_usage.record("whoisxml", _wx_action(url, payload.get("mode")), credits=1)
    return out


def _contact(rec, *keys):
    """Pull the first present nested contact block from a WHOIS record."""
    for k in keys:
        c = rec.get(k)
        if isinstance(c, dict) and c:
            return c
    return {}


def _phone(contact):
    """Normalized registrant phone (digits/+ only, keep extension marker)."""
    raw = (contact.get("telephone") or contact.get("phone") or "").strip()
    return raw or None


def _address(contact, country_override=None):
    """Single-line street/city/state/postal/country address, pivot-ready. `country_override`
    substitutes a reconciled country so a placeholder like 'NAMIBIA' is not re-injected."""
    country = country_override or contact.get("country")
    parts = [contact.get("street1"), contact.get("street2"), contact.get("city"),
             contact.get("state"), contact.get("postalCode"), country]
    parts = [str(p).strip() for p in parts if p and str(p).strip()]
    return ", ".join(parts) or None


# Some registrars/thin registries return an EMPTY registrantContact block but still print the
# registrant in the raw text record ("Registrant Name/Organization/.../Email: …"). Parsing that
# is the only way to recover the registrant at all for those records — the alternative is
# `whois_current` falling back to `contactEmail`, which is the REGISTRAR's own abuse/role mailbox,
# never the registrant's (SKILL.md RULE 5; the abuse-contact@registrar.example misparse).
_REGISTRANT_TEXT_RE = re.compile(
    r"(?im)^\s*Registrant\s+(Name|Organization|Street|City|Country|Phone|Email)\s*:\s*(.+?)\s*$")
_REGISTRANT_TEXT_FIELD = {"name": "name", "organization": "organization", "street": "street1",
                          "city": "city", "country": "country", "phone": "telephone", "email": "email"}
_REGISTRANT_TEXT_JUNK = ("n/a", "not available", "redacted for privacy", "data protected")


def _parse_registrant_text(rec):
    """Parse a 'Registrant Name/Organization/Street/City/Country/Phone/Email:' block out of a
    WhoisXML text record (`rawText`/`strippedText`/`cleanText`) when the structured
    registrantContact is empty. Returns a `_contact()`-shaped dict, or {} if no registrant line
    is found. Never reads `contactEmail` — that field is the registrar's, not the registrant's."""
    if not isinstance(rec, dict):
        return {}
    text = rec.get("rawText") or rec.get("strippedText") or rec.get("cleanText") or ""
    if not isinstance(text, str) or not text:
        return {}
    out = {}
    for m in _REGISTRANT_TEXT_RE.finditer(text):
        field = _REGISTRANT_TEXT_FIELD.get(m.group(1).strip().lower())
        value = m.group(2).strip()
        if field and value and value.strip().lower() not in _REGISTRANT_TEXT_JUNK:
            out[field] = value
    return out


# Country reconciliation — data-driven (references/whois_geo.json), not a per-country special case.
# ISO-3166 alpha-2 "NA" is Namibia's code AND the universal WHOIS "Not Available" placeholder;
# WhoisXML expands the token to "NAMIBIA", which then reads as a deliberately-false country. A
# placeholder-token country is overridden only when an INDEPENDENT signal — RDAP adr.cc, the
# phone's E.164 calling code, or a country NAME in street/city/state (never the country field) —
# resolves to a different country. A genuine +264 (or no contradicting signal) keeps it untouched.
_GEO_FALLBACK = {
    "calling_codes": {"49": "DE", "264": "NA", "1": ["US", "CA"]},
    "country_aliases": {"GERMANY": "DE", "NAMIBIA": "NA"},
    "placeholder_countries": ("NA", "NAMIBIA"),
}
_GEO = load_ref(ref_path(__file__, "whois_geo.json"), _GEO_FALLBACK)
_CALLING_CODES = dict(_GEO["calling_codes"])
_COUNTRY_ALIASES = {str(k).upper(): v for k, v in dict(_GEO["country_aliases"]).items()}
_PLACEHOLDER_COUNTRIES = {str(v).upper() for v in _GEO["placeholder_countries"]}
_PLACEHOLDER_ISO = "NA"   # the ISO code the placeholder token collides with


def _country_from_phone(phone):
    """ISO country of an unambiguous E.164 calling code, or None. Longest-prefix (3,2,1) match;
    a zone shared by several ISO countries resolves to None rather than guessing one member."""
    digits = re.sub(r"\D", "", phone or "")
    digits = re.sub(r"^00", "", digits)          # drop an international access prefix
    if not digits:
        return None
    for n in (3, 2, 1):
        if digits[:n] in _CALLING_CODES:
            c = _CALLING_CODES[digits[:n]]
            return c if isinstance(c, str) else None
    return None


def _country_from_address_fields(contact):
    """ISO of a country NAME appearing in street/city/state (never the country field), or None."""
    hay = " ".join(str(contact.get(k)) for k in ("street1", "street2", "city", "state")
                   if contact.get(k)).upper()
    if not hay:
        return None
    for name, iso in _COUNTRY_ALIASES.items():
        if re.search(r"\b" + re.escape(name) + r"\b", hay):
            return iso
    return None


def _vcard_param(vcard, field, param):
    """One jCard field parameter (e.g. adr.params.cc), or None."""
    for item in (vcard or []):
        if not isinstance(item, list) or len(item) < 4 or item[0] != field:
            continue
        params = item[1] if isinstance(item[1], dict) else {}
        value = params.get(param)
        if value is not None:
            return str(value).strip() or None
    return None


def _rdap_registrant_country(data):
    """Registrant adr.params.cc from an RDAP object, or None."""
    if not isinstance(data, dict):
        return None
    for ent in data.get("entities") or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrant" not in roles:
            continue
        cc = _vcard_param((ent.get("vcardArray") or [None, []])[1], "adr", "cc")
        if cc:
            return cc.upper()
    return None


def _rdap_country_from_whois_record(rec):
    """Registrant adr.params.cc from WhoisXML's embedded RDAP text — no extra request. WhoisXML
    reports the placeholder country ("NAMIBIA") in its normalized fields but preserves the true
    ISO cc in the raw RDAP jCard adr params, so this recovers it without another lookup."""
    for key in ("rawText", "strippedText"):
        raw = rec.get(key)
        if not raw:
            continue
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            continue
        cc = _rdap_registrant_country(data)
        if cc:
            return cc
    return None


def _reconcile_country(contact, rdap_cc=None):
    """Corrected ISO country for a contact, or None when the value stands as-is. Only a placeholder
    token (whois_geo.json) is changed, and only when an independent signal resolves to a different
    country. Never emits a note; callers keep the raw value for audit."""
    raw = (contact.get("country") or contact.get("countryCode") or "").strip()
    if raw.upper() not in _PLACEHOLDER_COUNTRIES:
        return None
    signal = ((str(rdap_cc).upper() if rdap_cc else None)
              or _country_from_phone(_phone(contact))
              or _country_from_address_fields(contact))
    if signal and signal != _PLACEHOLDER_ISO:
        return signal
    return None


# Some registrars (VN resellers observed so far) ship an EMPTY registrantContact/registrant block
# but embed the registrar's OWN RDAP JSON verbatim in rawText (top-level and/or registryData) —
# a full RDAP domain object whose entities[] carries a "registrant"-rolled vCard (fn/org/email/
# tel/adr) with the real owner. That vCard is the ONLY place the registrant exists for those
# records; without this, whois_current() (and whois_summary/whois_summary_keyless downstream)
# leaves registrant_name/email/phone/org null even though the record IS attributable, producing
# a false "no shared identity" read. Reuses `_vcard_get`/`_vcard_param` (already used by
# rdap_lookup for a live RDAP fetch) and the SAME junk-value list `_parse_registrant_text` uses,
# so a privacy-proxied vCard is dropped exactly like a privacy-proxied text record.
def _find_registrant_entity(data, _depth=0):
    """Depth-first search of an RDAP object's `entities[]` (and each entity's own nested
    `entities[]`, e.g. a registrar entity nesting its abuse contact) for the first whose `roles`
    include "registrant". An entity that ALSO carries administrative/technical alongside
    registrant still counts; a registrar/abuse/technical/administrative-ONLY entity never does."""
    if not isinstance(data, dict) or _depth > 4:
        return None
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrant" in roles:
            return ent
        nested = _find_registrant_entity(ent, _depth + 1)
        if nested:
            return nested
    return None


def _rdap_contact_from_vcard(vcard):
    """An RDAP jCard → a `_contact()`-shaped dict (name/organization/email/telephone/country/
    street1), dropping placeholder values ('REDACTED FOR PRIVACY', 'Data Protected', …) field by
    field via the same `_REGISTRANT_TEXT_JUNK` list the raw-text parser uses. `tel` is a URI
    ("tel:+84.…") per RFC 6350 — the "tel:" scheme is stripped the same way a `tel:` href is
    (wp_extract.TEL_HREF_RE) before the value ever reaches `_phone()`."""
    def _clean(v):
        v = (v or "").strip()
        return v if v and v.lower() not in _REGISTRANT_TEXT_JUNK else None
    out = {}
    name = _clean(_vcard_get(vcard, "fn"))
    if name:
        out["name"] = name
    org = _clean(_vcard_get(vcard, "org"))
    if org:
        out["organization"] = org
    email = _clean(_vcard_get(vcard, "email"))
    if email:
        out["email"] = email
    tel = _vcard_get(vcard, "tel")
    if tel:
        tel = tel[4:] if tel.lower().startswith("tel:") else tel
        tel = _clean(tel)
        if tel:
            # WhoisXML's structured `telephone` is bare digits ("84876264213"); a vCard carries the
            # E.164-dotted form ("+84.876264213"). Emit the structured shape so the same number from
            # the vCard and from WHOIS history is ONE selector, not two phone leads. RFC 3966 puts
            # the extension in a `;ext=` parameter, so parameters are cut off before the digits are
            # read; a legacy "x123" suffix is still honoured.
            main, *params = tel.split(";")
            ext = next((p.split("=", 1)[1] for p in params
                        if p.strip().lower().startswith("ext=") and "=" in p), "")
            if not ext:
                main, _, ext = main.lower().partition("x")
            digits = re.sub(r"\D", "", main)
            ext = re.sub(r"\D", "", ext)
            # A placeholder number ("+000000000", "+1.1111111111") is the privacy filler, not an
            # owner: as a decisive phone join key it would bind every placeholder domain together.
            if len(digits) >= 7 and len(set(digits)) > 1:
                out["telephone"] = digits + (f"x{ext}" if ext else "")
    cc = _vcard_param(vcard, "adr", "cc")
    country = _clean((cc.upper() if cc else None) or _vcard_get(vcard, "country-name"))
    if country:
        out["country"] = country
    addr = _clean(_vcard_get(vcard, "adr"))
    if addr:
        out["street1"] = addr   # single combined line; _address() just joins non-empty parts
    return out


def _rdap_registrant_contact(rec, reg_data):
    """Registrant contact recovered from WhoisXML's embedded RDAP rawText (rec and/or
    registryData) when the structured registrantContact is empty, or {} if none is found. Never
    raises on malformed/non-RDAP JSON — every record without this shape (the vast majority) must
    fall through unaffected."""
    for src in (rec, reg_data):
        if not isinstance(src, dict):
            continue
        for key in ("rawText", "strippedText"):
            raw = src.get(key)
            if not raw:
                continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else raw
            except (TypeError, ValueError):
                continue
            ent = _find_registrant_entity(data)
            if not ent:
                continue
            vcard = (ent.get("vcardArray") or [None, []])[1]
            contact = _rdap_contact_from_vcard(vcard)
            if contact:
                return contact
    return {}


def whois_current(domain, timeout=30, keep_raw=True):
    """Current WHOIS for a domain. Returns a normalized dict or {'error':...} / None.

    Subdomains resolve to their registrable APEX before any request or cache lookup — every host
    in an estate shares one owner registration, so `api.example.com`/`wss.example.com` must never
    each buy their own current-WHOIS record. `res['domain']` is always the apex; `res['queried_host']`
    is the literal input. Bought ONCE per case (wp_casememo under $WP_CASE_DIR) — the collector's
    one-process-per-host and the domain-summary sidecar both land on the cached record instead of
    a second purchase.

    With keep_raw (default), the FULL unmodified WhoisXML response is retained under
    the '_raw' key so the complete record is archived for later reference, not just
    the normalized fields we happen to surface today."""
    key = _key()
    if not key:
        return None
    try:
        from wp_common import _registrable
        apex = _registrable(domain) or domain
    except Exception:  # noqa: BLE001
        apex = domain
    _memo_key = f"current|{apex.lower()}"
    try:
        import wp_casememo
        _cached = wp_casememo.get("whoisxml", _memo_key)
    except Exception:  # noqa: BLE001
        wp_casememo, _cached = None, None
    if _cached is not None:
        out = dict(_cached)
        if not keep_raw:
            out.pop("_raw", None)
        out["queried_host"] = domain
        return out
    try:
        data = _get_json(WHOIS_CURRENT_URL,
                         {"apiKey": key, "domainName": apex,
                          "outputFormat": "JSON"}, timeout=timeout)
    except Exception as e:
        return {"error": str(e), "domain": apex, "queried_host": domain}
    rec = data.get("WhoisRecord") or {}
    if not rec:
        return {"error": "no WhoisRecord", "domain": apex, "queried_host": domain,
                "_raw": data if keep_raw else None}
    # Many registrars (e.g. Hostinger/thin registries) populate dates + name servers
    # ONLY under the nested registryData, leaving the top-level fields empty. Read
    # each field from rec, then fall back to registryData so they aren't dropped.
    reg_data = rec.get("registryData") or {}
    def _f(*keys):
        for src in (rec, reg_data):
            for k in keys:
                v = src.get(k)
                if v:
                    return v
        return None
    reg = _contact(rec, "registrantContact", "registrant") \
        or _contact(reg_data, "registrantContact", "registrant")
    # The registrar's OWN abuse/role contact (WhoisXML top-level `contactEmail`) is never the
    # registrant — archive it separately (SKILL.md RULE 5; the abuse-contact@registrar.example misparse, where
    # a registrar's abuse mailbox was ingested as `registered_by`).
    registrar_contact_email = (rec.get("contactEmail") or reg_data.get("contactEmail") or "").lower().strip() or None
    if not reg:
        # A thin/text-only record never populates registrantContact but DOES print
        # "Registrant Name/Organization/.../Email:" lines in the raw text — parse those before
        # falling back to nothing. Never falls back to contactEmail (the registrar's mailbox).
        reg = (_parse_registrant_text(rec) or _parse_registrant_text(reg_data)
               # Some VN-reseller records leave the text block empty too but embed the
               # registrar's own RDAP JSON verbatim in rawText/registryData.rawText instead —
               # the registrant lives only in its entities[] "registrant" vCard.
               or _rdap_registrant_contact(rec, reg_data) or {})
    ns = ((rec.get("nameServers") or {}).get("hostNames")
          or (reg_data.get("nameServers") or {}).get("hostNames") or [])
    country_raw = reg.get("country") or reg.get("countryCode") or None
    country_override = _reconcile_country(reg, rdap_cc=_rdap_country_from_whois_record(rec))
    registrant_email = (reg.get("email") or "").lower().strip() or None
    if registrant_email and is_privacy(registrant_email):
        # A registrar/abuse/role mailbox parsed as if it were the registrant (e.g. a thin text
        # record whose only "Email:" line is the registrar's) — never surface it as the
        # registrant; it is preserved only via registrar_contact_email above.
        registrant_email = None
    res = {
        "domain": apex,
        "queried_host": domain,
        "registrant_email": registrant_email,
        "registrant_name": reg.get("name") or None,
        "registrant_org": reg.get("organization") or None,
        "registrant_country": country_override or country_raw,
        "registrant_phone": _phone(reg),
        "registrant_address": _address(reg, country_override=country_override),
        "registrar": _f("registrarName"),
        "registrar_contact_email": registrar_contact_email,
        "created": _f("createdDateNormalized", "createdDate"),
        "updated": _f("updatedDateNormalized", "updatedDate"),
        "expires": _f("expiresDateNormalized", "expiresDate"),
        "name_servers": sorted({n.lower() for n in ns if n}),
    }
    if country_override:
        res["registrant_country_raw"] = country_raw
    res["_raw"] = data   # kept internally so the memo archives the full record regardless of keep_raw
    if wp_casememo is not None:
        wp_casememo.put("whoisxml", _memo_key, res)
    if not keep_raw:
        res.pop("_raw", None)
    return res


def whois_history(domain, mode="purchase", timeout=40, keep_raw=True, current_created=None):
    """Historical WHOIS records. mode=preview (count only) or purchase (full).

    Subdomains resolve to their registrable APEX before any request or cache lookup (see
    whois_current). `res['domain']` is the apex, `res['queried_host']` the literal input.

    Returns {'count','registrant_emails','registrant_names','registrant_phones',
    'registrant_addresses','registrars','records','prior_registrants','eras','era_basis'}.
    The aggregate registrant_* fields are the CURRENT era ONLY (whois_eras.owner_values contract):
    a domain that dropped and was re-registered must never have a previous owner's contacts
    treated as this owner's. `current_created` is the live record's registration date, when the
    caller has it (whois_summary does); a bare whois_history() call may not — split_eras then
    falls back to the newest dated era. Previous owners land only in 'prior_registrants'/'eras'
    (facts, never owner links, edges, frontier seeds or IOCs).
    With keep_raw (default), the full unmodified history response is kept under '_raw'.
    """
    try:
        from wp_common import _registrable
        apex = _registrable(domain) or domain
    except Exception:  # noqa: BLE001
        apex = domain
    _reuse_records = None
    try:
        import wp_quarry_reuse as _qr
        _hit = _qr.get(_qr.whois_history_key(apex))
        if isinstance(_hit, dict) and isinstance(_hit.get("records"), list):
            _reuse_records = _hit["records"]
    except Exception:  # noqa: BLE001
        pass
    if _reuse_records is not None:
        recs_built = _reuse_records
        data_raw = None
        count = len(recs_built)
    else:
        key = _key()
        if not key:
            return None
        _memo_key = f"history|{mode}|{apex.lower()}"
        try:
            import wp_casememo
            _cached = wp_casememo.get("whoisxml", _memo_key)
        except Exception:  # noqa: BLE001
            wp_casememo, _cached = None, None
        if _cached is not None:
            recs_built = _cached.get("_records") or []
            data_raw = _cached.get("_raw")
            count = _cached.get("count", len(recs_built))
        else:
            try:
                data = _get_json(WHOIS_HISTORY_URL,
                                 {"apiKey": key, "domainName": apex,
                                  "mode": mode, "outputFormat": "JSON"}, timeout=timeout)
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    body = ""
                    try:
                        body = e.read().decode("utf-8", "replace")
                    except Exception:  # noqa: BLE001
                        pass
                    return {"error": _explain_403(WHOIS_HISTORY_URL, body), "domain": apex,
                            "queried_host": domain, "http": 403}
                return {"error": str(e), "domain": apex, "queried_host": domain}
            except Exception as e:
                return {"error": str(e), "domain": apex, "queried_host": domain}
            recs = data.get("records") or []
            recs_built = []
            for rec in recs:
                reg = _contact(rec, "registrantContact", "registrant")
                em = (reg.get("email") or "").lower().strip()
                nm = (reg.get("name") or reg.get("organization") or "").strip()
                rg = (rec.get("registrarName") or "").strip()
                ph = _phone(reg)
                country_raw = reg.get("country") or reg.get("countryCode") or None
                country_override = _reconcile_country(reg, rdap_cc=_rdap_country_from_whois_record(rec))
                ad = _address(reg, country_override=country_override)
                if nm and any(0x80 <= ord(c) <= 0x9f for c in nm):
                    nm = ""  # drop C1-mojibake-corrupted names (double-encoding artifacts)
                item = {
                    "email": em or None, "name": nm or None, "registrar": rg or None,
                    "phone": ph, "address": ad, "country": country_override or country_raw,
                    "created": rec.get("createdDateNormalized") or rec.get("createdDateISO8601"),
                    "updated": rec.get("updatedDateNormalized"),
                    "expires": rec.get("expiresDateNormalized"),
                }
                if country_override:
                    item["country_raw"] = country_raw
                # "Contact Privacy Inc. Customer <id>" — the proxy name is noise, the id is one
                # customer account (whois_eras kind privacy_customer → rung whois.privacy_customer).
                # Read before is_privacy() drops the name; org/rawText carry it when name does not.
                _pc = whois_eras.privacy_customer_ids(reg.get("name"), reg.get("organization"),
                                                      reg.get("email"), reg.get("rawText"),
                                                      rec.get("rawText"))
                if _pc:
                    item["privacy_customer"] = _pc[0]
                recs_built.append(item)
            data_raw = data
            count = data.get("recordsCount", len(recs))
            if wp_casememo is not None:
                wp_casememo.put("whoisxml", _memo_key,
                                {"_records": recs_built, "_raw": data_raw, "count": count})
    # Ownership eras (whois_eras.py — the single place that turns history into OWNER values). A
    # flat merge of every registrant this name has EVER had treats previous owners as the current
    # one; the aggregate below is the current era only, recomputed fresh every call so a
    # `current_created` supplied AFTER the (memoized) network fetch still applies correctly.
    eras = whois_eras.split_eras({"records": recs_built}, current_created)
    cur = eras["current"]
    res = {
        "domain": apex,
        "queried_host": domain,
        "count": count,
        "registrant_emails": sorted(cur.get("emails") or []),
        "registrant_names": sorted(cur.get("names") or []),
        "registrant_phones": sorted(cur.get("phones") or []),
        "registrant_addresses": sorted(cur.get("addresses") or []),
        "registrars": sorted({it.get("registrar") for it in recs_built if it.get("registrar")}),
        "records": recs_built if mode == "purchase" else [],
        "prior_registrants": [
            {"created": era.get("created"), "email": (era.get("emails") or [None])[0],
             "name": (era.get("names") or [None])[0], "phone": (era.get("phones") or [None])[0],
             "registrar": (era.get("registrars") or [None])[0]}
            for era in eras["prior"]
        ],
        "eras": [{"created": cur.get("created"), "current": True,
                  "emails": cur.get("emails") or [], "names": cur.get("names") or [],
                  "phones": cur.get("phones") or [], "registrars": cur.get("registrars") or []}]
               + [{"created": era.get("created"), "current": False,
                   "emails": era.get("emails") or [], "names": era.get("names") or [],
                   "phones": era.get("phones") or [], "registrars": era.get("registrars") or []}
                  for era in eras["prior"]],
        "era_basis": eras["basis"],
    }
    if _reuse_records is not None:
        res["reused"] = "quarry"
    if keep_raw:
        res["_raw"] = data_raw   # full unmodified history response, archived for later ref
    return res


def reverse_whois(term, kind="email", search_type="current", mode="purchase", timeout=40):
    """Domains sharing a registrant term. kind: email|name|org. search_type: current|historic.

    mode=preview returns {'count'} only (cheap); purchase returns {'count','domains'}.
    """
    key = _key()
    if not key or not term:
        return None
    # Bought ONCE per case (wp_casememo under $WP_CASE_DIR): every estate host carries the same
    # registrant, and the collector runs one process per host — 3 hosts used to mean 12 identical
    # reverse-WHOIS purchases for one e-mail + one name.
    _memo_key = f"reverse_whois|{kind}|{search_type}|{mode}|{str(term).lower()}"
    try:
        import wp_casememo
        _cached = wp_casememo.get("whoisxml", _memo_key)
    except Exception:  # noqa: BLE001
        wp_casememo, _cached = None, None
    if _cached is not None:
        return dict(_cached, memo="case cache")
    payload = {
        "apiKey": key,
        "searchType": search_type,
        "mode": mode,
        "punycode": True,
        "basicSearchTerms": {"include": [term]},
    }
    try:
        data = _post_json(REVERSE_WHOIS_URL, payload, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            return {"error": _explain_403(REVERSE_WHOIS_URL, body), "term": term, "http": 403}
        try:
            body = json.load(e)
            return {"error": body.get("messages") or str(e), "term": term}
        except Exception:
            return {"error": str(e), "term": term}
    except Exception as e:
        return {"error": str(e), "term": term}
    domains = [d.get("domainName") if isinstance(d, dict) else d
               for d in (data.get("domainsList") or [])]
    out = {"term": term, "kind": kind, "search_type": search_type,
           "count": data.get("domainsCount", len(domains)),
           "domains": [d for d in domains if d][:200]}
    if wp_casememo is not None:
        wp_casememo.put("whoisxml", _memo_key, out)
    return out


# --------------------------------------------------------------- keyless WHOIS (RDAP + port-43)
#
# Registration data must land on EVERY domain, not only when a WhoisXML key is present. RDAP is
# the IETF-standard (RFC 9082/9083), free, structured-JSON, ToS-respecting successor to port-43
# whois: one polite request per domain via the bootstrap redirector, no key, no scraping. Even
# when the registrant is GDPR-redacted it reliably returns registrar, registration/expiry/updated
# dates, name servers, and domain status — exactly what the Domain Summary table needs on every
# host. A port-43 `whois` fallback covers ccTLDs with no RDAP service (e.g. .vn).

_RDAP_BOOTSTRAP = "https://rdap.org/domain/"          # redirects to the authoritative registry RDAP
_RDAP_UA = "WebPivot-whois/1.0 (RDAP; +authorized-osint)"


def _rdap_fetch(domain, timeout=25):
    """GET the RDAP domain object via the bootstrap redirector. Keyless, credits=0."""
    req = urllib.request.Request(
        _RDAP_BOOTSTRAP + domain,
        headers={"User-Agent": _RDAP_UA, "Accept": "application/rdap+json, application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # urllib follows the 302 to the registry
        data = json.load(r)
    if api_usage:
        api_usage.record("rdap", "domain", credits=0, query=domain)   # free/keyless — cost visibility only
    return data


def _vcard_get(vcard, field):
    """Pull a field's value from an RDAP jCard (vcardArray[1]). adr → single line; else the string."""
    for item in (vcard or []):
        if not isinstance(item, list) or len(item) < 4 or item[0] != field:
            continue
        val = item[3]
        if field == "adr":
            # value is a 7-element structured array (pobox, ext, street, city, region, code,
            # country); RFC 7095 lets a component itself be a list (multi-line street), which
            # registrars use — flatten it, or the street is stored as a Python list repr
            def _flat(x):
                if isinstance(x, list):
                    for y in x:
                        yield from _flat(y)
                elif x is not None and str(x).strip():
                    yield str(x).strip()
            parts = list(_flat(val if isinstance(val, list) else [val]))
            return ", ".join(parts) or None
        return str(val).strip() or None
    return None


def rdap_lookup(domain, timeout=25, keep_raw=True):
    """Keyless current-registration lookup via RDAP. Normalized to the whois_current() shape
    (so every downstream consumer works unchanged) plus 'source' and 'status'. None on failure."""
    try:
        data = _rdap_fetch(domain, timeout=timeout)
    except Exception as e:
        return {"error": str(e), "domain": domain, "source": "rdap"}
    if not isinstance(data, dict) or data.get("errorCode"):
        return {"error": (data or {}).get("title", "no RDAP record"),
                "domain": domain, "source": "rdap"}
    # events → registration / expiration / last-changed dates
    ev = {}
    for e in data.get("events") or []:
        act = (e.get("eventAction") or "").lower()
        if e.get("eventDate"):
            ev[act] = e["eventDate"]
    # entities → registrar name + (usually redacted) registrant contact
    registrar = reg = {}
    reg_vcard = []
    for ent in data.get("entities") or []:
        roles = [str(x).lower() for x in (ent.get("roles") or [])]
        vcard = (ent.get("vcardArray") or [None, []])[1]
        if "registrar" in roles and not registrar:
            registrar = {"name": _vcard_get(vcard, "fn")}
        if "registrant" in roles and not reg_vcard:
            reg, reg_vcard = ent, vcard
    ns = sorted({(n.get("ldhName") or "").lower() for n in (data.get("nameservers") or [])
                 if n.get("ldhName")})
    res = {
        "domain": (data.get("ldhName") or domain).lower(),
        "registrant_email": (_vcard_get(reg_vcard, "email") or "").lower() or None,
        "registrant_name": _vcard_get(reg_vcard, "fn"),
        "registrant_org": _vcard_get(reg_vcard, "org"),
        "registrant_country": (_vcard_param(reg_vcard, "adr", "cc")
                               or _vcard_get(reg_vcard, "country-name")),
        "registrant_phone": _vcard_get(reg_vcard, "tel"),
        "registrant_address": _vcard_get(reg_vcard, "adr"),
        "registrar": registrar.get("name"),
        "created": ev.get("registration"),
        "updated": ev.get("last changed") or ev.get("last update of rdap database"),
        "expires": ev.get("expiration"),
        "name_servers": ns,
        "status": [str(s) for s in (data.get("status") or [])],
        "source": "rdap",
    }
    if keep_raw:
        res["_raw"] = data
    return res


# port-43 whois fields → normalized keys (best-effort; ccTLD servers vary wildly)
_W43_FIELDS = {
    "registrant_email": (r"registrant\s*email", r"registrant contact email"),
    "registrant_name": (r"registrant\s*name", r"registrant"),
    "registrant_org": (r"registrant\s*organi[sz]ation", r"registrant\s*org"),
    "registrant_country": (r"registrant\s*country",),
    "registrant_phone": (r"registrant\s*phone",),
    "registrar": (r"^\s*registrar:", r"sponsoring registrar"),
    "created": (r"creation date", r"created", r"registration time", r"registered on"),
    "updated": (r"updated date", r"last updated", r"modified"),
    "expires": (r"regist(?:ry|rar) expiry date", r"expir\w+ date", r"expiration time", r"expires? on"),
}


def whois_port43(domain, timeout=None):
    """System `whois` fallback for TLDs with no RDAP service (e.g. .vn). None if unavailable.
    Bounded by the per-call ceiling (wp_common.CALL_TIMEOUT); a shorter `timeout` is floored."""
    binary = shutil.which("whois")
    if not binary:
        return None
    try:
        out = subprocess.run([binary, domain], capture_output=True, text=True,
                             timeout=_floor_timeout(timeout), errors="replace").stdout
    except Exception:
        return None
    if not out:
        return None
    res = {"domain": domain.lower(), "source": "whois43", "name_servers": [], "status": []}
    ns, status = [], []
    for raw in out.splitlines():
        line = raw.strip()
        low = line.lower()
        if ":" not in line:
            continue
        val = line.split(":", 1)[1].strip()
        if not val:
            continue
        if re.match(r"(name server|nserver|nameserver)", low):
            ns.append(val.split()[0].lower())
        elif low.startswith(("domain status", "status")):
            status.append(val)
        else:
            for field, pats in _W43_FIELDS.items():
                if field in res:
                    continue
                if any(re.match(p, low) for p in pats):
                    res[field] = val.lower() if field == "registrant_email" else val
                    break
    res["name_servers"] = sorted(set(ns))
    res["status"] = status
    # a whois server that returned no owning fields at all is not useful
    if not any(res.get(k) for k in ("registrar", "created", "expires", "registrant_name")) and not ns:
        return None
    return res



def _cld_vn_whois(domain, timeout=25):
    """ChongLuaDao WHOIS for a `.vn` host, mapped into the whois_summary() field shape, or None.

    WhoisXML and most RDAP servers have no `.vn` coverage, so for `.vn` CLD is the PRIMARY source
    (callers fall back to RDAP/port-43 when this returns None). Reuses wp_cld → cld_api (RULE 4);
    metered, so it is skipped when no CLD key is set. Never raises."""
    if not (domain or "").lower().endswith(".vn"):
        return None
    try:
        import wp_cld
        if not wp_cld.cld_configured():
            return None
        w = wp_cld.cld_whois(domain, timeout=timeout)
        if not isinstance(w, dict) or w.get("error") or not (w.get("registrar") or w.get("registration_date")):
            return None
    except Exception:
        return None

    def _iso(d):
        d = str(d or "").strip()
        m = re.match(r"^(\d{2})-(\d{2})-(\d{4})$", d)   # CLD returns DD-MM-YYYY
        if m:
            return f"{m.group(3)}-{m.group(2)}-{m.group(1)} 00:00:00 UTC"
        if re.match(r"^\d{4}-\d{2}-\d{2}$", d):          # bare ISO date -> WhoisXML datetime shape
            return f"{d} 00:00:00 UTC"
        return d or None
    st = w.get("status")
    return {"domain": domain, "registrar": w.get("registrar") or None,
            "registrant_name": w.get("owner") or None,
            "created": _iso(w.get("registration_date")), "expires": _iso(w.get("expiration_date")),
            "updated": _iso(w.get("updated_date")),
            "name_servers": list(w.get("nameservers") or []),
            "status": (", ".join(st) if isinstance(st, list) else st) or None,
            "source": "chongluadao"}


def whois_summary_keyless(domain, timeout=25, keep_raw=True):
    """Keyless combined block in the whois_summary() shape: for a `.vn` host CLD WHOIS is tried
    FIRST (WhoisXML/RDAP have no .vn coverage), then RDAP, then port-43 fallback; empty history
    (reverse/history need the licensed WhoisXML API). None only if every path fails."""
    cur = _cld_vn_whois(domain, timeout=min(timeout, 30))
    if not cur:
        cur = rdap_lookup(domain, timeout=timeout, keep_raw=keep_raw)
    if not cur or cur.get("error") or not any(
            cur.get(k) for k in ("registrar", "created", "expires", "name_servers", "registrant_name")):
        w43 = whois_port43(domain, timeout=timeout)
        if w43:
            cur = w43
    if not cur or cur.get("error"):
        return None
    cur_raw = cur.pop("_raw", None)
    out = dict(cur)
    # history + reverse-WHOIS require the licensed WhoisXML API — same shape as the keyed block
    out["history"] = {"records": [], "mode": "off"}
    if keep_raw:
        out["raw"] = {"current": cur_raw, "history": None}
    return out


def whois_summary(domain, history_mode="purchase", timeout=40, keep_raw=True):
    """Combined current + history block, ready to attach to a pivot_extract result.

    With a WhoisXML key: fetches the FULL current + history WHOIS. WITHOUT a key it falls back to
    keyless RDAP (+ port-43) so registration data lands on every domain regardless. With keep_raw
    (default) the complete unmodified API responses are archived under out['raw'] = {current, history}
    so later analysis can mine fields we don't normalize today."""
    if not _key():
        return whois_summary_keyless(domain, timeout=min(timeout, 30), keep_raw=keep_raw)
    # current + history are two INDEPENDENT WhoisXML calls (the long pole of enrichment). Run them
    # concurrently to ~halve WHOIS latency per host. Same two API calls, same credits/egress — only
    # concurrency changes; api_usage.record's single-line append is atomic, so it's ledger-safe.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as _ex:
        _f_cur = _ex.submit(whois_current, domain, timeout=timeout, keep_raw=keep_raw)
        _f_hist = _ex.submit(whois_history, domain, mode=history_mode, timeout=timeout, keep_raw=keep_raw)
        cur = _f_cur.result() or {}
        hist = _f_hist.result() or {}
    # `hist` was fetched CONCURRENTLY with `cur`, so its era split ran without the live created
    # date (falling back to the newest dated era). Recompute now that `cur` is known — cheap: the
    # network fetch is memoized per-apex (wp_casememo), only the pure era split reruns.
    if not hist.get("error") and cur.get("created"):
        _fresh_hist = whois_history(domain, mode=history_mode, timeout=timeout, keep_raw=keep_raw,
                                    current_created=cur.get("created"))
        if _fresh_hist and not _fresh_hist.get("error"):
            hist = _fresh_hist
    cur_raw = cur.pop("_raw", None)
    hist_raw = hist.pop("_raw", None)
    # WhoisXML sometimes returns "no WhoisRecord" for new/obscure TLDs. For `.vn` it has NO coverage
    # at all, so CLD WHOIS is the primary backfill there; then keyless RDAP for everything else.
    # Only fills what WhoisXML left empty; never overwrites.
    if cur.get("error") or not any(cur.get(k) for k in ("registrar", "created", "expires", "name_servers")):
        cld = _cld_vn_whois(domain, timeout=min(timeout, 30))
        if cld:
            filled = False
            for k, v in cld.items():
                if k == "source":
                    continue                 # provenance set once, below — never doubled
                if v and not cur.get(k):
                    cur[k] = v
                    filled = True
            if filled:
                cur.pop("error", None)   # WhoisXML has no .vn record; CLD supplied it → not a failed row
                base = cur.get("source")
                cur["source"] = "chongluadao" if base in (None, "", "whoisxml") else f"{base}+chongluadao"
        rd = rdap_lookup(domain, timeout=min(timeout, 30), keep_raw=False)
        if rd and not rd.get("error"):
            for k, v in rd.items():
                if v and not cur.get(k):
                    cur[k] = v
            cur.setdefault("source", "whoisxml+rdap")
    cur.setdefault("source", "whoisxml")
    out = dict(cur)
    out.pop("_raw", None)
    out["history"] = {k: hist.get(k) for k in
                      ("count", "registrant_emails", "registrant_names",
                       "registrant_phones", "registrant_addresses", "registrars",
                       "prior_registrants", "eras", "era_basis")}
    # The per-era record list is what case_timeline.whois_events() turns into registrant eras.
    # whois_history() returns it only under mode="purchase" ([] for preview) — carry it through
    # instead of dropping it, or every downstream era view stays empty.
    out["history"]["records"] = list(hist.get("records") or [])
    out["history"]["mode"] = history_mode
    if hist.get("error"):
        out["history"]["error"] = hist["error"]
    if keep_raw:
        # Readers of the raw record (house_report_dossier.registrant_country) accept both this
        # nested shape and whois_current()'s top-level `_raw` — no alias, no duplicated payload.
        out["raw"] = {"current": cur_raw, "history": hist_raw}
    return out


# ----------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="WhoisXML enrichment for WebPivot.")
    ap.add_argument("domain", nargs="?", help="domain to look up (current + history)")
    ap.add_argument("--history-mode", choices=["preview", "purchase"], default="purchase")
    ap.add_argument("--reverse-email", help="reverse WHOIS by registrant email")
    ap.add_argument("--reverse-name", help="reverse WHOIS by registrant name/org")
    ap.add_argument("--reverse-phone", help="reverse WHOIS by registrant phone (bulk = registrar noise)")
    ap.add_argument("--search-type", choices=["current", "historic"], default="current")
    ap.add_argument("--reverse-mode", choices=["preview", "purchase"], default="purchase")
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    args = ap.parse_args()

    if not _key():
        if args.reverse_email or args.reverse_name or args.reverse_phone:
            print("[!] reverse-WHOIS needs WHOISXML_API_KEY (RDAP has no reverse index).",
                  file=sys.stderr)
            sys.exit(2)
        if args.domain:
            print("[i] no WHOISXML_API_KEY — using keyless RDAP (+ port-43) for current registration.",
                  file=sys.stderr)

    out = {}
    if args.reverse_email:
        out["reverse_email"] = reverse_whois(args.reverse_email, "email",
                                             args.search_type, args.reverse_mode)
    if args.reverse_name:
        out["reverse_name"] = reverse_whois(args.reverse_name, "name",
                                            args.search_type, args.reverse_mode)
    if args.reverse_phone:
        out["reverse_phone"] = reverse_whois(args.reverse_phone, "phone",
                                             args.search_type, args.reverse_mode)
    if args.domain:
        out["whois"] = whois_summary(args.domain, history_mode=args.history_mode)

    if not out:
        ap.error("give a domain and/or --reverse-email/--reverse-name")

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    # human-readable
    w = out.get("whois")
    if w:
        print(f"# WHOIS — {w.get('domain')}")
        for k in ("registrant_email", "registrant_name", "registrant_org",
                  "registrant_phone", "registrant_address",
                  "registrar", "created", "updated", "expires"):
            if w.get(k):
                print(f"  {k:18} {w[k]}")
        if w.get("name_servers"):
            print(f"  name_servers       {', '.join(w['name_servers'])}")
        h = w.get("history") or {}
        if h.get("count"):
            print(f"  history: {h['count']} records")
            if h.get("registrant_emails"):
                print(f"    emails:    {', '.join(h['registrant_emails'])}")
            if h.get("registrant_names"):
                print(f"    names:     {', '.join(h['registrant_names'])}")
            if h.get("registrant_phones"):
                print(f"    phones:    {', '.join(h['registrant_phones'])}")
            if h.get("registrant_addresses"):
                print(f"    addresses: {', '.join(h['registrant_addresses'])}")
    for key in ("reverse_email", "reverse_name"):
        r = out.get(key)
        if r:
            if r.get("error"):
                print(f"# {key}: error — {r['error']}")
            else:
                print(f"# {key} '{r['term']}' ({r['search_type']}): {r['count']} domains")
                for d in r.get("domains", [])[:50]:
                    print(f"    {d}")


if __name__ == "__main__":
    main()
