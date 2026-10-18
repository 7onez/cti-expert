"""whois_eras.py — split a domain's WHOIS history into OWNERSHIP ERAS (stdlib only).

WHY THIS EXISTS (SKILL.md §2.5 rung 1/2, RULE 5)
  WHOIS history spans every registration a name has ever had. When a domain drops and is
  re-registered (drop-catch, auction, plain expiry) the `Creation Date` resets, and every contact
  recorded before that reset belongs to a DIFFERENT owner — an uninvolved third party. Treating the
  flat `history.registrant_emails` list as owner links pulls previous owners into the operator's
  cluster, buys enrichment on them, and names them in reports.

  This module is the single place that decides which historic contacts are the CURRENT owner's:

    * an era = the set of history records sharing one registration `created` date (day precision);
    * the CURRENT era = the era whose created date matches the live record's created date, else
      the newest dated era;
    * records with no created date are UNDATED — never owner links (they cannot be placed);
    * a history with no per-record list (a preview / counts-only purchase) yields NO historic owner
      values at all: only the live registrant fields count. Rung 2 ("two identities in one
      registration") needs records to prove "one registration".

CONTRACT (consumers: ingest_webpivot, case_state.frontier, wp_analyze, evidence_report,
house_report, build_report_data)
  split_eras(history, current_created=None) -> {
      "current": {"created", "emails", "names", "phones", "orgs", "addresses", "registrars", "records"},
      "prior":   [{"created", "emails", "names", "phones", "orgs", "addresses", "registrars", "records"}, …]
                 (newest first),
      "undated": {"emails", "names", "phones", "orgs", "addresses", "registrars", "records"},
      "basis":   "records" | "no-records",
  }
  owner_values(whois, kind)  -> current-era values of kind (email|name|phone|org|address|
                                privacy_customer), live field first. privacy_customer = the digits
                                of a "Contact Privacy Inc. Customer <id>" proxy account, extracted
                                from name/org/email (patterns: references/registrant_noise.json)
  prior_values(whois, kind)  -> [{"value", "era_created"}] for previous-owner eras (facts only)
  previous_owner_contacts(whois, kinds=("email", "phone"))
                             -> [{"kind", "value", "observed", "current_created"}] for registrant
                                contacts whose WHOIS OBSERVATION date predates the current
                                registration's creation date (analyst-confirmed era rule: surfaced
                                for approval as `previous_owner_era`, never seeded, never dropped).
                                Records with no observation date are not included.

  Values are returned verbatim (case preserved, de-duplicated case-insensitively). Privacy-proxy /
  registrar-boilerplate filtering stays the caller's job (whois_enrich.is_privacy,
  noise_filters.is_noise_email) — this module decides ERA, not noise.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA in references/*.json

_KIND_FIELDS = {"email": ("email",), "name": ("name",), "phone": ("phone",),
                "org": ("org", "organization"), "address": ("address",),
                "privacy_customer": ("privacy_customer",)}
_LIVE_FIELDS = {"email": "registrant_email", "name": "registrant_name", "phone": "registrant_phone",
                "org": "registrant_org", "address": "registrant_address",
                "privacy_customer": "registrant_privacy_customer"}
_PLURAL = {"email": "emails", "name": "names", "phone": "phones", "org": "orgs", "address": "addresses",
           "privacy_customer": "privacy_customers"}

# Privacy-service CUSTOMER IDs ("Contact Privacy Inc. Customer <digits>", the Google Domains /
# Squarespace / Tucows proxy). The proxy NAME is shared by every customer and stays privacy noise;
# the DIGITS are one account, so two domains carrying the same id are owner-link candidates (rung
# class whois.privacy_customer). The fallback is EMPTY on purpose: a broken data file extracts no
# ids, so it can never invent an owner link. DATA: references/registrant_noise.json.
_PC_FALLBACK = {"privacy_customer_patterns": ()}
_PC_REF = load_ref(ref_path(__file__, "registrant_noise.json"), _PC_FALLBACK)
PRIVACY_CUSTOMER_PATTERNS = tuple(re.compile(p, re.I) for p in _PC_REF["privacy_customer_patterns"])
# record / live fields a customer id is printed in (the proxy puts it in name and/or organization)
_PC_SOURCE_FIELDS = ("privacy_customer", "name", "org", "organization", "email")
_PC_LIVE_FIELDS = ("registrant_privacy_customer", "registrant_name", "registrant_org", "registrant_email")


def privacy_customer_ids(*texts) -> list:
    """Privacy-service customer ids (digit strings) found in any of `texts`, de-duplicated, in
    order. A bare digit string (an already-extracted id) is accepted as-is."""
    out = []
    for t in texts:
        s = " ".join(str(t or "").split())
        if not s:
            continue
        found = [s] if s.isdigit() else [m.group(1) for p in PRIVACY_CUSTOMER_PATTERNS for m in p.finditer(s)]
        for cid in found:
            if cid not in out:
                out.append(cid)
    return out


def _values(record: dict, kind: str) -> list:
    if kind == "privacy_customer":
        return privacy_customer_ids(*(record.get(f) for f in _PC_SOURCE_FIELDS))
    return [record.get(f) for f in _KIND_FIELDS[kind]]


def _live_values(whois: dict, kind: str) -> list:
    if kind == "privacy_customer":
        return privacy_customer_ids(*(whois.get(f) for f in _PC_LIVE_FIELDS))
    return [whois.get(_LIVE_FIELDS[kind])]


def _day(value) -> str | None:
    s = str(value or "").strip()
    return s[:10] if len(s) >= 10 and s[4] == "-" and s[7] == "-" else None


def _uniq(values) -> list:
    seen, out = set(), []
    for v in values:
        s = str(v or "").strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def _bucket(records: list, created: str | None) -> dict:
    b = {"created": created, "records": len(records), "registrars": _uniq(r.get("registrar") for r in records)}
    for kind in _KIND_FIELDS:
        b[_PLURAL[kind]] = _uniq(v for r in records for v in _values(r, kind))
    return b


def split_eras(history: dict | None, current_created=None) -> dict:
    """Partition `history["records"]` into ownership eras. See module docstring for the contract."""
    hist = history if isinstance(history, dict) else {}
    records = [r for r in (hist.get("records") or []) if isinstance(r, dict)]
    empty = _bucket([], None)
    if not records:
        return {"current": dict(empty, created=_day(current_created)), "prior": [],
                "undated": empty, "basis": "no-records"}
    by_day: dict = {}
    undated = []
    for r in records:
        d = _day(r.get("created"))
        if d:
            by_day.setdefault(d, []).append(r)
        else:
            undated.append(r)
    days = sorted(by_day, reverse=True)
    cur_day = _day(current_created)
    if cur_day not in by_day:
        # The live record's created date is not among the dated records: the newest dated era is
        # the current registration only if it is not NEWER than the live one (which cannot happen
        # for a consistent record); with no live date, the newest era stands.
        cur_day = days[0] if days and (not cur_day or days[0] <= cur_day) else None
    current = _bucket(by_day.get(cur_day, []), cur_day) if cur_day else dict(empty, created=_day(current_created))
    prior = [_bucket(by_day[d], d) for d in days if d != cur_day]
    return {"current": current, "prior": prior, "undated": _bucket(undated, None), "basis": "records"}


def owner_values(whois: dict | None, kind: str) -> list:
    """Owner-link values of `kind` for the CURRENT registration: the live registrant field first,
    then values recorded in the current era's history records. Never prior-era or undated values."""
    w = whois if isinstance(whois, dict) else {}
    eras = split_eras(w.get("history"), w.get("created"))
    return _uniq(_live_values(w, kind) + list(eras["current"].get(_PLURAL[kind]) or []))


def prior_values(whois: dict | None, kind: str) -> list:
    """Previous-owner values of `kind` as [{"value", "era_created"}] — record them as FACTS
    ("previous registrant"), never as edges, frontier seeds, IOCs or report subjects."""
    w = whois if isinstance(whois, dict) else {}
    eras = split_eras(w.get("history"), w.get("created"))
    current = {v.lower() for v in owner_values(w, kind)}
    out, seen = [], set()
    for era in eras["prior"]:
        for v in era.get(_PLURAL[kind]) or []:
            if v.lower() in current or v.lower() in seen:
                continue
            seen.add(v.lower())
            out.append({"value": v, "era_created": era.get("created")})
    return out


# A history record's OBSERVATION date: when this WHOIS-of-the-day was seen. An explicit capture
# date wins; otherwise the record's own last-update, then its registration date (a record cannot
# have been observed before the registration it describes was made or last touched).
_OBSERVED_FIELDS = ("observed", "audit_date", "audit_updated", "updated", "created")


def observed_day(record: dict | None) -> str | None:
    """Day-precision observation date of one history record, or None when it carries no date."""
    r = record if isinstance(record, dict) else {}
    for f in _OBSERVED_FIELDS:
        d = _day(r.get(f))
        if d:
            return d
    return None


def previous_owner_contacts(whois: dict | None, kinds=("email", "phone")) -> list:
    """Registrant contacts observed BEFORE the domain's current registration was created.

    Analyst-confirmed era rule: such a contact belongs to a previous owner of the name. It is not
    an owner link and must not seed, but it is not silently discarded either — the proposer
    surfaces each one as an approval item tagged `previous_owner_era` (with both dates in the
    reason) so the analyst confirms or rejects it. A value the current era also carries is the
    current owner's and is excluded; a record with no observation date is excluded (unaffected).
    Returns [{"kind", "value", "observed", "current_created"}], earliest observation kept per value."""
    w = whois if isinstance(whois, dict) else {}
    hist = w.get("history") if isinstance(w.get("history"), dict) else {}
    records = [r for r in (hist.get("records") or []) if isinstance(r, dict)]
    created = _day(w.get("created")) or split_eras(hist, w.get("created"))["current"].get("created")
    if not records or not created:
        return []
    out, seen = [], {}
    for kind in kinds:
        if kind not in _KIND_FIELDS:
            continue
        current = {v.lower() for v in owner_values(w, kind)}
        for r in records:
            obs = observed_day(r)
            if not obs or obs >= created:
                continue
            for v in _uniq(r.get(f) for f in _KIND_FIELDS[kind]):
                key = (kind, v.lower())
                if v.lower() in current:
                    continue
                if key in seen:
                    if obs < seen[key]["observed"]:
                        seen[key]["observed"] = obs
                    continue
                item = {"kind": kind, "value": v, "observed": obs, "current_created": created}
                seen[key] = item
                out.append(item)
    return out
