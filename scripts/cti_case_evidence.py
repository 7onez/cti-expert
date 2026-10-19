#!/usr/bin/env python3
# cti-expert skill — analyst-graded evidence layer for build_report_data.py (stdlib only).
"""cti_case_evidence.py — carry a case's GRADED, non-raw evidence into the flat report JSON.

build_report_data.py derives subjects/findings from raw/<host>.json pivots. A case worked on a
non-domain seed (a social-media page, a person, a phone) has no raw/ host at all, and even a domain
case holds evidence raw/ never sees. This module reads, from the case dir:

  evidence/imported/*.json      evidence_import outputs (`accepted` graded findings; preferred)
  analyst_findings*.json        analyst-graded findings (case root and evidence/), deduped by claim
  findings.json                 a graded list, {"findings": [...]}, or an intake summary dict
                                (seed / linked_accounts / candidate_identity / gaps / …)
  enrichment/**/*.json          deep-profile chains, leak-status sheets, meta_transparency captures
  intelx/*.json                 Intelligence X search outcomes (a zero is a real negative)
  appdev/*.json                 app-store developer records (wp_appdev --case)

and returns subjects / findings / connections / gaps / sources / ioc_exclude to merge into the
report. Grading is preserved verbatim (rung, rung_class, effective_rung, admiralty); only the
numeric confidence, weight and connection strength are derived, per references/analyst_grading.json.

Claim discipline: a finding graded at a candidate reliability (E/F) stays in the narrative but is
flagged `ioc_exclude`, and the selectors it alone vouches for enter the report-level `ioc_exclude`
unless an owner-rung finding also cites them. On a benign_check intake, contact / identity
subjects are evidence, not detection indicators, and are kept out of the IOC feed.
"""
import glob
import json
import os
import re

from cti_refs import load_ref

_FALLBACK = {
    "admiralty_credibility_confidence": {"1": 95, "2": 85, "3": 65, "4": 45, "5": 20, "6": 50},
    "admiralty_reliability_penalty": {"A": 0, "B": 0, "C": 5, "D": 10, "E": 20, "F": 25},
    "candidate_reliability": ["E", "F"],
    "rung_weight": {"owner": "HIGH", "kit": "MEDIUM", "neighbour": "LOW", "mention": "INFO"},
    "rung_strength": {"owner": "confirmed", "kit": "probable", "neighbour": "possible", "mention": "possible"},
    "indicator_subject_types": {"org": "organization", "name": "person"},
    "contact_subject_types": ["email", "phone", "username", "person", "organization", "social"],
    "social_profile_urls": {},
}
_REF = load_ref("analyst_grading.json", _FALLBACK)
_ADM_RE = re.compile(r"^\s*([A-F])\s*([1-6])\s*$", re.I)


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def _norm_claim(text):
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def grade(admiralty):
    """(confidence, reliability letter | None) for an Admiralty code like 'B2'."""
    m = _ADM_RE.match(str(admiralty or ""))
    if not m:
        return 60, None
    letter, digit = m.group(1).upper(), m.group(2)
    conf = int(_REF["admiralty_credibility_confidence"].get(digit, 50))
    conf -= int(_REF["admiralty_reliability_penalty"].get(letter, 0))
    return max(5, min(99, conf)), letter


# ------------------------------------------------------------------------------ collectors
def _graded_items(case_dir):
    """Every analyst-graded finding item, evidence_import outputs first (they carry the engine's
    effective_rung and id), then the analyst files they were imported from, deduped by claim."""
    items, seen = [], set()

    def take(row, origin):
        if not isinstance(row, dict):
            return
        claim = row.get("claim") or row.get("description")
        key = _norm_claim(claim)
        if not key or key in seen:
            return
        seen.add(key)
        items.append({**row, "claim": str(claim).strip(), "_origin": origin})

    for path in sorted(glob.glob(os.path.join(case_dir, "evidence", "imported", "*.json"))):
        doc = _load_json(path)
        for row in (doc.get("accepted") or []) if isinstance(doc, dict) else []:
            take(row, "evidence_import")
    for path in sorted(glob.glob(os.path.join(case_dir, "analyst_findings*.json"))
                       + glob.glob(os.path.join(case_dir, "evidence", "analyst_findings*.json"))):
        doc = _load_json(path)
        rows = doc if isinstance(doc, list) else (doc.get("findings") if isinstance(doc, dict) else None)
        for row in rows or []:
            take(row, "analyst_findings")
    doc = _load_json(os.path.join(case_dir, "findings.json"))
    rows = doc if isinstance(doc, list) else (doc.get("findings") if isinstance(doc, dict) else None)
    for row in rows if isinstance(rows, list) else []:
        take(row, "findings.json")
    return items


def _kv_summary(d, skip=()):
    bits = []
    for k, v in d.items():
        if k in skip or v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        bits.append(f"{k.replace('_', ' ')}: {v}")
    return "; ".join(bits)


def _intake_summary(case_dir):
    """findings.json written as an intake summary dict -> (seed, items, gaps)."""
    doc = _load_json(os.path.join(case_dir, "findings.json"))
    if not isinstance(doc, dict) or isinstance(doc.get("findings"), list):
        return None, [], []
    seed = doc.get("seed") if isinstance(doc.get("seed"), str) else None
    gaps = [str(g) for g in doc.get("gaps") or [] if str(g).strip()] if isinstance(doc.get("gaps"), list) else []
    items = []
    for acc in doc.get("linked_accounts") or []:
        if not isinstance(acc, dict) or not (acc.get("username") or acc.get("handle")):
            continue
        plat = str(acc.get("platform") or "account").lower()
        handle = str(acc.get("username") or acc.get("handle")).lstrip("@")
        items.append({
            "claim": f"Linked {plat} account @{handle}: " + (acc.get("link_meaning") or _kv_summary(
                acc, skip=("platform", "username", "handle", "admiralty", "former_usernames_asserted"))),
            "admiralty": acc.get("admiralty"), "source_url": None, "type": "account",
            "indicators": [{"type": "social", "value": f"{plat}:{handle}"}], "_origin": "findings.json"})
    cand = doc.get("candidate_identity")
    if isinstance(cand, dict) and cand.get("name"):
        items.append({
            "claim": f"Candidate identity (not attributed): {cand['name']} — "
                     + _kv_summary(cand, skip=("name", "admiralty")),
            "admiralty": cand.get("admiralty") or "F6", "type": "candidate", "candidate": True,
            "indicators": [{"type": "person", "value": str(cand["name"])}], "_origin": "findings.json"})
    for key, val in doc.items():
        if key in ("seed", "gaps", "linked_accounts", "candidate_identity", "collected_utc", "findings"):
            continue
        if isinstance(val, dict) and val:
            items.append({"claim": f"{key.replace('_', ' ').capitalize()}: " + _kv_summary(val, skip=("source",)),
                          "source_url": None, "source_note": val.get("source"), "type": "observation",
                          "indicators": [], "_origin": "findings.json"})
    return seed, items, gaps


def _count_phrase(n, what="record"):
    return f"{n} {what}{'' if n == 1 else 's'}"


def _intelx_items(case_dir):
    items = []
    for path in sorted(glob.glob(os.path.join(case_dir, "intelx", "*.json"))):
        doc = _load_json(path)
        val = doc.get("value") if isinstance(doc, dict) and isinstance(doc.get("value"), dict) else doc
        if not isinstance(val, dict) or not val.get("term"):
            continue
        recs = val.get("records")
        n = len(recs) if isinstance(recs, list) else int(recs or 0) if str(recs or "0").isdigit() else 0
        passes = [p.get("pass") for p in val.get("passes") or [] if isinstance(p, dict) and p.get("ran")]
        items.append({
            "claim": (f"Intelligence X search for {val['term']} ({val.get('selector') or 'selector'}"
                      + (f"; passes: {', '.join(passes)}" if passes else "") + f"): {_count_phrase(n)}. "
                      + str(val.get("note") or "")).strip(),
            "source_url": val.get("ui_url"), "type": "exposure", "rung": "mention",
            "tags": ["intelx", "exposure"] + (["negative-finding"] if n == 0 else []),
            "_term": str(val["term"]), "indicators": [], "_origin": "intelx"})
    return items


def _enrichment_items(case_dir):
    """Deep-profile chains ({selector, ran}), meta_transparency captures and status sheets."""
    items, meta = [], []
    for path in sorted(glob.glob(os.path.join(case_dir, "enrichment", "**", "*.json"), recursive=True)):
        if os.path.basename(path) == "index.json":        # build_report_data._enrichment owns it
            continue
        doc = _load_json(path)
        if not isinstance(doc, dict):
            continue
        if doc.get("tool") == "meta_transparency":
            meta.append(doc)
            continue
        if doc.get("selector") and isinstance(doc.get("ran"), dict):
            ran = ", ".join(f"{k} {(v or {}).get('status', '?')}" for k, v in doc["ran"].items()
                            if isinstance(v, dict))
            items.append({"claim": f"Enrichment chain for {doc['selector']} ({doc.get('mode') or 'selector'}): {ran}.",
                          "type": "exposure", "rung": "mention", "tags": ["enrichment"],
                          "_term": str(doc["selector"]), "indicators": [], "_origin": "enrichment"})
            continue
        bits = []
        for key, val in doc.items():
            if not isinstance(val, dict):
                continue
            for sel, row in val.items():
                if not isinstance(row, dict):
                    continue
                counts = [f"{k.replace('_', ' ')} {v}" for k, v in row.items()
                          if isinstance(v, int) and not isinstance(v, bool)]
                if counts:
                    extra = row.get("caveat") or row.get("relationship_to_page") or ""
                    bits.append(f"{sel}: {', '.join(counts)}" + (f" ({extra})" if extra else ""))
        if bits:
            head = doc.get("source") or os.path.splitext(os.path.basename(path))[0]
            tail = " ".join(str(doc.get(k)) for k in ("scope", "limitations") if isinstance(doc.get(k), str))
            items.append({"claim": f"Exposure status ({head}): " + "; ".join(bits) + (". " + tail if tail else "."),
                          "type": "exposure", "rung": "mention", "tags": ["enrichment", "exposure"],
                          "indicators": [], "_origin": "enrichment"})
    return items, meta


def _appdev_records(case_dir):
    out = []
    for path in sorted(glob.glob(os.path.join(case_dir, "appdev", "*.json"))):
        doc = _load_json(path)
        if isinstance(doc, dict) and isinstance(doc.get("developer"), dict) and not doc.get("error"):
            out.append(doc)
    return out


def intake_seed(case_dir):
    """The seed a non-domain case was opened on (scope.json seed, else findings.json seed)."""
    sc = _load_json(os.path.join(case_dir, "scope.json")) or {}
    if isinstance(sc, dict) and sc.get("seed"):
        return str(sc["seed"])
    seed, _, _ = _intake_summary(case_dir)
    return seed


# ------------------------------------------------------------------------------ the layer
def build_layer(case_dir, *, subjects, findings, connections, sub_by_host, benign, default_sid,
                seed_label, today):
    """Graded-evidence subjects/findings/connections, numbered after the existing ones.
    Returns {"subjects", "findings", "connections", "gaps", "sources", "ioc_exclude"}."""
    type_map = _REF["indicator_subject_types"]
    contact_types = set(_REF["contact_subject_types"])
    urls = _REF["social_profile_urls"]
    candidate_letters = set(_REF["candidate_reliability"])

    def _next(prefix, rows):
        n = 0
        for r in rows:
            m = re.match(prefix + r"-(\d+)$", str(r.get("id") or ""))
            if m:
                n = max(n, int(m.group(1)))
        return n

    n_sub, n_fnd, n_con = _next("SUB", subjects), _next("FND", findings), _next("CON", connections)
    con_base = n_con
    new_subj, new_fnd, new_con, sources = [], [], [], []
    by_key = {}                 # (type, value.lower()) -> subject dict
    by_label = {str(s.get("label") or "").strip().lower(): s for s in subjects}
    cites = {}                  # subject id -> {"owner": bool, "candidate": bool, "clean": bool}

    def subject_for(ind):
        nonlocal n_sub
        if not isinstance(ind, dict) or not str(ind.get("value") or "").strip():
            return None
        raw_t = str(ind.get("type") or "selector").strip().lower()
        stype = type_map.get(raw_t, raw_t)
        value = str(ind["value"]).strip()
        key = (stype, value.lower())
        if key in by_key:
            return by_key[key]
        if stype in ("domain", "ip") and value.lower() in sub_by_host:
            sid = sub_by_host[value.lower()]
            hit = next((s for s in subjects if s.get("id") == sid), None)
            if hit:
                by_key[key] = hit
                return hit
        if value.lower() in by_label and stype not in ("social",):
            by_key[key] = by_label[value.lower()]
            return by_key[key]
        n_sub += 1
        sub = {"id": f"SUB-{n_sub:03d}", "label": value, "type": stype, "role": "related",
               "confidence": 0, "verified": False, "aliases": [], "first_seen": None,
               "notes": "From analyst-graded case evidence.", "selectors": []}
        if stype == "social" and ":" in value:
            plat, handle = value.split(":", 1)
            tpl = urls.get(plat.strip().lower())
            sel = {"type": "social", "platform": plat.strip().lower(), "value": handle.strip()}
            if tpl:
                sel["url"] = tpl.replace("{handle}", handle.strip().lstrip("@"))
            sub["selectors"].append(sel)
        new_subj.append(sub)
        by_key[key] = sub
        return sub

    def add_finding(item, sid, rung, letter, conf):
        nonlocal n_fnd
        n_fnd += 1
        candidate = bool(item.get("candidate")) or (letter in candidate_letters)
        f = {"id": f"FND-{n_fnd:03d}", "subject_id": sid,
             "type": item.get("type") or ("identity" if rung == "owner" else "evidence"),
             "weight": _REF["rung_weight"].get(rung or "", "INFO"),
             "description": item["claim"], "source_url": item.get("source_url"),
             "collected_at": today, "confidence": int(conf),
             # explicit indicators ride on the subjects; the prose cites references (registries,
             # search platforms, news) and is never harvested by generate-cti-iocs.py
             "ioc_scan": False,
             "tags": list(item.get("tags") or []) + [f"rung-{rung}" if rung else "unrated",
                                                     "analyst-graded" if item.get("admiralty") else "case-evidence"]}
        for k in ("admiralty", "rung_class", "effective_rung"):
            if item.get(k):
                f[k] = item[k]
        if rung:
            f["rung"] = rung
        if item.get("id"):
            f["evidence_id"] = item["id"]
        if item.get("source_note"):
            f["source_note"] = item["source_note"]
        if candidate:
            f["ioc_exclude"] = True
            f["tags"].append("candidate")
        new_fnd.append(f)
        return candidate

    def cite(sub, rung, candidate, conf):
        c = cites.setdefault(sub["id"], {"owner": False, "candidate": False, "clean": False})
        c["owner"] |= rung == "owner"
        c["candidate"] |= candidate
        c["clean"] |= not candidate
        if sub in new_subj:
            sub["confidence"] = max(int(sub.get("confidence") or 0), int(conf))

    seed_sid = default_sid

    def ensure_seed():
        nonlocal seed_sid, n_sub
        if seed_sid:
            return seed_sid
        n_sub += 1
        seed = {"id": f"SUB-{n_sub:03d}", "label": seed_label, "type": "seed", "role": "related",
                "confidence": 90, "verified": True, "aliases": [], "first_seen": None,
                "notes": "The case seed (non-domain intake): the object the request was opened on."}
        new_subj.append(seed)
        seed_sid = seed["id"]
        return seed_sid

    def subject_by_term(term):
        t = str(term or "").strip().lower()
        for s in subjects + new_subj:
            if str(s.get("label") or "").strip().lower() == t:
                return s["id"]
            for sel in s.get("selectors") or []:
                if str(sel.get("value") or "").strip().lower() == t:
                    return s["id"]
        return None

    _seed, intake_items, gaps = _intake_summary(case_dir)
    graded = _graded_items(case_dir)
    graded_claims = {_norm_claim(i["claim"]) for i in graded}
    enrich_items, meta_docs = _enrichment_items(case_dir)
    all_items = graded + [i for i in intake_items if _norm_claim(i["claim"]) not in graded_claims] \
        + _intelx_items(case_dir) + enrich_items

    for item in all_items:
        rung = str(item.get("effective_rung") or item.get("rung") or "").strip().lower() or None
        conf, letter = grade(item.get("admiralty"))
        candidate = bool(item.get("candidate")) or (letter in candidate_letters)
        subs = [s for s in (subject_for(i) for i in item.get("indicators") or []) if s]
        sid = subs[0]["id"] if subs else (subject_by_term(item.get("_term")) if item.get("_term") else None)
        add_finding(item, sid or ensure_seed(), rung, letter, conf)
        for s in subs:
            cite(s, rung, candidate, conf)
        for link in item.get("selector_links") or []:
            if not isinstance(link, dict):
                continue
            a, b = subject_for(link.get("from")), subject_for(link.get("to"))
            if a and b and a is not b:
                n_con += 1
                new_con.append({"id": f"CON-{n_con:03d}", "from_id": a["id"], "to_id": b["id"],
                                "relationship": str(link.get("rel") or "related_to"),
                                "strength": "possible" if candidate else _REF["rung_strength"].get(rung or "", "possible")})
                cite(a, rung, candidate, conf)
                cite(b, rung, candidate, conf)
        if item.get("source_url") and str(item["source_url"]).startswith(("http://", "https://")):
            sources.append({"name": item.get("_origin") or "case evidence", "url": item["source_url"],
                            "date": today})

    # meta_transparency captures: one account subject per capture, account-level facts only
    for doc in meta_docs:
        plat = str(doc.get("platform") or "account").lower()
        target = str(doc.get("target") or "").strip()
        if not target:
            continue
        acct = subject_for({"type": "social", "value": f"{plat}:{target.lstrip('@')}"})
        found = [f"{k}: {v.get('value')}" for k, v in (doc.get("fields") or {}).items()
                 if isinstance(v, dict) and v.get("status") == "found" and v.get("value") not in (None, "")]
        for kind in ("emails", "phones"):
            for val in doc.get(kind) or []:
                v = val.get("value") if isinstance(val, dict) else val
                if v:
                    acct.setdefault("selectors", []).append({"type": kind[:-1], "value": str(v)})
        for h in doc.get("handles") or []:
            if isinstance(h, dict) and h.get("platform") and h.get("value"):
                other = subject_for({"type": "social", "value": f"{h['platform']}:{str(h['value']).lstrip('@')}"})
                if other and other is not acct:
                    n_con += 1
                    new_con.append({"id": f"CON-{n_con:03d}", "from_id": acct["id"], "to_id": other["id"],
                                    "relationship": str(h.get("kind") or "linked_account"), "strength": "possible"})
        item = {"claim": f"Meta transparency capture for {plat} {target} ({doc.get('collected_at') or 'undated'}): "
                         + ("; ".join(found) if found else "no field exposed")
                         + (f". {doc['caveat']}" if doc.get("caveat") else "."),
                "type": "account", "rung": "kit", "tags": ["meta-transparency", plat]}
        add_finding(item, acct["id"], "kit", None, 75)
        cite(acct, "kit", False, 75)

    # app-store developer records
    for rec in _appdev_records(case_dir):
        dev = rec["developer"]
        store = "Google Play" if rec.get("store") == "play" else "App Store" if rec.get("store") == "appstore" else "App store"
        label = dev.get("legal_name") or dev.get("seller_name") or dev.get("name")
        if not label:
            continue
        owners = [o for o in rec.get("owner_links") or [] if isinstance(o, dict)]
        rung = "owner" if owners else "kit"
        org = subject_for({"type": "organization", "value": label})
        for alias in (dev.get("name"), dev.get("seller_name")):
            if alias and alias != org["label"] and alias not in org.setdefault("aliases", []):
                org["aliases"].append(alias)
        sels = org.setdefault("selectors", [])
        for key, typ in (("email", "email"), ("developer_email", "email"), ("phone", "phone")):
            if dev.get(key) and not any(s.get("value") == dev[key] for s in sels):
                sels.append({"type": typ, "value": dev[key], "platform": store})
        if dev.get("website") and not any(s.get("value") == dev["website"] for s in sels):
            sels.append({"type": "website", "value": dev["website"], "url": dev["website"]})
        attrs = org.setdefault("attributes", {})
        attrs.update({k: v for k, v in {
            "store": store, "developer_page": dev.get("developer_page"),
            "developer_id": dev.get("developer_id") or dev.get("artist_id"),
            "address": dev.get("address"),
            "eu_trader_status": (dev.get("trader") or {}).get("status"),
            "support_url": dev.get("support_url"), "privacy_url": dev.get("privacy_url"),
            "other_apps": [a.get("package") or a.get("name") or a.get("bundle_id")
                           for a in rec.get("other_apps") or [] if isinstance(a, dict)] or None,
        }.items() if v})
        app = (dev.get("app") or {}) if isinstance(dev.get("app"), dict) else {}
        app_sub = subject_for({"type": "application", "value": app.get("name") and f"{app['name']} ({rec.get('query')})"
                               or str(rec.get("query") or "app")})
        app_sub.setdefault("attributes", {}).update({k: v for k, v in {
            "store": store, "query": rec.get("query"), "bundle_id": app.get("bundle_id")}.items() if v})
        facts = [f"display name {dev['name']}" if dev.get("name") else None,
                 f"legal name {dev['legal_name']}" if dev.get("legal_name") else None,
                 f"seller {dev['seller_name']}" if dev.get("seller_name") else None,
                 f"contact email {dev['email']}" if dev.get("email") else None,
                 f"developer email {dev['developer_email']}" if dev.get("developer_email") else None,
                 f"website {dev['website']}" if dev.get("website") else None,
                 f"address {dev['address']}" if dev.get("address") else None,
                 f"phone {dev['phone']}" if dev.get("phone") else None,
                 f"support link {dev['support_url']}" if dev.get("support_url") else None,
                 f"privacy policy {dev['privacy_url']}" if dev.get("privacy_url") else None]
        desc = f"{store} developer of {rec.get('query')}: " + ", ".join(x for x in facts if x) + "."
        if owners:
            desc += " " + " ".join(
                f"The developer website's registrable domain {o.get('value')} matches case domain "
                f"{o.get('matched_case_domain') or o.get('value')} — an owner link (rung class "
                f"{o.get('rung_class') or 'app.developer_url'})." for o in owners)
        elif dev.get("website"):
            desc += " The developer website is outside the case — a lead, not an owner link."
        tstat = (dev.get("trader") or {}).get("status")
        if tstat == "declared":
            desc += (" On the EU storefront the provider declared itself a trader under the EU Digital "
                     "Services Act; Apple displays the trader address/phone/email above, as declared "
                     "by the developer.")
        elif tstat == "not_declared":
            desc += (" On the EU storefront the provider has NOT declared itself a trader, so Apple "
                     "publishes no trader address/phone/email.")
        elif tstat == "geo_redirected":
            desc += (" The EU trader block was NOT read: the collection egress was redirected to the "
                     f"{(dev.get('trader') or {}).get('served_storefront') or 'local'} storefront, so "
                     "absence of a trader address/phone/email here is not evidence.")
        desc += " A store listing is self-declared: the legal name is who the account claims to be."
        src = (rec.get("source_urls") or [None])[0]
        add_finding({"claim": desc, "source_url": src, "type": "identity",
                     "rung_class": (owners[0].get("rung_class") if owners else "app.listing"),
                     "tags": ["app-developer", rec.get("store") or "app"] + (["owner-link"] if owners else [])},
                    org["id"], rung, None, 90 if owners else 70)
        cite(org, rung, False, 90 if owners else 70)
        cite(app_sub, rung, False, 90 if owners else 70)
        others = attrs.get("other_apps") or []
        if others:
            add_finding({"claim": f"The {store} developer account {label} also lists "
                                  f"{_count_phrase(len(others), 'other app')}: {', '.join(map(str, others[:25]))}"
                                  + (" …" if len(others) > 25 else "") + ".",
                         "source_url": (rec.get("source_urls") or [None])[-1], "type": "behavioral",
                         "tags": ["app-developer", "other-apps"]}, org["id"], "kit", None, 70)
        n_con += 1
        new_con.append({"id": f"CON-{n_con:03d}", "from_id": org["id"], "to_id": app_sub["id"],
                        "relationship": "publishes", "strength": "confirmed"})
        for o in owners:
            dom_sid = sub_by_host.get(str(o.get("matched_case_domain") or o.get("value") or "").lower())
            if dom_sid:
                n_con += 1
                new_con.append({"id": f"CON-{n_con:03d}", "from_id": org["id"], "to_id": dom_sid,
                                "relationship": "operates", "strength": "confirmed"})
        for u in rec.get("source_urls") or []:
            sources.append({"name": f"{store} listing", "url": u, "date": today})

    # roles + IOC gate on the subjects this layer minted
    exclude = set()
    clean_values = set()
    for s in new_subj:
        c = cites.get(s["id"], {})
        tainted = c.get("candidate") and not c.get("owner")
        benign_contact = benign and s.get("type") in contact_types
        if c.get("owner") and not benign:
            s["role"] = "actor"
        if tainted or benign_contact:
            s["ioc_exclude"] = True
            s["notes"] += (" Candidate selector (unverified grading) — kept for the narrative, excluded "
                           "from IOCs." if tainted else
                           " Benign-check party: identity evidence, not a detection indicator.")
        vals = [s["label"]] + [str(x.get("value")) for x in s.get("selectors") or []
                               if x.get("value") and x.get("type") != "website"]
        (exclude if s.get("ioc_exclude") else clean_values).update(v.strip().lower() for v in vals if v)
    exclude -= clean_values
    deduped, seen_con = [], set()
    for c in new_con:
        key = (c["from_id"], c["to_id"], c["relationship"])
        if key not in seen_con:
            seen_con.add(key)
            deduped.append({**c, "id": f"CON-{con_base + len(deduped) + 1:03d}"})
    return {"subjects": new_subj, "findings": new_fnd, "connections": deduped, "gaps": gaps,
            "sources": sources, "ioc_exclude": sorted(exclude)}
