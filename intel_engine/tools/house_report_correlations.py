#!/usr/bin/env python3
"""
house_report_correlations.py — the §VI "Temporal correlations" block of the house report.

Reads case_timeline's structured <stem>_events.json ("correlations") and renders each non-empty
correlation as a table with ONE judgment sentence; empty ones are named in a single line (Rule 19:
an absent result is stated). The markdown-bullet parser is the fallback for a report/ dir that
predates the events file. Stdlib only.
"""
from __future__ import annotations

import json
import re


# --------------------------------------------------------------------------- temporal correlations
# case_timeline.py writes <stem>_events.json with a structured "correlations" dict — the same data
# its markdown bullets print as Python reprs. The report reads the JSON (no repr parsing, nothing for
# the Rule-12 scrubber to eat); the bullet parser below is the fallback for a report/ dir that
# predates that file.
_CORR_SECTIONS = [                       # json key, section heading, date field
    ("registration_cohorts", "Registration cohorts (one provisioning sitting)", "date"),
    ("expiry_cohorts", "Expiry / renewal cohorts (one payer)", "expires"),
    ("whois_update_cohorts", "Same-day WHOIS updates", "date"),
    ("cert_batches", "Certificate issuance batches", "from"),
    ("ip_tenancy", "IP tenancy overlap", "from"),
    ("shared_artifact_windows", "Shared artifacts — contemporaneous?", "from"),
    ("lapse_cohorts", "Abandonment cohorts", "date"),
]
_ITEM_RE = re.compile(r"\*\*(.+?)\*\*\s*[—-]\s*(.*)")


def _norm_item(when, hosts, fields: dict) -> dict:
    f = {k: v for k, v in fields.items() if k not in ("reading", "links", "hosts")}
    return {"when": str(when or "")[:19], "hosts": [str(h) for h in hosts or []], "fields": f}


def correlations_from_events(events: dict) -> dict:
    corr = (events or {}).get("correlations") or {}
    secs: dict = {}
    for key, heading, datef in _CORR_SECTIONS:
        if key not in corr:
            continue
        secs[heading] = [_norm_item(it.get(datef) or it.get("date") or it.get("from"), it.get("hosts"), it)
                         for it in corr[key] if isinstance(it, dict)]
    return secs


def _parse_correlations(md: str) -> dict:
    """Fallback: '### Section' -> [{when, hosts[], fields{}}] from case_timeline's nested bullets."""
    secs: dict = {}
    sec, item = None, None
    in_corr = False
    for ln in md.splitlines():
        if ln.startswith("## Temporal correlations"):
            in_corr = True
            continue
        if not in_corr:
            continue
        if ln.startswith("## "):
            break
        if ln.startswith("### "):
            sec = ln[4:].strip()
            secs[sec] = []
            item = None
            continue
        if sec is None:
            continue
        if ln.startswith("- **"):
            m = _ITEM_RE.match(ln[2:].strip())
            if m:
                item = {"when": m.group(1).strip(), "hosts": [h.strip() for h in m.group(2).split(",") if h.strip()], "fields": {}}
                secs[sec].append(item)
            continue
        st = ln.strip()
        if item is not None and st.startswith("- ") and not st.startswith("- _"):
            k, _, v = st[2:].partition(":")
            item["fields"][k.strip()] = _listish(v.strip()) if v.strip().startswith("[") else v.strip()
    return secs


def _listish(v) -> list:
    if isinstance(v, list):
        return [str(i) for i in v]
    if isinstance(v, bool) or v is None or v == "":
        return []
    try:
        x = json.loads(str(v).replace("'", '"'))
        return [str(i) for i in x] if isinstance(x, list) else [str(x)]
    except ValueError:
        return [str(v)]


def _truthy(v) -> bool:
    return v is True or str(v).strip().lower() == "true"


def temporal_correlations_md(ledger_md: str, escape, events: dict | None = None) -> str:
    """Tables + one judgment sentence per non-empty correlation; empty ones named in one line."""
    secs = correlations_from_events(events) if events else _parse_correlations(ledger_md)
    if not secs:
        return ""
    L, empty = [], []
    for sec, items in secs.items():
        low = sec.lower()
        if not items:
            name = sec.split(" (")[0].split(" —")[0].strip()
            empty.append(name if name[:2].isupper() else name[:1].lower() + name[1:])   # keep acronyms (IP)
            continue
        if low.startswith("expiry"):
            indep = [it for it in items if _truthy(it["fields"].get("independent_signal"))]
            L += [f"### {sec}", ""]
            if not indep:
                terms = sorted({t for it in items for t in _listish(it["fields"].get("term_days", ""))})
                term = f"same {'/'.join(terms)}-day term" if terms else "same registration term"
                L += [f"{len(items)} expiry cohorts mirror the registration cohorts exactly (same creation day, "
                      f"{term}), so they restate the registration finding and are not counted twice.", ""]
            else:
                L += ["| Expiry day | Domains | Term (days) |", "|:--:|:------------------------|:--:|"]
                L += [f"| {it['when'][:10]} | {', '.join('`' + h + '`' for h in it['hosts'])} | "
                      f"{'/'.join(_listish(it['fields'].get('term_days', '')))} |" for it in indep]
                L += ["", f"{len(indep)} of {len(items)} expiry cohorts are independent of the creation date — a renewal paid "
                      "for several domains in one sitting is one payer.", ""]
            continue
        if low.startswith("certificate"):
            batches = sorted(items, key=lambda it: -len(it["hosts"]))
            big = batches[:3]
            L += [f"### {sec}", "",
                  f"{len(items)} certificate-issuance windows were shared by two or more estate hosts"
                  + (" — largest: " + "; ".join(f"{it['when'][:10]} ({', '.join('`' + h + '`' for h in it['hosts'])})" for it in big) if big else "")
                  + ". Shared CAs with 90-day auto-renewal synchronise unrelated sites too, so this corroborates "
                  "provisioning habits and does not bind domains.", ""]
            continue
        # registration cohorts, same-day WHOIS updates, IP tenancy, shared artifacts, abandonment
        has_reg = any(it["fields"].get("registrars") for it in items)
        L += [f"### {sec}", ""]
        L += ["| Day | Domains |" + (" Registrar |" if has_reg else ""), "|:--:|:------------------------|" + (":--------|" if has_reg else "")]
        regs_all = set()
        for it in items:
            regs = _listish(it["fields"].get("registrars", ""))
            regs_all.update(regs)
            L.append(f"| {it['when'][:10]} | {', '.join('`' + h + '`' for h in it['hosts'])} |"
                     + (f" {escape(', '.join(regs))} |" if has_reg else ""))
        L.append("")
        if low.startswith("registration"):
            biggest = max(len(it["hosts"]) for it in items)
            head = (f"{len(items)} same-day registration cohorts, {sum(len(it['hosts']) for it in items)} domains in all"
                    + (f", every one through {escape(next(iter(regs_all)))}" if len(regs_all) == 1 else "") + ".")
            # The one-operator reading is only stated when the data supports it: small cohorts through
            # one registrar. A large cohort, or several registrars, is exactly what a promotion produces.
            if biggest <= 4 and len(regs_all) == 1:
                head += (" Domains registered in one sitting share a purchaser; the cohorts are small enough that a "
                         "registrar promotion does not explain them, which favours one operator.")
            else:
                head += (" Same-day registration is consistent with one purchaser or with a registrar promotion, "
                         "and is not weighed as a link on its own.")
            L += [head, ""]
        elif low.startswith("same-day whois"):
            L += [("All updates fall inside one registrar, so a registrar-side event (system migration, privacy toggle) "
                   "explains them as well as an operator action does — discounted as a link."
                   if len(regs_all) <= 1 else
                   "Updates on one day across different registrars are an operator action, not a registrar event."), ""]
    if empty:
        L += [f"No {', '.join(empty[:-1])}{' or ' if len(empty) > 1 else ''}{empty[-1]} could be derived from the collected dates.", ""]
    return "\n".join(L).strip()


# --------------------------------------------------------------------------- registrant eras
# case_timeline.whois_events() emits one `registrant_era` event per distinct registrant identity
# in the WHOIS history (start = first record of that identity, end = the next identity's first
# record, else expiry). A host with ONE era is the normal case and says nothing; two or more eras
# is the drop-catch / reactivation signal the house report has to call out, because an archive
# capture dated inside an EARLIER era shows the previous owner's page, not the operator's.

def registrant_eras_from_events(events: dict) -> dict:
    """{host: [{start, end, identity, registrar}, …] sorted by start} for hosts with >1 era.

    WhoisXML returns several records per real era (registrant contact, registry contact, privacy
    relay — all dated the same day), so a raw fold on identity string produces zero-length "eras"
    and same-day flaps. Fold: (1) rows sharing a start day collapse to ONE, preferring a NAMED
    identity over a privacy/placeholder one; (2) consecutive rows with the same identity+registrar
    merge; (3) a zero-length row that has a neighbour on the same day is dropped."""
    by_host: dict = {}
    for ev in (events or {}).get("events") or []:
        if ev.get("kind") != "registrant_era":
            continue
        v = ev.get("value") or {}
        by_host.setdefault(str(ev.get("host") or ""), []).append({
            "start": str(ev.get("start") or "")[:10],
            "end": str(ev.get("end") or "")[:10],
            "identity": str(v.get("identity") or ev.get("label") or "").replace("registrant: ", ""),
            "registrar": str(v.get("registrar") or ""),
        })
    out = {}
    for h, eras in by_host.items():
        eras.sort(key=lambda e: (e["start"], e["end"]))
        # (1) one row per start day: keep the named identity when a same-day sibling is a placeholder
        by_day: dict = {}
        for e in eras:
            cur = by_day.get(e["start"])
            if cur is None:
                by_day[e["start"]] = dict(e)
                continue
            cur["end"] = max(cur["end"], e["end"])
            if _identity_rank(e["identity"], e["registrar"]) > _identity_rank(cur["identity"], cur["registrar"]):
                cur["identity"], cur["registrar"] = e["identity"], e["registrar"]
        folded = [by_day[k] for k in sorted(by_day)]
        # (2) merge consecutive identical identity+registrar
        merged = []
        for e in folded:
            if merged and (merged[-1]["identity"].lower(), merged[-1]["registrar"].lower()) == (e["identity"].lower(), e["registrar"].lower()):
                merged[-1]["end"] = max(merged[-1]["end"], e["end"])
            else:
                merged.append(e)
        # (3) each era ends where the next begins
        for a, b in zip(merged, merged[1:]):
            if b["start"] and (not a["end"] or a["end"] > b["start"] or a["end"] == a["start"]):
                a["end"] = b["start"]
        merged = [e for e in merged if not (e["start"] and e["end"] == e["start"])] or merged[:1]
        if len(merged) > 1:
            out[h] = merged
    return out


def _identity_rank(identity: str, registrar: str) -> int:
    """Higher = more informative: named person/mailbox > registrar placeholder > privacy > empty."""
    if not identity:
        return 0
    if _is_registrar_placeholder(identity, registrar):
        return 1
    return 2


def _is_registrar_placeholder(identity: str, registrar: str) -> bool:
    """The registrar's own name standing in the registrant field (`NameCheap, Inc.` on a Namecheap
    record) is a redaction placeholder, not an identity."""
    i = re.sub(r"[^a-z0-9]", "", str(identity or "").lower())
    r = re.sub(r"[^a-z0-9]", "", str(registrar or "").lower())
    if not i or not r:
        return False
    core_i = re.sub(r"(inc|llc|ltd|limited|corp|corporation|co|gmbh|sa|sarl)$", "", i)
    core_r = re.sub(r"(inc|llc|ltd|limited|corp|corporation|co|gmbh|sa|sarl)$", "", r)
    return bool(core_i) and (core_i == core_r or core_i in core_r or core_r in core_i)


def era_start_of(events: dict, host: str, fallback=None):
    """Start date (YYYY-MM-DD) of the LATEST registrant era for `host` when the host has changed
    registrant at least once; otherwise `fallback` (the WHOIS `created` date).

    This is the cutoff `predates_registration` compares an archive capture against: a capture
    between the WHOIS `created` date and the current era's start belongs to a previous registrant,
    not to the operator under investigation. A single-era host deliberately keeps `created` — its
    one history record is dated by its `updated` field, which can post-date registration and would
    otherwise mis-caption a legitimate early capture as pre-registration."""
    eras = registrant_eras_from_events(events).get(host)
    if not eras:
        return fallback
    latest = eras[-1]["start"] or ""
    # The current registration can never start before its own WHOIS `created` date. When the history
    # records stop at the PREVIOUS owner's era (no record for the current registrant yet), `eras[-1]`
    # is that previous era and would caption the previous owner's parking page as this operator's —
    # the exact mis-attribution this cutoff exists to prevent. Take the later of the two.
    fb = str(fallback or "")[:10]
    if fb and (not latest or fb > latest):
        return fb
    return latest or fallback


def _era_class(identity: str, is_privacy, registrar: str = "") -> str:
    if not identity:
        return "unknown"
    if _is_registrar_placeholder(identity, registrar):
        return "placeholder"
    try:
        if is_privacy and is_privacy(identity):
            return "privacy"
    except Exception:
        pass
    return "named"


def registrant_eras_md(events: dict, escape, is_privacy=None, whois: dict = None) -> str:
    """'Registrant eras' table for hosts with more than one registrant era, or ''.

    Columns: host · era start · era end · registrant identity · registrar · class. Class is
    `privacy` (proxy), `placeholder` (the registrar's own name in the registrant field), `named`.
    When `whois` ({host: current whois row}) is given, the CURRENT registration is appended as the
    last row (start = its `created`, end = current) and tagged `current · reactivation` — the
    operator's own era, which the history records alone usually do not spell out."""
    eras = registrant_eras_from_events(events)
    if not eras:
        return ""
    L = [f"{len(eras)} host(s) changed registrant identity at least once in the WHOIS history. An "
         "archive capture dated inside an earlier era shows the PREVIOUS registrant's page and is "
         "captioned as such; the current era's start, not the WHOIS creation date, is the cutoff.", "",
         "| Host | Era start | Era end | Registrant | Registrar | Class |",
         "|:-----|:--:|:--:|:------|:------|:--:|"]
    for host in sorted(eras):
        rows = list(eras[host])
        cur = (whois or {}).get(host) or (whois or {}).get(host.lower()) or {}
        cur_id = str(cur.get("registrant_email") or cur.get("registrant_name") or cur.get("registrant_org") or "").strip()
        cur_start = str(cur.get("created") or "")[:10]
        cur_reg = str(cur.get("registrar") or "")
        appended = False
        if cur_start and cur_start >= rows[-1]["start"] and not (rows[-1]["start"] == cur_start and rows[-1]["identity"].lower() == cur_id.lower()):
            if rows[-1]["start"] == cur_start:
                rows[-1] = {"start": cur_start, "end": "", "identity": cur_id or rows[-1]["identity"], "registrar": cur_reg or rows[-1]["registrar"]}
            else:
                rows[-1]["end"] = rows[-1]["end"] or cur_start
                rows.append({"start": cur_start, "end": "", "identity": cur_id, "registrar": cur_reg})
            appended = True
        for i, e in enumerate(rows):
            cls = _era_class(e["identity"], is_privacy, e["registrar"])
            if i == len(rows) - 1:
                cls = f"{cls} · {'current · ' if appended else ''}reactivation"
            L.append(f"| `{host}` | {e['start'] or '—'} | {e['end'] or 'current'} | "
                     f"{escape(e['identity']) or '—'} | {escape(e['registrar']) or '—'} | {cls} |")
    L.append("")
    return "\n".join(L).strip()

