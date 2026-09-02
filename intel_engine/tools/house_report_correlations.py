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


