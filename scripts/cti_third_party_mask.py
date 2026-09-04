#!/usr/bin/env python3
# cti-expert skill — shared third-party masking for SHAREABLE report exports.
"""cti_third_party_mask.py — mask uninvolved third parties in shareable deliverables.

Shareable exports (PDF / DOCX / HTML / IOC / report JSON) must not name uninvolved third parties:
a skim reader or an IOC scraper strips the exculpatory framing (SKILL §2.5, /cti output rule). The
operator's OWN selectors are the finding and stay in clear (`keep`); addresses at the estate's own
domains are operator infrastructure (`hosts`); everything else is masked:

  e-mails            -> x***@domain
  phones             -> 03********      (matched on the national significant number)
  other cases' ids   -> "a related case" (this case's own id is never masked)
  `extra` literals   -> initials for names ("Some Person" -> "S. P."), `qu***` for slugs

Both report paths — `intel_engine/tools/house_report.py` (editorial PDF/DOCX) and
`scripts/build_report_data.py` (dashboard bundle) — route through THIS implementation, so one test
covers every shareable output. Deliberately separate from cti_text_normalize.py, whose contract is
"dashes only, never mutate selectors": masking does the opposite on purpose.

Author: Hieu Ngo - chongluadao.vn
"""
import json
import os
import re

_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"(?<![\w.])(\+?84[.\s-]?\d{9,10}|0\d{9,10}|\+\d{1,3}[.\s-]?\d{7,12})(?![\w])")
_CASE_ID_RE = re.compile(r"\bCASE-[A-Za-z0-9][A-Za-z0-9-]{2,}\b")
# Registrar / host ROLE mailboxes (the abuse-referral targets a report exists to name) are not
# third-party PII — left in clear on purpose, consistently across every section.
_ROLE_LOCALS_IN_CLEAR = frozenset({"abuse", "hostmaster", "noc", "registrar-abuse", "postmaster"})


def nsn(v):
    """National significant number: digits without the +84 / 84 / leading-0 prefixes."""
    d = re.sub(r"\D", "", v or "")
    if d.startswith("84") and len(d) >= 11:
        d = d[2:]
    return d.lstrip("0")


def _initials(name):
    return " ".join(w[:1].upper() + "." for w in name.split() if w)


def load_case_mask(case_dir):
    """Extra literals to mask for this case: <case>/report_mask.json (a JSON list of strings)."""
    try:
        with open(os.path.join(case_dir, "report_mask.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        return [str(x) for x in data if x] if isinstance(data, list) else []
    except Exception:
        return []


def mask_third_parties(text, keep=(), hosts=(), extra=(), current_case=""):
    """Mask third-party e-mails, phones, other cases' ids and `extra` literals in `text`.
    `keep`: operator selectors (e-mails / phones) left in clear. `hosts`: the estate's own
    domains — mailboxes there stay in clear. `current_case`: this case's id, never masked."""
    if not text or not isinstance(text, str):
        return text
    keep_l = {k.lower() for k in keep if k}
    keep_nsn = {nsn(k) for k in keep if k and nsn(k)}
    hosts_l = {h.lower() for h in hosts if h}

    def email(m):
        local, dom = m.group(1), m.group(2)
        full = "%s@%s" % (local, dom)
        if full.lower() in keep_l or dom.lower() in hosts_l or local.lower() in _ROLE_LOCALS_IN_CLEAR:
            return full
        return "%s***@%s" % (local[:1], dom)

    def phone(m):
        v = m.group(1)
        if nsn(v) in keep_nsn:
            return v
        digits = re.sub(r"\D", "", v)
        return digits[:2] + "*" * max(4, len(digits) - 2)

    def case_id(m):
        return m.group(0) if m.group(0) == current_case else "a related case"

    text = _EMAIL_RE.sub(email, text)
    text = _PHONE_RE.sub(phone, text)
    text = _CASE_ID_RE.sub(case_id, text)
    for lit in extra:
        if lit and lit in text:
            text = text.replace(lit, _initials(lit) if " " in lit else lit[:2] + "***")
    return text


def mask_obj(obj, **kw):
    """Recursively apply mask_third_parties to every string in a JSON-like structure."""
    if isinstance(obj, str):
        return mask_third_parties(obj, **kw)
    if isinstance(obj, list):
        return [mask_obj(v, **kw) for v in obj]
    if isinstance(obj, dict):
        return {k: mask_obj(v, **kw) for k, v in obj.items()}
    return obj
