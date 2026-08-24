#!/usr/bin/env python3
"""sh_export.py — turn a CASE into a MISP EVENT, offline. The half of the MISP layer that
sends nothing.

WHAT THIS IS FOR
----------------
A finished case is a set of assertions about somebody else's infrastructure. A MISP event is
those assertions in the form other people's detection stacks consume. The translation is not
mechanical, and the failure modes run in both directions:

  * publish too little  — the case dies on one analyst's disk and the next victim is somebody
                          who could have blocked it;
  * publish too much    — a Cloudflare certificate, a template favicon, a registrant's personal
                          phone number, or a VICTIM's own WHOIS goes out with `to_ids` set, and
                          every subscriber's blocklist is now wrong in a way they will blame on
                          their own tooling for weeks.

So this module is mostly a series of refusals. It reads `cases/<case>/raw/*.json`, maps each
pivot through `references/misp.json`, and splits everything three ways: AUTO (operator-provisioned
infrastructure), REVIEW (personal data, identity handles, third-party-derived values — held back
until a human says yes to those specific values) and NEVER (page context, generated candidates,
shared platform noise, and our own operational data). It writes a JSON file. It has no network
code at all — pushing is `sh_misp.py`, and it is gated separately.

THE OWNERSHIP QUESTION COMES FIRST
-----------------------------------
`cases/<case>/scope.json` records the intake class, and it decides what may be shared before any
per-artifact rule runs. On a `victim_host` the page's WHOIS, favicon, certificate and analytics
belong to the VICTIM; publishing them as the operator's indicators tells every subscriber to
block a victim. On a `benign_check` there is nothing shareable at all. With no scope on file the
class is `unknown`, and unknown ownership means every artifact needs a human — the export says so
rather than assuming the seed was hostile.

BASE RATES ARE A SHARING CONTROL, NOT A CLUSTERING ONE
-------------------------------------------------------
The same filters that stop a parking favicon becoming a false cluster stop it becoming a false
indicator, so this module reuses `tools/kb/noise_filters.py` where it can find it. When it CANNOT
(the skill imported standalone, without the repo's KB), it does not fall back to publishing
everything: every `auto` artifact is downgraded to `review` and the reduced state is stated in
the export's warnings. A filter that quietly stops filtering is how bad indicators get shared.

CLI
---
    sh_export.py <case>                          # build, write cases/<case>/misp/event-<ts>.json
    sh_export.py <case> --leads                  # human-readable summary of what would be shared
    sh_export.py <case> --host site.example      # only artifacts collected from these hosts
    sh_export.py <case> --include-review         # add the held-back personal/derived values
    sh_export.py <case> --info "..." --tlp green --distribution 1
    sh_export.py <case> --root /path/to/repo -o out.json --pretty

Python 3 stdlib only.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import sys

from sh_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

#: Minimal embedded default. `load_ref` falls back to this and WARNS when the JSON is missing or
#: malformed; `tests/test_references.py` asserts the loaded groups are strictly richer than this
#: stub, which is how a silent fall back is detected. The stub is deliberately the CONSERVATIVE
#: subset: it knows fewer mappings (so more artifacts are excluded as unmapped) and it never
#: relaxes the staging rail. A degraded run shares less, never more.
_MISP_FALLBACK = {
    "endpoints": {"version": "/servers/getVersion",
                  "describe_types": "/attributes/describeTypes.json",
                  "add_event": "/events/add", "edit_event": "/events/edit/{event_id}",
                  "publish_event": "/events/publish/{event_id}",
                  "add_attribute": "/attributes/add/{event_id}",
                  "search_attributes": "/attributes/restSearch",
                  "event_ui": "/events/view/{event_id}"},
    "attribute_map": {
        "domain": {"type": "domain", "category": "Network activity", "to_ids": True,
                   "publish_class": "auto"},
        "url": {"type": "url", "category": "Network activity", "to_ids": True,
                "publish_class": "auto"},
        "file:sha256": {"type": "sha256", "category": "Payload delivery", "to_ids": True,
                        "publish_class": "auto"},
        "whois:registrant_email": {"type": "whois-registrant-email", "category": "Attribution",
                                   "to_ids": False, "publish_class": "review"},
    },
    "publish_classes": {"auto": "included on approval", "review": "needs a per-value decision",
                        "never": "never shared"},
    "excluded_kinds": {"third_party_host": "shared CDN/SaaS hostname by construction"},
    "value_validators": {"sha256": "[0-9a-fA-F]{64}", "md5": "[0-9a-fA-F]{32}",
                         "url": "(?i)https?://\\S{3,2000}"},
    # One object, and the grouping rule. On the stub the event is almost all loose attributes —
    # valid MISP, just less structured — which is the safe degradation: a wrong object_relation
    # is silently dropped by MISP, a plain attribute never is.
    "objects": {
        "whois": {"template_uuid": "429faea1-34ff-47af-8a00-7c62d3be5a6a",
                  "template_version": "10", "meta_category": "network", "min_relations": 2,
                  "anchor": "domain",
                  "relations": {"whois:registrant_email": "registrant-email",
                                "whois:registrar": "registrar"}},
    },
    "event_report": {
        "sections": ["summary", "contents", "not_included", "collection_basis", "handling"],
        "name_template": "{seed} — collection summary",
        "analyst_report_max_chars": 20000,
        "headings": {"summary": "Summary", "contents": "What this event contains",
                     "not_included": "What was deliberately NOT included",
                     "collection_basis": "Collection basis and limitations",
                     "handling": "Handling"},
    },
    # Only the two REFUSALS and a conservative default: a class the stub does not know falls
    # through to `unknown`, which on the stub caps at `review` — so a degraded run holds every
    # value for a per-value decision instead of sharing on a policy it could not read.
    "class_policy": {
        "victim_host": {"max_class": "never", "requires_acknowledgement": True, "event_tags": []},
        "benign_check": {"max_class": "never", "requires_acknowledgement": True, "event_tags": []},
        "unknown": {"max_class": "review", "requires_acknowledgement": True, "event_tags": []},
    },
    # The staging level, plus one level that is already irrecoverable. An unlisted level resolves
    # to a generic entry marked not-recallable, which is the safe reading of an unknown audience.
    "distribution_levels": {
        "0": {"name": "your_organisation_only", "who": "Only your own MISP organisation.",
              "recallable": True},
        "1": {"name": "this_community_only", "who": "Every organisation on this instance.",
              "recallable": False},
    },
    "event_defaults": {"threat_level_id": 2, "analysis": 1, "tlp": "amber",
                       "info_template": "{seed} — {label} infrastructure (OSINT, {date})",
                       "default_label": "fraud"},
    "taxonomy_tags": {"tlp": {"amber": "tlp:amber", "green": "tlp:green", "clear": "tlp:clear",
                              "red": "tlp:red"},
                      "always": ["type:OSINT"], "pap": "PAP:AMBER"},
    "confidence_map": {"high": "estimative-language:confidence-in-analyst-judgment=\"high\"",
                       "moderate": "estimative-language:confidence-in-analyst-judgment=\"moderate\"",
                       "low": "estimative-language:confidence-in-analyst-judgment=\"low\""},
    "never_publish": ["CASE-", "cases/", "/Users/", "/home/", "Authorization:"],
    "policy": {"staging_distribution": 0, "staged_published": False,
               "max_distribution_without_lock": 0, "publish_env_lock": "INTEL_MISP_PUBLISH",
               "require_confirmation": True, "require_review_confirmation": True,
               "strip_case_identifiers": True, "refuse_on_classes": ["benign_check"],
               "default_to_ids": False},
    "request_budget": {"max_requests_per_run": 40, "max_attributes_per_event": 400,
                       "attribute_batch_size": 100, "http_timeout_seconds": 45},
    "reporting": {
        "not_configured": "MISP is NOT configured (no MISP_URL / MISP_KEY): nothing was sent.",
        "staged_note": "STAGED ONLY — organisation-only and unpublished.",
        "publish_irreversible": "Publishing syncs to peer servers and cannot be recalled.",
        "review_pending": "Attributes classed `review` were NOT included.",
        "truncated": "The attribute list was TRUNCATED.",
        "type_downgraded": "Unknown attribute type downgraded to `text`.",
    },
}

_REFS = load_ref(ref_path(__file__, "misp.json"), _MISP_FALLBACK)

ENDPOINTS = _REFS["endpoints"]
ATTRIBUTE_MAP = _REFS["attribute_map"]
PUBLISH_CLASSES = _REFS["publish_classes"]
EXCLUDED_KINDS = _REFS["excluded_kinds"]
VALUE_VALIDATORS = _REFS["value_validators"]
OBJECTS = _REFS["objects"]
EVENT_REPORT = _REFS["event_report"]
CLASS_POLICY = _REFS["class_policy"]
DISTRIBUTION_LEVELS = _REFS["distribution_levels"]
EVENT_DEFAULTS = _REFS["event_defaults"]
TAXONOMY_TAGS = _REFS["taxonomy_tags"]
CONFIDENCE_MAP = _REFS["confidence_map"]
NEVER_PUBLISH = _REFS["never_publish"]
POLICY = _REFS["policy"]
BUDGET = _REFS["request_budget"]
REPORTING = _REFS["reporting"]

_RANK = {"auto": 0, "review": 1, "never": 2}


# --------------------------------------------------------------------------- base-rate filters
# Reuse the KB's noise filters when the full repo is present. When it is not, we do NOT publish
# unfiltered: `noise_available()` is False and every `auto` artifact is downgraded to `review`.
def _import_noise(root: str):
    for cand in (os.path.join(root, "tools", "kb"),
                 os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "tools", "kb")):
        if os.path.isdir(cand) and cand not in sys.path:
            sys.path.append(cand)
    try:
        import noise_filters  # noqa: PLC0415
        return noise_filters
    except Exception:  # noqa: BLE001
        return None


def _repo_root() -> str:
    """The repo this skill was imported into: IntelShare/tools -> IntelShare -> repo root."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# --------------------------------------------------------------------------- reading the case
def read_case(case: str, root: str | None = None) -> dict:
    """Read a case's collected pivots and its intake scope. Pure filesystem, no network."""
    root = root or _repo_root()
    case_dir = os.path.join(root, "cases", str(case))
    scope = {}
    scope_path = os.path.join(case_dir, "scope.json")
    if os.path.isfile(scope_path):
        try:
            scope = json.load(open(scope_path, encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            scope = {}
    records = []
    for path in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(doc, dict) or "pivots" not in doc:
            continue
        meta = doc.get("meta") or {}
        records.append({
            "host": meta.get("host") or os.path.splitext(os.path.basename(path))[0],
            "source": meta.get("source"), "final_url": meta.get("final_url"),
            "collected_at": meta.get("collected_at"),
            "pivots": doc.get("pivots") or [],
        })
    return {"case": str(case), "case_dir": case_dir, "scope": scope, "records": records,
            "exists": os.path.isdir(case_dir)}


# --------------------------------------------------------------------------- classification
def leak_scan(text) -> list:
    """Markers from `never_publish` present in a string WE are about to emit. Case-sensitive
    substring matching — see the group's `_comment` for why the markers must stay precise."""
    s = str(text or "")
    return [m for m in NEVER_PUBLISH if m and m in s]


def class_for_case(scope: dict) -> tuple:
    """(target_class, policy_entry). No scope on file means ownership was never established, which
    is `unknown` — not an assumption that the seed was hostile."""
    tc = str((scope or {}).get("target_class") or "unknown")
    pol = CLASS_POLICY.get(tc) or CLASS_POLICY.get("unknown") or {"max_class": "review"}
    return tc, pol


def _cap(klass: str, ceiling: str) -> str:
    """Downgrades only. A case class or a noise filter may push an artifact toward `never`;
    nothing pushes it back toward `auto`."""
    return klass if _RANK.get(klass, 2) >= _RANK.get(ceiling, 2) else ceiling


def classify(kind: str, value, *, confidence: str = "", noise=None) -> tuple:
    """(publish_class, spec, reason). `spec` is the attribute_map entry, or None when there is
    nothing to build an attribute from."""
    kind = str(kind or "")
    if kind in EXCLUDED_KINDS:
        return "never", None, EXCLUDED_KINDS[kind]
    base = kind.split(":")[0]
    if base in EXCLUDED_KINDS:                       # e.g. build_env:<VAR>
        return "never", None, EXCLUDED_KINDS[base]
    spec = ATTRIBUTE_MAP.get(kind)
    if not spec:
        return "never", None, ("no MISP mapping for this kind — add one to "
                               "IntelShare/references/misp.json if it should be shared")
    if not isinstance(value, (str, int, float)) or str(value).strip() == "":
        return "never", spec, "value is not a shareable scalar"
    bad = validate_value(spec.get("type"), value, kind)
    if bad:
        return "never", spec, bad
    klass = str(spec.get("publish_class") or "review")
    reason = ""
    if str(confidence).lower() == "low":
        klass, reason = _cap(klass, "review"), "collected at LOW confidence"
    if noise is not None:
        hit = noise_reason(kind, value, noise)
        if hit:
            return "never", spec, hit
    return klass, spec, reason


def validate_value(atype, value, kind="") -> str:
    """Shape check against `value_validators`. A malformed indicator is worse than a missing one:
    it can never match anything, and it makes the whole event look sloppy to the receiver.

    Keyed by our pivot KIND first, then by the MISP type. The kind matters because MISP has no
    attribute type for several things we collect — verified against a live 2.5.31 instance, its
    crypto types are btc, dash and xmr only — so an ETH address ships as `text`, and without a
    kind-keyed pattern it would be the one wallet in the event that nothing shape-checks."""
    pattern = VALUE_VALIDATORS.get(str(kind or "")) or VALUE_VALIDATORS.get(str(atype or ""))
    if not pattern:
        return ""
    try:
        if re.fullmatch(pattern, str(value).strip()):
            return ""
    except re.error:                       # a broken regex must not decide to publish
        return f"the validator for `{atype}` is not a valid regex — held back rather than shared"
    return (f"value does not have the shape of a `{kind or atype}` (extraction artefact?) — an "
            f"indicator that cannot match anything is noise in somebody else's feed")


def noise_reason(kind: str, value, noise) -> str:
    """The base-rate refusals, phrased for a reader who will act on the indicator. Every one of
    these is a value that is TRUE of the target and also true of thousands of unrelated hosts."""
    v = str(value)
    try:
        if kind == "favicon_hash" and noise.is_parking_favicon(value):
            return ("parking/template favicon shared by thousands of unrelated domains — "
                    "publishing it would match half a hosting provider's estate")
        if kind.startswith("tracker:") and noise.is_noise_tracker(v):
            return "platform-default tracker id, shared across unrelated tenants"
        if kind in ("email", "whois:registrant_email", "dmarc_contact") and noise.is_noise_email(v):
            return "registrar / privacy-proxy contact address, not the operator's"
        if kind in ("phone", "whois:registrant_phone") and noise.is_noise_phone(v):
            return "registrar / provider switchboard number, not the operator's"
        if kind in ("domain", "subdomain", "urlscan_related_domain", "mail_server",
                    "third_party_host") and noise.is_parking_host(v):
            return "parking / default-hosting host"
        if kind in ("domain", "urlscan_related_domain") and noise.is_shared_infra_apex(v):
            return "shared-infrastructure apex (a platform's own domain, not a tenant's)"
        if kind.startswith("social:") and noise.is_noise_social_handle(v):
            return "platform boilerplate handle (a share/intent link, not an account)"
    except Exception:  # noqa: BLE001 — a filter that errors must not decide to publish
        return "base-rate filter errored on this value — held back rather than shared"
    return ""


# --------------------------------------------------------------------------- building the event
def _dist_entry(level) -> dict:
    return DISTRIBUTION_LEVELS.get(str(level)) or {"name": f"level-{level}", "who": "unknown",
                                                   "recallable": False}


def _event_tags(tlp: str, confidence: str, class_pol: dict, extra=None) -> list:
    tags = []
    tlp_map = (TAXONOMY_TAGS.get("tlp") or {})
    tags.append(tlp_map.get(str(tlp).lower()) or f"tlp:{str(tlp).lower()}")
    tags += list(TAXONOMY_TAGS.get("always") or [])
    if TAXONOMY_TAGS.get("pap"):
        tags.append(TAXONOMY_TAGS["pap"])
    conf = CONFIDENCE_MAP.get(str(confidence).lower())
    if conf:
        tags.append(conf)
    tags += list(class_pol.get("event_tags") or [])
    tags += list(extra or [])
    seen, out = set(), []
    for t in tags:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def build_event(case: str, *, root: str | None = None, hosts=None, info: str = "",
                label: str = "", tlp: str = "", confidence: str = "moderate",
                threat_level=None, analysis=None, include_review: bool = False,
                review_values=None, requested_distribution: int = 0, extra_tags=None,
                max_attributes: int = 0, analyst_md: str = "") -> dict:
    """Build the MISP event for a case. Returns the event plus the two lists that matter more than
    it does: what was held back for review, and what was refused outright and why."""
    root = root or _repo_root()
    data = read_case(case, root)
    noise = _import_noise(root)
    warnings = []
    if noise is None:
        warnings.append(
            "BASE-RATE FILTERS UNAVAILABLE (tools/kb/noise_filters.py not importable). Every "
            "artifact was downgraded to `review`: without the filters a parking favicon or a "
            "registrar contact address cannot be told from an operator artifact, and sharing one "
            "as an indicator is worse than sharing nothing.")
    if not data["exists"]:
        warnings.append(f"no case directory on disk for {case!r} — nothing was read.")
    if not data["records"]:
        warnings.append("the case holds no collected pivot files (cases/<case>/raw/*.json). "
                        "This is absence of COLLECTION, not a case with no indicators.")

    target_class, class_pol = class_for_case(data["scope"])
    ceiling = str(class_pol.get("max_class") or "review")
    if noise is None:
        ceiling = _cap(ceiling, "review")
    refuse = str(target_class) in list(POLICY.get("refuse_on_classes") or [])

    want_hosts = {h.lower().lstrip(".") for h in (hosts or []) if h}
    review_values = {str(v) for v in (review_values or [])}
    cap = int(max_attributes or BUDGET.get("max_attributes_per_event", 400))

    seen, included, review, excluded = set(), [], [], []
    n_pivots = 0
    for rec in data["records"]:
        host = str(rec.get("host") or "")
        if want_hosts and host.lower().lstrip(".") not in want_hosts:
            continue
        for p in rec["pivots"]:
            n_pivots += 1
            kind, value = p.get("kind"), p.get("value")
            klass, spec, reason = classify(kind, value, confidence=p.get("confidence") or "",
                                           noise=noise)
            klass = _cap(klass, ceiling)
            if klass != "never":
                atype = str(spec.get("type") or "text")
                key = (atype, str(value))
                if key in seen:
                    continue
                seen.add(key)
            row = {"kind": kind, "value": value, "host": host,
                   "type": (spec or {}).get("type"), "category": (spec or {}).get("category"),
                   "reason": reason or (spec or {}).get("note") or ""}
            if klass == "never":
                row["reason"] = reason or "excluded by policy"
                excluded.append(row)
                continue
            if klass == "review" and not (include_review or str(value) in review_values):
                row["reason"] = reason or _review_reason(kind, spec, target_class)
                review.append(row)
                continue
            included.append({"pivot": p, "spec": spec, "rec": rec, "host": host, "kind": kind})

    objects, attributes = group_objects(included)

    truncated = 0
    in_objects = sum(len(o.get("Attribute") or []) for o in objects)
    if len(attributes) + in_objects > cap:
        keep = max(0, cap - in_objects)
        truncated = len(attributes) - keep
        attributes = attributes[:keep]
        warnings.append(f"{REPORTING.get('truncated')} {truncated} attribute(s) were dropped "
                        f"(cap {cap}, request_budget.max_attributes_per_event). Objects are kept "
                        f"whole — a half-populated object states something false about its "
                        f"subject, which a truncated attribute list does not.")

    seed = _seed_host(data)
    tlp = tlp or str(EVENT_DEFAULTS.get("tlp") or "amber")
    info = info or _default_info(seed, label or str(EVENT_DEFAULTS.get("default_label") or "fraud"))

    # Nothing WE compose may carry our own operational strings. Refusing beats stripping: a silent
    # strip would hide that the value was ever in scope.
    leaks = []
    for m_ in leak_scan(analyst_md):
        leaks.append(f"the analyst report attached with --report contains {m_!r}")
    for field, text in [("info", info)] + [(f"Attribute[{i}].comment", a.get("comment"))
                                           for i, a in enumerate(attributes)]:
        for m in leak_scan(text):
            leaks.append(f"{field} contains {m!r}")
    for i, a in enumerate(attributes):
        for m in leak_scan(a.get("value")):
            if m in ("/Users/", "/home/", "cases/", ".claude/skills", "Authorization:"):
                leaks.append(f"Attribute[{i}].value contains {m!r}")

    # The event DATE is the date of the observation, not of the export. A receiver ages an
    # indicator from it, so stamping today on a collection made three weeks ago quietly makes
    # stale infrastructure look fresh.
    stamps = sorted(str(r.get("collected_at") or "") for r in data["records"]
                    if r.get("collected_at"))
    staged = int(POLICY.get("staging_distribution", 0))
    event = {
        "info": info,
        "date": (stamps[0][:10] if stamps else _utcnow()[:10]),
        "threat_level_id": int(threat_level or EVENT_DEFAULTS.get("threat_level_id", 2)),
        "analysis": int(analysis if analysis is not None else EVENT_DEFAULTS.get("analysis", 1)),
        "distribution": staged,
        "published": bool(POLICY.get("staged_published", False)),
        "Tag": [{"name": t} for t in _event_tags(tlp, confidence, class_pol, extra_tags)],
        "Attribute": attributes,
    }
    if objects:
        event["Object"] = objects

    req = int(requested_distribution or 0)
    out = {
        "meta": {
            "case": str(case), "built_at": _utcnow(), "seed": seed,
            "target_class": target_class, "class_note": class_pol.get("note") or "",
            "max_publish_class_for_this_case": ceiling,
            "requires_acknowledgement": bool(class_pol.get("requires_acknowledgement")),
            "hosts_read": len({r["host"] for r in data["records"]}),
            "pivots_read": n_pivots,
            "base_rate_filters": "noise_filters" if noise else "UNAVAILABLE",
            "requested_distribution": req,
            "requested_distribution_name": _dist_entry(req).get("name"),
            "staged_distribution": staged,
            "staged_note": REPORTING.get("staged_note"),
            "truncated_attributes": truncated,
            "refused": refuse,
            "leaks": leaks,
            "warnings": warnings,
            "collected_from": (stamps[0][:10] if stamps else ""),
            "collected_to": (stamps[-1][:10] if stamps else ""),
            "exhaustion": _exhaustion(str(case), root, seed),
        },
        "Event": event,
        "review": review,
        "excluded": excluded,
        "counts": {"attributes": len(attributes), "objects": len(objects),
                   "attributes_in_objects": in_objects, "review": len(review),
                   "excluded": len(excluded), "pivots_read": n_pivots},
    }
    # The narrative is built LAST, from the finished event, so it can never describe something the
    # event does not contain. It rides alongside the Event rather than inside it: MISP takes an
    # event report through its own endpoint, and an unsupported key inside `Event` is dropped
    # silently — which would ship the indicators with the caveats quietly missing.
    out["EventReport"] = [build_report(out, analyst_md=analyst_md)]
    if refuse or ceiling == "never":
        out["meta"]["refusal"] = (
            f"REFUSED: the case's intake class is {target_class!r}. "
            + str(class_pol.get("note") or "")
            + " Nothing collected under this class may be shared as an indicator — not with "
              "include_review either, because the objection is OWNERSHIP, not sensitivity.")
        out["Event"]["Attribute"] = []
        out["counts"]["attributes"] = 0
    if leaks:
        out["meta"]["refusal"] = (
            "REFUSED: the event carries our own operational strings (case identifiers, local "
            "paths, persona or credential markers). Fix the source values or the event info and "
            "rebuild — this is not stripped silently on purpose. " + "; ".join(leaks[:6]))
        out["Event"]["Attribute"] = []
        out["counts"]["attributes"] = 0
    if review and not include_review:
        out["meta"]["review_note"] = (
            f"{REPORTING.get('review_pending')} {len(review)} value(s) are waiting — see `review`. "
            f"Ask the analyst about them by value, not in bulk.")
    return out


def group_objects(included: list) -> tuple:
    """(objects, loose_attributes) — fold related attributes into MISP OBJECTS.

    An object is the standard's way of saying several values describe ONE thing: a `whois` object
    states that THIS domain's registration record names that registrant, where four loose
    attributes only state that four values appeared somewhere in the case.

    Grouping is per HOST, because that is the thing being described. A candidate that would carry
    fewer than `min_relations` values stays a plain attribute — an object exists to group, and a
    one-attribute object is noise dressed as structure (twenty file hashes with nothing else known
    about any of them would otherwise become twenty `file` objects)."""
    by_host = {}
    for row in included:
        by_host.setdefault(row["host"], []).append(row)

    objects, used = [], set()
    for host, rows in by_host.items():
        for oname, ospec in OBJECTS.items():
            rel_map = ospec.get("relations") or {}
            members = [r for r in rows if r["kind"] in rel_map and id(r) not in used]
            anchor = str(ospec.get("anchor") or "")
            n = len(members) + (1 if (anchor and host) else 0)
            if not members or n < int(ospec.get("min_relations", 2)):
                continue
            # A relation the template does not mark `multiple` may appear ONCE. A second value
            # for it is not a richer object, it is a false statement about one record — two
            # registrant emails on one `whois` object assert that a single registration named
            # both, when what we have is two eras of the same domain. The extra value drops back
            # to a plain attribute, so nothing is lost and nothing is misstated.
            repeatable = set(ospec.get("multiple_relations") or [])
            attrs, taken = [], set()
            if anchor and host:
                stamp = _misp_datetime(str((members[0]["rec"] or {}).get("collected_at") or ""))
                a0 = {"type": "domain" if anchor == "domain" else "text",
                      "object_relation": anchor, "value": host,
                      "to_ids": False, "distribution": 5,
                      "comment": "the host this record describes"}
                if stamp:                       # the anchor is dated like every other attribute
                    a0["first_seen"] = a0["last_seen"] = stamp
                attrs.append(a0)
                taken.add(anchor)
            for r in members:
                rel = rel_map[r["kind"]]
                if rel in taken and rel not in repeatable:
                    continue                      # stays loose: not marked used
                taken.add(rel)
                used.add(id(r))
                a = _attribute(r["pivot"], r["spec"], r["rec"], "auto")
                a["object_relation"] = rel
                attrs.append(a)
            if len(attrs) < int(ospec.get("min_relations", 2)):
                for r in members:                 # the group collapsed — give the values back
                    used.discard(id(r))
                continue
            objects.append({
                "name": oname,
                "meta-category": ospec.get("meta_category") or "network",
                "template_uuid": ospec.get("template_uuid"),
                "template_version": str(ospec.get("template_version") or ""),
                "description": f"{oname} record for {host}" if host else oname,
                "distribution": 5,
                "comment": f"grouped from {len(members)} collected artifact(s)",
                "Attribute": attrs,
            })
    loose = [_attribute(r["pivot"], r["spec"], r["rec"], "auto")
             for r in included if id(r) not in used]
    return objects, loose


def _review_reason(kind: str, spec: dict, target_class: str) -> str:
    if target_class == "victim_host":
        return ("the case's intake class is victim_host — this artifact may belong to the VICTIM, "
                "not the operator, and publishing it would point detections at a victim")
    note = (spec or {}).get("note")
    if note:
        return note
    return "held for an explicit per-value analyst decision"


def _attribute(pivot: dict, spec: dict, rec: dict, klass: str) -> dict:
    """One MISP attribute.

    The COMMENT is the part a receiving analyst actually reads before deciding whether to act on
    a value, so it carries three things and never our case identifier: what kind of artifact this
    is and where we saw it, when we saw it, and — where the artifact type has one — the base-rate
    caveat that governs it ("thousands of unrelated sites share a template favicon"). A value
    shipped without that caveat gets used as though it were an identifier.

    `first_seen` / `last_seen` come from the collection timestamp. They are MISP-standard fields
    and they matter more here than in most feeds: infrastructure in these cases is rented for
    weeks, so an indicator with no date is one a receiver cannot age out."""
    host = str(rec.get("host") or "")
    when = str(rec.get("collected_at") or "")
    kind = str(pivot.get("kind") or "")
    bits = [f"{kind} observed on {host}"] if host else [kind]
    if when[:10]:
        bits.append(f"first collected {when[:10]}")
    conf = str(pivot.get("confidence") or "").lower()
    if conf:
        bits.append(f"collection confidence {conf}")
    caveat = str(spec.get("note") or pivot.get("note") or "").strip()
    if caveat:
        bits.append(caveat if len(caveat) <= 160 else caveat[:159] + "…")
    out = {
        "type": str(spec.get("type") or "text"),
        "category": str(spec.get("category") or "External analysis"),
        "value": str(pivot.get("value")),
        "to_ids": bool(spec.get("to_ids", POLICY.get("default_to_ids", False))),
        "distribution": 5,                       # inherit the event's level, never exceed it
        "comment": " · ".join(bits),
    }
    if _misp_datetime(when):
        out["first_seen"] = out["last_seen"] = _misp_datetime(when)
    return out


def _misp_datetime(ts: str) -> str:
    """`2026-01-02T03:04:05Z` -> the ISO form MISP stores. Empty when we have no timestamp: an
    invented date is worse than an absent one."""
    ts = str(ts or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts):
        return ""
    return ts.replace("Z", "+00:00")


def _exhaustion(case: str, root: str, host: str = "") -> dict:
    """The seed-exhaustion verdict, when the full repo is present. Opportunistic on purpose: the
    skill must work standalone, but when WebPivot is there this is the one caveat a RECEIVER can
    never reconstruct — whether the collection behind these indicators was exhaustive or a first
    look. An event that does not say so is read as the former."""
    cand = os.path.join(root, "WebPivot", "tools")
    if os.path.isdir(cand) and cand not in sys.path:
        sys.path.append(cand)
    try:
        import wp_exhaust  # noqa: PLC0415
        rep = wp_exhaust.assess_case(case, root=root)
        results = rep.get("results") or []
        if not results:
            return {}
        seed = next((r for r in results if str(r.get("host") or "") == str(host)), None)
        if seed:
            gaps = [g["label"] for g in seed.get("gaps") or []]
            verdict, scope = seed["verdict"], "the seed"
        else:
            # No record for the seed BY NAME — a case's files are named after the URL it was
            # given, which is not always the host that answered. Fall back to the INTERSECTION,
            # the layers missing from EVERY host, because that is the only claim the data
            # supports: the union would accuse the collection of gaps a single artifact record
            # merely had no use for, and the worst single host is usually exactly such a record.
            sets = [{g["layer"] for g in r.get("gaps") or []} for r in results]
            common = set.intersection(*sets) if sets else set()
            labels = {g["layer"]: g["label"] for r in results for g in (r.get("gaps") or [])}
            gaps = sorted(labels[x] for x in common)
            verdict = "triage" if rep.get("triage_hosts") else "exhausted"
            scope = "any host in this collection"
        return {"verdict": verdict, "gaps": gaps, "scope": scope,
                "hosts": rep["hosts"], "triage_hosts": rep["triage_hosts"]}
    except Exception:  # noqa: BLE001
        return {}


def build_report(result: dict, analyst_md: str = "") -> dict:
    """The MISP EVENT REPORT — the narrative an attribute list cannot carry.

    This is where the discipline the rest of this toolkit applies internally finally leaves the
    building with the indicators: what is here, what was held back and why, how far the collection
    actually went, and how the material may be redistributed. A receiver who is told none of that
    reads an indicator list as complete and current, which is the failure this whole layer exists
    to prevent — one hop further out than usual, because now it is somebody else's blocklist."""
    m, c = result["meta"], result["counts"]
    ev = result["Event"]
    head = EVENT_REPORT.get("headings") or {}
    order = EVENT_REPORT.get("sections") or ["summary", "contents", "not_included",
                                             "collection_basis", "handling"]
    objs = ev.get("Object") or []
    attrs = ev.get("Attribute") or []
    by_type = {}
    for a in attrs:
        by_type[a["type"]] = by_type.get(a["type"], 0) + 1
    ids_n = sum(1 for a in attrs if a.get("to_ids"))
    sec = {}

    sec["summary"] = [
        f"**{ev['info']}**", "",
        f"Open-source collection against {m['hosts_read']} host(s); "
        f"{m['pivots_read']} artifact(s) examined."
        + (f" Observed {m['collected_from']} to {m['collected_to']}."
           if m.get("collected_from") else ""),
    ]
    if m.get("requires_acknowledgement") and m.get("class_note"):
        sec["summary"] += ["", f"> {m['class_note']}"]

    sec["contents"] = [
        f"- {len(attrs)} attribute(s)" + (f" and {len(objs)} object(s)" if objs else "") + ".",
        f"- {ids_n} attribute(s) carry `to_ids`. Everything else is a HUNTING pivot — a favicon "
        f"hash, a TLS-stack fingerprint or a tracker id is shared by every site built from the "
        f"same kit, so it is for finding more infrastructure, not for blocking.",
    ]
    if by_type:
        sec["contents"].append("- By type: "
                               + ", ".join(f"{k} ×{v}" for k, v in sorted(by_type.items())) + ".")
    dated = sum(1 for a in attrs if a.get("first_seen"))
    if attrs and dated < len(attrs):
        sec["contents"].append(
            f"- {dated} of {len(attrs)} attribute(s) carry an observation date. The remainder come "
            f"from collections made before the collector recorded one; they are undated rather "
            f"than current, and no date was invented for them.")
    for o in objs:
        sec["contents"].append(f"- `{o['name']}` object: {o.get('description')} "
                               f"({len(o.get('Attribute') or [])} values).")

    sec["not_included"] = []
    if c["review"]:
        sec["not_included"].append(
            f"- {c['review']} value(s) were withheld pending a per-value decision: personal data "
            f"(registrant names, emails, phone numbers, identity handles) and values derived from "
            f"a third-party index rather than observed by us.")
    if c["excluded"]:
        by_reason = {}
        for r in result["excluded"]:
            by_reason[r["reason"]] = by_reason.get(r["reason"], 0) + 1
        sec["not_included"].append(
            f"- {c['excluded']} artifact(s) were refused as shared infrastructure, page context "
            f"or malformed values. The largest groups:")
        for reason, n in sorted(by_reason.items(), key=lambda kv: -kv[1])[:4]:
            sec["not_included"].append(f"    - {n} × {reason}")
    if not sec["not_included"]:
        sec["not_included"] = ["- Nothing was withheld from this event."]

    sec["collection_basis"] = [
        f"- Scope class at intake: `{m['target_class']}`.",
        "- Method: passive open-source collection (public DNS, certificate transparency, WHOIS/"
        "RDAP, archive and third-party scan indexes) plus retrieval of the pages themselves.",
    ]
    ex = m.get("exhaustion") or {}
    if ex.get("verdict") == "triage":
        gaps = ", ".join(ex.get("gaps") or [])
        scope = ex.get("scope") or "the seed"
        extra = ""
        if ex.get("hosts", 0) > 1:
            extra = (f" ({ex.get('triage_hosts')} of {ex.get('hosts')} collected hosts are still "
                     f"at triage depth.)")
        sec["collection_basis"].append(
            f"- **This collection was a TRIAGE, not an exhaustive search.**"
            + (f" These evidence layers were never run against {scope}: {gaps}." if gaps else "")
            + f"{extra} Their absence is absence of COLLECTION, not evidence that nothing exists "
              f"— do not read this event as the full extent of the actor's infrastructure.")
    elif ex.get("verdict") == "exhausted":
        sec["collection_basis"].append(
            "- Every required evidence layer was run against the seed before this event was "
            "assembled.")
    if m.get("base_rate_filters") != "noise_filters":
        sec["collection_basis"].append(
            "- Base-rate filtering was UNAVAILABLE for this export; values were reviewed by hand "
            "instead.")
    for w in m.get("warnings") or []:
        sec["collection_basis"].append(f"- {w}")

    tags = [t["name"] for t in ev.get("Tag") or []]
    tlp = next((t for t in tags if t.startswith("tlp:")), "tlp:amber")
    conf = next((t for t in tags if t.startswith("estimative-language:")), "")
    sec["handling"] = [
        f"- Redistribution is governed by **{tlp.upper()}**. Do not re-share beyond what that "
        f"permits.",
        "- Analytic confidence is expressed with the `estimative-language` taxonomy"
        + (f" (`{conf}`)." if conf else "."),
        "- Indicators are dated (`first_seen`); infrastructure in cases of this kind is commonly "
        "rented for weeks, so age them accordingly rather than treating them as durable.",
    ]

    body = []
    for key in order:
        lines = sec.get(key)
        if not lines:
            continue
        body += [f"## {head.get(key, key.replace('_', ' ').title())}", ""] + lines + [""]
    if analyst_md:
        limit = int(EVENT_REPORT.get("analyst_report_max_chars", 20000))
        cut = analyst_md[:limit]
        body += ["## Analyst assessment", ""]
        body += [cut + ("\n\n_(truncated for the event report; the full assessment is held by the "
                        "originating team.)_" if len(analyst_md) > limit else "")]
    name = str(EVENT_REPORT.get("name_template") or "{seed} — collection summary").format(
        seed=m.get("seed") or m.get("case"))
    return {"name": name, "content": "\n".join(body).strip() + "\n"}


def _seed_host(data: dict) -> str:
    """The host the event is named after: the first NAME we collected, by collection time. An
    address is a poor headline (it is usually shared hosting and it dates badly), so a name wins
    over an IP even when the IP was collected first."""
    recs = [r for r in (data.get("records") or []) if r.get("host")]
    if not recs:
        return str(data.get("case") or "")
    recs.sort(key=lambda r: str(r.get("collected_at") or "9999"))
    named = [r for r in recs if not re.fullmatch(r"[0-9.:a-fA-F]+", str(r["host"]))]
    return str((named or recs)[0]["host"])


def _default_info(seed: str, label: str) -> str:
    tpl = str(EVENT_DEFAULTS.get("info_template") or "{seed} — {label} ({date})")
    return tpl.format(seed=seed, label=label, date=_utcnow()[:10])


# --------------------------------------------------------------------------- reporting
def leads(result: dict) -> str:
    """The human-readable brief: what would be shared, what is held back, what was refused."""
    m, c = result["meta"], result["counts"]
    out = [f"MISP export — case {m['case']}  ({m['built_at']})",
           f"  intake class      {m['target_class']}  → artifacts capped at "
           f"`{m['max_publish_class_for_this_case']}`"
           + ("  · ACKNOWLEDGE BEFORE SHARING" if m.get("requires_acknowledgement") else ""),]
    if m.get("requires_acknowledgement") and m.get("class_note"):
        out.append(f"                    {m['class_note']}")
    out += [
           f"  collection read   {m['hosts_read']} host(s), {m['pivots_read']} pivot(s)",
           f"  base-rate filters {m['base_rate_filters']}",
           f"  event info        {result['Event']['info']}",
           f"  tags              {', '.join(t['name'] for t in result['Event']['Tag'])}",
           f"  attributes        {c['attributes']} to share  ·  {c['review']} held for review  "
           f"·  {c['excluded']} refused",
           f"  staged at         distribution {m['staged_distribution']} "
           f"({_dist_entry(m['staged_distribution']).get('name')}), published=false"]
    if m.get("requested_distribution"):
        d = _dist_entry(m["requested_distribution"])
        out.append(f"  REQUESTED         distribution {m['requested_distribution']} "
                   f"({d.get('name')}) — {d.get('who')}  [applied only by the publish step]")
    if m.get("refusal"):
        out += ["", "  " + m["refusal"]]
    for w in m.get("warnings") or []:
        out.append(f"  ⚠ {w}")
    if result["Event"]["Attribute"]:
        out.append("\n  WOULD SHARE")
        for a in result["Event"]["Attribute"][:40]:
            flag = "IDS" if a["to_ids"] else "   "
            out.append(f"    {flag}  {a['type']:<28} {str(a['value'])[:70]}")
        if len(result["Event"]["Attribute"]) > 40:
            out.append(f"    … and {len(result['Event']['Attribute']) - 40} more")
    if result["review"]:
        out.append("\n  HELD FOR REVIEW — ask about these by value, they are not bulk-approvable")
        for r in result["review"][:25]:
            out.append(f"    {str(r['kind']):<28} {str(r['value'])[:50]:<52} {r['reason'][:70]}")
        if len(result["review"]) > 25:
            out.append(f"    … and {len(result['review']) - 25} more")
    if result["excluded"]:
        by = {}
        for r in result["excluded"]:
            by[r["reason"]] = by.get(r["reason"], 0) + 1
        out.append("\n  REFUSED (never shared)")
        for reason, n in sorted(by.items(), key=lambda kv: -kv[1])[:12]:
            out.append(f"    {n:>4}  {reason[:100]}")
    return "\n".join(out)


def write_event(result: dict, case_dir: str, out_path: str = "") -> str:
    """Persist the built event. Timestamped and never overwritten — the diff between two exports
    is the record of what an analyst decided to add or hold back."""
    path = out_path or os.path.join(case_dir, "misp", f"event-{_stamp()}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    return path


# --------------------------------------------------------------------------- CLI
def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build a MISP event from a case — offline. Sends nothing; sh_misp.py does.")
    ap.add_argument("case")
    ap.add_argument("--root", default=None, help="repo root holding cases/ (default: this repo)")
    ap.add_argument("--host", action="append", default=[], help="only these collected hosts")
    ap.add_argument("--info", default="", help="event headline (never put a case id in it)")
    ap.add_argument("--label", default="", help="word for the default headline, e.g. phishing")
    ap.add_argument("--tlp", default="", choices=["", "clear", "green", "amber", "amber+strict",
                                                  "red"])
    ap.add_argument("--confidence", default="moderate",
                    help="ICD-203 term for the assessment; becomes an estimative-language tag")
    ap.add_argument("--threat-level", type=int, default=None, help="1 High 2 Medium 3 Low 4 Undef")
    ap.add_argument("--analysis", type=int, default=None, help="0 Initial 1 Ongoing 2 Completed")
    ap.add_argument("--distribution", type=int, default=0,
                    help="the distribution to REQUEST; the push still stages at 0")
    ap.add_argument("--include-review", action="store_true",
                    help="include the held-back personal / third-party-derived values")
    ap.add_argument("--review-value", action="append", default=[],
                    help="approve one held-back value (repeatable) — the per-value decision")
    ap.add_argument("--tag", action="append", default=[], help="extra machine tag (repeatable)")
    ap.add_argument("--report", default="",
                    help="attach an analyst-written markdown file to the event report (scanned "
                         "for our own operational strings and refused on a hit)")
    ap.add_argument("--max-attributes", type=int, default=0)
    ap.add_argument("-o", "--out", default="", help="write here instead of cases/<case>/misp/")
    ap.add_argument("--no-write", action="store_true", help="build and print, persist nothing")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--leads", action="store_true", help="human-readable summary instead of JSON")
    a = ap.parse_args(argv)

    res = build_event(a.case, root=a.root, hosts=a.host, info=a.info, label=a.label, tlp=a.tlp,
                      confidence=a.confidence, threat_level=a.threat_level, analysis=a.analysis,
                      include_review=a.include_review, review_values=a.review_value,
                      requested_distribution=a.distribution, extra_tags=a.tag,
                      max_attributes=a.max_attributes,
                      analyst_md=(open(a.report, encoding="utf-8").read() if a.report else ""))
    if not a.no_write:
        case_dir = os.path.join(a.root or _repo_root(), "cases", str(a.case))
        res["meta"]["written_to"] = write_event(res, case_dir, a.out)
    if a.leads:
        print(leads(res))
        if res["meta"].get("written_to"):
            print(f"\n  event file → {res['meta']['written_to']}")
            print("  NOTHING HAS BEEN SENT. Push it with sh_misp.py push <file> --confirm-push "
                  "(stages organisation-only, unpublished).")
        return 0
    print(json.dumps(res, ensure_ascii=False, indent=2 if a.pretty else None))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
