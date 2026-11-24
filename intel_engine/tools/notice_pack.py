#!/usr/bin/env python3
"""
notice_pack.py — draft the notices an analyst SENDS to act on a finding: registrar, host, CDN /
edge, platform, bank or e-wallet, a law-enforcement referral pack, and — for a compromised site —
a security notice to the victim. It drafts. It never sends, uploads or submits anything, and it
makes no network call: every fact comes from the stored case (assessment.json, clusters.json,
raw/*.json, whois/*.json, scope.json, victim_profile.json and evidence/custody.jsonl).

WHY THE RAILS (SKILL.md §2.5, RULE 5)
-------------------------------------
A notice names a party to someone outside the team. Naming an innocent party is the most damaging
error this skill can make, so the generator REFUSES rather than degrades:

  * no assessment.json, an `inconclusive` or `same-kit` attribution, a `contradicted` or
    `not_supported` premise_verdict, a `benign_check` intake, a confidence below
    notice_templates.json `min_confidence` (fallback `high`) or a threshold not on the scale ->
    exit 2, and every UNSENT earlier draft is marked `withdrawn` (sent ones are records, untouched);
  * the seed is a subject only as a member of the assessment's `cluster`; only the clusters.json
    component holding the seed counts; inside it a host is owner-linked by a binding only when ITS
    OWN relation to the indicator (binding `rels_by_domain`, else its own KB edges, read-only) grades
    OWNER (rungs.json via selector_types.rung_for) and is not a PREVIOUS owner's registration
    (whois_eras). Subjects are the hosts joined to the seed by such bindings; a host whose own
    relation cannot be established is excluded;
  * kit siblings, neighbours, mentions (assessment.json) and clusters.json `related_hosts` never
    become subjects; excluded hosts are listed with the reason in notices/index.json only, and every
    hidden host and its subdomains is replaced in every drafted notice; the assessment's prose
    (`bluf`) reaches the referral pack only;
  * a host notice goes only to an address whose origin era is `current` (wp_origin_history);
  * a victim_host (compromised-site) seed yields ONLY compromise notices to the site owner —
    never a takedown request against a victim.

Output: cases/<case>/notices/<class>-<slug>.md (each passed through house_report.scrub() and the
report's third-party masking) and notices/index.json {recipient, contact, contact_source,
contact_collected_at, subjects, excluded, evidence_refs, status: drafted}. `intel.py action-log`
later marks a notice sent and records its result; a sent notice's file and entry are never
rewritten by a re-draft. Templates and thresholds are DATA: tools/kb/references/notice_templates.json.

CLI:
  python3 tools/notice_pack.py <case>          # draft; exit 2 with the reason on refusal
"""
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
for _p in (HERE, KB_TOOLS, WP):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import kb_refs  # noqa: E402 — reference DATA loader (tools/kb/kb_refs.py)
import selector_types  # noqa: E402 — rung_for(): owner | kit | neighbour
from whois_eras import owner_values, prior_values  # noqa: E402 — the ONLY history -> owner decision
try:
    from wp_common import _registrable  # noqa: E402 — PSL-aware apex, same as the collectors
except Exception:  # noqa: BLE001
    def _registrable(host):
        parts = (host or "").strip(".").lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")
try:
    from whois_enrich import is_privacy as _is_privacy  # noqa: E402 — privacy-proxy / registrar mailbox
except Exception:  # noqa: BLE001
    def _is_privacy(_):
        return False
try:
    import wp_origin_history as _oh  # noqa: E402 — origin rows + tenancy era (host_origins)
except Exception:  # noqa: BLE001 — without it no host notice is drafted (never a guessed origin)
    _oh = None

CLASSES = ("registrar", "host", "cdn", "platform", "bank", "referral", "compromise")

# Conservative minimum (RULE 3 failure contract): refuse below high confidence and on a contradicted /
# unsupported premise or a benign_check intake, map NO binding to an owner class (so every member is
# excluded rather than accused) and fall back to plain text that carries no analyst prose.
_GENERIC_BODY = ("To {recipient},\n\nSubject(s):\n{subjects}\n\nEvidence (capture time and SHA-256):\n"
                 "{evidence}\n\nOur reference: {case}")
_FALLBACK = {
    "policy": {"min_confidence": "high"},
    "refuse_attribution_levels": ["inconclusive", "same-kit"],
    "refuse_premise_verdicts": ["contradicted", "not_supported"],
    "refuse_target_classes": ["benign_check"],
    "confidence_order": ["low", "moderate", "high"],
    "binding_rel_classes": {},
    "binding_prefix_classes": {},
    "platform_report_pages": {},
    "cdn_abuse_contacts": {},
    "templates": {
        "registrar": {"title": "Abuse report: {recipient}", "body": _GENERIC_BODY},
        "host": {"title": "Abuse report: {recipient}", "body": _GENERIC_BODY},
        "cdn": {"title": "Notice: {recipient}", "body": _GENERIC_BODY},
        "platform": {"title": "Platform report checklist: {recipient}",
                     "body": "{report_page}\n\n{checklist}\n\nOur reference: {case}"},
        "bank": {"title": "Fraud report: {recipient}",
                 "body": "{accounts}\n\nSite(s):\n{subjects}\n\nEvidence:\n{evidence}\n\nOur reference: {case}"},
        "referral": {"title": "Referral pack: {case}",
                     "body": "{bluf}\n\n{subjects}\n\n{timeline}\n\n{evidence}\n\n{ioc_bundle}\n\n{excluded}"},
        "compromise": {"title": "Security notice: your site",
                       "body": "To {recipient},\n\nSite(s):\n{subjects}\n\nEvidence:\n{evidence}\n\n"
                               "We are not asking anyone to take your site down.\n\nOur reference: {case}"},
    },
}
_REF = kb_refs.load_ref(kb_refs.ref_path(kb_refs.__file__, "notice_templates.json"), _FALLBACK)


class Refusal(Exception):
    """The generator declines to draft; str(exc) is the reason printed to the analyst."""


# --------------------------------------------------------------------------- small readers
def _load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return default


def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _mtime_iso(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat(timespec="seconds")
    except OSError:
        return None


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def case_dir(case):
    c = str(case)
    if os.path.isabs(c) or os.sep in c:
        return c
    return os.path.join(ROOT, "cases", c)


def _host(v):
    v = str(v or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    return v.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def _day(v):
    s = str(v or "").strip()
    return s[:10] if len(s) >= 10 and s[4] == "-" and s[7] == "-" else None


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")[:60] or "unknown"


def _conf_rank(conf):
    order = [str(x).lower() for x in (_REF.get("confidence_order") or _FALLBACK["confidence_order"])]
    c = str(conf or "").lower()
    return order.index(c) if c in order else -1


# --------------------------------------------------------------------------- case model
def _raw_index(cdir):
    """{host: (path, obj)} for every raw pivot JSON, keyed by meta.host (else the file stem)."""
    out = {}
    for p in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        obj = _load_json(p, {}) or {}
        if not isinstance(obj, dict):
            continue
        h = _host((obj.get("meta") or {}).get("host") or os.path.basename(p)[:-5])
        if h:
            out.setdefault(h, (p, obj))
    return out


def _domain_live(obj):
    """live_results of a raw's domain pivot ({} for an IP raw / no domain pivot)."""
    for p in obj.get("pivots") or []:
        if isinstance(p, dict) and p.get("kind") == "domain":
            return p.get("live_results") or {}
    return {}


def _whois_for(cdir, host, raws):
    """(whois dict, path or None, collected_at). The case sidecar for the host or its apex first
    (the registrar / abuse record the report used), then the raw's own artifacts.whois."""
    for name in (host, _registrable(host)):
        p = os.path.join(cdir, "whois", f"{name}.json")
        w = _load_json(p)
        if isinstance(w, dict) and w:
            return w, p, _mtime_iso(p)
    path, obj = raws.get(host, (None, {}))
    w = (obj.get("artifacts") or {}).get("whois") or {}
    return (w if isinstance(w, dict) else {}), None, (obj.get("meta") or {}).get("collected_at")


def _resolve_seed(cdir, raws):
    """The case seed, by the report's own rule (cti_case_meta.resolve_seed: scope.json seed, the
    seeds file, then the earliest capture). A fallback that names no collected host and is not the
    scope seed (resolve_seed returns the case id on an empty case) is no seed at all."""
    sc = _load_json(os.path.join(cdir, "scope.json"), {}) or {}
    scope_seed = _host(sc.get("seed")) if isinstance(sc, dict) else ""
    scripts = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        from cti_case_meta import resolve_seed
        hosts = sorted(h for h in raws if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", h) and ":" not in h)
        seed = _host(resolve_seed(cdir, hosts, [raws[h][0] for h in hosts]))
    except Exception:  # noqa: BLE001 — scope.json seed is the documented first source
        seed = scope_seed
    return seed if seed and (seed in raws or seed == scope_seed) else ""


def _tier_exclusions(assessment, clusters):
    """{host-or-apex: reason} for every host the assessment / partition keeps OUT of attribution."""
    out = {}
    for key, why in (("kit_siblings", "kit sibling — shares a kit artifact, never attributed"),
                     ("neighbours", "neighbour — co-tenancy or flow, never attributed")):
        for m in assessment.get(key) or []:
            if isinstance(m, dict) and m.get("value"):
                rc = m.get("rung_class") or "?"
                out.setdefault(_host(m["value"]), f"{why} (rung class {rc})")
    for m in assessment.get("mentions") or []:
        if isinstance(m, dict) and m.get("selector"):
            out.setdefault(_host(m["selector"]), "mention — a corpus hit naming it, never attributed")
    for h in clusters.get("related_hosts") or []:
        out.setdefault(_host(h), "related host at the expansion depth — owner-linked to a previous "
                                 "hop, not to the operator")
    return out


def _rels_class(rels, b):
    """rungs.json identifier class for ONE host's own relations `rels` to the binding indicator `b`
    ('' = unmapped = kit). The strongest rung among those relations wins (owner > kit > neighbour)."""
    ind = str(b.get("indicator") or "")
    typ, _, rest = ind.partition(":")
    prefix = rest.split(":", 1)[0] if typ == "indicator" else typ
    relmap = _REF.get("binding_rel_classes") or {}
    premap = _REF.get("binding_prefix_classes") or {}
    classes = [str(relmap.get(f"{r}|{typ}") or relmap.get(r) or premap.get(prefix) or "")
               for r in (str(x) for x in rels)]
    if not classes:
        return ""
    rank = {"owner": 0, "kit": 1, "neighbour": 2}
    return min(classes, key=lambda c: rank.get(selector_types.rung_for(c), 1))


def _kb_own_rels(keys):
    """{(dst_type, dst): {domain: {rel}}} for the binding indicators `keys`, read from the stored
    knowledge base WITHOUT writing it (the KB is opened only when its directories already exist, so
    its constructor creates nothing). None when no KB is available."""
    root = os.path.join(ROOT, "knowledge")
    if not all(os.path.isdir(os.path.join(root, d)) for d in ("entities", "relationships", "evidence")):
        return None
    try:
        from knowledge_base import KB
        kb = KB(root)
        out = {}
        for e in kb.edges():
            key = (e.get("dst_type"), e.get("dst"))
            if e.get("src_type") == "domain" and key in keys:
                out.setdefault(key, {}).setdefault(_host(e.get("src")), set()).add(str(e.get("rel")))
        return out
    except Exception:  # noqa: BLE001 — unreadable KB = the relation cannot be established
        return None


def _own_rels(b, h, kb_rels):
    """The relations host `h` ITSELF holds to binding `b`: the binding's `rels_by_domain` (written by
    intel.py _write_clusters), else the host's own KB edges. None when neither establishes it —
    never the binding's `rels`, which is the union over every domain sharing the indicator."""
    rbd = b.get("rels_by_domain")
    if isinstance(rbd, dict):
        for d, rels in rbd.items():
            if _host(d) == h:
                return [str(r) for r in (rels or [])]
        return None
    got = (kb_rels or {}).get(_binding_value(b), {}).get(h)
    return sorted(got) if got else None


def _binding_value(b):
    ind = str(b.get("indicator") or "")
    typ, _, rest = ind.partition(":")
    return typ, rest


def _prior_era_only(cls, b, whois):
    """True when an owner-rung WHOIS binding's value is a PREVIOUS owner's (prior era) and not the
    current registration's — the binding then says nothing about who runs the name today."""
    if not cls.startswith("whois.") or not whois:
        return False
    typ, val = _binding_value(b)
    kind = {"email": "email", "phone": "phone"}.get(typ)
    if not kind:
        return False

    def norm(v):
        v = str(v or "").strip().lower()
        return re.sub(r"\D", "", v) if kind == "phone" else v
    cur = {norm(v) for v in owner_values(whois, kind)}
    prior = {norm(p.get("value")) for p in prior_values(whois, kind)}
    return norm(val) in prior and norm(val) not in cur


def _evidence_for(cdir, hosts, raws, custody):
    """[{kind, host, path, captured_at, sha256}] — the stored records behind each subject."""
    out, seen = [], set()
    for h in hosts:
        path, obj = raws.get(h, (None, {}))
        if path and path not in seen:
            seen.add(path)
            out.append({"kind": "collection record", "host": h,
                        "path": os.path.relpath(path, cdir),
                        "captured_at": (obj.get("meta") or {}).get("collected_at") or _mtime_iso(path),
                        "sha256": _sha256(path)})
        for name in (h, _registrable(h)):
            wp = os.path.join(cdir, "whois", f"{name}.json")
            if os.path.isfile(wp) and wp not in seen:
                seen.add(wp)
                out.append({"kind": "registration record", "host": h,
                            "path": os.path.relpath(wp, cdir), "captured_at": _mtime_iso(wp),
                            "sha256": _sha256(wp)})
        rx = re.compile(r"(?<![a-z0-9.-])" + re.escape(h) + r"(?![a-z0-9-]|\.[a-z0-9])", re.I)
        for row in custody:
            item = str(row.get("item") or "")
            key = (item, row.get("sha256"))
            if row.get("sha256") and rx.search(item) and key not in seen:
                seen.add(key)
                out.append({"kind": f"custody: {row.get('action') or 'event'}", "host": h,
                            "path": os.path.join("evidence", item), "captured_at": row.get("utc"),
                            "sha256": row.get("sha256")})
    return out


def _custody(cdir):
    rows = []
    try:
        with open(os.path.join(cdir, "evidence", "custody.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict):
                    rows.append(r)
    except OSError:
        pass
    return rows


# --------------------------------------------------------------------------- subject selection
def _refusals(cdir, assessment):
    """Raise Refusal when the assessment / intake does not support naming anyone at all."""
    if not isinstance(assessment, dict) or not assessment:
        raise Refusal("no assessment.json in the case — a notice is never drafted without an "
                      "assessment; run the assessment first")
    level = str(assessment.get("attribution_level") or "").lower()
    if level in [str(x).lower() for x in (_REF.get("refuse_attribution_levels") or [])] or not level:
        raise Refusal(f"attribution_level is '{level or 'missing'}' — the evidence does not support "
                      f"naming an owner, so no notice is drafted")
    pv = str(assessment.get("premise_verdict") or "").lower()
    if pv in [str(x).lower() for x in (_REF.get("refuse_premise_verdicts") or [])]:
        raise Refusal(f"premise_verdict is '{pv}' — the run's own collection does not support the "
                      f"claim it was given, so it is not turned into a notice")
    sc = _load_json(os.path.join(cdir, "scope.json"), {}) or {}
    tc = str(sc.get("target_class") or "").lower() if isinstance(sc, dict) else ""
    if tc and tc in [str(x).lower() for x in (_REF.get("refuse_target_classes") or [])]:
        raise Refusal(f"the case intake is '{tc}' — a legitimacy check, not an accusation; no abuse "
                      f"notice is drafted from it")
    need = str((_REF.get("policy") or {}).get("min_confidence") or "high").lower()
    if _conf_rank(need) < 0:
        raise Refusal(f"policy.min_confidence '{need}' is not on the confidence_order scale — the "
                      f"threshold is unknown, so nothing passes it")
    conf = str(assessment.get("confidence") or "").lower()
    if _conf_rank(conf) < _conf_rank(need):
        raise Refusal(f"assessment confidence is '{conf or 'missing'}', below the '{need}' a notice "
                      f"requires (notice_templates.json policy.min_confidence)")


def select_subjects(cdir):
    """Subject selection under the attribution rails. Returns {assessment, seed, owner, victims,
    excluded[{host, reason}], hidden{host}, raws} or raises Refusal.

      * the seed is admitted only as a member of assessment.json `cluster`;
      * only the clusters.json component holding the seed is used;
      * inside it, a host is owner-linked through a binding only when ITS OWN relation to the
        indicator grades owner (rels_by_domain / its KB edges — never the merged `rels`) and is not
        a previous owner's registration; owner subjects are the hosts joined to the seed by such
        bindings. The seed needs no such link: it is the reported site, so a one-host case
        drafts notices for the seed alone;
      * kit siblings, neighbours, mentions and related hosts never become subjects; victims of a
        compromised-site case get a compromise notice only."""
    assessment = _load_json(os.path.join(cdir, "assessment.json"))
    _refusals(cdir, assessment)
    clusters = _load_json(os.path.join(cdir, "clusters.json"), {}) or {}
    raws = _raw_index(cdir)
    seed = _resolve_seed(cdir, raws)
    tiers = _tier_exclusions(assessment, clusters)
    members = []
    for m in assessment.get("cluster") or []:
        d = _host(m.get("domain") if isinstance(m, dict) else m)
        if d and d not in members:
            members.append(d)
    if not seed or seed not in members:
        raise Refusal(f"the seed ({seed or 'unresolved'}) is not a member of the assessment's cluster "
                      f"— the assessment does not support naming it")
    _victim_case, victims = _victims(cdir, seed)

    excluded, seen = [], set()

    def exclude(h, why):
        if h not in seen:
            seen.add(h)
            excluded.append({"host": h, "reason": why})

    nodes, victim_subj = [], []
    for h in members:
        why = tiers.get(h) or tiers.get(_registrable(h))
        if why:
            exclude(h, why)
        elif h in victims or _registrable(h) in victims:
            victim_subj.append(h)
        else:
            nodes.append(h)

    owner = []
    if seed not in nodes:            # a compromised seed anchors no owner group
        for h in nodes:
            exclude(h, "the seed is a compromised (victim) site — owner-side notices need a case "
                       "seeded on the operator's own infrastructure")
    else:
        comp = next((c for c in (clusters.get("clusters") or []) if isinstance(c, dict)
                     and seed in {_host(d) for d in (c.get("domains") or [])}), None)
        cdoms = {_host(d) for d in (comp or {}).get("domains") or []}
        for h in nodes:
            if h == seed:
                continue
            if comp is None:
                exclude(h, "the seed is in no clusters.json component — no stored owner link to grade")
            elif h not in cdoms:
                exclude(h, "in another clusters.json component than the seed — not linked to it")
        graph = [h for h in nodes if h == seed or h in cdoms]
        bindings = [b for b in (comp or {}).get("binding_indicators") or [] if isinstance(b, dict)]
        kb_rels = (_kb_own_rels({_binding_value(b) for b in bindings})
                   if any(not isinstance(b.get("rels_by_domain"), dict) for b in bindings) else None)
        notes = {h: {"owner": [], "prior": [], "weak": [], "unknown": []} for h in graph}
        parent = {h: h for h in graph}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for b in bindings:
            label = str(b.get("display") or b.get("indicator"))
            holders = []
            for d in b.get("domains_in_cluster") or []:
                h = _host(d)
                if h not in notes:
                    continue
                rels = _own_rels(b, h, kb_rels)
                if rels is None:
                    notes[h]["unknown"].append(label)
                    continue
                cls = _rels_class(rels, b)
                rung = selector_types.rung_for(cls)
                if rung != "owner":
                    notes[h]["weak"].append(f"{label} (own: {', '.join(rels) or 'none'} → "
                                            f"{cls or 'unmapped'} → {rung})")
                elif _prior_era_only(cls, b, _whois_for(cdir, h, raws)[0]):
                    notes[h]["prior"].append(f"{label} ({cls})")
                else:
                    notes[h]["owner"].append(label)
                    holders.append(h)
            for h in holders[1:]:
                parent[find(h)] = find(holders[0])
        group = [h for h in graph if find(h) == find(seed)]
        owner = group                    # always holds the seed
        for h in graph:
            if h in owner:
                continue
            n = notes[h]
            if n["owner"]:
                why = ("owner-linked only to hosts outside the seed's owner group: "
                       + "; ".join(n["owner"]))
            elif n["prior"]:
                why = ("previous-owner registration era — its registrant binding predates the current "
                       "registration: " + "; ".join(n["prior"]))
            elif n["weak"]:
                why = "bound only by kit/neighbour-class relation(s) of its own: " + "; ".join(n["weak"])
            elif n["unknown"]:
                why = ("its own relation to the binding indicator(s) cannot be established (no "
                       "rels_by_domain in clusters.json, no knowledge-base edge): " + "; ".join(n["unknown"]))
            else:
                why = "no binding indicator in the seed's cluster binds it"
            exclude(h, why)
    subjects = owner + victim_subj
    if not subjects:
        raise Refusal("no notice subject survives the attribution rails — "
                      + "; ".join(f"{e['host']}: {e['reason']}" for e in excluded))
    hidden = ({h for h in tiers if h} | seen) - set(subjects)
    return {"assessment": assessment, "seed": seed, "owner": owner, "victims": victim_subj,
            "excluded": excluded, "hidden": hidden, "raws": raws}


def _victims(cdir, seed):
    """(is_victim_case, {host/apex}) — the compromised-site hosts whose owner is a VICTIM."""
    sc = _load_json(os.path.join(cdir, "scope.json"), {}) or {}
    victim_case = isinstance(sc, dict) and sc.get("target_class") == "victim_host"
    out = set()
    if victim_case and seed:
        out |= {seed, _registrable(seed)}
    vp = _load_json(os.path.join(cdir, "victim_profile.json"), {}) or {}
    for v in (vp.get("victims") or []) if isinstance(vp, dict) else []:
        name = _host(v.get("apex") or v.get("domain") or "") if isinstance(v, dict) else _host(v)
        if name:
            out.add(name)
    return victim_case, out


# --------------------------------------------------------------------------- recipients
def _registrar_groups(cdir, hosts, raws):
    """One registrar notice per registrar. Contact: the RDAP abuse entity (registrar_abuse_email)
    when any subject's record carries one, else the WHOIS registrar contact e-mail — and the entry
    says which it used. Existing sidecars predate the abuse field, hence the fallback."""
    groups = {}
    for h in hosts:
        w, _wpath, at = _whois_for(cdir, h, raws)
        name = str(w.get("registrar") or "").strip()
        if not name:
            continue
        g = groups.setdefault(name.lower(), {"recipient": name, "subjects": [], "contact": None,
                                             "contact_source": None, "contact_collected_at": None,
                                             "_abuse": [], "_contact": []})
        g["subjects"].append(h)
        if w.get("registrar_abuse_email"):
            g["_abuse"].append((w["registrar_abuse_email"], at))
        if w.get("registrar_contact_email"):
            g["_contact"].append((w["registrar_contact_email"], at))
    for g in groups.values():
        abuse, contact = g.pop("_abuse"), g.pop("_contact")
        if abuse:
            g.update(contact=abuse[0][0], contact_collected_at=abuse[0][1],
                     contact_source="RDAP abuse entity (registrar_abuse_email)")
        elif contact:
            g.update(contact=contact[0][0], contact_collected_at=contact[0][1],
                     contact_source="registrar contact e-mail (registrar_contact_email) — "
                                    "no RDAP abuse entity stored")
        else:
            g["contact_source"] = "none stored — use the registrar's published abuse page"
    return list(groups.values())


def _origin_rows(obj):
    """CURRENT origin rows of a domain raw, through wp_origin_history.host_origins() (the one era
    authority): status `origin` and era `current` only — an undated, recent, historical or previous
    owner's address never receives a host notice. No origin-history module → no rows."""
    if _oh is None:
        return []
    try:
        _h, _reg, rows = _oh.host_origins(obj)
    except Exception:  # noqa: BLE001 — an unreadable block names no host
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("ip")
            and r.get("status") == "origin" and r.get("era") == "current"]


def _host_groups(hosts, raws):
    groups = {}
    for h in hosts:
        _, obj = raws.get(h, (None, {}))
        lr = _domain_live(obj)
        for r in _origin_rows(obj):
            ip = str(r["ip"])
            ip_path, ip_obj = raws.get(ip, (None, {}))
            info = ((ip_obj.get("artifacts") or {}).get("ip_intel") or {}).get("ipinfo") or {}
            abuse = info.get("abuse") or ((lr.get("ipinfo") or {}).get(ip) or {}).get("abuse") or {}
            at = (ip_obj.get("meta") or {}).get("collected_at") if ip_path else \
                (obj.get("meta") or {}).get("collected_at")
            name = (abuse.get("name") or info.get("org_name") or r.get("org") or r.get("asn")
                    or f"network of {ip}")
            key = str(abuse.get("email") or name).lower()
            g = groups.setdefault(key, {"recipient": str(name), "subjects": [], "contact": None,
                                        "contact_source": None, "contact_collected_at": None})
            line = f"{h} — {ip}"
            if line not in g["subjects"]:
                g["subjects"].append(line)
            if not g["contact"] and abuse.get("email"):
                g.update(contact=abuse["email"], contact_collected_at=at,
                         contact_source="abuse contact in the stored IP record (ip_intel abuse block)")
    for g in groups.values():
        if not g["contact"]:
            g["contact_source"] = "none stored — use the network's RIR abuse contact"
    return list(groups.values())


def _cdn_groups(hosts, raws):
    pages = {str(k).lower(): v for k, v in (_REF.get("cdn_abuse_contacts") or {}).items()}
    groups = {}
    for h in hosts:
        _, obj = raws.get(h, (None, {}))
        dns = _domain_live(obj).get("dns") or {}
        for c in dns.get("ip_classification") or []:
            if not isinstance(c, dict) or c.get("cdn") is not True or not c.get("provider"):
                continue
            prov = str(c["provider"])
            g = groups.setdefault(prov.lower(), {
                "recipient": prov, "subjects": [], "contact": pages.get(prov.lower()),
                "contact_source": ("notice_templates.json cdn_abuse_contacts" if pages.get(prov.lower())
                                   else "none stored — use the provider's abuse page"),
                "contact_collected_at": (obj.get("meta") or {}).get("collected_at")})
            if h not in g["subjects"]:
                g["subjects"].append(h)
    return list(groups.values())


def _platform_groups(hosts, raws):
    pages = _REF.get("platform_report_pages") or {}
    groups = {}

    def add(net, url, h, at):
        g = groups.setdefault(net, {"recipient": net, "subjects": [], "items": [], "contact": None,
                                    "contact_source": "no contact — report through the platform page",
                                    "contact_collected_at": at,
                                    "report_page": pages.get(net) or "the platform's own reporting page"})
        if h not in g["subjects"]:
            g["subjects"].append(h)
        item = f"- [ ] {url} (linked from {h})"
        if item not in g["items"]:
            g["items"].append(item)

    for h in hosts:
        _, obj = raws.get(h, (None, {}))
        art = obj.get("artifacts") or {}
        at = (obj.get("meta") or {}).get("collected_at")
        for net, urls in (art.get("socials") or {}).items():
            for u in (urls if isinstance(urls, list) else [urls]):
                if u:
                    add(str(net).lower(), str(u), h, at)
        for t in art.get("telegram") or []:
            u = t.get("url") if isinstance(t, dict) else t
            if u:
                add("telegram", str(u), h, at)
        apps = art.get("app_downloads") or {}
        for pkg in apps.get("android_packages") or []:
            add("google_play", f"https://play.google.com/store/apps/details?id={pkg}", h, at)
        for aid in apps.get("ios_app_ids") or []:
            add("app_store", f"https://apps.apple.com/app/id{str(aid).removeprefix('id')}", h, at)
    return list(groups.values())


def _bank_groups(hosts, raws):
    """Only when the raws carry artifacts.payment_accounts; otherwise [] (no error)."""
    groups = {}
    for h in hosts:
        _, obj = raws.get(h, (None, {}))
        for acc in (obj.get("artifacts") or {}).get("payment_accounts") or []:
            if isinstance(acc, dict):
                # an account whose bank is not in payment_rails.json is still addressed to ONE
                # institution: the rail's bank identifier, never just the rail (many banks share it)
                unnamed = (f"{acc.get('rail')} bank id {acc.get('bank_id')}"
                           if acc.get("rail") and acc.get("bank_id") else acc.get("rail"))
                bank = (acc.get("bank") or acc.get("bank_name") or acc.get("institution")
                        or unnamed or "unidentified institution")
                number = acc.get("account") or acc.get("account_number") or acc.get("iban") or "?"
                line = f"{number} ({bank})"
            else:
                bank, line = "unidentified institution", str(acc)
            g = groups.setdefault(str(bank).lower(), {
                "recipient": str(bank), "subjects": [], "accounts": [], "contact": None,
                "contact_source": "none stored — use the institution's fraud desk",
                "contact_collected_at": (obj.get("meta") or {}).get("collected_at")})
            if h not in g["subjects"]:
                g["subjects"].append(h)
            if f"- {line} — shown on {h}" not in g["accounts"]:
                g["accounts"].append(f"- {line} — shown on {h}")
    return list(groups.values())


def _compromise_groups(cdir, hosts, raws):
    out = []
    for h in hosts:
        w, _, at = _whois_for(cdir, h, raws)
        contact = next((v for v in owner_values(w, "email")
                        if v and "privacy" not in v.lower() and not v.lower().startswith("abuse@")
                        and not _is_privacy(v)), None)
        out.append({"recipient": f"owner of {_registrable(h)}", "subjects": [h], "contact": contact,
                    "contact_source": ("current-era WHOIS registrant e-mail" if contact
                                       else "none stored — use the site's own contact page"),
                    "contact_collected_at": at if contact else None})
    return out


def _ioc_bundle(cdir):
    pats = ("*.stix.json", "*ioc*.csv", "*ioc*.txt", "*ioc*.jsonl", "*IOC*")
    found = set()
    for sub in ("", "report"):
        for pat in pats:
            found.update(glob.glob(os.path.join(cdir, sub, pat)))
    return sorted(os.path.relpath(p, cdir) for p in found if os.path.isfile(p))


def _timeline(cdir, subjects, raws):
    ev = []
    for h in subjects:
        w, _, _ = _whois_for(cdir, h, raws)
        if _day(w.get("created")):
            ev.append((_day(w["created"]), f"{h} registered (current registration)"))
        _, obj = raws.get(h, (None, {}))
        at = (obj.get("meta") or {}).get("collected_at")
        if at:
            ev.append((str(at), f"{h} collected"))
        for r in _origin_rows(obj):
            if r.get("first_seen"):
                ev.append((str(r["first_seen"]), f"{h} first seen on {r['ip']}"))
    return [f"- {d} — {t}" for d, t in sorted(set(ev))]


# --------------------------------------------------------------------------- rendering
class _SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _template(cls):
    tpl = (_REF.get("templates") or {}).get(cls)
    if not (isinstance(tpl, dict) and tpl.get("title") and tpl.get("body")):
        tpl = _FALLBACK["templates"][cls]
    return tpl


_HIDDEN = "(a host outside this notice)"


def _mask_hidden(text, hidden, keep):
    """Replace every hidden host AND its subdomains (www.<host>, a.b.<host>) — kit siblings,
    neighbours, mentions, related hosts and every excluded candidate. A token that is itself one of
    this notice's subjects is kept. The lookarounds stop a match inside a longer name
    (`site-b.example` never matches `b.example`, `x.example.org` never matches `x.example`)."""
    keep = {str(k).lower() for k in keep if k}
    for h in sorted({str(x).lower() for x in hidden if x}, key=len, reverse=True):
        rx = re.compile(r"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*" + re.escape(h) + r"(?![a-z0-9-]|\.[a-z0-9])",
                        re.I)
        text = rx.sub(lambda m: m.group(0) if m.group(0).lower() in keep else _HIDDEN, text)
    return text


def _render(cls, fields, notice, keep, hidden):
    tpl = _template(cls)
    vals = _SafeDict(fields)
    title = str(tpl["title"]).format_map(vals)
    head = ["| Field | Value |", "|:--|:--|",
            f"| Recipient | {notice['recipient']} |",
            f"| Contact | {notice['contact'] or 'none stored'} |",
            f"| Contact source | {notice['contact_source']} |",
            f"| Contact collected | {notice['contact_collected_at'] or 'unknown'} |",
            "| Status | drafted — nothing has been sent |"]
    text = f"# {title}\n\n" + "\n".join(head) + "\n\n" + str(tpl["body"]).format_map(vals) + "\n"
    # no host the rails kept out appears in a notice someone outside the team reads; the case
    # index keeps the names and reasons
    text = _mask_hidden(text, hidden, fields.get("_hosts") or [])
    return _scrub(text, keep, fields.get("_hosts") or [])


def _scrub(text, keep, hosts):
    """house_report.scrub() + its third-party masking, with the case's own subjects and the
    recipients' published contacts kept in clear. No scrub available -> refuse, never emit raw."""
    try:
        import house_report as hr
    except Exception as e:  # noqa: BLE001
        raise Refusal(f"report scrub unavailable ({e}) — a notice is never written unscrubbed") from e
    saved = (set(hr._KEEP), set(hr._HOSTS), hr._CURRENT_CASE)
    try:
        hr._KEEP = set(saved[0]) | {str(k).lower() for k in keep if k}
        hr._HOSTS = set(hosts)
        return hr.scrub(text) + "\n"
    finally:
        hr._KEEP, hr._HOSTS, hr._CURRENT_CASE = saved


def _bullets(items, empty="- none recorded"):
    return "\n".join(items) if items else empty


def _ev_lines(ev):
    return [f"- {e['kind']} for {e['host']}: captured {e.get('captured_at') or 'unknown'}, "
            f"SHA-256 {e.get('sha256') or 'unavailable'} (`{os.path.basename(e['path'])}`)" for e in ev]


# --------------------------------------------------------------------------- driver
def _write_index(idx_path, index):
    tmp = idx_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, idx_path)


def withdraw(cdir, reason):
    """A refusal withdraws every UNSENT draft: marked `withdrawn` with the reason and time, so no
    report links (and no analyst sends) a notice the current assessment no longer supports. A SENT
    notice is a record and is left byte-identical. Returns the number withdrawn."""
    idx_path = os.path.join(cdir, "notices", "index.json")
    index = _load_json(idx_path)
    if not isinstance(index, dict):
        return 0
    n, at = 0, _now()
    for e in index.get("notices") or []:
        if isinstance(e, dict) and e.get("status") == "drafted":
            e.update(status="withdrawn", withdrawn_at=at, withdrawn_reason=str(reason))
            n += 1
    if n:
        _write_index(idx_path, index)
    return n


def draft(case):
    """Draft every notice the stored case supports. Returns the written index dict; raises Refusal
    (after withdrawing every unsent earlier draft)."""
    cdir = case_dir(case)
    if not os.path.isdir(cdir):
        raise Refusal(f"no such case: {case}")
    try:
        _scrub("", [], [])            # no scrub, no notice: probe before anything is written
        sel = select_subjects(cdir)
    except Refusal as e:
        withdraw(cdir, e)
        raise
    return _draft(cdir, sel)


def _draft(cdir, sel):
    case_id = os.path.basename(os.path.normpath(cdir))
    assessment, seed, raws = sel["assessment"], sel["seed"], sel["raws"]
    owner_subj, victim_subj, excluded = sel["owner"], sel["victims"], sel["excluded"]
    subjects = owner_subj + victim_subj
    custody = _custody(cdir)

    plan = []                     # (class, group)
    if owner_subj:
        plan += [("registrar", g) for g in _registrar_groups(cdir, owner_subj, raws)]
        plan += [("host", g) for g in _host_groups(owner_subj, raws)]
        plan += [("cdn", g) for g in _cdn_groups(owner_subj, raws)]
        plan += [("platform", g) for g in _platform_groups(owner_subj, raws)]
        plan += [("bank", g) for g in _bank_groups(owner_subj, raws)]
        plan.append(("referral", {"recipient": "law-enforcement referral (analyst selects the agency)",
                                  "slug": case_id,
                                  "subjects": list(owner_subj), "contact": None,
                                  "contact_source": "analyst-selected — not in stored data",
                                  "contact_collected_at": None}))
    plan += [("compromise", g) for g in _compromise_groups(cdir, victim_subj, raws)]

    ndir = os.path.join(cdir, "notices")
    os.makedirs(ndir, exist_ok=True)
    idx_path = os.path.join(ndir, "index.json")
    old = _load_json(idx_path, {}) or {}
    old_notes = [n for n in (old.get("notices") or []) if isinstance(n, dict) and n.get("file")]
    # a SENT notice is a record: its file and index entry stay byte-identical, and a new draft for
    # the same recipient takes a new name
    sent = [n for n in old_notes if n.get("status") == "sent"]
    used = {n["file"] for n in sent}

    common = {"case": case_id, "attribution_level": assessment.get("attribution_level"),
              "confidence": assessment.get("confidence")}
    bluf = " ".join(str(assessment.get("bluf") or "—").split())
    notices = []
    for cls, g in plan:
        hosts = list(dict.fromkeys(s.split(" — ", 1)[0] for s in g["subjects"]))
        ev = _evidence_for(cdir, hosts, raws, custody)
        fields = dict(common, recipient=g["recipient"], _hosts=hosts,
                      # analyst prose goes to the referral pack only, never to a third party
                      bluf=bluf if cls == "referral" else "",
                      subjects=_bullets([f"- {s}" for s in g["subjects"]]),
                      evidence=_bullets(_ev_lines(ev)),
                      report_page=g.get("report_page") or "",
                      checklist=_bullets(g.get("items") or []),
                      accounts=_bullets(g.get("accounts") or []),
                      timeline=_bullets(_timeline(cdir, hosts, raws)),
                      ioc_bundle=_bullets([f"- `{os.path.basename(p)}`" for p in _ioc_bundle(cdir)],
                                          empty="- not built yet (run the IOC export)"),
                      excluded=(f"{len(excluded)} host(s) named in the assessment are left out of this "
                                f"pack on purpose (not owner-linked, or a previous owner's registration)."
                                if excluded else "No host was left out."))
        base = f"{cls}-{_slug(g.get('slug') or g['recipient'])}"
        name, n = f"{base}.md", 2
        while name in used:
            name, n = f"{base}-{n}.md", n + 1
        used.add(name)
        entry = {"file": name, "class": cls, "recipient": g["recipient"], "contact": g["contact"],
                 "contact_source": g["contact_source"],
                 "contact_collected_at": g["contact_collected_at"],
                 "subjects": hosts, "excluded": excluded,
                 "evidence_refs": [{k: e[k] for k in ("path", "captured_at", "sha256")} for e in ev],
                 "status": "drafted"}
        if cls == "referral":
            entry["ioc_bundle"] = _ioc_bundle(cdir)
        keep = [g["contact"]] + hosts
        with open(os.path.join(ndir, name), "w", encoding="utf-8") as fh:
            fh.write(_render(cls, fields, entry, keep, sel["hidden"]))
        notices.append(entry)
    # an unsent earlier draft this run no longer produces is removed (its subject may have been
    # excluded since); sent ones were kept above
    for prev in old_notes:
        if prev.get("status") != "sent" and prev["file"] not in used:
            try:
                os.remove(os.path.join(ndir, os.path.basename(prev["file"])))
            except OSError:
                pass
    index = {"case": case_id, "generated": _now(),
             "assessment": {"attribution_level": assessment.get("attribution_level"),
                            "confidence": assessment.get("confidence")},
             "seed": seed, "subjects": subjects, "victim_subjects": victim_subj,
             "excluded": excluded, "notices": sent + notices,
             "note": "Drafts only — nothing was sent. Mark a notice sent with `intel.py action-log "
                     "<case> --notice <file> --sent-at YYYY-MM-DD --ref <id>`."}
    _write_index(idx_path, index)
    return index


def load_index(case):
    return _load_json(os.path.join(case_dir(case), "notices", "index.json"), {}) or {}


def update_notice(case, notice, **fields):
    """Set fields on one index entry (matched by file name). Returns the entry; ValueError if absent
    or withdrawn (a withdrawn draft is not supported by the current assessment)."""
    idx_path = os.path.join(case_dir(case), "notices", "index.json")
    index = _load_json(idx_path, {}) or {}
    want = os.path.basename(str(notice or ""))
    entry = next((n for n in index.get("notices") or [] if isinstance(n, dict) and n.get("file") == want), None)
    if entry is None:
        raise ValueError(f"no notice '{want}' in notices/index.json — draft notices first "
                         f"(intel.py notice <case>)")
    if entry.get("status") == "withdrawn":
        raise ValueError(f"notice '{want}' was withdrawn ({entry.get('withdrawn_reason')}) — it is not "
                         f"supported by the current assessment")
    entry.update({k: v for k, v in fields.items() if v is not None})
    _write_index(idx_path, index)
    return entry


def run(case):
    """CLI body: print the drafted notices, or the refusal reason. Returns the exit code."""
    try:
        index = draft(case)
    except Refusal as e:
        print(f"notice: REFUSED — {e} (every unsent earlier draft is withdrawn)", file=sys.stderr)
        return 2
    drafted = [n for n in index["notices"] if n.get("status") == "drafted"]
    print(f"notice: drafted {len(drafted)} notice(s) for '{index['case']}' — nothing was sent")
    for n in drafted:
        print(f"   {n['class']:<10} {n['file']:<48} contact: {n['contact'] or 'none stored'} "
              f"({n['contact_source']})")
    for n in index["notices"]:
        if n.get("status") == "sent":
            print(f"   sent       {n['file']} (kept as sent on {n.get('sent_at')})")
    for e in index["excluded"]:
        print(f"   excluded   {e['host']}: {e['reason']}")
    print(f"   index: notices/index.json   (mark one sent: intel.py action-log {index['case']} "
          f"--notice <file> --sent-at YYYY-MM-DD --ref <id>)")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Draft action notices from a stored case (no network, nothing sent).")
    ap.add_argument("case")
    a = ap.parse_args(argv)
    return run(a.case)


if __name__ == "__main__":
    sys.exit(main())
