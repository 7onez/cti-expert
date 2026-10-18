#!/usr/bin/env python3
"""wp_exhaust — has this seed actually been WORKED, or only triaged?

THE FAILURE THIS EXISTS FOR
---------------------------
A collection run is a first fetch plus whatever enrichment happens to be wired on by default.
Everything else — the leak corpus, passive SSL, Censys, the advertising layer, the document
metadata, the lookalike hunt — is behind an opt-in flag, and opt-in flags do not get typed once
the first result looks interesting. Measured across the stored collections in this repo when
this module was written, `intelx` appeared in `enriched_with` exactly ONCE.

The consequence is not that a case is thin; it is that the case cannot tell how thin it is. A
correlation pass over a triage-depth collection is scrupulous about every artifact it has and
silent about the search space it never entered, so "no further links found" reads as a finding
when it is really a statement about which flags were passed. That is the same error the keyless
capability banner exists to prevent, one level up: absence of COLLECTION reported as absence of
evidence.

WHAT IT DOES
------------
Reads a stored pivot JSON — no network, no credits, no key — and works out which evidence layers
ran, from what they leave behind (`enriched_with` entries, meta keys, top-level blocks, pivot
kinds). Then it names each layer that did NOT run, what its absence removes from the case, and
the exact command that closes it, cheapest first. It reports; it never collects and never spends.

    exhausted   every layer in `seed_policy.required_layers` has run
    triage      at least one has not — and the run says so, loudly, at the end of a collection
    failed      the collector itself crashed / timed out for this host — re-run it

EXECUTION OUTCOMES
------------------
Post-hoc evidence cannot tell "ran, crashed" from "never asked": both leave nothing behind. So
the code that RUNS a collection (collect_core.collect_host) records, per host and per layer, an
outcome {status, reason, elapsed_s, at} in cases/<case>/collection_outcomes.json:

    ran | empty | error | timed_out | skipped_no_key | skipped_policy

`error` / `timed_out` are FAILED and re-runnable — never read as collected-empty. A
`skipped_policy` layer (free-only, no_spend, hostile, smoke, onion) was withheld on purpose; a
`skipped_no_key` one is closed by a credential. A stored result's own `meta.capability` supplies
the key/policy view for collections that predate the outcome file.

CLI:
  wp_exhaust.py <case>                     # every host collected in the case
  wp_exhaust.py <case> <host>              # one host
  wp_exhaust.py --file cases/x/raw/h.json  # a stored result directly
  wp_exhaust.py <case> --json
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import sys
import tempfile
import threading

from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

#: Minimal embedded default — deliberately a SUBSET (see tests/test_references.py). On the stub
#: the checklist knows four layers instead of seventeen, so it reports FEWER gaps: a degraded run
#: under-claims what is missing rather than inventing gaps, which is the safe direction for a
#: module whose whole job is to make people collect more.
_EXHAUST_FALLBACK = {
    "layers": {
        "fetch": {"label": "page fetch / DOM", "cost": "free", "applies_to": "any",
                  "detect": {"fetched": True}, "evidence": "the page the operator served",
                  "without_it": "no page was retrieved", "how": "pivot_extract <url>"},
        "whois": {"label": "WHOIS / RDAP", "cost": "free", "applies_to": "domain",
                  "detect": {"artifact": "whois"}, "evidence": "registration timeline",
                  "without_it": "no registration timeline", "how": "automatic",
                  "clearnet_only": True},
        "capture": {"label": "raw evidence capture", "cost": "free", "applies_to": "any",
                    "detect": {"meta": "capture"}, "evidence": "the bytes served",
                    "without_it": "nothing to re-check a finding against",
                    "how": "pivot_extract --case <id>"},
        "intelx": {"label": "Intelligence X", "cost": "metered", "applies_to": "any",
                   "detect": {"enriched_with": "intelx"},
                   "evidence": "leaks, stealer logs, pastes, darknet",
                   "without_it": "the corpus outside the live internet was never queried",
                   "how": "pivot_extract --intelx", "key_env": ["INTELX_KEY"]},
    },
    "seed_policy": {"required_layers": ["fetch", "whois", "capture", "intelx"],
                    "min_layers_ran": 3},
    "reporting": {
        "triage_note": "SEED NOT EXHAUSTED — this was a TRIAGE; the layers below never ran.",
        "exhausted_note": "Seed exhausted: every required evidence layer has run.",
        "absence_note": "A layer that did not run produces no result. That is absence of "
                        "COLLECTION, not absence of evidence.",
        "keyless_note": "Some gaps are closed by a credential rather than a command.",
        "failed_note": "COLLECTION FAILED — the collector crashed or timed out; re-run it. "
                       "This is not a collected-empty host.",
    },
    # Execution-outcome policy. `rerunnable` statuses are FAILED, never collected-empty;
    # `not_applicable_reasons` are policy skips that remove a layer from the seed for good (an
    # onion has no WHOIS) rather than leaving it as a gap; `flag_policy` maps a collector flag to
    # the layers it withholds. The stub keeps the WHOIS skip so a smoke run still says why.
    "outcomes": {"rerunnable": ["error", "timed_out"],
                 "not_applicable_reasons": ["onion"],
                 "flag_policy": {"--no-whois": {"reason": "no_whois", "layers": ["whois"]}}},
}

_REFS = load_ref(ref_path(__file__, "exhaustion.json"), _EXHAUST_FALLBACK)

LAYERS = _REFS["layers"]
SEED_POLICY = _REFS["seed_policy"]
REPORTING = _REFS["reporting"]
OUTCOMES = _REFS["outcomes"]

#: the execution-outcome vocabulary collect_core / enrichment_run record (schema, not a tunable)
OUTCOME_STATUSES = ("ran", "empty", "error", "timed_out", "skipped_no_key", "skipped_policy")
#: statuses that mean "the layer was attempted and FAILED" — re-run it; never read as empty
RERUNNABLE = frozenset(OUTCOMES.get("rerunnable") or ("error", "timed_out"))
#: policy-skip reasons that make a layer not applicable to the seed instead of a gap
NOT_APPLICABLE_REASONS = frozenset(OUTCOMES.get("not_applicable_reasons") or ())
FLAG_POLICY = OUTCOMES.get("flag_policy") or {}
OUTCOMES_FILE = "collection_outcomes.json"
_OUTCOMES_LOCK = threading.Lock()

#: cheapest first — a free gap has no excuse, a metered one is a decision
COST_ORDER = {"free": 0, "free_account": 1, "keyed": 2, "metered": 3}


# --------------------------------------------------------------------------- detection
def _has_file_hash(result: dict) -> bool:
    return any(str(p.get("kind", "")).endswith(("sha256", "signing_sha256"))
               for p in (result.get("pivots") or []))


def _applies(spec: dict, result: dict) -> bool:
    scope = str(spec.get("applies_to") or "any")
    if scope == "any":
        return True
    meta = result.get("meta") or {}
    host = str(meta.get("host") or "")
    is_ip = bool(host) and all(c in "0123456789.:abcdefABCDEF" for c in host)
    if scope == "domain":
        return not is_ip
    if scope == "ip":
        return is_ip
    if scope == "if_file_hash":
        return _has_file_hash(result)
    return True


def layer_ran(spec: dict, result: dict) -> bool:
    """Did this layer run, judged only from what it leaves behind in a stored result?

    Every test is positive evidence of a RUN. A layer that ran and found nothing still leaves its
    source name in `enriched_with`, which is exactly the distinction this module is defending:
    "asked, nothing there" and "never asked" must not collapse into the same silence."""
    det = spec.get("detect") or {}
    meta = result.get("meta") or {}
    fetched = bool(meta.get("fetched_with")) and not meta.get("live_error")
    if "enriched_with" in det:
        want = str(det["enriched_with"]).lower()
        srcs = [str(s).lower() for s in (meta.get("enriched_with") or [])]
        # a source may be a '+'-joined provenance token (whoisxml+rdap, whoisxml+chongluadao); match a
        # component so a compound source still satisfies the layer it belongs to
        parts = {p for s in srcs for p in s.split("+")}
        if want in parts or any(s == want or s.startswith(want + "-") for s in srcs):
            return True
    if "artifact" in det and (result.get("artifacts") or {}).get(det["artifact"]) not in (None, "", [], {}):
        return True
    if "meta" in det and meta.get(det["meta"]) not in (None, "", [], {}):
        return True
    if "meta_any" in det and any(meta.get(k) not in (None, "", [], {}) for k in det["meta_any"]):
        return True
    if "result" in det and result.get(det["result"]) not in (None, "", [], {}):
        return True
    if "archives" in det and (result.get("archives") or {}).get(det["archives"]):
        return True
    if "pivot_prefix" in det:
        pre = str(det["pivot_prefix"])
        if any(str(p.get("kind", "")).startswith(pre) for p in (result.get("pivots") or [])):
            return True
    if det.get("fetched") and fetched:
        return True
    if det.get("or_fetched") and fetched:
        return True
    return False


# --------------------------------------------------------------------------- execution outcomes
#: v3 (56 base32) and v2 (16 base32) onion services, optionally with a subdomain label. Same
#: pattern as selector_types._ONION_RE / intel._ONION_RE (tests assert parity).
_ONION_HOST_RE = re.compile(r'^(?:[a-z0-9-]+\.)*(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion$', re.I)


def is_onion_host(host: str) -> bool:
    return bool(_ONION_HOST_RE.match(str(host or "").strip().rstrip(".")))


def outcome(status: str, reason: str = "", elapsed_s=None) -> dict:
    """One execution-outcome row. `status` must be in OUTCOME_STATUSES (a typo is a bug, so it
    raises — callers pass literals)."""
    if status not in OUTCOME_STATUSES:
        raise ValueError(f"unknown outcome status {status!r}")
    return {"status": status, "reason": " ".join(str(reason or "").split())[:300],
            "elapsed_s": (round(float(elapsed_s), 2) if elapsed_s is not None else None),
            "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def load_outcomes(case_dir: str) -> dict:
    """{host: {"collect": row, "layers": {layer: row}}} from cases/<case>/collection_outcomes.json;
    {} when absent or unreadable (a missing file means "no outcomes recorded", never "all ran")."""
    try:
        with open(os.path.join(case_dir, OUTCOMES_FILE), encoding="utf-8") as fh:
            hosts = (json.load(fh) or {}).get("hosts")
        return hosts if isinstance(hosts, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def record_outcomes(case_dir: str, host: str, collect: dict = None, layers: dict = None,
                    stages: dict = None) -> None:
    """Merge one host's outcomes into the case file (thread-safe within a process, atomic on disk).
    A `layers` dict REPLACES the host's previous layer rows — it is the full view of one run;
    `stages` (pipeline stages outside the layer checklist, e.g. subenum) merge per stage."""
    if not host:
        return
    with _OUTCOMES_LOCK:
        hosts = load_outcomes(case_dir)
        row = hosts.get(host) if isinstance(hosts.get(host), dict) else {}
        if collect is not None:
            row["collect"] = collect
        if layers is not None:
            row["layers"] = dict(layers)
        if stages:
            row["stages"] = {**(row.get("stages") or {}), **stages}
        hosts[host] = row
        os.makedirs(case_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".outcomes-", suffix=".json", dir=case_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"hosts": hosts}, fh, indent=2, ensure_ascii=False, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, os.path.join(case_dir, OUTCOMES_FILE))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _cap_outcome(lid: str, spec: dict, cap) -> dict | None:
    """Key / spend posture from the result's own meta.capability (wp_capabilities)."""
    keys = [str(k) for k in (spec.get("key_env") or [])]
    if not keys or not isinstance(cap, dict):
        return None
    free_only_layers = (FLAG_POLICY.get("--free-only") or {}).get("layers") or []
    if cap.get("mode") == "free-only" and lid in free_only_layers:
        return outcome("skipped_policy", "free_only")
    missing = {str(k) for k in (cap.get("keys_missing") or [])}
    if keys and all(k in missing for k in keys):
        return outcome("skipped_no_key", "set " + " / ".join(keys))
    return None


def layer_outcomes(result, recorded: dict = None, flags=(), failure: dict = None) -> dict:
    """{layer: outcome-row} for one host. Order of precedence:

      1. positive evidence in the stored result            -> ran
      2. an .onion host and a clearnet-only layer          -> skipped_policy (onion)
      3. `failure` (the collector itself crashed/timed out) -> that status, every applicable layer
         (a fetch whose meta.live_error is set                -> error: attempted and failed)
      4. a recorded error/timed_out/skip row                -> kept (it is newer than any guess)
      5. a collector flag that withholds the layer          -> skipped_policy (flag_policy reason)
      6. meta.capability: free-only / key absent            -> skipped_policy / skipped_no_key
    A layer with none of these has no row: it simply was not requested (a plain gap)."""
    result = result if isinstance(result, dict) else {"meta": {}, "pivots": []}
    recorded = recorded if isinstance(recorded, dict) else {}
    meta = result.get("meta") or {}
    onion = is_onion_host(meta.get("host"))
    cap = meta.get("capability")
    flags = {str(f) for f in (flags or ())}
    out = {}
    for lid, spec in LAYERS.items():
        if not isinstance(spec, dict) or not _applies(spec, result):
            continue
        if layer_ran(spec, result):
            out[lid] = outcome("ran")
            continue
        if onion and spec.get("clearnet_only"):
            out[lid] = outcome("skipped_policy", "onion")
            continue
        if failure:
            out[lid] = dict(failure)
            continue
        if (spec.get("detect") or {}).get("fetched") and meta.get("live_error"):
            # the live fetch was ATTEMPTED and failed — a failure, not "nothing served"
            out[lid] = outcome("error", f"live fetch failed: {meta['live_error']}")
            continue
        prev = recorded.get(lid)
        if isinstance(prev, dict) and prev.get("status") in OUTCOME_STATUSES \
                and prev.get("status") not in ("ran", "empty"):
            out[lid] = prev
            continue
        held = next((p for f, p in FLAG_POLICY.items()
                     if f in flags and lid in ((p or {}).get("layers") or [])), None)
        if held:
            out[lid] = outcome("skipped_policy", held.get("reason") or "policy")
            continue
        cap_row = _cap_outcome(lid, spec, cap)
        if cap_row:
            out[lid] = cap_row
    return out


# --------------------------------------------------------------------------- assessment
def assess(result: dict, outcomes: dict = None) -> dict:
    """One stored collection -> {verdict, ran, gaps, failed, skipped, statement}. Pure; no network.

    `outcomes` is this host's row from collection_outcomes.json ({"collect", "layers"}); without
    it the key/policy view still comes from the result's own meta.capability."""
    rec = outcomes if isinstance(outcomes, dict) else {}
    collect = rec.get("collect") if isinstance(rec.get("collect"), dict) else None
    states = layer_outcomes(result, recorded=rec.get("layers"))
    ran, gaps, skipped = [], [], []
    for lid, spec in LAYERS.items():
        if not _applies(spec, result):
            skipped.append(lid)
            continue
        st = states.get(lid) or {}
        if st.get("status") == "ran":
            ran.append(lid)
        elif st.get("status") == "skipped_policy" and st.get("reason") in NOT_APPLICABLE_REASONS:
            skipped.append(lid)
        else:
            gaps.append(lid)
    required = [x for x in (SEED_POLICY.get("required_layers") or [])
                if x in LAYERS and x not in skipped]
    missing_required = [x for x in required if x in gaps]
    exhausted = not missing_required and len(ran) >= int(SEED_POLICY.get("min_layers_ran", 0))
    # required first, then — unless the analyst turned `free_first` off — cheapest first, so the
    # gaps with no excuse are read before the ones that cost quota.
    cheap = bool(SEED_POLICY.get("free_first", True))
    gaps.sort(key=lambda lid: (lid not in required,
                               COST_ORDER.get(str(LAYERS[lid].get("cost")), 9) if cheap else 0,
                               lid))
    meta = result.get("meta") or {}
    collect_failed = bool(collect and collect.get("status") in RERUNNABLE)
    verdict = "failed" if collect_failed else ("exhausted" if exhausted else "triage")
    failed = [lid for lid in gaps if (states.get(lid) or {}).get("status") in RERUNNABLE]
    return {
        "host": meta.get("host"), "collected_at": meta.get("collected_at"),
        "verdict": verdict,
        "ran": ran, "not_applicable": skipped,
        "missing_required": missing_required,
        "gaps": [{"layer": lid, "label": LAYERS[lid].get("label", lid),
                  "cost": LAYERS[lid].get("cost"), "required": lid in required,
                  "status": (states.get(lid) or {}).get("status") or "not_run",
                  "reason": (states.get(lid) or {}).get("reason") or "",
                  "rerunnable": lid in failed,
                  "evidence": LAYERS[lid].get("evidence"),
                  "without_it": LAYERS[lid].get("without_it"),
                  "how": LAYERS[lid].get("how")} for lid in gaps],
        # FAILED layers: attempted and crashed / timed out — re-run them; never "found nothing"
        "failed": failed,
        "collect": collect,
        "rerunnable": collect_failed or bool(failed),
        "skipped": {lid: {"status": st["status"], "reason": st.get("reason", "")}
                    for lid, st in states.items()
                    if str(st.get("status", "")).startswith("skipped_")},
        "statement": (REPORTING.get("failed_note") if collect_failed
                      else REPORTING.get("exhausted_note") if exhausted
                      else REPORTING.get("triage_note")),
        "absence_note": REPORTING.get("absence_note"),
    }


def assess_case(case: str, root: str = "", host: str = "") -> dict:
    """Every host collected in a case. `root` defaults to the repo this skill sits in. A host
    whose collector crashed has no raw file — it is listed from collection_outcomes.json as
    `failed`, so a crash is never silently a host that was never asked about."""
    root = root or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    case_dir = os.path.join(root, "cases", str(case))
    recorded = load_outcomes(case_dir)
    pattern = os.path.join(case_dir, "raw", f"{host or '*'}.json")
    out, seen = [], set()
    for path in sorted(glob.glob(pattern)):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(doc, dict) or "pivots" not in doc:
            continue
        h = str((doc.get("meta") or {}).get("host") or os.path.basename(path)[:-5])
        a = assess(doc, recorded.get(h))
        a["file"] = os.path.relpath(path, root)
        out.append(a)
        seen.add(h)
    for h, rec in sorted(recorded.items()):
        if h in seen or (host and h != host) or not isinstance(rec, dict):
            continue
        c = rec.get("collect") or {}
        if c.get("status") not in RERUNNABLE and not str(c.get("status", "")).startswith("skipped_"):
            continue
        a = assess({"meta": {"host": h}, "pivots": []}, rec)
        if a["verdict"] != "failed":
            a["verdict"] = "skipped"          # policy-withheld seed (onion / hostile): no raw file
            a["statement"] = REPORTING.get("skipped_note") or a["statement"]
        a["file"] = None
        out.append(a)
    triage = [a for a in out if a["verdict"] in ("triage", "failed")]
    skipped = [a for a in out if a["verdict"] == "skipped"]
    failed = [a for a in out if a["rerunnable"]]
    return {"case": str(case), "hosts": len(out), "triage_hosts": len(triage),
            "exhausted_hosts": len(out) - len(triage) - len(skipped),
            "failed_hosts": len(failed), "skipped_hosts": len(skipped),
            "rerunnable": [{"host": a["host"],
                            "collect": (a.get("collect") or {}).get("status"),
                            "layers": a["failed"]} for a in failed],
            "enrichment": enrichment_states(case_dir),
            "results": out,
            "note": (REPORTING.get("absence_note") if triage else
                     REPORTING.get("exhausted_note"))}


def enrichment_states(case_dir: str) -> dict:
    """Lead execution states from enrichment/index.json (enrichment_run): which leads FAILED
    (re-runnable) and which were withheld by policy or a missing key. Rows written before the
    status field existed map from their legacy `outcome` (retry -> error, held -> skipped_policy,
    unavailable -> skipped_no_key)."""
    legacy = {"retry": "error", "held": "skipped_policy", "unavailable": "skipped_no_key",
              "ran": "ran", "empty": "empty"}
    try:
        with open(os.path.join(case_dir, "enrichment", "index.json"), encoding="utf-8") as fh:
            leads = (json.load(fh) or {}).get("leads") or {}
    except (OSError, ValueError, AttributeError):
        return {"failed": [], "skipped": {}, "counts": {}}
    failed, skipped, counts = [], {}, {}
    for key, row in sorted(leads.items()) if isinstance(leads, dict) else ():
        if not isinstance(row, dict):
            continue
        st = row.get("status") or legacy.get(str(row.get("outcome")), "error")
        counts[st] = counts.get(st, 0) + 1
        if st in RERUNNABLE:
            failed.append({"key": key, "status": st, "reason": row.get("reason") or row.get("summary")})
        elif st.startswith("skipped_"):
            skipped[key] = {"status": st, "reason": row.get("reason") or row.get("summary")}
    return {"failed": failed, "skipped": skipped, "counts": counts}


# --------------------------------------------------------------------------- reporting
def _state_tag(g: dict) -> str:
    st = g.get("status") or "not_run"
    if st == "not_run":
        return ""
    label = "FAILED " + st if st in RERUNNABLE else st
    return f"  <{label}{(': ' + g['reason']) if g.get('reason') else ''}>"


def banner_lines(result: dict, limit: int = 6) -> list:
    """The end-of-run block a collection prints for its own seed. Short by design: it has to be
    read at the bottom of a wall of collection output, so it names the gaps and stops."""
    a = assess(result)
    if a["verdict"] == "exhausted":
        return [f"[=] {REPORTING.get('exhausted_note')}"]
    lines = [f"[!] {REPORTING.get('triage_note')}"]
    for g in a["gaps"][:limit]:
        mark = "*" if g["required"] else " "
        lines.append(f"    {mark} {g['label']:<38} [{g['cost']}]  {g['how']}{_state_tag(g)}")
    if len(a["gaps"]) > limit:
        lines.append(f"      … and {len(a['gaps']) - limit} more — wp_exhaust.py <case> <host>")
    lines.append(f"    ({REPORTING.get('absence_note')})")
    return lines


def render(a: dict) -> str:
    """The human-readable per-host report."""
    out = [f"{a['host'] or '(unknown host)'} — {a['verdict'].upper()}"
           f"   ({len(a['ran'])} layer(s) ran, {len(a['gaps'])} gap(s), "
           f"{len(a.get('failed') or [])} failed)",
           f"  {a['statement']}"]
    c = a.get("collect") or {}
    if c.get("status") and c["status"] != "ran":
        out.append(f"  collector: {c['status']}" + (f" — {c['reason']}" if c.get("reason") else "")
                   + (f" ({c['elapsed_s']}s)" if c.get("elapsed_s") is not None else "")
                   + ("  → RE-RUN" if c["status"] in RERUNNABLE else ""))
    if a["ran"]:
        out.append("  ran: " + ", ".join(LAYERS[x].get("label", x) for x in a["ran"]))
    failed = [g for g in a["gaps"] if g.get("rerunnable")]
    if failed:
        out.append("\n  FAILED — attempted and broke; RE-RUN (this is not 'found nothing')")
        for g in failed:
            out.append(f"    {g['label']}  [{g['status']}]  {g.get('reason') or ''}".rstrip())
            out.append(f"        run   : {g['how']}")
    rest = [g for g in a["gaps"] if not g.get("rerunnable")]
    if rest:
        out.append("\n  NOT RUN — each one is a search space this case has not entered")
        for g in rest:
            req = "REQUIRED" if g["required"] else "optional"
            out.append(f"    {g['label']}  [{g['cost']} · {req}]{_state_tag(g)}")
            out.append(f"        loses : {g['without_it']}")
            out.append(f"        run   : {g['how']}")
        if any(str(g.get("status", "")).startswith("skipped_") for g in rest):
            out.append(f"    ({REPORTING.get('skipped_note') or REPORTING.get('keyless_note')})")
    if a["not_applicable"]:
        why = {lid: s.get("reason") for lid, s in (a.get("skipped") or {}).items()
               if s.get("reason") in NOT_APPLICABLE_REASONS}
        out.append("\n  not applicable to this seed: " + ", ".join(
            x + (f" ({why[x]})" if x in why else "") for x in a["not_applicable"]))
    out.append(f"\n  {a['absence_note']}")
    return "\n".join(out)


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Has this seed been worked, or only triaged? Reads stored results only — "
                    "no network, no credits.")
    ap.add_argument("case", nargs="?", default="", help="case id under cases/")
    ap.add_argument("host", nargs="?", default="", help="one collected host (default: all)")
    ap.add_argument("--file", default="", help="assess one stored pivot JSON directly")
    ap.add_argument("--root", default="", help="repo root holding cases/")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.file:
        res = assess(json.load(open(a.file, encoding="utf-8")))
        print(json.dumps(res, ensure_ascii=False, indent=2) if a.json else render(res))
        return 0
    if not a.case:
        ap.error("give a case id, or --file <stored pivot JSON>")
    rep = assess_case(a.case, root=a.root, host=a.host)
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0
    if not rep["results"]:
        print(f"no stored collections for case {a.case!r} — nothing to assess. This is absence "
              f"of COLLECTION, not a case with no findings.")
        return 0
    print(f"# collection exhaustion — case {rep['case']}: {rep['exhausted_hosts']} exhausted, "
          f"{rep['triage_hosts']} not exhausted ({rep['failed_hosts']} with FAILED collection), "
          f"{rep['skipped_hosts']} withheld by policy\n")
    for r in rep["rerunnable"]:
        print(f"RE-RUNNABLE  {r['host']}  collector={r['collect'] or 'ran'}  "
              f"failed layers: {', '.join(r['layers']) or '-'}")
    enr = rep.get("enrichment") or {}
    for r in enr.get("failed") or []:
        print(f"RE-RUNNABLE  enrichment {r['key']}  [{r['status']}]  {r.get('reason') or ''}".rstrip())
    if enr.get("skipped"):
        print("withheld enrichment: " + ", ".join(
            f"{k} [{v['status']}]" for k, v in sorted(enr["skipped"].items())))
    if rep["rerunnable"] or enr.get("failed") or enr.get("skipped"):
        print()
    for res in rep["results"]:
        print(render(res))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
