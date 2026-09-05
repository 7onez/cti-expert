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

CLI:
  wp_exhaust.py <case>                     # every host collected in the case
  wp_exhaust.py <case> <host>              # one host
  wp_exhaust.py --file cases/x/raw/h.json  # a stored result directly
  wp_exhaust.py <case> --json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

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
                  "without_it": "no registration timeline", "how": "automatic"},
        "capture": {"label": "raw evidence capture", "cost": "free", "applies_to": "any",
                    "detect": {"meta": "capture"}, "evidence": "the bytes served",
                    "without_it": "nothing to re-check a finding against",
                    "how": "pivot_extract --case <id>"},
        "intelx": {"label": "Intelligence X", "cost": "metered", "applies_to": "any",
                   "detect": {"enriched_with": "intelx"},
                   "evidence": "leaks, stealer logs, pastes, darknet",
                   "without_it": "the corpus outside the live internet was never queried",
                   "how": "pivot_extract --intelx"},
    },
    "seed_policy": {"required_layers": ["fetch", "whois", "capture", "intelx"],
                    "min_layers_ran": 3},
    "reporting": {
        "triage_note": "SEED NOT EXHAUSTED — this was a TRIAGE; the layers below never ran.",
        "exhausted_note": "Seed exhausted: every required evidence layer has run.",
        "absence_note": "A layer that did not run produces no result. That is absence of "
                        "COLLECTION, not absence of evidence.",
        "keyless_note": "Some gaps are closed by a credential rather than a command.",
    },
}

_REFS = load_ref(ref_path(__file__, "exhaustion.json"), _EXHAUST_FALLBACK)

LAYERS = _REFS["layers"]
SEED_POLICY = _REFS["seed_policy"]
REPORTING = _REFS["reporting"]

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


# --------------------------------------------------------------------------- assessment
def assess(result: dict) -> dict:
    """One stored collection -> {verdict, ran, gaps, statement}. Pure; no network."""
    ran, gaps, skipped = [], [], []
    for lid, spec in LAYERS.items():
        if not _applies(spec, result):
            skipped.append(lid)
            continue
        (ran if layer_ran(spec, result) else gaps).append(lid)
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
    return {
        "host": meta.get("host"), "collected_at": meta.get("collected_at"),
        "verdict": "exhausted" if exhausted else "triage",
        "ran": ran, "not_applicable": skipped,
        "missing_required": missing_required,
        "gaps": [{"layer": lid, "label": LAYERS[lid].get("label", lid),
                  "cost": LAYERS[lid].get("cost"), "required": lid in required,
                  "evidence": LAYERS[lid].get("evidence"),
                  "without_it": LAYERS[lid].get("without_it"),
                  "how": LAYERS[lid].get("how")} for lid in gaps],
        "statement": (REPORTING.get("exhausted_note") if exhausted
                      else REPORTING.get("triage_note")),
        "absence_note": REPORTING.get("absence_note"),
    }


def assess_case(case: str, root: str = "", host: str = "") -> dict:
    """Every host collected in a case. `root` defaults to the repo this skill sits in."""
    root = root or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    pattern = os.path.join(root, "cases", str(case), "raw", f"{host or '*'}.json")
    out = []
    for path in sorted(glob.glob(pattern)):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(doc, dict) or "pivots" not in doc:
            continue
        a = assess(doc)
        a["file"] = os.path.relpath(path, root)
        out.append(a)
    triage = [a for a in out if a["verdict"] == "triage"]
    return {"case": str(case), "hosts": len(out), "triage_hosts": len(triage),
            "exhausted_hosts": len(out) - len(triage), "results": out,
            "note": (REPORTING.get("absence_note") if triage else
                     REPORTING.get("exhausted_note"))}


# --------------------------------------------------------------------------- reporting
def banner_lines(result: dict, limit: int = 6) -> list:
    """The end-of-run block a collection prints for its own seed. Short by design: it has to be
    read at the bottom of a wall of collection output, so it names the gaps and stops."""
    a = assess(result)
    if a["verdict"] == "exhausted":
        return [f"[=] {REPORTING.get('exhausted_note')}"]
    lines = [f"[!] {REPORTING.get('triage_note')}"]
    for g in a["gaps"][:limit]:
        mark = "*" if g["required"] else " "
        lines.append(f"    {mark} {g['label']:<38} [{g['cost']}]  {g['how']}")
    if len(a["gaps"]) > limit:
        lines.append(f"      … and {len(a['gaps']) - limit} more — wp_exhaust.py <case> <host>")
    lines.append(f"    ({REPORTING.get('absence_note')})")
    return lines


def render(a: dict) -> str:
    """The human-readable per-host report."""
    out = [f"{a['host'] or '(unknown host)'} — {a['verdict'].upper()}"
           f"   ({len(a['ran'])} layer(s) ran, {len(a['gaps'])} gap(s))",
           f"  {a['statement']}"]
    if a["ran"]:
        out.append("  ran: " + ", ".join(LAYERS[x].get("label", x) for x in a["ran"]))
    if a["gaps"]:
        out.append("\n  NOT RUN — each one is a search space this case has not entered")
        for g in a["gaps"]:
            req = "REQUIRED" if g["required"] else "optional"
            out.append(f"    {g['label']}  [{g['cost']} · {req}]")
            out.append(f"        loses : {g['without_it']}")
            out.append(f"        run   : {g['how']}")
    if a["not_applicable"]:
        out.append("\n  not applicable to this seed: " + ", ".join(a["not_applicable"]))
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
          f"{rep['triage_hosts']} still at TRIAGE depth\n")
    for res in rep["results"]:
        print(render(res))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
