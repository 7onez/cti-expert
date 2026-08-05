#!/usr/bin/env python3
"""wp_capabilities — what this WebPivot run can actually do, given the keys that are present.

WHY THIS EXISTS
---------------
WebPivot's contract is that everything works **keyless**: no key is required and a missing one is
never an error. That contract has one dangerous edge. A keyless run and a fully-keyed run print the
same kind of output — a pivot list — but they searched different amounts of the internet. When the
FOFA reverse never ran, "no sibling domains" is not a finding about the operator, it is a fact about
our credentials. An analyst who is not told which run they are reading will write the first sentence
of an assessment on the second one's evidence.

So every run states its capability up front, in three places:

  - a **stderr banner** at the top of the run (`print_banner`) naming each absent key, the
    reverse-lookup it removes, and the free path that substitutes;
  - `meta.capability` in the result JSON (`capability_meta`) — so the assessment, the KB and any
    later reader can see the run's coverage without re-deriving it;
  - a line in `--leads`, where the analyst is actually looking.

WHAT IT DOES *NOT* DO
---------------------
It never blocks, prompts or changes behaviour. It reports. The one judgement it encodes is the
`impact` ordering — which absence costs the most evidence — and that lives in
`references/api_keys.json`, not here (RULE 3): the code holds only the presence check.

CLI:
  python3 wp_capabilities.py                # human-readable status table
  python3 wp_capabilities.py --json         # the same as meta.capability
  python3 wp_capabilities.py --free-only    # as the convergence loop sees it (metered keys unused)
"""
import argparse
import json
import sys
import textwrap

from wp_common import _secret                    # noqa — env-first secret lookup
from wp_refs import ref_path, load_ref           # noqa — reference DATA lives in references/*.json

# --- reference DATA (RULE 3). The fallback is the minimum that keeps the banner HONEST if the JSON
#     goes missing: it must never claim full capability just because it could not read the file.
_CAP_FALLBACK = {
    "api_keys": {
        "FOFA_KEY": {"service": "FOFA", "aliases": ["FOFA_API_KEY"], "impact": "critical",
                     "metered": True,
                     "without_it": "favicon/tracker/body reverse search unavailable"},
        "URLSCAN_API_KEY": {"service": "urlscan.io", "impact": "critical", "metered": True,
                            "without_it": "authenticated urlscan search unavailable"},
        "CENSYS_PAT": {"service": "Censys Platform", "impact": "high", "metered": True,
                       "without_it": "no Censys lookups (the CenQL builder still works)"},
        "WHOISXML_API_KEY": {"service": "WhoisXML API", "impact": "high", "metered": True,
                             "without_it": "no WHOIS history / reverse WHOIS"},
    },
    "keyless_baseline": ["artifact extraction", "keyless RDAP WHOIS", "crt.sh certificate search",
                         "live TLS certificate", "every pivot's ready-to-run query strings"],
    # Only the two levels the banner escalates on — medium/low absences are rolled up to one line
    # and never need a label, so a broken data file still prints an accurate worst-case warning.
    "impact_labels": {"critical": "a primary reverse-lookup index is unavailable",
                      "high": "a distinct evidence class is unavailable"},
}
_REFS = load_ref(ref_path(__file__, "api_keys.json"), _CAP_FALLBACK)
API_KEYS = _REFS["api_keys"]
KEYLESS_BASELINE = _REFS["keyless_baseline"]
IMPACT_LABELS = _REFS["impact_labels"]

_IMPACT_ORDER = ["critical", "high", "medium", "low"]

# How many absences get the full lost/instead treatment on the stderr banner. The rest roll up to
# one line. This is a readability budget, not a judgement: with no keys at all, spelling out eight
# credentials is a 40-line wall that trains the analyst to scroll past the one block that says the
# result may be meaningless. The full text is always one command away.
_MAX_DETAILED = 3


def _present(env: str, spec: dict) -> bool:
    """True when this credential is usable — the variable (or one of its aliases) is set, and so is
    every variable in `requires`.

    `requires` is DATA, never inferred from the variable's name: PDNS_PASSWORD really is useless
    without PDNS_USERNAME (HTTP Basic), while FOFA_EMAIL is needed only by FOFA's classic API. A
    guess in the strict direction reports a working key as missing, which is exactly the false
    alarm this module exists to prevent."""
    names = [env] + list(spec.get("aliases") or [])
    if not _secret(*names):
        return False
    return all(_secret(req) for req in (spec.get("requires") or []))


def key_status():
    """[{env, service, present, impact, metered, unlocks, without_it, free_fallback, signup}, …]
    in the file's own order (most costly absence first)."""
    rows = []
    for env, spec in API_KEYS.items():
        if not isinstance(spec, dict):
            continue
        rows.append({
            "env": env,
            "service": spec.get("service") or env,
            "present": _present(env, spec),
            "impact": spec.get("impact") or "medium",
            "metered": bool(spec.get("metered")),
            "aliases": list(spec.get("aliases") or []),
            "companion": list(spec.get("companion") or []),
            "requires": list(spec.get("requires") or []),
            "unlocks": spec.get("unlocks") or "",
            "without_it": spec.get("without_it") or "",
            "free_fallback": spec.get("free_fallback") or "",
            "signup": spec.get("signup") or "",
            # Optional, per key: what percentage of THAT layer still works with no key. Present
            # for layers where keyless mode still does real work (composing every query) but can
            # execute none of it — saying "~50% capability" is more honest, and more actionable,
            # than leaving the analyst to infer how degraded the run was.
            "power_without_key": spec.get("power_without_key"),
        })
    return rows


def capability_meta(free_only: bool = False) -> dict:
    """The run's capability, for `meta.capability` — a fact about the EVIDENCE, so it belongs in
    the case file next to `collected_at`, not only on the terminal.

    `mode` is one of:
      keyless   — no credential at all; every metered index is unqueried
      partial   — some keys present, at least one absent
      keyed     — every registered credential present
      free-only — keys may exist but --free-only forbade spending them (the convergence loop's
                  mode); analytically identical to keyless for the metered indexes
    """
    rows = key_status()
    present = [r["env"] for r in rows if r["present"]]
    missing = [r["env"] for r in rows if not r["present"]]
    unusable = [r["env"] for r in rows if r["present"] and r["metered"]] if free_only else []
    if free_only:
        mode = "free-only"
    elif not present:
        mode = "keyless"
    elif missing:
        mode = "partial"
    else:
        mode = "keyed"
    # What the analyst must not misread. Only the absences that remove an INDEX are listed —
    # a degraded detail level is not a reason to doubt a negative result.
    blind = [{"env": r["env"], "service": r["service"], "impact": r["impact"],
              "lost": r["without_it"], "instead": r["free_fallback"],
              **({"power_pct": r["power_without_key"]} if r.get("power_without_key") else {})}
             for r in rows
             if (not r["present"] or (free_only and r["metered"]))
             and r["impact"] in ("critical", "high")]
    # Layers that quantify their own degradation, at any impact level — reported separately so the
    # run can state "IntelX ran at ~50%" without the reader having to read it out of a prose field.
    degraded = [{"env": r["env"], "service": r["service"], "power_pct": r["power_without_key"]}
                for r in rows
                if r.get("power_without_key")
                and (not r["present"] or (free_only and r["metered"]))]
    return {
        "mode": mode,
        "keys_present": present,
        "keys_missing": missing,
        "metered_suppressed": unusable,
        "reduced": blind,
        "degraded_layers": degraded,
        "statement": statement(mode, blind, degraded),
        "keyless_baseline": list(KEYLESS_BASELINE),
    }


def statement(mode: str, blind: list, degraded: list = None) -> str:
    """The one sentence a report should carry. Written so it can be pasted into an assessment's
    collection-limitations note verbatim."""
    # Layers that quantify their own degradation get their number in the sentence — "IntelX ran at
    # ~50% capability" is a fact a reader can act on; "IntelX was unavailable" invites them to
    # assume nothing was produced at all, which is also wrong.
    pct = ""
    if degraded:
        pct = " " + "; ".join(f"{d['service']} ran at ~{d['power_pct']}% capability"
                              for d in degraded) + "."
    if mode == "keyed":
        return ("Collected with every registered API key present — all reverse-lookup indexes "
                "were queried.")
    if not blind:
        return (f"Collected in {mode} mode; the absent credentials cost detail only, not an "
                f"evidence class.{pct}")
    lost = ", ".join(b["service"] for b in blind)
    why = ("--free-only suppressed every metered index" if mode == "free-only"
           else "no credential was available for")
    return (f"COLLECTION LIMITATION — {mode} mode: {why} {lost}. Those reverse-lookup indexes were "
            f"never queried, so the ABSENCE of sibling infrastructure in this run is not evidence "
            f"that none exists.{pct}")


def _wrap(text: str, indent: str, width: int = 100, max_lines: int = 0) -> list:
    """Wrap one prose field for the stderr banner. A banner nobody can read is a banner nobody
    reads, and this one carries the reason a negative result may be meaningless — so the banner
    gets the short form and `wp_capabilities.py` / meta.capability keep the full text."""
    if max_lines:
        text = textwrap.shorten(text, width=width * max_lines - len(indent), placeholder=" …")
    return textwrap.wrap(text, width=width, initial_indent=indent,
                         subsequent_indent=" " * (len(indent) + 2)) or []


def banner_lines(free_only: bool = False) -> list:
    """The stderr banner, as lines. Empty when fully keyed and not --free-only — a run at full
    capability needs no caveat and should not train the analyst to ignore this block."""
    cap = capability_meta(free_only=free_only)
    if cap["mode"] == "keyed":
        return []
    rows = {r["env"]: r for r in key_status()}
    head = {"keyless": "KEYLESS MODE — no API key is configured",
            "partial": "PARTIAL CAPABILITY — some API keys are absent",
            "free-only": "FREE-ONLY MODE — metered indexes suppressed by --free-only"}[cap["mode"]]
    lines = [f"[!] {head}. Capability is REDUCED:"]
    # Full detail ONLY for the absences that remove an evidence class. A 40-line banner on every
    # keyless run is a banner the analyst learns to scroll past, which defeats the whole point —
    # medium/low absences roll up to one line and keep their detail in `wp_capabilities.py`.
    absent = cap["keys_missing"] + cap["metered_suppressed"]
    minor, detailed = [], 0
    for env in absent:
        r = rows.get(env) or {}
        if not r:
            continue
        if r.get("impact") not in ("critical", "high") or detailed >= _MAX_DETAILED:
            minor.append(f"{env} [{r.get('impact')}]")
            continue
        detailed += 1
        mark = "SUPPRESSED" if env in cap["metered_suppressed"] else "not set"
        pct = f" — ~{r['power_without_key']}% capability" if r.get("power_without_key") else ""
        lines.append(f"    · {env} [{r.get('impact')}] {r.get('service')} — {mark}{pct}")
        lines += _wrap(f"lost:    {r.get('without_it')}", "        ", max_lines=2)
        if r.get("free_fallback"):
            lines += _wrap(f"instead: {r['free_fallback']}", "        ", max_lines=2)
    if minor:
        lines += _wrap("also absent: " + ", ".join(minor) +
                       "  — full detail: `python3 WebPivot/tools/wp_capabilities.py`", "    · ")
    worst = next((i for i in _IMPACT_ORDER
                  if any((rows.get(e) or {}).get("impact") == i for e in absent)), None)
    if worst:
        lines += _wrap(IMPACT_LABELS.get(worst, ""), "    ⚠ ")
    lines.append(f"    Still free and running: {len(KEYLESS_BASELINE)} keyless capabilities "
                 f"(extraction · asset layer · RDAP WHOIS · crt.sh · live TLS · JARM · mail · "
                 f"archive · every pivot's query strings)")
    lines.append("    Full list: `python3 WebPivot/tools/wp_capabilities.py` · "
                 "wire keys up: WebPivot/references/Setup.md")
    return lines


def print_banner(free_only: bool = False, file=sys.stderr) -> None:
    for line in banner_lines(free_only=free_only):
        print(line, file=file)


__all__ = ["key_status", "capability_meta", "statement", "banner_lines", "print_banner",
           "API_KEYS", "KEYLESS_BASELINE", "IMPACT_LABELS"]


def main():
    ap = argparse.ArgumentParser(
        description="Report which WebPivot capabilities are available with the keys present.")
    ap.add_argument("--json", action="store_true", help="emit meta.capability as JSON")
    ap.add_argument("--free-only", action="store_true",
                    help="report as the convergence loop sees it: metered keys present but unusable")
    a = ap.parse_args()
    cap = capability_meta(free_only=a.free_only)
    if a.json:
        print(json.dumps(cap, indent=2, ensure_ascii=False))
        return 0
    print(f"WebPivot capability — mode: {cap['mode'].upper()}\n")
    for r in key_status():
        state = "PRESENT" if r["present"] else "absent "
        if a.free_only and r["present"] and r["metered"]:
            state = "SUPPRESSED (--free-only)"
        print(f"  [{state}] {r['env']} — {r['service']}  [{r['impact']}]"
              + ("  (metered: costs credits)" if r["metered"] else "")
              + (f"  (~{r['power_without_key']}% capability without it)"
                 if r.get("power_without_key") and not r["present"] else ""))
        if r["present"]:
            print(f"      unlocks: {r['unlocks']}")
        else:
            print(f"      LOST:    {r['without_it']}")
            if r["free_fallback"]:
                print(f"      instead: {r['free_fallback']}")
            if r["signup"]:
                print(f"      get one: {r['signup']}")
        print()
    print("Free and keyless regardless of any of the above:")
    for line in KEYLESS_BASELINE:
        print(f"  · {line}")
    print(f"\n{cap['statement']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
