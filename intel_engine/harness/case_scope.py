#!/usr/bin/env python3
"""case_scope.py — the harness's INTAKE record: what this case IS, and what claim it is testing.

WHY THIS EXISTS
---------------
WebPivot's §0 intake is a conversation, and the harness has nobody to talk to. `intel.py open`,
the SDK orchestrator, the MCP server and every batch run start from a bare seed list, so the
scoping that a Claude Code session gets by asking was simply absent from the automated path —
which is the path that does the volume. This module is where the answers live instead: a small
per-case record, given once (CLI flag, `--scope` file, or the `case_scope` MCP tool while an
analyst IS in the loop), persisted to `cases/<case>/scope.json`, and read back by every phase
and every resumed round.

It changes three things that were previously guesses:

  1. POSTURE, and it is ENFORCED, not merely suggested. `target_class` resolves to a
     `fetch_posture` in the intake reference; `never_direct_from_analyst_egress` (threat-actor
     infrastructure) and an explicit "don't touch it" constraint both derive `hostile=True`,
     which the PreToolUse gate in `audit.py` turns into a hard denial of outbound collection.
     A posture that only lived in a prompt is a posture the model can talk itself out of.
  2. OWNERSHIP, which decides whether the page's artifacts may be clustered at all. On a
     compromised host the WHOIS, favicon, certificate and analytics belong to the VICTIM;
     clustering on them fuses unrelated victims into one imaginary operator estate. The class's
     `clustering_rule` goes into the collect AND the judgment prompts.
  3. THE CLAIM, carried as a hypothesis under test rather than as a premise. The requester's
     stated class arrives with the seeds, and without this record it silently becomes the frame
     every ambiguous artifact is read through. Here it is stored with its source, put in front
     of the correlate/verify/assess phases with its falsifier, and answered by an explicit
     `premise_verdict` in the structured assessment.

NEVER BLOCKS (`policy.blocking: false` in the reference). A case with no scope resolves to
`unknown` — the conservative class — and every prompt it renders SAYS the run proceeded without
stated context. An absent scope must cost disclosure, never a refusal to run.

The vocabulary (classes, postures, questions, verdicts, prohibitions, switches) is DATA:
`WebPivot/references/intake.json`, one owner, shared with the WebPivot skill so the interactive
and automated front-ends cannot drift. See contributor RULE 3.

CLI:
    python3 harness/case_scope.py show <case>
    python3 harness/case_scope.py set  <case> --target-class victim_host --purpose attribution \
                                              --claim "..." --basis "vendor report" --brand "..."
    python3 harness/case_scope.py questions          # what to ask when an analyst IS in the loop
"""
from __future__ import annotations

import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
ROOT = os.path.dirname(HERE)                                  # repo root
_WP = os.path.join(ROOT, "WebPivot", "tools")
if _WP not in sys.path:
    sys.path.append(_WP)                                      # append: never shadow harness/tools.py

try:
    from wp_refs import load_ref                              # the shared RULE 3 loader
except Exception:                                             # noqa: BLE001 — degrade, never block a run
    def load_ref(path: str, fallback: dict) -> dict:
        print(f"[scope] WARNING: wp_refs unavailable; {os.path.basename(path)} not read — "
              f"running on the minimal embedded intake vocabulary.", file=sys.stderr)
        return dict(fallback)


# Minimal embedded vocabulary. Deliberately CONSERVATIVE: on a broken/missing data file the two
# classes that carry a hard constraint (never touch it / the artifacts are the victim's) survive,
# the claim is still tested, and `unknown` is still the default — the run just loses the richer
# guidance. The safe direction here is to collect LESS and disclose MORE.
#
# Shaped as the LOADED form, not the file's: `wp_refs._group` unwraps each top-level group, so
# `target_classes` arrives as its `entries` dict and `intake_questions` as its `values` list. The
# groups nested INSIDE `claim_verification` keep their `{_comment, values}` wrapper — `_bullets`
# reads either shape.
_INTAKE_FALLBACK: dict = {
    "target_classes": {
            "unknown": {
                "means": "No context supplied.",
                "fetch_posture": "passive_first",
                "opsec": "Assume it could be adversarial until the collection says otherwise.",
                "run": ["liveness", "archive_timeline", "full_pivot"],
                "clustering_rule": "Hold every edge as provisional until the class resolves.",
                "disconfirming": ["the collection establishes a class — restate the scope"],
                "confidence_note": "Say the run proceeded without stated context.",
            },
            "threat_actor_infra": {
                "means": "Intrusion / espionage / malware infrastructure.",
                "fetch_posture": "never_direct_from_analyst_egress",
                "opsec": "A direct request tells the operator they are being examined.",
                "run": ["passive_sources_only"],
                "clustering_rule": "Configuration overlap is usually a toolkit or provider default.",
                "disconfirming": ["the population count shows a provider default"],
                "confidence_note": "Same-toolkit is never same-actor.",
            },
            "victim_host": {
                "means": "A third party's host serving the operator's content.",
                "fetch_posture": "passive_first",
                "opsec": "The owner is uninvolved. Do not probe.",
                "run": ["victim_profile"],
                "clustering_rule": "The host's own artifacts are the VICTIM's — only the injected "
                                   "content is the operator's.",
                "disconfirming": ["no legitimate content exists alongside the injected path"],
                "confidence_note": "The output is the access vector, not another cluster member.",
            },
    },
    "intake_questions": [
        {"id": "target_class", "ask": "What do you believe this is?",
         "why": "It selects the collection posture and whose artifacts these are.",
         "changes": "posture, layers, clustering", "required": True,
         "default_if_unanswered": "unknown"},
        {"id": "purpose", "ask": "What is this run for?",
         "why": "Decides the deliverable and the depth.", "changes": "depth",
         "required": True, "default_if_unanswered": "triage"},
    ],
    "claim_verification": {
        "stance": "The stated class is a hypothesis this run TESTS. It sets the posture, never "
                  "the finding.",
        "record_as": "Assertion with a named source — never a collected fact.",
        "required_output_line": "Stated premise: <class> (source: <basis>). Collection verdict: "
                                "<supported | partially supported | not supported | contradicted "
                                "| inconclusive> — <one line of why>.",
        "verdicts": {
            "supported": "Independent collected evidence matches the stated class.",
            "partially_supported": "The class holds but a material part of the claim does not.",
            "not_supported": "The collection found nothing either way — NOT a refutation.",
            "contradicted": "Collected evidence is inconsistent with the stated class.",
            "inconclusive": "The target was never observed; the claim was not tested.",
        },
        "mandatory_checks": {"values": [
            "liveness — classify by reading the page, not by its status code",
            "archive timeline — the state at the incident date is the relevant one",
            "base rate — count the population behind an artifact before it becomes an edge",
        ]},
        "never": {"values": [
            "raise a confidence level because the requester was certain",
            "skip a disconfirming check because the class was stated as confirmed",
            "report 'not supported' as 'benign' when the run was keyless, passive or blocked",
        ]},
    },
    "scope_switches": {
        "target_class=threat_actor_infra": "Passive sources only; no direct fetch from analyst egress.",
        "target_class=victim_host": "Suppress clustering on host-owned artifacts.",
    },
    "policy": {
        "blocking": False,
        "unanswered_target_class": "unknown",
        "must_state_assumptions_in_output": True,
        "reclassify_mid_run": "When the collection establishes a different class, say so and "
                              "restate the posture.",
    },
}

_INTAKE_PATH = os.path.join(ROOT, "WebPivot", "references", "intake.json")
_I = load_ref(_INTAKE_PATH, _INTAKE_FALLBACK)

CLASSES: dict = _I["target_classes"]
QUESTIONS: list = _I["intake_questions"]
CLAIM: dict = _I["claim_verification"]
SWITCHES: dict = _I["scope_switches"]
POLICY: dict = _I["policy"]

DEFAULT_CLASS = str(POLICY.get("unanswered_target_class", "unknown"))
#: the posture that forbids touching the target at all — the one that becomes a GATE denial
NO_TOUCH = "never_direct_from_analyst_egress"

_FIELDS = ("target_class", "basis", "purpose", "brand", "how_encountered",
           "time_window", "falsifier", "claim")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _defaults() -> dict:
    """The two fields a run cannot proceed without, defaulted from the reference's own
    `default_if_unanswered` so the questions and the code cannot drift apart.

    Every OTHER field stays None when unanswered, deliberately. Injecting a default into
    `brand` / `time_window` / `falsifier` would render it back to the model as though the analyst
    had said it — "Date that matters: full history" reads as an incident date, and a defaulted
    falsifier reads as a test the requester asked for. A silent default that looks like an answer
    is the same anchoring failure this whole layer exists to prevent, one level down."""
    d = {q.get("id"): q.get("default_if_unanswered") for q in QUESTIONS if isinstance(q, dict)}
    out: dict = {f: None for f in _FIELDS}
    out["target_class"] = DEFAULT_CLASS
    out["purpose"] = d.get("purpose") or "triage"
    return out


def path(case: str, root: str = ROOT) -> str:
    return os.path.join(root, "cases", str(case), "scope.json")


def normalise_class(name: str | None) -> str:
    """Coerce a class name to one the reference knows. An unrecognised string degrades to the
    conservative default WITH a warning — never to a permissive class, and never to a crash: a
    typo in a CLI flag must not silently authorise a fetch the real class forbids."""
    if not name:
        return DEFAULT_CLASS
    key = str(name).strip().lower().replace("-", "_").replace(" ", "_")
    if key in CLASSES:
        return key
    print(f"[scope] WARNING: unknown target_class {name!r} — falling back to "
          f"{DEFAULT_CLASS!r} (known: {', '.join(sorted(CLASSES))}).", file=sys.stderr)
    return DEFAULT_CLASS


def load(case: str, root: str = ROOT) -> dict | None:
    """Read a persisted scope, or None. Never raises — a corrupt scope file must not kill a case."""
    p = path(case, root)
    try:
        with open(p, encoding="utf-8") as f:
            got = json.load(f)
        return got if isinstance(got, dict) else None
    except FileNotFoundError:
        return None
    except Exception as e:  # noqa: BLE001
        print(f"[scope] WARNING: {p} unreadable ({e}); proceeding as `{DEFAULT_CLASS}`.",
              file=sys.stderr)
        return None


def save(case: str, scope: dict, root: str = ROOT) -> str:
    """Persist the scope so later rounds, a `--continue` resume and the other front-end inherit
    it. Never raises: an unwritable case dir costs the persistence, not the run."""
    p = path(case, root)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(scope, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as e:
        print(f"[scope] WARNING: could not persist scope to {p} ({e}); this run still uses it, "
              f"but the next round will fall back to `{DEFAULT_CLASS}`.", file=sys.stderr)
    return p


def resolve(case: str, root: str = ROOT, *, persist: bool = True, **given: object) -> dict:
    """Build this run's scope: explicit arguments win, then the persisted `scope.json`, then the
    reference's own defaults. Unsupplied fields are NOT invented — they stay at their default and
    the rendered prompts disclose that the run is assuming.

    `given` accepts the intake fields plus `no_direct_contact` / `no_spend` (constraints).
    """
    prev = load(case, root) or {}
    scope = _defaults()
    # `stated_fields` is the honest bookkeeping this module turns on: it separates what an analyst
    # actually said from what we assumed, so a defaulted value is never rendered back to the model
    # as an answer and never activates a scope switch.
    stated: list[str] = [f for f in list(_FIELDS) + ["no_direct_contact", "no_spend"]
                         if f in (prev.get("stated_fields") or [])]
    for f in _FIELDS:
        if prev.get(f) not in (None, ""):
            scope[f] = prev[f]
    supplied = []
    for f in _FIELDS:
        v = given.get(f)
        if v not in (None, ""):
            scope[f] = v
            supplied.append(f)

    cons = dict(prev.get("constraints") or {})
    for c in ("no_direct_contact", "no_spend"):
        v = given.get(c)
        if v is not None:
            cons[c] = bool(v)
            supplied.append(c)
    scope["constraints"] = {"no_direct_contact": bool(cons.get("no_direct_contact")),
                            "no_spend": bool(cons.get("no_spend"))}

    scope["target_class"] = normalise_class(scope.get("target_class"))
    scope["case"] = str(case)
    scope["stated_fields"] = sorted(set(stated) | set(supplied))
    scope["stated"] = bool(scope["stated_fields"])
    scope["stated_at"] = _now() if supplied else prev.get("stated_at")
    scope["source"] = "argument" if supplied else ("scope.json" if prev else "default")
    if persist and (supplied or not prev):
        save(case, scope, root)
    return scope


def said(scope: dict, field: str) -> bool:
    """Did the analyst actually answer this field? A defaulted value is not an answer."""
    return field in (scope.get("stated_fields") or [])


def posture(scope: dict) -> dict:
    """The class entry driving this run. Always a dict — an unknown class was already coerced."""
    return CLASSES.get(normalise_class(scope.get("target_class")), {}) or {}


def is_hostile(scope: dict, explicit: bool = False) -> bool:
    """Derive the egress constraint the tool-call GATE enforces.

    Only two things set it, and both mean 'do not touch this from our own address': a class whose
    posture is `never_direct_from_analyst_egress`, or an analyst constraint saying so. Note that
    `passive_first` deliberately does NOT set it — passive-first is an ORDERING instruction
    (exhaust archive/CT/third-party scanners before requesting the page), not a prohibition, and
    conflating the two would silently turn every unscoped run into a no-fetch run and gut the
    collection while looking like caution."""
    return bool(explicit
                or posture(scope).get("fetch_posture") == NO_TOUCH
                or (scope.get("constraints") or {}).get("no_direct_contact"))


def _switch_keys(scope: dict) -> list[str]:
    """Which `scope_switches` entries this scope activates — the proof that an intake answer
    changes the run rather than decorating it."""
    # target_class always resolves, so its switch (the safety one) always applies. Every other
    # switch fires only on an ANSWER — a defaulted `purpose=triage` must not quietly instruct the
    # run to stop at leads and spend nothing, because nobody asked for that.
    keys = [f"target_class={scope.get('target_class')}"]
    if said(scope, "purpose") and scope.get("purpose"):
        keys.append(f"purpose={scope['purpose']}")
    if said(scope, "brand") and scope.get("brand"):
        keys.append("brand_or_entity=named")
    if said(scope, "time_window") and scope.get("time_window"):
        keys.append("time_window=given")
    # Match how-encountered on WORD tokens, never on substrings: "download" contains "ad", and a
    # substring match would fire the advertising probe on every file-download funnel.
    raw = str(scope.get("how_encountered") or "").lower() if said(scope, "how_encountered") else ""
    words = {w for w in "".join(c if c.isalnum() else " " for c in raw).split() if w}
    if words & {"ad", "ads", "advert", "advertising", "sponsored", "sponsor", "serp", "malvertising"}:
        keys.append("how_encountered=ad_or_sponsored")
    if words & {"file", "download", "apk", "exe", "installer", "dmg", "msi", "app"}:
        keys.append("how_encountered=file_download")
    if words & {"redirect", "redirects", "redirection", "chain"}:
        keys.append("how_encountered=redirect_chain")
    cons = scope.get("constraints") or {}
    if cons.get("no_direct_contact"):
        keys.append("constraints=no_direct_contact")
    if cons.get("no_spend"):
        keys.append("constraints=no_spend")
    return [k for k in keys if k in SWITCHES]


def switches(scope: dict) -> list[str]:
    return [f"{k} → {SWITCHES[k]}" for k in _switch_keys(scope)]


def _bullets(node: object) -> list[str]:
    """Read a `{_comment, values}` group or a bare list into a list of strings."""
    if isinstance(node, dict):
        node = node.get("values", [])
    return [str(v) for v in node] if isinstance(node, list) else []


def _unstated_note(scope: dict) -> str:
    if scope.get("stated"):
        return ""
    return ("NO CONTEXT WAS SUPPLIED for this case. You are running under the conservative "
            "default class, and the deliverable MUST say so — state that the run proceeded "
            "without stated context, which assumptions it therefore made, and that the class "
            "was resolved (or not) by the collection itself.\n")


def collect_directives(scope: dict) -> str:
    """The scope block for the COLLECT phase — posture, ownership, and the checks that keep a
    stated class from being assumed true."""
    p, cls = posture(scope), scope.get("target_class")
    mark = "" if said(scope, "target_class") else "  (DEFAULTED — nobody stated a class)"
    out = ["SCOPE — established at intake. It sets the POSTURE, never the finding.",
           f"- Target class: `{cls}`{mark} — {p.get('means', 'unspecified')}"]
    if said(scope, "claim") and scope.get("claim"):
        out.append(f"- What the requester asserted: \"{scope['claim']}\" "
                   f"(basis: {scope.get('basis') or 'unstated'}) — a HYPOTHESIS this run tests.")
    if said(scope, "purpose") and scope.get("purpose"):
        out.append(f"- Purpose: {scope['purpose']}")
    if said(scope, "brand") and scope.get("brand"):
        out.append(f"- Brand/entity in play: {scope['brand']} — confirm the DIRECTION "
                   f"(is the seed the imposter, or the brand's own site?) before writing anything.")
    if said(scope, "time_window") and scope.get("time_window"):
        out.append(f"- Date that matters: {scope['time_window']} — anchor the archive timeline "
                   f"there, not on today.")
    out.append(f"- Fetch posture: `{p.get('fetch_posture', 'passive_first')}` — {p.get('opsec', '')}")
    if is_hostile(scope):
        out.append("  ENFORCED: outbound collection from this address is DENIED by the tool gate. "
                   "Call the collectors with passive=true (archive / third-party sources only) or "
                   "a proxy; a denial is an instruction to change approach, not to retry.")
    out.append(f"- OWNERSHIP (decides what may be clustered): {p.get('clustering_rule', '')}")
    if p.get("run"):
        out.append(f"- Layers this class expects: {', '.join(p['run'])}")
    dis = p.get("disconfirming") or []
    if dis:
        out.append("- Observations that would move the target OUT of this class — run them "
                   "even if the class was stated confidently:")
        out += [f"    · {d}" for d in dis]
    sw = switches(scope)
    if sw:
        out.append("- Active scope switches:")
        out += [f"    · {s}" for s in sw]
    note = _unstated_note(scope)
    if note:
        out.append("- " + note.rstrip("\n"))
    out.append("- RECLASSIFY OUT LOUD: " + str(POLICY.get("reclassify_mid_run", "")))
    return "\n".join(out) + "\n"


def judgment_directives(scope: dict) -> str:
    """The scope block for CORRELATE / VERIFY / ASSESS — the claim under test, the checks that
    test it, the verdict vocabulary, and the prohibitions that stop the claim becoming evidence."""
    cls = scope.get("target_class")
    out = ["PREMISE UNDER TEST — " + str(CLAIM.get("stance", "")),
           f"- Stated class: `{cls}` (source: {scope.get('basis') or 'unstated'}; "
           f"{'analyst-supplied' if scope.get('stated') else 'DEFAULTED — no context was given'})"]
    if said(scope, "claim") and scope.get("claim"):
        out.append(f"- The assertion, verbatim: \"{scope['claim']}\"")
    if said(scope, "falsifier") and scope.get("falsifier"):
        out.append(f"- The requester's own falsifier — report on it explicitly: "
                   f"\"{scope['falsifier']}\"")
    elif posture(scope).get("disconfirming"):
        out.append("- No falsifier was given, so use the class's own disconfirming list: "
                   + "; ".join(str(d) for d in posture(scope)["disconfirming"]))
    if said(scope, "purpose") and scope.get("purpose"):
        out.append(f"- Purpose of the run: {scope['purpose']}")
    out.append(f"- Ownership rule in force: {posture(scope).get('clustering_rule', '')}")

    checks = _bullets(CLAIM.get("mandatory_checks"))
    if checks:
        out.append("- Checks you must have satisfied before pronouncing on the premise:")
        out += [f"    · {c}" for c in checks]

    verdicts = CLAIM.get("verdicts") or {}
    if verdicts:
        out.append("- Set `premise_verdict` to exactly one of these, and say why in one line:")
        out += [f"    · {k}: {v}" for k, v in verdicts.items()]
    out.append("- Output line required in the assessment: "
               + str(CLAIM.get("required_output_line", "")))

    never = _bullets(CLAIM.get("never"))
    if never:
        out.append("- NEVER:")
        out += [f"    · {n}" for n in never]
    note = _unstated_note(scope)
    if note:
        out.append("- " + note.rstrip("\n"))
    return "\n".join(out) + "\n"


def banner(scope: dict) -> str:
    """One line for the worklog / run header."""
    bits = [f"class={scope.get('target_class')}"]
    if said(scope, "purpose") and scope.get("purpose"):
        bits.append(f"purpose={scope['purpose']}")
    bits.append(f"posture={posture(scope).get('fetch_posture', '?')}")
    if is_hostile(scope):
        bits.append("egress=DENIED")
    bits.append("stated" if scope.get("stated") else "DEFAULTED (no context supplied)")
    return "scope · " + " · ".join(bits)


def questions_markdown() -> str:
    """What to ask when an analyst IS in the loop — rendered from the reference so the harness and
    the WebPivot §0 intake ask the same questions."""
    out = ["# Intake — ask before collecting", "",
           f"Never blocks: unanswered → `{DEFAULT_CLASS}` under the conservative posture, "
           f"disclosed in the deliverable.", ""]
    for q in QUESTIONS:
        if not isinstance(q, dict):
            continue
        req = " **(carries the scoping)**" if q.get("required") else ""
        out += [f"- **{q.get('ask', q.get('id'))}**{req}",
                f"  - why: {q.get('why', '')}",
                f"  - changes: {q.get('changes', '')}",
                f"  - if unanswered: `{q.get('default_if_unanswered')}`"]
    out += ["", "Known target classes:", ""]
    for k, v in CLASSES.items():
        out.append(f"- `{k}` — {v.get('means', '')} "
                   f"(posture: `{v.get('fetch_posture', '?')}`)")
    return "\n".join(out)


# --------------------------------------------------------------------------------- CLI
def _main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip().split("CLI:")[-1].strip())
        return 0
    cmd = argv[0]
    if cmd == "questions":
        print(questions_markdown())
        return 0
    if cmd not in ("show", "set") or len(argv) < 2:
        print("usage: case_scope.py show <case> | set <case> [--target-class …] | questions",
              file=sys.stderr)
        return 2
    case, rest = argv[1], argv[2:]

    given: dict = {}
    i = 0
    flagmap = {"--target-class": "target_class", "--purpose": "purpose", "--claim": "claim",
               "--basis": "basis", "--brand": "brand", "--how": "how_encountered",
               "--window": "time_window", "--falsifier": "falsifier"}
    while i < len(rest):
        a = rest[i]
        if a in flagmap and i + 1 < len(rest):
            given[flagmap[a]] = rest[i + 1]
            i += 2
        elif a == "--no-direct-contact":
            given["no_direct_contact"] = True
            i += 1
        elif a == "--no-spend":
            given["no_spend"] = True
            i += 1
        else:
            print(f"[scope] ignoring unrecognised argument {a!r}", file=sys.stderr)
            i += 1

    if cmd == "show" and not given:
        scope = resolve(case, persist=False)
    else:
        scope = resolve(case, **given)

    print(banner(scope))
    print()
    print(collect_directives(scope))
    print(judgment_directives(scope))
    if not scope.get("stated"):
        print("No scope has been stated for this case. To set one:\n"
              f"  python3 harness/case_scope.py set {case} --target-class <class> "
              f"--purpose <purpose> --claim \"<what the requester asserted>\"\n"
              "Run `case_scope.py questions` for what to ask.")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
