"""Shared interactive next-action prompt and machine-readable action emitter.

When a harness, loop, or cti run stops with work remaining (pending hosts, metered leads,
or unconverged state), this module:
  1. Computes the concrete candidate next actions with executable commands and descriptions.
  2. On an interactive terminal (stdin isatty): presents a numbered menu, lets the user pick
     an option or enter free-text input (e.g. a new seed to reopen with), and executes the choice.
  3. On a non-interactive run (agent/subagent, cron, pipe): emits a structured JSON line
     `NEXT_ACTIONS: {...}` that an agent can parse to invoke its `ask` capability.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def compute_actions(case: str, *, pending: list[str] | None = None,
                    metered: list[dict] | None = None,
                    status: str | None = None,
                    seeds: list[str] | None = None) -> list[dict[str, Any]]:
    """Build the list of viable next actions for `case`."""
    actions: list[dict[str, Any]] = []

    dispatcher = os.path.join(os.path.dirname(ROOT), "scripts", "backend", "intel.py")

    # 1. Pending hosts to collect
    if pending:
        short_pending = ", ".join(pending[:4]) + (" …" if len(pending) > 4 else "")
        actions.append({
            "id": "continue_harness",
            "label": f"Continue harness — collect {len(pending)} pending host(s) and re-judge (LLM)",
            "description": f"Live fetches + judgment via the dispatcher (keeps backend failover): {short_pending}",
            # through the dispatcher -> harness/cli.py, so backend failover still applies
            "command": [sys.executable, dispatcher, "harness", "continue", case, *pending[:8]],
            "recommended": True,
        })
        actions.append({
            "id": "continue_loop_free",
            "label": f"Continue deterministic loop (free-only) — chase {len(pending)} pending host(s)",
            "description": "Deterministic collector without LLM judgment; spends no metered credits",
            "command": [sys.executable, os.path.join(HERE, "intel.py"), "loop", case],
        })

    # 2. Metered leads. Nothing executes a frontier metered lead directly (cmd_loop --full only
    # unlocks paid engines while collecting PENDING hosts), so the menu must not claim it runs
    # them. Each lead is shown with its exact query; the analyst approves it individually.
    if metered:
        services = sorted({m.get("service", "metered") for m in metered})
        actions.append({
            "id": "review_metered",
            "label": f"Review {len(metered)} deferred metered lead(s) ({', '.join(services)}) — approve one at a time",
            "description": "; ".join(f"{m.get('service')} {m.get('query')}" for m in metered[:4]),
            "leads": metered,
        })

    # 3. Reopen with new seed
    actions.append({
        "id": "reopen",
        "label": "Reopen case with a new seed (domain, URL, IP, hash, wallet)",
        "description": "Merges a new target into the case and resumes expansion against the current KB",
        "needs_input": True,
        "input_prompt": "Enter new seed target: ",
    })

    # 4. Stop pivoting. Deliver goes through the report contract (ask about manual evidence, save
    # the base bundle, then ask the format) — the menu only points there, it never renders.
    actions.append({
        "id": "report",
        "label": "Stop pivoting — go to Deliver (asks about manual evidence, then output format)",
        "description": f"Next: /cti-report {case} (or: scripts/backend/intel.py house-report {case})",
    })

    return actions


def emit_or_prompt(case: str, *, pending: list[str] | None = None,
                   metered: list[dict] | None = None,
                   status: str | None = None,
                   seeds: list[str] | None = None,
                   force_prompt: bool = False) -> dict[str, Any] | None:
    """If interactive (or force_prompt): prompt the user to choose or input.
    If non-interactive: print a single-line NEXT_ACTIONS JSON block and return None.
    """
    # Only the OUTERMOST entry point asks: cmd_cti runs cmd_loop in-process and sets this so the
    # loop neither prompts mid-run nor prints a NEXT_ACTIONS line after which cti's JSON summary
    # would no longer be the last stdout line (callers parse that line).
    if os.environ.get("INTEL_NO_PROMPT"):
        return None
    actions = compute_actions(case, pending=pending, metered=metered, status=status, seeds=seeds)
    if not actions:
        return None

    is_interactive = force_prompt or (
        sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("CTI_NON_INTERACTIVE")
    )

    if not is_interactive:
        payload = {
            "case": case,
            "status": status or "unknown",
            "pending_count": len(pending or []),
            "metered_count": len(metered or []),
            "actions": actions,
        }
        print(f"\nNEXT_ACTIONS: {json.dumps(payload, ensure_ascii=False)}")
        return None

    # Interactive terminal prompt
    print(f"\n{'=' * 60}")
    print(f"CASE '{case}' — Next Actions Available (status: {status or 'open'})")
    print(f"{'=' * 60}")
    for idx, act in enumerate(actions, 1):
        rec = " [RECOMMENDED]" if act.get("recommended") else ""
        print(f"  [{idx}] {act['label']}{rec}")
        if act.get("description"):
            print(f"      ↳ {act['description']}")
    print(f"  [0] Exit / do nothing")

    try:
        choice = input("\nSelect an action [1-%d, or 0 to exit]: " % len(actions)).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return None

    if not choice or choice == "0":
        print("Done.")
        return None

    try:
        selected_idx = int(choice) - 1
        if selected_idx < 0 or selected_idx >= len(actions):
            print("Invalid choice.")
            return None
    except ValueError:
        print("Invalid choice.")
        return None

    selected = actions[selected_idx]

    # Free-text input handling (e.g. new seed)
    if selected.get("needs_input"):
        try:
            val = input(selected.get("input_prompt", "Enter input: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return None
        if not val:
            print("No input provided.")
            return None
        selected["user_input"] = val
        reopen_cmd = [sys.executable, os.path.join(HERE, "case_state.py"), "reopen", case, val]
        print(f"\nRunning: {' '.join(shlex.quote(c) for c in reopen_cmd)}")
        subprocess.run(reopen_cmd, cwd=ROOT)
        return selected

    # Command execution
    if selected.get("command"):
        cmd = selected["command"]
        print(f"\nRunning: {' '.join(shlex.quote(c) for c in cmd)}")
        subprocess.run(cmd, cwd=ROOT)
    elif selected.get("leads"):
        print("\nDeferred metered leads (none runs without your explicit per-lead approval):")
        for m in selected["leads"]:
            print(f"  · {m.get('service')} {m.get('query')} — {m.get('why', '')}")
    elif selected.get("description"):
        print(f"\n{selected['description']}")

    return selected
