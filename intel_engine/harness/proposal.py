"""Per-round pivot approval for the cross-type loop — `cases/<case>/proposal.json`.

The loop runs FREE (or quota-backed) pivots whose hit count is known and within
`pivot_map.auto_max_hits` on its own. Everything else — a metered pivot, an oversized or
unknown-size hit set — is written here as an item with a stable id, and the round stops at
`awaiting-approval`. The analyst approves ids (`harness approve`, the `case_approve` tool, or the
TTY prompt); `--continue` runs exactly those ids.

An approval is bound to the case state it was made against. `digest` hashes the inputs that mean
"the case moved on" — the collected raw files, the dispatched pivot ids and the typed node
registry — and NOT state.json's bookkeeping (status, history, round), which the run's own hand-back
rewrites right after the proposal is written. Approving after the case moved on is refused and the
loop re-proposes. While the loop is active, `audit.gate()` consults `gate_check()` and DENIES a
proposal-gated metered call that matches no approved, unused item — enforced at the tool gate on
every front-end (SDK hook, OpenAI shim, stdio MCP server: they all know the case). Approvals are
SINGLE-USE (each approved id lets exactly one call through), and `loop_active` / `running` carry a
lease, so a run killed mid-way can neither hold the gate shut nor leave approvals open.

Stdlib only; never raises out of the read helpers (a missing/corrupt file = no active proposal).
"""
from __future__ import annotations

import datetime
import glob
import hashlib
import json
import os
import threading

_LOCK = threading.RLock()     # one approval → one call, even across MCP worker threads

PROPOSAL_FILE = "proposal.json"
# Seconds a loop_active / running mark stays valid without being renewed. A crashed run's marks
# expire on their own; a live run renews them at every round boundary (set_loop_active/begin_run).
LEASE_SECONDS = int(os.environ.get("HARNESS_LOOP_LEASE") or 6 * 3600)


def _path(root: str, case: str) -> str:
    return os.path.join(root, "cases", str(case), PROPOSAL_FILE)


def _utc(delta: int = 0) -> str:
    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=delta)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _utc()


def _live(until) -> bool:
    """True while a lease timestamp is in the future (ISO strings compare lexicographically)."""
    return bool(until) and str(until) > _now()


def _get(c, key, default=None):
    """Field access for a Candidate dataclass or its dict form."""
    if isinstance(c, dict):
        return c.get(key, default)
    return getattr(c, key, default)


def _as_dict(c) -> dict:
    if isinstance(c, dict):
        return dict(c)
    to = getattr(c, "to_dict", None)
    return to() if callable(to) else dict(vars(c))


# --------------------------------------------------------------------------- split (pure)
def split(cands, *, no_spend: bool, auto_max: int):
    """(auto, needs_approval, dropped) — pure.

    auto     : not metered AND est_hits is known AND est_hits <= auto_max
    dropped  : metered under a no_spend scope (never proposed — the analyst said no spend)
    needs    : everything else (metered, oversized, or unknown size)"""
    auto, needs, dropped = [], [], []
    for c in cands:
        metered = bool(_get(c, "metered", False))
        est = _get(c, "est_hits")
        if metered and no_spend:
            dropped.append(c)
        elif not metered and est is not None and int(est) <= int(auto_max):
            auto.append(c)
        else:
            needs.append(c)
    return auto, needs, dropped


# --------------------------------------------------------------------------- digest
def digest(root: str, case: str) -> str:
    """sha256 over what makes a proposal stale: the sorted collected raw file names, the sorted
    dispatched pivot ids (`pivoted`) and the sorted typed node keys (`nodes`) from state.json."""
    h = hashlib.sha256()
    cdir = os.path.join(root, "cases", str(case))
    try:
        with open(os.path.join(cdir, "state.json"), encoding="utf-8") as fh:
            st = json.load(fh)
        st = st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        st = {}
    for name in sorted(os.path.basename(p) for p in glob.glob(os.path.join(cdir, "raw", "*.json"))):
        h.update(b"r\0" + name.encode("utf-8"))
    for pid in sorted(str(x) for x in (st.get("pivoted") or [])):
        h.update(b"p\0" + pid.encode("utf-8"))
    for key in sorted(str(k) for k in (st.get("nodes") or {})):
        h.update(b"n\0" + key.encode("utf-8"))
    return "sha256:" + h.hexdigest()


# --------------------------------------------------------------------------- file I/O
def load(root: str, case: str) -> dict | None:
    try:
        with open(_path(root, case), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _save(root: str, case: str, data: dict) -> None:
    p = _path(root, case)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, p)


def write(root: str, case: str, *, round_no: int, items, dropped=()) -> dict:
    """Write a fresh PENDING proposal for this round (replaces any previous one)."""
    prev = load(root, case) or {}
    data = {"case": str(case), "round": int(round_no), "created": _now(),
            "digest": digest(root, case), "status": "pending",
            "loop_active": bool(prev.get("loop_active")),
            "loop_lease_until": prev.get("loop_lease_until"),
            "items": [_as_dict(c) for c in items],
            "dropped_no_spend": [_as_dict(c) for c in dropped],
            "approved": [], "rejected": [], "used": []}
    _save(root, case, data)
    return data


def set_loop_active(root: str, case: str, active: bool) -> None:
    """Mark whether the cross-type loop is running for this case (the gate only enforces then).
    An active mark carries a lease (LEASE_SECONDS) so a killed run cannot keep it forever."""
    data = load(root, case) or {"case": str(case), "status": "none", "items": [],
                                "approved": [], "rejected": [], "used": []}
    data["loop_active"] = bool(active)
    data["loop_lease_until"] = _utc(LEASE_SECONDS) if active else None
    _save(root, case, data)


def loop_active(data: dict | None) -> bool:
    return bool(data and data.get("loop_active") and _live(data.get("loop_lease_until")))


def approve(root: str, case: str, *, only=None, reject=None, approve_all: bool = False) -> dict:
    """Record the analyst's decision. Returns the updated proposal, or {"error": ...} when there
    is nothing pending, an id is unknown, or the digest is stale (caller must re-propose).

    Only EXPLICIT rejections are permanent (the loop never re-proposes a rejected id). Items the
    analyst neither approved nor rejected are DEFERRED: they stay un-pivoted and come back in a
    later proposal — approving a few items never silently drops the rest."""
    data = load(root, case)
    if not data or data.get("status") != "pending" or not data.get("items"):
        return {"error": f"no pending proposal for {case}"}
    if data.get("digest") != digest(root, case):
        return {"error": "stale proposal: the case changed since it was proposed — re-propose",
                "stale": True}
    ids = [i.get("id") for i in data["items"]]
    want = list(ids) if approve_all else [str(x) for x in (only or [])]
    rej = [str(x) for x in (reject or [])]
    unknown = sorted(set(want + rej) - set(ids))
    if unknown:
        return {"error": f"unknown proposal id(s): {', '.join(unknown)}"}
    if not want and not rej:
        return {"error": "nothing to approve or reject — pass ids, --all, or --reject"}
    data["approved"] = [i for i in ids if i in set(want) - set(rej)]
    data["rejected"] = [i for i in ids if i in set(rej)]
    data["deferred"] = [i for i in ids if i not in set(data["approved"]) | set(rej)]
    data["used"] = []
    data["status"] = "approved"
    data["decided"] = _now()
    _save(root, case, data)
    return data


def approved_items(root: str, case: str) -> list[dict]:
    """Approved, still-unused items the gate may let through: an `approved` proposal whose digest
    is current, or a `running` one inside its lease (begin_run verified the digest and froze the
    set — the run's own collection must not void it mid-way)."""
    data = load(root, case)
    if not data:
        return []
    status = data.get("status")
    if status == "approved":
        if data.get("digest") != digest(root, case):
            return []
    elif status != "running" or not _live(data.get("run_lease_until")):
        return []
    keep = set(data.get("approved") or []) - set(data.get("used") or [])
    return [i for i in data.get("items") or [] if i.get("id") in keep]


def begin_run(root: str, case: str) -> dict:
    """Start executing an approved proposal: re-verify the digest, freeze the approved set under a
    lease, and return {"items": [...]} — or {"error": ...} (nothing approved / stale)."""
    data = load(root, case)
    if not data or data.get("status") != "approved":
        return {"error": f"no approved proposal for {case}"}
    if data.get("digest") != digest(root, case):
        return {"error": "stale proposal: the case changed since it was approved — re-propose",
                "stale": True}
    items = approved_items(root, case)
    data["status"] = "running"
    data["started"] = _now()
    data["run_lease_until"] = _utc(LEASE_SECONDS)
    _save(root, case, data)
    return {"items": items}


def mark_consumed(root: str, case: str) -> None:
    """After --continue ran the approved items: close the proposal (approvals are single-use)."""
    data = load(root, case)
    if not data:
        return
    data["status"] = "consumed"
    data["consumed"] = _now()
    data["run_lease_until"] = None
    _save(root, case, data)


def render(data: dict) -> str:
    """Fixed-width table of a proposal — the same view for the CLI, the TTY prompt and the
    case_approve briefing."""
    if not data or not data.get("items"):
        return "(no proposal items)"
    lines = [f"proposal {data.get('case')} round {data.get('round')} · status {data.get('status')}"
             f" · {len(data['items'])} item(s)",
             f"{'id':<11}{'type':<9}{'tool':<22}{'metered':<8}{'hits':>6}  {'rung':<9}{'by':<9}selector — why"]
    for i in data["items"]:
        hits = "?" if i.get("est_hits") is None else str(i.get("est_hits"))
        lines.append(f"{str(i.get('id')):<11}{str(i.get('type')):<9}{str(i.get('tool')):<22}"
                     f"{'yes' if i.get('metered') else 'no':<8}{hits:>6}  {str(i.get('rung')):<9}"
                     f"{str(i.get('by')):<9}{i.get('selector')} — {i.get('why') or ''}")
    if data.get("dropped_no_spend"):
        lines.append(f"({len(data['dropped_no_spend'])} metered item(s) dropped: scope is no_spend)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- gate (audit hook)
def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def matches(item: dict, tool: str, args: dict) -> bool:
    """Does a metered tool call correspond to this approved item?"""
    args = args or {}
    route = item.get("tool")
    if tool == "corpus_search":
        return (args.get("route") == route and _norm(args.get("query")) == _norm(item.get("query")))
    if tool == "reverse_whois":
        return route == "rwhois.purchase" and _norm(args.get("term")) == _norm(item.get("selector"))
    return False


def _host_of(url) -> str:
    u = str(url or "").strip().lower()
    if "://" in u:
        u = u.split("://", 1)[1]
    return u.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def is_seed_host(root: str, case: str, url) -> bool:
    """True when `url`'s host is one of the analyst's own typed seeds (cases/<case>/
    harness_seeds.json, written by the orchestrator). Consent to keyed collection is PER HOST:
    the seeds the analyst typed — never whatever else an agent reaches in the same round."""
    h = _host_of(url)
    if not h:
        return False
    try:
        with open(os.path.join(root, "cases", str(case), "harness_seeds.json"), encoding="utf-8") as fh:
            seeds = {_host_of(s) for s in (json.load(fh) or [])}
    except (OSError, ValueError):
        return False
    return h in seeds


def collect_free_only(root: str, case: str, url, *, free_only: bool = False,
                      allow_spend: bool = False) -> bool:
    """The ONE spend rule for host collection (collect_one, the collect_many fan-out, the gate):
    free-only when asked, when the case is no_spend, or while the cross-type loop is active —
    unless the host is an analyst-typed seed or an approved `enrich.host` (allow_spend).
    Unreadable loop state fails closed."""
    if free_only or _no_spend(root, case):
        return True
    try:
        in_loop = loop_active(load(root, case))
    except Exception:  # noqa: BLE001
        in_loop = True
    return in_loop and not allow_spend and not is_seed_host(root, case, url)


def _no_spend(root: str, case: str) -> bool:
    try:
        with open(os.path.join(root, "cases", str(case), "scope.json"), encoding="utf-8") as fh:
            return bool(((json.load(fh) or {}).get("constraints") or {}).get("no_spend"))
    except (OSError, ValueError, AttributeError):
        return False


def gate_check(root: str, case: str | None, tool: str, args: dict, *, gated: set) -> tuple[bool, str]:
    """(allow, reason) for a METERED call to a proposal-gated tool (the caller established both).

    (The case-wide `no_spend` denial for EVERY metered tool lives in audit.decide.)
    While the case's cross-type loop is active (lease live) the call is allowed only if it matches
    an approved, unused item — and that item is then marked used (single-use approval)."""
    if not case or tool not in gated:
        return True, ""
    data = load(root, case)
    if not loop_active(data):
        return True, ""
    with _LOCK:                   # check-and-consume atomically: two racing calls cannot share one id
        for item in approved_items(root, case):
            if matches(item, tool, args):
                data = load(root, case) or data
                data.setdefault("used", []).append(item.get("id"))
                _save(root, case, data)
                return True, ""
    return False, (f"metered call not in proposal.approved — {tool} is a metered pivot and the "
                   f"cross-type loop for {case} only spends on items the analyst approved in "
                   f"cases/{case}/{PROPOSAL_FILE} (each approval lets one call through). Propose it "
                   f"(it will appear in the next round's proposal) or re-call with free_only=true. "
                   f"Do not retry unchanged.")
