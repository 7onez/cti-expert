#!/usr/bin/env python3
"""
collect.py — the dashboard's READERS. Pure functions, JSON-able output, zero dependencies.

Every panel is a join over append-only sources that already exist; nothing here instruments
anything new, and nothing here writes. Five sources:

  Claude Code transcripts   ~/.claude/projects/<slug>/*.jsonl   exact per-turn token usage
  tool-call gate ledger     MEMORY/ + cases/*/tool_calls.jsonl  every call, allowed or DENIED
  API-credit ledger         MEMORY/api_usage.jsonl              third-party spend (NOT Anthropic)
  harness cost ledger       cases/*/run_cost.jsonl              per-phase total_cost_usd
  pinned prompt files       SKILL.md / prompts/*.md / CLAUDE.md the context floor before turn 1

TWO KINDS OF NUMBER, NEVER MIXED
--------------------------------
`usage`-derived token counts are EXACT — the API reported them. Anything measured off a file on
disk is an ESTIMATE from `chars_per_token`, and every such field is named `est_*` so the UI can
style it differently. A rough number rendered like a precise one is how it becomes a fact.

Cost is likewise an estimate at pay-as-you-go LIST prices, and `tools/cost_report.py` owns that
logic — this module imports it rather than restating a price. On a Pro/Max subscription the real
cost is the flat plan; the dollar figures answer "what would these tokens cost on the API".

PERFORMANCE
-----------
A project can hold a thousand transcripts. The index reads the newest N by mtime and memoises each
file's summary on (path, mtime, size). That key is exact rather than a staleness gamble: a
transcript is append-only and the tuple changes whenever it grows. A bounded scan is always
reported as bounded — a truncated total presented as a total is a wrong number, not a partial one.
"""
from __future__ import annotations

import glob
import json
import os
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/dashboard/
HARNESS = os.path.dirname(HERE)                               # harness/
ROOT = os.path.dirname(HARNESS)                               # repo root

for _p in (os.path.join(ROOT, "WebPivot", "tools"), os.path.join(ROOT, "tools")):
    if _p not in sys.path:
        sys.path.append(_p)

try:
    from wp_refs import load_ref                              # the shared RULE 3 loader
except Exception:                                             # noqa: BLE001 — degrade, never block
    def load_ref(path, fallback):
        print(f"[dashboard] WARNING: wp_refs unavailable; {os.path.basename(path)} not read — "
              f"running on the minimal embedded settings.", file=sys.stderr)
        return dict(fallback)

# Pricing + the per-iteration cache-tier accounting live in tools/cost_report.py and are imported,
# never re-implemented: two copies of a price table drift, and the one on the dashboard would be
# the copy nobody updates.
try:
    import cost_report as CR
    _PRICING_OK = True
except Exception as _e:  # noqa: BLE001
    CR = None
    _PRICING_OK = False
    print(f"[dashboard] WARNING: tools/cost_report.py unavailable ({_e}); token counts will "
          f"still be exact but every COST will read $0.00.", file=sys.stderr)


_FALLBACK = {
    "server": {"host": "127.0.0.1", "port": 7788, "allow_nonlocal_bind": False,
               "open_browser": True, "request_timeout_s": 60},
    "sources": {"transcripts_env": "CLAUDE_PROJECT_DIR",
                "tool_calls_ledger": "MEMORY/tool_calls.jsonl",
                "tool_calls_per_case": "cases/*/tool_calls.jsonl",
                "api_usage_ledger": "MEMORY/api_usage.jsonl",
                "run_cost_per_case": "cases/*/run_cost.jsonl",
                "rounds_per_case": "cases/*/rounds.jsonl",
                "scope_per_case": "cases/*/scope.json"},
    "scan": {"default_sessions": 40, "max_sessions": 2000, "max_turns_per_session": 400,
             "max_ledger_lines": 20000, "cache_summaries": True},
    "prompt_surface": {"chars_per_token": 4.0, "paths": ["CLAUDE.md"], "phase_composition": {}},
    "trace": {"max_steps": 500, "text_chars": 4000, "args_chars": 900, "result_chars": 1800,
              "thinking_chars": 2000, "expand_chars": 400000, "head_fraction": 0.7,
              "collapse_context_blocks": True, "join_gate_ledger": True, "inline_images": False,
              "context_markers": ["<system-reminder>"]},
    "health_checks": {
        "cache_write_share": {"warn_above": 0.45, "severity": "warn",
                              "why": "input tokens spent writing the cache rather than reading it"},
        "denied_tool_calls": {"warn_above": 5, "severity": "warn",
                              "why": "calls the gate blocked"},
    },
    "panels": {"overview": "Overview"},
}

_D = load_ref(os.path.join(HARNESS, "references", "dashboard.json"), _FALLBACK)

SERVER = _D["server"]
SOURCES = _D["sources"]
SCAN = _D["scan"]
PROMPT_SURFACE = _D["prompt_surface"]
TRACE = _D.get("trace") or _FALLBACK["trace"]
HEALTH = _D["health_checks"]
PANELS = _D["panels"]

CHARS_PER_TOKEN = float(PROMPT_SURFACE.get("chars_per_token", 4.0) or 4.0)


# --------------------------------------------------------------------------- small helpers
def est_tokens(chars: int) -> int:
    """Bytes on disk -> an ESTIMATED token count. Always surfaced as `est_*`."""
    return int(round(chars / CHARS_PER_TOKEN))


def _iter_jsonl(path: str, limit: int | None = None):
    """Yield parsed objects from a .jsonl, skipping unparseable lines. A half-written last line is
    normal for an append-only ledger being read while a run is in flight — it is not an error."""
    n = 0
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                n += 1
                if limit and n >= limit:
                    return
    except OSError:
        return


def transcript_dir() -> str:
    """Claude Code stores sessions under ~/.claude/projects/<cwd with / and _ as ->. Resolved from
    the REPO ROOT, not the process cwd, so the dashboard shows this project wherever it is started
    from — cost_report.py derives it from cwd, which is right for a CLI and wrong for a server."""
    override = os.environ.get(SOURCES.get("transcripts_env", "CLAUDE_PROJECT_DIR") or "")
    if override:
        return os.path.expanduser(override)
    enc = os.path.abspath(ROOT).replace("/", "-").replace("_", "-")
    return os.path.expanduser(f"~/.claude/projects/{enc}")


# --------------------------------------------------------------- Claude Code transcript reading
_SUMMARY_CACHE: dict[tuple, dict] = {}


def _price(usage: dict, model: str) -> tuple[dict, float]:
    if not _PRICING_OK:
        toks = {"input": usage.get("input_tokens", 0) or 0,
                "output": usage.get("output_tokens", 0) or 0,
                "cache_read": usage.get("cache_read_input_tokens", 0) or 0,
                "cache_write_5m": 0, "cache_write_1h": usage.get("cache_creation_input_tokens", 0) or 0}
        return toks, 0.0
    return CR.price_usage(usage, CR.norm_model(model))


def _known_model(model: str) -> bool:
    return bool(_PRICING_OK and CR.norm_model(model) in CR.PRICING)


def _blank_toks() -> dict:
    return {"input": 0, "output": 0, "cache_read": 0, "cache_write_5m": 0, "cache_write_1h": 0}


def _response_key(rec: dict, msg: dict, seq: int) -> str:
    """Identify the API RESPONSE a record belongs to — not the record.

    Claude Code splits one assistant response across several transcript records (the thinking
    block, then one record per tool_use), and EVERY one of them repeats the same `usage` object.
    Summing per record therefore multiplies that turn's tokens and its cost by however many
    blocks it happened to contain — a 2× overstatement is routine on a tool-heavy session, and
    it is invisible because each row looks individually plausible. Bill once per response.

    `requestId` is the true key; `message.id` is the same thing seen from the API side. A record
    with neither (a synthetic or hand-written transcript) falls back to its own uuid and then to
    its position, so a transcript that carries no ids at all still counts every record exactly
    once instead of collapsing to one."""
    return str(rec.get("requestId") or msg.get("id") or rec.get("uuid") or f"#{seq}")


def _add_toks(dst: dict, src: dict) -> None:
    for k, v in src.items():
        dst[k] = dst.get(k, 0) + v


def summarise_transcript(path: str) -> dict:
    """One session -> a summary dict. Memoised on (path, mtime, size): a transcript only ever
    grows, so that key changes exactly when the content does."""
    try:
        st = os.stat(path)
    except OSError:
        return {}
    key = (path, st.st_mtime, st.st_size)
    if SCAN.get("cache_summaries", True) and key in _SUMMARY_CACHE:
        return _SUMMARY_CACHE[key]

    sid = os.path.basename(path)[:-6]
    s = {"session": sid, "path": path, "title": "", "first_prompt": "",
         "started": None, "ended": None, "turns": 0, "sidechain_turns": 0,
         "models": {}, "unpriced_models": [], "cost": 0.0, "toks": _blank_toks(),
         "max_context": 0, "tool_calls": 0, "tool_names": {}, "biggest_tool_result": 0,
         "biggest_tool_result_name": "", "error_turns": 0, "stop_reasons": {},
         "branch": "", "size_bytes": st.st_size, "mtime": st.st_mtime}

    billed: set[str] = set()          # response keys already charged — see _response_key
    for seq, rec in enumerate(_iter_jsonl(path)):
        t = rec.get("type")
        ts = rec.get("timestamp")
        if ts:
            s["started"] = min(s["started"], ts) if s["started"] else ts
            s["ended"] = max(s["ended"], ts) if s["ended"] else ts
        if rec.get("gitBranch"):
            s["branch"] = rec["gitBranch"]
        # Claude Code writes these as `aiTitle` / `lastPrompt`; the older shapes are kept as
        # fallbacks so a transcript from another writer still labels itself instead of showing
        # up as "(untitled session)" — a session you cannot name is a session you cannot find.
        if t == "ai-title" and not s["title"]:
            m = rec.get("aiTitle") or rec.get("message") or rec.get("title")
            s["title"] = (m if isinstance(m, str) else str(m or ""))[:120]
        if t == "last-prompt" and not s["first_prompt"]:
            s["first_prompt"] = str(rec.get("lastPrompt") or rec.get("prompt")
                                    or rec.get("message") or "")[:160]

        # tool RESULT sizes — the panel that explains a context blowup nobody typed
        if rec.get("toolUseResult") is not None:
            blob = rec["toolUseResult"]
            size = len(blob if isinstance(blob, str) else json.dumps(blob, ensure_ascii=False))
            if size > s["biggest_tool_result"]:
                s["biggest_tool_result"] = size
                s["biggest_tool_result_name"] = _result_tool_name(rec)

        msg = rec.get("message") or {}
        if not isinstance(msg, dict):
            continue
        for block in (msg.get("content") or []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                s["tool_calls"] += 1
                nm = str(block.get("name") or "?")
                s["tool_names"][nm] = s["tool_names"].get(nm, 0) + 1

        usage = msg.get("usage")
        if not usage:
            continue
        # One API response, several records, the SAME usage on each: charge it once. The tool
        # calls above this line are still counted from every record — they are distinct calls
        # inside one response.
        rk = _response_key(rec, msg, seq)
        if rk in billed:
            continue
        billed.add(rk)
        s["turns"] += 1
        if rec.get("isSidechain"):
            s["sidechain_turns"] += 1
        stop = msg.get("stop_reason")
        if stop:
            s["stop_reasons"][stop] = s["stop_reasons"].get(stop, 0) + 1
            if stop in ("max_tokens", "refusal", "error"):
                s["error_turns"] += 1

        # Per-iteration where present: a Fable->Opus fallback bills two models in ONE turn, and
        # collapsing them to the outer `model` misprices the turn.
        iters = usage.get("iterations") or [usage]
        turn_ctx = 0
        seen_models = set()
        for it in iters:
            model = it.get("model") or msg.get("model") or "unknown"
            toks, cost = _price(it, model)
            _add_toks(s["toks"], toks)
            s["cost"] += cost
            mk = CR.norm_model(model) if _PRICING_OK else model
            m = s["models"].setdefault(mk, {"turns": 0, "cost": 0.0, "toks": _blank_toks()})
            m["cost"] += cost
            _add_toks(m["toks"], toks)
            seen_models.add(mk)
            if not _known_model(model) and mk not in s["unpriced_models"]:
                s["unpriced_models"].append(mk)
            turn_ctx += (toks.get("input", 0) + toks.get("cache_read", 0)
                         + toks.get("cache_write_5m", 0) + toks.get("cache_write_1h", 0))
        for mk in seen_models:       # a fallback bills two models in ONE turn; both saw the turn
            s["models"][mk]["turns"] += 1
        s["max_context"] = max(s["max_context"], turn_ctx)

    s.update(cache_metrics(s["toks"]))
    if not s["title"]:
        s["title"] = s["first_prompt"] or "(untitled session)"
    if SCAN.get("cache_summaries", True):
        _SUMMARY_CACHE[key] = s
    return s


def _result_tool_name(rec: dict) -> str:
    """Best-effort name for the tool a result came from — the transcript links it by uuid, and a
    missing link is common, so this degrades to '?' rather than guessing."""
    for k in ("toolName", "tool_name", "name"):
        v = rec.get(k)
        if v:
            return str(v)
    tur = rec.get("toolUseResult")
    if isinstance(tur, dict):
        for k in ("tool", "toolName", "name"):
            if tur.get(k):
                return str(tur[k])
    return "?"


def cache_metrics(toks: dict) -> dict:
    """The two ratios the token panel is really about.

    `cache_read_share` — of everything charged on the INPUT side, how much was a cheap cache read.
    High is good; it means the pinned prefix is being reused across turns.
    `cache_write_share` — how much was a cache WRITE. High is the smell: something near the front
    of the context keeps changing, so the prefix is re-cached (at a premium) instead of re-read.
    Output tokens are excluded from both: they are the work, not the overhead."""
    write = (toks.get("cache_write_5m", 0) or 0) + (toks.get("cache_write_1h", 0) or 0)
    read = toks.get("cache_read", 0) or 0
    fresh = toks.get("input", 0) or 0
    denom = write + read + fresh
    return {
        "input_side_tokens": denom,
        "cache_read_share": round(read / denom, 4) if denom else 0.0,
        "cache_write_share": round(write / denom, 4) if denom else 0.0,
        "cache_write_tokens": write,
    }


def sessions_index(limit: int | None = None) -> dict:
    """Newest-first session list. Bounded by default and SAYS it is bounded."""
    d = transcript_dir()
    files = sorted(glob.glob(os.path.join(d, "*.jsonl")), key=os.path.getmtime, reverse=True)
    total = len(files)
    cap = int(limit or SCAN.get("default_sessions", 40))
    cap = max(1, min(cap, int(SCAN.get("max_sessions", 2000))))
    t0 = time.time()
    rows = [summarise_transcript(p) for p in files[:cap]]
    rows = [r for r in rows if r]
    return {
        "dir": d,
        "exists": os.path.isdir(d),
        "sessions_total": total,
        "sessions_scanned": len(rows),
        "truncated": total > len(rows),
        "scan_seconds": round(time.time() - t0, 2),
        "sessions": rows,
        "note": (f"Showing the {len(rows)} most recent of {total} transcripts. Totals below cover "
                 f"ONLY those — they are not all-time figures.") if total > len(rows) else
                (f"All {total} transcripts in this project are included."),
    }


def session_detail(session: str) -> dict:
    """Turn-by-turn view of one session: what each turn cost, what it carried, what it called."""
    path = os.path.join(transcript_dir(), f"{session}.jsonl")
    if not os.path.exists(path):
        return {"error": f"no transcript {session}.jsonl in {transcript_dir()}"}
    cap = int(SCAN.get("max_turns_per_session", 400))
    turns, pending_tools = [], []
    by_response: dict[str, dict] = {}
    for seq, rec in enumerate(_iter_jsonl(path)):
        msg = rec.get("message") or {}
        if rec.get("toolUseResult") is not None:
            blob = rec["toolUseResult"]
            size = len(blob if isinstance(blob, str) else json.dumps(blob, ensure_ascii=False))
            pending_tools.append({"name": _result_tool_name(rec), "result_chars": size})
        if not isinstance(msg, dict) or not msg.get("usage"):
            continue
        calls_here = [b.get("name") for b in (msg.get("content") or [])
                      if isinstance(b, dict) and b.get("type") == "tool_use"]
        # A response split across records repeats its usage on each. MERGE the later records
        # into the row that already carries the cost — dropping them would lose the tool calls
        # they hold, and adding them would bill the same turn two or three times over.
        rk = _response_key(rec, msg, seq)
        if rk in by_response:
            prev = by_response[rk]
            prev["tool_calls"].extend(c for c in calls_here if c)
            prev["tool_results"] = (prev["tool_results"] + pending_tools)[-6:]
            prev["records"] += 1
            pending_tools = []
            continue
        usage = msg["usage"]
        iters = usage.get("iterations") or [usage]
        toks, cost = _blank_toks(), 0.0
        models = []
        for it in iters:
            model = it.get("model") or msg.get("model") or "unknown"
            tk, c = _price(it, model)
            _add_toks(toks, tk)
            cost += c
            models.append(CR.norm_model(model) if _PRICING_OK else model)
        ctx = (toks["input"] + toks["cache_read"] + toks["cache_write_5m"] + toks["cache_write_1h"])
        row = {
            "n": len(turns) + 1,
            "ts": rec.get("timestamp"),
            "models": sorted(set(models)),
            "effort": rec.get("effort"),
            "sidechain": bool(rec.get("isSidechain")),
            "stop_reason": msg.get("stop_reason"),
            "toks": toks, "cost": round(cost, 6), "context": ctx,
            "tool_calls": [c for c in calls_here if c],
            "tool_results": pending_tools[-6:],
            "records": 1,
            **cache_metrics(toks),
        }
        turns.append(row)
        by_response[rk] = row
        pending_tools = []
        if len(turns) >= cap:
            break
    summary = summarise_transcript(path)
    return {"session": session, "summary": summary, "turns": turns,
            "truncated": len(turns) >= cap}


# --------------------------------------------------------------------------- trace (replay)
#
# The other readers answer "how much". This one answers "what did it DO": the prompt that went
# in, the pinned context it carried, every tool call with its ARGUMENTS and the RAW RESULT that
# came back, the reply that came out, and what each turn cost — in the order it happened.
#
# Two rules it must not break:
#   * A CUT IS NEVER SILENT. Blobs are bounded for display, head AND tail, and every cut states
#     the exact number of characters omitted and offers to re-read the full value. A shortened
#     tool result rendered as if complete reads as a tool that found little.
#   * NO INVENTED LINKS. A call is annotated with a gate decision only on an exact (tool,
#     arguments) match against the ledger; anything fuzzier would put an ALLOW or a DENY on the
#     wrong call, which is worse than no badge at all.

def _clip(value, cap: int, *, pretty: bool = False) -> dict:
    """Bound one blob for the wire, keeping the HEAD and the TAIL and saying what was dropped.

    Mirrors harness/tools.py::_bounded — head because the useful framing (a tool's `meta`, a
    command line, the first rows) leads, tail because list-shaped output summarises at the end.
    The middle is what disappears, and its size is stated so the reader knows to expand rather
    than concluding the call came back empty."""
    if value is None:
        return {"text": "", "chars": 0, "truncated": False, "dropped": 0}
    if isinstance(value, str):
        s = value
    else:
        try:
            s = json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, default=str)
        except Exception:  # noqa: BLE001
            s = str(value)
    n = len(s)
    cap = max(80, int(cap))
    if n <= cap:
        return {"text": s, "chars": n, "truncated": False, "dropped": 0}
    head = max(1, int(cap * float(TRACE.get("head_fraction", 0.7))))
    tail = max(1, cap - head)
    return {"text": s[:head], "tail": s[-tail:], "chars": n, "kept": head + tail,
            "dropped": n - head - tail, "truncated": True}


def _blocks(msg) -> list:
    """Content blocks of one message. A user turn is sometimes a bare string rather than a
    block list; normalising here keeps every caller from re-checking."""
    if not isinstance(msg, dict):
        return []
    c = msg.get("content")
    if isinstance(c, str):
        return [{"type": "text", "text": c}]
    return [b for b in (c or []) if isinstance(b, dict)]


def _block_text(blocks) -> tuple[str, list]:
    """Text of a tool_result / message payload, plus the non-text parts described rather than
    inlined. A base64 screenshot is hundreds of KB: inlining one would make the trace payload
    larger than the transcript it is summarising."""
    if isinstance(blocks, str):
        return blocks, []
    parts, extras = [], []
    for b in (blocks or []):
        if isinstance(b, str):
            parts.append(b)
            continue
        if not isinstance(b, dict):
            continue
        if b.get("type") == "text":
            parts.append(str(b.get("text") or ""))
        elif b.get("type") == "image":
            src = b.get("source") or {}
            extras.append({"kind": "image",
                           "media_type": src.get("media_type") or "image/?",
                           "bytes": len(str(src.get("data") or ""))})
        else:
            extras.append({"kind": str(b.get("type") or "?"), "media_type": "", "bytes": 0})
    return "\n".join(p for p in parts if p), extras


def _is_context_text(text: str) -> bool:
    """Injected context (pinned CLAUDE.md, a hook's system-reminder, a slash-command echo) vs
    something a human typed. Matched on the START of the text only — a reminder quoted inside a
    real prompt is still a real prompt."""
    head = (text or "").lstrip()
    return any(head.startswith(m) for m in (TRACE.get("context_markers") or []))


def _gate_index() -> dict:
    """(tool, canonical-args) -> the gate's decision. Exact keys only; see the note above."""
    idx: dict[tuple, dict] = {}
    if not TRACE.get("join_gate_ledger", True):
        return idx
    for p in _ledger_paths():
        for rec in _iter_jsonl(p, limit=int(SCAN.get("max_ledger_lines", 20000))):
            try:
                key = (str(rec.get("tool") or ""),
                       json.dumps(rec.get("args") or {}, sort_keys=True, ensure_ascii=False))
            except Exception:  # noqa: BLE001
                continue
            idx[key] = {"decision": rec.get("decision"), "classes": rec.get("classes") or [],
                        "reason": rec.get("reason") or "", "case": rec.get("case"),
                        "phase": rec.get("phase"), "backend": rec.get("backend")}
    return idx


def _short_tool(name: str) -> str:
    """`mcp__intel__pivot_extract` -> `pivot_extract`, so a transcript call and a ledger row for
    the same tool compare equal."""
    n = str(name or "")
    if n.startswith("mcp__"):
        return n.split("__")[-1]
    return n


def _index_results(records: list) -> dict:
    """tool_use_id -> what came back. Read from the tool_result BLOCK (what the model actually
    saw), with the record's structured `toolUseResult` used only for the extra facts the block
    does not carry (stderr, interruption, an image result)."""
    out: dict[str, dict] = {}
    for rec in records:
        struct = rec.get("toolUseResult")
        for b in _blocks(rec.get("message") or {}):
            if b.get("type") != "tool_result":
                continue
            tid = str(b.get("tool_use_id") or "")
            if not tid:
                continue
            text, extras = _block_text(b.get("content"))
            entry = {"text": text, "extras": extras, "is_error": bool(b.get("is_error")),
                     "ts": rec.get("timestamp"), "stderr": "", "interrupted": False,
                     "struct_keys": []}
            if isinstance(struct, dict):
                entry["stderr"] = str(struct.get("stderr") or "")[:2000]
                entry["interrupted"] = bool(struct.get("interrupted"))
                entry["struct_keys"] = sorted(k for k in struct if not str(k).startswith("_"))
                if not text:
                    # Some tools report only through the structured payload.
                    entry["text"] = json.dumps(struct, ensure_ascii=False, default=str)
            elif isinstance(struct, str) and not text:
                entry["text"] = struct
            out[tid] = entry
    return out


def session_trace(session: str, limit: int | None = None) -> dict:
    """Replay one session as an ordered list of STEPS — the panel that answers 'what did it do'.

    Step kinds: `context` (injected prompt surface, folded by default) · `user` (what was typed)
    · `assistant` (reply text + whether it thought) · `tool` (name, ARGUMENTS, RAW RESULT) ·
    `event` (hooks, mode switches, local commands). Token cost is attached to the first step of
    the turn that was billed, so the numbers stay tied to the API call that produced them."""
    path = os.path.join(transcript_dir(), f"{session}.jsonl")
    if not os.path.exists(path):
        return {"error": f"no transcript {session}.jsonl in {transcript_dir()}"}

    records = list(_iter_jsonl(path))
    results = _index_results(records)
    gate = _gate_index()
    cap = int(limit or TRACE.get("max_steps", 500))
    steps, tools_used = [], Counter()
    total_result_chars = 0
    turn_no = 0
    billed: set[str] = set()          # one API response can span several records — bill once

    def add(step: dict) -> dict:
        step["i"] = len(steps)
        steps.append(step)
        return step

    for seq, rec in enumerate(records):
        if len(steps) >= cap:
            break
        t = rec.get("type")
        ts = rec.get("timestamp")
        side = bool(rec.get("isSidechain"))
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}

        if t == "attachment":
            att = rec.get("attachment") or {}
            label = str(att.get("hookName") or att.get("type") or "attachment")
            add({"kind": "event", "ts": ts, "label": label, "sidechain": side,
                 "detail": _clip(att.get("stdout") or att.get("content") or att.get("type"), 400)})
            continue
        if t == "system":
            add({"kind": "event", "ts": ts, "label": str(rec.get("subtype") or "system"),
                 "sidechain": side, "detail": _clip(rec.get("content"), 400)})
            continue
        if t == "mode":
            add({"kind": "event", "ts": ts, "label": "mode → " + str(rec.get("mode") or "?"),
                 "sidechain": side, "detail": _clip("", 10)})
            continue
        if t not in ("user", "assistant") or not msg:
            continue

        blocks = _blocks(msg)
        if t == "user":
            if all(b.get("type") == "tool_result" for b in blocks) and blocks:
                continue                       # rendered inside the tool step it belongs to
            text, extras = _block_text(blocks)
            is_ctx = bool(rec.get("isMeta")) or _is_context_text(text)
            add({"kind": "context" if is_ctx else "user", "ts": ts, "sidechain": side,
                 "text": _clip(text, int(TRACE.get("text_chars", 4000))),
                 "attachments": extras})
            continue

        # --- assistant -------------------------------------------------------------------
        usage = msg.get("usage")
        turn = None
        rk = _response_key(rec, msg, seq)
        if usage and rk not in billed:
            # The continuation records of one response repeat its usage. Showing the same cost
            # again under each tool call would read as three expensive turns instead of one.
            billed.add(rk)
            turn_no += 1
            iters = usage.get("iterations") or [usage]
            toks, cost, models = _blank_toks(), 0.0, []
            for it in iters:
                model = it.get("model") or msg.get("model") or "unknown"
                tk, c = _price(it, model)
                _add_toks(toks, tk)
                cost += c
                models.append(CR.norm_model(model) if _PRICING_OK else model)
            turn = {"n": turn_no, "models": sorted(set(models)), "effort": rec.get("effort"),
                    "stop_reason": msg.get("stop_reason"), "toks": toks,
                    "cost": round(cost, 6),
                    "context": toks["input"] + toks["cache_read"]
                               + toks["cache_write_5m"] + toks["cache_write_1h"],
                    **cache_metrics(toks)}

        said, thought = _block_text([b for b in blocks if b.get("type") == "text"])[0], ""
        for b in blocks:
            if b.get("type") == "thinking":
                thought += str(b.get("thinking") or "")
        first_of_turn = True
        if said or thought or not any(b.get("type") == "tool_use" for b in blocks):
            add({"kind": "assistant", "ts": ts, "sidechain": side,
                 "text": _clip(said, int(TRACE.get("text_chars", 4000))),
                 "thinking": _clip(thought, int(TRACE.get("thinking_chars", 2000))),
                 # An empty `thinking` string with a signature means the reasoning was
                 # ENCRYPTED by the API, not that the model did not think. Saying "no thinking"
                 # there would be a false statement about the run.
                 "thinking_redacted": bool(
                     not thought and any(b.get("type") == "thinking" for b in blocks)),
                 "turn": turn if first_of_turn else None})
            first_of_turn = False

        for b in blocks:
            if b.get("type") != "tool_use" or len(steps) >= cap:
                continue
            name = str(b.get("name") or "?")
            tools_used[name] += 1
            args = b.get("input") or {}
            res = results.get(str(b.get("id") or ""), None)
            total_result_chars += len(res["text"]) if res else 0
            try:
                key = (_short_tool(name), json.dumps(args, sort_keys=True, ensure_ascii=False))
            except Exception:  # noqa: BLE001
                key = None
            add({"kind": "tool", "ts": ts, "sidechain": side, "name": name,
                 "id": str(b.get("id") or ""), "caller": b.get("caller"),
                 "args": _clip(args, int(TRACE.get("args_chars", 900)), pretty=True),
                 "result": _clip(res["text"] if res else None,
                                 int(TRACE.get("result_chars", 1800))),
                 "result_chars": len(res["text"]) if res else 0,
                 "pending": res is None,
                 "is_error": bool(res and res["is_error"]),
                 "interrupted": bool(res and res["interrupted"]),
                 "stderr": (res or {}).get("stderr", ""),
                 "extras": (res or {}).get("extras", []),
                 "gate": gate.get(key) if key else None,
                 "turn": turn if first_of_turn else None})
            first_of_turn = False

    summary = summarise_transcript(path)
    flow = [{"i": s["i"], "kind": s["kind"],
             "label": s.get("name") or s["kind"], "err": bool(s.get("is_error"))}
            for s in steps if s["kind"] in ("user", "tool", "assistant")]
    return {
        "session": session,
        "summary": summary,
        "steps": steps,
        "flow": flow,
        "tools_used": tools_used.most_common(),
        "total_result_chars": total_result_chars,
        "truncated": len(steps) >= cap and len(records) > 0,
        "records": len(records),
        "gate_joined": bool(gate),
        "note": ("Blobs are bounded FOR DISPLAY (head + tail) and every cut states what it "
                 "dropped — expand a step to re-read the full value from the transcript. A "
                 "gate badge appears only where a ledger row matches the call's tool AND its "
                 "exact arguments; no badge means no matching record, not an allowed call."),
    }


def trace_step(session: str, id: str) -> dict:  # noqa: A002 — the query param is `id`
    """The FULL arguments and result of one tool call, re-read from the transcript on demand.

    This is the expand behind a truncation marker. It is bounded too (`expand_chars`) — a single
    result can be megabytes — and says so by the same rule."""
    path = os.path.join(transcript_dir(), f"{session}.jsonl")
    if not os.path.exists(path):
        return {"error": f"no transcript {session}.jsonl in {transcript_dir()}"}
    records = list(_iter_jsonl(path))
    results = _index_results(records)
    cap = int(TRACE.get("expand_chars", 400000))
    for rec in records:
        for b in _blocks(rec.get("message") or {}):
            if b.get("type") == "tool_use" and str(b.get("id") or "") == str(id):
                res = results.get(str(id))
                return {"session": session, "id": id, "name": b.get("name"),
                        "ts": rec.get("timestamp"),
                        "args": _clip(b.get("input") or {}, cap, pretty=True),
                        "result": _clip(res["text"] if res else None, cap),
                        "is_error": bool(res and res["is_error"]),
                        "stderr": (res or {}).get("stderr", ""),
                        "pending": res is None,
                        "note": f"Full payload, capped at {cap:,} chars for transport."}
    return {"error": f"no tool call {id!r} in session {session}"}


# --------------------------------------------------------------------------- gate ledger
def _ledger_paths() -> list[str]:
    paths = [os.path.join(ROOT, SOURCES.get("tool_calls_ledger", "MEMORY/tool_calls.jsonl"))]
    paths += sorted(glob.glob(os.path.join(
        ROOT, SOURCES.get("tool_calls_per_case", "cases/*/tool_calls.jsonl"))))
    return [p for p in paths if os.path.exists(p)]


def tool_calls(case: str | None = None, denied: bool = False, limit: int = 300) -> dict:
    """The gate ledger, joined across every front-end. An ABSENT ledger is absence of RECORD —
    never 'nothing happened' — and the payload says so explicitly rather than showing an empty
    table that reads like a clean bill of health."""
    paths = _ledger_paths()
    rows, by_tool, by_decision, by_class = [], Counter(), Counter(), Counter()
    repeats = Counter()
    cap = int(SCAN.get("max_ledger_lines", 20000))
    for p in paths:
        for rec in _iter_jsonl(p, limit=cap):
            if case and rec.get("case") != case:
                continue
            if denied and rec.get("decision") != "DENY":
                continue
            by_tool[rec.get("tool") or "?"] += 1
            by_decision[rec.get("decision") or "?"] += 1
            for c in (rec.get("classes") or []):
                by_class[c] += 1
            sig = (rec.get("case"), rec.get("tool"),
                   json.dumps(rec.get("args") or {}, sort_keys=True, ensure_ascii=False)[:300])
            repeats[sig] += 1
            rows.append(rec)
    rows.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    dup = [{"case": k[0], "tool": k[1], "args": k[2][:160], "count": v}
           for k, v in repeats.most_common(12)
           if v > int((HEALTH.get("repeated_identical_call") or {}).get("warn_above", 3) or 3)]
    return {
        "ledgers": [os.path.relpath(p, ROOT) for p in paths],
        "have_ledger": bool(paths),
        "note": ("No tool-call ledger found. That is ABSENCE OF RECORD — the cases predate the "
                 "gate, or nothing has run — never evidence that nothing happened.")
                if not paths else "",
        "total": sum(by_decision.values()),
        "by_decision": dict(by_decision),
        "by_tool": by_tool.most_common(25),
        "by_class": dict(by_class),
        "repeated": dup,
        "rows": rows[:limit],
    }


# --------------------------------------------------------------------------- credits + cost
def api_credits() -> dict:
    """Third-party credits — a SEPARATE ledger from Anthropic model cost, and the one with hard
    monthly caps. Never folded into the dollar totals; they are different currencies."""
    path = os.path.join(ROOT, SOURCES.get("api_usage_ledger", "MEMORY/api_usage.jsonl"))
    by_provider, by_day, by_case = Counter(), Counter(), Counter()
    calls, fails, recent = 0, 0, []
    for rec in _iter_jsonl(path, limit=int(SCAN.get("max_ledger_lines", 20000))):
        credits = rec.get("credits") or 0
        prov = rec.get("provider") or "?"
        by_provider[prov] += credits
        by_day[str(rec.get("ts") or "")[:10]] += credits
        by_case[rec.get("case") or "(no case)"] += credits
        calls += 1
        if rec.get("ok") is False:
            fails += 1
        recent.append(rec)
    recent.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    return {
        "ledger": os.path.relpath(path, ROOT),
        "have_ledger": os.path.exists(path),
        "calls": calls, "failed_calls": fails,
        "by_provider": by_provider.most_common(),
        "by_day": sorted(by_day.items())[-30:],
        "by_case": by_case.most_common(15),
        "recent": recent[:100],
        "note": "Third-party API credits. These are NOT in any Anthropic dollar figure on this "
                "dashboard — different ledger, different currency, and the tight ones (Censys) "
                "are a per-account monthly grant that does not roll over.",
    }


def run_costs() -> dict:
    """The harness's own per-phase Anthropic ledger — what the SDK reported, not our estimate."""
    rows, by_case, by_phase = [], Counter(), Counter()
    for p in sorted(glob.glob(os.path.join(
            ROOT, SOURCES.get("run_cost_per_case", "cases/*/run_cost.jsonl")))):
        for rec in _iter_jsonl(p):
            rows.append(rec)
            by_case[rec.get("case") or "?"] += rec.get("total_cost_usd") or 0.0
            for ph, c in (rec.get("phases") or {}).items():
                by_phase[ph] += c or 0.0
    rows.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    return {
        "runs": len(rows),
        "by_case": [[k, round(v, 4)] for k, v in by_case.most_common(20)],
        "by_phase": [[k, round(v, 4)] for k, v in by_phase.most_common()],
        "recent": rows[:60],
        "note": "Reported by the SDK itself (total_cost_usd) — Anthropic model cost only. "
                "Third-party API credits are the separate ledger on this same panel.",
    }


# --------------------------------------------------------------------------- prompt surface
def prompt_surface() -> dict:
    """What occupies the context before anyone types. Sizes are ESTIMATES (`est_tokens`).

    This is the panel that answers 'why is every phase expensive' — the harness pins whole
    SKILL.md bodies as system prompts, so a paragraph added to a skill is paid for on every phase
    of every case from then on."""
    files = []
    for rel in PROMPT_SURFACE.get("paths", []):
        p = os.path.join(ROOT, rel)
        try:
            n = os.path.getsize(p)
            files.append({"path": rel, "bytes": n, "est_tokens": est_tokens(n),
                          "exists": True, "mtime": os.path.getmtime(p)})
        except OSError:
            files.append({"path": rel, "bytes": 0, "est_tokens": 0, "exists": False,
                          "mtime": None})
    idx = {f["path"]: f for f in files}
    phases = []
    for phase, parts in (PROMPT_SURFACE.get("phase_composition") or {}).items():
        # `_comment` lives INSIDE this group, so the loader (which only strips underscore keys at
        # the top level of a group) hands it through. Skip documentation keys here or the panel
        # renders the comment string as a phase whose "files" are its characters.
        if phase.startswith("_") or not isinstance(parts, list):
            continue
        tot = sum(idx.get(x, {}).get("est_tokens", 0) for x in parts)
        phases.append({"phase": phase, "parts": parts, "est_tokens": tot,
                       "missing": [x for x in parts if not idx.get(x, {}).get("exists")]})
    phases.sort(key=lambda r: -r["est_tokens"])

    # The MCP/tool description surface: every @tool description is context paid on every phase
    # that exposes the tool. Counted from the registry rather than guessed.
    tool_desc = {"tools": 0, "est_tokens": 0, "error": ""}
    try:
        sys.path.insert(0, HARNESS)
        import tools as T
        chars = 0
        n = 0
        for name in dir(T):
            obj = getattr(T, name)
            desc = getattr(obj, "description", None) or (
                getattr(obj, "__doc__", None) if callable(obj) else None)
            if isinstance(desc, str) and getattr(obj, "name", None):
                chars += len(desc)
                n += 1
        tool_desc = {"tools": n, "est_tokens": est_tokens(chars), "error": ""}
    except Exception as e:  # noqa: BLE001
        tool_desc["error"] = f"tool registry not importable here ({e})"

    files.sort(key=lambda r: -r["bytes"])
    return {
        "chars_per_token": CHARS_PER_TOKEN,
        "files": files,
        "phases": phases,
        "tool_descriptions": tool_desc,
        "note": "ESTIMATES, from file size ÷ chars-per-token — a floor, since code and JSON pack "
                "denser than prose. Exact per-turn numbers are on the Tokens panel; these tell "
                "you what you are paying for BEFORE the first message.",
    }


# --------------------------------------------------------------------------- findings
def _chk(name: str) -> dict:
    return HEALTH.get(name) or {}


def findings(limit: int | None = None) -> dict:
    """The 'what looks wrong' list. Every rule is data-driven (references/dashboard.json →
    health_checks) and every finding carries the WHY from that file, so a number the reader has
    never seen before still explains itself."""
    out = []
    idx = sessions_index(limit)

    def add(kind, severity, title, detail, where="", rank=0.0):
        out.append({"check": kind, "severity": severity, "title": title,
                    "detail": detail, "where": where, "rank": rank,
                    "why": str(_chk(kind).get("why", ""))})

    cw = _chk("cache_write_share")
    lr = _chk("low_cache_reuse")
    cpt = _chk("context_per_turn")
    btr = _chk("big_tool_result")
    err = _chk("error_turns")
    unp = set()

    for s in idx["sessions"]:
        label = f"{s['session'][:8]} · {s['title'][:60]}"
        # A short session is ~100% cache writes by construction — it wrote the prefix once and
        # ended before it could read it. Only a session long enough to have amortised the write
        # says anything, so `min_turns` gates the check rather than the ratio alone.
        if (s["turns"] >= int(cw.get("min_turns", 6))
                and s["cache_write_share"] > float(cw.get("warn_above", 0.45))):
            add("cache_write_share", cw.get("severity", "warn"),
                f"{int(s['cache_write_share'] * 100)}% of input tokens went to cache WRITES",
                f"{s['cache_write_tokens']:,} write tokens vs {s['toks']['cache_read']:,} read "
                f"over {s['turns']} turns (${s['cost']:.2f}).", label,
                rank=s["cache_write_tokens"])
        if (s["turns"] >= int(lr.get("min_turns", 6))
                and s["cache_read_share"] < float(lr.get("warn_below", 0.35))):
            add("low_cache_reuse", lr.get("severity", "warn"),
                f"cache reuse only {int(s['cache_read_share'] * 100)}% over {s['turns']} turns",
                "The pinned prefix is barely being hit — it is changing between turns, or "
                "expiring before the next one.", label, rank=s["input_side_tokens"])
        if s["max_context"] > int(cpt.get("warn_above", 400000)):
            add("context_per_turn", cpt.get("severity", "warn"),
                f"peak context {s['max_context']:,} tokens in one turn",
                "Compare against the window of the model you ran; truncation is silent.", label,
                rank=s["max_context"])
        if s["biggest_tool_result"] > int(btr.get("warn_above_chars", 40000)):
            add("big_tool_result", btr.get("severity", "warn"),
                f"a single tool result was {s['biggest_tool_result']:,} chars",
                f"from `{s['biggest_tool_result_name']}` — narrow it at the source, or confirm "
                f"the context governor truncated it (the full copy is on disk).", label,
                rank=s["biggest_tool_result"])
        if s["error_turns"] > int(err.get("warn_above", 0)):
            add("error_turns", err.get("severity", "info"),
                f"{s['error_turns']} turn(s) stopped on {', '.join(sorted(s['stop_reasons']))}",
                "A max_tokens stop mid-structure looks complete and is not.", label,
                rank=s["error_turns"])
        unp |= set(s["unpriced_models"])

    # Pseudo-models the client stamps on locally-generated turns were never billed as a model
    # call, so listing them as "unpriced" is noise. The ignore list is DATA, not a code constant:
    # suppressing a real model id here would silently remove its spend from every total.
    unp -= set(_chk("unpriced_model").get("ignore") or [])
    if unp:
        add("unpriced_model", _chk("unpriced_model").get("severity", "warn"),
            f"no price for {', '.join(sorted(unp))}",
            "Those tokens are counted but cost $0 here, so every dollar figure on this dashboard "
            "is an UNDER-estimate. Fix harness/references/model_pricing.json.", "pricing table")

    tc = tool_calls(limit=1)
    denied = int(tc["by_decision"].get("DENY", 0))
    dt = _chk("denied_tool_calls")
    if denied > int(dt.get("warn_above", 5)):
        add("denied_tool_calls", dt.get("severity", "warn"),
            f"{denied} tool call(s) blocked by the gate",
            "A few is the gate working. A pile of identical ones is an agent retrying something "
            "it was told not to do — turns and tokens spent producing no evidence.", "tool ledger")
    for r in tc["repeated"]:
        add("repeated_identical_call", _chk("repeated_identical_call").get("severity", "warn"),
            f"`{r['tool']}` called {r['count']}× with identical arguments",
            f"case {r['case'] or '(none)'} — {r['args'][:120]}", "tool ledger",
            rank=r["count"])

    # Collapse repeats: the same check firing on thirty sessions is ONE lesson, and a wall of
    # identical rows is how a findings list gets scrolled past. Keep the worst few per check and
    # say out loud how many were folded — a silently trimmed list reads as "that is all of them".
    cap = int(SCAN.get("max_findings_per_check", 5))
    by_check: dict[str, list] = defaultdict(list)
    for f in out:
        by_check[f["check"]].append(f)
    kept = []
    for check, group in by_check.items():
        group.sort(key=lambda f: -float(f.get("rank") or 0))
        kept.extend(group[:cap])
        if len(group) > cap:
            kept.append({"check": check, "severity": "info",
                         "title": f"+{len(group) - cap} more session(s) tripped the same check",
                         "detail": "Showing the worst few. Raise scan.max_findings_per_check in "
                                   "harness/references/dashboard.json to see them all.",
                         "where": "", "rank": -1, "why": str(_chk(check).get("why", ""))})
    order = {"warn": 0, "info": 1}
    kept.sort(key=lambda f: (order.get(f["severity"], 2), -float(f.get("rank") or 0)))
    return {"findings": kept, "checks_fired": len(by_check), "raw_findings": len(out),
            "scanned": idx["sessions_scanned"],
            "sessions_total": idx["sessions_total"], "truncated": idx["truncated"]}


def overview(limit: int | None = None) -> dict:
    """Headline totals + the findings list. Deliberately the landing panel: the point is to learn
    something is wrong WITHOUT already knowing which tab to open."""
    idx = sessions_index(limit)
    toks, cost, turns, tools_called = _blank_toks(), 0.0, 0, 0
    models = defaultdict(lambda: {"cost": 0.0, "turns": 0})
    for s in idx["sessions"]:
        _add_toks(toks, s["toks"])
        cost += s["cost"]
        turns += s["turns"]
        tools_called += s["tool_calls"]
        for m, v in s["models"].items():
            models[m]["cost"] += v["cost"]
            models[m]["turns"] += v["turns"]
    rc, cr = run_costs(), api_credits()
    return {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repo": ROOT,
        "transcript_dir": idx["dir"],
        "scan": {"sessions_scanned": idx["sessions_scanned"],
                 "sessions_total": idx["sessions_total"],
                 "truncated": idx["truncated"], "seconds": idx["scan_seconds"],
                 "note": idx["note"]},
        "claude_code": {"turns": turns, "toks": toks, "cost": round(cost, 4),
                        "tool_calls": tools_called, **cache_metrics(toks),
                        "models": {k: {"cost": round(v["cost"], 4), "turns": v["turns"]}
                                   for k, v in models.items()}},
        "harness": {"runs": rc["runs"], "by_phase": rc["by_phase"],
                    "total": round(sum(v for _, v in rc["by_case"]), 4)},
        "credits": {"calls": cr["calls"], "by_provider": cr["by_provider"]},
        "pricing_available": _PRICING_OK,
        "findings": findings(limit)["findings"],
        "panels": PANELS,
        "cost_note": "Dollar figures for Claude Code sessions are ESTIMATES at pay-as-you-go API "
                     "list prices (tools/cost_report.py owns the table). On a Pro/Max plan your "
                     "real cost is the flat subscription. Harness figures are the SDK's own "
                     "total_cost_usd. Neither includes third-party API credits.",
    }


if __name__ == "__main__":                       # tiny CLI so the readers are testable alone
    what = sys.argv[1] if len(sys.argv) > 1 else "overview"
    fn = {"overview": overview, "sessions": sessions_index, "tools": tool_calls,
          "credits": api_credits, "runs": run_costs, "prompts": prompt_surface,
          "findings": findings}.get(what)
    if not fn:
        raise SystemExit(f"unknown view {what!r}; try: overview sessions tools credits runs "
                         f"prompts findings")
    print(json.dumps(fn(), indent=2, default=str))
