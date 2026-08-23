#!/usr/bin/env python3
"""
test_dashboard.py — the gate on the debug dashboard (harness/dashboard/).

Run:  python3 tests/test_dashboard.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
The dashboard exists to answer "where did the tokens go" and "what went wrong". Every failure
below makes it answer that question WRONGLY while still looking authoritative:

  * A NUMBER THAT LIES. Token counts read out of a transcript's `usage` are exact; anything
    measured off a file on disk is an estimate from chars-per-token. They must not be conflated,
    and a bounded scan must report itself as bounded — a truncated total presented as a total is
    a wrong number, not a partial one.
  * A MISSING PRICE READ AS FREE. An unpriced model still contributes tokens, so every dollar
    figure silently under-reports. That must surface as a finding, and the ignore list for
    client-side pseudo-models must not be able to swallow a real model id.
  * A CHECK THAT CRIES WOLF. A two-turn session is ~100% cache writes by construction; if the
    finding fires there it fires everywhere and gets scrolled past.
  * AN ABSENT LEDGER READ AS "NOTHING HAPPENED". Absence of record is not evidence of absence —
    the same rule the tool-call gate is built on.
  * DATA LEAVING THE MACHINE. The pages render case data with no authentication, so a
    non-loopback bind must be refused unless someone explicitly opted in.
  * A READER CRASH KILLING THE SERVER, or an unknown URL reaching an arbitrary module attribute.

Everything is offline: synthetic transcripts in a temp dir, an in-process HTTP request against
the real handler. No network, no case data (contributor RULE 1).
"""
import glob
import io
import json
import contextlib
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "harness", "dashboard"))

import collect as C  # noqa: E402
import serve as S  # noqa: E402


def _usage(inp=0, out=0, read=0, w1h=0, w5m=0):
    return {"input_tokens": inp, "output_tokens": out, "cache_read_input_tokens": read,
            "cache_creation": {"ephemeral_1h_input_tokens": w1h,
                               "ephemeral_5m_input_tokens": w5m}}


def _turn(model="claude-opus-5", **kw):
    return {"type": "assistant", "timestamp": "2026-08-10T10:00:00Z",
            "message": {"model": model, "usage": _usage(**kw), "content": []}}


def write_transcript(d, name, turns, extra=()):
    with open(os.path.join(d, name + ".jsonl"), "w", encoding="utf-8") as f:
        for rec in list(turns) + list(extra):
            f.write(json.dumps(rec) + "\n")


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    tmp = tempfile.mkdtemp(prefix="dash-test-")
    saved_env = os.environ.get("CLAUDE_PROJECT_DIR")
    os.environ["CLAUDE_PROJECT_DIR"] = tmp
    try:
        # --- 1. exact vs estimated, and the cache ratios --------------------------------------
        m = C.cache_metrics({"input": 100, "cache_read": 800, "cache_write_1h": 100,
                             "cache_write_5m": 0, "output": 5000})
        ok(m["input_side_tokens"] == 1000,
           "input-side total excludes output (output is the work, not the overhead)")
        ok(abs(m["cache_read_share"] - 0.8) < 1e-9, "cache_read_share is read / input-side")
        ok(abs(m["cache_write_share"] - 0.1) < 1e-9, "cache_write_share is write / input-side")
        ok(C.est_tokens(4000) == int(round(4000 / C.CHARS_PER_TOKEN)),
           "est_tokens divides by the configured chars-per-token")

        # --- 2. a transcript is summarised exactly ---------------------------------------------
        write_transcript(tmp, "aaaaaaaa-0000-0000-0000-000000000001", [
            _turn(inp=10, out=100, read=0, w1h=1000),
            _turn(inp=10, out=200, read=1000, w1h=0),
        ], extra=[{"type": "ai-title", "message": "a synthetic session"}])
        idx = C.sessions_index(limit=10)
        s = next(x for x in idx["sessions"] if x["session"].startswith("aaaaaaaa"))
        ok(s["turns"] == 2, "both billed turns counted")
        ok(s["toks"]["output"] == 300, "output tokens summed exactly")
        ok(s["toks"]["cache_read"] == 1000 and s["toks"]["cache_write_1h"] == 1000,
           "cache read and 1h-write kept as distinct tiers (different prices)")
        ok(s["max_context"] == 1010,
           "peak context is the largest single turn's input-side total, not the sum")
        ok(s["cost"] > 0, "a priced model produces a non-zero cost estimate")
        ok(s["title"] == "a synthetic session", "the session title is read from the transcript")

        # Per-iteration accounting: a fallback bills two models in ONE turn.
        write_transcript(tmp, "aaaaaaaa-0000-0000-0000-000000000002", [{
            "type": "assistant", "timestamp": "2026-08-10T10:00:00Z",
            "message": {"model": "claude-opus-5", "content": [], "usage": {
                "input_tokens": 0, "output_tokens": 0,
                "iterations": [
                    {"model": "claude-opus-5", **_usage(out=100)},
                    {"model": "claude-haiku-4-5", **_usage(out=50)},
                ]}}}])
        s2 = C.summarise_transcript(os.path.join(tmp, "aaaaaaaa-0000-0000-0000-000000000002.jsonl"))
        ok(set(s2["models"]) == {"claude-opus-5", "claude-haiku-4-5"},
           "a two-model turn is billed per iteration, not collapsed to the outer model")
        ok(s2["toks"]["output"] == 150, "per-iteration output tokens are summed")
        ok(all(v["turns"] == 1 for v in s2["models"].values()),
           "both models are credited with the one turn they took part in")

        # --- 3. a bounded scan says it is bounded -----------------------------------------------
        for i in range(6):
            write_transcript(tmp, f"bbbbbbbb-0000-0000-0000-00000000000{i}", [_turn(out=10)])
        small = C.sessions_index(limit=2)
        ok(small["sessions_scanned"] == 2, "the scan honours its limit")
        ok(small["truncated"] is True, "a bounded scan is flagged truncated")
        ok("not all-time" in small["note"] or "ONLY" in small["note"],
           "the note says the totals cover only the scanned window")
        full = C.sessions_index(limit=500)
        ok(full["truncated"] is False and "All" in full["note"],
           "an exhaustive scan says so instead of implying a cap")

        # --- 4. the findings engine -------------------------------------------------------------
        # A short session is ~100% cache writes by construction — it must NOT fire.
        write_transcript(tmp, "cccccccc-0000-0000-0000-000000000001",
                         [_turn(out=10, w1h=9000), _turn(out=10, w1h=9000)])
        f = C.findings(limit=50)
        short = [x for x in f["findings"]
                 if x["check"] == "cache_write_share" and "cccccccc" in (x["where"] or "")]
        ok(not short, "a 2-turn session does not trip the cache-write check (min_turns guard)")

        # A long session that keeps re-writing the cache MUST fire.
        write_transcript(tmp, "dddddddd-0000-0000-0000-000000000001",
                         [_turn(out=10, w1h=9000, read=100) for _ in range(10)])
        f = C.findings(limit=50)
        churn = [x for x in f["findings"]
                 if x["check"] == "cache_write_share" and "dddddddd" in (x["where"] or "")]
        ok(churn, "a long session dominated by cache WRITES trips the churn check")
        ok(churn and churn[0]["why"], "every finding carries the why from the reference file")

        # An unpriced model is a finding, because its tokens make every total an under-estimate.
        write_transcript(tmp, "eeeeeeee-0000-0000-0000-000000000001",
                         [_turn(model="claude-not-a-real-model", out=50_000)])
        f = C.findings(limit=50)
        unp = [x for x in f["findings"] if x["check"] == "unpriced_model"]
        ok(unp, "an unpriced model is surfaced (its tokens silently under-report cost)")
        ok(unp and "claude-not-a-real-model" in unp[0]["title"], "the finding names the model")
        ignore = set((C.HEALTH.get("unpriced_model") or {}).get("ignore") or [])
        ok("<synthetic>" in ignore, "the client's synthetic pseudo-model is on the ignore list")
        ok(not any(i.startswith("claude-") for i in ignore),
           "no real model id is on the ignore list (that would hide real spend)")

        # Findings collapse rather than repeating one lesson N times — and say how many folded.
        for i in range(12):
            write_transcript(tmp, f"ffffffff-0000-0000-0000-0000000000{i:02d}",
                             [_turn(out=10, w1h=9000, read=100) for _ in range(10)])
        f = C.findings(limit=60)
        cw = [x for x in f["findings"] if x["check"] == "cache_write_share"]
        cap = int(C.SCAN.get("max_findings_per_check", 5))
        ok(len(cw) <= cap + 1, f"repeats collapse to at most {cap} rows (+1 summary)")
        ok(any("more session" in x["title"] for x in cw),
           "the folded-away count is stated rather than silently dropped")
        ok(f["raw_findings"] >= len(f["findings"]),
           "the raw finding count is reported alongside the collapsed list")

        # --- 5. absent ledger = absence of RECORD ----------------------------------------------
        saved_sources = dict(C.SOURCES)
        try:
            C.SOURCES["tool_calls_ledger"] = "MEMORY/does-not-exist.jsonl"
            C.SOURCES["tool_calls_per_case"] = "cases/__none__/tool_calls.jsonl"
            t = C.tool_calls()
            ok(t["have_ledger"] is False, "a missing ledger is reported as missing")
            ok("ABSENCE OF RECORD" in t["note"],
               "an absent ledger is absence of RECORD, never 'nothing happened'")
            ok(t["total"] == 0 and t["rows"] == [], "no rows are invented for a missing ledger")
        finally:
            C.SOURCES.clear()
            C.SOURCES.update(saved_sources)

        # --- 6. the prompt surface is labelled as an estimate ------------------------------------
        p = C.prompt_surface()
        ok(all("est_tokens" in r for r in p["files"]),
           "file sizes are exposed as est_tokens, never as a token count")
        ok(not any(str(ph["phase"]).startswith("_") for ph in p["phases"]),
           "documentation keys are not rendered as phases")
        ok(all(isinstance(ph["parts"], list) for ph in p["phases"]),
           "every phase lists the files it pins")
        ok("ESTIMATE" in p["note"].upper(), "the panel states that its numbers are estimates")
        ok(p["files"] == sorted(p["files"], key=lambda r: -r["bytes"]),
           "the biggest always-loaded file is listed first")

        # --- 6b. the TRACE: what the agent actually did -----------------------------------------
        # The panel that answers "what did it DO" rather than "how much did it cost". Its whole
        # value is that the arguments and the raw result shown belong to the call above them and
        # are not quietly shortened — both are checked here.
        big = "R" * 9000
        write_transcript(tmp, "77777777-0000-0000-0000-000000000001", [
            {"type": "user", "timestamp": "2026-08-10T10:00:00Z", "isMeta": True,
             "message": {"role": "user", "content": "<system-reminder>pinned</system-reminder>"}},
            {"type": "user", "timestamp": "2026-08-10T10:00:01Z",
             "message": {"role": "user", "content": [
                 {"type": "text", "text": "analyse site-a.example"},
                 {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                              "data": "SCREENSHOTBYTES" * 500}}]}},
            {"type": "assistant", "timestamp": "2026-08-10T10:00:02Z", "effort": "high",
             "message": {"role": "assistant", "model": "claude-opus-5", "usage": _usage(out=40),
                         "content": [
                             {"type": "thinking", "thinking": "", "signature": "abc"},
                             {"type": "tool_use", "id": "toolu_1", "name": "mcp__intel__pivot",
                              "input": {"url": "site-a.example"}},
                             {"type": "tool_use", "id": "toolu_2", "name": "Bash",
                              "input": {"command": "echo hi"}}]}},
            {"type": "user", "timestamp": "2026-08-10T10:00:03Z",
             "toolUseResult": {"stdout": "ignored", "stderr": "a warning"},
             "message": {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": "toolu_1", "content": big}]}},
            {"type": "assistant", "timestamp": "2026-08-10T10:00:04Z",
             "message": {"role": "assistant", "model": "claude-opus-5", "usage": _usage(out=20),
                         "content": [{"type": "text", "text": "one operator, medium confidence"}]}},
        ], extra=[{"type": "ai-title", "aiTitle": "a replayed case"},
                  {"type": "last-prompt", "lastPrompt": "analyse site-a.example"}])

        tr = C.session_trace("77777777-0000-0000-0000-000000000001")
        kinds = [s["kind"] for s in tr["steps"]]
        ok(kinds == ["context", "user", "tool", "tool", "assistant"],
           f"the replay is in order and the tool_result record is folded into its call ({kinds})")
        ok(tr["summary"]["title"] == "a replayed case",
           "the session title is read from the key Claude Code actually writes (aiTitle)")
        ok(tr["summary"]["first_prompt"] == "analyse site-a.example",
           "the first prompt is read from lastPrompt, not an assumed key")
        ctx, usr = tr["steps"][0], tr["steps"][1]
        ok(ctx["kind"] == "context" and usr["text"]["text"] == "analyse site-a.example",
           "injected context is separated from what the human typed")
        t1 = tr["steps"][2]
        ok(t1["name"] == "mcp__intel__pivot" and "site-a.example" in t1["args"]["text"],
           "a tool step carries the ARGUMENTS the call was made with")
        ok(t1["result_chars"] == len(big) and t1["result"]["truncated"] is True,
           "the result is paired to its call by tool_use_id and bounded for display")
        ok(t1["result"]["dropped"] > 0
           and t1["result"]["dropped"] + t1["result"]["kept"] == t1["result"]["chars"],
           "a display cut states exactly how much it dropped — the numbers reconcile")
        ok(bool(t1["result"].get("tail")),
           "head AND tail are kept, so the end of a long result is still visible")
        ok(t1["stderr"] == "a warning",
           "stderr from the structured payload survives onto the step")
        t2 = tr["steps"][3]
        ok(t2["pending"] is True and t2["result_chars"] == 0,
           "a call with no recorded result is marked pending, not shown as an empty result")
        ok(t1.get("turn") and t2.get("turn") is None,
           "the turn's tokens are attached ONCE, not repeated on every call it made")
        ok(tr["steps"][4]["thinking_redacted"] is False
           and tr["steps"][2]["turn"]["effort"] == "high",
           "per-turn effort is carried through to the step")
        asst = [s for s in tr["steps"] if s["kind"] == "assistant"][0]
        ok("one operator" in asst["text"]["text"], "the reply text is in the replay")

        # An empty `thinking` string with a signature is ENCRYPTED reasoning, not an absent
        # thought. Reporting "no thinking" there would be a false statement about the run.
        thinker = [s for s in tr["steps"] if s["kind"] == "tool"]
        ok(all("thinking" not in s for s in thinker), "tool steps do not carry a thinking field")

        # A base64 screenshot is described, never inlined — otherwise the trace payload is
        # larger than the transcript it summarises.
        blob = json.dumps(tr, default=str)
        ok("SCREENSHOTBYTESSCREENSHOTBYTES" not in blob,
           "base64 image data is NOT inlined into the trace payload")
        ok(any(a.get("kind") == "image" and a.get("bytes", 0) > 1000
               for a in (usr.get("attachments") or [])),
           "the image is reported with its size instead")

        # The expand behind a truncation marker returns the FULL value.
        full = C.trace_step("77777777-0000-0000-0000-000000000001", "toolu_1")
        ok(full["result"]["chars"] == len(big) and full["result"]["truncated"] is False,
           "expanding a step re-reads the whole result from the transcript")
        ok(C.trace_step("77777777-0000-0000-0000-000000000001", "nope").get("error"),
           "an unknown step id returns an error payload rather than raising")

        # The gate badge is an EXACT (tool, args) join. A fuzzy one would put an ALLOW or a DENY
        # on the wrong call, which is worse than showing no badge at all.
        led = os.path.join(tmp, "ledger.jsonl")
        with open(led, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": "2026-08-10T10:00:02Z", "tool": "pivot",
                                 "args": {"url": "site-a.example"}, "decision": "DENY",
                                 "classes": ["outbound"], "reason": "hostile scope"}) + "\n")
            fh.write(json.dumps({"ts": "2026-08-10T10:00:02Z", "tool": "Bash",
                                 "args": {"command": "echo OTHER"}, "decision": "allow"}) + "\n")
        saved_sources = dict(C.SOURCES)
        try:
            C.SOURCES["tool_calls_ledger"] = led
            C.SOURCES["tool_calls_per_case"] = "cases/__none__/tool_calls.jsonl"
            tg = C.session_trace("77777777-0000-0000-0000-000000000001")
            g1, g2 = tg["steps"][2]["gate"], tg["steps"][3]["gate"]
            ok(g1 and g1["decision"] == "DENY",
               "a ledger row matching tool AND exact arguments annotates the call")
            ok(g2 is None,
               "the same tool with DIFFERENT arguments gets no badge — no invented decision")
        finally:
            C.SOURCES.clear()
            C.SOURCES.update(saved_sources)

        # One API RESPONSE, several transcript records, the SAME usage repeated on each: bill it
        # once. Counting per record multiplies a tool-heavy turn's tokens and cost while every
        # row still looks individually plausible — the most expensive kind of wrong number.
        write_transcript(tmp, "88888888-0000-0000-0000-000000000001", [
            {"type": "assistant", "timestamp": "2026-08-10T10:00:00Z", "requestId": "req_1",
             "uuid": "u1", "message": {"role": "assistant", "model": "claude-opus-5",
                                       "id": "msg_1", "usage": _usage(out=500, read=1000),
                                       "content": [{"type": "thinking", "thinking": "hm"}]}},
            {"type": "assistant", "timestamp": "2026-08-10T10:00:00Z", "requestId": "req_1",
             "uuid": "u2", "message": {"role": "assistant", "model": "claude-opus-5",
                                       "id": "msg_1", "usage": _usage(out=500, read=1000),
                                       "content": [{"type": "tool_use", "id": "tu_a",
                                                    "name": "Read", "input": {"p": 1}}]}},
            {"type": "assistant", "timestamp": "2026-08-10T10:00:00Z", "requestId": "req_1",
             "uuid": "u3", "message": {"role": "assistant", "model": "claude-opus-5",
                                       "id": "msg_1", "usage": _usage(out=500, read=1000),
                                       "content": [{"type": "tool_use", "id": "tu_b",
                                                    "name": "Bash", "input": {"c": "ls"}}]}},
            # a subagent's own turn — same run, separate thread of work
            {"type": "assistant", "timestamp": "2026-08-10T10:00:05Z", "requestId": "req_2",
             "uuid": "u4", "isSidechain": True,
             "message": {"role": "assistant", "model": "claude-opus-5", "id": "msg_2",
                         "usage": _usage(out=10), "content": [{"type": "text", "text": "sub"}]}},
        ])
        dup = C.summarise_transcript(
            os.path.join(tmp, "88888888-0000-0000-0000-000000000001.jsonl"))
        ok(dup["turns"] == 2,
           f"3 records of ONE response + 1 subagent response = 2 billed turns (got {dup['turns']})")
        ok(dup["toks"]["output"] == 510 and dup["toks"]["cache_read"] == 1000,
           "a response split across records is billed once, not once per record")
        ok(dup["tool_calls"] == 2,
           "every tool call in the response is still counted — the dedupe is on billing only")
        ok(dup["sidechain_turns"] == 1, "the subagent's turn is counted as a subagent turn")
        det = C.session_detail("88888888-0000-0000-0000-000000000001")
        ok(len(det["turns"]) == 2, "the turn table has one row per API response")
        ok(sorted(det["turns"][0]["tool_calls"]) == ["Bash", "Read"],
           "the continuation records are MERGED into that row, so their tool calls survive")
        trd = C.session_trace("88888888-0000-0000-0000-000000000001")
        with_turn = [s for s in trd["steps"] if s.get("turn")]
        ok(len(with_turn) == 2,
           "in the replay the turn's cost is shown once, not under every call it made")
        ok(any(s.get("sidechain") for s in trd["steps"]),
           "a subagent step is flagged so it can be set apart from the main thread")

        # A bounded replay says it is bounded.
        saved_max = C.TRACE.get("max_steps")
        try:
            C.TRACE["max_steps"] = 2
            short_tr = C.session_trace("77777777-0000-0000-0000-000000000001")
            ok(len(short_tr["steps"]) == 2 and short_tr["truncated"] is True,
               "a step cap is honoured and reported as truncated, not presented as the whole run")
        finally:
            C.TRACE["max_steps"] = saved_max
        ok(C.session_trace("no-such-session").get("error"),
           "a missing session returns an error payload rather than raising")

        # --- 7. HTTP surface: allowlist, error isolation, no crash ------------------------------
        ok(set(S.VIEWS) == {"overview", "findings", "sessions", "session", "trace", "step",
                            "tools", "credits", "runs", "prompts"},
           "the URL space is an explicit allowlist, not attribute lookup on the module")
        ok(all(callable(fn) for fn, _ in S.VIEWS.values()), "every view maps to a reader")
        ok(S._coerce("limit", "not-a-number") is None,
           "a non-numeric limit is dropped rather than raising")
        ok(S._coerce("limit", "-5") == 1, "a negative limit is clamped, never passed through")
        ok(S._coerce("denied", "true") is True, "boolean params are coerced")

        # --- 8. opsec: loopback only unless explicitly opted in ----------------------------------
        ok(C.SERVER.get("allow_nonlocal_bind") is False,
           "the reference file ships with non-loopback binding disabled")
        ok(C.SERVER.get("host") in ("127.0.0.1", "::1", "localhost"),
           "the default bind is loopback")
        src = open(os.path.join(ROOT, "harness", "dashboard", "serve.py"), encoding="utf-8").read()
        ok("allow_nonlocal_bind" in src and "sys.exit(" in src,
           "the server refuses a non-loopback bind rather than warning and continuing")
        ok("ssh -N -L" in src, "the refusal names the safe alternative (an SSH tunnel)")

        # The UI must not interpolate ledger values into markup.
        # The hazard is ASSIGNING markup, not the word appearing in a comment — match the sinks.
        app = open(os.path.join(ROOT, "harness", "dashboard", "static", "app.js"),
                   encoding="utf-8").read()
        sinks = re.findall(r"\b(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|"
                           r"document\.write\s*\(", app)
        ok(not sinks,
           f"the UI never writes markup from data (no innerHTML/outerHTML/insertAdjacentHTML "
           f"assignment) — captured case data is rendered as text{': ' + str(sinks) if sinks else ''}")
        ok("textContent" in app, "the UI sets textContent for ledger values")

        # --- 9. every reader survives an empty world --------------------------------------------
        empty = tempfile.mkdtemp(prefix="dash-empty-")
        os.environ["CLAUDE_PROJECT_DIR"] = empty
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                idx0 = C.sessions_index()
                ov = C.overview()
            ok(idx0["sessions"] == [] and idx0["sessions_total"] == 0,
               "an empty transcript dir yields an empty list, not an exception")
            ok(ov["claude_code"]["turns"] == 0, "the overview renders with no sessions at all")
            ok(C.session_detail("nope").get("error"),
               "a missing session returns an error payload rather than raising")
        finally:
            shutil.rmtree(empty, ignore_errors=True)
            os.environ["CLAUDE_PROJECT_DIR"] = tmp

        # --- 10. static assets exist (a 404 UI is a broken tool) ----------------------------------
        for asset in ("index.html", "app.js", "style.css"):
            ok(os.path.exists(os.path.join(ROOT, "harness", "dashboard", "static", asset)),
               f"static/{asset} is present")
        ok(glob.glob(os.path.join(ROOT, "harness", "references", "dashboard.json")),
           "the reference data file is present")
        ok(len(C.HEALTH) >= 5, f"health checks come from the data file ({len(C.HEALTH)} loaded)")
        ok(len(C.HEALTH) > len(C._FALLBACK["health_checks"]),
           "health checks are loaded from dashboard.json, not the embedded fallback")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if saved_env is None:
            os.environ.pop("CLAUDE_PROJECT_DIR", None)
        else:
            os.environ["CLAUDE_PROJECT_DIR"] = saved_env

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
