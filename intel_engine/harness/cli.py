#!/usr/bin/env python3
"""intel — one console entrypoint for the OSINT harness.

    intel open     CASE  <seed-url> ...        # one Collect→Correlate→Assess round
    intel continue CASE  <seed-url> ...        # iterate to convergence (--continue)
    intel status   [CASE]                      # case state, NO LLM, NO API key
    intel approve  CASE [--only ids|--all] [--reject ids] [--show]
                                               # cross-type loop: approve this round's proposal

`open` / `continue` are thin wrappers over `orchestrator.py` — every extra flag
(`--hostile`, `--parallel`, `--depth N`, `--collect-conc N`, …) is passed straight
through, so the CLI never has to know about them. `status` reads the git-ignored
`cases/` store directly (stdlib only): it does not import the Agent SDK and spends
no tokens, so it works with no `ANTHROPIC_API_KEY` and while a run is in flight.

Run it via the repo-root `intel` shim (`./intel status`) or `python3 harness/cli.py …`.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))            # harness/
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)                                 # repo root
CASES = os.path.join(ROOT, "cases")


# ---------------------------------------------------------------- open / continue
FAILOVER_MODES = ("ask", "auto", "off")


def _failover_mode(rest: list[str]) -> str:
    """--failover ask|auto|off (stripped from the passthrough), else HARNESS_FAILOVER, else `ask`
    on an interactive terminal and `off` for cron/CI (nobody to answer the prompt)."""
    mode = os.environ.get("HARNESS_FAILOVER", "").strip().lower()
    if "--failover" in rest:
        i = rest.index("--failover")
        mode = (rest[i + 1] if i + 1 < len(rest) else "").strip().lower()
        del rest[i:i + 2]
    if mode not in FAILOVER_MODES:
        mode = "ask" if sys.stdin.isatty() else "off"
    return mode


def _confirm(question: str) -> bool:
    try:
        ans = input(f"{question} [Y/n] ").strip().lower()
    except EOFError:
        return False
    return ans in ("", "y", "yes")


def _run_orchestrator(passthrough: list[str], *, cont: bool) -> int:
    """Forward to orchestrator.py verbatim (inserting --continue for `continue`). cwd=ROOT so the
    harness's .env discovery — which starts at the invocation cwd — finds the repo-root keys.

    FAILOVER: the orchestrator picks the backend itself (backend_select: the host agent first, then
    claude → codex → omp → an OpenAI key, each probed with one tiny request). If that backend dies
    MID-RUN on a login / credit / rate-limit error, the orchestrator exits FAILOVER_EXIT; this loop
    then probes the remaining backends, asks (or not — see _failover_mode) and re-runs the SAME
    command on the next one. The case resumes: collected pivots are cached, so nothing is re-bought."""
    import backend_select as bs
    if not passthrough:
        sys.exit("need a CASE id and at least one seed url")
    case, rest = passthrough[0], list(passthrough[1:])
    mode = _failover_mode(rest)
    cmd = [sys.executable, os.path.join(HERE, "orchestrator.py"), case]
    if cont:
        cmd.append("--continue")
    cmd += rest
    env = dict(os.environ)
    failed: list[str] = []
    fd, signal_file = tempfile.mkstemp(prefix="intel-failover-", suffix=".json")
    os.close(fd)
    try:
        while True:
            if os.path.exists(signal_file):
                os.remove(signal_file)
            env["HARNESS_FAILOVER_FILE"] = signal_file
            rc = subprocess.run(cmd, cwd=ROOT, env=env).returncode
            if rc != bs.FAILOVER_EXIT:
                # Cross-type loop stopped at awaiting-approval: on an interactive terminal, show the
                # proposal, record the analyst's choice and resume; headless runs keep the
                # checkpoint for `intel approve` / the case_approve tool.
                if rc == 0 and sys.stdin.isatty() and _tty_approve(case):
                    if "--continue" not in cmd:
                        cmd.insert(3, "--continue")
                    continue
                return rc
            info = bs.read_failover(signal_file)
            failed.append(info.get("backend") or env.get("HARNESS_BACKEND") or "?")
            bs.mark_failed(failed[-1], info.get("reason") or "backend unavailable")
            print(f"\n[failover] {failed[-1]} stopped: {info.get('reason', 'backend unavailable')}",
                  file=sys.stderr)
            if mode == "off":
                print("[failover] off (non-interactive). Re-run with HARNESS_BACKEND=<other> or "
                      "--failover auto to switch automatically.", file=sys.stderr)
                return rc
            print(f"[failover] checking the other backends (tried: {', '.join(failed)}) …", file=sys.stderr)
            saved = os.environ.pop("HARNESS_BACKEND", None)
            try:
                nxt, why, tried = bs.resolve(exclude=failed)
            except SystemExit as e:
                print(f"[failover] {e}", file=sys.stderr)
                return rc
            finally:
                if saved is not None:
                    os.environ["HARNESS_BACKEND"] = saved
            for n, ok, w in tried:
                if not ok:
                    print(f"[failover]   ✗ {n}: {w}", file=sys.stderr)
            if mode == "ask" and not _confirm(f"[failover] {nxt} is usable ({why}). Resume case {case} on {nxt}?"):
                print(f"[failover] not switching. Resume later with: HARNESS_BACKEND={nxt} "
                      f"python3 scripts/backend/intel.py harness {'continue' if cont else 'open'} "
                      f"{case} …", file=sys.stderr)
                return rc
            print(f"[failover] resuming {case} on {nxt}", file=sys.stderr)
            env["HARNESS_BACKEND"] = nxt
    finally:
        if os.path.exists(signal_file):
            os.remove(signal_file)


# ---------------------------------------------------------------- approve (cross-type loop)
def _tty_approve(case: str) -> bool:
    """Interactive approval of a pending proposal. True when something was approved (resume)."""
    import proposal as P
    data = P.load(ROOT, case)
    if not data or data.get("status") != "pending" or not data.get("items"):
        return False
    print("\n" + P.render(data), file=sys.stderr)
    try:
        ans = input("approve which ids? [all / id,id,… / none] ").strip().lower()
    except EOFError:
        return False
    if ans in ("", "none", "n", "no"):
        print(f"[approve] nothing approved; resume later with: intel approve {case} --only <ids>",
              file=sys.stderr)
        return False
    res = (P.approve(ROOT, case, approve_all=True) if ans in ("all", "a", "y", "yes")
           else P.approve(ROOT, case, only=[x.strip() for x in ans.replace(" ", ",").split(",") if x.strip()]))
    if res.get("error"):
        print(f"[approve] {res['error']}", file=sys.stderr)
        return False
    print(f"[approve] approved {len(res.get('approved') or [])} item(s); resuming {case}", file=sys.stderr)
    return bool(res.get("approved"))


def _cmd_approve(case: str, only: list[str], reject: list[str], approve_all: bool, show: bool) -> int:
    import proposal as P
    data = P.load(ROOT, case)
    if show or not (only or reject or approve_all):
        print(P.render(data or {}))
        return 0 if data else 1
    res = P.approve(ROOT, case, only=only, reject=reject, approve_all=approve_all)
    if res.get("error"):
        print(f"approve: {res['error']}", file=sys.stderr)
        return 1
    print(f"approved {len(res.get('approved') or [])} · rejected {len(res.get('rejected') or [])} · "
          f"deferred {len(res.get('deferred') or [])} (deferred items come back next round) — "
          f"resume with: intel continue {case}")
    return 0


# ---------------------------------------------------------------- status (no LLM)
def _load_json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001 — a half-written/absent file just means "no data yet"
        return None


def _rounds(case_dir: str) -> list[dict]:
    p = os.path.join(case_dir, "rounds.jsonl")
    if not os.path.exists(p):
        return []
    out = []
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:  # noqa: BLE001
                pass
    return out


def _converged(rounds: list[dict], stale: int = 2) -> bool:
    """Same rule as convergence.py / orchestrator._is_converged: the last `stale` snapshot rounds
    each added zero new hosts and zero new indicators."""
    if len(rounds) < stale:
        return False
    return all(r.get("new_hosts") == 0 and r.get("new_indicators") == 0 for r in rounds[-stale:])


def _latest_assessment(case_dir: str) -> dict | None:
    """The newest immutable snapshot (assessments/<UTC>_r*.json), falling back to the
    back-compat head assessment.json."""
    snaps = sorted(glob.glob(os.path.join(case_dir, "assessments", "*.json")))
    if snaps:
        return _load_json(snaps[-1])
    return _load_json(os.path.join(case_dir, "assessment.json"))


def _wc(path: str) -> int:
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def _case_stat(case: str) -> dict:
    case_dir = os.path.join(CASES, case)
    a = _latest_assessment(case_dir) or {}
    rounds = _rounds(case_dir)
    return {
        "case": case,
        "collected": len(glob.glob(os.path.join(case_dir, "raw", "*.json"))),
        "snapshots": len(glob.glob(os.path.join(case_dir, "assessments", "*.json"))),
        "evidence": _wc(os.path.join(case_dir, "evidence", "manifest.jsonl")),
        "attribution": a.get("attribution_level", "—"),
        "confidence": a.get("confidence", "—"),
        "cluster": len(a.get("cluster") or []),
        "bluf": (a.get("bluf") or "").replace("\n", " ").strip(),
        "next_pivots": a.get("next_pivots") or [],
        "converged": _converged(rounds),
        "rounds": len(rounds),
    }


def _cmd_status(case: str | None) -> int:
    if not os.path.isdir(CASES):
        print("no cases/ store yet.")
        return 0

    # No case → one line per case (a fleet view).
    if not case:
        cases = sorted(d for d in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, d)))
        if not cases:
            print("no cases yet.")
            return 0
        print(f"{'CASE':<28} {'DOM':>4} {'RND':>4} {'ATTRIB/CONF':<20} {'CONV':<5} BLUF")
        for c in cases:
            s = _case_stat(c)
            conv = "yes" if s["converged"] else ("—" if not s["rounds"] else "no")
            print(f"{c:<28} {s['collected']:>4} {s['snapshots']:>4} "
                  f"{(s['attribution'] + '/' + s['confidence']):<20} {conv:<5} {s['bluf'][:60]}")
        return 0

    # One case → the detail view.
    if not os.path.isdir(os.path.join(CASES, case)):
        print(f"no such case: {case}  (looked in {os.path.relpath(os.path.join(CASES, case), ROOT)})")
        return 1
    s = _case_stat(case)
    print(f"# {case}")
    print(f"  domains collected : {s['collected']}")
    print(f"  assessment rounds : {s['snapshots']}"
          + (f"   (converged after {s['rounds']} snapshot round(s))" if s["converged"]
             else (f"   ({s['rounds']} snapshot round(s), not converged)" if s["rounds"] else "")))
    print(f"  attribution       : {s['attribution']} / {s['confidence']}"
          + (f"   ({s['cluster']} in cluster)" if s["cluster"] else ""))
    print(f"  evidence rows     : {s['evidence']}")
    if s["bluf"]:
        print(f"\n  BLUF: {s['bluf']}")
    if s["next_pivots"]:
        print("\n  next pivots:")
        for p in s["next_pivots"][:8]:
            print(f"    - {p}")
    print(f"\n  files: {os.path.relpath(os.path.join(CASES, case), ROOT)}/"
          f"  (SUMMARY.md · CHANGELOG.md · assessments/ · evidence/)")
    return 0


# ---------------------------------------------------------------- doctor (no LLM phases)
def _cmd_doctor(pin: str | None) -> int:
    """Which LLM backend would `open` run on, and why each other candidate was skipped. Probes
    auth (one tiny request per CLI backend) so a dead login is found HERE, not mid-case."""
    import backend_select as bs
    if pin:
        os.environ["HARNESS_BACKEND"] = pin
    print(f"host agent      : {bs.host_agent() or 'none detected'}")
    print(f"euid            : {os.geteuid() if hasattr(os, 'geteuid') else 'n/a'}"
          + ("  (root — IS_SANDBOX=1 will be set for the Claude CLI)" if bs.is_root() else ""))
    print(f"HARNESS_BACKEND : {os.environ.get('HARNESS_BACKEND') or 'auto'}")
    try:
        name, why, tried = bs.resolve(deep=True)     # doctor: ONE real request each, cached for runs
    except SystemExit as e:
        print(str(e))
        return 1
    for n, ok, w in tried:
        print(f"  {'✓' if ok else '✗'} {n:<8} {w}")
    if not tried:
        avail, w = bs.check(name, deep=True)
        print(f"  {'✓' if avail else '✗'} {name:<8} {w}  (pinned)")
        if not avail:
            print(f"\nselected        : {name} (pinned) — but it is NOT usable: {w}")
            return 1
    print(f"\nselected        : {name} — {why}")
    # What a mid-run failover could switch to (probed now, so the answer is current).
    seen = {n for n, _ok, _w in tried} | {name}
    backups = []
    for n in bs.candidates():
        if n in seen:
            continue
        ok, w = bs.check(n, deep=True)
        backups.append((n, ok, w))
    ready = [n for n, ok, _w in backups if ok]
    for n, ok, w in backups:
        print(f"  {'✓' if ok else '✗'} {n:<8} {w}  (fallback)")
    print(f"fallback        : {', '.join(ready) if ready else 'none ready'}"
          f"  (a mid-run backend failure {'offers these' if ready else 'stops the run'}; "
          f"--failover ask|auto|off)")
    # The per-run path, run here with the SAME interpreter and env as `harness open` — it reads the
    # results just cached above, so this line is what an open/continue started now would use.
    try:
        run_name, run_why, _ = bs.resolve()
    except SystemExit as e:
        run_name, run_why = "none", str(e).splitlines()[0]
    sdk = "yes" if bs.available("claude")[0] or "claude_agent_sdk" in sys.modules else "no"
    print(f"harness open    : {run_name} — {run_why}")
    print(f"interpreter     : {sys.executable}  (Claude SDK importable: {sdk})")
    return 0


# ---------------------------------------------------------------- provider
def _cmd_provider(a) -> int:
    """OrcaRouter Cyber Inference — two explicit ways in, one credential type out.

    `api-key` reads a pasted key (stdin or a hidden prompt, never an argv value, because argv
    lands in shell history and process lists). `oauth` runs OAuth 2.0 + PKCE and stores the
    durable key the exchange returns. Both write to the skill-root `.env` — the store this
    project already uses — and both yield the same `Credential`, so the harness cannot tell
    which was used.
    """
    import orcarouter as orc

    action = a.action
    if action == "status":
        summary = orc.provider_summary()
        cat = None
        if summary.get("credential"):
            cat = orc.fetch_catalog(capability="chat")
        if a.json:
            print(json.dumps({**summary, "catalog": cat.to_dict() if cat else None}, indent=2))
            return 0
        print(f"{summary['label']}  ({summary['id']})")
        print(f"  inference : {summary['api_base_url']}")
        print(f"  auth      : {summary['auth_base_url']}")
        print(f"  default   : {summary['default_model']}   fallback: {summary['fallback_model']}")
        cred = summary.get("credential")
        if not cred:
            print("  credential: none — `intel provider login --method api-key|oauth`")
            return 0
        state = " — NEEDS REAUTHENTICATION (401)" if cred["needs_reauth"] else ""
        print(f"  credential: {cred['masked']}  via {cred['source']}  scope={cred['scope']}{state}")
        if cat is not None:
            flag = " (degraded: verified seed)" if cat.degraded else ""
            print(f"  catalog   : {len(cat.models)} chat models from {cat.source}{flag}")
            if cat.degraded and cat.error:
                print(f"              {cat.error}")
        return 0

    if action == "models":
        cat = orc.fetch_catalog(capability=a.capability, modality=a.modality)
        if a.json:
            print(json.dumps(cat.to_dict(), indent=2))
            return 0
        head = f"{len(cat.models)} {a.capability} models"
        if a.modality:
            head += f" with {a.modality} input"
        print(f"{head} — source: {cat.source}")
        if cat.degraded:
            print(f"  DEGRADED: live catalog unavailable ({cat.error}). Showing the verified "
                  f"fallback; it is not the live account catalog.")
        for m in cat.models:
            mods = ",".join(m.get("input_modalities") or []) or "?"
            print(f"  {m['id']:<40} {mods}")
        return 0

    if action == "logout":
        adapter = orc.ApiKeyAdapter()
        was = adapter.read()
        adapter.clear()
        orc.clear_unauthorized()
        print("removed the stored OrcaRouter credential" if was else "no stored credential")
        return 0

    if action == "login":
        if a.method == "api-key":
            adapter = orc.ApiKeyAdapter()
            if a.key_stdin:
                key = sys.stdin.readline().strip()
            else:
                import getpass
                key = getpass.getpass("Paste your OrcaRouter API key (sk-orca-…): ").strip()
            if not key:
                print("no key supplied", file=sys.stderr)
                return 2
            if not orc.looks_like_key(key):
                print("warning: that does not look like an sk-orca-… key; saving anyway — the "
                      "first real request decides validity", file=sys.stderr)
            cred = adapter.save(key)
            orc.clear_unauthorized()
            print(f"stored {cred.masked} in {orc.env_path()} (chmod 600, gitignored)")
            return 0

        def read_code(url: str) -> str:
            print("Authorize in your browser, then paste the code back here:\n" + url)
            return sys.stdin.readline().strip()

        try:
            cred = orc.connect_with_pkce(flow=a.flow, open_browser=not a.no_browser,
                                         code_reader=read_code if a.flow == "oob" else None)
        except orc.ConnectError as e:
            print(f"login failed ({e.kind}): {e}", file=sys.stderr)
            return 1
        print(f"connected via OAuth 2.0 + PKCE (scope {cred.scope}); stored {cred.masked} in "
              f"{orc.env_path()}")
        return 0

    return 2


# ---------------------------------------------------------------- entry
def main() -> int:
    ap = argparse.ArgumentParser(prog="intel", description="OSINT harness console")
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open", help="one Collect→Correlate→Assess round over the seeds")
    o.add_argument("args", nargs=argparse.REMAINDER, help="CASE <seed-url> ... [orchestrator flags]")
    c = sub.add_parser("continue", help="iterate to convergence (--continue)")
    c.add_argument("args", nargs=argparse.REMAINDER, help="CASE <seed-url> ... [--depth N ...]")
    st = sub.add_parser("status", help="case state (no LLM, no API key)")
    st.add_argument("case", nargs="?", help="a CASE id; omit to list every case")
    dr = sub.add_parser("doctor", help="which LLM backend a run would use (probes auth; no phases)")
    dr.add_argument("--backend", default=None, help="pin claude|codex|omp|openai|deepseek|kimi|local|orcarouter")
    ap_ = sub.add_parser("approve", help="approve/reject the cross-type loop's pending proposal")
    ap_.add_argument("case")
    ap_.add_argument("--only", default="", help="comma-separated proposal ids to approve")
    ap_.add_argument("--reject", default="", help="comma-separated proposal ids to reject")
    ap_.add_argument("--all", action="store_true", dest="approve_all", help="approve every item")
    ap_.add_argument("--show", action="store_true", help="print the proposal and exit")
    pv = sub.add_parser("provider", help="OrcaRouter Cyber Inference: credential, catalog, model choice")
    pv.add_argument("action", choices=("status", "login", "logout", "models"),
                    help="status | login | logout | models")
    pv.add_argument("--method", choices=("api-key", "oauth"), default="oauth",
                    help="login method: paste an existing key, or OAuth 2.0 + PKCE (default)")
    pv.add_argument("--flow", choices=("loopback", "oob"), default="loopback",
                    help="oauth flow: loopback redirect (default) or out-of-band code")
    pv.add_argument("--key-stdin", action="store_true",
                    help="api-key login: read the key from stdin instead of a prompt")
    pv.add_argument("--no-browser", action="store_true", help="print the URL instead of opening it")
    pv.add_argument("--capability", default="chat",
                    choices=("chat", "embedding", "image", "video", "rerank"),
                    help="models: which capability to list (default chat)")
    pv.add_argument("--modality", default=None, help="models: require this input modality (e.g. image)")
    pv.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()

    if a.cmd == "open":
        return _run_orchestrator(a.args, cont=False)
    if a.cmd == "continue":
        return _run_orchestrator(a.args, cont=True)
    if a.cmd == "status":
        return _cmd_status(a.case)
    if a.cmd == "doctor":
        return _cmd_doctor(a.backend)
    if a.cmd == "approve":
        split = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]  # noqa: E731
        return _cmd_approve(a.case, split(a.only), split(a.reject), a.approve_all, a.show)
    if a.cmd == "provider":
        return _cmd_provider(a)
    return 2


if __name__ == "__main__":
    sys.exit(main())
