#!/usr/bin/env python3
"""
serve.py — the local debug dashboard. Python stdlib only; no framework, no build step.

    python3 harness/dashboard/serve.py            # → http://127.0.0.1:7788
    python3 harness/dashboard/serve.py --port 9000 --no-browser
    python3 harness/dashboard/serve.py --sessions 200      # scan more history

WHAT IT SERVES
--------------
`/`            the single-page UI (static/)
`/api/<view>`  JSON from collect.py — overview · sessions · session · trace · step · tools ·
               credits · runs · prompts · findings

`trace` is the replay of one session — the prompt in, every tool call with its arguments and
the raw result that came back, the reply out — and `step` re-reads one call's full payload
behind a truncation marker.

Everything is read-only. The process never writes to `cases/`, `MEMORY/`, or the transcript
store, and never makes an outbound request — a debug tool that mutates the evidence it is
inspecting is worse than no tool.

OPSEC — WHY IT BINDS TO LOOPBACK AND STAYS THERE
------------------------------------------------
The pages render investigation data: case names, target domains, operator artifacts, and the
full text of prompts. There is no authentication and there will not be one; the correct way to
reach this from another machine is an SSH tunnel, not a password box on a debug server. A
non-loopback bind is refused unless `server.allow_nonlocal_bind` in
`harness/references/dashboard.json` is explicitly flipped, and the refusal says why.
"""
from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import socketserver
import sys
import threading
import traceback
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import collect as C  # noqa: E402

STATIC = os.path.join(HERE, "static")

#: view name -> (reader, allowed query params). Anything not listed is a 404 — the URL space is
#: an allowlist so a typo can't reach an arbitrary attribute of the module.
VIEWS = {
    "overview": (C.overview, ("limit",)),
    "findings": (C.findings, ("limit",)),
    "sessions": (C.sessions_index, ("limit",)),
    "session": (C.session_detail, ("session",)),
    "trace": (C.session_trace, ("session", "limit")),
    "step": (C.trace_step, ("session", "id")),
    "tools": (C.tool_calls, ("case", "denied", "limit")),
    "credits": (C.api_credits, ()),
    "runs": (C.run_costs, ()),
    "prompts": (C.prompt_surface, ()),
}

_INT_PARAMS = {"limit"}
_BOOL_PARAMS = {"denied"}


def _coerce(name: str, raw: str):
    if name in _INT_PARAMS:
        try:
            return max(1, int(raw))
        except ValueError:
            return None
    if name in _BOOL_PARAMS:
        return raw.lower() in ("1", "true", "yes", "on")
    return raw


class Handler(http.server.SimpleHTTPRequestHandler):
    """Static files from static/, JSON from /api/<view>."""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def log_message(self, fmt, *args):     # quieter than the default one-line-per-asset
        if self.path.startswith("/api/"):
            sys.stderr.write("  %s\n" % (fmt % args))

    def _json(self, payload, status=200):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # A debug page rendering case data: keep it out of caches and out of frames.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                       # noqa: N802 — BaseHTTPRequestHandler's name
        path, _, query = self.path.partition("?")
        if not path.startswith("/api/"):
            return super().do_GET()

        view = path[len("/api/"):].strip("/")
        entry = VIEWS.get(view)
        if not entry:
            return self._json({"error": f"unknown view {view!r}",
                               "views": sorted(VIEWS)}, status=404)
        fn, allowed = entry

        kwargs = {}
        for pair in query.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            k = k.strip()
            if k not in allowed:
                continue
            from urllib.parse import unquote_plus
            val = _coerce(k, unquote_plus(v))
            if val is not None:
                kwargs[k] = val

        try:
            return self._json(fn(**kwargs))
        except TypeError as e:              # a required param (e.g. ?session=) was missing
            return self._json({"error": str(e), "expects": list(allowed)}, status=400)
        except Exception as e:              # noqa: BLE001 — a reader crash must not kill the server
            traceback.print_exc()
            return self._json({"error": f"{type(e).__name__}: {e}",
                               "note": "the reader raised; the server is still up. See stderr "
                                       "for the traceback."}, status=500)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--host", default=C.SERVER.get("host", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(C.SERVER.get("port", 7788)))
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--sessions", type=int, default=None,
                    help="how many recent transcripts the default scan reads "
                         f"(default {C.SCAN.get('default_sessions', 40)})")
    args = ap.parse_args()

    if args.sessions:
        C.SCAN["default_sessions"] = max(1, args.sessions)

    local = args.host in ("127.0.0.1", "::1", "localhost")
    if not local and not C.SERVER.get("allow_nonlocal_bind"):
        sys.exit(
            f"refusing to bind {args.host}: this dashboard renders investigation data "
            f"(case names, target domains, operator artifacts, full prompt text) and has no "
            f"authentication. Reach it from another machine with an SSH tunnel:\n"
            f"    ssh -N -L {args.port}:127.0.0.1:{args.port} <this-host>\n"
            f"If you genuinely need a non-loopback bind, set server.allow_nonlocal_bind=true "
            f"in harness/references/dashboard.json and accept that anyone who can route to "
            f"this port can read the case data.")

    url = f"http://{args.host}:{args.port}/"
    d = C.transcript_dir()
    print(f"debug dashboard → {url}", file=sys.stderr)
    print(f"  repo         {C.ROOT}", file=sys.stderr)
    print(f"  transcripts  {d}" + ("" if os.path.isdir(d) else "   (NOT FOUND — the Claude Code "
                                   "panels will be empty; set CLAUDE_PROJECT_DIR)"),
          file=sys.stderr)
    print(f"  pricing      {'loaded' if C._PRICING_OK else 'UNAVAILABLE — all costs read $0.00'}",
          file=sys.stderr)
    print("  read-only · loopback · Ctrl-C to stop", file=sys.stderr)

    with Server((args.host, args.port), Handler) as httpd:
        if C.SERVER.get("open_browser", True) and not args.no_browser:
            threading.Timer(0.4, functools.partial(webbrowser.open, url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
