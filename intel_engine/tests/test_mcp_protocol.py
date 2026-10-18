#!/usr/bin/env python3
"""
test_mcp_protocol.py — the stdio MCP server's wire behaviour, its tool-call ledger, and the
completeness of every tool's inputSchema.

Run:  .venv/bin/python intel_engine/tests/test_mcp_protocol.py   (needs the SDK venv: the
      transcript checks start the real harness/mcp_server.py, which imports harness/tools.py)

WHAT THIS PROTECTS
------------------
* Shutdown: `printf '<request>\\n' | mcp_server.py` closes stdin at once. The loop used to stop on
  EOF and destroy every in-flight handler, so the request got no reply at all.
* Protocol: a batch / scalar / null line, a non-object `params`, a non-string tool name, a missing
  method or a wrong `jsonrpc` must each get the right JSON-RPC error (never a crash, never
  silence); a client RESPONSE must not be answered; initialize must answer with a protocol
  version this server actually speaks; tools/list must carry each tool's annotations.
* Ledger: a lone surrogate or NaN in an argument used to make the ledger write raise, failing a
  call whose tool had nothing wrong with it; and credentials in URL userinfo, query strings,
  nested headers or camelCase/prefixed key names were written to disk in cleartext.
* Schemas: every key a handler reads from `args` must be a declared inputSchema property — an
  undeclared argument exists only in prose a mid-size model does not read.

The gate ledger is redirected to a temporary ROOT for every check here; nothing is written under
intel_engine/MEMORY or intel_engine/cases.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile

ENGINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ENGINE, "harness")
TOOLS_PY = os.path.join(HARNESS, "tools.py")
SERVER_PY = os.path.join(HARNESS, "mcp_server.py")

# Keys a handler reads that are deliberately NOT model-facing arguments. Each needs a reason.
INTERNAL_KEYS: dict[tuple[str, str], str] = {}

# The secrets planted in the redaction checks; none may reach the ledger file.
SECRETS = ("S3cretPass", "abc123", "XYZ", "sk-live-123", "K1-secret", "K2-secret", "T1-secret",
           "B1-secret", "P1-secret", "nested-pw")
SECRET_ARGS = {
    "proxy": "http://alice:S3cretPass@203.0.113.5:80",
    "url": "https://example.com/path?token=abc123&apikey=XYZ&q=ok",
    "headers": {"Authorization": "Bearer sk-live-123", "Accept": "text/html"},
    "apiKey": "K1-secret", "x_api_key": "K2-secret", "access_token": "T1-secret",
    "bearer": "B1-secret", "passwd": "P1-secret",
    "nested": [{"inner": {"password": "nested-pw"}}],
    "case": "CASE-0001", "domain": "example.com", "passive": True, "secrets": "true",
}


# ------------------------------------------------------------------ AST: what each handler reads
def _literal(node, consts):
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id in consts):
        base = consts[node.func.value.id]
        if isinstance(base, dict) and node.func.attr in ("items", "keys", "values"):
            return list(getattr(base, node.func.attr)())
    try:
        return ast.literal_eval(node)
    except Exception:  # noqa: BLE001
        return None


def _bindings(fn) -> dict:
    """Loop/comprehension variable -> the constant strings it iterates over in this handler."""
    consts = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            v = _literal(n.value, {})
            if isinstance(v, (dict, list, tuple, set)):
                consts[n.targets[0].id] = v
    out: dict = {}
    loops = [(n.target, n.iter) for n in ast.walk(fn) if isinstance(n, (ast.For, ast.AsyncFor))]
    loops += [(g.target, g.iter) for n in ast.walk(fn) if isinstance(n, ast.comprehension)
              for g in [n]]
    for target, it in loops:
        items = _literal(it, consts)
        if isinstance(items, dict):
            items = list(items)
        if not isinstance(items, (list, tuple, set)):
            continue
        names = [target] if isinstance(target, ast.Name) else list(getattr(target, "elts", []))
        for i, t in enumerate(names):
            if not isinstance(t, ast.Name):
                continue
            for item in items:
                val = item if isinstance(target, ast.Name) else (
                    item[i] if isinstance(item, (tuple, list)) and len(item) > i else None)
                if isinstance(val, str):
                    out.setdefault(t.id, set()).add(val)
    return out


def handler_reads(fn) -> tuple[set, list]:
    """(keys read from the handler's args dict, unresolvable read expressions)."""
    argn = fn.args.args[0].arg
    binds = _bindings(fn)
    keys, unresolved = set(), []

    def take(expr):
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            keys.add(expr.value)
        elif isinstance(expr, ast.Name) and expr.id in binds:
            keys.update(binds[expr.id])
        else:
            unresolved.append(ast.unparse(expr))

    def is_args(node):
        return isinstance(node, ast.Name) and node.id == argn

    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr == "get" and is_args(f.value) and n.args:
                take(n.args[0])
            elif getattr(f, "id", None) == "_flag" and len(n.args) > 1 and is_args(n.args[0]):
                take(n.args[1])
            elif any(is_args(a) for a in n.args) or any(is_args(k.value) for k in n.keywords):
                if getattr(f, "id", None) != "_flag":
                    unresolved.append(f"args passed whole to {ast.unparse(f)}")
        elif isinstance(n, ast.Subscript) and is_args(n.value):
            take(n.slice)
        elif (isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], (ast.In, ast.NotIn))
              and is_args(n.comparators[0])):
            take(n.left)
    return keys, unresolved


def tool_handlers() -> dict:
    """tool name -> handler AST node, for every @tool(...) in harness/tools.py."""
    tree = ast.parse(open(TOOLS_PY, encoding="utf-8").read())
    out = {}
    for fn in tree.body:
        if not isinstance(fn, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for d in fn.decorator_list:
            if (isinstance(d, ast.Call) and getattr(d.func, "id", "") == "tool" and d.args
                    and isinstance(d.args[0], ast.Constant)):
                out[d.args[0].value] = fn
    return out


# ------------------------------------------------------------------ stdio transcript helpers
def _wrapper(root: str) -> str:
    # Runs the real server as __main__ with the ledger redirected: mcp_server does `import audit`,
    # which returns this already-patched module.
    return (f"import sys, runpy\nsys.path.insert(0, {HARNESS!r})\nimport audit\n"
            f"audit.ROOT = {root!r}\nrunpy.run_path({SERVER_PY!r}, run_name='__main__')\n")


def transcript(messages, root: str, raw_lines=()) -> tuple[list, str]:
    """Pipe `messages` (JSON-encoded, one per line) + `raw_lines` into a fresh server; stdin then
    hits EOF. Returns (parsed reply objects, stderr)."""
    data = "".join(json.dumps(m) + "\n" for m in messages) + "".join(l + "\n" for l in raw_lines)
    env = dict(os.environ, HARNESS_ALLOWED_TOOLS="", HARNESS_EMIT_SCHEMA_FILE="",
               HARNESS_EMIT_OUT_FILE="", INTEL_CASE="")
    p = subprocess.run([sys.executable, "-c", _wrapper(root)], input=data.encode("utf-8"),
                       capture_output=True, timeout=180, env=env, cwd=ENGINE)
    out = [json.loads(l) for l in p.stdout.decode("utf-8").splitlines() if l.strip()]
    return out, p.stderr.decode("utf-8", "backslashreplace")


def _ledger_text(root: str) -> str:
    chunks = []
    for d, _, files in os.walk(root):
        for f in files:
            if f == "tool_calls.jsonl":
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    chunks.append(fh.read())
    return "".join(chunks)


def check():
    """run_eval.py entry point — returns (passed, failed, lines)."""
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    # ---------------------------------------------------------------- ledger, in-process
    sys.path.insert(0, HARNESS)
    import audit
    real_root = audit.ROOT
    with tempfile.TemporaryDirectory() as tmp:
        audit.ROOT = tmp
        try:
            raised = None
            try:
                audit.record("hash_id", {"hashes": "\ud800", "score": float("nan"),
                                         "ratio": float("inf")},
                             allowed=True, reason="", classes=[])
            except Exception as e:  # noqa: BLE001
                raised = e
            text = _ledger_text(tmp)
            recs = [json.loads(l) for l in text.splitlines() if l.strip()]
            ok(raised is None and len(recs) == 1,
               "ledger: a lone surrogate + NaN/inf argument is recorded, record() does not raise")
            ok(bool(recs) and recs[0]["args"]["hashes"] == "\ud800"
               and recs[0]["args"]["score"] == "nan" and recs[0]["args"]["ratio"] == "inf",
               "ledger: the surrogate round-trips as a JSON escape and NaN/inf become strings")

            audit.record("pivot_extract", SECRET_ARGS, allowed=True, reason="", classes=[])
            text = _ledger_text(tmp)
            leaked = [s for s in SECRETS if s in text]
            ok(not leaked, f"ledger redaction: no planted secret on disk (leaked: {leaked})")
            rec = json.loads(text.splitlines()[-1])["args"]
            ok("203.0.113.5:80" in rec["proxy"] and "alice" not in rec["proxy"],
               "ledger redaction: proxy userinfo stripped, host:port kept")
            ok(rec["url"].startswith("https://example.com/path?") and "q=ok" in rec["url"],
               "ledger redaction: url host/path and non-secret query params stay readable")
            ok(rec["headers"]["Accept"] == "text/html"
               and rec["headers"]["Authorization"] == "<redacted>",
               "ledger redaction: nested header dict — Authorization redacted, Accept kept")
            ok(all(rec[k] == "<redacted>" for k in
                   ("apiKey", "x_api_key", "access_token", "bearer", "passwd")),
               "ledger redaction: apiKey / x_api_key / access_token / bearer / passwd redacted")
            ok(rec["case"] == "CASE-0001" and rec["domain"] == "example.com"
               and rec["passive"] is True and rec["secrets"] == "true",
               "ledger redaction: case/domain readable; boolean switches passive/secrets kept")

            # A switch-shaped VALUE must not exempt a secret-named key: only the declared boolean
            # parameters (redact_bool_switches) keep one. password="true" is a password.
            audit.record("pivot_extract", {"password": "true", "token": "1", "api_key": "yes",
                                           "headers": {"Authorization": "0"},
                                           "passive": "false"},
                         allowed=True, reason="", classes=[])
            rec = json.loads(_ledger_text(tmp).splitlines()[-1])["args"]
            ok(rec["password"] == rec["token"] == rec["api_key"] == "<redacted>"
               and rec["headers"]["Authorization"] == "<redacted>",
               "ledger redaction: password='true' / token='1' / api_key='yes' / nested auth='0' "
               "are redacted (a boolean-looking value is not a switch)")
            ok(rec["passive"] == "false",
               "ledger redaction: the declared switch passive='false' stays readable")
        finally:
            audit.ROOT = real_root

    # ---------------------------------------------------------------- stdio transcripts
    with tempfile.TemporaryDirectory() as tmp:
        out, err = transcript([{"jsonrpc": "2.0", "id": 1, "method": "ping"}], tmp)
        ok(out == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
           and "never awaited" not in err and "destroyed" not in err,
           "shutdown: a request in flight at stdin EOF is still answered (printf | server)")

        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "1999-01-01"}},
            {"jsonrpc": "2.0", "id": 2, "method": "initialize",
             "params": {"protocolVersion": "2025-03-26"}},
            {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {"protocolVersion": 42}},
            [{"jsonrpc": "2.0", "id": 4, "method": "ping"}],
            42,
            None,
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": ["hash_id"]},
            {"jsonrpc": "2.0", "id": 6, "method": "ping", "params": "x"},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": ["hash_id"], "arguments": {}}},
            {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
             "params": {"name": "hash_id", "arguments": ["x"]}},
            {"jsonrpc": "2.0", "id": 9, "result": {}},
            {"jsonrpc": "2.0", "id": 10, "error": {"code": -1, "message": "client error"}},
            {"jsonrpc": "2.0", "id": 11},
            {"jsonrpc": "1.0", "id": 12, "method": "ping"},
            {"id": 13, "method": "ping"},
            {"jsonrpc": "2.0", "id": 14, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 15, "method": "tools/call", "params": {
                "name": "hash_id", "arguments": {"hashes": "d41d8cd98f00b204e9800998ecf8427e",
                                                 "note": "\ud800", **SECRET_ARGS}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ]
        out, err = transcript(msgs, tmp, raw_lines=["{not json"])
        by_id = {r.get("id"): r for r in out if r.get("id") is not None}
        nulls = [r for r in out if r.get("id") is None]

        def code(i):
            return ((by_id.get(i) or {}).get("error") or {}).get("code")

        ok((by_id.get(1) or {}).get("result", {}).get("protocolVersion") == "2025-06-18"
           and (by_id.get(3) or {}).get("result", {}).get("protocolVersion") == "2025-06-18",
           "initialize: an unknown protocolVersion ('1999-01-01', 42) is answered with the newest supported")
        ok((by_id.get(2) or {}).get("result", {}).get("protocolVersion") == "2025-03-26",
           "initialize: a supported older protocolVersion is echoed")
        ok(sorted(r["error"]["code"] for r in nulls) == [-32700, -32600, -32600, -32600]
           and 4 not in by_id,
           "invalid request: batch array / scalar / null -> -32600 with id null (plus -32700 for bad JSON)")
        ok(code(5) == -32602 and code(6) == -32602,
           "invalid params: list/string params -> -32602")
        ok(code(7) == -32602 and code(8) == -32602,
           "invalid params: non-string tool name / list arguments -> -32602")
        ok(9 not in by_id and 10 not in by_id and 8 in by_id and 11 in by_id,
           "a client RESPONSE ({id,result} / {id,error}) is not answered (its neighbours are)")
        ok(code(11) == -32600 and code(12) == -32600 and code(13) == -32600,
           "invalid request: missing method / jsonrpc != '2.0' / no jsonrpc -> -32600")
        tools = {t["name"]: t for t in ((by_id.get(14) or {}).get("result") or {}).get("tools", [])}
        ok((tools.get("hash_id") or {}).get("annotations", {}).get("readOnlyHint") is True,
           "tools/list: hash_id carries annotations.readOnlyHint = true")
        ok(all(v is not None for t in tools.values() for v in (t.get("annotations") or {}).values()),
           "tools/list: annotations omit None-valued hints")
        res15 = by_id.get(15) or {}
        ok("result" in res15 and res15["result"].get("isError") is False,
           "ledger: a call carrying a lone-surrogate argument still succeeds (no -32603)")
        text = _ledger_text(tmp)
        leaked = [s for s in SECRETS if s in text]
        ok("hash_id" in text and not leaked,
           f"ledger (stdio): call recorded under the temp ROOT with no planted secret (leaked: {leaked})")
        ok(len(out) == len(by_id) + len(nulls) and "Traceback" not in err,
           "server survived every malformed line without a traceback")

        # ------------------------------------------------------------ schema completeness
        handlers = tool_handlers()
        missing, unresolved = [], []
        for name, fn in sorted(handlers.items()):
            if name not in tools:
                continue
            props = set((tools[name].get("inputSchema") or {}).get("properties") or {})
            reads, unres = handler_reads(fn)
            missing += [f"{name}.{k}" for k in sorted(reads - props)
                        if (name, k) not in INTERNAL_KEYS]
            unresolved += [f"{name}: {u}" for u in unres]
        ok(len(handlers) > 50 and set(handlers) <= set(tools),
           f"schema: every @tool in tools.py is served by tools/list ({len(handlers)} handlers)")
        ok(not missing, f"schema: every key a handler reads is a declared inputSchema property "
                        f"(undeclared: {missing})")
        ok(not unresolved, f"schema: every args read is statically resolvable (unresolved: {unresolved})")
        req = {n: set((tools.get(n) or {}).get("inputSchema", {}).get("required") or [])
               for n in ("kb_query_shared", "reverse_whois")}
        ok("min" not in req["kb_query_shared"] and "kind" not in req["reverse_whois"]
           and "term" in req["reverse_whois"],
           "schema: handler-defaulted params (kb_query_shared.min, reverse_whois.kind) are optional")
        bad_types = [f"{n}.{k}" for n, t in tools.items()
                     for k, s in ((t.get("inputSchema") or {}).get("properties") or {}).items()
                     if s.get("type") not in ("string", "integer", "number", "boolean", "array", "object")]
        ok(not bad_types, f"schema: every property has a JSON Schema type (bad: {bad_types})")

    return passed, failed, lines


if __name__ == "__main__":
    p, f, out = check()
    for status, label in out:
        print(f"  [{status}] {label}")
    print(f"{'FAIL' if f else 'PASS'} test_mcp_protocol ({p} passed, {f} failed)")
    raise SystemExit(bool(f))
