#!/usr/bin/env python3
"""
bp_rea.py — OPTIONAL deep-static layer for BinaryPivot through REA (morluto/rea, npm `rea-agents`).

WHY IT EXISTS
-------------
analyze_artifact's sweep is ASCII strings plus container parsing. Three things it cannot see:
  * .NET user strings — `ldstr` literals are UTF-16 in the #US heap, invisible to an ASCII sweep;
  * which Dart packages a Flutter build compiled (the app's own project name) and the exact
    libapp.so build it shipped;
  * WHERE in an Electron bundle a literal lives (module + line), which a citation needs.
REA parses those structures without running the sample. This module calls it, keeps the evidence
ids, and hands analyze_artifact literals, indicators and build-identity facts.

SAFETY CONTRACT
---------------
  * STATIC ONLY. `_STATIC_CEILING` is the complete set of REA commands that may run — each reads
    the file and neither executes it nor opens a network connection. references/rea.json selects
    from it per file kind; a listed command outside the ceiling is refused (stderr warning).
    `_ALLOWED_ARGS` is the same ceiling for the step's extra CLI arguments: a step carrying any
    argument (or argument value) not listed there is refused and never executed.
  * Version-gated args: a step's `min_version` names the REA release its `args` need. On an older
    REA the args are dropped (recorded as the run's `args_skipped`), the command still runs; if REA
    still answers `Unknown flag`, the command is retried once without args.
  * Never installs or updates REA. A missing binary is a recorded COLLECTION LIMITATION, so an
    absent REA section is never read as "no .NET strings / no Dart packages".
  * Attribution rail: everything here is a fact or a cited lead. REA's indicators are NEVER merged
    into the sample's base iocs (whose labels — wallets, Firebase, S3, messenger handles — are
    edges). Each REA indicator kind reaches artifacts.trackers only through references/rea.json
    `ioc_labels`, and every label it maps to — plus the rea_* build identities — must be listed in
    tools/kb/references/rungs.json binary_fact_only_trackers (tests/test_references.py enforces it).
    A kind with no mapping stays in the result as a cited lead and is never ingested as a tracker.
  * Collected, never clustered: `nodes` (pivot_nodes()) are kit-rung rows — URL-literal hosts, C2
    IPs, wallets, Telegram handles, e-mails — that tools/binary_auto.register_rea_nodes hands to
    the cross-type loop, so the harness collects/pivots them while case_state.tier_hosts keeps
    them out of the same-operator partition.

Usage:
  bp_rea.py <file> --kind apk|pe|elf|macho|asar [--evidence-dir DIR]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bp_refs  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "WebPivot", "tools"))
    from wp_timeouts import floor as _floor  # noqa: E402
except Exception:  # noqa: BLE001 — a standalone BinaryPivot keeps the caller's timeout
    def _floor(t):
        return t

# The only REA commands this module will ever run. Each is documented by REA as static:
# it parses the file's structures and does not launch it, attach to it or fetch anything.
_STATIC_CEILING = frozenset({
    "identify-flutter-build", "inspect-dart-aot", "inspect-go-binary", "inspect-rust-binary",
    "inspect-managed-artifact", "inspect-managed-members", "analyze-javascript-application",
    "inspect-pe-resources",
})

# The only extra arguments a rea.json step may pass, mapped to the values each accepts (None = a
# boolean flag that takes no value). `--format json` is added by _call itself. Every entry is a
# parse/output option of a static command above; none launches, attaches or fetches.
_ALLOWED_ARGS = {
    "--include-string-literals": None,
    "--artifact-format": frozenset({"asar"}),
}


def args_allowed(args):
    """None when every token of `args` is an allowed flag (with an allowed value), else the first
    offending token."""
    i = 0
    while i < len(args):
        tok = args[i]
        if not isinstance(tok, str) or tok not in _ALLOWED_ARGS:
            return str(tok)
        values = _ALLOWED_ARGS[tok]
        if values is not None:
            if i + 1 >= len(args) or not isinstance(args[i + 1], str) or args[i + 1] not in values:
                return f"{tok} {args[i + 1] if i + 1 < len(args) else '<missing value>'}"
            i += 1
        i += 1
    return None


def version_tuple(v):
    """'6.9.0' / 'v6.9.0' / 'rea 6.9.0' -> (6, 9, 0); None when no x.y[.z] is found."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(v or ""))
    return tuple(int(x or 0) for x in m.groups()) if m else None


# Conservative minimum: no commands at all, so a broken data file runs nothing (and says so).
_REA_FALLBACK = {
    "install": {"pinned_version": "6.9.0", "env": "REA_BIN",
                "install_hint": "npm install --global rea-agents@6.9.0"},
    "commands": {},
    "limits": {"max_literals": 5000, "max_citations": 50, "max_facts_per_label": 10,
               "max_json_depth": 64},
    "dart_package_noise": ["flutter", "flutter_web_plugins", "sky_engine"],
    # Unmapped kinds are dropped from trackers (kept as citations), so the minimum is the two
    # embedded-endpoint labels that are already fact-only.
    "ioc_labels": {"host": "app_backend_host", "ip_port": "app_c2_endpoint"},
    # No pivot nodes: a broken data file never makes the loop collect anything.
    "pivot": {"rung_class": "binary.rea", "max_nodes": 40},
    "pivot_nodes": {},
}
_REF = bp_refs.load_ref(bp_refs.ref_path(__file__, "rea.json"), _REA_FALLBACK)
INSTALL = _REF["install"]
COMMANDS = _REF["commands"]
LIMITS = _REF["limits"]
DART_PACKAGE_NOISE = frozenset(_REF["dart_package_noise"])
# REA indicator kind -> tracker label. The only path from a REA literal into artifacts.trackers.
IOC_LABELS = dict(_REF["ioc_labels"])
# REA indicator kind -> cross-type node type the harness collects/pivots at kit rung (pivot_nodes()).
PIVOT = _REF["pivot"]
PIVOT_NODES = dict(_REF["pivot_nodes"])

# Build-identity labels this layer contributes to artifacts.trackers. These and every IOC_LABELS
# value are listed in tools/kb/references/rungs.json binary_fact_only_trackers — never an edge.
BUILD_LABELS = ("rea_go_module", "rea_dart_package", "rea_flutter_libapp", "rea_managed_mvid")
TRACKER_LABELS = BUILD_LABELS + tuple(sorted(set(IOC_LABELS.values())))

_IOC_KINDS = ("host", "url", "ip_port", "email", "telegram", "whatsapp", "onion", "s3_bucket",
              "firebase", "btc_wallet", "eth_wallet", "tron_wallet")


def resolve_bin():
    """Resolve REA_BIN (process env wins over .env), then `rea` on PATH. A missing or non-executable
    REA_BIN (for example after replacing Node) is skipped, not fatal. Keep the shared .env reader's
    precedence rather than temporarily removing process settings or reimplementing its parser."""
    import bp_anyrun  # noqa: E402 — shared .env reader (process env always wins)
    name = INSTALL.get("env") or "REA_BIN"
    configured = bp_anyrun._secret(name)
    notes = []
    if configured:
        if os.path.isfile(configured) and os.access(configured, os.X_OK):
            return {"path": configured, "source": name, "notes": notes}
        notes.append(f"{name} points to {configured}, which is missing or not executable; skipped")
    found = shutil.which("rea")
    return {"path": found, "source": "PATH" if found else None, "notes": notes}


def _rea_env(binary):
    """REA is a `#!/usr/bin/env node` script: put its own bin dir first on PATH so the node it was
    installed with (nvm / npm-global; REA 6.9.0 needs Node ^22.23.4 || ^24.22.1 || >=26.12.1)
    runs it, not an older system node."""
    return {**os.environ,
            "PATH": os.path.dirname(os.path.abspath(binary)) + os.pathsep + os.environ.get("PATH", "")}


def rea_version(binary):
    try:
        p = subprocess.run([binary, "--version"], capture_output=True, text=True, errors="replace",
                           timeout=_floor(60), env=_rea_env(binary))
        return (p.stdout or "").strip().splitlines()[0] if p.returncode == 0 and p.stdout else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def _dotenv_origin(name, value):
    """'.env' when the shared .env reader alone yields `value` for `name`, else 'env' (an exported
    variable). Asked of a child interpreter with `name` removed from its environment, so the shared
    reader (bp_anyrun) is reused as-is and this process's environment is never touched."""
    code = ("import os, sys; sys.path.insert(0, sys.argv[1]); import bp_anyrun; "
            "bp_anyrun._load_env_files(); print(os.environ.get(sys.argv[2], ''))")
    try:
        p = subprocess.run([sys.executable, "-c", code, os.path.dirname(os.path.abspath(__file__)), name],
                           capture_output=True, text=True, errors="replace", timeout=_floor(30),
                           env={k: v for k, v in os.environ.items() if k != name})
        return ".env" if p.returncode == 0 and (p.stdout or "").strip() == value else "env"
    except (OSError, subprocess.SubprocessError, ValueError):
        return "env"


def _fix_hint(pinned):
    """The exact commands that repair REA under the ACTIVE Node: npm installs a global package's
    bin next to the `node` on PATH (nvm and system installs alike)."""
    name = INSTALL.get("env") or "REA_BIN"
    node = shutil.which("node")
    target = os.path.join(os.path.dirname(node), "rea") if node else "$(npm prefix -g)/bin/rea"
    return {"install": f"npm install --global rea-agents@{pinned}",
            "env_line": f"{name}={target}",
            "text": (f"npm install --global rea-agents@{pinned}  (under the active Node), then set "
                     f"`{name}={target}` in .env (an exported {name} overrides .env)")}


def install_health():
    """Is the REA install usable and at the pin? Never raises. Returns {binary, source (env|.env|
    PATH|None), configured, exists, version, pinned, status, hint, fix, notes}; status is ok |
    missing | stale_path (REA_BIN names a deleted or non-executable file, e.g. after an nvm Node
    upgrade) | older_than_pin | newer_than_pin | unrunnable (found, but `rea --version` fails, e.g.
    the Node it needs is gone). `hint` is None only when status is ok."""
    pinned = INSTALL.get("pinned_version")
    out = {"binary": None, "source": None, "configured": None, "exists": False, "version": None,
           "pinned": pinned, "status": "missing", "hint": None, "fix": None, "notes": []}
    try:
        import bp_anyrun  # noqa: E402 — shared .env reader
        name = INSTALL.get("env") or "REA_BIN"
        res = resolve_bin()
        out["notes"] = list(res.get("notes") or [])
        configured = bp_anyrun._secret(name)
        out["configured"] = configured
        binary = res.get("path")
        if binary:
            out["binary"], out["exists"] = binary, True
            out["source"] = (_dotenv_origin(name, configured) if res.get("source") == name
                             else res.get("source"))
            out["version"] = rea_version(binary)
            have, want = version_tuple(out["version"]), version_tuple(pinned)
            if out["version"] is None or have is None:
                out["status"] = "unrunnable"
            elif want and have < want:
                out["status"] = "older_than_pin"
            elif want and have > want:
                out["status"] = "newer_than_pin"
            else:
                out["status"] = "ok"
        if configured and binary != configured:
            # REA_BIN is set but unusable: say so even when a PATH fallback hides it this run.
            out["status"] = "stale_path"
            if not binary:
                out["binary"], out["source"] = configured, _dotenv_origin(name, configured)
        if out["status"] != "ok":
            fix = _fix_hint(pinned)
            out["fix"], out["hint"] = fix, fix["text"]
    except Exception as e:  # noqa: BLE001 — a health probe reports, it never breaks its caller
        out["status"] = "unrunnable" if out["exists"] else out["status"]
        out["notes"].append(f"health check error: {type(e).__name__}")
        if out["hint"] is None and out["status"] != "ok":
            out["hint"] = f"npm install --global rea-agents@{pinned}"
    return out


def kind_for(kind, path):
    """An Electron archive has no magic bytes; its name is the only signal."""
    return "asar" if str(path).lower().endswith(".asar") else kind


def _dict(v):
    return v if isinstance(v, dict) else {}


def _list(v):
    return v if isinstance(v, list) else []


# One JSON string literal (escapes included) or one bracket — a string is consumed whole, so a
# bracket inside it never counts toward the nesting depth.
_JSON_DEPTH_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]')


def _json_depth_over(text, cap):
    """True when `text` nests arrays/objects deeper than `cap` — checked before json.loads, whose
    recursive decoder overflows the stack on deep input (RecursionError) instead of failing."""
    depth = 0
    for m in _JSON_DEPTH_TOKEN.finditer(text):
        tok = m.group()
        if tok in "[{":
            depth += 1
            if depth > cap:
                return True
        elif tok in "]}":
            depth -= 1
    return False


def _call(binary, command, path, args, timeout):
    """Run one static REA command. Returns (status, doc, error): status is ok / not_applicable /
    error. REA reports a failure as a JSON object: `error` set (exit 0), or — REA 6.9.0 — only
    `code`/`category` with no normalized_result (exit 1). An unsupported target is not_applicable.
    Undecodable bytes are replaced, JSON nested past limits.max_json_depth is refused unparsed, and
    an envelope of the wrong shape is an error — never a raise."""
    try:
        p = subprocess.run([binary, command, path, *args, "--format", "json"], capture_output=True,
                           text=True, errors="replace", timeout=_floor(timeout), env=_rea_env(binary))
    except subprocess.TimeoutExpired:
        return "error", None, f"timed out after {timeout}s"
    except (OSError, ValueError) as e:
        return "error", None, f"{type(e).__name__}: {e}"
    try:
        return _envelope(p)
    except (RecursionError, MemoryError) as e:  # defensive: the depth cap should pre-empt both
        return "error", None, f"exit {p.returncode}, REA JSON not parsed: {type(e).__name__}"


def _envelope(p):
    """Parse and classify one REA reply (see _call)."""
    cap = int(LIMITS.get("max_json_depth", 64))
    if _json_depth_over(p.stdout or "", cap):
        return "error", None, f"exit {p.returncode}, JSON nested deeper than {cap} levels; not parsed"
    try:
        doc = json.loads(p.stdout or "")
    except ValueError:
        tail = (p.stderr or p.stdout or "").strip()[-300:]
        return "error", None, f"exit {p.returncode}, no JSON: {tail}"
    if not isinstance(doc, dict):
        return "error", None, "unexpected JSON shape"
    if "details" in doc and not isinstance(doc["details"], dict):
        return "error", None, "unexpected JSON shape: details is not an object"
    if "issues" in _dict(doc.get("details")) and not isinstance(doc["details"]["issues"], list):
        return "error", None, "unexpected JSON shape: details.issues is not a list"
    if doc.get("error") or (doc.get("code") and "normalized_result" not in doc):
        det = _dict(doc.get("details"))
        issue = next((i.get("message") for i in _list(det.get("issues")) if isinstance(i, dict)), None)
        reason = det.get("reason") or issue or doc.get("message") or doc.get("error") or doc["code"]
        status = ("not_applicable" if doc.get("category") in ("unsupported_provider", "unsupported_target")
                  else "error")
        return status, None, str(reason)[:300]
    if not isinstance(doc.get("normalized_result", {}), dict):
        return "error", None, "unexpected JSON shape: normalized_result is not an object"
    return "ok", doc, None


# ----------------------------------------------------------------------------- extractors
# Each takes REA's normalized_result and returns (literals, facts, detail):
#   literals = [(string, location)]  — scanned for indicators, cited by location
#   facts    = {tracker_label: [values]}
#   detail   = small dict kept in the result for the report (versions, flags)

def _validate_result(nr, shape, path="normalized_result"):
    """Validate only fields we consume; unknown REA fields remain forward-compatible."""
    if not isinstance(nr, dict):
        raise ValueError(f"{path} is not an object")
    for key, expected in shape.items():
        if key not in nr or nr[key] is None:
            continue
        value, location = nr[key], f"{path}.{key}"
        if isinstance(expected, dict):
            _validate_result(value, expected, location)
        elif isinstance(expected, list):
            if not isinstance(value, list):
                raise ValueError(f"{location} is not a list")
            for item in value:
                if isinstance(expected[0], dict):
                    _validate_result(item, expected[0], location + "[]")
                elif not isinstance(item, expected[0]):
                    raise ValueError(f"{location} contains a non-{expected[0].__name__}")
        elif not isinstance(value, expected):
            raise ValueError(f"{location} is not a {expected.__name__}")


_RESULT_SHAPES = {
    "identify-flutter-build": {"abis": [{"libapp": {}, "libflutter": {}}]},
    "inspect-dart-aot": {"string_pool": {"package_uris": [str]}},
    "inspect-managed-members": {"user_strings": {"literals": [{}]}, "module": {}, "metadata": {}},
    "inspect-go-binary": {"build_info": {"module": {"main": {}, "settings": [{}]}},
                          "string_literals": {"items": [{"location": {}}]}},
    "analyze-javascript-application": {"semantic_graph": {"nodes": [
        {"properties": {}, "identity": {"source_range": {"start": {}}}}]}},
}

def _x_flutter(nr):
    facts, detail = {"rea_flutter_libapp": []}, {"flutter_detected": bool(nr.get("flutter_detected"))}
    for abi in nr.get("abis") or []:
        lib = abi.get("libapp") or {}
        if lib.get("sha256"):
            facts["rea_flutter_libapp"].append(lib["sha256"])
        fl = abi.get("libflutter") or {}
        if lib.get("snapshot_hash"):
            detail.setdefault("dart_snapshot_hash", lib["snapshot_hash"])
        if fl.get("dart_version"):
            detail.setdefault("dart_version", fl["dart_version"])
    return [], facts, detail


def _x_dart_aot(nr):
    pool = nr.get("string_pool") or {}
    names = []
    for uri in pool.get("package_uris") or []:
        name = str(uri).split(":", 1)[-1].split("/", 1)[0]
        if uri.startswith("package:") and name and name not in DART_PACKAGE_NOISE:
            names.append(name)
    literals = [(u, "dart string pool") for u in pool.get("package_uris") or []]
    return literals, {"rea_dart_package": names}, {"abi": nr.get("abi"),
                                                  "package_uri_count": pool.get("package_uri_count_at_least")}


def _x_managed(nr):
    lits = [(str(x.get("value")), f"ldstr {x.get('token')}")
            for x in ((nr.get("user_strings") or {}).get("literals") or []) if x.get("value")]
    mod = nr.get("module") or {}
    return lits, {"rea_managed_mvid": [mod["mvid"]] if mod.get("mvid") else []}, \
        {"module": mod.get("name"), "runtime": (nr.get("metadata") or {}).get("version")}


# A Go binary's (ptr, len) string table is dominated by runtime/stdlib names and messages
# ("inconsistent poll.fdMutex", "reflect.Value.Elem") that the host regex reads as hostnames. A
# literal with a dot is kept only with structure an indicator needs — a scheme, '@', a host/path
# (t.me/x; not a Go import path like internal/sync.X) or an ip:port; dot-free literals (wallets,
# handles) always stay. Bare hosts remain the base sweep's job.
_GO_STRUCTURED = re.compile(r"://|@|\b[\w-]+\.[A-Za-z]{2,24}/|\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b")


def _x_go(nr):
    bi = nr.get("build_info") or {}
    mod = bi.get("module") or {}
    path = (mod.get("main") or {}).get("path") or mod.get("path")
    vcs = {s.get("key"): s.get("value") for s in mod.get("settings") or []
           if str(s.get("key", "")).startswith("vcs")}
    detail = {"go_version": bi.get("go_version")} if bi.get("go_version") else {}
    if vcs:
        detail["vcs"] = vcs
    # REA >= 6.9.0 with --include-string-literals: inferred (ptr, len) strings, cited by file offset.
    lits = [(x["value"], f"go string @{(x.get('location') or {}).get('offset', '?')}")
            for x in ((nr.get("string_literals") or {}).get("items") or [])
            if isinstance(x.get("value"), str) and x["value"]
            and ("." not in x["value"] or _GO_STRUCTURED.search(x["value"]))]
    return lits, {"rea_go_module": [path] if path else []}, detail


def _x_javascript(nr):
    lits = []
    for node in ((nr.get("semantic_graph") or {}).get("nodes") or []):
        if node.get("kind") != "literal":
            continue
        val = (node.get("properties") or {}).get("value")
        if not isinstance(val, str) or not val:
            continue
        ident = node.get("identity") or {}
        line = ((ident.get("source_range") or {}).get("start") or {}).get("line")
        lits.append((val, f"{ident.get('module_path', '?')}:{line if line is not None else '?'}"))
    return lits, {}, {}


_EXTRACTORS = {
    "identify-flutter-build": _x_flutter,
    "inspect-dart-aot": _x_dart_aot,
    "inspect-managed-members": _x_managed,
    "inspect-go-binary": _x_go,
    "analyze-javascript-application": _x_javascript,
}


def limitation(reason):
    return (f"COLLECTION LIMITATION — the REA deep-static layer did not run ({reason}). .NET user "
            "strings, Flutter build / Dart package identity, Go module identity and Electron bundle "
            "literals were NOT inspected; their absence here is not a finding. "
            f"Install: {INSTALL.get('install_hint')} (set {INSTALL.get('env')} if not on PATH).")


def enrich(path, kind, evidence_dir=None):
    """Run every configured static REA command for this file kind. Never raises.

    Returns {status, version, pinned_version, runs[], iocs{}, trackers{}, citations[], detail{},
    limitation?}. status: ran / not_installed / not_applicable."""
    pinned = INSTALL.get("pinned_version")
    kind = kind_for(kind, path)
    plan = COMMANDS.get(kind) or []
    resolved = resolve_bin()
    binary = resolved["path"]
    if not binary:
        res = {"status": "not_installed", "pinned_version": pinned,
               "limitation": limitation("REA is not installed")}
        if resolved["notes"]:
            res["binary_notes"] = resolved["notes"]
        return res
    if not plan:
        return {"status": "not_applicable", "pinned_version": pinned, "kind": kind}
    version = rea_version(binary)
    out = {"status": "ran", "version": version, "pinned_version": pinned, "kind": kind,
           "binary": binary, "binary_source": resolved["source"],
           "runs": [], "iocs": {}, "trackers": {}, "citations": [], "detail": {}}
    if resolved["notes"]:
        out["binary_notes"] = resolved["notes"]
    if version != pinned:
        out["version_note"] = (f"installed REA {version or '?'} is not the pinned {pinned}; output "
                               "shapes may differ — upgrade/downgrade by hand, never automatically")
    have = version_tuple(version)
    flags, literals = {}, []
    for step in plan:
        if not isinstance(step, dict):
            out["runs"].append({"command": None, "status": "refused", "reason": "step is not an object"})
            continue
        cmd = step.get("command")
        if not isinstance(cmd, str) or cmd not in _STATIC_CEILING:
            sys.stderr.write(f"[bp_rea] refused {cmd!r}: not a static command (ceiling in bp_rea.py)\n")
            out["runs"].append({"command": cmd, "status": "refused"})
            continue
        if step.get("when") and not flags.get(str(step["when"])):
            out["runs"].append({"command": cmd, "status": "skipped", "reason": f"{step['when']} false"})
            continue
        args = step.get("args") or []
        bad = args_allowed(args) if isinstance(args, list) else f"{args!r} (args must be a list)"
        if bad is not None:
            sys.stderr.write(f"[bp_rea] refused {cmd!r}: argument {bad!r} is not allowed "
                             "(_ALLOWED_ARGS in bp_rea.py)\n")
            out["runs"].append({"command": cmd, "status": "refused", "reason": f"argument {bad} not allowed"})
            continue
        args, skipped = list(args), None
        need = version_tuple(step.get("min_version"))
        if args and need and have and have < need:
            skipped = {"args": args, "reason": f"REA {version} is older than {step['min_version']}, "
                                               "which these args need"}
            args = []
        try:
            timeout = int(step.get("timeout") or 300)
        except (TypeError, ValueError):
            timeout = 300
        status, doc, err = _call(binary, cmd, path, args, timeout)
        if args and err and "unknown flag" in err.lower():
            skipped = {"args": args, "reason": f"REA rejected them ({err}); retried once without args"}
            status, doc, err = _call(binary, cmd, path, [], timeout)
        run = {"command": cmd, "status": status}
        if skipped:
            run["args_skipped"] = skipped
        if err:
            run["error"] = err
        if doc is not None:
            try:
                _validate_result(doc.get("normalized_result") or {}, _RESULT_SHAPES.get(cmd, {}))
                lits, facts, detail = _EXTRACTORS.get(cmd, lambda _nr: ([], {}, {}))(
                    doc.get("normalized_result") or {})
                lits = [(v, str(loc)) for v, loc in lits if isinstance(v, str) and v]
                facts = {k: [v for v in vals if isinstance(v, str) and v] for k, vals in facts.items()}
            except Exception as e:  # noqa: BLE001 — a malformed result costs this step, not the rest
                run["status"] = "error"
                run["error"] = f"malformed {cmd} result: {type(e).__name__}: {e}"[:300]
                out["runs"].append(run)
                continue
            run["evidence_id"] = doc.get("evidence_id")
            flags.update({k: v for k, v in detail.items() if isinstance(v, bool)})
            if detail:
                out["detail"][cmd] = detail
            for label, vals in facts.items():
                bucket = out["trackers"].setdefault(label, [])
                bucket += [v for v in vals if v not in bucket]
                del bucket[int(LIMITS.get("max_facts_per_label", 40)):]
            literals += [(v, cmd, loc) for v, loc in lits]
            run["literals"] = len(lits)
            if evidence_dir:
                try:
                    os.makedirs(evidence_dir, exist_ok=True)
                    sha = _dict(_dict(doc.get("subject")).get("digest")).get("sha256")
                    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha)):
                        sha = "sample"
                    dest = os.path.join(evidence_dir, f"{sha}.{cmd}.json")
                    with open(dest, "w", encoding="utf-8") as fh:
                        json.dump(doc, fh, ensure_ascii=False)
                    run["evidence_file"] = dest
                except (OSError, ValueError, TypeError, RecursionError) as e:
                    run["evidence_error"] = str(e)
        out["runs"].append(run)
    out["trackers"] = {k: v for k, v in out["trackers"].items() if v}
    literals = literals[:int(LIMITS.get("max_literals", 20000))]
    if literals:
        import analyze_artifact  # noqa: E402 — lazy: analyze_artifact imports this module
        blob = "\n".join(v for v, _, _ in literals).encode("utf-8", "ignore")
        iocs = {k: v for k, v in analyze_artifact.scan_iocs(blob, label="rea").items() if v}
        out["iocs"] = iocs
        # REA indicators reach trackers only through the explicit ioc_labels mapping; hosts use the
        # same cloud/messenger filter the base sweep applies before app_backend_host.
        nfacts = int(LIMITS.get("max_facts_per_label", 40))
        for k, label in IOC_LABELS.items():
            vals = analyze_artifact._operator_hosts(iocs) if k == "host" else iocs.get(k) or []
            if vals:
                bucket = out["trackers"].setdefault(label, [])
                bucket += [v for v in vals if v not in bucket]
                del bucket[nfacts:]
        out["nodes"] = pivot_nodes(iocs, analyze_artifact)
        cap = int(LIMITS.get("max_citations", 200))
        for k in _IOC_KINDS:
            for value in iocs.get(k) or []:
                if len(out["citations"]) >= cap:
                    break
                hit = next(((c, loc) for v, c, loc in literals if value.lower() in v.lower()), None)
                if hit:
                    out["citations"].append({"kind": k, "value": value, "command": hit[0],
                                             "location": hit[1]})
    return out


def _url_hosts(iocs, aa):
    """Hosts parsed out of a real http(s):// URL literal — the trustworthy half of the sweep.
    Bare host-shaped tokens (dotted .NET/JS identifiers) are leads only, never pivot nodes."""
    from urllib.parse import urlparse
    hosts = []
    for u in iocs.get("url") or []:
        try:
            h = urlparse(u).netloc.split("@")[-1].split(":")[0].lower()
        except ValueError:
            continue
        if h and aa._valid_host(h, from_url=True) and h not in hosts:
            hosts.append(h)
    return aa._operator_hosts({"host": hosts})


def pivot_nodes(iocs, aa):
    """Rows for the cross-type loop's node registry (case_state.add_nodes): COLLECTED by the
    harness automatically, at the kit rung class from references/rea.json `pivot` — so a host
    reached only through a REA literal is tiered kit (case_state.tier_hosts): collected, never in
    the same-operator partition, never attributed. The KB side stays facts (ioc_labels)."""
    rc = str(PIVOT.get("rung_class") or "binary.rea")
    cap = int(PIVOT.get("max_nodes", 40))
    rows = []
    for kind, ntype in PIVOT_NODES.items():
        vals = _url_hosts(iocs, aa) if kind == "url_host" else iocs.get(kind) or []
        for v in vals:
            v = str(v).strip()
            if ntype == "ip":
                v = v.split(":", 1)[0]
            elif ntype == "telegram":
                v = v.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
            if v and not any(r["type"] == ntype and r["value"] == v for r in rows):
                rows.append({"type": ntype, "value": v, "rung_class": rc})
    return rows[:cap]


def main():
    ap = argparse.ArgumentParser(description="REA deep-static layer for one local file (static commands only).")
    ap.add_argument("path")
    ap.add_argument("--kind", required=True, help="BinaryPivot file kind: apk, pe, elf, macho, asar")
    ap.add_argument("--evidence-dir", help="also save each REA evidence JSON here")
    a = ap.parse_args()
    print(json.dumps(enrich(os.path.abspath(a.path), a.kind, a.evidence_dir), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
