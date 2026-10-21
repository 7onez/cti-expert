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

# Conservative minimum: no commands at all, so a broken data file runs nothing (and says so).
_REA_FALLBACK = {
    "install": {"pinned_version": "6.7.0", "env": "REA_BIN",
                "install_hint": "npm install --global rea-agents@6.7.0"},
    "commands": {},
    "limits": {"max_literals": 5000, "max_citations": 50, "max_facts_per_label": 10},
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


def rea_bin():
    """The REA executable: $REA_BIN (process env, then the skill .env via bp_anyrun._secret) when it
    points at an executable file, else `rea` on PATH, else None."""
    import bp_anyrun  # noqa: E402 — shared .env reader (process env always wins)
    env = bp_anyrun._secret(INSTALL.get("env") or "REA_BIN")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return shutil.which("rea")


def _rea_env(binary):
    """REA is a `#!/usr/bin/env node` script: put its own bin dir first on PATH so the node it was
    installed with (nvm / npm-global, Node >= 22) runs it, not an older system node."""
    return {**os.environ,
            "PATH": os.path.dirname(os.path.abspath(binary)) + os.pathsep + os.environ.get("PATH", "")}


def rea_version(binary):
    try:
        p = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=_floor(60),
                           env=_rea_env(binary))
        return (p.stdout or "").strip().splitlines()[0] if p.returncode == 0 and p.stdout else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def kind_for(kind, path):
    """An Electron archive has no magic bytes; its name is the only signal."""
    return "asar" if str(path).lower().endswith(".asar") else kind


def _call(binary, command, path, args, timeout):
    """Run one static REA command. Returns (status, doc, error): status is ok / not_applicable /
    error. REA reports an unsupported target as a JSON error object with exit status 0."""
    try:
        p = subprocess.run([binary, command, path, *args, "--format", "json"],
                           capture_output=True, text=True, timeout=_floor(timeout), env=_rea_env(binary))
    except subprocess.TimeoutExpired:
        return "error", None, f"timed out after {timeout}s"
    except OSError as e:
        return "error", None, f"{type(e).__name__}: {e}"
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        tail = (p.stderr or p.stdout or "").strip()[-300:]
        return "error", None, f"exit {p.returncode}, no JSON: {tail}"
    if not isinstance(doc, dict):
        return "error", None, "unexpected JSON shape"
    if doc.get("error"):
        reason = ((doc.get("details") or {}).get("reason") or doc.get("message") or doc["error"])
        status = "not_applicable" if doc.get("category") == "unsupported_provider" else "error"
        return status, None, str(reason)[:300]
    return "ok", doc, None


# ----------------------------------------------------------------------------- extractors
# Each takes REA's normalized_result and returns (literals, facts, detail):
#   literals = [(string, location)]  — scanned for indicators, cited by location
#   facts    = {tracker_label: [values]}
#   detail   = small dict kept in the result for the report (versions, flags)

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


def _x_go(nr):
    bi = nr.get("build_info") or {}
    mod = bi.get("module") or {}
    path = (mod.get("main") or {}).get("path") or mod.get("path")
    vcs = {s.get("key"): s.get("value") for s in mod.get("settings") or []
           if str(s.get("key", "")).startswith("vcs")}
    detail = {"go_version": bi.get("go_version")} if bi.get("go_version") else {}
    if vcs:
        detail["vcs"] = vcs
    return [], {"rea_go_module": [path] if path else []}, detail


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
    binary = rea_bin()
    if not binary:
        return {"status": "not_installed", "pinned_version": pinned,
                "limitation": limitation("REA is not installed")}
    if not plan:
        return {"status": "not_applicable", "pinned_version": pinned, "kind": kind}
    version = rea_version(binary)
    out = {"status": "ran", "version": version, "pinned_version": pinned, "kind": kind,
           "runs": [], "iocs": {}, "trackers": {}, "citations": [], "detail": {}}
    if version != pinned:
        out["version_note"] = (f"installed REA {version or '?'} is not the pinned {pinned}; output "
                               "shapes may differ — upgrade/downgrade by hand, never automatically")
    flags, literals = {}, []
    for step in plan:
        cmd = step.get("command")
        if cmd not in _STATIC_CEILING:
            sys.stderr.write(f"[bp_rea] refused {cmd!r}: not a static command (ceiling in bp_rea.py)\n")
            out["runs"].append({"command": cmd, "status": "refused"})
            continue
        if step.get("when") and not flags.get(step["when"]):
            out["runs"].append({"command": cmd, "status": "skipped", "reason": f"{step['when']} false"})
            continue
        status, doc, err = _call(binary, cmd, path, list(step.get("args") or []),
                                 int(step.get("timeout") or 300))
        run = {"command": cmd, "status": status}
        if err:
            run["error"] = err
        if doc is not None:
            run["evidence_id"] = doc.get("evidence_id")
            nr = doc.get("normalized_result") or {}
            lits, facts, detail = _EXTRACTORS.get(cmd, lambda _nr: ([], {}, {}))(nr)
            flags.update({k: v for k, v in detail.items() if isinstance(v, bool)})
            if detail:
                out["detail"][cmd] = detail
            for label, vals in facts.items():
                bucket = out["trackers"].setdefault(label, [])
                bucket += [v for v in vals if v and v not in bucket]
                del bucket[int(LIMITS.get("max_facts_per_label", 40)):]
            literals += [(v, cmd, loc) for v, loc in lits]
            run["literals"] = len(lits)
            if evidence_dir:
                try:
                    os.makedirs(evidence_dir, exist_ok=True)
                    sha = (doc.get("subject") or {}).get("digest", {}).get("sha256") or "sample"
                    dest = os.path.join(evidence_dir, f"{sha}.{cmd}.json")
                    with open(dest, "w", encoding="utf-8") as fh:
                        json.dump(doc, fh, ensure_ascii=False)
                    run["evidence_file"] = dest
                except OSError as e:
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
