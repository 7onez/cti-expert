#!/usr/bin/env python3
"""Offline end-to-end case binary processing: local HTTP, real static analyzer, stub sandbox."""
import hashlib
import io
import importlib.util
import json
import os
import sys
import tempfile
import threading
import types
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
import binary_auto as ba  # noqa: E402


def check():
    passed, failed, lines = 0, 0, []

    def ok(cond, label):
        nonlocal passed, failed
        lines.append(("ok" if cond else "FAIL", label))
        passed += bool(cond)
        failed += not cond
    ar = ba.bp_anyrun
    saved_env, saved_cwd = dict(os.environ), os.getcwd()
    saved_file, saved_loaded = ar.__file__, ar._ENV_LOADED
    try:
        with tempfile.TemporaryDirectory() as isolated:
            os.chdir(isolated)
            os.environ.clear()
            os.environ.update({"HOME": isolated,
                               "CTI_API_KEYS_ENV": os.path.join(isolated, ".env")})
            ar.__file__ = os.path.join(isolated, "intel_engine", "BinaryPivot", "tools", "bp_anyrun.py")
            with open(os.environ["CTI_API_KEYS_ENV"], "w", encoding="utf-8") as out:
                out.write("")
            ar._ENV_LOADED = False
            ok(not ar.anyrun_configured(), "empty isolated .env cannot enable sandbox submission")
            with open(os.environ["CTI_API_KEYS_ENV"], "w", encoding="utf-8") as out:
                out.write("ANYRUN_API_KEY=test-key-not-a-real-credential\n")
            ar._ENV_LOADED = False
            ok(ar.anyrun_configured(), "a configured .env key enables the sandbox branch")
    finally:
        ar.__file__, ar._ENV_LOADED = saved_file, saved_loaded
        os.environ.clear()
        os.environ.update(saved_env)
        os.chdir(saved_cwd)


    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic manifest")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\0" * 32)
    sample = payload.getvalue()
    sha = hashlib.sha256(sample).hexdigest()
    payload_alt = io.BytesIO()
    with zipfile.ZipFile(payload_alt, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"second synthetic manifest")
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\0" * 32)
    sample_alt = payload_alt.getvalue()
    sha_alt = hashlib.sha256(sample_alt).hexdigest()

    user_agents = {}
    hits = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            user_agents[self.path] = self.headers.get("User-Agent", "")
            hits[self.path] = hits.get(self.path, 0) + 1
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.end_headers()
            self.wfile.write(sample_alt if self.path.endswith("?v=2") else sample)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    orig_key, orig_submit = ba.bp_anyrun.anyrun_configured, ba.bp_anyrun.submit
    submissions = []
    try:
        with tempfile.TemporaryDirectory() as root:
            url = f"http://localhost:{server.server_port}/app.apk"
            for case in ("CASE-0001", "CASE-0002", "CASE-0003", "CASE-0004",
                         "CASE-0005", "CASE-0006", "CASE-0007", "CASE-0008", "CASE-0009"):
                raw = os.path.join(root, "cases", case, "raw")
                os.makedirs(raw)
                with open(os.path.join(raw, "example.com.json"), "w", encoding="utf-8") as out:
                    json.dump({"meta": {"host": "example.com"},
                               "pivots": [{"kind": "app:apk", "value": url}]}, out)
            raw5 = os.path.join(root, "cases", "CASE-0005", "raw", "example.com.json")
            with open(raw5, "w", encoding="utf-8") as out:
                json.dump({"meta": {"host": "example.com"},
                           "pivots": [{"kind": "app:apk", "value": url},
                                      {"kind": "app:apk", "value": url + "?v=2"}]}, out)
            mirrors = (url + "?ref=one", url + "?ref=two")
            raw9 = os.path.join(root, "cases", "CASE-0009", "raw", "example.com.json")
            with open(raw9, "w", encoding="utf-8") as out:
                json.dump({"meta": {"host": "example.com"},
                           "pivots": [{"kind": "app:apk", "value": u} for u in mirrors]}, out)
            for case, kind, path in (("CASE-0007", "app:apk", "/fetch"),
                                     ("CASE-0008", "app:desktop_installer", "/installer.msi")):
                raw = os.path.join(root, "cases", case, "raw", "example.com.json")
                with open(raw, "w", encoding="utf-8") as out:
                    json.dump({"meta": {"host": "example.com"},
                               "pivots": [{"kind": kind,
                                           "value": f"http://localhost:{server.server_port}{path}"}]}, out)
            ba.bp_anyrun.anyrun_configured = lambda: False
            kb_live = os.path.join(root, "kb_live")
            notes = ba.run("CASE-0001", root=root)
            ingested, _ = ba.ingest(os.path.join(root, "cases", "CASE-0001"), kb_live)
            bin_dir = os.path.join(root, "cases", "CASE-0001", "bin")
            files = [name for name in os.listdir(bin_dir) if os.path.isfile(os.path.join(bin_dir, name))]
            ok(len(files) == 1 and files[0].startswith(sha) and
               open(os.path.join(bin_dir, files[0]), "rb").read() == sample,
               "keyless run downloads exact APK bytes and keeps a hash-named local copy")
            ok(any("no key" in n for n in notes) and
               os.path.isfile(os.path.join(bin_dir, "analysis", f"{sha}.json")) and
               json.load(open(os.path.join(root, "cases", "CASE-0001", "raw", "example.com.json")))
               ["meta"]["host"] == "example.com",
               "keyless static result survives without overwriting the web collection")
            ok(ingested and
               os.path.isdir(os.path.join(kb_live, "evidence", f"binarypivot_{sha}")) and
               set(os.listdir(os.path.join(root, "cases", "CASE-0001", "raw"))) == {"example.com.json"},
               "automatic binary KB ingestion preserves a single web host in raw")
            notes5 = ba.run("CASE-0005", root=root)
            copies = {name for name in os.listdir(os.path.join(root, "cases", "CASE-0005", "bin"))
                      if os.path.isfile(os.path.join(root, "cases", "CASE-0005", "bin", name))}
            ok(len(copies) == 2 and
               any(name.startswith(sha) for name in copies) and
               any(name.startswith(sha_alt) for name in copies) and
               sum("statically analysed" in note for note in notes5) == 2,
               "same URL basename with different bytes never overwrites another local sample")
            ba.run("CASE-0009", root=root, free_only=True)
            before = tuple(hits.get("/app.apk?" + u.split("?")[1], 0) for u in mirrors)
            analysis9 = ba.bin_json_path(os.path.join(root, "cases", "CASE-0009"), sha)
            stored = json.load(open(analysis9))
            resumed = ba.run("CASE-0009", root=root, free_only=True)
            after = tuple(hits.get("/app.apk?" + u.split("?")[1], 0) for u in mirrors)
            ok(before == after == (1, 1) and
               set(stored["sources"]) == set(mirrors) and
               not any("statically analysed" in n for n in resumed),
               "mirrored URLs yielding one SHA are not re-downloaded on resume")
            notes7 = ba.run("CASE-0007", root=root, free_only=True)
            notes8 = ba.run("CASE-0008", root=root, free_only=True)
            ok("Android" in user_agents.get("/fetch", "") and
               "Windows" in user_agents.get("/installer.msi", "") and
               any("statically analysed" in n for n in notes7 + notes8) and
               os.path.isfile(os.path.join(root, "cases", "CASE-0007", "bin", sha + ".bin")),
               "APK pivots use Android UA even without an extension; installers use desktop UA")
            from analyze_artifact import acquire
            acquired, _ = acquire(f"http://localhost:{server.server_port}/download.php")
            ok(acquired == sample and "Android" in user_agents.get("/download.php", ""),
               "standalone extensionless binary URLs default to Android UA")

            ba.bp_anyrun.anyrun_configured = lambda: True
            ba.bp_anyrun.submit = lambda path, **kw: (submissions.append((path, kw)) or
                                                     {"submitted": True, "task_uuid": "synthetic-task",
                                                      "privacy_verified": False})
            notes = ba.run("CASE-0001", root=root, free_only=True)
            ok(not submissions and any("free-only" in n for n in notes),
               "free-only prevents sandbox upload but preserves static result")
            notes = ba.run("CASE-0001", root=root)
            ok(len(submissions) == 1 and submissions[0][0] == os.path.join(bin_dir, files[0]) and
               submissions[0][1] == {"confirm": True, "env_os": "android"},
               "keyed run submits the saved local APK through the gated submit API")
            ledger = os.path.join(root, "cases", "CASE-0001", "anyrun", "submissions.json")
            ok(json.load(open(ledger))[sha]["task_uuid"] == "synthetic-task" and
               len(submissions) == 1 and any("already attempted" in n for n in ba.run("CASE-0001", root=root)),
               "task uuid is persisted and resumed runs never resubmit a hash")
            attempts = []
            ba.bp_anyrun.submit = lambda path, **kw: (attempts.append(path) or
                                                     {"refused": "public task requires authorization"})
            notes = ba.run("CASE-0007", root=root)
            ledger7 = os.path.join(root, "cases", "CASE-0007", "anyrun", "submissions.json")
            ok(any("requires authorization" in n for n in notes) and
               sha not in json.load(open(ledger7)) and len(attempts) == 1,
               "pre-POST privacy refusal is not pinned as a completed task")
            ba.bp_anyrun.submit = lambda path, **kw: (attempts.append(path) or
                                                     {"submitted": True, "task_uuid": "synthetic-second"})
            ba.run("CASE-0007", root=root)
            ok(len(attempts) == 2 and json.load(open(ledger7))[sha]["task_uuid"] == "synthetic-second"
               and any("already attempted" in n for n in ba.run("CASE-0007", root=root)),
               "authorization change retries a denied pre-POST attempt but not a created task")
            ba.bp_anyrun.submit = lambda path, **kw: {
                "submitted": True, "task_uuid": "synthetic-third", "privacy_verified": None,
                "privacy_note": "verify task privacy after completion",
                "verify_command": "bp_anyrun.py verify-privacy synthetic-third"}
            notes = ba.run("CASE-0008", root=root)
            ledger8 = json.load(open(os.path.join(root, "cases", "CASE-0008",
                                                   "anyrun", "submissions.json")))[sha]
            ok(any("verify task privacy" in n for n in notes) and
               ledger8["verify_command"] == "bp_anyrun.py verify-privacy synthetic-third" and
               "privacy verification pending" in ledger8["status"],
               "unverified sandbox privacy stays visible alongside the task UUID")
            # A fabricated raw JSON must not turn an arbitrary local file into an upload.
            private_path = os.path.join(root, "unrelated.txt")
            with open(private_path, "wb") as out:
                out.write(sample)
            forged = os.path.join(root, "cases", "CASE-0006", "bin", "analysis", f"{sha}.json")
            os.makedirs(os.path.dirname(forged))
            with open(forged, "w", encoding="utf-8") as out:
                json.dump({"meta": {"source": url, "saved_to": private_path, "http_status": 200},
                           "artifacts": {"binary": {"file_kind": "apk",
                                                    "hashes": {"sha256": sha}}}}, out)
            notes = ba.run("CASE-0006", root=root)
            forged_ing = ba.ingest(os.path.join(root, "cases", "CASE-0006"),
                                    os.path.join(root, "neg_kb_forged"))
            ok(any("saved file moved or hash mismatch" in n for n in notes) and
               len(submissions) == 1 and forged_ing == (True, "") and
               not os.path.exists(os.path.join(root, "neg_kb_forged", "evidence")),
               "case JSON cannot redirect sandbox upload to an unrelated local file")

            notes = ba.run("CASE-0002", root=root, hostile=True)
            ok(any("blocked" in n for n in notes) and
               not os.path.exists(os.path.join(root, "cases", "CASE-0002", "bin")) and
               len(submissions) == 1,
               "explicit hostile flag refuses direct download even without a scope file")
            scope = os.path.join(root, "cases", "CASE-0002", "scope.json")
            with open(scope, "w", encoding="utf-8") as out:
                json.dump({"constraints": {"no_direct_contact": True}}, out)
            ok(any("blocked" in n for n in ba.run("CASE-0002", root=root)),
               "persisted no-direct-contact posture also refuses download")
            scope = os.path.join(root, "cases", "CASE-0003", "scope.json")
            with open(scope, "w", encoding="utf-8") as out:
                json.dump({"constraints": {"no_spend": True}}, out)
            notes = ba.run("CASE-0003", root=root)
            ok(any("statically analysed" in n for n in notes) and
               any("free-only/no_spend" in n for n in notes) and len(submissions) == 1,
               "persisted no_spend still downloads and analyzes but never uploads")
            bad_raw = os.path.join(root, "cases", "CASE-0004", "raw")
            partial = b"partial sample"
            partial_sha = hashlib.sha256(partial).hexdigest()
            partial_file = os.path.join(root, "cases", "CASE-0004", "bin", partial_sha + ".apk")
            os.makedirs(os.path.dirname(partial_file))
            with open(partial_file, "wb") as out:
                out.write(partial)
            os.makedirs(os.path.join(root, "cases", "CASE-0004", "bin", "analysis"), exist_ok=True)
            with open(os.path.join(root, "cases", "CASE-0004", "bin", "analysis",
                                   f"{partial_sha}.json"), "w", encoding="utf-8") as out:
                json.dump({"meta": {"source": url, "saved_to": partial_file, "truncated": True,
                                    "http_status": 200},
                           "artifacts": {"binary": {"file_kind": "apk",
                                                    "hashes": {"sha256": partial_sha}}}}, out)
            notes = ba.run("CASE-0004", root=root)
            trunc_ing = ba.ingest(os.path.join(root, "cases", "CASE-0004"),
                                   os.path.join(root, "neg_kb_trunc"))
            ok(any("incomplete/non-binary" in n for n in notes) and len(submissions) == 1 and
               trunc_ing == (True, "") and
               not os.path.exists(os.path.join(root, "neg_kb_trunc", "evidence")),
               "truncated downloads are never submitted, deduped, or ingested into the KB")
            # The binary must not replace the host's web evidence inside the KB either.
            kb_tools = os.path.join(ROOT, "intel_engine", "tools", "kb")
            if kb_tools not in sys.path:
                sys.path.insert(0, kb_tools)
            from ingest_webpivot import ingest_file
            from knowledge_base import KB
            raw_dir = os.path.join(root, "cases", "CASE-0001", "raw")
            binary_path = os.path.join(bin_dir, "analysis", f"{sha}.json")
            binary_doc = json.load(open(binary_path))
            binary_doc["meta"]["host"] = "example.com"
            binary_doc["artifacts"]["trackers"] = {"apk_signing_cert": ["a" * 64]}
            with open(binary_path, "w", encoding="utf-8") as out:
                json.dump(binary_doc, out)
            kb = KB(os.path.join(root, "kb"))
            ingest_file(kb, os.path.join(raw_dir, "example.com.json"))
            ingest_file(kb, binary_path)
            sources = os.listdir(os.path.join(root, "kb", "evidence"))
            ok("webpivot" in sources and f"binarypivot_{sha}" in sources,
               "KB preserves both web and same-host binary evidence on the same day")
            ok(("indicator", "apk_signing_cert:" + "a" * 64, "uses_tracker", 0.6)
               in kb.neighbors("domain", "example.com") and
               any(t == "indicator" and v == "apk_signing_cert:" + "a" * 64
                   for t, v, _, _ in kb.neighbors("file_hash", sha)),
               "collected self-hosted seed and its file retain owner-specific joins")
            # Managed-provider half of the CLAUDE.md Rule 5 pair: the download host is ALSO a
            # collected "site", so the raw-exists + host-match owner check passes — only
            # is_shared_infra_apex may veto the operator edge. Two unrelated scam sites distribute
            # APKs that share a signing cert (a common repacker template) from one shared CDN.
            shared_host = "cdn.mediafire.com"
            cert = "b" * 64
            case_dir = os.path.join(root, "cases", "CASE-0010")
            os.makedirs(os.path.join(case_dir, "raw"))
            for site in (shared_host, "alpha.example", "beta.example"):
                with open(os.path.join(case_dir, "raw", site + ".json"), "w", encoding="utf-8") as out:
                    json.dump({"meta": {"host": site}, "pivots": []}, out)
            for digest, payload, ref in ((sha, sample, "one"), (sha_alt, sample_alt, "two")):
                saved_bin = os.path.join(case_dir, "bin", digest + ".apk")
                os.makedirs(os.path.dirname(saved_bin), exist_ok=True)
                with open(saved_bin, "wb") as out:
                    out.write(payload)
                doc = {"meta": {"host": shared_host, "http_status": 200, "saved_to": saved_bin,
                                "collector": "binarypivot/analyze_artifact",
                                "source": f"https://{shared_host}/{ref}.apk"},
                       "artifacts": {"binary": {"file_kind": "apk", "hashes": {"sha256": digest}},
                                     "trackers": {"apk_signing_cert": [cert]}}}
                path = ba.save_analysis(case_dir, doc)
                ok(path is not None, f"complete storage-host binary {ref} is persisted")
                ingest_file(kb, path)
            for site in (shared_host, "alpha.example", "beta.example"):
                ingest_file(kb, os.path.join(case_dir, "raw", site + ".json"))
            shared_edges = kb.neighbors("domain", shared_host)
            ok(not any(t == "indicator" and str(v).startswith("apk_signing_cert:")
                       for t, v, _, _ in shared_edges) and
               all(("indicator", "apk_signing_cert:" + cert, "uses_tracker", 0.6)
                   in kb.neighbors("file_hash", digest) and
                   any(f["attribute"] == "served_from" and f["value"] == shared_host
                       for f in kb.entity("file_hash", digest)["facts"])
                   for digest in (sha, sha_alt)) and
               not any(str(row["indicator"]).startswith("apk_signing_cert:")
                       for row in kb.shared_indicators()),
               "shared download host never carries a signing-cert edge or fuses two APK owners")
            evidence_dir = os.path.join(root, "kb", "evidence", f"binarypivot_{sha}")
            ok(os.path.isdir(os.path.join(evidence_dir, sha + "_CASE-0001")) and
               os.path.isdir(os.path.join(evidence_dir, sha + "_CASE-0010")),
               "identical file hashes retain separate collection provenance across cases")

            # Exercise the real manual analyzer and KB writer without requiring the optional SDK.
            sdk = types.ModuleType("claude_agent_sdk")
            sdk.ToolAnnotations = lambda **_: None
            sdk.create_sdk_mcp_server = lambda *_a, **_kw: None
            sdk.tool = lambda *_a, **_kw: lambda fn: fn
            original_sdk = sys.modules.get("claude_agent_sdk")
            try:
                sys.modules["claude_agent_sdk"] = sdk
                spec = importlib.util.spec_from_file_location(
                    "test_binary_harness_tools", os.path.join(ROOT, "intel_engine", "harness", "tools.py"))
                tools = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(tools)
                isolated_engine = os.path.join(root, "manual_engine")
                os.makedirs(isolated_engine)
                os.symlink(os.path.join(ROOT, "intel_engine", "BinaryPivot"),
                           os.path.join(isolated_engine, "BinaryPivot"))
                tools.ROOT = isolated_engine
                tools.KB_DIR = os.path.join(root, "manual_kb")
                tools.POLICY["hostile"] = False
                sample_path = os.path.join(root, "sample.apk")
                with open(sample_path, "wb") as out:
                    out.write(sample)
                result = tools.collect_binary(sample_path, case="CASE-0012")
                reingested, _ = tools.ingest("CASE-0012")
                manual_case = os.path.join(isolated_engine, "cases", "CASE-0012")
                manual_kb = KB(tools.KB_DIR)
                ok(result["ok"] and reingested and
                   result["saved"] == ba.bin_json_path(manual_case, sha) and
                   os.path.isfile(result["saved"]) and
                   not os.path.exists(os.path.join(manual_case, "raw")) and
                   manual_kb.entity("file_hash", sha) is not None and
                   os.path.isdir(os.path.join(tools.KB_DIR, "evidence", f"binarypivot_{sha}")),
                   "manual analyzer writes isolated case binary and ingests scoped KB")
            finally:
                if original_sdk is None:
                    sys.modules.pop("claude_agent_sdk", None)
                else:
                    sys.modules["claude_agent_sdk"] = original_sdk
            # Sandbox submissions do not deplete the distinct TI Lookup request allowance.
            ar = ba.bp_anyrun
            prev = ar.api_usage, ar._log_path, ar._RUN_SPENT, ar._MONTH_SPENT
            try:
                ar.api_usage = None
                ar._log_path = lambda: os.path.join(root, "usage.jsonl")
                ar._RUN_SPENT, ar._MONTH_SPENT = 0, 0
                for _ in range(11):
                    ar._record("submit", ar.REQUEST_BUDGET["submit_costs"], "file:synthetic")
                ok(ar._RUN_SPENT == 0 and ar.month_spent(refresh=True) == 0 and
                   ar._budget_block(1, "TI Lookup") is None,
                   "eleven sandbox uploads leave TI Lookup allowance untouched")
            finally:
                ar.api_usage, ar._log_path, ar._RUN_SPENT, ar._MONTH_SPENT = prev
    finally:
        ba.bp_anyrun.anyrun_configured, ba.bp_anyrun.submit = orig_key, orig_submit
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return passed, failed, lines


if __name__ == "__main__":
    passed, failed, lines = check()
    for status, label in lines:
        print(f"{status}: {label}")
    raise SystemExit(bool(failed))
