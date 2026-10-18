"""Process APK/installer links discovered in a case, without overwriting web evidence.

Static analysis and the local copy always run. A configured ANY.RUN sandbox key authorizes
submission only in a spending run; the sandbox client still proves private entitlement and
checks the applied privacy. A submission without a task ID is never retried automatically:
the POST may have succeeded even when its response was lost.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BP_TOOLS = os.path.join(ROOT, "BinaryPivot", "tools")
HARNESS = os.path.join(ROOT, "harness")
sys.path.insert(0, BP_TOOLS)
sys.path.append(HARNESS)
import bp_anyrun  # noqa: E402
import case_scope  # noqa: E402


KINDS = {"app:apk", "app:desktop_installer"}
FILE_KINDS = {"apk", "pe", "elf", "macho", "jar", "zip", "dex", "gzip",
              "msi", "deb", "rpm", "pkg", "dmg"}


def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".binary-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, ensure_ascii=False)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}

def bin_json_path(case_dir, sha):
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError("binary analysis needs a SHA-256 file hash")
    return os.path.join(case_dir, "bin", "analysis", sha + ".json")


def _complete(doc, bin_dir):
    """A doc worth persisting/ingesting: a real, fully retrieved binary whose hash matches the
    bytes we hold. Rejects an error/truncated/non-2xx/non-binary download and a `saved_to` that
    points anywhere but a hash-named file in bin/. A LOCAL-file analysis (no download metadata)
    is trusted on its own hash. This gate guards BOTH save and ingest, so neither the automatic
    run nor the manual analyzer can leak an incomplete sample into the KB on a later pass."""
    meta = doc.get("meta") or {}
    if doc.get("error") or meta.get("truncated"):
        return False
    binary = (doc.get("artifacts") or {}).get("binary") or {}
    sha = (binary.get("hashes") or {}).get("sha256")
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        return False
    if binary.get("file_kind") not in FILE_KINDS:
        return False
    status = meta.get("http_status")
    downloaded = (isinstance(status, int) or bool(meta.get("saved_to")) or
                  str(meta.get("source", "")).lower().startswith(("http://", "https://")))
    if downloaded:
        if not (isinstance(status, int) and 200 <= status < 300):
            return False
        saved = meta.get("saved_to")
        if not (isinstance(saved, str) and os.path.isfile(saved) and
                _saved_sample_matches(saved, bin_dir, sha)):
            return False
    return True


def save_analysis(case_dir, doc):
    """One JSON per file; preserve every download URL that produced these bytes. Returns the
    written path, or None when the doc is not a complete binary (never persisted, never ingested)."""
    bin_dir = os.path.join(case_dir, "bin")
    if not _complete(doc, bin_dir):
        return None
    sha = ((((doc.get("artifacts") or {}).get("binary") or {}).get("hashes") or {})
           .get("sha256"))
    path = bin_json_path(case_dir, sha)
    old = _load(path)
    if ((((old.get("artifacts") or {}).get("binary") or {}).get("hashes") or {})
            .get("sha256")) != sha:
        old = {}
    source = (doc.get("meta") or {}).get("source")
    sources = {s for s in (old.get("sources") if isinstance(old.get("sources"), list) else [])
               if isinstance(s, str)}
    sources.update(s for s in (doc.get("sources") if isinstance(doc.get("sources"), list) else [])
                   if isinstance(s, str))
    if isinstance(source, str) and source:
        sources.add(source)
    if old and _saved_sample_matches((old.get("meta") or {}).get("saved_to"), bin_dir, sha):
        doc = old
    doc["sources"] = sorted(sources)
    _save(path, doc)
    return path


def ingest(case_dir, kb):
    """Ingest binary evidence separately; raw/ remains exclusively web-host evidence. Only docs
    that still pass the completeness gate are ingested — a stale truncated/forged JSON left on
    disk by an interrupted run never reaches the KB on a later pass."""
    analysis_dir = os.path.join(case_dir, "bin", "analysis")
    bin_dir = os.path.join(case_dir, "bin")
    if not os.path.isdir(analysis_dir):
        return True, ""
    files = [os.path.join(analysis_dir, name) for name in sorted(os.listdir(analysis_dir))
             if re.fullmatch(r"[0-9a-f]{64}\.json", name) and
             _complete(_load(os.path.join(analysis_dir, name)), bin_dir)]
    if not files:
        return True, ""
    try:
        result = subprocess.run([sys.executable, os.path.join(HERE, "kb", "ingest_webpivot.py"),
                                 "--kb", kb, *files], capture_output=True, text=True,
                                timeout=120, check=False)
        return result.returncode == 0 and "[skip]" not in result.stderr, result.stdout + result.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _saved_sample_matches(path, bin_dir, sha):
    """Never let a case JSON redirect the uploader to an unrelated local file."""
    if (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha) or
            not isinstance(path, str) or
            os.path.dirname(os.path.realpath(path)) != os.path.realpath(bin_dir) or
            not os.path.basename(path).startswith(sha + ".")):
        return False
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest() == sha
    except OSError:
        return False


def _candidates(raw_dir):
    urls = {}
    for name in os.listdir(raw_dir):
        if not name.endswith(".json") or name.startswith("bin_"):
            continue
        for pivot in _load(os.path.join(raw_dir, name)).get("pivots", []):
            if not isinstance(pivot, dict):
                continue
            url = pivot.get("value")
            if pivot.get("kind") not in KINDS or not isinstance(url, str):
                continue
            try:
                if urlsplit(url).scheme in ("http", "https"):
                    if url not in urls or pivot["kind"] == "app:apk":
                        urls[url] = pivot["kind"]
            except ValueError:
                continue
    return dict(sorted(urls.items()))


def run(case, *, hostile=False, free_only=False, root=ROOT):
    """Return human-readable outcomes. Existing on-disk results survive resumes/restarts."""
    case_dir = os.path.join(root, "cases", case)
    raw_dir = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw_dir):
        return []
    scope = case_scope.load(case, root=root) or {}
    hostile = (hostile or os.environ.get("HARNESS_HOSTILE", "").lower() in
               ("1", "true", "yes", "on") or case_scope.is_hostile(scope))
    free_only = free_only or bool((scope.get("constraints") or {}).get("no_spend"))
    urls = _candidates(raw_dir)
    if not urls:
        return []
    if hostile:
        return [f"binary: direct download blocked by hostile egress posture: {url}" for url in urls]

    bin_dir = os.path.join(case_dir, "bin")
    analysis_dir = os.path.join(bin_dir, "analysis")
    ledger_path = os.path.join(case_dir, "anyrun", "submissions.json")
    ledger = _load(ledger_path)
    outcomes = []
    key = bp_anyrun.anyrun_configured()
    existing = {}
    if os.path.isdir(analysis_dir):
        for name in os.listdir(analysis_dir):
            if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
                continue
            doc = _load(os.path.join(analysis_dir, name))
            sources = doc.get("sources") if isinstance(doc.get("sources"), list) else []
            for source in (*sources, (doc.get("meta") or {}).get("source")):
                if isinstance(source, str) and source:
                    existing[source] = doc
    for url, kind in urls.items():
        # Reuse a completed, locally saved static analysis. Do not re-fetch on a resume.
        doc = existing.get(url)
        if doc is None:
            os.makedirs(bin_dir, exist_ok=True)
            fd, temp = tempfile.mkstemp(dir=bin_dir, suffix=".json")
            os.close(fd)
            try:
                res = subprocess.run([sys.executable, os.path.join(BP_TOOLS, "analyze_artifact.py"),
                                      url, "--keep", bin_dir, "-o", temp, "--ua",
                                      "android" if kind == "app:apk" else "desktop"], cwd=root,
                                     capture_output=True, text=True, timeout=300, check=False)
                doc = _load(temp)
                meta = doc.get("meta") or {}
                binary = (doc.get("artifacts") or {}).get("binary") or {}
                status = meta.get("http_status")
                if (res.returncode or doc.get("error") or meta.get("truncated") or
                        not meta.get("saved_to") or not isinstance(status, int) or
                        not 200 <= status < 300 or binary.get("file_kind") not in FILE_KINDS):
                    reason = ("download truncated" if meta.get("truncated") else
                              doc.get("error") or f"not a complete binary (HTTP {status})")
                    outcomes.append(f"binary: skipped {url}: {reason}")
                    if meta.get("saved_to") and os.path.isfile(meta["saved_to"]):
                        os.unlink(meta["saved_to"])
                    continue
                sha = (binary.get("hashes") or {}).get("sha256")
                if not sha:
                    outcomes.append(f"binary: skipped {url}: no sha256 from static analysis")
                    continue
                save_analysis(case_dir, doc)
                outcomes.append(f"binary: statically analysed {url} → {meta['saved_to']} ({sha})")
            except (OSError, subprocess.TimeoutExpired) as exc:
                outcomes.append(f"binary: skipped {url}: {exc}")
                continue
            finally:
                os.unlink(temp)
        meta = doc.get("meta") or {}
        binary = (doc.get("artifacts") or {}).get("binary") or {}
        sha = (binary.get("hashes") or {}).get("sha256")
        saved = meta.get("saved_to")
        status = meta.get("http_status", 200)
        if (not sha or meta.get("truncated") or not saved or not os.path.isfile(saved)
                or not isinstance(status, int) or not 200 <= status < 300
                or binary.get("file_kind") not in FILE_KINDS):
            outcomes.append(f"binary: upload skipped for {url}: incomplete/non-binary download (HTTP {status})")
            continue
        if not _saved_sample_matches(saved, bin_dir, sha):
            outcomes.append(f"binary: skipped for {sha}: saved file moved or hash mismatch")
            continue
        if not key:
            outcomes.append(f"binary: ANY.RUN skipped for {sha}: no key (static only)")
            continue
        if free_only:
            outcomes.append(f"binary: ANY.RUN skipped for {sha}: free-only/no_spend (static only)")
            continue
        if sha in ledger:
            outcomes.append(f"binary: ANY.RUN already attempted for {sha}: {ledger[sha].get('task_uuid') or 'check task history before retry'}")
            continue
        # Persist the intent before POST: a lost response or interruption must not create a second
        # public/private task on the next loop run. Reconciliation is a deliberate analyst action.
        ledger[sha] = {"source": url, "file": saved, "status": "pending; check history before retry"}
        try:
            _save(ledger_path, ledger)
        except OSError as exc:
            outcomes.append(f"binary: ANY.RUN skipped for {sha}: cannot checkpoint submission ({exc})")
            continue
        try:
            result = bp_anyrun.submit(saved, confirm=True,
                                      env_os="android" if binary.get("file_kind") == "apk" else None)
        except Exception as exc:
            result = {"error": str(exc)}
        uuid = result.get("task_uuid")
        reason = (result.get("refused") or result.get("skipped") or result.get("error")
                  or "unknown; check history before retry")
        # Only a pre-POST refusal is safe to retry. Privacy read-back can also return
        # 'refused', but it carries a UUID for a task already created (and perhaps exposed).
        retryable = not uuid and (result.get("refused") or result.get("skipped"))
        if retryable:
            del ledger[sha]
        else:
            status = (reason if result.get("refused") else
                      "submitted (PUBLIC task)" if result.get("public_task") else
                      "submitted; privacy verification pending" if uuid and result.get("privacy_note") else
                      "submitted" if uuid else reason)
            ledger[sha].update({"task_uuid": uuid, "task_url": result.get("task_url"),
                                "status": status,
                                "privacy_verified": result.get("privacy_verified"),
                                "privacy_applied": result.get("privacy_applied"),
                                "verify_command": result.get("verify_command")})
        try:
            _save(ledger_path, ledger)
        except OSError as exc:
            outcomes.append(f"binary: ANY.RUN outcome for {sha}, but task record could not be saved: {exc}")
        outcomes.append(f"binary: ANY.RUN {sha}: {reason if retryable else ledger[sha]['status']}")
        if result.get("privacy_note"):
            outcomes.append(f"binary: ANY.RUN {sha}: {result['privacy_note']}")
    return outcomes
