#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
evidence-images.py — turn captured screenshots into the report JSON `evidence_images`
array (base64 data URIs), so findings get visual backup in the HTML / DOCX / PDF exports.

The report generators (generate-cti-html.py, generate-cti-docx-hybrid.py) render an
`evidence_images` top-level array. Each entry:

    {
      "caption": "Login page impersonating Bank X",   // optional, human label
      "host": "phish.example",                          // optional
      "data_uri": "data:image/png;base64,....",         // REQUIRED (offline-safe)
      "sha256": "....",                                 // auto-added, citable
      "captured_at": "2026-08-27T18:00:00Z",            // optional
      "source_url": "https://phish.example/login",      // optional
      "finding_id": "FND-003",                          // optional — backs a finding
      "subject_id": "SUB-002"                           // optional
    }

Inputs (stdlib only — no Pillow, images embedded as-is):
  - explicit PNG/JPG paths, and/or
  - --case <dir>: pull every screenshot a case captured, reading
    <case>/evidence/manifest.jsonl (`screenshot_path`, `host`, `collected_at`,
    `source_url`) when present, else globbing <case>/screenshots/*.png and
    <case>/evidence/screenshots/**/*.png.

Output:
  - default: prints the JSON array to stdout.
  - --into report.json: merges the entries into that report JSON's `evidence_images`
    (creating/extending the array), de-duplicated by sha256, and writes it back.

Usage:
  uv run evidence-images.py shot1.png shot2.png --caption "Phishing login" > evid.json
  uv run evidence-images.py --case intel_engine/cases/CASE-XXXX --into REPORT.json
  python3 evidence-images.py --case <dir> --finding FND-003 --into REPORT.json
"""
import argparse
import base64
import datetime
import glob
import hashlib
import json
import os
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
         ".gif": "image/gif", ".webp": "image/webp"}


def _entry(path, caption=None, host=None, captured_at=None, source_url=None,
           finding_id=None, subject_id=None):
    """Build one evidence_images entry from an image file, or None if unreadable."""
    ext = os.path.splitext(path)[1].lower()
    mime = _MIME.get(ext)
    if not mime:
        sys.stderr.write("skip (unsupported image type): %s\n" % path)
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        sys.stderr.write("skip (unreadable): %s (%s)\n" % (path, e))
        return None
    if not raw:
        sys.stderr.write("skip (empty): %s\n" % path)
        return None
    b64 = base64.b64encode(raw).decode("ascii")
    e = {
        "caption": caption or (host or os.path.basename(path)),
        "data_uri": "data:%s;base64,%s" % (mime, b64),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if host:
        e["host"] = host
    e["captured_at"] = captured_at or datetime.datetime.fromtimestamp(
        os.path.getmtime(path), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if source_url:
        e["source_url"] = source_url
    if finding_id:
        e["finding_id"] = finding_id
    if subject_id:
        e["subject_id"] = subject_id
    return e


def _from_case(case_dir):
    """Yield (path, host, captured_at, source_url) for a case's captured screenshots.
    Prefer the evidence manifest (authoritative provenance); fall back to globbing."""
    manifest = os.path.join(case_dir, "evidence", "manifest.jsonl")
    seen = set()
    root = _repo_root(case_dir)
    if os.path.isfile(manifest):
        with open(manifest, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                sp = row.get("screenshot_path")
                if not sp:
                    continue
                p = sp if os.path.isabs(sp) else os.path.join(root, sp)
                if os.path.isfile(p) and p not in seen:
                    seen.add(p)
                    yield (p, row.get("host"), row.get("collected_at"), row.get("source_url"))
    # fallback / supplement: any PNG under the case's screenshot dirs
    for pat in (os.path.join(case_dir, "screenshots", "*.png"),
                os.path.join(case_dir, "evidence", "screenshots", "**", "*.png")):
        for p in glob.glob(pat, recursive=True):
            if p not in seen:
                seen.add(p)
                host = os.path.splitext(os.path.basename(p))[0]
                yield (p, host, None, None)


def _repo_root(case_dir):
    """cases/<id> lives under intel_engine/cases; manifest paths are repo-relative."""
    d = os.path.abspath(case_dir)
    parts = d.split(os.sep)
    if "cases" in parts:
        return os.sep.join(parts[: parts.index("cases")]) or os.sep
    return os.path.dirname(os.path.dirname(d))


def main(argv):
    ap = argparse.ArgumentParser(description="Build report evidence_images from screenshots.")
    ap.add_argument("images", nargs="*", help="image files (png/jpg/...)")
    ap.add_argument("--case", help="case dir: pull all captured screenshots")
    ap.add_argument("--caption", help="caption applied to explicitly-listed images")
    ap.add_argument("--host", help="host tag applied to explicitly-listed images")
    ap.add_argument("--source-url", help="source_url applied to explicitly-listed images")
    ap.add_argument("--finding", help="finding_id to tag every produced entry (backs a finding)")
    ap.add_argument("--subject", help="subject_id to tag every produced entry")
    ap.add_argument("--into", help="merge into this report JSON's evidence_images and write back")
    a = ap.parse_args(argv)

    entries = []
    for p in a.images:
        e = _entry(p, caption=a.caption, host=a.host, source_url=a.source_url,
                   finding_id=a.finding, subject_id=a.subject)
        if e:
            entries.append(e)
    if a.case:
        for (p, host, cap_at, src) in _from_case(a.case):
            e = _entry(p, host=host, captured_at=cap_at, source_url=src,
                       finding_id=a.finding, subject_id=a.subject)
            if e:
                entries.append(e)

    if not entries:
        sys.stderr.write("no evidence images produced\n")
        return 1

    if a.into:
        try:
            with open(a.into, encoding="utf-8") as f:
                report = json.load(f)
        except (OSError, ValueError) as e:
            sys.stderr.write("error: cannot read report JSON %r: %s\n" % (a.into, e))
            return 1
        existing = report.get("evidence_images") or []
        have = {im.get("sha256") for im in existing if isinstance(im, dict)}
        added = [e for e in entries if e["sha256"] not in have]
        report["evidence_images"] = existing + added
        with open(a.into, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        sys.stderr.write("merged %d new evidence image(s) into %s (%d total)\n"
                         % (len(added), a.into, len(report["evidence_images"])))
        return 0

    json.dump(entries, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
