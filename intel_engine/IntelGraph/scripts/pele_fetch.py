#!/usr/bin/env python3
"""
pele_fetch.py — install the pinned Pele Mermaid renderer into IntelGraph/vendor/pele/.

Pele (github.com/obsidianmd/pele) is one dependency-free ES module. render_mermaid.py runs it
under Node or Bun; this script is the single place that puts it on disk. The installers call it,
and render_mermaid.py calls ensure() on first use when the module is missing, so a checkout that
predates the installer step still renders.

Pin, tarball URL and sha512 integrity live in references/pele.json (contributor RULE 3). The
tarball is verified BEFORE anything is extracted, and only the members that file names are
written — nothing in the archive is executed.

Usage:
  pele_fetch.py            # install if missing or at another version; prints the module path
  pele_fetch.py --check    # exit 0 if the pinned version is installed, 1 otherwise (no network)
"""
import argparse
import base64
import hashlib
import io
import os
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ig_refs import load_ref, ref_path  # noqa: E402

try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "WebPivot", "tools"))
    from wp_common import DEFAULT_UA as _UA  # noqa: E402
except Exception:  # noqa: BLE001 — standalone IntelGraph copy
    _UA = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36")

# Conservative fallback: no pin. A broken pele.json must refuse to download, never fetch an
# unverified "latest".
_PELE_FALLBACK = {"release": {}, "files": {}}
_REF = load_ref(ref_path(__file__, "pele.json"), _PELE_FALLBACK)
RELEASE = _REF["release"]
FILES = _REF["files"]

VENDOR_DIR = os.path.normpath(os.path.join(HERE, "..", "vendor", "pele"))
MODULE = os.path.join(VENDOR_DIR, "pele.mjs")   # .mjs: Node 20 treats a bare .js as CommonJS
_VERSION_FILE = os.path.join(VENDOR_DIR, "VERSION")


def installed_version():
    try:
        with open(_VERSION_FILE, encoding="utf-8") as fh:
            v = fh.read().strip()
    except OSError:
        return None
    return v if os.path.isfile(MODULE) else None


def _verify(blob, integrity):
    algo, _, want = (integrity or "").partition("-")
    if algo not in ("sha512", "sha384", "sha256") or not want:
        raise ValueError(f"pele.json integrity {integrity!r} is not an npm sha512/384/256 value")
    got = base64.b64encode(hashlib.new(algo, blob).digest()).decode()
    if got != want:
        raise ValueError(f"tarball {algo} mismatch (got {got[:16]}…) — NOT installed")


def ensure(timeout=60):
    """Return the path of the pinned pele.mjs, downloading it first if needed. Raises on failure."""
    version = RELEASE.get("version")
    if not (version and RELEASE.get("tarball") and RELEASE.get("integrity") and FILES):
        raise RuntimeError("references/pele.json carries no usable pin — refusing to download")
    if installed_version() == version:
        return MODULE
    req = urllib.request.Request(RELEASE["tarball"], headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — pinned https URL
        blob = resp.read()
    _verify(blob, RELEASE["integrity"])
    os.makedirs(VENDOR_DIR, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member, name in FILES.items():
            src = tar.extractfile(member)
            if src is None:
                raise RuntimeError(f"tarball has no {member}")
            dst = os.path.join(VENDOR_DIR, os.path.basename(name))
            with open(dst + ".tmp", "wb") as fh:
                fh.write(src.read())
            os.replace(dst + ".tmp", dst)
    with open(_VERSION_FILE, "w", encoding="utf-8") as fh:
        fh.write(version + "\n")
    return MODULE


def main():
    ap = argparse.ArgumentParser(description="Install the pinned Pele Mermaid renderer.")
    ap.add_argument("--check", action="store_true",
                    help="exit 0 if the pinned version is installed, 1 otherwise (no network)")
    args = ap.parse_args()
    if args.check:
        have = installed_version()
        print(f"pele {have or 'missing'} (pinned {RELEASE.get('version') or 'none'})")
        raise SystemExit(0 if have and have == RELEASE.get("version") else 1)
    try:
        path = ensure()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"pele: {exc}")
    print(f"pele {RELEASE['version']} -> {path}")


if __name__ == "__main__":
    main()
