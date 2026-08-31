#!/usr/bin/env python3
"""
Hybrid CTI Report DOCX Generator
Combines full narrative from Markdown with charts/diagrams from JSON.

Usage:
    python3 generate-cti-docx-hybrid.py <report.md> <report.json> <output.docx>
    python3 generate-cti-docx-hybrid.py <report.md> <report.json>
    python3 generate-cti-docx-hybrid.py <report.md> <output.docx>   # MD-only mode
    python3 generate-cti-docx-hybrid.py <report.md>                 # MD-only, auto name

Phase 1: pandoc converts MD to DOCX (preserves all tables, lists, formatting).
Phase 2: python-docx post-processes to add CTI styling, cover page, TOC, and
         injects charts/diagrams from JSON at matching section headings.

Recommended runner (zero setup, any OS): `uv run generate-cti-docx-hybrid.py ...`
uv reads the inline dependency metadata below and provisions an ephemeral env.
"""
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "python-docx>=1.0.0",
#     "matplotlib>=3.8.0",
#     "networkx>=3.2.0",
#     "cairosvg>=2.7.0",
# ]
# ///
import sys
import os
import json
import shutil
import subprocess
import tempfile
import datetime

# Force UTF-8 console output so arrow/box-drawing chars (→, ✔, ─) don't crash
# under Windows' default cp1252 code page. Harmless no-op on macOS/Linux.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)


def ensure_deps():
    """Ensure runtime deps are importable. Prefer uv (fast, cross-platform); fall back to pip.

    Under `uv run` the deps are already provided by the inline metadata above, so this
    is a no-op — it only does work under a bare `python script.py` invocation.
    """
    required = {"python-docx": "docx", "matplotlib": "matplotlib", "networkx": "networkx", "cairosvg": "cairosvg"}
    missing = []
    for pkg, mod in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    # Prefer uv: installs into the current interpreter, fast, identical on every OS.
    if shutil.which("uv"):
        try:
            subprocess.check_call(["uv", "pip", "install", "--python", sys.executable, *missing],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except (subprocess.CalledProcessError, OSError):
            pass
    # pip fallback: --break-system-packages is needed on Debian/PEP-668 envs but
    # rejected by pip < 23; retry without it so all platforms install.
    base = [sys.executable, "-m", "pip", "install"]
    try:
        subprocess.check_call(base + ["--break-system-packages", *missing],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.check_call(base + missing,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


ensure_deps()

from docx import Document
from cti_docx_postprocess import (
    apply_cti_styles, rebuild_with_cover_toc_and_charts, setup_header_footer_compat,
)


def ensure_pandoc():
    """Locate pandoc on any OS; install via the platform package manager if missing.

    pandoc is required for Phase 1 (Markdown -> DOCX). On Windows it is commonly
    installed under %LOCALAPPDATA%\\Pandoc but not added to PATH, so probe the
    usual locations before attempting an install.
    """
    if shutil.which("pandoc"):
        return

    # Probe common install dirs that may not be on PATH (esp. Windows).
    probe_dirs = []
    if os.name == "nt":
        for base in (os.environ.get("LOCALAPPDATA"), os.environ.get("ProgramFiles"),
                     os.environ.get("ProgramFiles(x86)")):
            if base:
                probe_dirs.append(os.path.join(base, "Pandoc"))
    else:
        probe_dirs += ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"]
    exe = "pandoc.exe" if os.name == "nt" else "pandoc"
    for d in probe_dirs:
        if os.path.isfile(os.path.join(d, exe)):
            os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
            return

    # Still missing — try a quiet, OS-appropriate install, then re-check.
    install_cmd = None
    if sys.platform == "darwin" and shutil.which("brew"):
        install_cmd = ["brew", "install", "pandoc"]
    elif sys.platform.startswith("linux"):
        if shutil.which("apt-get"):
            install_cmd = ["sudo", "apt-get", "install", "-y", "pandoc"]
        elif shutil.which("dnf"):
            install_cmd = ["sudo", "dnf", "install", "-y", "pandoc"]
        elif shutil.which("pacman"):
            install_cmd = ["sudo", "pacman", "-S", "--noconfirm", "pandoc"]
    elif os.name == "nt" and shutil.which("winget"):
        install_cmd = ["winget", "install", "--id", "JohnMacFarlane.Pandoc", "--exact",
                       "--accept-package-agreements", "--accept-source-agreements"]

    if install_cmd:
        try:
            subprocess.run(install_cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        except OSError:
            pass

    if not shutil.which("pandoc"):
        raise RuntimeError(
            "pandoc not found and automatic install was unavailable. Install it manually:\n"
            "  Windows: winget install JohnMacFarlane.Pandoc\n"
            "  macOS:   brew install pandoc\n"
            "  Linux:   sudo apt install pandoc   (or dnf/pacman)\n"
            "Then re-run, or fall back to generate-cti-docx.py (JSON-only, no pandoc needed)."
        )


def convert_md_to_docx(md_path: str) -> str:
    """Normalize prose dashes, then run pandoc to convert Markdown to a temporary DOCX."""
    from cti_text_normalize import normalize_dashes
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = normalize_dashes(f.read())
    md_norm = tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w",
                                          encoding="utf-8", newline="\n")
    md_norm.write(md_text)
    md_norm.close()
    tmp = tempfile.NamedTemporaryFile(suffix=".docx", delete=False)
    tmp.close()
    try:
        subprocess.run(
            ["pandoc", md_norm.name, "-o", tmp.name, "--from", "markdown", "--to", "docx", "--standalone"],
            check=True,
            capture_output=True,
        )
    finally:
        try:
            os.unlink(md_norm.name)
        except OSError:
            pass
    return tmp.name


def load_json(json_path: str) -> dict:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("case", {})
    case = data["case"]
    case.setdefault("id", "CTI-001")
    case.setdefault("label", "CTI Report")
    case.setdefault("classification", "OPEN SOURCE")
    case.setdefault("analyst", "AI-Assisted CTI")
    case.setdefault("date", datetime.date.today().isoformat())
    case.setdefault("subject", "N/A")
    case.setdefault("status", "active")
    return data


def build_minimal_json_from_md(md_path: str) -> dict:
    """When no JSON is provided, build minimal metadata from the MD filename."""
    basename = os.path.splitext(os.path.basename(md_path))[0]
    parts = basename.split("-")
    case_id = "-".join(parts[2:4]) if len(parts) >= 4 else basename
    date_str = parts[-1] if len(parts) >= 5 else datetime.date.today().isoformat()
    return {
        "case": {
            "id": case_id,
            "label": f"CTI Report — {case_id}",
            "classification": "OPEN SOURCE",
            "analyst": "AI-Assisted CTI",
            "date": date_str,
            "subject": case_id,
            "status": "active",
        }
    }


def resolve_output_path(md_path: str, json_data: dict) -> str:
    case = json_data.get("case", {})
    case_id = case.get("id", "CTI-001")
    date = case.get("date", datetime.date.today().isoformat())
    directory = os.path.dirname(md_path) or "."
    return os.path.join(directory, f"CTI-REPORT-{case_id}-{date}.docx")


def parse_args():
    """Parse CLI args into (md_path, json_path_or_none, output_path_or_none, want_pdf)."""
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    md_path = args[0]
    json_path = None
    output_path = None
    want_pdf = False

    for arg in args[1:]:
        if arg in ("--pdf", "-p"):
            want_pdf = True
        elif arg.endswith(".json"):
            json_path = arg
        elif arg.endswith(".docx"):
            output_path = arg

    return md_path, json_path, output_path, want_pdf


def main():
    md_path, json_path, output_path, want_pdf = parse_args()

    if not os.path.exists(md_path):
        print(f"Error: MD file not found: {md_path}")
        sys.exit(1)

    ensure_pandoc()

    json_data = load_json(json_path) if json_path and os.path.exists(json_path) else build_minimal_json_from_md(md_path)
    has_json = json_path is not None and os.path.exists(json_path)
    from cti_text_normalize import normalize_obj
    json_data = normalize_obj(json_data)

    if not output_path:
        output_path = resolve_output_path(md_path, json_data)

    print(f"[Phase 1] pandoc: {os.path.basename(md_path)} → temp.docx")
    pandoc_docx = convert_md_to_docx(md_path)

    try:
        doc = Document(pandoc_docx)

        print("[Phase 2] Applying CTI styles")
        apply_cti_styles(doc)

        print("[Phase 2] Prepending cover page + TOC, injecting charts")
        case_dir = os.path.dirname(os.path.abspath(json_path)) if json_path else os.path.dirname(os.path.abspath(output_path))
        rebuild_with_cover_toc_and_charts(doc, json_data, case_dir)

        case = json_data["case"]
        setup_header_footer_compat(doc, case["id"], case.get("classification", "OPEN SOURCE"))

        doc.save(output_path)
        print(f"Saved: {output_path}")

        subjects = json_data.get("subjects", [])
        findings = json_data.get("findings", [])
        connections = json_data.get("connections", [])
        timeline = json_data.get("timeline", [])
        mode = "MD + JSON (hybrid)" if has_json else "MD-only (styled)"
        print(f"  Mode: {mode}")
        if has_json:
            print(f"  Subjects: {len(subjects)}  Findings: {len(findings)}  "
                  f"Connections: {len(connections)}  Timeline: {len(timeline)}")

        if want_pdf:
            from cti_docx_pdf import convert_docx_to_pdf
            pdf_path = os.path.splitext(output_path)[0] + ".pdf"
            print("[Phase 3] LibreOffice: DOCX \u2192 PDF (document-style, same charts)")
            try:
                pdf_out = convert_docx_to_pdf(output_path, pdf_path)
                print(f"Saved: {pdf_out}")
            except Exception as e:
                print(f"  PDF conversion skipped: {e}")

    finally:
        try:
            os.unlink(pandoc_docx)
        except OSError:
            pass


if __name__ == "__main__":
    main()
