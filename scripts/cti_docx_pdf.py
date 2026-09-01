"""
DOCX -> PDF via LibreOffice (soffice) headless.

This is the PDF path for CTI reports: the PDF is a faithful render of the generated
DOCX (same cover, TOC, styles, tables, and every injected chart/heatmap), NOT an
HTML-to-PDF browser print. One document format, two file types.

The cover / TOC / charts are injected into the DOCX *after* pandoc via python-docx, so
a pandoc->LaTeX PDF could never match — rendering the finished DOCX is the only faithful
route. `ensure_soffice()` mirrors `ensure_pandoc()` in generate-cti-docx-hybrid.py:
probe common locations -> quiet OS-appropriate install -> re-probe -> actionable error.
`convert_docx_to_pdf` then runs soffice against an isolated user profile (so it never
collides with a desktop LibreOffice session) and returns the resulting PDF path.
"""
import os
import sys
import shutil
import subprocess
import tempfile

# Common install locations when soffice is not on PATH (macOS app bundle, Windows).
_PROBE_PATHS = (
    "/Applications/LibreOffice.app/Contents/MacOS/soffice",
    r"C:\Program Files\LibreOffice\program\soffice.exe",
    r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
)


def _find_soffice() -> str | None:
    for name in ("soffice", "libreoffice"):
        p = shutil.which(name)
        if p:
            return p
    for cand in _PROBE_PATHS:
        if os.path.isfile(cand):
            d = os.path.dirname(cand)
            os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
            return cand
    return None


def ensure_soffice() -> str:
    """Locate LibreOffice (soffice) on any OS; install it via the platform package
    manager if missing, then re-probe. Raises RuntimeError with an actionable message
    only when both discovery and automatic install fail."""
    found = _find_soffice()
    if found:
        return found

    # Quiet, OS-appropriate install (apt uses --no-install-recommends: Writer + core
    # only, ~10x smaller than the full suite).
    install_cmd = None
    if sys.platform == "darwin" and shutil.which("brew"):
        install_cmd = ["brew", "install", "--cask", "libreoffice"]
    elif sys.platform.startswith("linux"):
        if shutil.which("apt-get"):
            install_cmd = ["sudo", "apt-get", "install", "-y",
                           "--no-install-recommends", "libreoffice-writer"]
        elif shutil.which("dnf"):
            install_cmd = ["sudo", "dnf", "install", "-y", "libreoffice-writer"]
        elif shutil.which("pacman"):
            install_cmd = ["sudo", "pacman", "-S", "--noconfirm", "libreoffice-still"]
    elif os.name == "nt" and shutil.which("winget"):
        install_cmd = ["winget", "install", "--id", "TheDocumentFoundation.LibreOffice",
                       "--exact", "--accept-package-agreements", "--accept-source-agreements"]

    if install_cmd:
        try:
            subprocess.run(install_cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        except OSError:
            pass

    found = _find_soffice()
    if found:
        return found

    raise RuntimeError(
        "LibreOffice (soffice) not found and automatic install was unavailable — "
        "it renders the DOCX-style PDF. Install it manually, then re-run with --pdf:\n"
        "  Windows: winget install TheDocumentFoundation.LibreOffice\n"
        "  macOS:   brew install --cask libreoffice\n"
        "  Linux:   sudo apt install --no-install-recommends libreoffice-writer   (or dnf/pacman)\n"
        "The DOCX itself was still written; only the PDF render was skipped."
    )


def convert_docx_to_pdf(docx_path: str, out_pdf: str | None = None,
                        timeout: int = 180) -> str:
    """Convert `docx_path` to PDF; return the PDF path. `out_pdf` defaults to the
    DOCX path with a .pdf extension.

    The DOCX already carries a real, clickable TOC baked into the field cache
    (see cti_docx_toc), so a plain headless `--convert-to` renders it faithfully —
    headless LibreOffice never updates fields, and the minimal libreoffice-writer
    install ships no pyuno/macro bridge, so there is nothing to update here."""
    docx_path = os.path.abspath(docx_path)
    if not os.path.isfile(docx_path):
        raise RuntimeError(f"DOCX not found: {docx_path}")
    soffice = ensure_soffice()

    out_dir = os.path.dirname(docx_path)
    with tempfile.TemporaryDirectory(prefix="lo_profile_") as profile:
        cmd = [
            soffice, "--headless", "--nologo", "--nofirststartwizard",
            f"-env:UserInstallation=file://{profile}",
            "--convert-to", "pdf:writer_pdf_Export",
            "--outdir", out_dir, docx_path,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    produced = os.path.join(out_dir, os.path.splitext(os.path.basename(docx_path))[0] + ".pdf")
    if not os.path.isfile(produced):
        raise RuntimeError(
            "soffice did not produce a PDF.\n"
            f"  cmd: {' '.join(cmd)}\n  stdout: {proc.stdout}\n  stderr: {proc.stderr}")

    if out_pdf:
        out_pdf = os.path.abspath(out_pdf)
        if out_pdf != produced:
            shutil.move(produced, out_pdf)
        return out_pdf
    return produced
