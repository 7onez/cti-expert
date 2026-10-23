#!/usr/bin/env python3
"""
evidence_capture.py — generate the UI evidence the release check looks for.

    python3 intel_engine/harness/dashboard/evidence_capture.py

Starts the real dashboard on a free loopback port, drives it with Playwright +
Chromium, asserts what the screenshots must show, and writes:

    orca-evidence/auth-methods.png        API key + OAuth 2.0 + PKCE, side by side
    orca-evidence/text-model-dropdown.png the model listbox, open
    orca-evidence/manifest.json           sha256, dimensions and the DOM assertions

The manifest keeps every release-check field under one `automation` object
(`framework`, `passed`, `catalog_source`, `catalog_model_count`, `image_model_count`)
and one `artifacts` entry per screenshot (`kind`, `path`, `sha256`, `ui`). The counts are
read back from the dashboard's own catalog endpoint and compared with the rendered list,
so the numbers in the manifest describe what the screenshot actually shows.

The evidence is GENERATED here and is not committed: the repo's `.gitignore` skips
`orca-evidence/`, so a checkout never carries a stale picture of a UI that has moved on.

A credential is needed to render the "stored … (masked)" state. If ORCAROUTER_API_KEY is
in the environment it is used as-is (a developer sees the live catalog); otherwise the
script writes a synthetic key into a temporary .env and the catalog falls back to the
verified seed, which the panel labels `degraded`. Either way no real key is written
into the evidence: the UI prints only the public `sk-orca-` prefix and a length.

Exit codes: 0 = assertions passed, 1 = an assertion failed, 2 = could not run
(playwright or a Chromium binary is missing).
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent          # .../intel_engine/harness/dashboard
ROOT = HERE.parents[2]                          # repo root
OUT = ROOT / "orca-evidence"
SERVER = HERE / "serve.py"

# The one catalog the dropdown must be built from: chat-capable models of the account's catalog.
CATALOG_URL = "https://api.orcarouter.ai/v1/models?capability=chat"

CHROMIUM_CANDIDATES = (
    os.environ.get("CHROME_PATH", ""),
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _png_size(path: Path) -> tuple[int, int]:
    head = path.read_bytes()[:24]
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"not a PNG: {path}")
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def _chromium(exe: str):
    from playwright.sync_api import sync_playwright
    kw = {"args": ["--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server",
                   "--proxy-bypass-list=*"],
          "env": {"HOME": tempfile.gettempdir()}}
    if exe:
        kw["executable_path"] = exe
    return sync_playwright, kw


def _server_json(port: int, path: str) -> dict:
    """Ask the dashboard itself what it served, with proxies disabled (loopback only)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}{path}", timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _start_server(port: int, env: dict) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(SERVER), "--port", str(port), "--no-browser"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit("dashboard exited: " + (proc.stderr.read() or "").strip()[:500])
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return proc
        except OSError:
            time.sleep(0.15)
    proc.terminate()
    raise SystemExit("dashboard did not accept a connection within 15 s")


def main() -> int:
    try:
        import playwright  # noqa: F401
    except ImportError:
        print("playwright is not installed (uv pip install playwright)", file=sys.stderr)
        return 2
    exe = next((c for c in CHROMIUM_CANDIDATES if c and os.path.exists(c)), "")

    OUT.mkdir(exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="orca-evidence-")
    env = dict(os.environ)
    env.pop("HARNESS_BACKEND", None)
    if not env.get("ORCAROUTER_API_KEY"):
        # Synthetic credential: enough to render the masked state, useless as a key.
        env_path = os.path.join(tmpdir, ".env")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("ORCAROUTER_API_KEY=sk-orca-evidence-synthetic-000000000000\n")
        os.chmod(env_path, 0o600)
        env["CTI_API_KEYS_ENV"] = env_path

    port = _free_port()
    server = _start_server(port, env)
    try:
        sync_playwright, launch_kw = _chromium(exe)
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_kw)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 900},
                                        device_scale_factor=1)
                page.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
                page.click('#tabs button[data-tab="provider"]')
                page.wait_for_selector('[data-testid="auth-methods"]', timeout=20000)
                page.wait_for_selector('[data-testid="model-select-trigger"]', timeout=20000)
                page.wait_for_timeout(1500)

                auth = page.evaluate("""() => {
                  const vis = (s) => { const e = document.querySelector(s); if (!e) return false;
                    const r = e.getBoundingClientRect(); const cs = getComputedStyle(e);
                    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden'
                           && cs.display !== 'none'; };
                  const key = document.querySelector('[data-testid="api-key-input"]');
                  const save = document.querySelector('[data-testid="api-key-save"]');
                  const pkce = document.querySelector('[data-testid="pkce-connect"]');
                  const card = document.querySelector('[data-testid="auth-methods"]');
                  const text = card ? card.innerText : '';
                  return {
                    api_key_visible: vis('[data-testid="api-key-input"]'),
                    secret_masked: /[•*]{2,}|…/.test(text) && !/[A-Za-z0-9_-]{40,}/.test(text),
                    controls_enabled: !!save && !save.disabled && !!pkce && !pkce.disabled
                                      && vis('[data-testid="pkce-connect"]'),
                    pkce_visible: vis('[data-testid="pkce-connect"]'),
                  };
                }""")

                page.screenshot(path=str(OUT / "auth-methods.png"))

                page.click('[data-testid="model-select-trigger"]')
                page.wait_for_selector('[data-testid="model-dropdown"]', state="visible", timeout=8000)
                page.wait_for_timeout(250)
                drop = page.evaluate("""() => {
                  const panel = document.querySelector('[data-testid="model-dropdown"]');
                  const trig = document.querySelector('[data-testid="model-select-trigger"]');
                  const items = panel.querySelectorAll('[data-testid="model-option"]');
                  const cs = getComputedStyle(panel);
                  const pr = panel.getBoundingClientRect(), tr = trig.getBoundingClientRect();
                  const bg = cs.backgroundColor || '';
                  const m = bg.match(/rgba?\\(([^)]+)\\)/);
                  const parts = m ? m[1].split(',').map(s => parseFloat(s)) : [];
                  const alpha = parts.length === 4 ? parts[3] : (parts.length === 3 ? 1 : 0);
                  return {
                    dropdown_open: pr.width > 0 && pr.height > 0 && cs.display !== 'none',
                    item_count: items.length,
                    opaque_background: alpha === 1 && bg !== 'transparent',
                    visible_border: parseFloat(cs.borderTopWidth) >= 1
                                    && cs.borderTopStyle === 'solid',
                    trigger_panel_right_delta: Math.round(Math.abs(pr.right - tr.right)),
                    ids: Array.from(items).slice(0, 5).map(i => i.innerText.trim().split('\\n')[0]),
                  };
                }""")
                page.screenshot(path=str(OUT / "text-model-dropdown.png"))
            finally:
                browser.close()
        # What the panel was built from, read back from the server (not scraped from the DOM).
        catalog = _server_json(port, "/api/provider/models?capability=chat")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()

    catalog_count = len(catalog.get("models") or [])
    passed = (all(auth[k] for k in ("api_key_visible", "secret_masked", "controls_enabled",
                                    "pkce_visible"))
              and all(drop[k] for k in ("dropdown_open", "opaque_background", "visible_border"))
              and drop["item_count"] > 0
              and drop["item_count"] == catalog_count
              and drop["trigger_panel_right_delta"] <= 2)

    artifacts = []
    for kind, name, ui in (("auth-methods", "auth-methods.png", auth),
                           ("text-model-dropdown", "text-model-dropdown.png", drop)):
        path = OUT / name
        w, h = _png_size(path)
        artifacts.append({"kind": kind, "path": name, "width": w, "height": h,
                          "bytes": path.stat().st_size, "sha256": _sha256(path),
                          "ui": ui})

    manifest = {
        "automation": {
            "framework": "playwright",
            "passed": passed,
            "catalog_source": CATALOG_URL,
            "catalog_model_count": catalog_count,
            # The harness's model path is text-only: there is no multimodal entry point to
            # drive, so no multimodal-model-dropdown exists for it to count.
            "image_model_count": 0,
        },
        "dashboard": "intel_engine/harness/dashboard/serve.py",
        "viewport": "1280x900",
        "catalog_mode": catalog.get("source") or "unknown",
        "catalog_degraded": bool(catalog.get("degraded")),
        "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": artifacts,
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"automation": manifest["automation"],
                      "catalog_mode": manifest["catalog_mode"],
                      "artifacts": [a["kind"] + ": " + a["path"] for a in artifacts]},
                     indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
