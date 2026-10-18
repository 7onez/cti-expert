#!/usr/bin/env python3
# cti-expert skill — renderer-level confirmation for ClickFix + visibility analyzers.
"""render_confirm.py — upgrade the STATIC ClickFix / visibility verdicts with RENDERER-level
evidence (runtime clipboard writes, computed-style hidden elements), closing the evasion gap
those static analyzers explicitly flag.

Grounded in: *"PasteJacked"* (Nabeel/Melicher/Starov, Palo Alto) and *"Visibility-Aware HTML
Analysis through Renderer-Level Extraction"* (Betts et al., Auckland), APWG eCrime 2026 — the
Auckland paper's thesis is that raw-HTML analysis misleads and a renderer is required to know
what actually renders / runs.

Design:
  * The RECONCILE logic is a pure function (reconcile / confirm_from_evidence) — offline and
    deterministic, tested in CI with synthetic captured evidence. It feeds a renderer's
    captured clipboard strings into clickfix_detect.detect(..., captured_clipboard=...) and its
    computed-style hidden elements into html_visibility_analysis.analyze(..., computed_hidden=...).
    The render NEVER lowers a static verdict: reconciliation takes the max, and non-corroboration
    of a static signal is surfaced as `static_only_higher` for the analyst to weigh — it is not
    applied as a downgrade.
  * The RENDER step (drive Moli or Chromium, hook the clipboard API before any page script runs,
    dump computed-style hidden elements) is OPTIONAL and lives behind availability checks. It is
    an OUTBOUND, attributable, JS-executing fetch of the target, so it requires `--render` and
    warns (and accepts `--proxy` for a research egress). Engine choice is the engine's own
    wp_browser rule (Moli when installed and the proxy scheme is verified, else Chromium). Absent a
    renderer it returns evidence=None with a note — the static verdict stays authoritative.

Usage (pure reconcile over supplied evidence — the offline path):
  echo '{"clipboard":["powershell -enc AAAA"],"computed_hidden":[]}' \
    | uv run render_confirm.py page.html --evidence -
  uv run render_confirm.py page.html --evidence ev.json --origin site.com --json

Usage (attempt a live render — optional, needs a renderer; outbound + attributable):
  uv run render_confirm.py --url https://suspicious.example/ --render --proxy socks5://127.0.0.1:9050

Exit codes: 0 = ran, 3 = renderer requested but unavailable (reported), 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import os
import re
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clickfix_detect as cf            # noqa: E402
import html_visibility_analysis as hv   # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _reconcile_verdict(static_v, rendered_v):
    """Rendered evidence is authoritative when present: take the max, and record the direction.
    Fails CLOSED on an out-of-vocabulary verdict — the static verdict is retained, never a silent
    downgrade to the rendered value."""
    if static_v not in _ORDER or rendered_v not in _ORDER:
        return static_v, "unknown_verdict_vocabulary_static_retained"
    sv, rv = _ORDER[static_v], _ORDER[rendered_v]
    final = rendered_v if rv >= sv else static_v
    if rv > sv:
        direction = "promoted_by_render"
    elif rv < sv:
        direction = "static_only_higher"   # render did not corroborate the static signal
    else:
        direction = "agree"
    return final, direction


def confirm_from_evidence(html, evidence, origin=None, brands=None):
    """Pure, deterministic. Combine static analysis with renderer-captured evidence.

    evidence: {"clipboard": [str, ...], "computed_hidden": [finding-dict, ...]} (either optional).
    A non-dict evidence is treated as no evidence (never raises)."""
    evidence = evidence if isinstance(evidence, dict) else {}
    clip = [c for c in (evidence.get("clipboard") or []) if c]
    comp = [c for c in (evidence.get("computed_hidden") or []) if isinstance(c, dict)]

    cf_static = cf.detect(html)
    cf_rendered = cf.detect(html, captured_clipboard=clip) if clip else cf_static
    cf_final, cf_dir = _reconcile_verdict(cf_static["verdict"], cf_rendered["verdict"])

    hv_static = hv.analyze(html, origin=origin, brands=brands)
    hv_rendered = hv.analyze(html, origin=origin, brands=brands, computed_hidden=comp) if comp else hv_static
    hv_final, hv_dir = _reconcile_verdict(hv_static["verdict"], hv_rendered["verdict"])

    return {
        "rendered_evidence_present": bool(clip or comp),
        "clickfix": {
            "static_verdict": cf_static["verdict"],
            "rendered_verdict": cf_rendered["verdict"],
            "final_verdict": cf_final,
            "reconciliation": cf_dir,
            "iocs": cf_rendered["iocs"],
            "decoded_commands": cf_rendered.get("decoded_commands", []),
        },
        "visibility": {
            "static_verdict": hv_static["verdict"],
            "rendered_verdict": hv_rendered["verdict"],
            "final_verdict": hv_final,
            "reconciliation": hv_dir,
            "counts": hv_rendered["counts"],
        },
        "note": ("Reconciled static analysis with renderer-captured evidence; the render never "
                 "lowers a static verdict."
                 if (clip or comp) else
                 "No renderer evidence supplied — static verdicts are authoritative."),
    }


# ------------------------------------------------- optional live render (degrades to a note)
# One instrumentation pair for both engines: the hook runs before any page script (Playwright
# add_init_script / Moli --document-start-script) and the probe is evaluated after readiness.
# A copy of a selected <textarea>/<input> (the classic ClickFix staging) is read from the field's
# own selection range when getSelection() is empty — Moli does not mirror field selections there.
_CLIPBOARD_HOOK = (
    "window.__clip=[];"
    "const _w=navigator.clipboard&&navigator.clipboard.writeText;"
    "if(_w){navigator.clipboard.writeText=function(t){window.__clip.push(String(t));"
    "return _w.call(navigator.clipboard,t);};}"
    "document.execCommand=(function(o){return function(c){"
    "if(String(c).toLowerCase()==='copy'){try{"
    "var s=(document.getSelection&&document.getSelection().toString())||'';"
    "if(!s){var f=[document.activeElement].concat(Array.from(document.querySelectorAll('textarea,input')));"
    "for(var i=0;i<f.length&&!s;i++){var a=f[i];"
    "if(a&&typeof a.value==='string'&&a.selectionEnd>a.selectionStart){"
    "s=a.value.substring(a.selectionStart,a.selectionEnd);}}}"
    "window.__clip.push(String(s));}catch(e){}}"
    "return o.apply(document,arguments);};})(document.execCommand);"
)
_HIDDEN_PROBE = (
    "Array.from(document.querySelectorAll('*')).filter(function(e){"
    "var s=getComputedStyle(e);return (s.display==='none'||s.visibility==='hidden'||"
    "parseFloat(s.opacity)===0) && (e.querySelector('input[type=password]')||"
    "e.tagName==='FORM'||e.tagName==='A');}).slice(0,50).map(function(e){return {"
    "kind:(e.tagName==='FORM'?'hidden_form':e.tagName==='A'?'hidden_link':'hidden_field'),"
    "detail:(e.getAttribute('action')||e.getAttribute('href')||e.tagName),"
    "concealment:getComputedStyle(e).display==='none'?'display:none':'hidden',"
    "severity:(e.querySelector('input[type=password]')?'high':'medium')};})"
)


def _wp_browser():
    """The engine's browser router (intel_engine/WebPivot/tools/wp_browser.py), or None when this
    script runs without the vendored engine (stateless Tier 3)."""
    here = os.path.dirname(os.path.abspath(__file__))
    for root in (os.environ.get("INTEL_HOME"), os.path.join(here, "..", "intel_engine")):
        tools = os.path.join(root, "WebPivot", "tools") if root else ""
        if tools and os.path.isfile(os.path.join(tools, "wp_browser.py")):
            if tools not in sys.path:
                sys.path.insert(0, tools)
            try:
                import wp_browser
                return wp_browser
            except Exception:  # noqa: BLE001
                return None
    return None


def _render_available(proxy=None):
    """(engine, why): 'moli' | 'playwright' | 'agent-browser' | None. Never raises."""
    wb = _wp_browser()
    if wb is not None:
        engine, why = wb.select_dom_engine(proxy)
        if engine:
            return ("playwright" if engine == "chromium" else engine), why
        # The router already decided (no Chromium for a pixel/CF render, unverified proxy, …).
        # agent-browser has no driver here, so reporting it would hide the real reason.
        return None, why
    try:
        import playwright  # noqa: F401
        return "playwright", "Playwright importable"
    except Exception:  # noqa: BLE001
        why = "no engine router"
    from shutil import which
    if which("agent-browser"):
        return "agent-browser", why
    return None, why


def run_render(url, proxy=None):
    """Attempt a live render capturing clipboard writes + computed-hidden elements.
    Returns (evidence_dict|None, note). OPTIONAL: absent a renderer, returns (None, note) — the
    caller keeps the static verdict. This is deliberately the only non-pure function here."""
    engine, why = _render_available(proxy)
    if not engine:
        return None, (f"no renderer available ({why}) — static verdict stands; install Moli "
                      "(scripts/install.sh) or Chromium (--headless) to enable renderer confirmation")
    drivers = {"moli": _render_moli, "playwright": _render_playwright}
    if engine in drivers:
        try:
            return drivers[engine](url, proxy)
        except Exception as e:  # noqa: BLE001
            return None, f"render failed ({e}); static verdict stands"
    return None, (f"renderer '{engine}' detected but no driver wired here — "
                  "run it out-of-band and feed --evidence, or install Moli/Chromium")


def _note(engine, proxy, clip, comp):
    return (f"rendered with {engine}" + (" via proxy" if proxy else "")
            + f": {len(clip)} clipboard write(s), {len(comp)} computed-hidden element(s)")


def _render_moli(url, proxy=None):
    """Moli driver: the clipboard hook as a document-start script, one eval for both probes."""
    wb = _wp_browser()
    import wp_moli
    got = wp_moli.eval_page(
        url, "(function(){return {clipboard:(window.__clip||[]).filter(Boolean),"
             "computed_hidden:" + _HIDDEN_PROBE + "};})()",
        timeout=20, proxy=wb.resolve_proxy(proxy), start_script=_CLIPBOARD_HOOK)
    got = got if isinstance(got, dict) else {}
    clip = [c for c in (got.get("clipboard") or []) if c]
    comp = [c for c in (got.get("computed_hidden") or []) if isinstance(c, dict)]
    return {"clipboard": clip, "computed_hidden": comp}, _note(wp_moli.renderer_tag(), proxy, clip, comp)


def _render_playwright(url, proxy=None):
    """Chromium driver: hook clipboard API, collect computed-hidden elements. Best-effort."""
    from playwright.sync_api import sync_playwright  # type: ignore
    wb = _wp_browser()
    launch = (wb.chromium_launch_kwargs(proxy) if wb
              else {"headless": True, **({"proxy": {"server": proxy}} if proxy else {})})
    clip, comp = [], []
    with sync_playwright() as pw:
        b = pw.chromium.launch(**launch)
        try:
            pg = b.new_page()
            pg.add_init_script(_CLIPBOARD_HOOK)
            pg.goto(url, wait_until="networkidle", timeout=20000)
            clip = [c for c in (pg.evaluate("window.__clip||[]") or []) if c]
            comp = pg.evaluate(_HIDDEN_PROBE) or []
        finally:
            b.close()
    return {"clipboard": clip, "computed_hidden": comp}, _note("Chromium", proxy, clip, comp)


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _merge_evidence(a, b):
    a = a if isinstance(a, dict) else {}
    b = b if isinstance(b, dict) else {}
    return {k: list(a.get(k) or []) + list(b.get(k) or []) for k in ("clipboard", "computed_hidden")}


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Renderer-level confirmation for ClickFix + visibility (offline reconcile; "
                    "optional live render).")
    ap.add_argument("input", nargs="?", help="HTML file (or '-') to analyze statically")
    ap.add_argument("--url", help="URL to render (with --render)")
    ap.add_argument("--render", action="store_true", help="attempt a live render (OUTBOUND, attributable)")
    ap.add_argument("--proxy", help="proxy for the render egress, e.g. socks5://127.0.0.1:9050")
    ap.add_argument("--evidence", help="JSON evidence {clipboard[],computed_hidden[]} ('-' for stdin)")
    ap.add_argument("--origin", help="page origin host for off-origin judgement")
    ap.add_argument("--brand", action="append")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--out")
    args = ap.parse_args(argv)

    note_render = None
    evidence = {}
    html = ""

    if args.render:
        if not args.url:
            print("error: --render needs --url", file=sys.stderr)
            return 4
        if not args.proxy:
            host = re.sub(r"^[a-z]+://", "", args.url, flags=re.I).split("/")[0]
            print(f"warning: --render performs an OUTBOUND, attributable request to {host} from "
                  f"this machine and executes its JavaScript; use --proxy for a research egress",
                  file=sys.stderr)
        ev, note_render = run_render(args.url, args.proxy)
        if ev is None:
            print(f"note: {note_render}", file=sys.stderr)
            if not args.input and not args.evidence:
                return 3
        else:
            evidence = ev
    if args.evidence:
        try:
            supplied = json.loads(_read(args.evidence))
        except (OSError, ValueError) as e:
            print(f"error: --evidence: {e}", file=sys.stderr)
            return 4
        if not isinstance(supplied, dict):
            print("error: --evidence must be a JSON object {clipboard[],computed_hidden[]}", file=sys.stderr)
            return 4
        evidence = _merge_evidence(evidence, supplied)   # merge with any render capture
    if args.input:
        try:
            html = _read(args.input)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 4
    elif not (args.evidence or args.render):
        print("error: provide an HTML file, or --evidence, or --render --url", file=sys.stderr)
        return 4

    r = confirm_from_evidence(html, evidence, origin=args.origin, brands=args.brand)
    if note_render:
        r["render_note"] = note_render
    if args.json:
        body = json.dumps(r, indent=2, ensure_ascii=False)
    else:
        c, v = r["clickfix"], r["visibility"]
        body = (f"ClickFix   : static={c['static_verdict']} rendered={c['rendered_verdict']} "
                f"-> {c['final_verdict']} ({c['reconciliation']})\n"
                f"Visibility : static={v['static_verdict']} rendered={v['rendered_verdict']} "
                f"-> {v['final_verdict']} ({v['reconciliation']})\n"
                + (f"Render     : {note_render}\n" if note_render else "")
                + "\nNOTE: " + r["note"])
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
