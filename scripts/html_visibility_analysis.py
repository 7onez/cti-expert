#!/usr/bin/env python3
# cti-expert skill — visibility-aware HTML analysis (hidden-content phishing evasion).
"""html_visibility_analysis.py — surface content a phishing page HIDES from a casual viewer:
hidden links, hidden forms, hidden credential inputs, and off-screen brand/lure text.

Grounded in: Lucas Betts, Eric Spero, Robert Biddle, Danielle Lottridge, Giovanni Russello
(University of Auckland) — "Visibility-Aware HTML Analysis through Renderer-Level Extraction",
APWG eCrime 2026. The paper's premise: analysing raw HTML without knowing what actually
renders misleads detection — phishing kits hide, cloak, and offscreen content to evade both
humans and naive parsers. A full solution needs a renderer; this script implements the
STATIC, keyless approximation that catches the common concealment idioms, and clearly flags
that renderer-level confirmation (the tool's Playwright/agent-browser path) is the upgrade.

What it flags (each with the concealment reason and a snippet):
  * inline hiding      — style="display:none | visibility:hidden | opacity:0 | font-size:0"
                         width/height:0, text-indent:-9999px, position:absolute;left:-9999px,
                         clip/clip-path hiding, the bare `hidden` attribute.
  * class-based hiding — <style> rules whose selector sets a hiding property, then any element
                         carrying that class (kits reuse .hidden/.d-none/.sr-only heavily).
  * hidden inputs      — <input type="hidden">, and inputs inside a hidden container.
  * concealed intent   — a hidden element that carries a LINK (href/action), a FORM, a
                         PASSWORD/credential input, or brand/lure keywords. This is the part
                         that matters: hidden boilerplate is noise; a hidden credential form
                         posting off-domain is evasion.

Severity: HIGH = hidden password/credential input OR hidden form whose action leaves the page
origin; MEDIUM = hidden external link or hidden brand/lure text; LOW = hidden content with no
malicious intent signal (reported for completeness).

Offline, deterministic, stdlib-only (html.parser — no bs4). Never fetches or renders.

Usage:
  uv run html_visibility_analysis.py page.html
  curl -s https://site/ | uv run html_visibility_analysis.py - --origin site.com
  uv run html_visibility_analysis.py page.html --json -o hidden.json
  uv run html_visibility_analysis.py page.html --brand paypal --brand microsoft

Exit codes: 0 = ran, 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import re
import sys
import json
import argparse
from html.parser import HTMLParser

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# CSS declarations that hide an element. Value tested case-insensitively, whitespace-loose.
_HIDE_RULES = [
    ("display:none", re.compile(r"display\s*:\s*none", re.I)),
    ("visibility:hidden", re.compile(r"visibility\s*:\s*hidden", re.I)),
    ("opacity:0", re.compile(r"opacity\s*:\s*0(\.0+)?\b", re.I)),
    ("font-size:0", re.compile(r"font-size\s*:\s*0(px|em|%)?\b", re.I)),
    ("zero-size", re.compile(r"(width|height)\s*:\s*0(px|em|%)?\b", re.I)),
    ("offscreen-indent", re.compile(r"text-indent\s*:\s*-\s*\d{3,}", re.I)),
    ("offscreen-position", re.compile(r"(left|top)\s*:\s*-\s*\d{3,}\s*px", re.I)),
    ("clip-hidden", re.compile(r"clip(-path)?\s*:\s*(rect\(\s*0|inset\(\s*(50%|100%))", re.I)),
]
_HIDE_CLASS_HINTS = ("hidden", "d-none", "hide", "sr-only", "visually-hidden",
                     "invisible", "screen-reader", "offscreen")
# 'token'/'csrf' deliberately excluded: hidden csrf/session-state inputs are ubiquitous and
# benign — matching them turns every legitimate form into a false HIGH.
_CRED_FIELD = re.compile(r"(pass(word|wd)?|otp|mfa|cvv|card(number)?|ssn|pin|seed|"
                         r"mnemonic|secret|passcode)", re.I)
_LURE = re.compile(r"(verify|login|sign\s?in|account|update|confirm|secure|unlock|suspend|"
                   r"password|bank|wallet|urgent)", re.I)


def _style_hides(style):
    hits = [name for name, rx in _HIDE_RULES if style and rx.search(style)]
    return hits


def _extract_hiding_classes(html):
    """Parse <style> blocks; return class names whose rule sets a hiding property."""
    classes = set()
    for block in re.findall(r"<style[^>]*>(.*?)</style>", html, re.I | re.S):
        # naive rule split on '}' — good enough to associate a selector with its body
        for rule in block.split("}"):
            if "{" not in rule:
                continue
            sel, _, body = rule.partition("{")
            if any(rx.search(body) for _, rx in _HIDE_RULES):
                for cls in re.findall(r"\.([A-Za-z0-9_-]+)", sel):
                    classes.add(cls.lower())
    return classes


class _Vis(HTMLParser):
    """Walk the DOM, tracking a hidden-ancestor stack so nested content inherits concealment."""

    def __init__(self, hiding_classes, origin, brands):
        super().__init__(convert_charrefs=True)
        self.hiding_classes = hiding_classes
        self.origin = (origin or "").lower().lstrip(".")
        self.brands = [b.lower() for b in (brands or []) if b]
        self.stack = []          # list of (tag, hide_reason_or_None, depth)
        self.findings = []
        self._depth = 0
        self._text_owner = None  # innermost hidden container capturing text

    # -- helpers ------------------------------------------------------------
    def _hidden_now(self):
        for _, reason, _d in reversed(self.stack):
            if reason:
                return reason
        return None

    def _reason_for(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if "hidden" in a and tag not in ("input",):  # bare hidden attribute
            return "hidden-attr"
        hits = _style_hides(a.get("style", ""))
        if hits:
            return "style:" + "+".join(hits)
        cls = a.get("class", "").lower().split()
        for c in cls:
            if c in self.hiding_classes or any(h in c for h in _HIDE_CLASS_HINTS):
                return f"class:{c}"
        return None

    def _record(self, kind, detail, reason, severity):
        self.findings.append({
            "kind": kind, "detail": detail, "concealment": reason, "severity": severity,
        })

    def _is_external(self, url):
        if not url:
            return False
        m = re.match(r"https?://([^/]+)/?", url, re.I)
        if not m:
            return False  # relative link -> same origin
        host = m.group(1).lower()
        if not self.origin:
            return True   # no origin given: any absolute URL counts as "off-page"
        return not (host == self.origin or host.endswith("." + self.origin))

    # -- parser callbacks ---------------------------------------------------
    def handle_starttag(self, tag, attrs):
        self._depth += 1
        a = {k.lower(): (v or "") for k, v in attrs}
        reason = self._reason_for(tag, attrs)
        # a container just went hidden
        self.stack.append((tag, reason, self._depth))
        hidden = self._hidden_now()

        # input handling. A bare type=hidden input is normal HTML (csrf/session/form-state),
        # so it is reported ONLY when its name is credential-like (harvest-staging tell).
        if tag == "input":
            itype = a.get("type", "text").lower()
            name = a.get("name", "") or a.get("id", "")
            if itype == "hidden":
                if _CRED_FIELD.search(name):
                    self._record("hidden_input", f"name={name!r} type=hidden",
                                 "type=hidden (credential-named)", "medium")
            elif hidden:
                sev = "high" if (_CRED_FIELD.search(name) or itype == "password") else "medium"
                self._record("hidden_field", f"name={name!r} type={itype}", hidden, sev)

        if hidden and tag == "a":
            href = a.get("href", "")
            if href and href not in ("#", "javascript:void(0)"):
                sev = "medium" if self._is_external(href) else "low"
                self._record("hidden_link", href, hidden, sev)

        if hidden and tag == "form":
            action = a.get("action", "")
            sev = "high" if self._is_external(action) else "medium"
            self._record("hidden_form", f"action={action or '(self)'}", hidden, sev)

    def handle_startendtag(self, tag, attrs):
        # self-closing (e.g. <input .../>) — run start logic, no stack push kept
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        # pop matching frame (tolerant of unbalanced markup)
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        self._depth = max(0, self._depth - 1)

    def handle_data(self, data):
        hidden = self._hidden_now()
        if not hidden:
            return
        txt = data.strip()
        if len(txt) < 4:
            return
        low = txt.lower()
        brand_hit = next((b for b in self.brands if b in low), None)
        if brand_hit:
            self._record("hidden_brand_text", f"'{txt[:80]}' (brand: {brand_hit})",
                         hidden, "medium")
        elif _LURE.search(low):
            self._record("hidden_lure_text", f"'{txt[:80]}'", hidden, "medium")
        else:
            self._record("hidden_text", f"'{txt[:80]}'", hidden, "low")


_SEV_ORDER = {"low": 1, "medium": 2, "high": 3}


def analyze(html, origin=None, brands=None, computed_hidden=None):
    """Pure, deterministic. Returns {verdict, counts, findings[], rationale}.

    computed_hidden: optional list of finding dicts a RENDERER produced from getComputedStyle
    (each {kind, detail, concealment, severity}), merged with the static findings so
    JS-injected/computed concealment the static pass can't see is included."""
    html = html or ""
    hiding_classes = _extract_hiding_classes(html)
    p = _Vis(hiding_classes, origin, brands)
    try:
        p.feed(html)
        p.close()
    except Exception:  # malformed markup must degrade, never crash the collector
        pass

    findings = list(p.findings)
    coerced = 0
    for cf in (computed_hidden or []):
        if not isinstance(cf, dict):
            continue
        sev = cf.get("severity")
        if sev not in _SEV_ORDER:      # clamp unknown severities rather than dropping evidence
            sev = "medium"
            coerced += 1
        findings.append({
            "kind": cf.get("kind", "hidden_computed"),
            "detail": cf.get("detail", ""),
            "concealment": "computed-style (rendered): " + cf.get("concealment", ""),
            "severity": sev,
        })
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if counts["high"]:
        verdict = "high"
    elif counts["medium"]:
        verdict = "medium"
    elif counts["low"]:
        verdict = "low"
    else:
        verdict = "none"

    hp = [f for f in findings if f["kind"] in ("hidden_input", "hidden_field") and f["severity"] == "high"]
    hf = [f for f in findings if f["kind"] == "hidden_form" and f["severity"] == "high"]
    bits = []
    if hp:
        bits.append(f"{len(hp)} hidden credential input(s)")
    if hf:
        bits.append(f"{len(hf)} hidden form(s) posting off-origin")
    if counts["medium"]:
        bits.append(f"{counts['medium']} concealed link/text signal(s)")
    rationale = ("Page conceals: " + "; ".join(bits) + "."
                 if bits else ("Hidden content present but no malicious-intent signal."
                               if findings else "No concealed content detected."))

    return {
        "verdict": verdict,
        "counts": counts,
        "hiding_classes": sorted(hiding_classes),
        "findings": sorted(findings, key=lambda f: -_SEV_ORDER[f["severity"]]),
        "rationale": rationale,
        "note": "Static approximation — renderer-level extraction (Playwright/agent-browser) "
                "confirms true visibility; JS-injected/computed styles are not evaluated here.",
    }


def _fmt_text(r):
    out = [f"Verdict: {r['verdict'].upper()}  "
           f"(high {r['counts']['high']}, medium {r['counts']['medium']}, low {r['counts']['low']})",
           "", r["rationale"]]
    if r["findings"]:
        out.append("")
        out.append("Concealed content:")
        for f in r["findings"]:
            out.append(f"  [{f['severity'].upper():<6}] {f['kind']:<18} via {f['concealment']}: {f['detail']}")
    out.append("")
    out.append("NOTE: " + r["note"])
    return "\n".join(out)


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Visibility-aware HTML analysis — surface hidden links/forms/inputs/text "
                    "used for phishing evasion (offline, static approximation).")
    ap.add_argument("input", nargs="?", default="-", help="HTML file, or '-' for stdin")
    ap.add_argument("--origin", help="page origin host (e.g. site.com) to judge off-origin form/link")
    ap.add_argument("--brand", action="append", help="brand term to flag in hidden text (repeatable)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("-o", "--out", help="write output to a file")
    args = ap.parse_args(argv)

    try:
        html = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    r = analyze(html, origin=args.origin, brands=args.brand)
    body = json.dumps(r, indent=2, ensure_ascii=False) if args.json else _fmt_text(r)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
