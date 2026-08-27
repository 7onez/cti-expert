#!/usr/bin/env python3
# cti-expert skill — ClickFix / PasteJacking (clipboard-hijack) detector.
"""clickfix_detect.py — detect clipboard-hijacking ("ClickFix" / "PasteJacking") lures in
page HTML/JS, and extract the command the page tries to plant on the victim's clipboard.

Grounded in: Mohamed Nabeel, William Melicher, Oleksii Starov (Palo Alto Networks) —
"PasteJacked: Detection and Characterization of Clipboard-Hijacking Attacks", APWG eCrime
2026. The attack (a.k.a. ClickFix) has become a dominant 2024-2025 initial-access vector:
a page silently writes an OS command to the clipboard, then a fake "verify you are human" /
"fix this error" lure instructs the victim to open the Run dialog or a terminal and paste it,
executing malware with the victim's own hands — sidestepping download/attachment defences.

This runs on collected page content (DOM, inline/linked scripts) — offline, keyless,
deterministic. It never fetches or executes anything. Three independent signal families are
scored; the verdict rises as they co-occur, because any one alone is weak:

  1. CLIPBOARD WRITE  — navigator.clipboard.writeText, document.execCommand('copy'),
                        ClipboardItem, an 'copy'/oncopy handler that mutates clipboardData.
  2. SOCIAL LURE      — fake CAPTCHA / Cloudflare/Chrome "verification", and the tell-tale
                        keystroke choreography: Win+R, Ctrl+V + Enter, "open PowerShell",
                        "paste in Terminal", numbered "steps to verify".
  3. PAYLOAD SIGNATURE— an OS command in the page: powershell/pwsh, mshta, cmd /c, curl|iex,
                        iwr/Invoke-WebRequest, Invoke-Expression, -enc/-EncodedCommand,
                        certutil -urlcache, bitsadmin, msiexec /i http, wscript/cscript, .hta.

Verdict: HIGH = clipboard-write AND payload signature (the mechanism is present, wired to a
command); MEDIUM = any two families, or a payload signature with a strong lure; LOW = one
family only. Extracted payloads + any embedded URLs are returned as IOCs.

MITRE ATT&CK: T1204.004 (User Execution: Malicious Copy and Paste), T1059 (Command and
Scripting Interpreter), T1071 (payload delivery URL).

Usage:
  uv run clickfix_detect.py page.html
  curl -s https://site/ | uv run clickfix_detect.py -            # feed collected DOM
  uv run clickfix_detect.py page.html --json -o finding.json
  uv run clickfix_detect.py page.html --min low                  # report threshold

Exit codes: 0 = ran (see 'verdict'), 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import re
import sys
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# ------------------------------------------------------------------ signal patterns
# (label, compiled regex, weight). Weights are additive within a family; the family is
# considered "present" if it scores > 0. Kept readable and analyst-tunable.
CLIPBOARD = [
    ("navigator.clipboard.writeText", re.compile(r"navigator\s*\.\s*clipboard\s*\.\s*writeText", re.I), 25),
    ("document.execCommand('copy')", re.compile(r"execCommand\s*\(\s*['\"]copy['\"]", re.I), 20),
    ("ClipboardItem", re.compile(r"\bnew\s+ClipboardItem\b", re.I), 12),
    ("clipboardData.setData", re.compile(r"clipboardData\s*\.\s*setData", re.I), 15),
    ("copy-event handler", re.compile(r"addEventListener\s*\(\s*['\"]copy['\"]", re.I), 10),
]

# Lure text. Case-insensitive; matched against visible-ish text and attributes.
LURE = [
    ("fake human/robot verification", re.compile(r"(verify (you('?| a)re )?(a )?human|i'?m not a robot|prove you('?| a)re human)", re.I), 14),
    ("fake CAPTCHA/Cloudflare/Chrome check", re.compile(r"(cloudflare|recaptcha|captcha|ray id|verification (step|required)|chrome (needs|update))", re.I), 8),
    ("Win+R run-dialog choreography", re.compile(r"(win(dows)?\s*\+\s*r|windows key\s*\+\s*r|press\s+(the\s+)?(⊞|win|windows)\b)", re.I), 22),
    ("paste-and-run instruction", re.compile(r"(ctrl\s*\+\s*v|cmd\s*\+\s*v|paste (it|the code|and)|then press (enter|return))", re.I), 16),
    ("open-terminal instruction", re.compile(r"(open (the )?(powershell|terminal|command prompt|run dialog|run box)|iTerminalq)", re.I), 18),
    ("numbered verification steps", re.compile(r"(step\s*1[).:\s].{0,40}step\s*2|1\).{0,30}2\).{0,30}3\))", re.I | re.S), 8),
]

# Payload command signatures. A hit strongly implies weaponization.
PAYLOAD = [
    ("powershell", re.compile(r"\b(powershell(\.exe)?|pwsh)\b", re.I), 22),
    ("mshta", re.compile(r"\bmshta(\.exe)?\b", re.I), 22),
    ("cmd /c", re.compile(r"\bcmd(\.exe)?\s*/[ckr]\b", re.I), 16),
    ("Invoke-Expression / iex", re.compile(r"\b(Invoke-Expression|iex)\b", re.I), 20),
    ("iwr / Invoke-WebRequest", re.compile(r"\b(iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b", re.I), 16),
    ("curl|wget pipe", re.compile(r"\b(curl|wget)\b[^\n|]{0,120}\|", re.I), 16),
    ("encoded command", re.compile(r"-e(nc(odedcommand)?)?\b\s+[A-Za-z0-9+/=]{16,}", re.I), 20),
    ("certutil -urlcache", re.compile(r"certutil(\.exe)?\b.{0,40}(-urlcache|-decode)", re.I), 18),
    ("bitsadmin", re.compile(r"\bbitsadmin(\.exe)?\b", re.I), 16),
    ("msiexec remote", re.compile(r"\bmsiexec(\.exe)?\b.{0,40}https?://", re.I), 18),
    ("wscript/cscript", re.compile(r"\b(wscript|cscript)(\.exe)?\b", re.I), 14),
    (".hta reference", re.compile(r"\.hta\b", re.I), 10),
    ("hidden window flag", re.compile(r"-w(indowstyle)?\s+hidden\b", re.I), 10),
]

URL_RE = re.compile(r"https?://[^\s'\"<>()\\]+", re.I)
# A candidate command line to extract for the analyst / IOC bundle.
CMD_LINE_RE = re.compile(
    r"((?:powershell|pwsh|mshta|cmd|certutil|bitsadmin|msiexec|wscript|cscript|curl|wget|iex|iwr|irm)"
    r"(?:\.exe)?[^\n\r'\"`]{0,400})", re.I)


def _families(text):
    """Score every family; return (matches_by_family, evidence[])."""
    found = {"clipboard": [], "lure": [], "payload": []}
    for fam, table in (("clipboard", CLIPBOARD), ("lure", LURE), ("payload", PAYLOAD)):
        for label, rx, w in table:
            m = rx.search(text)
            if m:
                snippet = text[max(0, m.start() - 20): m.end() + 40].replace("\n", " ").strip()
                found[fam].append({"label": label, "weight": w, "evidence": snippet[:160]})
    return found

# PowerShell -EncodedCommand carries the real command as UTF-16LE base64, hiding the URL and
# intent from a plain-text scan. Decoding it is where the actionable IOC actually lives.
_ENC_RE = re.compile(r"-e(?:nc(?:odedcommand)?)?\b\s+([A-Za-z0-9+/=]{16,})", re.I)


def _decode_encoded(text):
    """Decode any -enc base64 blob(s). Returns a list of decoded command strings.
    Tries UTF-16LE (PowerShell's actual encoding) first, then UTF-8/latin-1."""
    import base64
    out, seen = [], set()
    for m in _ENC_RE.finditer(text):
        blob = m.group(1)
        pad = "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob + pad, validate=False)
        except Exception:
            continue
        for enc in ("utf-16-le", "utf-8", "latin-1"):
            try:
                dec = raw.decode(enc).replace("\x00", "").strip()
            except Exception:
                continue
            # printable-ratio guard so we only keep a plausible decode, not binary noise
            if dec and sum(c.isprintable() for c in dec) / len(dec) > 0.8:
                if dec.lower() not in seen:
                    seen.add(dec.lower())
                    out.append(dec[:400])
                break
    return out


def _extract_payloads(text):
    """Best-effort extraction of the command line(s) the page carries."""
    out, seen = [], set()
    for m in CMD_LINE_RE.finditer(text):
        cmd = m.group(1).strip().strip(";,")
        key = cmd.lower()[:120]
        if len(cmd) >= 6 and key not in seen:
            seen.add(key)
            out.append(cmd[:400])
        if len(out) >= 10:
            break
    return out


def detect(text, captured_clipboard=None):
    """Pure, deterministic detector. Returns a finding dict; never fetches or executes.

    captured_clipboard: optional list of strings a RENDERER observed being written to the
    clipboard at runtime (from the renderer-confirmation path). These are authoritative
    clipboard-write evidence and are scanned for payloads/URLs alongside the static text, so a
    JS-assembled payload the static pass can't join is still caught."""
    text = text or ""
    captured_clipboard = [c for c in (captured_clipboard or []) if c]
    # payload/decoder scan covers any runtime-captured clipboard strings FIRST (so the actually
    # pasted command wins the extraction cap), then the static text.
    scan_text = ("\n".join(captured_clipboard) + "\n" + text) if captured_clipboard else text
    fam = _families(scan_text)
    if captured_clipboard:
        # a rendered clipboard write is authoritative evidence of the mechanism
        fam["clipboard"].append({
            "label": "runtime clipboard write (rendered)", "weight": 25,
            "evidence": captured_clipboard[0][:160],
        })
    has = {k: bool(v) for k, v in fam.items()}
    fam_count = sum(has.values())

    score = 0
    for v in fam.values():
        score += sum(x["weight"] for x in v)
    score = min(100, score)

    # Verdict from family co-occurrence, not raw score (co-occurrence is the real signal).
    if has["clipboard"] and has["payload"]:
        verdict = "high"
    elif fam_count >= 2 or (has["payload"] and has["lure"]):
        verdict = "medium"
    elif fam_count == 1:
        verdict = "low"
    else:
        verdict = "none"

    payloads = _extract_payloads(scan_text) if has["payload"] else []
    decoded = _decode_encoded(scan_text) if has["payload"] else []
    # decoded EncodedCommand strings are payloads in their own right; scan both for URLs
    all_cmds = payloads + [d for d in decoded if d.lower() not in {p.lower() for p in payloads}]
    urls = []
    for p in all_cmds:
        urls += URL_RE.findall(p)
    # de-dup urls, preserve order
    seen, uurls = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uurls.append(u)

    findings = []
    for famname in ("clipboard", "lure", "payload"):
        for x in fam[famname]:
            findings.append({"family": famname, **x})

    rationale_bits = []
    if has["clipboard"]:
        rationale_bits.append("writes to the clipboard programmatically")
    if has["lure"]:
        rationale_bits.append("carries paste-and-run social-engineering text")
    if has["payload"]:
        rationale_bits.append("embeds an OS command payload")
    if decoded:
        rationale_bits.append(f"{len(decoded)} base64 -enc command(s) decoded")
    if captured_clipboard:
        rationale_bits.append("confirmed by a rendered runtime clipboard write")
    rationale = ("Page " + "; ".join(rationale_bits) + "."
                 if rationale_bits else "No clipboard-hijack signals found.")

    return {
        "verdict": verdict,
        "score": score,
        "families_present": [k for k, v in has.items() if v],
        "findings": findings,
        "extracted_payloads": payloads,
        "decoded_commands": decoded,
        "iocs": {"urls": uurls, "commands": all_cmds},
        "mitre": ["T1204.004", "T1059", "T1071"] if verdict in ("high", "medium") else [],
        "rationale": rationale,
        "rendered": bool(captured_clipboard),
    }


_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _fmt_text(r):
    out = [f"Verdict : {r['verdict'].upper()}  (score {r['score']}/100)",
           f"Families: {', '.join(r['families_present']) or 'none'}",
           "", r["rationale"]]
    if r["findings"]:
        out.append("")
        out.append("Signals:")
        for f in r["findings"]:
            out.append(f"  [{f['family']:<9}] +{f['weight']:<3} {f['label']}: {f['evidence']}")
    if r["extracted_payloads"]:
        out.append("")
        out.append("Extracted payload(s):")
        for p in r["extracted_payloads"]:
            out.append(f"  $ {p}")
    if r.get("decoded_commands"):
        out.append("")
        out.append("Decoded -enc command(s):")
        for d in r["decoded_commands"]:
            out.append(f"  > {d}")
    if r["iocs"]["urls"]:
        out.append("")
        out.append("URL IOCs: " + ", ".join(r["iocs"]["urls"]))
    if r["mitre"]:
        out.append("")
        out.append("ATT&CK: " + ", ".join(r["mitre"]))
    return "\n".join(out)


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Detect ClickFix / PasteJacking clipboard-hijack lures in page HTML/JS (offline).")
    ap.add_argument("input", nargs="?", default="-", help="HTML/JS file, or '-' for stdin")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--min", choices=["none", "low", "medium", "high"], default="none",
                    help="minimum verdict to print (exit stays 0)")
    ap.add_argument("-o", "--out", help="write output to a file")
    args = ap.parse_args(argv)

    try:
        text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    r = detect(text)
    if _ORDER[r["verdict"]] < _ORDER[args.min]:
        # below threshold: emit nothing to stdout but stay successful
        return 0
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
