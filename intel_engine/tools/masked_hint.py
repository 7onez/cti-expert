#!/usr/bin/env python3
"""masked_hint.py — correlate MASKED account-recovery hints against selectors already known.

A password-reset or login flow often shows a masked recovery address or number:
`de*****@mail.example`, `j***@e*****.com`, `*******08`, `+84 *** *** *12`, `•••• 4321`. Each one
is a constraint, not a selector: it cannot be searched, but it can be TESTED against e-mails and
phones a case already holds. This module compiles every hint into a regex over the normalised
candidate (lower-cased e-mail; phone as digits in E.164 and national forms) and reports which
known candidates fit.

ATTRIBUTION SAFETY (CLAUDE.md RULE 5)
-------------------------------------
A hint match is CORROBORATING only. Two characters and a mail domain fit thousands of strangers;
even a unique fit among the case's candidates only says the hint does not contradict a selector
the case ALREADY links by real evidence. It is never a join key, never a KB edge, never names an
operator. The output carries `rung: corroborating` and a `caveat` saying so. Nothing is written.

Pure and offline: no network, no KB writes. Mask grammar, provider length semantics and
thresholds are reference DATA in tools/kb/references/masked_hint.json (RULE 3).

CLI:
    masked_hint.py --hints "op*****@example.com,*******08" --candidates "operator@example.com,+84900000008"
    masked_hint.py --hints-file hints.txt --case CASE-0001 [--kb DIR] [--provider microsoft]
"""
import argparse
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # intel_engine/
_KB_TOOLS = os.path.join(HERE, "kb")
if _KB_TOOLS not in sys.path:
    sys.path.append(_KB_TOOLS)

_FALLBACK = {
    "mask_chars": {"always": ["*", "•", "·", "●"], "contextual": ["x", "X", "_"], "email_min_run": 3},
    "providers": {"unknown": {"length": "unknown"}, "generic_exact": {"length": "exact"}},
    "matching": {"min_hidden": 1, "min_visible_email": 3, "min_visible_phone": 4},
    "common_mail_domains": ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"],
    "calling_codes": ["1", "7", "33", "44", "49", "61", "81", "82", "84", "86", "91"],
    "case_scan": {"max_file_bytes": 20000000, "phone_keys": ["phone", "tel", "mobile"]},
}
try:
    import kb_refs as _kb_refs                     # tools/kb/kb_refs.py — the shared RULE 3 loader
    _REF = _kb_refs.load_ref(_kb_refs.ref_path(_kb_refs.__file__, "masked_hint.json"), _FALLBACK)
except Exception:                                  # noqa: BLE001 — degrade, never block
    sys.stderr.write("[masked_hint] WARNING: kb_refs unavailable; masked_hint.json not read — "
                     "running on the minimal embedded fallback.\n")
    _REF = dict(_FALLBACK)

_MASK = _REF.get("mask_chars") or _FALLBACK["mask_chars"]
_ALWAYS = set(_MASK.get("always") or _FALLBACK["mask_chars"]["always"])
_CONTEXT = set(_MASK.get("contextual") or ())
_EMAIL_MIN_RUN = int(_MASK.get("email_min_run") or 3)
_PROVIDERS = _REF.get("providers") or _FALLBACK["providers"]
_MATCH = {**_FALLBACK["matching"], **(_REF.get("matching") or {})}
_COMMON_MAIL = {d.lower() for d in (_REF.get("common_mail_domains") or ())}
_CODES = sorted({str(c) for c in (_REF.get("calling_codes") or _FALLBACK["calling_codes"])},
                key=len, reverse=True)
_SCAN = {**_FALLBACK["case_scan"], **(_REF.get("case_scan") or {})}

CAVEAT = ("A masked-hint match is CORROBORATING only (RULE 5): it may raise confidence in a selector "
          "the case already links by real evidence; it is never a join key, never a KB edge, and "
          "never names an operator.")

_EMAIL_RE = re.compile(r"^[a-z0-9._%+'-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}$")
_PHONE_SEP = set(" -.()/\u00a0")


# ---------------------------------------------------------------- candidates
def _phone_forms(raw):
    """Digit strings a phone candidate may be displayed as: E.164 digits, national with and
    without the trunk 0. Returns (e164_digits_or_None, set_of_all_forms)."""
    s = str(raw).strip()
    digits = "".join(c for c in s if c.isdigit())
    if len(digits) < 6:
        return None, set()
    intl = s.startswith("+") or digits.startswith("00")
    if digits.startswith("00"):
        digits = digits[2:]
    forms = {digits}
    e164 = None
    if intl:
        e164 = digits
        for cc in _CODES:
            if digits.startswith(cc) and len(digits) - len(cc) >= 4:
                national = digits[len(cc):]
                forms |= {national, "0" + national}
                break
    elif digits.startswith("0"):
        forms.add(digits[1:])
    return e164, forms


def candidate(raw, source="cli"):
    """Normalise one known selector, or None when it is neither an e-mail nor a phone."""
    v = str(raw or "").strip()
    if v.lower().startswith("mailto:"):
        v = v[7:]
    if "@" in v:
        v = v.lower()
        return {"value": v, "kind": "email", "norm": v, "source": source} if _EMAIL_RE.match(v) else None
    if any(c in _ALWAYS for c in v) or not re.fullmatch(r"\+?[0-9()\-\s./\u00a0]{6,24}", v):
        return None
    e164, forms = _phone_forms(v)
    if not forms:
        return None
    return {"value": v, "kind": "phone", "norm": e164 or sorted(forms, key=len)[-1],
            "e164": e164, "forms": sorted(forms), "source": source}


def _add(out, raw, source):
    c = candidate(raw, source)
    if not c:
        return
    key = (c["kind"], c["norm"])
    if key in out:
        if source not in out[key]["source"].split(";"):
            out[key]["source"] += ";" + source
    else:
        out[key] = c


def _case_dir(case):
    c = str(case)
    if os.path.isabs(c) or os.sep in c or (os.altsep and os.altsep in c):
        return c
    return os.path.join(ROOT, "cases", c)


def _walk_json(obj, out, source, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_json(v, out, source, str(k).lower())
    elif isinstance(obj, list):
        for v in obj:
            _walk_json(v, out, source, key)
    elif isinstance(obj, str):
        s = obj.strip()
        if "@" in s and len(s) <= 254:
            _add(out, s, source)
        elif key and any(p in key for p in _SCAN["phone_keys"]):
            _add(out, s, source)
    elif isinstance(obj, int) and not isinstance(obj, bool) and key \
            and any(p in key for p in _SCAN["phone_keys"]):
        _add(out, str(obj), source)


def case_candidates(case, kb_root=None):
    """Known e-mails/phones of a case, read-only: every JSON/JSONL file under cases/<id>/ plus the
    KB's live e-mail/phone edge endpoints and e-mail entities whose provenance lists the case.
    Returns (candidates_dict, notes)."""
    out, notes = {}, []
    cdir = _case_dir(case)
    cid = os.path.basename(os.path.normpath(str(case)))
    if os.path.isdir(cdir):
        for root, _, files in os.walk(cdir):
            for fn in sorted(files):
                if not (fn.endswith(".json") or fn.endswith(".jsonl")):
                    continue
                p = os.path.join(root, fn)
                try:
                    if os.path.getsize(p) > int(_SCAN["max_file_bytes"]):
                        notes.append(f"skipped oversized {os.path.relpath(p, cdir)}")
                        continue
                    src = "case:" + os.path.relpath(p, cdir)
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        if fn.endswith(".jsonl"):
                            for line in fh:
                                line = line.strip()
                                if line:
                                    try:
                                        _walk_json(json.loads(line), out, src)
                                    except ValueError:
                                        continue
                        else:
                            _walk_json(json.load(fh), out, src)
                except (OSError, ValueError):
                    notes.append(f"unreadable {os.path.relpath(p, cdir)}")
    else:
        notes.append(f"case directory not found: {cdir}")
    kb = kb_root or os.path.join(ROOT, os.environ.get("HARNESS_KB", "knowledge"))
    edges = os.path.join(kb, "relationships", "edges.jsonl")
    if os.path.isfile(edges):
        with open(edges, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("status") == "retracted" or cid not in (e.get("cases") or ()):
                    continue
                for t, v in ((e.get("src_type"), e.get("src")), (e.get("dst_type"), e.get("dst"))):
                    if t in ("email", "phone"):
                        _add(out, v, "kb:edge")
    edir = os.path.join(kb, "entities", "email")
    if os.path.isdir(edir):
        for fn in os.listdir(edir):
            try:
                with open(os.path.join(edir, fn), encoding="utf-8") as fh:
                    ent = json.load(fh)
            except (OSError, ValueError):
                continue
            if any(f.get("status") != "retracted" and cid in (f.get("cases") or ())
                   for f in ent.get("facts") or ()):
                _add(out, ent.get("value"), "kb:entity")
    return out, notes


# ---------------------------------------------------------------- hints
def _tokens(text, masks):
    """[(is_mask, run)] — consecutive mask characters merged into one run."""
    toks = []
    for ch in text:
        m = ch in masks
        if toks and toks[-1][0] == m and m:
            toks[-1] = (True, toks[-1][1] + ch)
        else:
            toks.append((m, ch))
    return toks


def _email_masks(hint):
    if any(c in _ALWAYS for c in hint):
        return _ALWAYS
    ctx = set()
    for ch in _CONTEXT:
        if re.search(re.escape(ch) + "{%d,}" % _EMAIL_MIN_RUN, hint):
            ctx.add(ch)
    return ctx


def _run_re(run, cls, exact):
    n = len(run)
    return f"{cls}{{{n}}}" if exact else f"{cls}{{{int(_MATCH['min_hidden'])},}}"


def compile_hint(hint, provider="unknown"):
    """Compile one masked hint. Returns a dict with kind/pattern/visible counts, or {"error"}."""
    raw = str(hint or "").strip()
    if not raw:
        return {"error": "empty hint"}
    prov = _PROVIDERS.get(provider) or _PROVIDERS.get("unknown") or {"length": "unknown"}
    exact = prov.get("length") == "exact"
    if "@" in raw:
        h = raw.lower()
        masks = _email_masks(raw)
        masks = {m.lower() for m in masks}
        if h.count("@") != 1:
            return {"error": f"malformed e-mail hint: {raw}"}
        local, domain = h.split("@")
        parts, visible, disc, masked_any = [], 0, 0, False
        dom_masked = any(c in masks for c in domain)
        common = (not dom_masked) and domain in _COMMON_MAIL
        contextual = not (masks & _ALWAYS)
        for part, is_domain in ((local, False), (domain, True)):
            rx = ""
            for m, tok in _tokens(part, masks):
                if m and contextual and len(tok) < _EMAIL_MIN_RUN:
                    m = False                  # a lone x/_ in an address is a letter, not a mask
                if m:
                    rx += _run_re(tok, "[^@]", exact)
                    masked_any = True
                else:
                    rx += re.escape(tok)
                    for ch in tok:
                        if ch.isalnum():
                            visible += 1
                            if not (is_domain and common):
                                disc += 1
            parts.append(rx)
        if not masked_any:
            return {"error": f"no mask characters in hint: {raw}"}
        alphabet = 37
        pattern = "^" + parts[0] + "@" + parts[1] + "$"
        kind = "email"
        e164_only = False
    else:
        masks = _ALWAYS | _CONTEXT
        body = "".join(c for c in raw if c not in _PHONE_SEP)
        e164_only = body.startswith("+")
        body = body.lstrip("+")
        if not body or any(not (c.isdigit() or c in masks) for c in body):
            return {"error": f"unparseable hint (not an e-mail or digit mask): {raw}"}
        if not any(c in masks for c in body):
            return {"error": f"no mask characters in hint: {raw}"}
        rx, visible = "", 0
        for m, tok in _tokens(body, masks):
            if m:
                rx += _run_re(tok, r"\d", exact)
            else:
                rx += tok
                visible += 1
        disc, alphabet = visible, 10
        pattern = "^" + rx + "$"
        kind = "phone" if (e164_only or len(body) >= 7) else "digits"
    return {"hint": raw, "kind": kind, "pattern": pattern, "provider": provider,
            "length_semantics": "exact" if exact else "unknown",
            "e164_only": e164_only, "visible_chars": visible, "discriminating_chars": disc,
            "est_bits": round(disc * math.log2(alphabet), 1)}


def match_hint(hint, cands, provider="unknown", min_visible=None):
    c = compile_hint(hint, provider)
    if "error" in c:
        return {"hint": str(hint), "error": c["error"], "matches": [], "verdict": "no_match"}
    rx = re.compile(c["pattern"])
    hits = []
    for cand in cands:
        if c["kind"] == "email":
            if cand["kind"] == "email" and rx.match(cand["norm"]):
                hits.append(cand)
        elif cand["kind"] == "phone":
            forms = [cand["e164"]] if c["e164_only"] else cand["forms"]
            if c["e164_only"] and not cand.get("e164"):
                forms = cand["forms"]          # no country code known: national forms are all we have
            if any(f and rx.match(f) for f in forms):
                hits.append(cand)
    if min_visible is None:
        min_visible = int(_MATCH["min_visible_email" if c["kind"] == "email" else "min_visible_phone"])
    strength = "unique" if len(hits) == 1 else "ambiguous"
    c["matches"] = [{"candidate": h["value"], "normalised": h["norm"], "source": h["source"],
                     "strength": strength} for h in hits]
    c["min_visible"] = min_visible
    if not hits:
        c["verdict"], c["reason"] = "no_match", "no known candidate fits the hint"
    elif len(hits) == 1 and c["discriminating_chars"] >= min_visible:
        c["verdict"] = "corroborates"
        c["reason"] = (f"exactly one known candidate fits and {c['discriminating_chars']} discriminating "
                       f"characters are visible (>= {min_visible})")
    elif len(hits) == 1:
        c["verdict"] = "consistent"
        c["reason"] = (f"one known candidate fits, but only {c['discriminating_chars']} discriminating "
                       f"characters are visible (< {min_visible}) — does not single it out")
    else:
        c["verdict"], c["reason"] = "consistent", f"{len(hits)} known candidates fit the hint"
    c["rung"] = "corroborating"
    return c


def _split(text):
    return [s.strip() for s in re.split(r"[,\n;]", text or "") if s.strip()]


def run(hints, candidates=None, case=None, kb_root=None, provider="unknown", min_visible=None):
    """Tri-state: result dict, or {"error": ...}. Never raises."""
    try:
        hints = [h for h in (hints or []) if h]
        if not hints:
            return {"error": "no hints given"}
        if provider not in _PROVIDERS:
            return {"error": f"unknown provider {provider!r}; one of {sorted(_PROVIDERS)}"}
        pool, notes = {}, []
        for v in candidates or ():
            _add(pool, v, "cli")
        if case:
            got, notes = case_candidates(case, kb_root)
            for k, v in got.items():
                if k in pool:
                    pool[k]["source"] += ";" + v["source"]
                else:
                    pool[k] = v
        cands = list(pool.values())
        if not cands:
            return {"error": "no known e-mail/phone candidates to test against", "notes": notes}
        results = [match_hint(h, cands, provider, min_visible) for h in hints]
        return {"hints": results,
                "candidates": {"count": len(cands),
                               "emails": sum(1 for c in cands if c["kind"] == "email"),
                               "phones": sum(1 for c in cands if c["kind"] == "phone"),
                               "case": case, "notes": notes},
                "summary": {v: sum(1 for r in results if r.get("verdict") == v)
                            for v in ("corroborates", "consistent", "no_match")},
                "provider": provider, "rung": "corroborating", "caveat": CAVEAT}
    except Exception as e:                         # noqa: BLE001 — tri-state, never raise
        return {"error": f"{type(e).__name__}: {e}"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Correlate masked recovery hints against known selectors "
                                             "(corroborating only — never a join key or KB edge).")
    ap.add_argument("--hints", default="", help="comma/newline-separated masked hints")
    ap.add_argument("--hints-file", help="file with one hint per line")
    ap.add_argument("--candidates", default="", help="comma-separated known e-mails/phones")
    ap.add_argument("--case", help="case ID or path: load its known e-mails/phones (read-only)")
    ap.add_argument("--kb", help="KB root (default intel_engine/knowledge or $HARNESS_KB)")
    ap.add_argument("--provider", default="unknown",
                    help="provider that displayed the hint (mask length semantics): " + ", ".join(_PROVIDERS))
    ap.add_argument("--min-visible", type=int, help="override discriminating-character threshold")
    a = ap.parse_args(argv)
    hints = _split(a.hints)
    if a.hints_file:
        try:
            with open(a.hints_file, encoding="utf-8") as fh:
                hints += [ln.strip() for ln in fh if ln.strip()]
        except OSError as e:
            print(json.dumps({"error": f"cannot read hints file: {e}"}))
            return 1
    res = run(hints, _split(a.candidates), a.case, a.kb, a.provider, a.min_visible)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 1 if "error" in res else 0


if __name__ == "__main__":
    sys.exit(main())
