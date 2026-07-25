#!/usr/bin/env python3
# cti-expert skill — reversible PII redaction for shareable report variants.
# Technique (stable numbered placeholders + exportable reversible map) reimplemented from
# the documented behaviour of the Exploratores Redactor. No source was copied — that project
# is AGPL-3.0 and this skill is MIT.
"""redact.py — replace PII in a report with stable numbered placeholders, keeping a
reversible map so the original can be restored.

The skill's pivot engine expands PII by default and every report auto-saves five formats.
This is the valve that makes a report shareable outside the handling organisation without
losing the ability to reconstitute it for evidence.

Guarantees:
  * stable  — the same value always maps to the same placeholder within one map, so
              "[EMAIL_1] contacted [PHONE_2]" stays analytically readable
  * reversible — restore is exact; round-trip is lossless
  * offline  — no network, no dependencies
  * additive — reusing a map across files keeps numbering consistent across a whole case

Known trade-off: placeholders key on the *literal* string, so one account written two ways
("GB29 NWBK …" and "GB29NWBK…") gets two placeholders. Byte-exact restore requires this —
a shared placeholder could not be reversed back to both spellings. Normalise selectors in
the report before redacting if a single placeholder per account matters for the reader.

Usage:
  uv run redact.py REPORT.md -o REPORT.redacted.md --map REPORT.map.json
  uv run redact.py findings.csv -o out.csv --map case.map.json          # CSV cells
  uv run redact.py REPORT.json -o out.json --map case.map.json          # JSON string values
  uv run redact.py --restore REPORT.redacted.md --map REPORT.map.json -o RESTORED.md
  uv run redact.py REPORT.md --types email,phone,iban --dry-run
  uv run redact.py REPORT.md -o out.md --map m.json --custom 'CASE_REF=\\bCR-\\d{6}\\b'
  uv run redact.py --list-types
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import io
import os
import re
import csv
import sys
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# ----------------------------------------------------------------- entity patterns
# Order matters: the first match wins, so composite/longer selectors are declared before the
# narrower ones they contain (URL before DOMAIN, EMAIL before DOMAIN, IBAN before ACCOUNT).
PATTERNS = [
    ("URL",        re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)),
    ("EMAIL",      re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("IBAN",       re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b")),
    ("BTC",        re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("ETH",        re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("XMR",        re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93,104}\b")),
    ("TRON",       re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")),
    ("CARD",       re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("BIC",        re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")),
    ("USCC",       re.compile(r"\b[0-9][0-9A-HJ-NPQRTUWXY]{17}\b")),
    ("SSN",        re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("IPV6",       re.compile(r"\b(?:[A-F0-9]{1,4}:){3,7}[A-F0-9]{1,4}\b", re.I)),
    ("IPV4",       re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                              r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    # Trailing guard is "not another digit" only — guarding against a following dot would
    # break a phone at the end of a sentence. IPs are claimed by IPV4 first via the
    # overlap check, so they never reach this pattern.
    ("PHONE",      re.compile(r"(?<![\w.])\+?\d[\d\s().\-]{7,16}\d(?!\d)")),
    ("DOMAIN",     re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                              r"(?:com|net|org|io|co|vn|cn|top|xyz|info|biz|ru|hk|tw|sg|th|ph|"
                              r"my|id|kh|la|mm|shop|site|online|store|club|live|cc|me|tk|icu|"
                              r"vip|app|dev|pro|asia|email|link|fun|space|website|tech)\b", re.I)),
    ("HANDLE",     re.compile(r"(?<![\w/@])@[A-Za-z0-9._]{3,30}\b")),
]

# Types that are usually infrastructure rather than personal data. Kept out of the default
# set so a "redacted" CTI report still reads as a threat report — an actor's domain is the
# subject of the analysis, not incidental PII.
INFRA_TYPES = {"URL", "DOMAIN", "IPV4", "IPV6"}
DEFAULT_TYPES = [t for t, _ in PATTERNS if t not in INFRA_TYPES]

# Values that must never be redacted: they are analytic vocabulary, not selectors.
NEVER = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1",
}

_LUHN_TYPES = {"CARD"}
_MOD97_TYPES = {"IBAN"}
# PHONE's character class necessarily contains '.', so an IPv4 literal fits its shape. IPV4
# normally claims the span first, but it is off by default — so PHONE must reject IPs itself,
# otherwise an address gets rewritten as [PHONE_n].
_IPV4_SHAPE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOTTED_QUAD_ISH = re.compile(r"^\d{1,3}(?:\.\d{1,3}){2,}$")


def _luhn_ok(value):
    ds = [int(c) for c in re.sub(r"\D", "", value)]
    if not 13 <= len(ds) <= 19:
        return False
    total, parity = 0, len(ds) % 2
    for i, d in enumerate(ds):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mod97_ok(value):
    v = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{9,30}", v):
        return False
    rem = 0
    for ch in (v[4:] + v[:4]):
        for d in (str(int(ch, 36)) if ch.isalpha() else ch):
            rem = (rem * 10 + int(d)) % 97
    return rem == 1


def plausible(kind, value):
    """Reject matches that the shape allows but the standard does not.

    Without this, CARD swallows any long digit run and IBAN swallows arbitrary
    uppercase tokens — over-redaction destroys a report as surely as under-redaction.
    """
    if value.strip() in NEVER:
        return False
    if kind in _LUHN_TYPES:
        return _luhn_ok(value)
    if kind in _MOD97_TYPES:
        return _mod97_ok(value)
    if kind == "USCC":
        return len(re.sub(r"\s", "", value)) == 18
    if kind == "PHONE":
        v = value.strip()
        if _IPV4_SHAPE.match(v) or _DOTTED_QUAD_ISH.match(v):
            return False                      # an address or a version string, not a number
        return len(re.sub(r"\D", "", v)) >= 7   # shortest realistic subscriber number
    return True


class Redactor:
    """Holds the value -> placeholder map and applies it consistently."""

    def __init__(self, types=None, custom=None, existing=None):
        self.patterns = [(k, rx) for k, rx in PATTERNS
                         if types is None or k in types]
        for name, expr in (custom or {}).items():
            self.patterns.append((name.upper(), re.compile(expr)))
        # map: placeholder -> {"type","value"};  index: value -> placeholder
        self.map = {}
        self.index = {}
        self.counters = {}
        if existing:
            self.load(existing)

    # ---------------------------------------------------------------- map I/O
    def load(self, data):
        entries = data.get("entries", data) if isinstance(data, dict) else data
        for ph, rec in entries.items():
            kind = rec["type"] if isinstance(rec, dict) else ph.strip("[]").rsplit("_", 1)[0]
            val = rec["value"] if isinstance(rec, dict) else rec
            self.map[ph] = {"type": kind, "value": val}
            self.index[val] = ph
            m = re.search(r"_(\d+)\]$", ph)
            if m:
                self.counters[kind] = max(self.counters.get(kind, 0), int(m.group(1)))

    def dump(self):
        return {"_note": "cti-expert redaction map — restores the redacted report. "
                         "Handle at the same classification as the unredacted original.",
                "count": len(self.map),
                "entries": self.map}

    # ---------------------------------------------------------------- core
    def placeholder_for(self, kind, value):
        if value in self.index:
            return self.index[value]
        self.counters[kind] = self.counters.get(kind, 0) + 1
        ph = f"[{kind}_{self.counters[kind]}]"
        self.map[ph] = {"type": kind, "value": value}
        self.index[value] = ph
        return ph

    def redact_text(self, text):
        """Single left-to-right pass so earlier patterns win over later, narrower ones."""
        if not text:
            return text, 0
        spans = []          # (start, end, kind, matched_text)
        taken = []          # already-claimed [start,end) ranges

        def overlaps(a, b):
            return any(a < e and s < b for s, e in taken)

        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                s, e = m.span()
                raw = m.group(0)
                # Keep trailing sentence punctuation and whitespace out of the captured
                # selector — grouped formats (card/IBAN) legitimately match a trailing
                # separator, and swallowing it would weld the placeholder to the next word.
                trimmed = raw.rstrip(".,;:!?)]}’\"' \t ")
                e -= len(raw) - len(trimmed)
                raw = trimmed
                if not raw or overlaps(s, e) or not plausible(kind, raw):
                    continue
                taken.append((s, e))
                spans.append((s, e, kind, raw))

        if not spans:
            return text, 0
        spans.sort()
        out, pos = [], 0
        for s, e, kind, raw in spans:
            out.append(text[pos:s])
            out.append(self.placeholder_for(kind, raw))
            pos = e
        out.append(text[pos:])
        return "".join(out), len(spans)

    def restore_text(self, text):
        n = 0
        # longest placeholder first so [EMAIL_1] never eats [EMAIL_12]
        for ph in sorted(self.map, key=len, reverse=True):
            if ph in text:
                n += text.count(ph)
                text = text.replace(ph, self.map[ph]["value"])
        return text, n

    # ---------------------------------------------------------------- structured formats
    def walk_json(self, obj, fn):
        if isinstance(obj, dict):
            return {k: self.walk_json(v, fn) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk_json(v, fn) for v in obj]
        if isinstance(obj, str):
            return fn(obj)[0]
        return obj


def process(path, out_path, red, mode, fmt):
    """Apply redact/restore to a file, dispatching on format. Returns hit count."""
    apply_ = red.redact_text if mode == "redact" else red.restore_text

    if fmt == "csv":
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
        n = 0
        for r in rows:
            for i, cell in enumerate(r):
                r[i], k = apply_(cell)
                n += k
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(rows)
        text = buf.getvalue()
    elif fmt == "json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        before = len(red.map)
        data = red.walk_json(data, apply_)
        text = json.dumps(data, ensure_ascii=False, indent=2)
        n = len(red.map) - before if mode == "redact" else -1
    else:
        # newline="" disables translation both ways, so redact -> restore is byte-exact
        # regardless of whether the source used LF or CRLF.
        with open(path, encoding="utf-8", newline="") as f:
            text = f.read()
        text, n = apply_(text)

    if out_path:
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    else:
        print(text)
    return n


def detect_format(path, override):
    if override:
        return override
    ext = os.path.splitext(path)[1].lower()
    return {".csv": "csv", ".json": "json"}.get(ext, "text")


def main():
    ap = argparse.ArgumentParser(
        description="Reversible PII redaction with stable numbered placeholders.")
    ap.add_argument("input", nargs="?", help="file to redact (or restore with --restore)")
    ap.add_argument("--restore", action="store_true",
                    help="reverse a redaction using --map (map is required)")
    ap.add_argument("--map", help="redaction map JSON — read if it exists, written after redact")
    ap.add_argument("-o", "--out", help="output file (default: stdout)")
    ap.add_argument("--types", help="comma-separated entity types (default: all PII types; "
                                    "infrastructure types are opt-in — see --list-types)")
    ap.add_argument("--all-types", action="store_true",
                    help="also redact URL/DOMAIN/IPV4/IPV6 (off by default: a CTI report's "
                         "subject infrastructure is the analysis, not incidental PII)")
    ap.add_argument("--custom", action="append", default=[], metavar="NAME=REGEX",
                    help="extra pattern, repeatable (e.g. --custom 'CASE_REF=\\bCR-\\d{6}\\b')")
    ap.add_argument("--format", choices=["text", "csv", "json"], help="override format detection")
    ap.add_argument("--dry-run", action="store_true", help="report what would be redacted only")
    ap.add_argument("--list-types", action="store_true", help="print entity types and exit")
    args = ap.parse_args()

    if args.list_types:
        print("entity types (default set marked *):\n")
        for k, _ in PATTERNS:
            print(f"  {'*' if k in DEFAULT_TYPES else ' '} {k}")
        print("\nUnmarked types are infrastructure — enable with --all-types or --types.")
        return 0

    if not args.input:
        ap.error("no input file given")
    if args.restore and not args.map:
        ap.error("--restore needs --map (the map is the only way back)")

    types = None
    if args.types:
        types = {t.strip().upper() for t in args.types.split(",") if t.strip()}
        unknown = types - {k for k, _ in PATTERNS}
        if unknown:
            ap.error(f"unknown type(s): {', '.join(sorted(unknown))} — see --list-types")
    elif not args.all_types:
        types = set(DEFAULT_TYPES)

    custom = {}
    for c in args.custom:
        if "=" not in c:
            ap.error(f"--custom needs NAME=REGEX, got: {c}")
        name, expr = c.split("=", 1)
        try:
            re.compile(expr)
        except re.error as e:
            ap.error(f"--custom {name}: bad regex ({e})")
        custom[name] = expr

    existing = None
    if args.map and os.path.exists(args.map):
        with open(args.map, encoding="utf-8") as f:
            existing = json.load(f)

    red = Redactor(types=types, custom=custom, existing=existing)
    fmt = detect_format(args.input, args.format)
    mode = "restore" if args.restore else "redact"

    if args.dry_run:
        with open(args.input, encoding="utf-8") as f:
            _, n = red.redact_text(f.read()) if fmt != "csv" else (None, 0)
        by_type = {}
        for rec in red.map.values():
            by_type[rec["type"]] = by_type.get(rec["type"], 0) + 1
        print(f"dry-run: {n} replacement(s), {len(red.map)} distinct value(s)")
        for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"  {k:<10} {v}")
        return 0

    before = len(red.map)
    n = process(args.input, args.out, red, mode, fmt)

    if mode == "redact" and args.map:
        with open(args.map, "w", encoding="utf-8") as f:
            json.dump(red.dump(), f, ensure_ascii=False, indent=2)
        try:
            os.chmod(args.map, 0o600)     # no-op on Windows; correct on POSIX
        except OSError:
            pass

    new = len(red.map) - before
    if mode == "redact":
        print(f"redact: {n if n >= 0 else 'n/a'} replacement(s), {new} new value(s), "
              f"{len(red.map)} in map"
              + (f" -> {args.map}" if args.map else "  ⚠ NO --map: THIS IS IRREVERSIBLE"),
              file=sys.stderr)
    else:
        print(f"restore: {n if n >= 0 else 'n/a'} placeholder(s) resolved from {args.map}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
