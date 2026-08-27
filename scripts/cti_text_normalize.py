#!/usr/bin/env python3
# cti-expert skill — shared text normalization for report exports.
"""cti_text_normalize.py — normalize typographic dashes in generated report text.

Em dashes (—, U+2014), en dashes (–, U+2013) and horizontal bars (―, U+2015) are a
strong "written by an LLM" tell and read unnaturally in analyst deliverables. Every
report generator (HTML, DOCX) routes its human-facing text through here so exported
reports use a plain ASCII hyphen instead.

Rules:
- A dash with text on either side becomes a spaced hyphen: "a—b" and "a — b" both
  render as "a - b" (also normalizes numeric ranges: "2020–2021" -> "2020 - 2021").
- A dash at the very start/end of a string (or of a line) drops the orphan space so no
  leading/trailing whitespace is introduced.
- Only prose is touched. Structured selectors/IOCs are normalized by their own writers,
  never here, so indicator values are never mutated.

Author: Hieu Ngo - chongluadao.vn
"""
import re

# em dash, en dash, horizontal bar
_DASHES = "\u2014\u2013\u2015"
# a run of one-or-more fancy dashes plus any whitespace hugging it
_DASH_RUN = re.compile(r"[ \t]*[" + _DASHES + r"]+[ \t]*")


def normalize_dashes(text):
    """Replace em/en/horizontal-bar dashes with a plain, sensibly-spaced hyphen."""
    if not text or not isinstance(text, str):
        return text
    if not any(c in text for c in _DASHES):
        return text

    def _repl(m):
        s, e = m.start(), m.end()
        # No spaces when the dash sits against a line boundary, so we never leave a
        # dangling leading/trailing space (e.g. "— note" -> "- note", "end —" -> "end -").
        at_start = s == 0 or text[s - 1] == "\n"
        at_end = e == len(text) or text[e] == "\n"
        if at_start and at_end:
            return "-"
        if at_start:
            return "- "
        if at_end:
            return " -"
        return " - "

    return _DASH_RUN.sub(_repl, text)


def normalize_obj(obj):
    """Recursively normalize every string inside a JSON-like structure.

    Returns a new structure; the input is left untouched. Dict keys are preserved as-is
    (they are field names, not prose)."""
    if isinstance(obj, str):
        return normalize_dashes(obj)
    if isinstance(obj, list):
        return [normalize_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(normalize_obj(v) for v in obj)
    if isinstance(obj, dict):
        return {k: normalize_obj(v) for k, v in obj.items()}
    return obj


def _cli(argv):
    """In-place file normalizer used by the export workflow to clean the on-disk
    deliverables (REPORT.md, REPORT.json, …) that no generator otherwise touches.

    Usage:
        cti_text_normalize.py FILE [FILE ...]   # rewrite each file in place
        cti_text_normalize.py -                 # stdin -> stdout

    A file's dashes are replaced by treating it as raw UTF-8 text — safe for .md, .txt,
    .csv and .json alike, because em/en/bar dashes only ever occur inside string content,
    never in structural syntax. Files are rewritten only when something actually changes.
    """
    import sys
    args = [a for a in argv if a != "--"]
    if not args:
        sys.stderr.write("usage: cti_text_normalize.py FILE [FILE ...] | -\n")
        return 2
    if args == ["-"]:
        sys.stdout.write(normalize_dashes(sys.stdin.read()))
        return 0
    rc = 0
    for path in args:
        try:
            with open(path, "r", encoding="utf-8") as f:
                original = f.read()
        except OSError as e:
            sys.stderr.write("skip %r: %s\n" % (path, e))
            rc = 1
            continue
        normalized = normalize_dashes(original)
        changed = sum(original.count(c) for c in _DASHES)
        if normalized != original:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(normalized)
            print("normalized %d dash(es): %s" % (changed, path))
        else:
            print("no change: %s" % path)
    return rc


if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
