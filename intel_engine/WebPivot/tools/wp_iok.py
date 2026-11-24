#!/usr/bin/env python3
"""wp_iok — convert phish.report IOK rules (Sigma, as IOK uses it) into wp_kitsig rules.

IOK (https://github.com/phish-report/IOK, ODbL-1.0) is the public rule set the named-kit library
is seeded from. The rules are NEVER copied into this repository: `scripts/kit_rules_import.py
update` downloads the repository tarball into the git-ignored cache and calls `convert_tarball`
here; wp_kitsig reads the result. This module is pure and stdlib-only — the YAML parser is injected
by the caller (the root script runs with PyYAML under `uv run`).

    convert_rule(doc, stem, filename=None) -> (rule | None, reason)
    convert_tarball(data, load_yaml)       -> {rules, skipped, counts, commit}

FAITHFUL OR REFUSED. IOK runs sigma-go with its case-sensitive comparators: `contains`,
`startswith`, `endswith` and `re` are case-SENSITIVE, a bare value is case-insensitive equality,
and `*`/`?` in a value are literal characters (no glob). The converter maps each onto the matching
wp_kitsig op (contains_cs, startswith_cs, endswith_cs, regex_cs, iequals). Anything it does not
understand — an unknown field or modifier, an unparsable condition, a field the engine cannot
populate, an empty detection, an over-size value, a regex that does not compile within the bound,
a rule that could hold with no positive leaf — returns (None, "<reason>"), never a guessed or
partial rule.

Prevalence is mapped conservatively through reference data (`iok_import` in
kit_signatures.json): only a rule tagged as a specific kit is `limited`; everything else is
`commodity` (noise context, never a pivot). Never `private`.
"""
import fnmatch
import gzip
import io
import json
import os
import re
import tarfile
from urllib.parse import quote

from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
import wp_kitsig  # noqa: E402 — FIELDS / OPS / term rails are the matcher's own

# DATA: references/kit_signatures.json -> iok_import. The conservative minimum imports NOTHING
# (empty field_map: every rule is refused as using an unknown field) and maps every tag to
# commodity; the download URL and the size caps stay so a broken file fails loudly, not wide.
_IOK_FALLBACK = {
    "iok_import": {
        "source_url": "https://codeload.github.com/phish-report/IOK/tar.gz/refs/heads/main",
        "rule_url_template": "https://github.com/phish-report/IOK/blob/main/indicators/{file}",
        "licence": "ODbL-1.0",
        "attribution": "Contains information from phish.report IOK "
                       "(https://github.com/phish-report/IOK), made available under the ODbL-1.0.",
        "timeout_seconds": 60,
        "max_tarball_bytes": 8388608,
        "max_unpacked_bytes": 33554432,
        "max_members": 1000,
        "max_rules": 500,
        "max_rule_bytes": 16384,
        "max_value_len": 1024,
        "max_values_per_key": 32,
        "max_leaves": 64,
        "field_map": {},
        "unavailable_fields": [],
        "limited_tags": [],
        "commodity_tags": [],
        "commodity_rule_ids": [],
        "kind_tags": [],
        "default_kind": "phishing",
    },
}
_IOK_REF = load_ref(ref_path(__file__, "kit_signatures.json"), _IOK_FALLBACK)
SETTINGS = _IOK_REF["iok_import"] if isinstance(_IOK_REF.get("iok_import"), dict) else {}
_FB = _IOK_FALLBACK["iok_import"]


def _setting(key):
    v = SETTINGS.get(key)
    fb = _FB[key]
    if isinstance(fb, int):
        try:
            v = int(v)
        except (TypeError, ValueError):
            return fb
        return v if v > 0 else fb
    return v if isinstance(v, type(fb)) else fb


SOURCE_URL = _setting("source_url")
RULE_URL_TEMPLATE = _setting("rule_url_template")
LICENCE = _setting("licence")
ATTRIBUTION = _setting("attribution")
TIMEOUT = _setting("timeout_seconds")
MAX_TARBALL_BYTES = _setting("max_tarball_bytes")
MAX_UNPACKED_BYTES = _setting("max_unpacked_bytes")
MAX_MEMBERS = _setting("max_members")
MAX_RULES = _setting("max_rules")
MAX_RULE_BYTES = _setting("max_rule_bytes")
MAX_VALUE_LEN = _setting("max_value_len")
MAX_VALUES_PER_KEY = _setting("max_values_per_key")
MAX_LEAVES = _setting("max_leaves")
FIELD_MAP = {str(k): str(v) for k, v in _setting("field_map").items()
             if str(v) in wp_kitsig.FIELDS}
UNAVAILABLE_FIELDS = [str(f) for f in _setting("unavailable_fields")]
LIMITED_TAGS = [str(t) for t in _setting("limited_tags")]
COMMODITY_TAGS = [str(t) for t in _setting("commodity_tags")]
COMMODITY_RULE_IDS = [str(t) for t in _setting("commodity_rule_ids")]
KIND_TAGS = [(str(r[0]), str(r[1])) for r in _setting("kind_tags")
             if isinstance(r, list) and len(r) == 2]
DEFAULT_KIND = _setting("default_kind")

# Sigma modifier (as IOK's case-sensitive evaluator runs it) -> wp_kitsig op
_MOD_OP = {"": "iequals", "contains": "contains_cs", "startswith": "startswith_cs",
           "endswith": "endswith_cs", "re": "regex_cs"}
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_STEM_RE = re.compile(r"[^\x00-\x20\x7f./\\][^\x00-\x20\x7f/\\]{0,127}\Z")   # no path, space or control


class Refused(Exception):
    """A construct the converter does not express faithfully; the message is the skip reason."""


# ------------------------------------------------------------------------ condition grammar
_TOKEN_RE = re.compile(r"\s*(?:(?P<paren>[()])|(?P<num>\d+)|(?P<word>[A-Za-z_*][A-Za-z0-9_*]*)"
                       r"|(?P<bad>\S))")
_KEYWORDS = ("and", "or", "not", "of", "them", "all")


def _tokens(text):
    out, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        if m.group("bad"):
            raise Refused(f"unsupported condition syntax: {m.group('bad')!r}")
        if m.group("paren"):
            out.append(("paren", m.group("paren")))
        elif m.group("num"):
            out.append(("num", m.group("num")))
        elif m.group("word"):
            w = m.group("word")
            out.append(("kw", w.lower()) if w.lower() in _KEYWORDS else ("ident", w))
    return out


class _Parser:
    """Recursive descent over Sigma's search-expression grammar as sigma-go defines it:
        expr  := conj ("or" conj)*
        conj  := term ("and" term)*
        term  := "not" term | "(" expr ")" | quant | IDENT
        quant := ("1" | "all") "of" ("them" | IDENT | PATTERN)
    `not` binds tighter than `and`, which binds tighter than `or`."""

    def __init__(self, text, selections):
        self.toks = _tokens(text)
        self.i = 0
        self.sel = selections          # name -> converted term, detection order

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def _take(self, kind=None, value=None):
        tok = self._peek()
        if tok[0] is None or (kind and tok[0] != kind) or (value and tok[1] != value):
            want = value or kind or "a token"
            raise Refused(f"unparsable condition: expected {want}, got {tok[1]!r}")
        self.i += 1
        return tok

    def parse(self):
        if not self.toks:
            raise Refused("empty condition")
        node = self._expr()
        if self.i != len(self.toks):
            raise Refused(f"unparsable condition: trailing {self._peek()[1]!r}")
        return node

    def _expr(self):
        parts = [self._conj()]
        while self._peek() == ("kw", "or"):
            self.i += 1
            parts.append(self._conj())
        return _group("any", parts)

    def _conj(self):
        parts = [self._term()]
        while self._peek() == ("kw", "and"):
            self.i += 1
            parts.append(self._term())
        return _group("all", parts)

    def _term(self):
        kind, val = self._peek()
        if (kind, val) == ("kw", "not"):
            self.i += 1
            return {"not": self._term()}
        if (kind, val) == ("paren", "("):
            self.i += 1
            node = self._expr()
            self._take("paren", ")")
            return node
        if kind == "num" or (kind, val) == ("kw", "all"):
            return self._quant()
        if kind == "ident":
            self.i += 1
            if "*" in val:
                raise Refused(f"unparsable condition: pattern {val!r} outside 'of'")
            if val not in self.sel:
                raise Refused(f"condition references undefined selection: {val}")
            return self.sel[val]
        raise Refused(f"unparsable condition: unexpected {val!r}")

    def _quant(self):
        kind, val = self._take()
        if kind == "num" and val != "1":
            raise Refused(f"unsupported quantifier: {val} of")
        self._take("kw", "of")
        kind, target = self._take()
        if (kind, target) == ("kw", "them"):
            names = list(self.sel)
        elif kind == "ident":
            names = [n for n in self.sel if fnmatch.fnmatchcase(n, target)] if "*" in target \
                else ([target] if target in self.sel else [])
            if not names:
                raise Refused(f"quantifier target matches no selection: {target}")
        else:
            raise Refused(f"unparsable condition: bad quantifier target {target!r}")
        return _group("any" if val == "1" else "all", [self.sel[n] for n in names])


def _group(key, parts):
    """An all/any group, flattening same-kind children; a single part is itself."""
    flat = []
    for p in parts:
        if isinstance(p, dict) and set(p) == {key}:
            flat += p[key]
        else:
            flat.append(p)
    return flat[0] if len(flat) == 1 else {key: flat}


# ------------------------------------------------------------------------ detection -> terms
def _leaves(term):
    if "not" in term:
        return _leaves(term["not"])
    for key in ("all", "any"):
        if key in term:
            return sum(_leaves(k) for k in term[key])
    return 1


def _field_term(key, value):
    parts = str(key).split("|")
    field, mods = parts[0], parts[1:]
    every = False
    if mods and mods[-1] == "all":
        every, mods = True, mods[:-1]
    if "all" in mods:
        raise Refused("modifier 'all' must be last")
    if len(mods) > 1:
        raise Refused(f"unsupported modifier chain: {'|'.join(mods)}")
    mod = mods[0] if mods else ""
    if mod not in _MOD_OP:
        raise Refused(f"unsupported modifier: {mod}")
    if field in UNAVAILABLE_FIELDS:
        raise Refused(f"field the engine cannot populate: {field}")
    if field not in FIELD_MAP:
        raise Refused(f"unknown field: {field}")
    op = _MOD_OP[mod]
    values = value if isinstance(value, list) else [value]
    if not values:
        raise Refused("empty value list")
    if len(values) > MAX_VALUES_PER_KEY:
        raise Refused("too many values for one field")
    leaves = []
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise Refused(f"unsupported value type: {type(v).__name__}")
        s = str(v)
        if not s:
            raise Refused("empty value")
        if len(s) > MAX_VALUE_LEN:
            raise Refused("value too long")
        if len(s) > 1 and s.startswith("%") and s.endswith("%"):
            raise Refused("placeholder value")
        if op == "regex_cs":
            why = wp_kitsig.regex_problem(s)
            if why:
                raise Refused(why)
        leaves.append({"field": FIELD_MAP[field], "op": op, "value": s})
    return _group("all" if every else "any", leaves)


def _selection(node):
    if isinstance(node, dict):
        if not node:
            raise Refused("empty selection")
        return _group("all", [_field_term(k, v) for k, v in node.items()])
    if isinstance(node, list):
        if not node:
            raise Refused("empty selection")
        if not all(isinstance(m, dict) for m in node):
            raise Refused("keyword selection (bare values) unsupported")
        return _group("any", [_selection(m) for m in node])
    raise Refused(f"unsupported selection type: {type(node).__name__}")


def _matches_any(tags, patterns):
    return any(fnmatch.fnmatchcase(t, p) for t in tags for p in patterns)


def prevalence_for(tags, stem=None) -> str:
    """commodity when the rule id (file stem) matches commodity_rule_ids or any tag is a commodity
    pattern — commodity always wins; else limited when a tag names a specific kit; else
    commodity. Never private: an imported rule is public, so never one crew's alone."""
    tags = [str(t) for t in tags or []]
    if stem is not None and any(fnmatch.fnmatchcase(str(stem), p) for p in COMMODITY_RULE_IDS):
        return "commodity"
    if _matches_any(tags, COMMODITY_TAGS):
        return "commodity"
    return "limited" if _matches_any(tags, LIMITED_TAGS) else "commodity"


def kind_for(tags) -> str:
    tags = [str(t) for t in tags or []]
    return next((k for p, k in KIND_TAGS if _matches_any(tags, [p])), DEFAULT_KIND)


def convert_rule(doc, stem, filename=None):
    """(rule, "") for one parsed IOK document, or (None, reason). `stem` is the file name without
    extension; `filename` (default `<stem>.yml`) builds the GitHub source URL."""
    try:
        return _convert(doc, stem, filename), ""
    except Refused as exc:
        return None, str(exc)
    except RecursionError:
        return None, "rule too deeply nested"


def _convert(doc, stem, filename):
    if not isinstance(doc, dict):
        raise Refused("not a mapping")
    if not _STEM_RE.match(str(stem or "")):
        raise Refused("unsafe file name")
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        raise Refused("missing title")
    det = doc.get("detection")
    if not isinstance(det, dict):
        raise Refused("missing detection")
    cond = det.get("condition")
    if isinstance(cond, list):
        raise Refused("condition list unsupported")
    if not isinstance(cond, str) or not cond.strip():
        raise Refused("missing condition")
    if "|" in cond:
        raise Refused("aggregation (|) unsupported")
    names = [k for k in det if k != "condition"]
    if not names:
        raise Refused("empty detection")
    selections = {}
    for name in names:
        if not isinstance(name, str) or not _IDENT_RE.match(name) or name.lower() in _KEYWORDS:
            raise Refused(f"invalid selection name: {name!r}")
        selections[name] = _selection(det[name])
    tree = _Parser(cond, selections).parse()
    if not wp_kitsig.has_positive(tree):
        raise Refused("no positive term (rule could match on absence alone)")
    if _leaves(tree) > MAX_LEAVES:
        raise Refused("too many terms")
    if not wp_kitsig.term_ok(tree):
        raise Refused("converted rule fails the matcher's term check")
    match = {"all": list(tree["all"])} if set(tree) == {"all"} else {"all": [tree]}
    if len(json.dumps(match, ensure_ascii=False).encode("utf-8")) > MAX_RULE_BYTES:
        raise Refused("rule too large")
    tags = [str(t) for t in (doc.get("tags") or []) if isinstance(t, (str, int))] \
        if isinstance(doc.get("tags"), list) else []
    refs = doc.get("references") if isinstance(doc.get("references"), list) else []
    source = next((r.strip() for r in refs if isinstance(r, str)
                   and r.strip().lower().startswith(("https://", "http://"))), None)
    return {
        "id": f"iok:{stem}",
        "name": title.strip()[:200],
        "kind": kind_for(tags),
        "match": match,
        "prevalence": prevalence_for(tags, stem),
        "source_url": source or RULE_URL_TEMPLATE.format(file=quote(filename or f"{stem}.yml")),
        "tags": tags,
        "_source": "iok",
    }


# ------------------------------------------------------------------------ tarball -> rules
def indicator_member(name) -> str:
    """The file name when tar member `name` is a direct child of `<top>/indicators/` with a YAML
    extension and no unsafe component; else ''."""
    name = str(name or "")
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return ""
    parts = name.split("/")
    if ".." in parts or len(parts) != 3 or parts[1] != "indicators" or not parts[0]:
        return ""
    return parts[2] if os.path.splitext(parts[2])[1].lower() in (".yml", ".yaml") else ""


class UnpackLimit(Exception):
    """The archive inflated past max_unpacked_bytes (a decompression bomb, or not IOK)."""


class _Bounded(io.RawIOBase):
    """A read-only stream that raises UnpackLimit once it has produced more than `budget` bytes —
    so neither a gzip bomb nor a giant pax/GNU long-name header is ever held in memory."""

    def __init__(self, raw, budget):
        super().__init__()
        self._raw, self._left = raw, budget

    def readable(self):
        return True

    def read(self, n=-1):
        want = self._left + 1 if n is None or n < 0 else min(n, self._left + 1)
        data = self._raw.read(want)
        self._left -= len(data)
        if self._left < 0:
            raise UnpackLimit(f"archive inflates past max_unpacked_bytes ({MAX_UNPACKED_BYTES})")
        return data


def convert_tarball(data, load_yaml) -> dict:
    """Read the IOK repository tarball IN MEMORY, as a stream (nothing is extracted to disk; the
    inflated bytes are capped at max_unpacked_bytes, the entries at max_members) and convert every
    `indicators/*.yml`. `load_yaml(text)` parses one file (yaml.safe_load). Raises UnpackLimit on a
    bomb. Returns {rules, skipped: [{file, reason}], counts: {files, imported, skipped,
    prevalence}, commit}."""
    rules, skipped, seen, files = [], [], set(), 0
    commit = None
    src = io.BytesIO(data)
    if data[:2] == b"\x1f\x8b":
        src = gzip.GzipFile(fileobj=src, mode="rb")
    with tarfile.open(fileobj=_Bounded(src, MAX_UNPACKED_BYTES), mode="r|") as tf:
        for n, member in enumerate(tf):
            if commit is None:
                commit = (tf.pax_headers or {}).get("comment")
            if n >= MAX_MEMBERS:
                skipped.append({"file": "*", "reason": "max_members reached"})
                break
            fname = indicator_member(member.name)
            if not fname or not member.isfile():
                continue
            files += 1
            stem = os.path.splitext(fname)[0]
            if member.size > MAX_RULE_BYTES:
                skipped.append({"file": fname, "reason": "file too large"})
                continue
            try:
                fh = tf.extractfile(member)
                raw = fh.read(MAX_RULE_BYTES + 1) if fh else b""
                doc = load_yaml(raw.decode("utf-8"))
            except UnpackLimit:
                raise
            except Exception:  # noqa: BLE001 — any parse failure skips this file only
                skipped.append({"file": fname, "reason": "yaml parse error"})
                continue
            rule, reason = convert_rule(doc, stem, filename=fname)
            if rule is None:
                skipped.append({"file": fname, "reason": reason})
            elif rule["id"] in seen:
                skipped.append({"file": fname, "reason": "duplicate rule id"})
            elif len(rules) >= MAX_RULES:
                skipped.append({"file": fname, "reason": "max_rules reached"})
            else:
                seen.add(rule["id"])
                rules.append(rule)
    rules.sort(key=lambda r: r["id"])
    skipped.sort(key=lambda s: (s["file"], s["reason"]))
    prev = {p: sum(1 for r in rules if r["prevalence"] == p) for p in ("limited", "commodity")}
    return {"rules": rules, "skipped": skipped, "commit": commit,
            "counts": {"files": files, "imported": len(rules),
                       "skipped": sum(1 for s in skipped if s["file"] != "*"),
                       "prevalence": prev}}
