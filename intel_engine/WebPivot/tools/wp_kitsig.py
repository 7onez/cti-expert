#!/usr/bin/env python3
"""wp_kitsig — put a NAME on a page's kit, from declarative rules.

WebPivot already measures a kit: the DOM-skeleton hash, the favicon hash, the harvest form's field
names, the asset paths, the post-redirect path template. What it could not do was say WHICH kit
those artifacts belong to. This module evaluates the rules in `references/kit_signatures.json`
against the artifacts a pivot_extract result already holds and returns the rules that hit:

    match(pivot, js_texts=None, html=None) -> [{rule_id, name, kind, prevalence, matched, source}]

ATTRIBUTION RAIL (SKILL.md RULE 5). A named kit is LINEAGE, not ownership: kits are sold, shared
and cloned, so a match is written to the KB as a kit_link-rung FACT only — never an edge, a
cluster member or an operator lead. A `commodity` match (a mass-market or stock kit) is recorded
as noise context and never offered as a pivot; `pivots()` drops it.

Rule order: the tracked rules first, then the rules IMPORTED from the public phish.report IOK set
into the git-ignored cache (`scripts/kit_rules_import.py update`; source `iok`, never `private`),
then the analyst's LOCAL kit signatures from the existing reference ledger (`tools/kb/reference.py`,
verdict `signal`, tag `kit`). Case-derived signatures live only there — in the git-ignored KB —
never in the tracked rule file (CLAUDE.md RULE 1); imported rules live only in the cache.

A term is a leaf {field, op, value} or a group {"all": [...]}, {"any": [...], "min": n},
{"not": term}. A rule with any malformed term never matches, and a hit must rest on at least one
positive leaf: absence alone never names a kit.

Stdlib only; never raises: a malformed rule or regex is skipped, not fatal.

CLI:
  python3 wp_kitsig.py raw/<host>.json [--js captured.js ...] [--html page.html] [--kb knowledge]
"""
import argparse
import json
import os
import re
import sys
import warnings
from urllib.parse import urljoin, urlparse

try:                                    # Python's own regex parser: inspect a pattern's structure
    import re._parser as _sre_parse      # noqa: WPS433 — 3.11+
    import re._constants as _sre_c       # noqa: WPS433
except ImportError:                      # pragma: no cover — 3.10
    import sre_parse as _sre_parse       # noqa: WPS433
    import sre_constants as _sre_c       # noqa: WPS433
try:                                    # optional linear-time engine (google-re2); never required
    import re2 as _RE2                   # noqa: WPS433
except Exception:  # noqa: BLE001
    _RE2 = None

from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

_ENGINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# DATA: references/kit_signatures.json -> rules + matcher bounds. The conservative minimum is NO
# rule (a page is never named after a kit unless the data file says so) and the SMALLER bounds.
_KITSIG_FALLBACK = {
    "rules": [],
    "matcher": {"regex_max_pattern": 256, "regex_max_text": 65536,
                "regex_max_text_wildcard": 16384, "max_broad_unbounded_repeats": 0,
                "max_repeat_count": 100, "max_doc_bytes": 1048576,
                "imported_cache_path": "cache/kit_rules/iok.json"},
}
_KITSIG_REF = load_ref(ref_path(__file__, "kit_signatures.json"), _KITSIG_FALLBACK)
RULES = [r for r in (_KITSIG_REF.get("rules") or []) if isinstance(r, dict)]
MATCHER = _KITSIG_REF.get("matcher") if isinstance(_KITSIG_REF.get("matcher"), dict) else {}


def _bound(key) -> int:
    fb = _KITSIG_FALLBACK["matcher"][key]
    try:
        v = int(MATCHER.get(key, fb))
    except (TypeError, ValueError):
        return fb
    return v if v > 0 else fb


REGEX_MAX_PATTERN = _bound("regex_max_pattern")
REGEX_MAX_TEXT = _bound("regex_max_text")
REGEX_MAX_TEXT_WILDCARD = min(_bound("regex_max_text_wildcard"), REGEX_MAX_TEXT)
MAX_BROAD_REPEATS = _bound("max_broad_unbounded_repeats")
MAX_REPEAT_COUNT = _bound("max_repeat_count")
MAX_DOC_BYTES = _bound("max_doc_bytes")
CACHE_ENV = "CTI_KIT_RULES_CACHE"     # overrides matcher.imported_cache_path (tests, other homes)

FIELDS = ("path_template", "dom_skeleton_sha1", "favicon_mmh3", "title", "form_fields",
          "asset_tail", "html_comment", "js_marker",
          "html", "dom", "js", "css", "requests", "cookies", "headers", "hostname")
OPS = ("equals", "contains", "regex", "iequals", "startswith", "endswith",
       "contains_cs", "startswith_cs", "endswith_cs", "regex_cs")
PREVALENCE = ("commodity", "limited", "private")
_REGEX_OPS = ("regex", "regex_cs")
_MAX_DEPTH = 32

# reference-ledger entry type -> how its value is matched (a local, case-derived kit signature)
_LEDGER_FIELD = {
    "favicon": ("favicon_mmh3", "equals"),
    "dom_skeleton": ("dom_skeleton_sha1", "prefix"),     # the KB keeps a 16-hex prefix
    "path_kit": ("path_template", "contains"),
    "path_template": ("path_template", "equals"),
    "title": ("title", "equals"),
    "js_marker": ("js_marker", "contains"),
}

# page-document scanners for the html-derived fields (css, requests, inline js when none passed)
_STYLE_RE = re.compile(r"<style[^>]*>(.*?)</style>", re.I | re.S)
_SRC_ATTR_RE = re.compile(r"""\b(?:src|data-src|poster)\s*=\s*["']?([^"'\s>]+)""", re.I)
_LINK_HREF_RE = re.compile(r"""<link\b[^>]*?\bhref\s*=\s*["']?([^"'\s>]+)""", re.I)
_CSS_URL_RE = re.compile(r"""url\(\s*["']?([^"')\s]+)""", re.I)

_RX_CACHE = {}
_RX_PROBLEM = {}
_IMPORTED = {}            # cache path -> ((mtime_ns, size), [rule])
_WARNED = []              # one stderr line per process for an unreadable / partly bad cache

# RE2-only syntax Python's `re` rejects or silently reads differently (RE2 syntax reference)
_RE2_ONLY_ESCAPES = ("Q", "E", "p", "P", "z", "C")
_RE2_FLAGS = set("imsU")
_REPEATS = tuple(c for c in (getattr(_sre_c, "MAX_REPEAT", None), getattr(_sre_c, "MIN_REPEAT", None))
                 if c is not None)
_RE2_REJECTS = tuple(c for c in (getattr(_sre_c, "POSSESSIVE_REPEAT", None),
                                 getattr(_sre_c, "ATOMIC_GROUP", None)) if c is not None)


def _syntax_problem(p):
    """A reason when pattern `p` uses syntax only RE2 understands (Python would reject it or read it
    as something else) or syntax RE2 rejects (so the rule never ran upstream); else None."""
    i, n, in_class, class_start = 0, len(p), False, 0
    while i < n:
        c = p[i]
        if c == "\\":
            nxt = p[i + 1:i + 2]
            if nxt in _RE2_ONLY_ESCAPES or (nxt == "x" and p[i + 2:i + 3] == "{"):
                return "regex uses Go/RE2-only syntax"
            if nxt.isdigit() and nxt != "0" and not in_class:
                return "regex uses a backreference"
            if nxt == "Z":
                return "regex uses syntax RE2 rejects"
            i += 2
            continue
        if in_class:
            if c == "[" and p[i + 1:i + 2] == ":":
                return "regex uses Go/RE2-only syntax"          # POSIX class [[:digit:]]
            if c == "]":
                in_class = False
        elif c == "[":
            in_class, j = True, i + 1
            if p[j:j + 1] == "^":
                j += 1
            class_start = j + 1 if p[j:j + 1] == "]" else j      # a leading ] is literal
            i = class_start
            continue
        elif c == "(" and p[i + 1:i + 2] == "?":
            rest = p[i + 2:]
            if rest.startswith(("=", "!", "<=", "<!")):
                return "regex uses lookaround (RE2 rejects)"
            if rest.startswith("P="):
                return "regex uses a backreference"
            if rest.startswith((">", "#")) or rest[:1] in ("a", "L", "u", "x"):
                return "regex uses syntax RE2 rejects"
            m = re.match(r"([A-Za-z-]+)([):])", rest)
            if m and set(m.group(1).replace("-", "")) <= _RE2_FLAGS:
                if "U" in m.group(1) or (m.group(2) == ")" and i != 0):
                    return "regex uses Go/RE2-only syntax"   # ungreedy / mid-pattern global flags
            elif rest.startswith("<") or (m and not rest.startswith("P<")):
                return "regex uses Go/RE2-only syntax"
        i += 1
    return None


def _is_category_not(av):
    return str(av).startswith("CATEGORY_NOT")


def _broad(body):
    """Is a repeat body a wildcard (`.`, a negated class, \\S / \\W / \\D, [\\s\\S] …)?"""
    items = list(body)
    while len(items) == 1 and items[0][0] is _sre_c.SUBPATTERN:
        items = list(items[0][1][-1])
    if len(items) != 1:
        return False
    op, av = items[0]
    if op is _sre_c.ANY or op is _sre_c.NOT_LITERAL:
        return True
    if op is _sre_c.CATEGORY:
        return _is_category_not(av)
    if op is _sre_c.IN:
        return any(o is _sre_c.NEGATE or (o is _sre_c.CATEGORY and _is_category_not(a)) for o, a in av)
    return False


def _shape_problem(sub, in_repeat, broad):
    """A reason when the parsed pattern can backtrack super-linearly: a quantifier inside a
    quantified group, a backreference or lookaround, or an RE2-rejected construct."""
    for op, av in sub:
        if op in _RE2_REJECTS:
            return "regex uses syntax RE2 rejects"
        if op in _REPEATS:
            lo, hi, body = av
            if lo > MAX_REPEAT_COUNT or (hi != _sre_c.MAXREPEAT and hi > MAX_REPEAT_COUNT):
                return "regex repeat count too large"
            if in_repeat:
                return "regex has nested quantifiers"
            if hi == _sre_c.MAXREPEAT and _broad(body):
                broad[0] += 1
            why = _shape_problem(body, hi > 1, broad)
        elif op is _sre_c.SUBPATTERN:
            why = _shape_problem(av[-1], in_repeat, broad)
        elif op is _sre_c.BRANCH:
            why = next((w for w in (_shape_problem(b, in_repeat, broad) for b in av[1]) if w), None)
        elif op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
            why = "regex uses lookaround (RE2 rejects)"
        elif op in (_sre_c.GROUPREF, getattr(_sre_c, "GROUPREF_EXISTS", None)):
            why = "regex uses a backreference"
        else:
            why = None
        if why:
            return why
    return None


def regex_problem(pattern):
    """Why `pattern` must not run, or None. Imported patterns come from the internet and are
    applied to attacker-controlled pages: with the optional RE2 engine any pattern RE2 compiles is
    safe (linear time); on Python's backtracking `re` a pattern is refused for RE2-only syntax,
    nested quantifiers, backreferences/lookaround, an oversized repeat count or more than
    matcher.max_broad_unbounded_repeats unbounded wildcard repeats. The import and the matcher
    run this same check, so a hand-edited cache cannot slip a pattern past it."""
    pattern = str(pattern)
    if pattern in _RX_PROBLEM:
        return _RX_PROBLEM[pattern]
    why = None
    if len(pattern) > REGEX_MAX_PATTERN:
        why = "regex too long"
    elif _RE2 is not None:
        try:
            _RE2.compile(pattern)
        except Exception:  # noqa: BLE001
            why = "regex does not compile"
    else:
        why = _syntax_problem(pattern)
        if not why:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    tree = _sre_parse.parse(pattern, 0)
                broad = [0]
                why = _shape_problem(tree, False, broad)
                if not why and broad[0] > MAX_BROAD_REPEATS:
                    why = f"regex has more than {MAX_BROAD_REPEATS} unbounded wildcard repeat(s)"
            except Exception:  # noqa: BLE001 — re.error, RecursionError, OverflowError …
                why = "regex does not compile"
    _RX_PROBLEM[pattern] = why
    return why


def _rx(pattern, cs=False):
    """(compiled, text cap) for a pattern that passes regex_problem, else None. A pattern holding
    an unbounded wildcard repeat sees at most regex_max_text_wildcard characters of a value: on a
    backtracking engine one `.*` still costs quadratic time in the text it scans."""
    key = (pattern, cs)
    if key not in _RX_CACHE:
        _RX_CACHE[key] = None
        if regex_problem(pattern) is None:
            try:
                if _RE2 is not None:
                    _RX_CACHE[key] = (_RE2.compile(pattern if cs else "(?i)" + pattern), REGEX_MAX_TEXT)
                else:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        # regex_cs is IOK's Go RE2: ASCII \d \w \s \b; regex keeps the tracked meaning
                        rx = re.compile(pattern, re.ASCII if cs else re.I)
                        broad = [0]
                        _shape_problem(_sre_parse.parse(pattern, 0), False, broad)
                    _RX_CACHE[key] = (rx, REGEX_MAX_TEXT_WILDCARD if broad[0] else REGEX_MAX_TEXT)
            except Exception:  # noqa: BLE001
                _RX_CACHE[key] = None
    return _RX_CACHE[key]


def _tail(url):
    try:
        path = urlparse(str(url)).path or str(url)
    except ValueError:
        path = str(url)
    return path.rstrip("/").rsplit("/", 1)[-1]


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _resolve(path):
    """A stored path as written (absolute, or relative to cwd), else relative to $INTEL_HOME."""
    if not path:
        return None
    path = str(path)
    if os.path.isabs(path) or os.path.exists(path):
        return path
    return os.path.join(os.environ.get("INTEL_HOME") or _ENGINE, path)


def _capture_files(capdir, role):
    """[(url, text)] stored in the pivot's capture bundle for `role` — read from disk, no request."""
    capdir = _resolve(capdir)
    if not capdir or not os.path.isdir(capdir):
        return []
    try:
        import wp_capture  # noqa: WPS433 — lazy: only a pivot that has a capture bundle needs it
        return wp_capture.stored_files(capdir, role, max_bytes=MAX_DOC_BYTES)
    except Exception:  # noqa: BLE001 — an unreadable bundle is no evidence, never a failure
        return []


def _page_document(pivot, html, capdir):
    """The one page document the engine holds: the caller's HTML, else the capture bundle's stored
    DOM, else the --save-dom file the pivot names. '' when none is stored."""
    if html:
        return str(html)[:MAX_DOC_BYTES]
    docs = _capture_files(capdir, "dom")
    if docs:
        return docs[0][1]
    path = _resolve(((pivot or {}).get("meta") or {}).get("raw_dom_file"))
    if path:
        try:
            with open(path, "rb") as fh:
                return fh.read(MAX_DOC_BYTES).decode("utf-8", "replace")
        except OSError:
            pass
    return ""


def _canon_header(name):
    """Go's CanonicalMIMEHeaderKey shape (x-powered-by -> X-Powered-By): IOK rules read headers so."""
    return "-".join(p[:1].upper() + p[1:].lower() for p in str(name).split("-"))


def _cookies(resp_headers, cookie_names):
    out = []
    raw = next((v for k, v in resp_headers.items() if str(k).lower() == "set-cookie"), None)
    if raw:
        for part in re.split(r",\s*(?=[^ ;=,]+=)", str(raw)):     # an Expires date never splits
            nv = part.split(";", 1)[0].strip()
            if "=" in nv and nv.split("=", 1)[0].strip():
                out.append(nv)
    named = {c.split("=", 1)[0] for c in out}
    out += [f"{n}=" for n in (cookie_names or []) if n and str(n) not in named]
    return _uniq(out)


def _requests(art, meta, doc, css_texts):
    base = meta.get("final_url") or ""
    raw = list(art.get("script_srcs") or []) + list(art.get("stylesheets") or [])
    if doc:
        raw += _SRC_ATTR_RE.findall(doc) + _LINK_HREF_RE.findall(doc)
    for css in css_texts:
        raw += _CSS_URL_RE.findall(css)
    out = []
    for u in raw:
        u = str(u).strip()
        if not u or u.lower().startswith(("data:", "javascript:", "about:", "blob:", "#")):
            continue
        try:
            out.append(urljoin(base, u) if base else u)
        except ValueError:
            out.append(u)
    return _uniq(out)


def field_values(pivot, js_texts=None, html=None) -> dict:
    """{field: [str, ...]} — where each match field lives in a pivot_extract result (and the
    evidence it stores). The field → source table is in references/kit_signatures.json."""
    meta = (pivot or {}).get("meta") or {}
    art = (pivot or {}).get("artifacts") or {}
    fav = art.get("favicon") or {}
    forms = [f for f in (art.get("forms") or []) if isinstance(f, dict)]
    capdir = (meta.get("capture") or {}).get("dir") if isinstance(meta.get("capture"), dict) else None
    doc = _page_document(pivot, html, capdir)
    if js_texts is None:
        inline = []
        if doc:
            try:
                from wp_extract import INLINE_SCRIPT_RE  # noqa: WPS433 — the one inline-script scanner
                inline = [s for s in INLINE_SCRIPT_RE.findall(doc) if s.strip()]
            except Exception:  # noqa: BLE001
                inline = []
        js = inline + [t for _, t in _capture_files(capdir, "js")]
    else:
        js = [str(t) for t in js_texts if t]
    css = ([s for s in _STYLE_RE.findall(doc) if s.strip()] if doc else []) \
        + [t for _, t in _capture_files(capdir, "css") if t]
    http = art.get("http") if isinstance(art.get("http"), dict) else {}
    resp = http.get("response_headers") if isinstance(http.get("response_headers"), dict) else {}
    if not resp and isinstance(art.get("server_headers"), dict):
        resp = art["server_headers"]
    try:
        host = (urlparse(str(meta.get("final_url") or "")).hostname or meta.get("host") or "").lower()
    except ValueError:
        host = str(meta.get("host") or "").lower()
    return {
        "path_template": [meta["path_template"]] if meta.get("path_template") else [],
        "dom_skeleton_sha1": [art["dom_skeleton_sha1"]] if art.get("dom_skeleton_sha1") else [],
        "favicon_mmh3": ([str(fav["shodan_mmh3"])] if isinstance(fav, dict)
                         and fav.get("shodan_mmh3") is not None else []),
        "title": [art["title"]] if art.get("title") else [],
        "form_fields": [str(i) for f in forms for i in (f.get("inputs") or []) if i],
        "asset_tail": [t for t in (_tail(u) for u in list(art.get("script_srcs") or [])
                                   + list(art.get("stylesheets") or [])) if t],
        "html_comment": [str(c) for c in (art.get("html_comments") or []) if c],
        "js_marker": [t for t in js if t],
        "js": [t for t in js if t],
        "html": [doc] if doc else [],
        "dom": [doc] if doc else [],
        "css": css,
        "requests": _requests(art, meta, doc, css),
        "cookies": _cookies(resp, art.get("cookie_names")),
        "headers": [f"{_canon_header(k)}: {v}" for k, v in resp.items()
                    if k and not str(k).startswith("_")],
        "hostname": [host] if host else [],
    }


class _Values:
    """Field values plus their lower-cased form, computed once per page and field."""

    def __init__(self, values):
        self.v = values
        self._low = {}

    def get(self, field):
        return self.v.get(field) or []

    def low(self, field):
        if field not in self._low:
            self._low[field] = [x.lower() for x in self.get(field)]
        return self._low[field]


def _hit(term, ctx) -> bool:
    field, op, want = term.get("field"), term.get("op"), term.get("value")
    if want is None or op not in OPS + ("prefix",):
        return False
    want = str(want)
    values = ctx.get(field)
    if not values:
        return False
    if op == "equals":
        return any(v == want for v in values)
    if op == "prefix":
        return any(v.startswith(want) for v in values)
    if op in _REGEX_OPS:
        got = _rx(want, cs=(op == "regex_cs"))
        if not got:
            return False
        rx, cap = got
        return any(rx.search(v[:cap]) for v in values)
    if not want:
        return False
    if op.endswith("_cs"):
        if op == "contains_cs":
            return any(want in v for v in values)
        if op == "startswith_cs":
            return any(v.startswith(want) for v in values)
        return any(v.endswith(want) for v in values)
    low, lows = want.lower(), ctx.low(field)
    if op == "iequals":
        return any(v == low for v in lows)
    if op == "contains":
        return any(low in v for v in lows)
    if op == "startswith":
        return any(v.startswith(low) for v in lows)
    return any(v.endswith(low) for v in lows)


def _label(term) -> str:
    return f"{term.get('field')} {term.get('op')} {str(term.get('value'))[:80]!r}"


def term_ok(term, depth=0) -> bool:
    """A well-formed term: a leaf with a known field and op (a regex that compiles within the
    bound), or an all/any/not group of well-formed terms. Checked over the WHOLE tree, so a
    broken leaf under `not` can never make a rule match vacuously."""
    if not isinstance(term, dict) or depth > _MAX_DEPTH:
        return False
    if "not" in term:
        return set(term) == {"not"} and term_ok(term["not"], depth + 1)
    if "all" in term or "any" in term:
        key = "all" if "all" in term else "any"
        kids = term[key]
        if set(term) - {key, "min"} or not isinstance(kids, list) or not kids:
            return False
        if "min" in term:
            if key != "any" or isinstance(term["min"], bool) or not isinstance(term["min"], int) \
                    or not 1 <= term["min"] <= len(kids):
                return False
        return all(term_ok(k, depth + 1) for k in kids)
    if term.get("field") not in FIELDS or term.get("op") not in OPS + ("prefix",):
        return False
    value = term.get("value")
    if value is None or isinstance(value, (dict, list, bool)):
        return False
    if term["op"] in _REGEX_OPS and _rx(str(value), cs=(term["op"] == "regex_cs")) is None:
        return False
    return True


def has_positive(term) -> bool:
    """Could `term` be satisfied only with at least one positive leaf hitting? A leaf: yes; `not`:
    no; `all`: when any child can; `any`: only when every child can (conservative)."""
    if not isinstance(term, dict):
        return False
    if "not" in term:
        return False
    if "all" in term:
        return any(has_positive(k) for k in term["all"] or [])
    if "any" in term:
        kids = term["any"] or []
        return bool(kids) and all(has_positive(k) for k in kids)
    return True


def _eval(term, ctx, matched) -> bool:
    """True when `term` holds; appends the labels of the positive leaves that hit to `matched`."""
    if "not" in term:
        return not _eval(term["not"], ctx, [])
    if "all" in term:
        got = []
        for k in term["all"]:
            if not _eval(k, ctx, got):
                return False
        matched += got
        return True
    if "any" in term:
        need, hits, got = int(term.get("min", 1)), 0, []
        for k in term["any"]:
            sub = []
            if _eval(k, ctx, sub):
                hits += 1
                got += sub
        if hits < need:
            return False
        matched += got
        return True
    if _hit(term, ctx):
        matched.append(_label(term))
        return True
    return False


def _evaluate(rule, ctx):
    """The matched positive-leaf labels when `rule` hits, else None."""
    m = rule.get("match") or {}
    all_terms = [t for t in (m.get("all") or []) if isinstance(t, dict)]
    any_terms = [t for t in (m.get("any") or []) if isinstance(t, dict)]
    if not all_terms and not any_terms:
        return None                                    # a rule with no terms never matches
    if not all(term_ok(t) for t in all_terms + any_terms):
        return None                                    # a typo'd field must not match vacuously
    matched = []
    for t in all_terms:
        if not _eval(t, ctx, matched):
            return None
    if any_terms:
        try:
            need = int(rule.get("min_any", 1))
        except (TypeError, ValueError):
            need = 1
        hits, got = 0, []
        for t in any_terms:
            sub = []
            if _eval(t, ctx, sub):
                hits += 1
                got += sub
        if hits < max(1, need):
            return None
        matched += got
    matched = _uniq(matched)
    return matched or None                             # absence alone never names a kit


def imported_cache_path() -> str:
    """Where the IOK import lives: $CTI_KIT_RULES_CACHE, else matcher.imported_cache_path under
    $INTEL_HOME (default intel_engine/cache/kit_rules/iok.json)."""
    env = os.environ.get(CACHE_ENV)
    if env:
        return env
    rel = str(MATCHER.get("imported_cache_path")
              or _KITSIG_FALLBACK["matcher"]["imported_cache_path"])
    return rel if os.path.isabs(rel) else os.path.join(os.environ.get("INTEL_HOME") or _ENGINE, rel)


def _imported_rule(r):
    """An imported rule held to the rails, or None: `iok:` id, well-formed match (groups are
    lists of dicts), a positive leaf, prevalence commodity|limited (never private), source iok.
    Never raises: a malformed row is dropped, it never stops the other rules."""
    try:
        if not isinstance(r, dict) or not str(r.get("id") or "").startswith("iok:"):
            return None
        m = r.get("match")
        if not isinstance(m, dict) or not all(isinstance(m.get(g, []), list) for g in ("all", "any")):
            return None
        all_t, any_t = m.get("all") or [], m.get("any") or []
        terms = all_t + any_t
        if not terms or not all(isinstance(t, dict) and term_ok(t) for t in terms):
            return None
        if not (any(has_positive(t) for t in all_t) or (any_t and all(has_positive(t) for t in any_t))):
            return None
        out = dict(r)
        out["prevalence"] = "limited" if r.get("prevalence") == "limited" else "commodity"
        out["_source"] = "iok"
        return out
    except Exception:  # noqa: BLE001 — TypeError, RecursionError … : drop the row
        return None


def _warn_once(msg):
    if not _WARNED:
        _WARNED.append(msg)
        print(f"[kitsig] {msg}", file=sys.stderr)


def imported_rules(path=None) -> list:
    """The IOK rules in the git-ignored cache (`scripts/kit_rules_import.py update`), validated
    once per file version and remembered for the process. Missing cache: none, silently (the
    default state). A cache that cannot be parsed: none; malformed rows: dropped, the rest kept —
    either way one stderr line per process, and never an exception into match()."""
    path = path or imported_cache_path()
    try:
        st = os.stat(path)
    except OSError:
        return []
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _IMPORTED.get(path)
    if hit and hit[0] == stamp:
        return hit[1]
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        rows = doc.get("rules") if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            raise ValueError("no `rules` list")
    except Exception as exc:  # noqa: BLE001 — OSError, ValueError, RecursionError, MemoryError …
        _warn_once(f"imported kit-rule cache {path} unreadable ({type(exc).__name__}); using no "
                   f"imported rules — re-run scripts/kit_rules_import.py update")
        _IMPORTED[path] = (stamp, [])
        return []
    rules = [r for r in (_imported_rule(x) for x in rows) if r]
    if len(rules) < len(rows):
        _warn_once(f"imported kit-rule cache {path}: {len(rows) - len(rules)} malformed rule(s) "
                   f"dropped, {len(rules)} kept — re-run scripts/kit_rules_import.py update")
    _IMPORTED[path] = (stamp, rules)
    return rules


def local_rules(kb_dir=None) -> list:
    """Case-derived kit signatures from the reference ledger (verdict `signal`, tag `kit`), as
    rules. Read through tools/kb/reference.py — the one ledger; never a second store."""
    kb_dir = kb_dir or os.path.join(os.environ.get("INTEL_HOME") or _ENGINE, "knowledge")
    try:
        kb_tools = os.path.join(_ENGINE, "tools", "kb")
        if kb_tools not in sys.path:
            sys.path.append(kb_tools)
        import reference  # noqa: WPS433 — lazy: the ledger lives beside the KB
        entries = reference.load(kb_dir)
    except Exception:  # noqa: BLE001 — no ledger, no local rules
        return []
    rules = []
    for e in entries:
        tags = [str(t).lower() for t in (e.get("tags") or [])]
        if e.get("verdict") != "signal" or "kit" not in tags:
            continue
        typ, value = str(e.get("type") or ""), str(e.get("value") or "")
        spec = _LEDGER_FIELD.get(typ)
        if not spec or not value:
            continue
        raw = value.split(":", 1)[1] if value.startswith(typ + ":") else value
        prev = next((p for p in PREVALENCE if p in tags), "limited")
        rules.append({"id": f"local:{typ}:{raw}", "name": e.get("label") or raw, "kind": "kit",
                      "match": {"all": [{"field": spec[0], "op": spec[1], "value": raw}]},
                      "prevalence": prev, "_source": "reference_ledger"})
    return rules


def match(pivot, js_texts=None, rules=None, kb_dir=None, local=True, imported=None,
          html=None) -> list:
    """Every rule `pivot` satisfies: [{rule_id, name, kind, prevalence, matched, source}].

    `js_texts` are inline-script bodies and captured JavaScript files (the js / js_marker fields);
    `html` is the page document when the caller holds it (else the stored capture/DOM file).
    `rules` replaces the tracked library (tests). `imported`: None = the IOK cache when `rules`
    is None, else none; False = none; a path = that cache file; a list = those rules (held to the
    same rails). `local=False` skips the reference ledger."""
    ctx = _Values(field_values(pivot, js_texts, html))
    if imported is None:
        imp = imported_rules() if rules is None else []
    elif imported is False:
        imp = []
    elif isinstance(imported, str):
        imp = imported_rules(imported)
    else:
        imp = [r for r in (_imported_rule(x) for x in imported) if r]
    out, seen = [], set()
    pool = list(RULES if rules is None else rules) + imp + (local_rules(kb_dir) if local else [])
    for rule in pool:
        rid = str(rule.get("id") or "")
        if not rid or rid in seen:
            continue
        try:
            matched = _evaluate(rule, ctx)
        except Exception:  # noqa: BLE001 — one malformed rule never blocks the rest
            matched = None
        if matched is None:
            continue
        seen.add(rid)
        prev = str(rule.get("prevalence") or "").lower()
        out.append({"rule_id": rid, "name": str(rule.get("name") or rid),
                    "kind": str(rule.get("kind") or "kit"),
                    "prevalence": prev if prev in PREVALENCE else "commodity",
                    "matched": matched,
                    "source": rule.get("_source") or "kit_signatures.json"})
    return out


def offer_pivot(m) -> bool:
    """A commodity match is noise context: never offered as a pivot."""
    return (m or {}).get("prevalence") in ("limited", "private")


def pivots(matches) -> list:
    """Pivot rows for the non-commodity matches (same KIT — never same operator)."""
    out = []
    for m in matches or []:
        if not offer_pivot(m):
            continue
        out.append({"kind": "kit_signature", "value": m["rule_id"], "confidence": "low",
                    "note": (f"Page matches the named kit '{m['name']}' ({m['prevalence']}). Same KIT, "
                             f"not same operator — kits are sold and cloned; corroborate with an "
                             f"owner-rung artifact before any link."),
                    "queries": [{"service": "kit rule", "query": "; ".join(m.get("matched") or [])}]})
    return out


def cld_family_matches(phaas_block) -> list:
    """ChongLuaDao Shield PhaaS rows that carry a `family`, in the kit-match shape. PhaaS is a
    service sold to many crews, so a family is commodity-prevalence: context, never a pivot."""
    if not isinstance(phaas_block, dict) or phaas_block.get("error") or phaas_block.get("skipped"):
        return []
    rows = next((phaas_block[k] for k in ("items", "data", "results")
                 if isinstance(phaas_block.get(k), list)), [])
    out, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        fam = str(row.get("family") or "").strip()
        if not fam or fam.lower() in seen:
            continue
        seen.add(fam.lower())
        tag = str(row.get("tag") or "").strip()
        out.append({"rule_id": f"cld:{fam.lower()}", "name": fam, "kind": "phishing",
                    "prevalence": "commodity",
                    "matched": [f"ChongLuaDao PhaaS family={fam}" + (f" tag={tag}" if tag else "")],
                    "source": "cld"})
    return out


def _main(argv=None):
    ap = argparse.ArgumentParser(description="match a pivot_extract result against kit signatures")
    ap.add_argument("raw", help="a pivot_extract JSON result")
    ap.add_argument("--js", action="append", default=[], help="a JavaScript file to scan (repeatable)")
    ap.add_argument("--html", default=None, help="the page document (default: the stored capture/DOM)")
    ap.add_argument("--kb", default=None, help="KB directory holding reference.jsonl")
    a = ap.parse_args(argv)
    with open(a.raw, encoding="utf-8") as fh:
        pivot = json.load(fh)
    texts = None
    if a.js:
        texts = []
        for p in a.js:
            with open(p, encoding="utf-8", errors="replace") as fh:
                texts.append(fh.read())
    html = None
    if a.html:
        with open(a.html, encoding="utf-8", errors="replace") as fh:
            html = fh.read()
    print(json.dumps(match(pivot, texts, kb_dir=a.kb, html=html), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()
