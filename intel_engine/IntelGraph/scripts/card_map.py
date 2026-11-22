#!/usr/bin/env python3
"""
card_map.py — the relationship CARD MAP: one subject (dark hub card) at the top of a vertical
trunk, rounded panels of cards to either side of it, and an Admiralty badge on every card.

It is the figure for "who is this subject connected to" (the people, organisations, accounts and
places linked to one subject) and "which kinds of actor are reported against this organisation".
Unlike the network graph it carries no inferred layout: the analyst decides the panels, so the
figure reads like a hand-composed exhibit rather than a hairball.

INPUT — the C2 spec (JSON):

    {"title": str, "subtitle": "Public sources, compiled to YYYY-MM-DD",
     "hub": {"name", "lines": [str], "cc": "XX", "icon" | "initials" | "logo"},
     "trunk_labels": [{"text", "grade"}],
     "panels": [{"title", "side": "left|right|full|center",
                 "cards": [{"name", "lines": [str], "cc": "XX", "icon", "initials",
                            "logo": local path, "relation": str, "grade": "A1".."F6",
                            "confirmed": bool (default true), "dates": str,
                            "indent": bool (default false)}]}],
     "legend": true}

Extensions beyond C2 (all optional, backward compatible): panel side "center" stacks its cards
on the trunk (an intermediate node, e.g. the subject's current employer); card "indent" hangs the
card under the card above it with an elbow connector (a relation of a relation — a sibling's
bakery under the sibling).

LAYOUT. Panels are laid out in reading order: consecutive left / center / right panels share a
row until a side repeats; a full panel takes a row of its own and flows its cards in a grid. Each
side panel is joined to the trunk by a branch at its title line; each card by a short stub from
the panel's trunk-side edge (or an elbow for an indented card). A card with confirmed:false has a
DASHED border and a dashed connector, and the footer legend says what dashed means.

DETERMINISM. Stdlib only, no clock, no randomness, no font metrics: text width is estimated per
character (references/card_map.json `sizes.char_*`) and every number is rounded, so the same spec
always produces the same SVG bytes. All text is XML-escaped. render_svg never touches module
state: the per-render sizes (wide_scale applied or not) are passed down explicitly, so concurrent
renders in one process are safe.

LOGOS are never fetched. A logo path is embedded (base64) only when it resolves (symlinks
followed) inside the spec's directory or the case's `report/` directory (the nearest
`cases/<id>/report/` above the spec), is at most `logo.max_bytes`, and starts with a PNG, JPEG
or SVG signature. Anything else falls back to initials/icon with a WARNING on stderr.

RASTERISING reuses render_mermaid's one chain (rsvg-convert, then headless Chrome/Edge, then
cairosvg). With none available the SVG is still written and the CLI exits 1 naming what to
install.

    card_map.py spec.json -o out.svg [--png out.png] [--pdf out.pdf] [--mask]

--mask ALWAYS applies the local reduction, whatever the house mask does: every person card (icon
"person" or explicit initials, hub included) is reduced to its initials ("Alex Example" ->
"A. E."), every `logo` is dropped, and those person names are replaced by the same initials in
the title, trunk labels, panel titles and every card's lines / relation / dates. E-mail
addresses, phone numbers and birth dates are stripped from every string (scrub_pii below).
Organisation and place names stay. The house third-party mask (house_report.mask_third_parties)
is then applied on top when it is importable.

PII STRIPPING (scrub_pii; patterns in references/card_map.json `pii` / `pii_full_dates`):
  * e-mail addresses and phone numbers are replaced by `pii.replacement`. A phone candidate needs
    `phone_min_digits` digits (`phone_min_digits_intl` with a leading +), at most
    `phone_max_digits`; a candidate holding a full date, or (without +) two 19xx/20xx groups such
    as "2019 2026", is not a phone.
  * A FULL DATE has day, month and a 19xx/20xx year (1990-01-02, 02/01/1990, 2 January 1990,
    Jan 2, 1990). Month-year ("03/2024") and year ranges ("2019 to 2026") are never full dates.
  * A full date is a BIRTH DATE, and replaced, when a `pii.dob_cue` word (born, b., DOB, date of
    birth, birthday) immediately precedes it (optional punctuation and on/in) or
    follows it in brackets ("1990-01-02 (DOB)"), or when it sits on a PERSON card at all. Any
    other full date (an incorporation date on an organisation card) is kept.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from xml.sax.saxutils import escape as _xml_escape

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ig_refs import load_ref, ref_path  # noqa: E402

_FALLBACK = {
    "theme": {"font_family": "Helvetica, Arial, sans-serif", "background": "#ffffff",
              "ink": "#1f1d1a", "muted": "#6f6a61", "title": "#22333f", "panel_fill": "#f3f1ec",
              "panel_stroke": "#e2ddd3", "panel_title": "#3f3b35", "card_fill": "#ffffff",
              "card_stroke": "#d9d3c7", "trunk": "#8d867a", "hub_fill": "#22333f",
              "hub_stroke": "#22333f", "hub_ink": "#ffffff", "hub_muted": "#c9d3da",
              "avatar_fill": "#ebe7df", "avatar_ink": "#3b5566", "hub_avatar_fill": "#ffffff",
              "chip_fill": "#f3f1ec", "chip_stroke": "#d9d3c7", "chip_ink": "#3f3b35",
              "hub_chip_fill": "#2f4452", "hub_chip_stroke": "#5b707e", "dash": "5 4"},
    "badges": {"A": "#2e7d4f", "B": "#2f5f9e", "C": "#b0670f", "D": "#7a766e", "E": "#7a766e",
               "F": "#7a766e", "badge_ink": "#ffffff"},
    "sizes": {"width": 1200, "narrow_width": 760, "trunk_gap": 72, "margin": 28, "title_size": 22,
              "subtitle_size": 12,
              "panel_title_size": 13, "name_size": 14, "line_size": 12, "chip_size": 12,
              "legend_size": 12, "chip_pad": 12,
              "line_height": 1.32, "center_width": 260, "hub_width": 320, "panel_pad": 14,
              "panel_radius": 10, "card_pad": 10, "card_radius": 7, "card_gap": 10,
              "row_gap": 26, "avatar_radius": 17, "indent": 40, "chip_height": 20,
              "chip_gap": 6, "full_columns": 3, "trunk_width": 1.6, "char_regular": 0.55,
              "char_bold": 0.6, "char_wide": 1.0, "char_caps": 0.68, "png_scale": 2,
              "icon_scale": 0.95, "wide_scale": 1.65, "full_min_card_width": 300,
              "subtitle_max_share": 0.45},
    "legend": {"badge_sample": "A1",
               "badge_text": "Admiralty grade: source reliability A to F, information credibility 1 to 6",
               "dashed_text": "Unconfirmed claim"},
    "type_icons": {"default": "group"},
    "wide_scale_keys": ["title_size", "subtitle_size", "panel_title_size", "name_size", "line_size",
                        "chip_size", "chip_height", "chip_gap", "chip_pad", "legend_size",
                        "avatar_radius", "card_pad",
                        "panel_pad", "card_radius", "panel_radius", "card_gap", "row_gap", "indent",
                        "hub_width", "trunk_gap", "trunk_width", "margin", "full_min_card_width"],
    "logo": {"max_bytes": 524288},
    "pii": {"replacement": "(withheld)",
            "email": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+",
            "phone": r"(?<![\w+])\+?\(?\d{1,4}\)?(?:[ .\-]?\(?\d{1,4}\)?){2,6}(?!\w)",
            "phone_min_digits": 10, "phone_min_digits_intl": 8, "phone_max_digits": 15,
            "dob_cue": r"(?:born|b\.|d\.?\s?o\.?\s?b\.?|date\s+of\s+birth|birth\s*date|birthday)"},
    "pii_full_dates": [r"(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])",
                       r"(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19|20)\d{2}"],
}
REF = load_ref(ref_path(__file__, "card_map.json"), _FALLBACK)
T, B, S, LEG = REF["theme"], REF["badges"], REF["sizes"], REF["legend"]

# Built-in icons: stroke-only paths on a 24x24 grid (no fills, so they survive greyscale print).
ICONS = {
    "person": '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
    "group": ('<circle cx="9" cy="8" r="3.2"/><circle cx="16.5" cy="9" r="2.6"/>'
              '<path d="M3 20c0-3.6 2.7-6 6-6s6 2.4 6 6"/><path d="M15.5 14.2c3 .2 5.5 1.9 5.5 5.8"/>'),
    "organisation": ('<rect x="5" y="3" width="14" height="18" rx="1"/>'
                     '<path d="M9 7h2M13 7h2M9 11h2M13 11h2M9 15h2M13 15h2M11 21v-3h2v3"/>'),
    "building": '<path d="M3 9l9-5 9 5M5 10v9M9.5 10v9M14.5 10v9M19 10v9M3 20h18"/>',
    "location": ('<path d="M12 21s-6-6.2-6-11a6 6 0 0 1 12 0c0 4.8-6 11-6 11z"/>'
                 '<circle cx="12" cy="10" r="2.2"/>'),
    "globe": ('<circle cx="12" cy="12" r="9"/>'
              '<path d="M3 12h18M12 3c2.8 3 2.8 15 0 18M12 3c-2.8 3-2.8 15 0 18"/>'),
    "chip": ('<rect x="7" y="7" width="10" height="10" rx="1"/>'
             '<path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>'),
    "lightning": '<path d="M13 2L5 13h6l-1 9 8-12h-6l1-8z"/>',
}
ICONS["organization"] = ICONS["organisation"]
_GRADE = re.compile(r"^[A-F][1-6]$")
_CC = re.compile(r"^[A-Za-z]{2}$")
_YEAR_GROUP = re.compile(r"(?<!\d)(?:19|20)\d{2}(?!\d)")


def _compile(pat, default, flags=re.IGNORECASE):
    """Compile a reference regex; a malformed one keeps the embedded default, loudly."""
    try:
        return re.compile(str(pat), flags)
    except (re.error, TypeError) as exc:
        sys.stderr.write(f"[card_map] WARNING: bad pii pattern {pat!r} ({exc}); using the default\n")
        return re.compile(default, flags)


def _pii_setting(key):
    v = (REF.get("pii") or {}).get(key)
    return v if v is not None else _FALLBACK["pii"][key]


_FB_DATE = rf"\b(?:{'|'.join(f'(?:{d})' for d in _FALLBACK['pii_full_dates'])})\b"
_DATE_RE = _compile(rf"\b(?:{'|'.join(f'(?:{d})' for d in REF.get('pii_full_dates') or [])})\b"
                    if REF.get("pii_full_dates") else _FB_DATE, _FB_DATE)
_FB_CUE = _FALLBACK["pii"]["dob_cue"]
_DOB_BEFORE = _compile(rf"\b{_pii_setting('dob_cue')}(?!\w)[\s:.,\-\u2013(]*(?:on\s+|in\s+)?"
                       rf"(?P<d>{_DATE_RE.pattern})",
                       rf"\b{_FB_CUE}(?!\w)[\s:.,\-\u2013(]*(?:on\s+|in\s+)?(?P<d>{_FB_DATE})")
_DOB_AFTER = _compile(rf"(?P<d>{_DATE_RE.pattern})\s*[(\[]\s*{_pii_setting('dob_cue')}(?!\w)",
                      rf"(?P<d>{_FB_DATE})\s*[(\[]\s*{_FB_CUE}(?!\w)")
_EMAIL_RE = _compile(_pii_setting("email"), _FALLBACK["pii"]["email"])
_PHONE_RE = _compile(_pii_setting("phone"), _FALLBACK["pii"]["phone"])


def _is_phone(cand: str) -> bool:
    digits = sum(ch.isdigit() for ch in cand)
    intl = cand.startswith("+")
    lo = int(_pii_setting("phone_min_digits_intl" if intl else "phone_min_digits"))
    if not lo <= digits <= int(_pii_setting("phone_max_digits")):
        return False
    if _DATE_RE.search(cand):
        return False
    return intl or len(_YEAR_GROUP.findall(cand)) < 2


def scrub_pii(text, person: bool = False) -> str:
    """`text` with e-mail addresses, phone numbers and birth dates replaced by pii.replacement
    (rules in the module docstring). `person`: the text sits on a person card, so EVERY full
    date is treated as a birth date. Plain date ranges and month-year dates are never touched."""
    s = str(text if text is not None else "")
    if not s:
        return s
    rep = str(_pii_setting("replacement"))

    def _date_only(m):
        a, b = m.start("d") - m.start(), m.end("d") - m.start()
        return m.group(0)[:a] + rep + m.group(0)[b:]
    s = _EMAIL_RE.sub(rep, s)
    s = _DOB_BEFORE.sub(_date_only, s)
    s = _DOB_AFTER.sub(_date_only, s)
    if person:
        s = _DATE_RE.sub(rep, s)
    return _PHONE_RE.sub(lambda m: rep if _is_phone(m.group(0)) else m.group(0), s)


def warn(msg: str) -> None:
    sys.stderr.write(f"[card_map] WARNING: {msg}\n")


def _n(v) -> str:
    """Deterministic number formatting: one decimal, no trailing .0."""
    s = f"{round(float(v), 1):.1f}"
    return s[:-2] if s.endswith(".0") else s


def esc(s) -> str:
    return _xml_escape(str(s if s is not None else ""), {'"': "&quot;"})


# ── text measurement + wrapping ─────────────────────────────────────────────

def _char_w(ch: str, size: float, bold: bool) -> float:
    o = ord(ch)
    if o >= 0x2E80:                                   # CJK / wide
        f = S["char_wide"]
    elif ch.isupper() or ch in "MWmw@%":
        f = S["char_caps"]
    elif ch in "ilj.,:;'|!()[] ":
        f = 0.3
    else:
        f = S["char_bold"] if bold else S["char_regular"]
    return f * size


def text_w(s: str, size: float, bold: bool = False) -> float:
    return sum(_char_w(c, size, bold) for c in str(s))


def wrap(s: str, width: float, size: float, bold: bool = False) -> list:
    """Greedy word wrap by estimated width; a word longer than the line is broken by character.
    The line is never narrower than one glyph (`size`), so a zero or negative width still ends."""
    width = max(float(width), float(size))
    out, cur = [], ""
    for word in str(s or "").split():
        cand = f"{cur} {word}" if cur else word
        if text_w(cand, size, bold) <= width:
            cur = cand
            continue
        if cur:
            out.append(cur)
        cur = ""
        while word and text_w(word, size, bold) > width:
            cut = 1
            while cut < len(word) and text_w(word[:cut + 1], size, bold) <= width:
                cut += 1
            out.append(word[:cut])
            word = word[cut:]
        cur = word
    if cur:
        out.append(cur)
    return out


def _initials(name: str) -> str:
    parts = [p for p in re.split(r"[\s\-_.]+", str(name or "")) if p and p[0].isalnum()]
    return "".join(p[0].upper() for p in parts[:2]) or "?"


def _logo_roots(base_dir: str) -> list:
    """Directories a logo may come from: the spec's own directory and, when the spec sits inside
    a case (an ancestor named `cases`), that case's report/ directory."""
    d = os.path.realpath(base_dir or ".")
    roots = [d]
    while True:
        parent = os.path.dirname(d)
        if parent == d:
            break
        if os.path.basename(parent) == "cases":
            roots.append(os.path.realpath(os.path.join(d, "report")))
            break
        d = parent
    return roots


def _sniff_mime(head: bytes) -> str | None:
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    txt = head[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    if txt.startswith((b"<?xml", b"<svg", b"<!--", b"<!DOCTYPE svg")) and b"<svg" in txt:
        return "image/svg+xml"
    return None


# ── drawing primitives ──────────────────────────────────────────────────────

class Canvas:
    def __init__(self, base_dir: str = ".", sizes: dict | None = None):
        self.under: list = []        # connectors and trunk: drawn first
        self.over: list = []         # panels, cards, chips
        self.clip = 0
        self.base_dir = base_dir
        self.s = sizes if sizes is not None else S

    def text(self, x, y, s, size, fill, bold=False, anchor="start", layer=None):
        (layer if layer is not None else self.over).append(
            f'<text x="{_n(x)}" y="{_n(y)}" font-size="{_n(size)}" fill="{fill}"'
            + (' font-weight="700"' if bold else "")
            + (f' text-anchor="{anchor}"' if anchor != "start" else "") + f">{esc(s)}</text>")

    def rect(self, x, y, w, h, rx, fill, stroke, dashed=False, sw=1):
        self.over.append(
            f'<rect x="{_n(x)}" y="{_n(y)}" width="{_n(w)}" height="{_n(h)}" rx="{_n(rx)}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{_n(sw)}"'
            + (f' stroke-dasharray="{T["dash"]}"' if dashed else "") + "/>")

    def line(self, pts, stroke, dashed=False, sw=1.2, over=False):
        """A polyline. `over`: draw above panel fills (in-panel stubs/elbows); else under all."""
        d = "M" + " L".join(f"{_n(x)} {_n(y)}" for x, y in pts)
        (self.over if over else self.under).append(
            f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{_n(sw)}"'
            + (f' stroke-dasharray="{T["dash"]}"' if dashed else "") + "/>")

    def chip(self, x, y, label, fill, stroke, ink, bold=False) -> float:
        """A small rounded label box at (x, y) top-left; returns its width."""
        s = self.s
        size = s["chip_size"]
        w = text_w(label, size, bold) + s["chip_pad"]
        self.rect(x, y, w, s["chip_height"], 3, fill, stroke)
        self.text(x + w / 2, y + s["chip_height"] / 2 + size * 0.36, label, size, ink, bold, "middle")
        return w

    def badge(self, x, y, grade) -> float:
        col = B.get(grade[0], B.get("D", "#7a766e"))
        return self.chip(x, y, grade, col, col, B.get("badge_ink", "#ffffff"), bold=True)

    def logo_href(self, path) -> str | None:
        """A data: URI for a local logo, or None (with a warning) unless the file is inside the
        spec directory or the case report/ directory, within logo.max_bytes, and a PNG, JPEG or
        SVG by signature."""
        if not path:
            return None
        p = str(path)
        p = p if os.path.isabs(p) else os.path.join(self.base_dir, p)
        if not os.path.isfile(p):
            warn(f"logo {path!r} not found locally — ignored (logos are never fetched); "
                 f"drawing initials/icon instead")
            return None
        rp = os.path.realpath(p)
        if not any(os.path.commonpath([rp, root]) == root for root in _logo_roots(self.base_dir)):
            warn(f"logo {path!r} is outside the spec directory and the case report/ directory — "
                 f"ignored; drawing initials/icon instead")
            return None
        cap = int((REF.get("logo") or {}).get("max_bytes") or _FALLBACK["logo"]["max_bytes"])
        try:
            if os.path.getsize(rp) > cap:
                warn(f"logo {path!r} is larger than {cap} bytes — ignored")
                return None
            with open(rp, "rb") as fh:
                data = fh.read(cap + 1)
        except OSError as exc:
            warn(f"logo {path!r} unreadable ({type(exc).__name__}) — ignored")
            return None
        mime = _sniff_mime(data) if len(data) <= cap else None
        if not mime:
            warn(f"logo {path!r} is not a PNG, JPEG or SVG by its signature — ignored")
            return None
        return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")

    def avatar(self, cx, cy, r, card, hub=False):
        fill = T["hub_avatar_fill"] if hub else T["avatar_fill"]
        self.over.append(f'<circle cx="{_n(cx)}" cy="{_n(cy)}" r="{_n(r)}" fill="{fill}"/>')
        href = self.logo_href(card.get("logo"))
        if href:
            self.clip += 1
            cid = f"cm-clip-{self.clip}"
            self.over.append(f'<clipPath id="{cid}"><circle cx="{_n(cx)}" cy="{_n(cy)}" '
                             f'r="{_n(r)}"/></clipPath>')
            self.over.append(f'<image x="{_n(cx - r)}" y="{_n(cy - r)}" width="{_n(2 * r)}" '
                             f'height="{_n(2 * r)}" preserveAspectRatio="xMidYMid slice" '
                             f'clip-path="url(#{cid})" href="{href}"/>')
            return
        icon = str(card.get("icon") or "").lower()
        if icon and icon not in ICONS:
            warn(f"unknown icon {icon!r} — using initials (known: {', '.join(sorted(ICONS))})")
        if icon in ICONS and not card.get("initials"):
            k = r * self.s["icon_scale"] / 12     # the 24-unit icon grid spans icon_scale x diameter
            self.over.append(
                f'<g transform="translate({_n(cx - 12 * k)} {_n(cy - 12 * k)}) scale({k:.4f})" '
                f'fill="none" stroke="{T["avatar_ink"]}" stroke-width="1.8" '
                f'stroke-linecap="round" stroke-linejoin="round">{ICONS[icon]}</g>')
            return
        ini = str(card.get("initials") or _initials(card.get("name")))[:3]
        size = r * 0.78
        self.text(cx, cy + size * 0.36, ini, size, T["avatar_ink"], True, "middle")


# ── cards ───────────────────────────────────────────────────────────────────

def _chips(card) -> list:
    """[(kind, label)] for the chip row: country code, relation, grade."""
    out = []
    cc = str(card.get("cc") or "").strip()
    if cc:
        if _CC.match(cc):
            out.append(("cc", cc.upper()))
        else:
            warn(f"country code {cc!r} is not two letters — not drawn")
    if str(card.get("relation") or "").strip():
        out.append(("rel", str(card["relation"]).strip()))
    g = str(card.get("grade") or "").strip().upper()
    if g:
        if _GRADE.match(g):
            out.append(("grade", g))
        else:
            warn(f"grade {g!r} is not Admiralty A1..F6 — not drawn")
    return out


def card_layout(card, w, sizes=None):
    """Measure one card -> dict with wrapped lines and chip rows, and its height."""
    S = sizes if sizes is not None else REF["sizes"]
    p, r = S["card_pad"], S["avatar_radius"]
    tx = p + 2 * r + 10
    tw = w - tx - p
    lh_n, lh_l = S["name_size"] * S["line_height"], S["line_size"] * S["line_height"]
    name = wrap(card.get("name") or "", tw, S["name_size"], True) or [""]
    lines = []
    for ln in list(card.get("lines") or []) + ([card["dates"]] if card.get("dates") else []):
        lines += wrap(ln, tw, S["line_size"])
    rows, cur, cx = [], [], 0.0
    chips = []
    for kind, label in _chips(card):
        if kind == "rel" and text_w(label, S["chip_size"]) + S["chip_pad"] > tw:   # never cut: one chip per line
            chips += [("rel", part) for part in wrap(label, tw - S["chip_pad"] - 2, S["chip_size"])]
        else:
            chips.append((kind, label))
    for kind, label in chips:
        cw = text_w(label, S["chip_size"], kind == "grade") + S["chip_pad"]
        if cur and cx + cw > tw:
            rows.append(cur)
            cur, cx = [], 0.0
        cur.append((kind, label))
        cx += cw + S["chip_gap"]
    if cur:
        rows.append(cur)
    text_h = len(name) * lh_n + len(lines) * lh_l + len(rows) * (S["chip_height"] + 4) + (4 if rows else 0)
    h = max(2 * p + 2 * r, 2 * p + text_h)
    return {"name": name, "lines": lines, "chips": rows, "h": h, "tx": tx}


def draw_card(cv: Canvas, x, y, w, card, lay, hub=False):
    S = cv.s
    p, r = S["card_pad"], S["avatar_radius"]
    dashed = card.get("confirmed") is False
    if hub:
        cv.rect(x, y, w, lay["h"], S["card_radius"], T["hub_fill"], T["hub_stroke"], dashed)
    else:
        cv.rect(x, y, w, lay["h"], S["card_radius"], T["card_fill"], T["card_stroke"], dashed,
                sw=1.3 if dashed else 1)
    cv.avatar(x + p + r, y + p + r, r, card, hub)
    ink, muted = (T["hub_ink"], T["hub_muted"]) if hub else (T["ink"], T["muted"])
    tx = x + lay["tx"]
    cy = y + p
    for ln in lay["name"]:
        cy += S["name_size"] * S["line_height"]
        cv.text(tx, cy - S["name_size"] * 0.3, ln, S["name_size"], ink, True)
    for ln in lay["lines"]:
        cy += S["line_size"] * S["line_height"]
        cv.text(tx, cy - S["line_size"] * 0.3, ln, S["line_size"], muted)
    cy += 4
    for row in lay["chips"]:
        cx = tx
        for kind, label in row:
            if kind == "grade":
                cx += cv.badge(cx, cy, label) + S["chip_gap"]
            elif hub:
                cx += cv.chip(cx, cy, label, T["hub_chip_fill"], T["hub_chip_stroke"], T["hub_ink"]) + S["chip_gap"]
            else:
                cx += cv.chip(cx, cy, label, T["chip_fill"], T["chip_stroke"], T["chip_ink"],
                              bold=(kind == "cc")) + S["chip_gap"]
        cy += S["chip_height"] + 4


# ── panels ──────────────────────────────────────────────────────────────────

def _panel_title_lines(title, w, sizes):
    return wrap(title or "", w, sizes["panel_title_size"], True)


def side_panel_height(panel, w, sizes=None) -> float:
    S = sizes if sizes is not None else REF["sizes"]
    pp, g = S["panel_pad"], S["card_gap"]
    tl = _panel_title_lines(panel.get("title"), w - 2 * pp, S)
    h = pp + len(tl) * S["panel_title_size"] * S["line_height"] + 6
    for card in panel.get("cards") or []:
        cw = w - 2 * pp - (S["indent"] if card.get("indent") else 0)
        h += card_layout(card, cw, S)["h"] + g
    return h - g + pp if panel.get("cards") else h + pp


def draw_side_panel(cv: Canvas, x, y, w, h, panel, side):
    S = cv.s
    pp, g = S["panel_pad"], S["card_gap"]
    cv.rect(x, y, w, h, S["panel_radius"], T["panel_fill"], T["panel_stroke"])
    cy = y + pp
    for ln in _panel_title_lines(panel.get("title"), w - 2 * pp, S):
        cy += S["panel_title_size"] * S["line_height"]
        cv.text(x + pp, cy - S["panel_title_size"] * 0.3, ln, S["panel_title_size"], T["panel_title"], True)
    cy += 6
    parent_ax = None
    for card in panel.get("cards") or []:
        ind = S["indent"] if card.get("indent") else 0
        cw = w - 2 * pp - ind
        lay = card_layout(card, cw, S)
        cx = x + pp + ind
        dashed = card.get("confirmed") is False
        mid = cy + S["card_pad"] + S["avatar_radius"]
        if ind and parent_ax is not None:
            cv.line([(parent_ax[0], parent_ax[1]), (parent_ax[0], mid), (cx, mid)], T["trunk"], dashed,
                    over=True)
        elif side == "left":          # stub from the panel's trunk-side edge
            cv.line([(x + w, mid), (cx + cw, mid)], T["trunk"], dashed, over=True)
        elif side == "right":
            cv.line([(x, mid), (cx, mid)], T["trunk"], dashed, over=True)
        draw_card(cv, cx, cy, cw, card, lay)
        if not ind:
            parent_ax = (cx + S["card_pad"] + S["avatar_radius"], cy + lay["h"])
        cy += lay["h"] + g


def full_panel_layout(panel, w, sizes=None):
    S = sizes if sizes is not None else REF["sizes"]
    pp, g = S["panel_pad"], S["card_gap"]
    cards = panel.get("cards") or []
    fit = int((w - 2 * pp + g) // (S["full_min_card_width"] + g))   # columns that keep a card readable
    cols = max(1, min(int(S["full_columns"]), len(cards) or 1, fit))
    cw = (w - 2 * pp - (cols - 1) * g) / cols
    tl = _panel_title_lines(panel.get("title"), w - 2 * pp, S)
    h = pp + len(tl) * S["panel_title_size"] * S["line_height"] + 6
    grid = []
    for i in range(0, len(cards), cols):
        row = [(c, card_layout(c, cw, S)) for c in cards[i:i + cols]]
        grid.append(row)
        h += max(lay["h"] for _, lay in row) + g
    return {"h": (h - g + pp) if grid else h + pp, "grid": grid, "cw": cw, "title": tl}


def draw_full_panel(cv: Canvas, x, y, w, panel, fl):
    S = cv.s
    pp, g = S["panel_pad"], S["card_gap"]
    cv.rect(x, y, w, fl["h"], S["panel_radius"], T["panel_fill"], T["panel_stroke"])
    cy = y + pp
    for ln in fl["title"]:
        cy += S["panel_title_size"] * S["line_height"]
        cv.text(x + pp, cy - S["panel_title_size"] * 0.3, ln, S["panel_title_size"], T["panel_title"], True)
    cy += 6
    for row in fl["grid"]:
        for i, (card, lay) in enumerate(row):
            draw_card(cv, x + pp + i * (fl["cw"] + g), cy, fl["cw"], card, lay)
        cy += max(lay["h"] for _, lay in row) + g


def _rows(panels) -> list:
    rows, cur = [], {}
    for p in panels:
        side = str(p.get("side") or "left").lower()
        if side not in ("left", "right", "center", "full"):
            warn(f"panel side {side!r} unknown — treated as left")
            side = "left"
        if side == "full":
            if cur:
                rows.append(cur)
                cur = {}
            rows.append({"full": p})
            continue
        if side in cur:
            rows.append(cur)
            cur = {}
        cur[side] = p
    if cur:
        rows.append(cur)
    return rows


# ── the figure ──────────────────────────────────────────────────────────────

def render_svg(spec: dict, base_dir: str = ".") -> str:
    """C2 spec -> SVG text (deterministic).

    A map with a full-width grid panel is drawn on the wide canvas (sizes.width). Embedded at the
    report's figure width that canvas is shrunk more than the narrow one, so every key listed in
    `wide_scale_keys` (type, chips, avatars, padding, gaps) is multiplied by sizes.wide_scale
    for the duration of the render — the printed type stays as large as on the narrow canvas."""
    sizes = S
    rows = _rows(spec.get("panels") or [])
    if any("full" in r for r in rows):
        f = float(S.get("wide_scale") or 1)
        sizes = {k: (v * f if k in REF["wide_scale_keys"] else v) for k, v in S.items()}
    return _render(spec, base_dir, rows, sizes)


def _render(spec: dict, base_dir: str, rows: list, sizes: dict) -> str:
    S = sizes
    cv = Canvas(base_dir, sizes)
    # A map with no full-width grid is one card column per side: draw it on the narrower canvas so
    # a page-width embed prints its text larger. Without a center panel the trunk needs only a gap.
    has_full = any("full" in r for r in rows)
    cw_center = float(S["center_width"] if any("center" in r for r in rows) else S["trunk_gap"])
    W = float(S["width"] if has_full else S["narrow_width"] + cw_center - S["trunk_gap"])
    M = float(S["margin"])
    mid = W / 2
    pw = (W - 2 * M - cw_center) / 2
    y = M + S["title_size"]
    content_w = W - 2 * M
    sub_lines = wrap(spec.get("subtitle") or "", content_w * S["subtitle_max_share"], S["subtitle_size"])
    sub_w = max((text_w(ln, S["subtitle_size"]) for ln in sub_lines), default=0)
    title_w = max(S["title_size"], content_w - sub_w - 30)
    for i, ln in enumerate(wrap(spec.get("title") or "", title_w, S["title_size"], True) or [""]):
        if i:
            y += S["title_size"] * 1.2
        cv.text(M, y, ln, S["title_size"], T["title"], True)
    for i, ln in enumerate(sub_lines):
        cv.text(W - M, M + S["title_size"] + i * S["subtitle_size"] * S["line_height"],
                ln, S["subtitle_size"], T["muted"], anchor="end")
    if sub_lines:
        y = max(y, M + S["title_size"] + (len(sub_lines) - 1) * S["subtitle_size"] * S["line_height"])
    y += 22

    # hub
    hub = spec.get("hub") or {}
    hw = float(S["hub_width"])
    hlay = card_layout(hub, hw, S)
    draw_card(cv, mid - hw / 2, y, hw, hub, hlay, hub=True)
    trunk_top = y + hlay["h"]
    y = trunk_top + 12

    # trunk labels (chips riding on the trunk)
    for tl in spec.get("trunk_labels") or []:
        label = str(tl.get("text") or "")
        g = str(tl.get("grade") or "").strip().upper()
        gw = (text_w(g, S["chip_size"], True) + S["chip_pad"] + 4) if _GRADE.match(g) else 0
        lw = text_w(label, S["chip_size"]) + S["chip_pad"]
        x0 = mid - (lw + gw) / 2
        cv.chip(x0, y, label, T["card_fill"], T["card_stroke"], T["chip_ink"])
        if gw:
            cv.badge(x0 + lw + 4, y, g)
        y += S["chip_height"] + 10
    y += 6

    trunk_bottom = y
    for row in rows:
        if "full" in row:
            fl = full_panel_layout(row["full"], W - 2 * M, S)
            trunk_bottom = y
            draw_full_panel(cv, M, y, W - 2 * M, row["full"], fl)
            y += fl["h"] + S["row_gap"]
            continue
        heights = {}
        for side in ("left", "right"):
            if side in row:
                heights[side] = side_panel_height(row[side], pw, S)
        center_lays = []
        if "center" in row:
            ccw = cw_center - 30
            hc = 0.0
            for card in row["center"].get("cards") or []:
                lay = card_layout(card, ccw, S)
                center_lays.append((card, lay))
                hc += lay["h"] + S["card_gap"]
            heights["center"] = hc - S["card_gap"] if center_lays else 0
        rh = max(heights.values() or [0])
        branch_y = y + S["panel_pad"] + S["panel_title_size"] * 0.6
        for side, x in (("left", M), ("right", W - M - pw)):
            if side not in row:
                continue
            cards = row[side].get("cards") or []
            all_unconf = bool(cards) and all(c.get("confirmed") is False for c in cards)
            edge = x + pw if side == "left" else x
            cv.line([(mid, branch_y), (edge, branch_y)], T["trunk"], all_unconf, S["trunk_width"])
            draw_side_panel(cv, x, y, pw, heights[side], row[side], side)
            trunk_bottom = max(trunk_bottom, branch_y)
        cy = y
        for card, lay in center_lays:
            ccw = cw_center - 30
            draw_card(cv, mid - ccw / 2, cy, ccw, card, lay)
            if card.get("confirmed") is False:     # the trunk segment into it is dashed
                cv.line([(mid, cy - S["card_gap"]), (mid, cy)], T["background"], False, S["trunk_width"] + 1)
                cv.line([(mid, cy - S["card_gap"]), (mid, cy)], T["trunk"], True, S["trunk_width"])
            cy += lay["h"] + S["card_gap"]
            trunk_bottom = max(trunk_bottom, cy - S["card_gap"])
        y += rh + S["row_gap"]

    if trunk_bottom > trunk_top:
        cv.under.insert(0, f'<path d="M{_n(mid)} {_n(trunk_top)} L{_n(mid)} {_n(trunk_bottom)}" '
                           f'fill="none" stroke="{T["trunk"]}" stroke-width="{_n(S["trunk_width"])}"/>')

    # legend
    if spec.get("legend", True):
        y += 2
        bw = cv.badge(M, y, str(LEG.get("badge_sample") or "A1"))
        x = M + bw + 8
        ls = S["legend_size"]
        cv.text(x, y + S["chip_height"] / 2 + ls * 0.36, LEG.get("badge_text", ""), ls, T["muted"])
        x += text_w(LEG.get("badge_text", ""), ls) + 24
        rest = (sum(text_w(s, S["chip_size"], True) + S["chip_pad"] + 4 for s in ("A", "B", "C", "D-F")) + 16
                + ls * 3.5 + text_w(LEG.get("dashed_text", ""), ls))
        if x + rest > W - M:                      # narrow canvas: swatches + dashed on a 2nd line
            x, y = M, y + S["chip_height"] + 6
        for letter in ("A", "B", "C", "D-F"):
            x += cv.badge(x, y, letter) + 4
        x += 16
        ly = y + S["chip_height"] / 2
        dl = ls * 2.8                              # dashed sample length follows the legend type size
        cv.over.append(f'<path d="M{_n(x)} {_n(ly)} L{_n(x + dl)} {_n(ly)}" fill="none" '
                       f'stroke="{T["trunk"]}" stroke-width="{_n(S["trunk_width"])}" '
                       f'stroke-dasharray="{T["dash"]}"/>')
        cv.text(x + ls * 3.5, ly + ls * 0.36, LEG.get("dashed_text", ""), ls, T["muted"])
        y += S["chip_height"] + 4
    H = y + M - 4
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{_n(W)}" height="{_n(H)}" '
            f'viewBox="0 0 {_n(W)} {_n(H)}">')
    body = [head, f'<rect x="0" y="0" width="{_n(W)}" height="{_n(H)}" fill="{T["background"]}"/>',
            f'<g font-family="{esc(T["font_family"])}">', *cv.under, *cv.over, "</g>", "</svg>"]
    return "\n".join(body) + "\n"


def svg_size(svg: str) -> tuple:
    m = re.search(r'<svg[^>]*\swidth="([\d.]+)"[^>]*\sheight="([\d.]+)"', svg)
    return (float(m.group(1)), float(m.group(2))) if m else (float(S["width"]), 800.0)


# ── masking ─────────────────────────────────────────────────────────────────

def _house_mask():
    """house_report.mask_third_parties, or None when the engine is not importable."""
    tools = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools")
    if os.path.isdir(tools) and tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        import house_report  # noqa: E402
        return house_report.mask_third_parties
    except Exception as exc:  # noqa: BLE001
        warn(f"house masking unavailable ({type(exc).__name__}); using the local fallback "
             f"(person-card names reduced to initials)")
        return None


def _is_person(card) -> bool:
    return str(card.get("icon") or "").lower() == "person" or bool(card.get("initials"))


def mask_spec(spec: dict, fn=None) -> dict:
    """Copy with mandatory local initials/logo/PII reduction, then the optional house mask."""
    out = json.loads(json.dumps(spec))
    cards = [out.get("hub") or {}] + [c for p in out.get("panels") or [] for c in p.get("cards") or []]
    names = {}
    for c in cards:
        c.pop("logo", None)
        if _is_person(c) and c.get("name"):
            ini = _initials(c["name"])
            names[str(c["name"])] = ". ".join(ini) + "."
            c["initials"] = ini

    def clean(value, person=False):
        text = str(value)
        for name in sorted(names, key=lambda n: (-len(n), n)):
            text = re.sub(re.escape(name), lambda m: names[name], text, flags=re.IGNORECASE)
        text = scrub_pii(text, person)
        return fn(text) if fn else text

    for c in cards:
        for k in ("name", "relation", "dates"):
            if c.get(k):
                c[k] = clean(c[k], _is_person(c))
        c["lines"] = [clean(x, _is_person(c)) for x in c.get("lines") or []]
    for k in ("title", "subtitle"):
        if out.get(k):
            out[k] = clean(out[k])
    for p in out.get("panels") or []:
        if p.get("title"):
            p["title"] = clean(p["title"])
    for label in out.get("trunk_labels") or []:
        if label.get("text"):
            label["text"] = clean(label["text"])
    return out


# ── output ──────────────────────────────────────────────────────────────────

def _raster_chain():
    import render_mermaid as rm
    return rm


def write(spec: dict, svg_path: str, png: str | None = None, pdf: str | None = None,
          base_dir: str = ".", scale: float | None = None) -> dict:
    """Render `spec` to svg_path (+ png/pdf via the one IntelGraph chain). Returns
    {"svg", "png", "pdf", "error"} — error names what to install when no rasteriser exists."""
    svg = render_svg(spec, base_dir)
    d = os.path.dirname(os.path.abspath(svg_path))
    os.makedirs(d, exist_ok=True)
    with open(svg_path, "w", encoding="utf-8") as fh:
        fh.write(svg)
    res = {"svg": svg_path, "png": None, "pdf": None, "error": ""}
    if not (png or pdf):
        return res
    rm = _raster_chain()
    kind, binary = rm.pick_rasteriser()
    if not kind:
        res["error"] = (f"wrote {svg_path}, but no SVG rasteriser for the PNG/PDF outputs — install "
                        f"librsvg (rsvg-convert), Chrome/Chromium, or cairosvg")
        warn(res["error"])
        return res
    w, h = svg_size(svg)
    for out, kw, key in ((png, {"scale": scale or S["png_scale"]}, "png"), (pdf, {"pdf": True}, "pdf")):
        if not out:
            continue
        try:
            rm.rasterise(kind, binary, svg_path, out, w, h, **kw)
            res[key] = out
        except Exception as exc:  # noqa: BLE001 — RenderError or a converter crash
            res["error"] = f"{key} not written ({kind}): {exc}"
            warn(res["error"])
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Render a relationship card map (C2 spec) to SVG/PNG/PDF.")
    ap.add_argument("spec", help="card-map spec JSON")
    ap.add_argument("-o", "--out", required=True, help="output SVG path")
    ap.add_argument("--png", help="also write a PNG (device scale from references/card_map.json)")
    ap.add_argument("--pdf", help="also write a vector PDF")
    ap.add_argument("--mask", action="store_true",
                    help="reduce person names to initials, drop logos and strip personal contact/birth data")
    a = ap.parse_args(argv)
    with open(a.spec, encoding="utf-8") as fh:
        spec = json.load(fh)
    if a.mask:
        spec = mask_spec(spec, _house_mask())
    res = write(spec, a.out, a.png, a.pdf, base_dir=os.path.dirname(os.path.abspath(a.spec)))
    print(json.dumps(res))
    return 1 if res["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
