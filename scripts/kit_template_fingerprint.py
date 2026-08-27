#!/usr/bin/env python3
# cti-expert skill — phishing kit / template structural fingerprint + similarity.
"""kit_template_fingerprint.py — fingerprint a phishing page's kit/template structure and
measure structural similarity between pages, so the same kit links across rotating hosts.

Grounded in: Unai Agirre, manol Jerico, Felipe Castaño, Andrea Venturi, Francesco Zola
(Vicomtech) — *"A Tree-Structured Approach for Phishing Template and Attacker Attribution
Analysis"*, APWG eCrime 2026. Kits are reused verbatim across many deployments; the DOM
structure (not the swappable text/brand) is the stable signal that ties them to one builder or
operator lineage.

Offline, deterministic, stdlib `html.parser` only. Produces:
  * structure_hash    — a stable digest of the sorted tag-path skeleton (quick equality)
  * tag_path_shingles — root→node tag paths (order-tolerant; the similarity substrate)
  * form_signature    — sorted input field-name set (kits carry a fixed harvest form)
  * asset_skeleton    — normalized asset path tails (shared kit assets)
  * markers           — CMS/site-builder generator tells (commodity detection)

ATTRIBUTION SAFETY (the whole point of the commodity guard): a shared **commodity** template
(WordPress/Wix/Shopify theme, a popular free kit) is on thousands of unrelated hosts — matching
it is the §2.5 "commodity site kit" trap, NOT a same-operator link. The commodity check is
applied FIRST and unconditionally, so no branch ordering can leak a commodity match into a
lineage edge; commodity → noise; non-commodity high-similarity → a *lower-rung* lineage edge to
corroborate, never an automatic same-operator merge. Analyst-supplied `--refs` markers are
matched against page content like the built-ins.

Usage:
  uv run kit_template_fingerprint.py page.html                    # fingerprint (text)
  uv run kit_template_fingerprint.py page.html --json             # fingerprint (JSON)
  uv run kit_template_fingerprint.py --compare a.html b.html      # similarity + grading
  uv run kit_template_fingerprint.py --compare a.html b.html --refs commodity.json

Exit codes: 0 = ran, 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import re
import sys
import json
import hashlib
import argparse
from html.parser import HTMLParser

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# CMS / site-builder / popular-free-kit markers → a match on these is commodity, not attribution.
DEFAULT_COMMODITY = [
    "wordpress", "wp-content", "wp-includes", "wix.com", "_wixcss", "squarespace",
    "shopify", "cdn.shopify", "joomla", "drupal", "elementor", "webflow", "weebly",
    "godaddy", "framer", "hostinger website builder", "bootstrapcdn",
]
# structural tags worth counting (ignore purely-cosmetic inline tags to keep the skeleton stable)
_SKELETON_TAGS = {"html", "head", "body", "div", "section", "form", "input", "button", "select",
                  "textarea", "table", "tr", "td", "ul", "ol", "li", "nav", "header", "footer",
                  "main", "article", "aside", "label", "fieldset", "iframe", "script", "link", "img"}
# void elements: recorded in the path but never pushed onto the nesting stack (no end tag).
_VOID = {"input", "img", "link"}
_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


class _Fp(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.paths = set()       # set of tag-path shingles
        self.form_fields = set()
        self.assets = set()

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in _SKELETON_TAGS:
            if tag in _VOID:
                self.paths.add(">".join((self.stack + [tag])[-5:]))   # record, do not nest
            else:
                self.stack.append(tag)
                self.paths.add(">".join(self.stack[-5:]))
        if tag == "input":
            name = a.get("name") or a.get("id")
            if name:
                self.form_fields.add(name.strip().lower())
        for k in ("src", "href"):
            v = a.get(k)
            if v and not v.startswith(("data:", "javascript:", "#", "mailto:")):
                self.assets.add(_asset_tail(v))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)   # void tags are not nested, so no pop needed

    def handle_endtag(self, tag):
        if tag in _SKELETON_TAGS and tag not in _VOID:
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i] == tag:
                    del self.stack[i:]
                    break


def _asset_tail(url):
    """Normalize an asset URL to a host-independent skeleton: last 2 path segments (no query).
    Handles protocol-relative //host/path too."""
    u = re.sub(r"[?#].*$", "", url)
    u = re.sub(r"^(?:https?:)?//[^/]+", "", u)      # drop scheme+host (incl. protocol-relative)
    segs = [s for s in u.split("/") if s]
    return "/".join(segs[-2:]).lower() if segs else ""


def _norm_extra(extra):
    return {str(x).lower() for x in (extra or []) if str(x).strip()}


def fingerprint(html, extra_commodity=None):
    """Pure structural fingerprint of a page. Deterministic.
    extra_commodity markers are matched against page content like the built-ins."""
    html = html or ""
    p = _Fp()
    try:
        p.feed(html)
        p.close()
    except Exception:  # malformed markup degrades, never crashes
        pass
    shingles = sorted(p.paths)
    skeleton = "\n".join(shingles)
    markers = set()
    low = html.lower()
    for m in list(DEFAULT_COMMODITY) + sorted(_norm_extra(extra_commodity)):
        if m and m in low:
            markers.add(m)
    gen = _GENERATOR_RE.search(html)
    generator = gen.group(1).strip() if gen else None
    if generator:
        markers.add("generator:" + generator.lower())
    return {
        "structure_hash": hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:16],
        "tag_path_shingles": shingles,
        "form_signature": sorted(p.form_fields),
        "asset_skeleton": sorted(a for a in p.assets if a),
        "markers": sorted(markers),
        "generator": generator,
    }


def _jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _is_commodity(fp, extra=None):
    markers = set(fp.get("markers", []))
    seeds = set(DEFAULT_COMMODITY) | _norm_extra(extra)
    for m in markers:
        base = m.split(":", 1)[-1]
        if any(s in base or s in m for s in seeds):
            return True, m
    return False, None


def similarity(fp_a, fp_b, extra_commodity=None):
    """Structural similarity + attribution grading between two fingerprints."""
    j_paths = _jaccard(fp_a["tag_path_shingles"], fp_b["tag_path_shingles"])
    j_form = _jaccard(fp_a["form_signature"], fp_b["form_signature"])
    j_asset = _jaccard(fp_a["asset_skeleton"], fp_b["asset_skeleton"])

    # renormalize over components that carry data on either side, so a form-less/asset-less page
    # can still reach a high score on structure alone.
    parts = [(0.6, j_paths, True),
             (0.3, j_form, bool(fp_a["form_signature"] or fp_b["form_signature"])),
             (0.1, j_asset, bool(fp_a["asset_skeleton"] or fp_b["asset_skeleton"]))]
    wsum = sum(w for w, _j, active in parts if active) or 1.0
    score = round(sum(w * j for w, j, active in parts if active) / wsum, 3)

    shared = []
    if j_paths > 0:
        shared.append(f"tag-path overlap {j_paths:.2f}")
    if fp_a["form_signature"] and fp_a["form_signature"] == fp_b["form_signature"]:
        shared.append("identical form field-name set")
    elif j_form > 0:
        shared.append(f"form-field overlap {j_form:.2f}")
    if j_asset > 0:
        shared.append(f"shared asset tails {j_asset:.2f}")
    if fp_a["structure_hash"] == fp_b["structure_hash"]:
        shared.append("identical structure hash")

    ca, ma = _is_commodity(fp_a, extra_commodity)
    cb, mb = _is_commodity(fp_b, extra_commodity)
    commodity = ca or cb
    commodity_marker = ma or mb

    # commodity check FIRST + unconditional — no branch ordering can leak it into a lineage edge.
    if commodity and score >= 0.5:
        grade, edge = "commodity_template_noise", "none"
        note = (f"Structural similarity {score} but a commodity template marker is present "
                f"({commodity_marker}) — this is kit/CMS-level, NOT a same-operator link (§2.5 trap). "
                f"Do not cluster on it.")
    elif score >= 0.75:
        grade, edge = "candidate_same_kit", "lineage_low_confidence"
        note = ("High structural similarity with no commodity marker — a candidate same-kit / "
                "builder-lineage link. This is a LOWER-RUNG edge: corroborate with a unique "
                "indicator (tracker ID, wallet, cert) before treating as same-operator. Never auto-merge.")
    elif score >= 0.5:
        grade, edge = "weak_similarity", "hold"
        note = "Moderate structural similarity — hold pending corroboration; not clusterable alone."
    else:
        grade, edge = "dissimilar", "none"
        note = "Structures differ — no kit-lineage signal."

    return {
        "score": score,
        "components": {"tag_path": round(j_paths, 3), "form": round(j_form, 3), "asset": round(j_asset, 3)},
        "shared_features": shared,
        "commodity": commodity,
        "commodity_marker": commodity_marker,
        "grade": grade,
        "clustering_edge": edge,
        "note": note,
    }


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Fingerprint a phishing page's kit/template structure and compare pages (offline).")
    ap.add_argument("input", nargs="?", help="HTML file (or '-') to fingerprint")
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"), help="two HTML files to compare")
    ap.add_argument("--refs", help="JSON array of extra commodity marker strings")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--out")
    args = ap.parse_args(argv)

    extra = None
    if args.refs:
        try:
            extra = json.loads(_read(args.refs))
        except (OSError, ValueError) as e:
            print(f"error: --refs: {e}", file=sys.stderr)
            return 4
        if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
            print("error: --refs must be a JSON array of strings", file=sys.stderr)
            return 4

    if args.compare:
        try:
            fa = fingerprint(_read(args.compare[0]), extra)
            fb = fingerprint(_read(args.compare[1]), extra)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 4
        r = similarity(fa, fb, extra)
        if args.json:
            body = json.dumps(r, indent=2, ensure_ascii=False)
        else:
            body = (f"Similarity : {r['score']}  (tag-path {r['components']['tag_path']}, "
                    f"form {r['components']['form']}, asset {r['components']['asset']})\n"
                    f"Grade      : {r['grade']}  (clustering edge: {r['clustering_edge']})\n"
                    f"Commodity  : {r['commodity']}" + (f" ({r['commodity_marker']})" if r['commodity'] else "") + "\n"
                    + ("Shared     : " + "; ".join(r["shared_features"]) + "\n" if r["shared_features"] else "")
                    + "\nNOTE: " + r["note"])
    elif args.input:
        try:
            r = fingerprint(_read(args.input), extra)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 4
        if args.json:
            body = json.dumps(r, indent=2, ensure_ascii=False)
        else:
            body = (f"structure_hash : {r['structure_hash']}\n"
                    f"tag-path shingles: {len(r['tag_path_shingles'])}\n"
                    f"form_signature : {', '.join(r['form_signature']) or '(none)'}\n"
                    f"asset_skeleton : {len(r['asset_skeleton'])} tails\n"
                    f"markers        : {', '.join(r['markers']) or '(none)'}")
    else:
        print("error: provide an HTML file, or --compare A B", file=sys.stderr)
        return 4

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
