#!/usr/bin/env python3
"""
test_paths_capture.py — the gate on the URL-PATH layer and the RAW-EVIDENCE capture.

Run:  python3 tests/test_paths_capture.py
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Two failure modes, both silent in production and both expensive.

1. THE BASE-RATE CONTROL ON PATHS. `wp_paths` turns a URL path into a clustering indicator, which
   is the whole point — an operator who routes brands by path defeats every host-level pivot, and
   the kit directory is the only string that survives their host rotation. But the same mechanism
   pointed at `/login` or `/assets` would fuse every unrelated site on the internet into one
   operator. The denylist is what stands between those two outcomes, so these tests assert that a
   generic path emits NOTHING as hard as they assert that a distinctive one emits a kit.

2. THE EVIDENCE CONTRACT. A capture is only evidence if its manifest can be checked: every stored
   file hashed, a bundle digest that changes when any file changes, and an explicit statement when
   the bundle is INCOMPLETE. A capture that quietly dropped half a page reads as the whole page,
   which is worse than no capture at all.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))

import wp_paths as P      # noqa: E402
import wp_capture as C    # noqa: E402


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 1. the kit directory is extracted from a path-routed URL ---------------------------
    ok(P.kit_segment("https://123456.example/au-rewards/") == "au-rewards",
       "kit directory extracted from a path-routed URL")
    ok(P.kit_segment("https://a.example/AU-Rewards/Step2") == "au-rewards",
       "kit extraction is case-insensitive")
    ok(P.kit_segment("https://a.example/%61u-rewards/") == "au-rewards",
       "percent-encoded path is decoded before comparison (an operator hiding from string match)")

    # --- 2. THE BASE-RATE CONTROL: a generic path must emit nothing -------------------------
    for generic in ("https://a.example/", "https://a.example/login", "https://a.example/en/",
                    "https://a.example/wp-admin/index.php", "https://a.example/api/v1/",
                    "https://a.example/static/", "https://a.example/assets/js/app.js"):
        ok(P.kit_segment(generic) is None, f"generic path emits no kit: {generic.split('example')[1]}")
        ok(P.path_pivots(generic) == [], f"generic path emits no PIVOT: {generic.split('example')[1]}")
    ok(not P.clusterable("https://a.example/login"),
       "clusterable() fails closed on a generic path")

    # A one/two-character segment is routing, not a name.
    ok(P.kit_segment("https://a.example/x/y/") is None, "sub-minimum-length segments are not kits")
    # A static asset FILE is never a template directory (else every bundler output becomes a
    # fingerprint shared by unrelated sites).
    ok(P.kit_segment("https://a.example/assets/js/app.js") is None, "a .js file is not a kit")
    ok(P.kit_segment("https://a.example/static/css/main.4f3a.css") is None, "a .css file is not a kit")
    # ...but a kit's HTML entry point is a legitimate artifact and must survive.
    ok(P.kit_segment("https://a.example/vnpost.html") is not None,
       "an .html entry page IS still a kit candidate (page extensions are deliberately not filtered)")

    # --- 3. templates collapse the VARIABLE parts ------------------------------------------
    ok(P.path_template("https://a.example/kit/9f3a1c7b8d/step2") == "/kit/{hex}/step2",
       "a hex session segment normalises to a placeholder")
    ok(P.path_template("https://a.example/kit/00000000-1111-2222-3333-444444444444/") ==
       "/kit/{uuid}", "a uuid segment normalises to a placeholder")
    ok(P.path_template("https://a.example/vi/kit/") == "/{locale}/kit",
       "a locale segment normalises, so one kit in N markets is ONE kit")
    ok(P.locale_of("https://a.example/vi/kit/") == "vi",
       "...but the concrete locale is KEPT — target-market evidence, not noise")
    # Two per-victim URLs must land on the same template, or recurrence can never be counted.
    ok(P.path_template("https://a.example/kit/aaaaaaaa/x") ==
       P.path_template("https://a.example/kit/bbbbbbbb/x"),
       "two per-victim URLs collapse to ONE template")
    # A directory-index filename is the directory itself.
    ok(P.normalise_path("/kit/index.php") == P.normalise_path("/kit/") == "/kit",
       "index filenames strip, so one location is not counted as three")
    # Depth is bounded, so a deep CMS URL cannot become a self-matching 'fingerprint'.
    deep = "/" + "/".join(f"seg{i}" for i in range(20))
    ok(len([s for s in P.path_template(deep).split("/") if s]) <=
       P.KIT_THRESHOLDS.get("max_segments", 6), "path template is bounded by max_segments")

    # --- 4. the pattern finder: one kit on many hosts, and one host with many kits ----------
    recs = [{"url": "https://111111.example/kit-a/"},
            {"url": "https://222222.example/kit-a/x/44b0de"},
            {"url": "https://333333.example/kit-a/index.html"},
            {"url": "https://444444.example/kit-b/"},
            {"url": "https://444444.example/kit-c/"},
            {"url": "https://555555.example/login"}]
    pat = P.path_patterns(recs)
    kits = {r["value"]: r["host_count"] for r in pat["recurring_kits"]}
    ok(kits.get("kit-a") == 3,
       "one kit directory on three disposable hosts is reported as a recurring pattern")
    ok(all(r["value"] != "kit-b" for r in pat["recurring_kits"]),
       "a kit on a single host stays below the pattern threshold")
    ok(any(r["value"] == "kit-b" for r in pat["single_host_kits"]),
       "...and is still surfaced as a lead rather than dropped")
    ok(any(h["host"] == "444444.example" for h in pat["multi_kit_hosts"]),
       "one host serving several kits is reported (the other half of the technique)")
    ok("same-OPERATOR" in pat["note"] and "SAME-KIT" in pat["note"],
       "the pattern report states that a shared kit is same-KIT, not same-operator")

    # --- 5. the path pivot carries the reverse queries that find the NEXT host ---------------
    pivs = P.path_pivots("https://123456.example/kit-a/")
    ok(pivs and pivs[0]["kind"] == "path:kit", "a distinctive path emits a path:kit pivot")
    svcs = " ".join(q["service"] + q["query"] for q in pivs[0]["queries"])
    ok("urlscan" in svcs.lower() and "inurl:" in svcs,
       "the kit pivot ships urlscan + inurl: queries (the indexes that store the full URL)")
    ok("SAME-KIT" in pivs[0]["note"],
       "the pivot note states the same-kit limit rather than implying attribution")

    # --- 6. the evidence capture: hashing, the bundle digest, and tamper detection ----------
    tmp = tempfile.mkdtemp(prefix="wp_capture_test_")
    try:
        html = ('<html><head><link rel="stylesheet" href="/s/theme.css">'
                '<script src="/s/app.js"></script>'
                '<script src="https://cdn.example/lib.js"></script></head><body>x</body></html>')
        refs = C.referenced_assets(html, "https://host.example/kit-a/")
        roles = sorted(r["role"] for r in refs)
        ok(roles == ["css", "js", "js"], "referenced_assets finds every JS and CSS, incl. third-party")
        ok(any(r["url"] == "https://host.example/s/theme.css" for r in refs),
           "relative asset URLs are absolutised against the page URL")
        ok(all(not r["url"].startswith("data:") for r in refs), "data: URIs are not treated as assets")

        # The bundle digest must change when ANY file changes — that is what makes it citable.
        files = [{"sha256": hashlib.sha256(b"a").hexdigest(), "stored_as": "dom.html"},
                 {"sha256": hashlib.sha256(b"b").hexdigest(), "stored_as": "assets/x.js"}]
        d1 = C.bundle_digest(files)
        d2 = C.bundle_digest(list(reversed(files)))
        ok(d1 == d2, "bundle digest is order-independent (same bytes -> same digest)")
        files2 = [dict(files[0]), {"sha256": hashlib.sha256(b"c").hexdigest(),
                                   "stored_as": "assets/x.js"}]
        ok(C.bundle_digest(files2) != d1, "bundle digest CHANGES when any file's hash changes")
        ok(C.bundle_digest(files + [{"sha256": "z", "stored_as": "assets/extra.js"}]) != d1,
           "bundle digest changes when a file is ADDED")

        # verify() must catch an altered file and refuse to bless the bundle.
        capdir = os.path.join(tmp, "cap")
        os.makedirs(os.path.join(capdir, "assets"))
        with open(os.path.join(capdir, "dom.html"), "wb") as fh:
            fh.write(b"<html>original</html>")
        entry = {"url": "https://host.example/", "sha256":
                 hashlib.sha256(b"<html>original</html>").hexdigest(),
                 "bytes": 21, "stored_as": "dom.html", "role": "dom"}
        man = {"files": [entry], "capture_sha256": C.bundle_digest([entry])}
        with open(os.path.join(capdir, "manifest.json"), "w") as fh:
            json.dump(man, fh)
        ok(C.verify(capdir)["ok"], "verify() confirms an intact capture")
        with open(os.path.join(capdir, "dom.html"), "wb") as fh:
            fh.write(b"<html>TAMPERED</html>")
        v = C.verify(capdir)
        ok(not v["ok"] and v["altered"], "verify() detects a single altered byte")
        ok("MISMATCH" in v["verdict"], "...and says not to cite the capture until explained")
        os.remove(os.path.join(capdir, "dom.html"))
        ok(C.verify(capdir)["missing"], "verify() detects a MISSING file, not just a changed one")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- 7. the capture must never imply a completeness it does not have --------------------
    ok(int(C.BUDGETS.get("same_site_total_bytes", 0)) >
       int(C.BUDGETS.get("third_party_total_bytes", 1)),
       "same-site assets (the operator's own code) get a larger budget than third-party libs")
    ok("skipped_for_budget" in (C.MANIFEST_FIELDS.get("per_capture") or []),
       "the manifest schema carries skipped_for_budget — a partial bundle must SAY it is partial")
    ok(C._wants("js") and C._wants("css") and C._wants("dom"),
       "DOM, JS and CSS are all captured by default (CSS is otherwise never retained anywhere)")

    # --- 8. the KB clusters on the kit, and only when it is distinctive ---------------------
    import ingest_webpivot as IW      # noqa: E402
    ok(hasattr(IW, "_ingest_paths"), "the KB ingest has a URL-path layer")

    class _KB:
        def __init__(self):
            self.edges, self.facts = [], []

        def touch(self, *a, **k):
            pass

        def add_fact(self, *a, **k):
            self.facts.append(a)

        def add_edge(self, et, e, rel, it, ind, *a, **k):
            self.edges.append((e, rel, ind))

    kb = _KB()
    n = IW._ingest_paths(kb, {}, {"kit": "kit-a", "url_path": "/kit-a"}, "111111.example", "T", "ev")
    ok(n == 1 and ("111111.example", "serves_kit", "path_kit:kit-a") in kb.edges,
       "a distinctive kit produces a serves_kit edge on the path_kit indicator")
    kb2 = _KB()
    ok(IW._ingest_paths(kb2, {}, {"kit": None, "url_path": "/login"}, "a.example", "T", "ev") == 0
       and not kb2.edges,
       "a generic path produces NO KB edge (the base-rate control reaches the knowledge base)")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
