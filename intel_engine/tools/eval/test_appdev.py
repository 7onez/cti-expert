#!/usr/bin/env python3
"""Regression: wp_appdev (keyless app-store developer lookup) + BinaryPivot's Apple team ID.

Offline: the store HTTP seam (`wp_appdev._fetch`) is stubbed with synthetic Play HTML and iTunes
JSON fixtures. Defends: developer name / legal name / email / website parsed from a Play listing;
the developer's other apps from the developer page; iTunes artistName / artistId / sellerName /
other apps; a developer website on the case apex is an OWNER link (rung app.developer_url →
owner) while an off-case website and the email stay seed candidates (auto_seed false); malformed
pages / empty lookups return None and a transport failure returns {"error"} — never an exception;
a Mach-O signing identity yields its 10-char team ID as indicator apple_team (rung app.apple_team →
owner) and a non-Mach-O carrying the same bytes does not. Synthetic data only (example.com)."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for _p in (os.path.join(ROOT, "WebPivot", "tools"), os.path.join(ROOT, "BinaryPivot", "tools"),
           os.path.join(ROOT, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_appdev as ad  # noqa: E402
import analyze_artifact as bp  # noqa: E402
import selector_types  # noqa: E402

PKG = "com.example.demoapp"

_PLAY_HTML = """<html><head><title>Demo App - Apps on Google Play</title>
<script>var x = "mailto:script@example.net";</script></head><body>
<h1>Demo App</h1>
<div><a href="/store/apps/dev?id=1234567890123456789"><span>Example Demo Studio</span></a></div>
<div><a href="mailto:support@google.com">Contact Google Play</a></div>
<section><header><h2>App support</h2></header>
  <a href="https://www.example.com/contact"><div>Website</div><div>www.example.com</div></a>
  <a href="mailto:dev@example.com"><div>Email</div><div>dev@example.com</div></a>
  <a href="https://policies.google.com/privacy"><div>Privacy Policy</div></a>
</section>
<section><header><div>About the developer</div></header>
  <div>Example Demo Ltd</div>
  <div>dev@example.com</div>
  <div>1 Example Street, Example City</div>
  <div>+1 555 0100</div>
</section>
<section><h2>Similar apps</h2>
  <a href="/store/apps/details?id=org.other.app">Other</a>
  <a href="/store/apps/dev?id=999">Someone Else Studio</a>
</section>
</body></html>"""

_PLAY_DEV_HTML = """<html><body><h1>Example Demo Studio</h1>
<a href="/store/apps/details?id=com.example.demoapp">Demo App</a>
<a href="/store/apps/details?id=com.example.second">Second</a>
<a href="/store/apps/details?id=com.example.third&amp;hl=en">Third</a>
<a href="/store/apps/details?id=com.example.second">Second again</a>
</body></html>"""

_ITUNES_APP = json.dumps({"resultCount": 1, "results": [{
    "wrapperType": "software", "trackId": 1000000001, "trackName": "Demo App",
    "bundleId": "com.example.demoapp", "artistId": 2000000002,
    "artistName": "Example Demo Studio", "sellerName": "Example Demo Ltd",
    "sellerUrl": "https://shop.example.com/", "artistViewUrl":
    "https://apps.apple.com/us/developer/example-demo-studio/id2000000002"}]})

_ITUNES_ARTIST = json.dumps({"resultCount": 3, "results": [
    {"wrapperType": "artist", "artistId": 2000000002, "artistName": "Example Demo Studio"},
    {"wrapperType": "software", "trackId": 1000000001, "trackName": "Demo App",
     "bundleId": "com.example.demoapp"},
    {"wrapperType": "software", "trackId": 1000000003, "trackName": "Second App",
     "bundleId": "com.example.second"}]})


def _stub(routes):
    """_fetch replacement: first route whose substring is in the URL answers (text, err, status)."""
    calls = []

    def fake(url, timeout=None, accept=None):
        calls.append(url)
        for frag, resp in routes:
            if frag in url:
                return resp
        return None, "HTTP 404", 404
    fake.calls = calls
    return fake


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    real_fetch = ad._fetch
    try:
        # --- Play listing parse -----------------------------------------------------------
        dev = ad.parse_play_details(_PLAY_HTML, PKG) or {}
        ok(dev.get("name") == "Example Demo Studio", "play: developer display name parsed")
        ok(dev.get("legal_name") == "Example Demo Ltd", "play: About-the-developer legal name parsed")
        ok(dev.get("email") == "dev@example.com", "play: developer email parsed (store mailto skipped)")
        ok(dev.get("website") == "https://www.example.com/contact",
           "play: developer website parsed (store policy link skipped)")
        ok(dev.get("developer_id") == "1234567890123456789"
           and dev.get("developer_page", "").startswith("https://play.google.com/store/apps/dev?id="),
           "play: own developer link chosen over a similar app's developer")

        # --- Play end-to-end, owner link on the case apex -----------------------------------
        ad._fetch = _stub([("/store/apps/details", (_PLAY_HTML, None, 200)),
                           ("/store/apps/dev", (_PLAY_DEV_HTML, None, 200))])
        r = ad.play_developer(PKG, case_domains=["example.com"]) or {}
        ok([a["package"] for a in r.get("other_apps") or []]
           == ["com.example.second", "com.example.third"],
           "play: other apps of the account from the developer page (self excluded, deduped)")
        owners = r.get("owner_links") or []
        ok(len(owners) == 1 and owners[0]["value"] == "example.com" and owners[0]["owner_link"]
           and owners[0]["rung_class"] == "app.developer_url" and owners[0]["rung"] == "owner",
           "play: developer website on the case apex is an owner link (app.developer_url → owner)")
        emails = [c for c in r.get("seed_candidates") or [] if c["type"] == "email"]
        ok(len(emails) == 1 and emails[0]["value"] == "dev@example.com"
           and emails[0]["auto_seed"] is False,
           "play: developer email is a seed candidate, never auto-seeded")

        r2 = ad.play_developer(PKG, case_domains=["site-a.example"]) or {}
        ok(not r2.get("owner_links")
           and any(c["type"] == "domain" and c["value"] == "example.com" and not c["owner_link"]
                   and c["auto_seed"] is False for c in r2.get("seed_candidates") or []),
           "play: off-case developer website is a candidate, not an owner link")
        ok(selector_types.rung_for("app.developer_url") == "owner"
           and selector_types.rung_for("app.apple_team") == "owner",
           "rungs.json: app.developer_url and app.apple_team are owner")

        # --- App Store via iTunes lookup ------------------------------------------------------
        ad._fetch = _stub([("entity=software", (_ITUNES_ARTIST, None, 200)),
                           ("lookup?id=1000000001", (_ITUNES_APP, None, 200)),
                           ("lookup?bundleId=", (_ITUNES_APP, None, 200))])
        a = ad.lookup("id1000000001", case_domains=["www.example.com"]) or {}
        d = a.get("developer") or {}
        ok(a.get("store") == "appstore" and d.get("name") == "Example Demo Studio"
           and d.get("artist_id") == 2000000002 and d.get("seller_name") == "Example Demo Ltd",
           "appstore: artistName / artistId / sellerName parsed")
        ok([x["bundle_id"] for x in a.get("other_apps") or []] == ["com.example.second"],
           "appstore: artist's other apps (artist row and self excluded)")
        ok(any(o["value"] == "example.com" and o["rung"] == "owner" for o in a.get("owner_links") or []),
           "appstore: sellerUrl on the case apex is an owner link")
        b = ad.lookup(PKG, store="appstore") or {}
        ok(b.get("store") == "appstore" and any("bundleId=" in u for u in b.get("source_urls") or []),
           "appstore: dotted id with store=appstore uses the bundleId lookup")
        ok(ad.normalise_query("https://play.google.com/store/apps/details?id=" + PKG)
           == ("play", PKG, False), "query: a Play URL normalises to its package")

        # --- malformed / empty / transport failure -------------------------------------------
        ok(ad.parse_play_details("<html><body><p>Something went wrong</p></body></html>") is None,
           "malformed: Play page without a developer block → None")
        ok(ad.parse_play_details("") is None and ad.parse_play_details(None) is None,
           "malformed: empty Play body → None")
        ok(ad.parse_itunes_lookup("<html>not json</html>") is None,
           "malformed: non-JSON iTunes body → None")
        ok(ad.parse_itunes_lookup('{"resultCount":0,"results":[]}') is None,
           "malformed: empty iTunes results → None")
        ad._fetch = _stub([("/store/apps/details", ("<html><div>oops</div>", None, 200))])
        ok(ad.play_developer(PKG) is None, "malformed: garbage Play page end-to-end → None")
        ad._fetch = _stub([])
        ok(ad.play_developer(PKG) is None, "Play 404 (no such app) → None")
        ad._fetch = _stub([("lookup", ('{"resultCount":0,"results":[]}', None, 200))])
        ok(ad.appstore_developer("1000000001") is None, "iTunes no results → None")
        ad._fetch = lambda url, timeout=None, accept=None: (None, "URLError: offline", None)
        e = ad.play_developer(PKG)
        ok(isinstance(e, dict) and "error" in e, "transport failure → {'error'}, never raises")
        ok("error" in (ad.play_developer("not a package") or {}), "bad package name → {'error'}")
    finally:
        ad._fetch = real_fetch

    # --- BinaryPivot: Apple team ID from a Mach-O signing identity -------------------------------
    ident = b"Developer ID Application: Example Person (ABCDE12345)"
    macho = (b"\xcf\xfa\xed\xfe" + b"\x00" * 60 + b"\x30\x82\x01\x00\x0c\x37" + ident
             + b"\x00" * 32 + b"Apple Code Signing Certification Authority" + b"\x00" * 64
             + b"Apple Distribution: Example Person (ABCDE12345)" + b"\x00" * 16)
    teams = bp.apple_team_ids(macho)
    ok([t["team_id"] for t in teams] == ["ABCDE12345"]
       and teams[0]["rung_class"] == "app.apple_team"
       and teams[0]["identity"] == ident.decode(),
       "binary: signing identity yields the team ID (deduped, Apple CA string ignored)")
    ok(bp.apple_team_ids(b"\xcf\xfa\xed\xfe" + b"\x00" * 200) == [],
       "binary: unsigned Mach-O → no team ID")
    tmp = tempfile.mkdtemp()
    try:
        mpath = os.path.join(tmp, "demo.bin")
        with open(mpath, "wb") as fh:
            fh.write(macho)
        res = bp.analyze(mpath)
        tr = res["artifacts"]["trackers"]
        piv = [p for p in res["pivots"] if p["kind"] == "app:apple_team"]
        ok(tr.get("apple_team") == ["ABCDE12345"], "binary: apple_team folded into trackers")
        ok(len(piv) == 1 and piv[0]["value"] == "ABCDE12345"
           and piv[0].get("rung_class") == "app.apple_team",
           "binary: app:apple_team pivot carries rung class app.apple_team")
        epath = os.path.join(tmp, "demo.elf")
        with open(epath, "wb") as fh:
            fh.write(b"\x7fELF" + macho[4:])
        res2 = bp.analyze(epath)
        ok("apple_team" not in res2["artifacts"]["trackers"]
           and not any(p["kind"] == "app:apple_team" for p in res2["pivots"]),
           "binary: non-Mach-O behaviour unchanged (no apple_team)")
    finally:
        for f in os.listdir(tmp):
            os.unlink(os.path.join(tmp, f))
        os.rmdir(tmp)

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
