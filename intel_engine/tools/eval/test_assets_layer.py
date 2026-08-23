#!/usr/bin/env python3
"""Offline unit gate for the ASSET layer (wp_assets.py).

The fetches themselves are LIVE and can't run in the offline harness, but every
PARSER and every SELECTION rule is pure and must be gated:

  * bundle selection — third-party libs skipped, off-site scripts skipped,
    config/env names prioritized over hashed builds over entry points
  * source maps — sourceMappingURL resolution, sources[] → developer username /
    internal project root, node_modules and CI-runner accounts rejected
  * API endpoints — off-apex backend vs same-site backend vs analytics noise,
    build-time env vars (the white-label tenant tell), websockets, graphql
  * well-known files — ads.txt publisher rows, robots.txt, sitemap, security.txt,
    apple-app-site-association team/bundle ids

All values below are synthetic placeholders (example.com / Operator A / pub-000…)
per the repo CLAUDE.md RULE 1 — no case data in tracked files.

Run standalone or via run_eval.py (which imports and executes check()).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "WebPivot", "tools"))
import wp_assets as a  # noqa: E402


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- bundle selection -------------------------------------------------------
    srcs = [
        "/assets/config.js",                       # priority 3 — config name
        "/assets/index-B3GD2NjP.js",               # priority 2 — hashed build
        "/js/main.js",                             # priority 1 — entry
        "/js/misc.js",                             # priority 0
        "https://cdn.example.net/jquery.min.js",   # off-site → skipped
        "/vendor/bootstrap.bundle.min.js",         # known library → skipped
    ]
    chosen, skipped = a.select_bundles(srcs, "https://site-a.example/", "site-a.example")
    names = [u.rsplit("/", 1)[-1] for u in chosen]
    ok(names[0] == "config.js", "config.js is fetched first")
    ok(names[1] == "index-B3GD2NjP.js", "hashed build ranks above plain entry point")
    ok("jquery.min.js" not in " ".join(names), "off-site script not fetched")
    ok("bootstrap.bundle.min.js" not in " ".join(names), "known library skipped")
    ok(any("third-party host" == s["reason"] for s in skipped), "off-site skip is reported")
    ok(any("library" in s["reason"] for s in skipped), "library skip is reported")
    # a cap must REPORT what it dropped, never silently truncate
    _, sk2 = a.select_bundles(srcs, "https://site-a.example/", "site-a.example", limit=2)
    ok(any("over --assets-max" in s["reason"] for s in sk2), "over-cap drops are reported")

    # --- source maps ------------------------------------------------------------
    js = 'var x=1;\n//# sourceMappingURL=index-B3GD2NjP.js.map\n'
    ok(a.sourcemap_url(js, "https://site-a.example/assets/index-B3GD2NjP.js")
       == "https://site-a.example/assets/index-B3GD2NjP.js.map",
       "sourceMappingURL resolves against the bundle URL")
    ok(a.sourcemap_url("var x=1;", "https://site-a.example/a.js") is None,
       "no sourceMappingURL → None")

    smap = json.dumps({
        "version": 3,
        "sources": [
            "webpack://internal-kit-name/./src/App.vue",
            "webpack://internal-kit-name/./node_modules/axios/index.js",
            "/Users/operator-a/projects/internal-kit-name/src/api.js",
            "/home/builder/ci/src/x.js",
        ],
        "sourcesContent": ["<template/>"],
    })
    sm = a.parse_sourcemap(smap)
    ok(sm is not None, "valid source map parses")
    ok("operator-a" in sm["usernames"], "developer username extracted from /Users/ path")
    ok("builder" not in sm["usernames"], "CI-runner account rejected as a username")
    ok("internal-kit-name" in sm["project_roots"], "internal project root extracted")
    ok(all("node_modules" not in p for p in sm["dev_paths"]), "node_modules excluded from dev paths")
    ok(sm["has_sources_content"] is True, "sourcesContent flagged (original source recoverable)")
    ok(a.parse_sourcemap('{"not":"a map"}') is None, "non-sourcemap JSON rejected")
    ok(a.parse_sourcemap("not json at all") is None, "non-JSON body rejected")

    # Windows build machine, JSON-escaped separators
    winmap = json.dumps({"version": 3, "sources": ["C:\\Users\\Operator B\\proj\\src\\main.ts"]})
    ok("Operator B" in (a.parse_sourcemap(winmap) or {}).get("usernames", []),
       "windows C:\\Users\\<dev> path yields the username")

    # --- API endpoints ----------------------------------------------------------
    bundle = """
    axios.create({baseURL:"https://api.backend-x.example/v1"});
    var s = {VUE_APP_BRAND:"tenant-a",VUE_APP_API:"https://api.backend-x.example",
             REACT_APP_DEBUG:"false",VUE_APP_EMPTY:""};
    var sock = "wss://ws.backend-x.example/stream";
    var gq = "https://api.backend-x.example/graphql";
    var own = "https://api.site-a.example/internal";
    var noise = "https://www.googletagmanager.com/gtm.js";
    var sentry = "https://o0000000.ingest.sentry.io/1234";
    """
    api = a.extract_api_endpoints(bundle, "site-a.example")
    ok(any("api.backend-x.example" in u for u in api["api_bases"]),
       "off-apex backend captured from baseURL")
    ok(any("api.site-a.example" in u for u in api["same_site_api"]),
       "same-site backend classified separately, not as a cross-site pivot")
    ok(not any("googletagmanager" in u for u in api["api_bases"]),
       "analytics/CDN endpoint rejected as a backend")
    ok(not any("sentry.io" in u for u in api["api_bases"]),
       "sentry ingest rejected as a backend")
    ok(api["build_env"].get("VUE_APP_BRAND") == ["tenant-a"],
       "build-time tenant/brand token extracted (the white-label tell)")
    ok("REACT_APP_DEBUG" not in api["build_env"], "boolean-valued env var dropped")
    ok("VUE_APP_EMPTY" not in api["build_env"], "empty-valued env var dropped")
    ok(any("ws.backend-x.example" in w for w in api["websockets"]), "websocket endpoint captured")
    ok(any("/graphql" in g for g in api["graphql"]), "graphql endpoint captured")

    # --- extractors re-pointed at bundle text -----------------------------------
    jsd = a.extract_from_bundles(
        'var c={ga:"G-XXXXXXXXXX",tg:"https://t.me/examplechannel",'
        'mail:"operator@example.com"};', "site-a.example")
    ok("G-XXXXXXXXXX" in (jsd["trackers"].get("google_analytics_ga4") or []),
       "GA4 id found in bundle source (not just HTML)")
    ok(any(t["handle"] == "examplechannel" for t in jsd["telegram"]),
       "telegram channel found in bundle source")
    ok("operator@example.com" in jsd["emails"], "email found in bundle source")
    ok(a.extract_from_bundles("", "x.example") == {}, "empty bundle text → no artifacts")

    # --- SPA route table --------------------------------------------------------
    # Recovered from the already-fetched bundle: zero extra requests, no path brute-forcing.
    vue_bundle = """
    import {createRouter,createWebHistory} from "vue-router";
    const r=[{path:"/",name:"home",component:H},
             {path:"/deposit",name:"userDeposit",component:D},
             {path:"/withdraw",name:"userWithdraw",component:W},
             {path:"/admin/console",name:"adminConsole",component:A},
             {path:"/invite/:code",name:"referralLanding",component:I},
             {path:"/:pathMatch(.*)*",name:"nf",component:N}];
    const icon='<svg><path d="M0 0L10 10z"/></svg>';
    const ico2={path:"M12,4 a8,8 0 1,0 0.1,0"};
    const asset={path:"/assets/app.css"};
    """
    rt = a.extract_spa_routes(vue_bundle)
    ok(rt.get("router") == "vue-router", "vue-router detected from runtime markers")
    ok("/deposit" in rt["routes"] and "/admin/console" in rt["routes"],
       "application routes recovered from the bundle")
    ok("/" not in rt["routes"], "root route dropped (carries no information)")
    ok(not any("pathMatch" in r for r in rt["routes"]), "vue catch-all route dropped")
    ok(not any(r.startswith("/M") or "L10" in r for r in rt["routes"]),
       "SVG icon path data rejected (the main false-positive source)")
    ok(not any("app.css" in r for r in rt["routes"]), "bundled asset path rejected as a route")
    ok("/admin/console" in rt["admin_routes"], "admin/operator route classified")
    ok("/deposit" in rt["funnel_routes"] and "/withdraw" in rt["funnel_routes"],
       "money/funnel routes classified")
    ok("/admin/console" not in rt["funnel_routes"], "admin route not miscounted as funnel")
    ok("referralLanding" in rt["route_names"], "named routes captured")
    ok(len(rt["signature"]) == 64, "route signature is a sha256")

    # Signature must be order-independent (bundlers reshuffle declaration order between builds)
    shuffled = """
    const r=[{path:"/admin/console"},{path:"/withdraw"},{path:"/invite/:code"},{path:"/deposit"}];
    createRouter();
    """
    inorder = """
    const r=[{path:"/deposit"},{path:"/invite/:code"},{path:"/withdraw"},{path:"/admin/console"}];
    createRouter();
    """
    ok(a.extract_spa_routes(shuffled)["signature"] == a.extract_spa_routes(inorder)["signature"],
       "route signature is order-independent (same app, reshuffled build)")
    # A genuinely different route SET (one extra route) must not collide with the original.
    different = """
    const r=[{path:"/deposit"},{path:"/invite/:code"},{path:"/withdraw"},
             {path:"/admin/console"},{path:"/kyc/upload"}];
    createRouter();
    """
    ok(a.extract_spa_routes(different)["signature"] != a.extract_spa_routes(inorder)["signature"],
       "a DIFFERENT route inventory yields a different signature")

    # Angular declares routes without a leading slash — must normalize to the same signature
    ng = 'RouterModule.forRoot([{path:"deposit"},{path:"withdraw"},{path:"admin/console"}])'
    vu = 'createRouter([{path:"/deposit"},{path:"/withdraw"},{path:"/admin/console"}])'
    ok(a.extract_spa_routes(ng)["signature"] == a.extract_spa_routes(vu)["signature"],
       "angular (no leading slash) normalizes to the same signature as vue")

    # Next.js ships a build manifest instead of a router literal
    nx = a.extract_spa_routes('self.__BUILD_MANIFEST={sortedPages:["/","/kyc","/admin"]}')
    ok("/kyc" in nx["routes"] and nx["router"] == "next.js", "next.js sortedPages inventory read")
    nxd = a.extract_spa_routes("", '<script id="__NEXT_DATA__">{"page":"/wallet"}</script>')
    ok("/wallet" in nxd["routes"], "next.js __NEXT_DATA__ page read from HTML")

    # Fewer than 3 routes is not a distinctive fingerprint
    ok(a.extract_spa_routes('const r=[{path:"/deposit"}];createRouter();')["signature"] is None,
       "a 1-route app gets no signature (not distinctive)")
    ok(a.extract_spa_routes("var x=1;") == {}, "a non-SPA page yields no route table")
    ok(a.extract_spa_routes('<svg><path d="M0 0L10 10"/></svg>') == {},
       "a page of pure SVG yields no routes")

    # --- regression: UNQUOTED html attributes -----------------------------------
    # Every HTML minifier (the default in a vue-cli/webpack/vite production build) drops
    # quotes around attribute values. A quote-mandatory SCRIPT_SRC_RE returned NOTHING on
    # those pages, so the whole asset layer (and third_party_hosts, and the urlscan resource
    # reverse) went silently empty on exactly the built-SPA kits that matter most.
    import wp_extract as wx  # noqa: E402
    minified = ('<script src=/static/js/app.6c9e4bdf.js></script>'
                '<script src="/static/js/quoted.js"></script>'
                "<script src='/static/js/single.js'></script>"
                '<link href=/static/css/app.css rel=stylesheet>')
    got = wx.SCRIPT_SRC_RE.findall(minified)
    ok("/static/js/app.6c9e4bdf.js" in got, "UNQUOTED script src is captured (regression)")
    ok("/static/js/quoted.js" in got, "double-quoted script src still captured")
    ok("/static/js/single.js" in got, "single-quoted script src still captured")
    ok(all(">" not in g and '"' not in g for g in got),
       "captured src never swallows the tag/quote boundary")
    ok("/static/css/app.css" in wx.HREF_IN_TAG_RE.findall(minified),
       "UNQUOTED href is captured (regression)")

    # --- ads.txt ----------------------------------------------------------------
    ads = a.parse_ads_txt(
        "# comment line\n"
        "google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0\n"
        "exchange.example, 12345, RESELLER\n"
        "garbage line without commas\n")
    ok(len(ads) == 2, "ads.txt parses exactly the two valid rows")
    ok(ads[0]["publisher_id"] == "pub-0000000000000000", "publisher id parsed")
    ok(ads[0]["relationship"] == "DIRECT", "relationship parsed")
    ok(ads[0]["cert_authority_id"] == "f08c47fec0942fa0", "certification authority id parsed")
    ok(ads[1]["cert_authority_id"] is None, "optional cert authority id may be absent")

    # --- robots / sitemap / security.txt ----------------------------------------
    rb = a.parse_robots("User-agent: *\nDisallow: /admin/\nDisallow: /staging\n"
                        "Sitemap: /sitemap.xml\n", "https://site-a.example")
    ok(rb["disallow"] == ["/admin/", "/staging"], "robots Disallow paths parsed")
    ok(rb["sitemaps"] == ["https://site-a.example/sitemap.xml"], "relative Sitemap resolved")

    sm2 = a.parse_sitemap("<urlset><url><loc>https://site-a.example/a</loc></url>"
                          "<url><loc>https://site-a.example/b</loc></url></urlset>")
    ok(sm2["count"] == 2 and not sm2["is_index"], "sitemap urls counted")
    ok(a.parse_sitemap("<sitemapindex><sitemap><loc>https://site-a.example/s1.xml</loc>"
                       "</sitemap></sitemapindex>")["is_index"], "sitemap index detected")

    st = a.parse_security_txt("Contact: mailto:security@example.com\nPolicy: https://x.example/p\n")
    ok(st["contacts"] == ["security@example.com"], "security.txt mailto: stripped")
    ok(st["fields"].get("policy") == "https://x.example/p", "security.txt Policy field kept")

    # --- apple-app-site-association ---------------------------------------------
    aasa = a.parse_aasa(json.dumps({
        "applinks": {"details": [{"appID": "ABCDE12345.com.example.app", "paths": ["*"]}]}}))
    ok(aasa["team_ids"] == ["ABCDE12345"], "apple team id extracted")
    ok(aasa["bundle_ids"] == ["com.example.app"], "ios bundle id extracted")
    ok(a.parse_aasa("{}") == {"app_ids": [], "team_ids": [], "bundle_ids": []}
       or not a.parse_aasa("{}")["app_ids"], "empty AASA yields no app ids")
    ok(a.parse_aasa("not json") is None, "invalid AASA rejected")

    # --- toggles are honoured (a run must never silently collect when told not to) ---
    _saved = (a.COLLECT_ASSETS, a.COLLECT_WELL_KNOWN)
    try:
        a.COLLECT_ASSETS = a.COLLECT_WELL_KNOWN = False
        res = a.collect(["https://site-a.example/a.js"], "https://site-a.example/",
                        "site-a.example")
        ok(res["collected"] == [] and res["well_known"] == {},
           "toggles off → nothing fetched")
        ok(res["coverage"]["bundles"] == "off" and res["coverage"]["well_known"] == "off",
           "coverage records that we did NOT look (absence stays visible)")
    finally:
        a.COLLECT_ASSETS, a.COLLECT_WELL_KNOWN = _saved

    return passed, failed, out


if __name__ == "__main__":
    ps, fs, lines = check()
    for status, label in lines:
        mark = "\033[32m✔\033[0m" if status == "ok" else "\033[31mx\033[0m"
        print(f"  {mark} {label}")
    print(f"\n{ps}/{ps+fs} assertions passed" + ("" if not fs else f" — {fs} FAILED"))
    sys.exit(1 if fs else 0)
