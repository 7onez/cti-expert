#!/usr/bin/env python3
"""
test_liveness.py — the gate on the liveness guardrail (WebPivot/tools/wp_liveness.py).

Run:  python3 tests/test_liveness.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Liveness used to be a status-code check, and a status-code check is wrong in both directions.
Each assertion below corresponds to a way a case gets corrupted SILENTLY:

  * A 200 that is a parking page / server default page / suspension notice / soft-404 must NOT
    come back `live`. If it does, the collector fingerprints a template shared by millions of
    unrelated domains and the KB grows a cluster that does not exist.
  * A 404 / 403 / 5xx / bot wall must NOT come back dead. If it does, a registered, resolving,
    operator-controlled name is deleted from the case and never re-checked.
  * Every state where the name is still controlled must set `reuse_watch`, because operators
    park between campaigns and rebuild after takedowns while KEEPING the domain.
  * Only NXDOMAIN may set `dead`.
  * A `live` verdict with no body read must be refused (`require_content_for_live`).

Everything here is OFFLINE — synthetic responses passed straight to classify(). No network,
no fixtures to rot, and no case data (contributor RULE 1).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))

import wp_liveness as L  # noqa: E402


def page(body, chars=3000):
    """A believable HTML document with `body` embedded, padded past the thin-content floor."""
    return f"<html><head><title>t</title></head><body>{body}{'word ' * (chars // 5)}</body></html>"


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

    # --- 1. HTTP 200 IS NOT ALIVE — a success status over boilerplate content ---------------
    for expect, body, why in (
        ("parked", page("This domain is parked and may be for sale. Buy this domain today."),
         "registrar parking page"),
        ("suspended", page("Account Suspended — This account has been suspended."),
         "hosting suspension notice"),
        ("default_page", page("Welcome to nginx! If you see this page, the nginx web server is "
                              "successfully installed."), "server default page"),
        ("soft_404", page("404 Not Found — the page you are looking for does not exist."),
         "not-found page served with HTTP 200"),
    ):
        v = L.classify(url="site-a.example", final_url="https://site-a.example/", status=200,
                       body=body, ips=["203.0.113.10"])
        ok(v["state"] == expect, f"HTTP 200 + {why} -> {expect} (got {v['state']})")
        ok(v["live"] is not True, f"  …a {why} is never reported LIVE")
        ok(v["reuse_watch"] is True, f"  …a {why} sets reuse_watch — the name is still controlled")
        ok(v["dead"] is False, f"  …a {why} is never dead")

    v = L.classify(url="site-a.example", status=200,
                   body=page("Real product copy for a real site."), ips=["203.0.113.10"])
    ok(v["state"] == "live", f"HTTP 200 + ordinary content -> live (got {v['state']})")
    ok(v["live"] is True and v["reuse_watch"] is False, "  …live sets live=True, reuse_watch=False")

    v = L.classify(url="site-a.example", status=200, body=page("Hello."), ips=["203.0.113.10"],
                   nameservers=["ns1.sedoparking.com", "ns2.sedoparking.com"])
    ok(v["state"] == "parked",
       f"parking NAMESERVERS alone -> parked, even when the page gives nothing away "
       f"(got {v['state']})")

    # --- 2. 4xx / 5xx / BOT WALL IS NOT DEAD — the server answered --------------------------
    for status, expect in ((404, "not_found"), (410, "not_found"), (403, "forbidden"),
                           (401, "forbidden"), (500, "server_error"), (503, "server_error")):
        v = L.classify(url="site-a.example", status=status, body=page("Error."),
                       ips=["203.0.113.10"])
        ok(v["state"] == expect, f"HTTP {status} -> {expect} (got {v['state']})")
        ok(v["dead"] is False, f"  HTTP {status} is NOT dead — a status code cannot kill a name")
        ok(v["reuse_watch"] is True, f"  HTTP {status} sets reuse_watch")

    v = L.classify(url="site-a.example", status=403,
                   body=page("Just a moment... Checking your browser before accessing the site. "
                             "Attention Required! | Cloudflare"), ips=["203.0.113.10"])
    ok(v["state"] == "blocked", f"Cloudflare interstitial -> blocked (got {v['state']})")
    ok(v["live"] is None, "  blocked is live=None — the page was never seen")
    ok(v["dead"] is False, "  blocked is never dead")

    # The widget carve-out is scoped to SERVED pages: a 4xx carrying a wall marker is a wall no
    # matter how verbose (Cloudflare 1020 copy), while a 200 with the marker buried in thousands
    # of chars of real copy is a captcha badge on a page that WAS seen.
    v = L.classify(url="site-a.example", status=403,
                   body=page("Attention Required! | Cloudflare. Why have I been blocked? ", chars=4000),
                   ips=["203.0.113.10"])
    ok(v["state"] == "blocked",
       f"verbose 403 block page (> widget threshold) is still blocked (got {v['state']})")
    v = L.classify(url="site-a.example", status=200,
                   body=page("Verify you are human to sign in. Welcome to our shop. ", chars=4000),
                   ips=["203.0.113.10"])
    ok(v["state"] != "blocked",
       f"wall marker on a served page with thousands of chars of copy is a WIDGET (captcha badge), "
       f"the page WAS seen -> not blocked (got {v['state']})")

    v = L.classify(url="site-a.example", status=404,
                   body=page("This domain is parked. Buy this domain."), ips=["203.0.113.10"])
    ok(v["state"] == "parked",
       f"HTTP 404 over a parking template -> parked, not merely not_found (got {v['state']})")

    # --- 3. ONLY DNS EVIDENCES A DEAD NAME --------------------------------------------------
    v = L.classify(url="site-a.example", ips=[],
                   error="gaierror: [Errno 8] nodename nor servname provided, or not known")
    ok(v["state"] == "unresolved", f"NXDOMAIN -> unresolved (got {v['state']})")
    ok(v["dead"] is True, "  unresolved is the ONLY state allowed to report dead")

    v = L.classify(url="site-a.example", ips=["203.0.113.10"], error="TimeoutError: timed out")
    ok(v["state"] == "no_http", f"resolves but no HTTP -> no_http (got {v['state']})")
    ok(v["dead"] is False, "  no_http is NOT dead — the name is registered and pointed somewhere")
    ok(v["reuse_watch"] is True, "  no_http sets reuse_watch")

    dead_states = sorted(k for k, s in L.STATES.items() if isinstance(s, dict) and s.get("dead"))
    ok(dead_states == ["unresolved"],
       f"no HTTP-derived state is marked dead in liveness.json (dead: {dead_states})")

    # --- 4. THE GUARDRAIL POLICY — a verdict cannot rest on thin evidence -------------------
    v = L.classify(url="site-a.example", status=200, body=None, ips=["203.0.113.10"])
    ok(v["state"] != "live",
       f"HTTP 200 with NO body read is never 'live' — require_content_for_live (got {v['state']})")

    v = L.classify(url="site-a.example", status=200, body="<html><body></body></html>",
                   ips=["203.0.113.10"])
    ok(v["state"] == "empty", f"HTTP 200 with an empty body -> empty (got {v['state']})")
    ok(v["live"] is None, "  empty is live=None (may be a client-rendered kit), not live=False")

    v = L.classify(url="site-a.example", status=200,
                   body="<html><body><script>x=1</script></body></html>" + "<div></div>" * 200,
                   ips=["203.0.113.10"])
    ok(v["state"] == "empty",
       f"HTML with no visible text -> empty, not live (got {v['state']})")

    v = L.classify(url="site-a.example", ips=[], error="")
    ok(v["state"] == "unknown" and v["dead"] is False,
       f"no status and no DNS evidence -> unknown, never dead (got {v['state']})")

    v = L.classify(url="site-a.example", status=200, final_url="https://elsewhere.example/landing",
                   body=page("Some content on another host."), ips=["203.0.113.10"])
    ok(v["state"] == "redirected_offsite",
       f"offsite redirect -> redirected_offsite (got {v['state']})")

    v = L.classify(url="site-a.example", final_url="https://www.site-a.example/", status=200,
                   body=page("Real content."), ips=["203.0.113.10"])
    ok(v["state"] == "live",
       f"same-registrable redirect (www) is still live (got {v['state']})")

    ok(L.classify(url="site-a.example", ips=["203.0.113.10"],
                  error="TimeoutError")["confident"] is False,
       "a one-signal verdict is marked unconfident, so a report can hedge")
    ok(L.classify(url="site-a.example", status=200, body=page("Real content."),
                  ips=["203.0.113.10"])["confident"] is True,
       "a multi-signal verdict is marked confident")

    # --- 5. DATA FILE — every state the classifier can emit is documented -------------------
    emitted = {"live", "parked", "default_page", "suspended", "soft_404", "not_found",
               "forbidden", "blocked", "empty", "redirected_offsite", "server_error",
               "no_http", "unresolved", "unknown"}
    missing = sorted(emitted - set(L.STATES))
    ok(not missing, f"liveness.json documents every emitted state (missing: {missing})")
    undocumented = sorted(k for k, s in L.STATES.items()
                          if not isinstance(s, dict) or not s.get("note"))
    ok(not undocumented, f"every state carries an analyst note (missing: {undocumented})")
    ok(len(L.PARKING_MARKERS) > len(L._LIVE_FALLBACK["parking_markers"]),
       f"markers loaded from JSON, not the embedded fallback ({len(L.PARKING_MARKERS)} loaded)")
    ok("alert" not in L.visible_text("<html><script>alert(1)</script><p>hello</p></html>"),
       "visible_text strips script/style so a JS blob is not counted as page text")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
