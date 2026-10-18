#!/usr/bin/env python3
"""Regression: the run-scoped Wayback (web.archive.org / archive.org) circuit breaker
(WebPivot/tools/wp_wayback_guard.py), the egress pacer + cooldown, the wp_wayback client's
endpoint failover / resolver, and their call sites.

WHAT THIS PROTECTS
------------------
A Wayback FAILURE is the archive not answering (network error, timeout, connection
refused/reset, proxy CONNECT failure, HTTP 429, HTTP 5xx) — never a valid answer that there is
simply no capture. After 20 consecutive FAILURES within one run, every further Wayback call site
must return its normal tri-state skip WITHOUT making a request; any success resets the streak; a
fresh $INTEL_RUN_ID starts a fresh counter; parallel processes sharing a run id share the counter;
and a tripped skip must read as a collection GAP (never queried), not as "no snapshots" — so it
must not be memoisable by wp_casememo and must not satisfy wp_exhaust's "archive" layer.

The client layer: an index endpoint that answers 503 must fail over to the next one; an archive
that never answers must surface as a gap (never "no history"); the id_ redirect names the capture
(even when that capture's own playback 5xx's); a refused connection / 429 must cool that HOST down
machine-wide so no further request is made, without cooling a different host; the pacer spaces
same-lane requests and refuses a slot past the caller's budget.

Fully offline: every network seam is stubbed; no real HTTP call is made. Synthetic data only.

Run:  python3 tests/test_wayback_breaker.py
"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
import uuid

os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

# the proxy vars too: importing the collectors runs cti_proxy.install(), which exports the analyst's
# real pool; the per-exit cooldown keys on them, so each test starts on a known ("direct") exit.
_PROXY_KEYS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
_ENV_KEYS = ("WP_CASE_DIR", "INTEL_CASE", "INTEL_RUN_ID", "WAYBACK_FAIL_LIMIT",
             "WAYBACK_PACE_STATE", "WAYBACK_MIN_INTERVAL") + _PROXY_KEYS


class _Env:
    """Save/restore the breaker's env knobs around a test; each test gets its own temp state dir
    and its own run id so tests never see each other's counters."""

    def __init__(self, case_dir=None, run_id=None):
        self.case_dir = case_dir
        self.run_id = run_id if run_id is not None else uuid.uuid4().hex

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        if self.case_dir:
            os.environ["WP_CASE_DIR"] = self.case_dir
            # machine-wide pacer/cooldown state: isolated per test, spacing off unless a test opts in
            os.environ["WAYBACK_PACE_STATE"] = os.path.join(self.case_dir, "wayback_pace.json")
            os.environ["WAYBACK_MIN_INTERVAL"] = "0"
        if self.run_id:
            os.environ["INTEL_RUN_ID"] = self.run_id
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


class _FakeResp:
    """A minimal urlopen()-compatible context manager over a JSON payload."""

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_20_consecutive_failures_trip_and_21st_makes_no_request():
    import wp_wayback_guard as wg
    import wp_net

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        assert wg.blocked() is None, "clean state must not start blocked"
        for _ in range(20):
            wg.record(False, kind="cdx")
        reason = wg.blocked()
        assert reason and "20 consecutive failures" in reason, reason

        def _forbidden(*a, **k):
            raise AssertionError("network call made after the breaker tripped")

        saved = urllib.request.urlopen
        urllib.request.urlopen = _forbidden
        try:
            snap, ts = wp_net.wayback_closest("https://tripped.example/")
            assert (snap, ts) == (None, None)
        finally:
            urllib.request.urlopen = saved


def test_success_resets_the_streak():
    import wp_wayback_guard as wg

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        for _ in range(19):
            wg.record(False, kind="cdx")
        assert wg.blocked() is None, "19 failures must not trip a 20-limit breaker"
        wg.record(True, kind="cdx")
        for _ in range(19):
            wg.record(False, kind="cdx")
        assert wg.blocked() is None, "a success must reset the streak, not just decrement it"


def test_a_no_capture_answer_never_counts_as_a_failure():
    """wayback_closest() answered with a valid 'nothing here' (resolver 404 or an empty index),
    repeated well past the fail limit — none of that may ever trip the breaker."""
    import wp_wayback_guard as wg
    import wp_net

    def _fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "id_/" in url:                   # the real resolver answers 404 for a never-archived URL
            raise _http_error(url, 404)
        return _FakeResp(["timestamp,original,statuscode"])   # header row only: 0 real captures

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        saved = urllib.request.urlopen
        urllib.request.urlopen = _fake_urlopen
        try:
            for _ in range(25):        # well past the 20-failure limit
                snap, ts = wp_net.wayback_closest("https://never-archived.example/")
                assert (snap, ts) == (None, None)
                assert wg.blocked() is None, "a valid 'no capture' answer must never trip the breaker"
        finally:
            urllib.request.urlopen = saved


def test_a_new_run_id_starts_fresh():
    import wp_wayback_guard as wg

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp, run_id="run-A"):
        for _ in range(20):
            wg.record(False, kind="cdx")
        assert wg.blocked() is not None, "run-A should be tripped"
        os.environ["INTEL_RUN_ID"] = "run-B"
        assert wg.blocked() is None, "a different run id must start with a clean counter"


def test_two_processes_sharing_a_run_id_share_the_counter():
    """Two separate subprocesses, same $WP_CASE_DIR and $INTEL_RUN_ID, each recording failures:
    the SECOND one's failures must land on top of the first's, not a fresh in-process counter."""
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, WP_CASE_DIR=tmp, INTEL_RUN_ID="shared-run",
                   PYTHONPATH=WP + os.pathsep + os.environ.get("PYTHONPATH", ""))
        env.pop("WAYBACK_FAIL_LIMIT", None)
        code_a = "import wp_wayback_guard as wg\n" + "wg.record(False, kind='cdx')\n" * 12
        code_b = "import wp_wayback_guard as wg\n" + "wg.record(False, kind='cdx')\n" * 8
        for code in (code_a, code_b):
            r = subprocess.run([sys.executable, "-c", code], env=env,
                               capture_output=True, text=True, timeout=30)
            assert r.returncode == 0, r.stderr

        check = "import wp_wayback_guard as wg\nprint(wg.blocked() or 'NOT-BLOCKED')\n"
        r = subprocess.run([sys.executable, "-c", check], env=env,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        out = r.stdout.strip()
        assert out != "NOT-BLOCKED", (
            "12 + 8 = 20 consecutive failures split across two processes sharing a run id "
            "must trip the same counter")
        assert "20 consecutive failures" in out, out


def test_tripped_skip_is_not_memoised_and_reads_as_a_gap_not_empty():
    import wp_casememo
    import wp_exhaust

    skip = {"skipped": "Wayback skipped for the rest of this run after 20 consecutive "
                       "failures — retried on the next run", "skipped_kind": "breaker"}
    assert wp_casememo.memoisable(skip) is False, (
        "a breaker skip must not be memoisable — wp_casememo already refuses any "
        "skipped_kind outside {'entitlement', 'plan'}")

    # A pivot_extract-shaped result where the breaker skipped the archive check entirely: no
    # positive archived_via_wayback / recovered_via field was ever set (nothing was queried).
    result = {"meta": {"host": "site-a.example", "fetched_with": "requests"}, "pivots": []}
    assert wp_exhaust.layer_ran(wp_exhaust.LAYERS["archive"], result) is False, (
        "a breaker skip must read as the archive layer never having run (a gap), not as "
        "'ran, found nothing'")


class _Router:
    """urlopen() stand-in: route(url, req) returns a response object or raises; every URL is
    logged so a test can assert what was (and was not) requested."""

    def __init__(self, route):
        self.route, self.calls = route, []

    def __call__(self, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        self.calls.append((getattr(req, "method", None) or "GET", url))
        return self.route(url, req)


class _Redirected(_FakeResp):
    """A response whose final URL (after the archive's redirect) differs from the request."""

    def __init__(self, final_url, payload=None):
        super().__init__(payload if payload is not None else {})
        self._final, self.status = final_url, 200

    def geturl(self):
        return self._final


def _http_error(url, code):
    import urllib.error
    return urllib.error.HTTPError(url, code, f"HTTP {code}", {}, None)


def _stubbed(router, fn):
    saved = urllib.request.urlopen
    urllib.request.urlopen = router
    try:
        return fn()
    finally:
        urllib.request.urlopen = saved


def _no_backoff():
    import wp_wayback
    saved = wp_wayback.BACKOFF
    wp_wayback.BACKOFF = 0
    return lambda: setattr(wp_wayback, "BACKOFF", saved)


def test_index_fails_over_to_the_next_endpoint_on_503():
    import wp_wayback
    rows = [["timestamp", "original"], ["20240101000000", "http://site-a.example/"]]

    def route(url, req):
        if "/web/timemap/" in url:
            raise _http_error(url, 503)
        return _FakeResp(rows)

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        r = _Router(route)
        got, err = _stubbed(r, lambda: wp_wayback.index([("url", "site-a.example")]))
        assert err is None and got == [["20240101000000", "http://site-a.example/"]], (got, err)
        assert [u for _, u in r.calls][0].startswith(wp_wayback.INDEX_ENDPOINTS[0]) \
            and r.calls[-1][1].startswith(wp_wayback.INDEX_ENDPOINTS[1]), r.calls


def test_an_unanswered_index_is_a_gap_not_an_empty_history():
    import wp_wayback
    import wayback_ga
    restore = _no_backoff()
    try:
        with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
            r = _Router(lambda url, req: (_ for _ in ()).throw(_http_error(url, 503)))
            rows, err = _stubbed(r, lambda: wp_wayback.index([("url", "site-a.example")]))
            assert rows is None and err, (rows, err)
            assert len(r.calls) == wp_wayback.ATTEMPTS * len(wp_wayback.INDEX_ENDPOINTS), r.calls
            res = _stubbed(_Router(lambda url, req: (_ for _ in ()).throw(_http_error(url, 503))),
                           lambda: wayback_ga.analyze_domain("site-a.example"))
            assert res.get("skipped") and res.get("skipped_kind"), (
                "an index that never answered must read as a gap (skipped), not as zero history", res)
            empty, err2 = _stubbed(_Router(lambda url, req: _FakeResp([])),
                                   lambda: wp_wayback.index([("url", "site-a.example")]))
            assert empty == [] and err2 is None, "a valid [] answer is 'no captures', not an error"
    finally:
        restore()


def test_resolver_redirect_names_the_capture_and_404_is_final():
    import wp_wayback
    cap = "https://web.archive.org/web/20210209023603id_/https://site-a.example/"

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        r = _Router(lambda url, req: _Redirected(cap))
        snap, ts, err = _stubbed(r, lambda: wp_wayback.closest("https://site-a.example/", "2020"))
        assert (ts, err) == ("20210209023603", None), (snap, ts, err)
        assert snap == "https://web.archive.org/web/20210209023603/https://site-a.example/", snap
        assert len(r.calls) == 1 and r.calls[0][0] == "HEAD", (
            "a resolver redirect must answer on its own — no availability/index fallback", r.calls)

        # the capture's own playback 5xx's after the 302: the redirect still named the timestamp
        r = _Router(lambda url, req: (_ for _ in ()).throw(_http_error(cap, 503)))
        snap, ts, err = _stubbed(r, lambda: wp_wayback.closest("https://site-a.example/", "2020"))
        assert ts == "20210209023603" and err is None and len(r.calls) == 1, (snap, ts, err, r.calls)

        r = _Router(lambda url, req: (_ for _ in ()).throw(_http_error(url, 404)))
        got = _stubbed(r, lambda: wp_wayback.closest("https://never-archived.example/"))
        assert got == (None, None, None) and len(r.calls) == 1, (got, r.calls)


def test_a_refused_connection_cools_that_host_and_no_further_request_is_made():
    import urllib.error
    import wp_wayback
    import wp_wayback_guard as wg

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        refused = _Router(lambda url, req: (_ for _ in ()).throw(
            urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))))
        rows, err = _stubbed(refused, lambda: wp_wayback.index([("url", "site-a.example")]))
        assert rows is None and err and len(refused.calls) == 1, (
            "a refused connection must stop at once, not retry into the firewall", refused.calls)
        assert wg.cooling("web.archive.org"), "a refused connection must arm the host cooldown"

        def _forbidden(req, timeout=None):
            raise AssertionError("request made while web.archive.org is cooling down")
        rows, err = _stubbed(_forbidden, lambda: wp_wayback.index([("url", "site-b.example")]))
        assert rows is None and "cooling down" in err, err
        assert wg.cooling("archive.org") is None, "a cooldown is per host, not archive-wide"


def test_a_429_cools_only_that_host_on_that_exit_and_pacing_is_per_exit():
    import time
    import wp_wayback_guard as wg

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        wg.observe("web.archive.org", _http_error("https://web.archive.org/web/x", 429),
                   {"Retry-After": "30"}, exit_id="203.0.113.7:50100")
        assert wg.cooling("web.archive.org", "203.0.113.7:50100")
        assert wg.cooling("web.archive.org", "direct") is None, "another exit is not throttled"
        assert wg.cooling("urlscan.io", "203.0.113.7:50100") is None, "another host is not throttled"
        assert wg.admit("web.archive.org", "playback", exit_id="203.0.113.7:50100") is not None
        os.environ["WAYBACK_MIN_INTERVAL"] = "0.5"
        assert wg.admit("web.archive.org", "playback", exit_id="direct") is None
        t = time.monotonic()
        assert wg.admit("web.archive.org", "playback", exit_id="198.51.100.9:1080") is None
        assert time.monotonic() - t < 0.3, "a different exit must not wait behind direct's slot"


def test_pacer_spaces_one_lane_and_refuses_a_slot_past_the_budget():
    import time
    import wp_wayback_guard as wg

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        os.environ["WAYBACK_MIN_INTERVAL"] = "0.4"
        t0 = time.monotonic()
        assert wg.admit("web.archive.org", "playback") is None
        assert wg.admit("web.archive.org", "playback") is None
        assert time.monotonic() - t0 >= 0.35, "the second same-lane request must wait its slot"
        t1 = time.monotonic()
        reason = wg.admit("web.archive.org", "playback", max_wait=0.05)
        assert reason and "pacing" in reason and time.monotonic() - t1 < 0.2, (
            "a slot further away than max_wait must be refused at once, not slept on", reason)
        t2 = time.monotonic()
        assert wg.admit("web.archive.org", "index") is None and time.monotonic() - t2 < 0.2, (
            "another lane is not queued behind playback")


def test_a_capped_domain_index_is_flagged_truncated_and_topped_up_with_recent_captures():
    import wayback_ga

    def route(url, req):
        if "limit=-" in url:            # the apex's newest captures (the top-up query)
            return _FakeResp([["timestamp", "original"], ["20260901000000", "http://site-a.example/"]])
        return _FakeResp([["timestamp", "original"]] +
                         [[f"2019010{i}000000", f"http://site-a.example/p{i}"] for i in range(3)])

    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        r = _Router(route)
        report = {}
        snaps = _stubbed(r, lambda: wayback_ga.cdx_snapshots("site-a.example", limit_scan=3,
                                                            include_assets=False, report=report))
        assert report.get("truncated") is True, report
        assert snaps[-1][0] == "20260901000000", (
            "a row-capped whole-domain query must be topped up with the newest captures", snaps)
        report = {}
        _stubbed(_Router(route), lambda: wayback_ga.cdx_snapshots(
            "site-a.example", limit_scan=50, include_assets=False, report=report))
        assert not report.get("truncated"), "a result under the cap is complete, not truncated"


def test_a_proxy_side_failure_never_cools_the_archive_and_a_block_is_per_exit():
    import urllib.error
    import wp_wayback_guard as wg

    refused = lambda: urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
    with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
        os.environ["HTTPS_PROXY"] = "http://user:secret@proxy-a.example:50100"
        # the exit itself is down: the archive never saw the request
        assert wg.observe("web.archive.org", urllib.error.URLError(OSError(
            "Error connecting to SOCKS5 proxy 127.0.0.1:40000: [Errno 111] Connection refused"))) is None
        assert wg.observe("web.archive.org", refused()) is None, (
            "through a proxy a bare TCP refusal is the proxy's own port, not the archive")
        assert wg.observe("web.archive.org", OSError(
            "Tunnel connection failed: 407 Proxy Authentication Required")) is None, (
            "a proxy rejecting its credentials is not the archive blocking the exit")
        assert wg.cooling("web.archive.org") is None
        # the exit reached the archive and was refused: THAT exit is blocked…
        assert wg.observe("web.archive.org", OSError(
            "Tunnel connection failed: 502 Bad Gateway (connect refused)")) == "refused"
        assert wg.cooling("web.archive.org"), "an archive-side refusal must cool the exit"
        assert "secret" not in open(os.environ["WAYBACK_PACE_STATE"]).read(), (
            "the cooldown state must never persist a proxy credential")
        # …but not a different exit, nor the direct IP
        os.environ["HTTPS_PROXY"] = "http://user:secret@proxy-b.example:50100"
        assert wg.cooling("web.archive.org") is None, "a block earned on one exit is per exit"
        os.environ.pop("HTTPS_PROXY")
        assert wg.cooling("web.archive.org") is None
        assert wg.observe("web.archive.org", refused()) == "refused", (
            "on the direct IP a bare refusal IS the archive's firewall")


def test_failover_attempts_bypass_the_timeout_floor_and_the_final_attempt_keeps_it():
    """wp_common floors every urlopen timeout to CTI_CALL_TIMEOUT; a hanging endpoint must not hold
    a failover attempt to that ceiling, but the LAST attempt must still get it (project rule)."""
    import wp_wayback
    restore = _no_backoff()
    seen = []

    def orig(req, timeout=None):                 # the unfloored urlopen
        seen.append(("orig", timeout))
        raise TimeoutError("timed out")

    def floored(req, timeout=None):              # what wp_common installs
        seen.append(("floored", timeout))
        raise TimeoutError("timed out")
    floored._cti_orig = orig
    try:
        with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
            rows, err = _stubbed(floored, lambda: wp_wayback.index([("url", "site-a.example")], timeout=7))
            n = wp_wayback.ATTEMPTS * len(wp_wayback.INDEX_ENDPOINTS)
            assert rows is None and err and len(seen) == n, (seen, err)
            assert seen[:-1] == [("orig", 7)] * (n - 1) and seen[-1][0] == "floored", seen
    finally:
        restore()


def test_an_unplayable_capture_falls_back_to_its_nearest_playable_neighbour():
    import wp_wayback
    restore = _no_backoff()
    bad = "20210209023603"

    def route(url, req):
        if f"/web/{bad}id_/" in url:
            raise _http_error(url, 503)
        if "sort=closest" in url:
            return _FakeResp([["timestamp", "original"], [bad, "https://site-a.example/"],
                              ["20210208101132", "https://site-a.example/"]])
        if "/web/20210208101132id_/" in url:
            return _Redirected(url, {"page": "x" * 500})
        raise AssertionError("unexpected " + url)

    try:
        with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
            resp, used, err = _stubbed(_Router(route), lambda: wp_wayback.fetch_capture(
                bad, "https://site-a.example/"))
            assert resp is not None and resp.status == 200 and used == "20210208101132" \
                and err is None, (resp, used, err)
    finally:
        restore()


def test_the_index_fallback_of_closest_keeps_the_requested_path():
    import wp_wayback
    restore = _no_backoff()

    def route(url, req):
        if "/web/timemap/" in url or "/cdx/search/" in url:
            return _FakeResp([["timestamp", "original"], ["20240101000000", "https://site-a.example/login/x"]])
        raise _http_error(url, 503)          # the resolver fails

    try:
        with tempfile.TemporaryDirectory() as tmp, _Env(case_dir=tmp):
            r = _Router(route)
            snap, ts, err = _stubbed(r, lambda: wp_wayback.closest("https://site-a.example/login/x"))
            idx = [u for _, u in r.calls if "/web/timemap/" in u]
            assert idx and "url=site-a.example/login/x" in idx[0] and "fastLatest=true" in idx[0], idx
            assert ts == "20240101000000" and snap.endswith("/login/x"), (snap, ts, err)
    finally:
        restore()


_TESTS = [
    test_20_consecutive_failures_trip_and_21st_makes_no_request,
    test_success_resets_the_streak,
    test_a_no_capture_answer_never_counts_as_a_failure,
    test_a_new_run_id_starts_fresh,
    test_two_processes_sharing_a_run_id_share_the_counter,
    test_tripped_skip_is_not_memoised_and_reads_as_a_gap_not_empty,
    test_index_fails_over_to_the_next_endpoint_on_503,
    test_an_unanswered_index_is_a_gap_not_an_empty_history,
    test_resolver_redirect_names_the_capture_and_404_is_final,
    test_a_refused_connection_cools_that_host_and_no_further_request_is_made,
    test_a_429_cools_only_that_host_on_that_exit_and_pacing_is_per_exit,
    test_pacer_spaces_one_lane_and_refuses_a_slot_past_the_budget,
    test_a_capped_domain_index_is_flagged_truncated_and_topped_up_with_recent_captures,
    test_a_proxy_side_failure_never_cools_the_archive_and_a_block_is_per_exit,
    test_failover_attempts_bypass_the_timeout_floor_and_the_final_attempt_keeps_it,
    test_an_unplayable_capture_falls_back_to_its_nearest_playable_neighbour,
    test_the_index_fallback_of_closest_keeps_the_requested_path,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
