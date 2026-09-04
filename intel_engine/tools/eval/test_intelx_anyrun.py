#!/usr/bin/env python3
"""Offline unit gate for the two SELECTOR/OBSERVATION layers — IntelX (wp_intelx) and ANY.RUN
(bp_anyrun).

Neither layer's live calls are exercised here: both need a key and both spend a metered allowance.
What IS gated is everything that decides whether their output is usable or actively misleading, and
each of these has a silent failure mode:

  1. **Keyless must still produce the query.** Both layers exist to be half-useful with no key: the
     selector/query is composed offline and the analyst runs it in the web UI. If the builder ever
     starts requiring a key, a keyless run degrades from "here is the query" to nothing, silently.
  2. **The ~50% capability statement must be present and loud.** A missing key is not an error, but
     an absent IntelX/ANY.RUN section that is not labelled reads as "the operator is in no leak" /
     "this sample is unknown" — a fact about the credentials misread as a fact about the target.
  3. **Soft selectors never reach IntelX.** IntelX refuses a brand or person name with an HTTP 400
     that still counts against the allowance. Classification happens locally, before the call.
  4. **ANY.RUN gets an observation field, not a string match.** `app:c2_endpoint` is `ip:port`; sent
     literally it matches nothing forever. It has to split into destinationIP + destinationPort.
  5. **Kinds neither service indexes emit NOTHING.** A favicon hash on IntelX or a signing cert on
     ANY.RUN is not a query that returns zero — it is a query that should never have been built.
  6. **The clustering policy fails CLOSED.** Breach co-membership (IntelX) and a shared malware
     family (ANY.RUN) are the textbook false clusters for these two corpora. If the policy data is
     unreadable, `clusterable()` / `grade_field()` must deny, not allow.
  7. **The spend guard actually blocks.** Both allowances are small and both fail silently when
     exhausted, so an over-budget call must come back as a `skipped` reason carrying the balance.

Run standalone (`python3 tools/eval/test_intelx_anyrun.py`) or via run_eval.py.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "BinaryPivot", "tools"))
import wp_intelx as ix     # noqa: E402
import bp_anyrun as ar     # noqa: E402

FAKE_EMAIL = "registrant@example.com"
FAKE_DOMAIN = "site-a.example"
FAKE_SHA256 = "a" * 64


_IX_KEYS = ("INTELX_KEY", "INTELX_API_KEY", "INTELLIGENCEX_KEY")   # every alias wp_intelx.intelx_key() reads


def _pop_ix_keys():
    return {k: os.environ.pop(k, None) for k in _IX_KEYS}


def _restore_ix_keys(saved):
    for k, v in saved.items():
        os.environ.pop(k, None)
        if v is not None:
            os.environ[k] = v


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

    # --- 1. reference DATA actually loaded (not the embedded fallback) -----------------------
    ok(len(ix.SELECTOR_TYPES) > 5,
       f"intelx.json selector_types loaded ({len(ix.SELECTOR_TYPES)} classes)")
    ok(len(ix.BUCKETS) >= 5, f"intelx.json bucket catalogue loaded ({len(ix.BUCKETS)} buckets)")
    ok(len(ar.QUERY_FIELDS) > 10,
       f"anyrun.json query_fields loaded ({len(ar.QUERY_FIELDS)} fields)")

    # --- 2. IntelX classifies STRONG selectors locally, and refuses soft ones -----------------
    ok(ix.classify_selector(FAKE_EMAIL)[0] == "email", "an email classifies as the email selector")
    ok(ix.classify_selector(FAKE_DOMAIN)[0] == "domain", "a domain classifies as the domain selector")
    ok(ix.classify_selector("198.51.100.7")[0] == "ipv4", "an IPv4 classifies as the ipv4 selector")
    ok(ix.classify_selector("+84 90 000 0000")[0] == "phone", "a phone number classifies as phone")
    ok(ix.classify_selector("https://site-a.example/login")[0] == "url", "a URL classifies as url")
    ok(ix.classify_selector("Some Brand Name")[0] is None,
       "a SOFT term (brand/person name) is refused locally — never sent, never charged")
    ok(ix.classify_selector("")[0] is None, "an empty term is refused")
    # A wildcard apex is the phonebook's whole point and must not be rejected by the pattern.
    ok(ix.classify_selector("*.site-a.example")[0] == "domain", "a wildcard apex still classifies")

    # --- 3. the KEYLESS query builder produces a runnable URL with no key ---------------------
    was_key = _pop_ix_keys()
    try:
        ok(not ix.intelx_configured(), "no INTELX_KEY -> the layer reports itself unconfigured")
        qs = ix.intelx_queries("email", FAKE_EMAIL)
        ok(bool(qs), "keyless: an email pivot still gets IntelX entries")
        ok(any(q["query"].startswith("https://intelx.io/") for q in qs),
           "keyless: a ready-to-run intelx.io UI URL is emitted")
        dqs = ix.intelx_queries("domain", FAKE_DOMAIN)
        ok(any("phonebook" in (q.get("service") or "").lower() for q in dqs),
           "a domain pivot names the PHONEBOOK inventory explicitly (the layer's best move)")
        cap = ix.capability()
        ok(cap["power_pct"] == 50 and cap["mode"] == "keyless",
           "keyless IntelX reports ~50% capability")
        ok("not queried" in cap["statement"] or "never EXECUTED" in cap["statement"],
           "the IntelX statement says the indexes were NOT queried (an empty result is not a finding)")
        ok(bool(ix.banner_lines()), "keyless IntelX prints a banner")
        ok(not ix.banner_lines(free_only=False) == [], "banner is non-empty in keyless mode")
    finally:
        _restore_ix_keys(was_key)
    # Fully keyed, the banner must be SILENT — a caveat on every run trains people to skip it.
    _was_real = _pop_ix_keys()
    os.environ["INTELX_KEY"] = "test-key-not-a-real-credential"
    try:
        ok(ix.capability()["power_pct"] == 100, "with a key, IntelX reports full capability")
        ok(ix.banner_lines() == [], "with a key, IntelX prints NO banner")
        ok(ix.capability(free_only=True)["power_pct"] == 50,
           "--free-only reports ~50% even when the key exists (it is suppressed, not absent)")
    finally:
        os.environ.pop("INTELX_KEY", None)
        _restore_ix_keys(_was_real)

    # --- 4. kinds IntelX cannot search emit NOTHING -------------------------------------------
    ok(ix.intelx_queries("favicon_hash", "123456789") == [],
       "a favicon hash emits no IntelX query (IntelX does not index it)")
    ok(ix.intelx_queries("tracker:ga4", "G-XXXXXXXXXX") == [],
       "a GA4 tracker emits no IntelX query")
    ok(ix.selector_for_kind("jarm:hash") is None, "JARM is not an IntelX selector")

    # --- 5. IntelX bucket grading + FALSE-CLUSTER control -------------------------------------
    ok(not ix.clusterable("leaks.public.general"),
       "a public breach corpus is NOT clusterable — shared victims, not a shared operator")
    ok(not ix.clusterable("leaks.logs"),
       "a stealer log is NOT clusterable — it is victim/exposure evidence")
    ok(ix.clusterable("whois"), "a historical WHOIS snapshot IS clusterable")
    ok(ix.clusterable("pastes"), "a paste IS clusterable (often the operator's own text)")
    ok(not ix.clusterable("some.bucket.we.have.never.seen"),
       "an UNKNOWN bucket is not clusterable — the policy fails closed")
    ok(ix.bucket_grade("web.public.com")["grade"] != "ungraded",
       "a per-TLD web.public.<tld> bucket inherits the web.public grade")
    ok(ix.bucket_grade("leaks.logs")["grade"] == "strong", "stealer logs are graded strong")
    # LOGS BEAT DUMPS. A breach dump is one site's user table (an address and a year, recycled
    # through dozens of combolists); a stealer log is one machine at one moment, and may be the
    # OPERATOR's machine holding the campaign's panel credentials. If the ranking ever inverts, a
    # long-exposed address buries its one useful hit under a hundred stale combolist rows.
    ok(ix.bucket_rank("leaks.logs") < ix.bucket_rank("leaks.public.general"),
       "an infostealer log outranks a public breach dump")
    ok(ix.bucket_rank("leaks.logs") < ix.bucket_rank("leaks.private.general"),
       "an infostealer log outranks a private breach dump too")
    ok(ix.bucket_rank("leaks.logs") == min(ix.bucket_rank(b) for b in ix.BUCKETS),
       "the stealer-log bucket is ranked FIRST of all buckets")
    ok(ix.bucket_rank("some.bucket.we.have.never.seen") >= 99, "an unknown bucket ranks last")
    # "not an automatic edge" and "not worth reading" are DIFFERENT claims — collapsing them
    # throws away the best material IntelX has.
    ok(ix.item_evidence("leaks.logs") and not ix.clusterable("leaks.logs"),
       "a stealer log is per-ITEM evidence to open by hand, yet still never an automatic edge")
    ok(not ix.item_evidence("leaks.public.general"),
       "a breach dump is NOT flagged for item-by-item reading (skim it for the date)")
    ok(ix.summarise_record({"bucket": "leaks.logs", "name": "x"}).get("read_item") is True,
       "a stealer-log record is flagged read_item in the case file")
    # Ordering is what the analyst actually sees; assert it on the summarised records directly.
    mixed = [ix.summarise_record({"bucket": b, "name": b})
             for b in ("leaks.public.general", "dumpster", "leaks.logs", "pastes")]
    mixed.sort(key=lambda r: r.get("rank", 99))
    ok(mixed[0]["bucket"] == "leaks.logs" and mixed[-1]["bucket"] == "dumpster",
       "sorting summarised records by rank puts logs first and the unsorted dumpster last")
    rec = ix.summarise_record({"bucket": "leaks.public.general", "name": "x", "media": 24,
                               "systemid": "id", "date": "2026-01-01"})
    ok(rec.get("clusterable") is False and rec.get("grade") == "context",
       "every summarised record carries its grade + clusterable flag into the case file")

    # --- 6. ANY.RUN builds an OBSERVATION query, not a string match ---------------------------
    ok(ar.build_query("file:sha256", FAKE_SHA256) == f'sha256:"{FAKE_SHA256}"',
       "a file hash maps to the sha256 field")
    c2 = ar.build_query("app:c2_endpoint", "203.0.113.10:8443")
    ok("destinationIP:" in c2 and 'destinationPort:"8443"' in c2,
       "an ip:port C2 endpoint SPLITS into destinationIP + destinationPort")
    ok(ar.build_query("app:c2_endpoint", "203.0.113.10") == 'destinationIP:"203.0.113.10"',
       "a bare IP endpoint still builds a destinationIP query")
    ok(ar.build_query("app:backend_host", "api.site-a.example") ==
       'domainName:"api.site-a.example"', "a backend host maps to domainName")
    ok(ar.build_query("apk:signing_cert_sha256", "abc") == "",
       "a signing certificate emits NO ANY.RUN query (not an observation field)")
    ok(ar.build_query("apk:package", "com.example.app") == "",
       "an APK package name emits NO ANY.RUN query")
    ok(ar.build_query("cloud:firebase_project", "proj") == "",
       "a firebase project id emits NO ANY.RUN query")
    ok(ar.build_query("file:sha256", "") == "", "an empty value never builds a query")

    # --- 7. ANY.RUN keyless capability + query attachment --------------------------------------
    _AR_KEYS7 = ("ANYRUN_API_KEY", "ANY_RUN_API_KEY", "ANYRUN_KEY")
    ar.anyrun_key()                    # prime bp_anyrun's one-shot .env loader BEFORE popping (else the pop is undone)
    was_ar = {k: os.environ.pop(k, None) for k in _AR_KEYS7}
    try:
        cap = ar.capability()
        ok(cap["power_pct"] == 50 and cap["mode"] == "keyless",
           "keyless ANY.RUN reports ~50% capability")
        ok("PACKED" in cap["statement"],
           "the ANY.RUN statement names the PACKED-sample case, where the loss actually bites")
        ok(bool(ar.banner_lines()), "keyless ANY.RUN prints a banner")
        pivots = [{"kind": "file:sha256", "value": FAKE_SHA256, "queries": []},
                  {"kind": "apk:package", "value": "com.example.app", "queries": []}]
        ar.attach_anyrun_queries(pivots)
        ok(any("ANY.RUN" in (q["service"] or "") for q in pivots[0]["queries"]),
           "keyless: the hash pivot gains a TI Lookup query")
        ok(pivots[1]["queries"] == [],
           "keyless: the package pivot gains nothing (correctly — not indexed)")
        ar.attach_anyrun_queries(pivots)
        ok(len([q for q in pivots[0]["queries"] if "ANY.RUN" in q["service"]]) == 2,
           "attach is idempotent — a second pass does not duplicate the entries")
    finally:
        for k, v in was_ar.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    # --- 7b. THE SUBMISSION GATE -------------------------------------------------------------
    # A submission is outbound, attributable and irreversible: it hands case material to a third
    # party and tells the target it is being sandboxed. Every one of these assertions is a case
    # that has burned real investigations, so the gate must hold even when the reference data is
    # unreadable and even when a caller passes confirm-adjacent arguments by accident.
    was_ar = os.environ.pop("ANYRUN_API_KEY", None)
    os.environ["ANYRUN_API_KEY"] = "test-key-not-a-real-credential"
    ar.anyrun_key()                                  # prime the .env loader so the pop below sticks
    was_pub = os.environ.pop("ANYRUN_ALLOW_PUBLIC", None)   # the analyst's standing setting must not leak in
    os.environ["ANYRUN_ALLOW_PUBLIC"] = "0"                  # process env wins over .env in the loader
    try:
        pf = ar.submit("./sample.bin", "file")                       # no confirm at all
        ok(pf.get("action", "").startswith("CONFIRMATION REQUIRED"),
           "submit() WITHOUT confirm returns the briefing and sends nothing")
        ok(pf.get("irreversible") is True and len(pf.get("risks") or []) >= 3,
           "the briefing states irreversibility and enumerates the OPSEC risks")
        ok(any("EXISTING detonation" in c or "static" in c for c in (pf.get("try_first") or [])),
           "the briefing points at the cheaper alternatives before detonating")
        ok(pf["would_use"]["privacy"] == "owner",
           "the default privacy is `owner` (only you), NOT the SDK's shareable `bylink`")
        ok(any("case ID" in n for n in (pf.get("never_send") or [])),
           "the briefing forbids sending case identifiers to a third party (RULE 1 over an API)")
        ok(ar.submit("http://site-a.example", "url", confirm=False).get("action", "")
           .startswith("CONFIRMATION REQUIRED"),
           "an explicit confirm=False is still a refusal, not a default-through")
        pub = ar.submit("./sample.bin", "file", confirm=True, privacy="public")
        ok("refused" in pub and "public feed" in pub["refused"],
           "confirm=True is NOT enough for a PUBLIC task — that needs allow_public as well")
        ok("preflight" in pub, "the public refusal hands back the briefing rather than a bare error")
    finally:
        os.environ.pop("ANYRUN_API_KEY", None)
        if was_ar is not None:
            os.environ["ANYRUN_API_KEY"] = was_ar
        os.environ.pop("ANYRUN_ALLOW_PUBLIC", None)
        if was_pub is not None:
            os.environ["ANYRUN_ALLOW_PUBLIC"] = was_pub
    # With no key nothing can be submitted regardless of what the caller passes.
    was_ar2 = os.environ.pop("ANYRUN_API_KEY", None)
    try:
        r = ar.submit("./sample.bin", "file", confirm=True)
        ok("skipped" in r, "keyless: even a confirmed submit sends nothing")
    finally:
        if was_ar2 is not None:
            os.environ["ANYRUN_API_KEY"] = was_ar2
    # The gate is enforced in the SIGNATURE, not read from the JSON — a config edit (or a stale
    # copy of the reference file) must never be able to switch it off.
    saved_policy = dict(ar.SUBMISSION_POLICY)
    try:
        ar.SUBMISSION_POLICY["require_explicit_confirmation"] = False
        ar.SUBMISSION_POLICY["forbidden_privacy"] = []
        os.environ["ANYRUN_API_KEY"] = "test-key-not-a-real-credential"
        ok(ar.submit("./sample.bin", "file").get("action", "").startswith("CONFIRMATION REQUIRED"),
           "flipping require_explicit_confirmation in the DATA cannot disable the gate")
    finally:
        ar.SUBMISSION_POLICY.clear()
        ar.SUBMISSION_POLICY.update(saved_policy)
        os.environ.pop("ANYRUN_API_KEY", None)
        if was_ar is not None:
            os.environ["ANYRUN_API_KEY"] = was_ar

    # --- 7c. refuse_on_free_plan — PRE-FLIGHT proof, attestation, and the POST-SUBMIT read-back --
    # Pre-flight reads the account record — `/user` limits.private (0 ⇒ denied even against an
    # attestation; -1/positive ⇒ entitled), else a prior non-public own task — and FAILS CLOSED
    # without proof. Deleting a public task un-publishes nothing, so the
    # read-back after the POST is defence-in-depth, not the gate. Fully stubbed at the transport
    # seam: nothing here reaches the network or the spend ledger.
    was_ar = os.environ.pop("ANYRUN_API_KEY", None)
    os.environ["ANYRUN_API_KEY"] = "test-key-not-a-real-credential"
    was_pub = os.environ.pop("ANYRUN_ALLOW_PUBLIC", None)
    os.environ["ANYRUN_ALLOW_PUBLIC"] = "0"
    _saved = (ar._call, ar._post_multipart, ar._record, ar.time.sleep)
    calls = []
    NEW = "00000000-0000-4000-8000-00000000new0"

    def _fake_transport(history, applied_privacy, report_ok=True, private_quota=None, running_for=0):
        """`history`: {uuid: privacy | None(unreadable)} for prior own tasks; `applied_privacy` is
        what ANY.RUN reports for the task this submission creates; `private_quota` is the
        `/user` → limits.private block (None = block absent, as older connector schemas show);
        `running_for`: how many report reads of the NEW task return the live-observed "in progress"
        stub (status only, no analysis.options) before the finished record appears."""
        state = {"new_reads": 0}

        def _post(url, fields, filepath, timeout=120):
            calls.append(("POST", url, fields.get("opt_privacy_type")))
            return {"data": {"taskid": NEW}}, None

        def _call(url, *, method="GET", body=None, timeout=30):
            calls.append((method, url, None))
            if url.endswith("/user"):
                limits = {"api": {"month": 250}}
                if private_quota is not None:
                    limits["private"] = private_quota
                return {"data": {"limits": limits}}, None
            if "/analysis/delete/" in url:
                return {"error": False}, None
            if "/analysis?" in url:
                return {"data": {"tasks": [{"uuid": u, "verdict": "x", "date": "d"} for u in history]}}, None
            uuid = url.rsplit("/", 1)[-1]
            if uuid == NEW:
                state["new_reads"] += 1
                if not report_ok:
                    return None, {"skipped": "HTTP 404 — not in the ANY.RUN dataset"}
                if state["new_reads"] <= running_for:
                    return {"data": {"status": "in progress", "analysis": {}}}, None
                priv = applied_privacy
            else:
                priv = history.get(uuid)
            if priv is None:
                return None, {"skipped": "HTTP 404 — not in the ANY.RUN dataset"}
            return {"data": {"status": "done", "analysis": {"options": {"privacy": priv}}}}, None
        return _post, _call

    def _reset(history, applied, **kw):
        calls.clear()
        with ar._MEMO_LOCK:
            ar._MEMO.clear()
        ar._post_multipart, ar._call = _fake_transport(history, applied, **kw)

    ZERO_Q = {"minute": 0, "hour": 0, "day": 0, "month": 0}
    UNLIM_Q = {"minute": -1, "hour": -1, "day": -1, "month": -1}

    try:
        ar._record = lambda *a, **k: None
        ar.time.sleep = lambda s: None
        # (a) history proves a private task exists → allowed; the new task is verified `owner`
        _reset({"t1": "public", "t2": "owner"}, "owner")
        r = ar.submit(__file__, "file", confirm=True)
        ok(r.get("submitted") is True and r.get("privacy_verified") is True
           and r.get("privacy_applied") == "owner" and "exposed" not in r,
           "a prior own 'owner' task proves the plan; the new private task is verified, not withdrawn")
        ok(not any(m == "DELETE" for m, _, _ in calls), "no delete is issued when privacy matches")
        # (b) FAIL CLOSED: only public tasks on record → refused BEFORE any POST
        _reset({"t1": "public", "t2": "public"}, "public")
        r = ar.submit(__file__, "file", confirm=True)
        ok("refused" in r and r.get("plan_evidence", {}).get("verdict") == "unknown"
           and "preflight" in r and not any(m == "POST" for m, _, _ in calls),
           "a history of only PUBLIC tasks refuses pre-flight — nothing is POSTed")
        # (c) FAIL CLOSED: empty history (fresh account) → refused, reason names the attestation
        _reset({}, "owner")
        r = ar.submit(__file__, "file", confirm=True)
        ok("refused" in r and "attestation" in r["plan_evidence"].get("reason", "")
           and not any(m == "POST" for m, _, _ in calls),
           "an empty history cannot prove a plan — refused pre-flight, attestation route named")
        # (d) FAIL CLOSED: history unreadable → refused, never assumed paid
        _reset({"t1": None}, "owner")
        r = ar.submit(__file__, "file", confirm=True)
        ok("refused" in r and not any(m == "POST" for m, _, _ in calls),
           "unreadable task reports do not count as proof")
        # (d2) /user limits.private all ZERO (observed live on a free-tier key) → DENIED, and the
        #      attestation cannot override positive evidence; no history probe, no POST
        _reset({"t1": "owner"}, "owner", private_quota=ZERO_Q)
        r = ar.submit(__file__, "file", confirm=True, allow_unverified_plan=True)
        ok("refused" in r and r["plan_evidence"].get("verdict") == "denied"
           and "regardless of allow_unverified_plan" in r["refused"]
           and not any(m == "POST" or "/analysis?" in u for m, u, _ in calls),
           "a zero private quota on /user is DENIED even with the attestation — no probe, no POST")
        # (d2b) same zero quota, but the analyst holds a STANDING public authorization in .env:
        #       the submission is downgraded to public EXPLICITLY — the result names the downgrade,
        #       the authorization source and the exposure — and the read-back verifies `public`
        os.environ["ANYRUN_ALLOW_PUBLIC"] = "1"
        try:
            _reset({}, "public", private_quota=ZERO_Q)
            pf = ar.submit(__file__, "file")
            ok("standing_public_authorization" in pf.get("would_use", {}),
               "the briefing warns that a standing public authorization will make the task public")
            r = ar.submit(__file__, "file", confirm=True)
            ok(r.get("submitted") is True and r.get("privacy") == "public"
               and r.get("downgraded_from") == "owner" and r.get("public_task") is True
               and "ANYRUN_ALLOW_PUBLIC" in r.get("public_authorized_by", "")
               and r.get("privacy_verified") is True
               and any(m == "POST" and p == "public" for m, _, p in calls),
               "zero quota + standing ANYRUN_ALLOW_PUBLIC → explicit, labelled downgrade to a public task")
            # the standing setting never touches the confirmation gate
            ok(ar.submit(__file__, "file").get("action", "").startswith("CONFIRMATION REQUIRED"),
               "ANYRUN_ALLOW_PUBLIC does not bypass per-submission confirmation")
            # ...and an entitled plan under the same setting still goes PRIVATE — public is a
            # fallback for plans that cannot go private, not a new default
            _reset({}, "owner", private_quota=UNLIM_Q)
            r = ar.submit(__file__, "file", confirm=True)
            ok(r.get("privacy") == "owner" and "downgraded_from" not in r and "public_task" not in r,
               "with a private-capable plan the standing public authorization changes nothing")
        finally:
            os.environ.pop("ANYRUN_ALLOW_PUBLIC", None)
        # (d2c) per-call allow_public on a zero-quota plan → same explicit downgrade, attributed to the call
        _reset({}, "public", private_quota=ZERO_Q)
        r = ar.submit(__file__, "file", confirm=True, allow_public=True)
        ok(r.get("submitted") is True and r.get("downgraded_from") == "owner"
           and r.get("public_authorized_by") == "allow_public on this call",
           "zero quota + allow_public on the call → downgrade attributed to the call")
        # (d3) /user limits.private unlimited → ENTITLED from the account record alone: no history
        #      probe needed, the POST goes through and is verified
        _reset({}, "owner", private_quota=UNLIM_Q)
        r = ar.submit(__file__, "file", confirm=True)
        ok(r.get("submitted") is True and r.get("privacy_verified") is True
           and not any("/analysis?" in u for _, u, _ in calls),
           "a non-zero private quota on /user proves entitlement without probing history")
        # (d4) a finite positive quota (paid plan with N private runs left) is entitled too — only
        #      0 denies; mixed -1/positive windows are the normal paid shape
        _reset({}, "owner", private_quota={"minute": -1, "hour": -1, "day": 20, "month": 5})
        r = ar.submit(__file__, "file", confirm=True)
        ok(r.get("submitted") is True and r.get("plan_evidence") is None
           and not any("/analysis?" in u for _, u, _ in calls),
           "a finite positive private quota counts as entitled")
        # (e) analyst attestation bypasses the pre-flight proof; the read-back still runs and,
        #     on a silent downgrade to public, withdraws the task and flags EXPOSED — never green
        _reset({}, "public")
        r = ar.submit(__file__, "file", confirm=True, allow_unverified_plan=True)
        ok(any(m == "POST" for m, _, _ in calls), "allow_unverified_plan lets the POST through")
        ok(r.get("exposed") is True and r.get("privacy_verified") is False
           and r.get("deleted") is True and "refused" in r,
           "a task ANY.RUN made PUBLIC despite 'owner' is withdrawn and flagged exposed")
        ok(any(m == "DELETE" and "/analysis/delete/" in u for m, u, _ in calls),
           "the withdrawal hits the delete endpoint")
        ok("world-readable" in r["refused"] and "tipped" in r["refused"],
           "the refusal admits the exposure interval instead of claiming prevention")
        # (f) attested, record unreadable: verification is None with a loud note, never a silent True
        _reset({}, "owner", report_ok=False)
        r = ar.submit(__file__, "file", confirm=True, allow_unverified_plan=True)
        ok(r.get("privacy_verified") is None and NEW in r.get("verify_command", "")
           and "privacy_note" in r,
           "an unreadable task record yields privacy_verified=None plus a verify_command naming the task")
        # (f2) LIVE-OBSERVED SHAPE: the record is an "in progress" stub (no options) while the
        #      sandbox runs. The read-back must keep polling past it and read the finished record.
        _reset({}, "owner", private_quota=UNLIM_Q, running_for=5)
        r = ar.submit(__file__, "file", confirm=True)
        ok(r.get("privacy_verified") is True and r.get("privacy_applied") == "owner"
           and sum(1 for m, u, _ in calls if m == "GET" and u.endswith(NEW)) == 6,
           "the read-back polls through the in-progress stub and reads the finished record")
        # (f3) same, but the task lands PUBLIC after running: the withdrawal still fires
        _reset({}, "public", private_quota=UNLIM_Q, running_for=3)
        r = ar.submit(__file__, "file", confirm=True)
        ok(r.get("exposed") is True and r.get("deleted") is True
           and any(m == "DELETE" for m, _, _ in calls),
           "a downgrade discovered after the task finished is still withdrawn")
        # (f4) task outlives the bounded wait → None + verify_command; the FOLLOW-UP verify_privacy()
        #      later completes the same check, including the withdrawal
        _reset({}, "public", private_quota=UNLIM_Q, running_for=10**6)
        r = ar.submit(__file__, "file", confirm=True)
        ok(r.get("privacy_verified") is None and "verify-privacy" in r.get("verify_command", "")
           and not any(m == "DELETE" for m, _, _ in calls),
           "a task still running at the end of the bounded wait yields None + verify_command, no delete")
        _reset({}, "public", private_quota=UNLIM_Q, running_for=0)
        r = ar.verify_privacy(NEW)                     # requested defaults to the policy default (owner)
        ok(r.get("exposed") is True and r.get("deleted") is True and r.get("task_uuid") == NEW
           and not any(m == "POST" for m, _, _ in calls),
           "verify_privacy() later reads the finished record and withdraws the public task — no POST")
        _reset({}, "public", private_quota=UNLIM_Q, running_for=0)
        r = ar.verify_privacy(NEW, "public")           # the analyst knowingly went public
        ok(r.get("privacy_verified") is True and not any(m == "DELETE" for m, _, _ in calls),
           "verify_privacy() on a knowingly public task confirms and withdraws nothing")
        # (f5) HAZARD CASE: the analyst deliberately went public via the STANDING .env authorization,
        #      then runs the bare follow-up with no `requested`. Defaulting to 'owner' must NOT delete
        #      their own authorized task — it is confirmed and labelled instead (mirrors the live run
        #      on a real public task).
        os.environ["ANYRUN_ALLOW_PUBLIC"] = "1"
        try:
            _reset({}, "public", private_quota=ZERO_Q, running_for=0)
            r = ar.verify_privacy(NEW)
            ok(r.get("privacy_applied") == "public" and r.get("public_task") is True
               and "ANYRUN_ALLOW_PUBLIC" in r.get("public_authorized_by", "")
               and "exposed" not in r and not any(m == "DELETE" for m, _, _ in calls),
               "verify_privacy() under a standing public authorization never deletes the analyst's own public task")
        finally:
            os.environ["ANYRUN_ALLOW_PUBLIC"] = "0"
        # (f6) the still-running result carries the exact MCP call shape, not just a CLI hint
        _reset({}, "public", private_quota=UNLIM_Q, running_for=10**6)
        r = ar.submit(__file__, "file", confirm=True)
        tc = r.get("verify_tool_call") or {}
        ok(tc.get("tool") == "anyrun_submit" and tc.get("args", {}).get("target") == NEW
           and tc.get("args", {}).get("verify_task") is True,
           "a still-running result names the anyrun_submit(target=<uuid>, verify_task=true) follow-up")
        # (h) a knowingly-PUBLIC submission (confirm + allow_public) has no private entitlement to
        #     prove: no history probe, the POST goes through, and the read-back verifies `public`
        _reset({}, "public")
        r = ar.submit(__file__, "file", confirm=True, privacy="public", allow_public=True)
        ok(r.get("submitted") is True and r.get("privacy_verified") is True
           and not any("/analysis?" in u for _, u, _ in calls),
           "allow_public skips the plan proof — a public task needs no private entitlement")
        # (g) policy switch off → neither proof nor read-back (the analyst opted out, visibly)
        saved_policy = dict(ar.SUBMISSION_POLICY)
        ar.SUBMISSION_POLICY["refuse_on_free_plan"] = False
        try:
            _reset({}, "public")
            r = ar.submit(__file__, "file", confirm=True)
            ok(r.get("submitted") is True and "privacy_verified" not in r
               and [m for m, _, _ in calls] == ["POST"],
               "refuse_on_free_plan=false skips proof and read-back and issues only the POST")
        finally:
            ar.SUBMISSION_POLICY.clear()
            ar.SUBMISSION_POLICY.update(saved_policy)
    finally:
        with ar._MEMO_LOCK:
            ar._MEMO.clear()
        ar._call, ar._post_multipart, ar._record, ar.time.sleep = _saved
        os.environ.pop("ANYRUN_API_KEY", None)
        if was_ar is not None:
            os.environ["ANYRUN_API_KEY"] = was_ar
        os.environ.pop("ANYRUN_ALLOW_PUBLIC", None)
        if was_pub is not None:
            os.environ["ANYRUN_ALLOW_PUBLIC"] = was_pub

    # --- 8. ANY.RUN clustering policy fails closed ---------------------------------------------
    ok(ar.grade_field("domainName") == "cluster", "a contacted domain may support an operator edge")
    ok(ar.grade_field("threatName") == "context",
       "a malware FAMILY is context only — same kit, not same operator")
    ok(ar.grade_field("suricataID") == "context", "a Suricata signature id is context only")
    ok(ar.grade_field("madeUpField") == "ungraded",
       "an unknown field is ungraded (never silently clusterable)")

    # --- 9. the spend guards actually block ----------------------------------------------------
    saved = (ix._RUN_SPENT, ar._RUN_SPENT)
    try:
        ix._RUN_SPENT = ix.budget_status()["max_searches_per_run"]
        blocked = ix._budget_block(1, "test search")
        ok(isinstance(blocked, str) and "per-run" in blocked,
           "IntelX: over the per-run cap returns a skip REASON, not a silent call")
        ar._RUN_SPENT = ar.budget_status()["max_requests_per_run"]
        blocked = ar._budget_block(1, "test lookup")
        ok(isinstance(blocked, str) and "per-run" in blocked,
           "ANY.RUN: over the per-run cap returns a skip REASON, not a silent call")
    finally:
        ix._RUN_SPENT, ar._RUN_SPENT = saved

    # --- 10. the two layers never crash a keyless run -----------------------------------------
    _AR_KEYS = ("ANYRUN_API_KEY", "ANY_RUN_API_KEY", "ANYRUN_KEY")   # every alias bp_anyrun.anyrun_key() reads
    ar.anyrun_key()                    # prime bp_anyrun's one-shot .env loader BEFORE popping (else the pop is undone)
    was_ix, was_ar = _pop_ix_keys(), {k: os.environ.pop(k, None) for k in _AR_KEYS}
    # belt and braces: even if a new alias appears, the transport must not be reachable from here
    _saved_call, _saved_ar_call = ix._call, ar._call
    ix._call = lambda *a, **k: (_ for _ in ()).throw(AssertionError("IntelX network reached from the keyless gate"))
    ar._call = lambda *a, **k: (_ for _ in ()).throw(AssertionError("ANY.RUN network reached from the keyless gate"))
    try:
        ok(ix.search(FAKE_EMAIL) is None, "keyless IntelX search returns None, never raises")
        ok(ix.phonebook(FAKE_DOMAIN) is None, "keyless IntelX phonebook returns None, never raises")
        ok(ar.ti_lookup('sha256:"x"') is None, "keyless ANY.RUN lookup returns None, never raises")
        res = {"meta": {"host": FAKE_DOMAIN}, "pivots": []}
        ix.enrich_result(res)
        ok(res["intelx"]["capability"]["power_pct"] == 50,
           "keyless enrich_result records the capability instead of an empty result set")
        bres = {"pivots": [{"kind": "file:sha256", "value": FAKE_SHA256}]}
        ar.enrich_result(bres)
        ok(bres["anyrun"]["capability"]["power_pct"] == 50,
           "keyless ANY.RUN enrich_result records the capability instead of an empty result set")
    finally:
        ix._call, ar._call = _saved_call, _saved_ar_call
        _restore_ix_keys(was_ix)
        for k, v in was_ar.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  {'ok ' if status == 'ok' else 'FAIL'}  {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
