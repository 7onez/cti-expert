"""Offline behavior tests for case-matched enrichment execution and closure."""
import json
import os
import sys
import tempfile
from unittest.mock import patch

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLS)
import case_state as cs  # noqa: E402
import enrichment_run as er  # noqa: E402


def _case(tmp):
    raw = os.path.join(tmp, "raw")
    os.makedirs(raw)
    with open(os.path.join(raw, "example.com.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"host": "example.com"},
                   "artifacts": {"whois": {"registrant_email": "owner@example.com",
                                           "registrant_org": "Example Labs"},
                                 "socials": {"github": ["https://github.com/test-owner"]}},
                   "pivots": [{"kind": "whois:registrant_phone", "value": "+18005550100"},
                              {"kind": "telegram", "value": "site_support"},
                              {"kind": "username", "value": "devaccount", "confidence": "high"},
                              {"kind": "telegram", "value": "+PlaceholderInvite123"}]}, fh)
    return tmp


def _index(case):
    with open(os.path.join(case, "enrichment", "index.json"), encoding="utf-8") as fh:
        return json.load(fh)["leads"]


def _email_all_done(extra_free=None):
    ran = {
        "hudsonrock": {"status": "ok", "hits": 1},
        "zonecruncher": {"status": "ok", "hits": 0},
        "intelx_search": {"status": "ok", "records": 0},
        "reverse_whois": {"status": "skipped", "stage": "preview", "count": 180,
                          "purchased": False},
    }
    if extra_free:
        ran.update(extra_free)
    return {"ran": ran, "planned": [
        {"step": "hudsonrock", "status": "RAN — key set and this selector needs it"},
        {"step": "zonecruncher", "status": "RAN — key set and this selector needs it"},
        {"step": "intelx_search", "status": "RAN — key set and this selector needs it"},
        {"step": "reverse_whois", "status": "RAN — key set and this selector needs it"},
        {"step": "hibp", "status": "BLOCKED — key absent"},
    ]}


def _fake(calls, fail_internal=False, email=None, github=None):
    def call(op, argv, case_dir, hide_env=None):
        calls.append((op, tuple(argv), tuple(sorted(hide_env or ()))))
        if op == "cld":
            if fail_internal and argv[0] == "internal-leaks":
                return {"returncode": 2, "stdout": '{"ok": false, "error": "HTTP 503"}'}
            data = {"ok": True, "op": argv[0], "result": {"items": [{"website": "example.com"}]}}
            if argv[0] == "route":
                data["result"] = {"sides": {"feeds": {"ok": True, "matched": 1},
                                            "shield": {"ok": True, "matched": 0}}}
        elif op == "email-deep":
            data = email(calls, argv, hide_env or ()) if email else _email_all_done()
        elif op == "phone":
            data = {"summary": {"valid": 1}}
        elif op == "intelx":
            data = {"domains": ["sibling.example.com"]}
        elif op == "github" and github:
            data = github(argv)
        else:
            data = {"identities": [{"email": "dev@example.com"}], "api": {"errors": []}}
        return {"returncode": 0, "stdout": json.dumps(data), "credits": []}
    return call


def _key_env(**overrides):
    # Build the blank set from the live registry-expanded sets so a dev/CI machine that exports a
    # key ALIAS (INTELLIGENCEX_KEY, WHOIS_API_KEY, …) can't leak into a "missing key" assertion.
    names = {"HIBP_API_KEY", "GITHUB_TOKEN"}
    for grp in list(er.KEY_ENVS.values()) + list(er.EMAIL_METERED.values()):
        names.update(grp)
    env = {n: "" for n in names}
    env.update(overrides)
    return env


def test_keyed_matches_and_persists_index_rows():
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake", INTELX_KEY="fake", HUDSONROCK_API_KEY="fake",
            ZONECRUNCHER_API_KEY="fake", WHOISXML_API_KEY="fake")):
        case = _case(tmp)
        leads = {x["key"]: x for x in cs.frontier(case)["enrichment_leads"]}
        assert "cld-actor:devaccount" in leads and "phone:+18005550100" in leads
        assert "cld-telegram:site_support" in leads
        assert "cld-telegram:+placeholderinvite123" not in leads
        assert leads["cld-org:example labs"]["run"] == [
            {"op": "cld", "argv": ["ransomware", "Example Labs"]},
            {"op": "cld", "argv": ["internal-leaks", "Example Labs"]}]
        calls = []
        er.run_case(case, call=_fake(calls))
        assert ("phone", ("+18005550100",), ()) in calls
        assert ("cld", ("route", "t.me/site_support"), ()) in calls
        assert ("cld", ("actor-usernames", "devaccount"), ()) in calls
        assert ("intelx", ("phonebook", "example.com"), ()) in calls
        assert cs.load_state(case)["enrichment_done"]["cld-org:example labs"] == "ran"
        idx = _index(case)
        row = idx["cld-org:example labs"]
        assert row["outcome"] == "ran" and row["file"].endswith(".json")
        assert "matched=" in row["summary"] and "\n" not in row["summary"]
        assert {x["key"] for x in cs.frontier(case)["enrichment_leads"]} >= {
            "dork:example.com", "github:example.com", "grayhatwarfare:example.com"}
        er.run_case(case, call=_fake(calls))
        assert len(calls) == 9, calls


def test_free_only_holds_metered_but_runs_unlimited_cld():
    # free-only holds METERED legs (email-deep, IntelX phonebook) open until a keyed full run, but
    # ChongLuaDao is unlimited, so its legs RUN even under free-only. Missing keys still hold.
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake", INTELX_KEY="fake", HUDSONROCK_API_KEY="fake",
            ZONECRUNCHER_API_KEY="fake", WHOISXML_API_KEY="fake")):
        case = _case(tmp)
        calls = []
        er.run_case(case, call=_fake(calls), free_only=True)
        idx = _index(case)
        assert idx["email-deep:owner@example.com"]["outcome"] == "held"        # metered → held
        assert idx["intelx-phonebook:example.com"]["outcome"] == "held"        # metered → held
        open_keys = {x["key"] for x in cs.frontier(case)["enrichment_leads"]}
        assert "email-deep:owner@example.com" in open_keys
        assert ("cld", ("route", "+18005550100"), ()) in calls                 # unlimited → ran
        assert cs.load_state(case)["enrichment_done"]["cld-phone:+18005550100"] in ("ran", "empty")
        er.run_case(case, call=_fake(calls))                                   # keyed full run
        assert cs.load_state(case)["enrichment_done"]["email-deep:owner@example.com"] in ("ran", "empty")
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env()):
        case = _case(tmp)
        calls = []
        er.run_case(case, call=_fake(calls))
        done = cs.load_state(case)["enrichment_done"]
        assert "cld-phone:+18005550100" not in done                           # no CLD key
        assert _index(case)["cld-phone:+18005550100"]["outcome"] == "unavailable"
        assert "cld-phone:+18005550100" in {x["key"] for x in cs.frontier(case)["enrichment_leads"]}
        with patch.dict(os.environ, _key_env(CHONGLUADAO_API_KEY="fake")):
            er.run_case(case, call=_fake(calls))
        assert ("cld", ("route", "+18005550100"), ()) in calls


def test_default_defer_holds_metered_runs_free_and_cld():
    # The default loop defers METERED enrichment; free legs (phone, github) and unlimited CLD legs
    # still run. email-deep and IntelX phonebook stay held.
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake", INTELX_KEY="fake", HUDSONROCK_API_KEY="fake")):
        case = _case(tmp)
        calls = []
        er.run_case(case, call=_fake(calls), defer_metered=True)
        ops = {op for op, _argv, _hide in calls}
        assert {"phone", "github", "cld"} <= ops, calls
        assert _index(case)["cld-phone:+18005550100"]["outcome"] in ("ran", "empty")
        assert _index(case)["email-deep:owner@example.com"]["outcome"] == "held"
        assert _index(case)["intelx-phonebook:example.com"]["outcome"] == "held"
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake", INTELX_KEY="fake")):
        case = _case(tmp)
        calls = []
        er.run_case(case, call=_fake(calls), passive=True)
        # passive is an egress posture, not a spend gate: the metered IntelX phonebook still runs.
        assert ("intelx", ("phonebook", "example.com"), ()) in calls
        assert ("cld", ("route", "t.me/site_support"), ()) in calls
        assert cs.load_state(case)["enrichment_done"]["intelx-phonebook:example.com"] in ("ran", "empty")
        assert cs.load_state(case)["enrichment_done"]["cld-telegram:site_support"] in ("ran", "empty")
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake")):
        case = _case(tmp)
        with open(os.path.join(case, "scope.json"), "w", encoding="utf-8") as fh:
            json.dump({"constraints": {"no_spend": True}}, fh)
        calls = []
        er.run_case(case, call=_fake(calls))
        # no_spend blocks metered credits; CLD is unlimited, so it still runs under no_spend.
        assert cs.load_state(case)["enrichment_done"]["cld-telegram:site_support"] in ("ran", "empty")
        assert ("cld", ("route", "t.me/site_support"), ()) in calls


def test_partial_org_resume_and_email_deep_judging():
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake", INTELX_KEY="fake", HUDSONROCK_API_KEY="fake")):
        case = _case(tmp)
        calls = []
        er.run_case(case, call=_fake(calls, fail_internal=True))
        assert "cld-org:example labs" not in cs.load_state(case)["enrichment_done"]
        before = len([x for x in calls if x[:2] == ("cld", ("ransomware", "Example Labs"))])
        er.run_case(case, call=_fake(calls))
        after = len([x for x in calls if x[:2] == ("cld", ("ransomware", "Example Labs"))])
        assert before == after == 1, calls
        assert cs.load_state(case)["enrichment_done"]["cld-org:example labs"] == "ran"
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            HUDSONROCK_API_KEY="fake", ZONECRUNCHER_API_KEY="fake", INTELX_KEY="fake",
            WHOISXML_API_KEY="fake")):
        case = _case(tmp)
        calls = []

        def email_with_free_failure(_calls, _argv, _hide):
            return _email_all_done({
                "email_hygiene": {"status": "failed (TimeoutError)"},
                "domain_reputation": {"status": "ok"},
            })

        er.run_case(case, call=_fake(calls, email=email_with_free_failure))
        done = cs.load_state(case)["enrichment_done"]
        assert done["email-deep:owner@example.com"] == "ran"
        row = _index(case)["email-deep:owner@example.com"]
        assert row["outcome"] == "ran"
        assert "reverse_whois=done:180" in row["summary"]
        assert "free=2 ran/1 failed" in row["summary"]


def test_email_deep_memo_hides_successful_metered_steps_on_retry():
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            HUDSONROCK_API_KEY="fake", ZONECRUNCHER_API_KEY="fake")):
        case = _case(tmp)
        calls = []

        def email_partial(_calls, _argv, hide):
            if "HUDSONROCK_API_KEY" in hide:
                ran = {"zonecruncher": {"status": "ok", "hits": 0}}
            else:
                ran = {"hudsonrock": {"status": "ok", "hits": 1},
                       "zonecruncher": {"status": "unavailable", "error": "HTTP 503"}}
            return {"ran": ran, "planned": [
                {"step": "hudsonrock", "status": "RAN — key set and this selector needs it"},
                {"step": "zonecruncher", "status": "RAN — key set and this selector needs it"},
                {"step": "intelx_search", "status": "BLOCKED — key absent"},
                {"step": "reverse_whois", "status": "BLOCKED — key absent"},
                {"step": "hibp", "status": "BLOCKED — key absent"},
            ]}

        er.run_case(case, call=_fake(calls, email=email_partial))
        assert "email-deep:owner@example.com" not in cs.load_state(case)["enrichment_done"]
        er.run_case(case, call=_fake(calls, email=email_partial))
        assert any(c[0] == "email-deep" and "HUDSONROCK_API_KEY" in c[2] for c in calls), calls
        assert _index(case)["email-deep:owner@example.com"]["outcome"] == "unavailable"


def test_github_rate_limit_with_partial_profile_stays_open():
    with tempfile.TemporaryDirectory() as tmp:
        case = _case(tmp)

        def limited(_argv):
            return {"api": {"errors": ["rate-limited by api.github.com"],
                            "rate_limit_remaining": 0},
                    "profile": {"login": "test-owner"}, "repos": [], "identities": []}

        er.run_case(case, call=_fake([], github=limited), defer_metered=True)
        assert "github-account:test-owner" not in cs.load_state(case)["enrichment_done"]
        assert _index(case)["github-account:test-owner"]["outcome"] == "retry"
        assert "github-account:test-owner" in {
            lead["key"] for lead in cs.frontier(case)["enrichment_leads"]}


def test_legacy_unavailable_reopen_only_when_safe_or_explicit():
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake")):
        case = _case(tmp)
        cs.mark_enrichment_done(case, ["cld-phone:+18005550100"], "unavailable")
        er.run_case(case, call=_fake([]))
        assert "cld-phone:+18005550100" in cs.load_state(case)["enrichment_done"]
        calls = []
        er.run_case(case, call=_fake(calls), reopen_legacy=True)
        assert ("cld", ("route", "+18005550100"), ()) in calls
        assert cs.load_state(case)["enrichment_done"]["cld-phone:+18005550100"] in ("ran", "empty")
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            CHONGLUADAO_API_KEY="fake")):
        case = _case(tmp)
        key = "cld-phone:+18005550100"
        er._save(er._artifact(case, key), {"key": key, "steps": {}})
        cs.mark_enrichment_done(case, [key], "unavailable")
        calls = []
        er.run_case(case, call=_fake(calls))
        assert ("cld", ("route", "+18005550100"), ()) in calls
        assert cs.load_state(case)["enrichment_done"][key] in ("ran", "empty")



def test_index_records_empty_outcome():
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env()):
        case = _case(tmp)

        def empty_phone(op, argv, case_dir, hide_env=None):
            if op == "phone":
                return {"returncode": 0, "stdout": json.dumps({"summary": {"valid": 0}})}
            return _fake([])(op, argv, case_dir, hide_env=hide_env)

        er.run_case(case, call=empty_phone, defer_metered=True)
        row = _index(case)["phone:+18005550100"]
        assert row["outcome"] == "empty"
        assert row["file"].endswith(".json")
        assert cs.load_state(case)["enrichment_done"]["phone:+18005550100"] == "empty"


def test_call_does_not_ledger_cld_manually():
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env(
            API_USAGE_LOG=os.path.join(tmp, "usage.jsonl"))):
        case = _case(tmp)

        class Result:
            returncode = 0
            stderr = ""
            stdout = json.dumps({"ok": True, "op": "route",
                                 "result": {"sides": {"feeds": {"ok": True, "matched": 1}}}})

        with patch.object(er.subprocess, "run", return_value=Result()):
            res = er._call("cld", ["route", "example.com"], case)
        assert res.get("credits") == []
        assert not os.path.exists(os.environ["API_USAGE_LOG"])


def test_key_aliases_expand_from_registry():
    # A registered alias must count as the key (else a keyed .env reads as missing) AND must be
    # blanked on retry — otherwise deep_profile's .env reload resurrects the key through the alias
    # and re-buys the memoized metered step (reverse-WHOIS purchase, IntelX search).
    assert {"WHOISXML_API_KEY", "WHOISXMLAPI_KEY", "WHOIS_API_KEY"} <= set(er.EMAIL_METERED["reverse_whois"])
    assert "INTELLIGENCEX_KEY" in er.EMAIL_METERED["intelx_search"]
    assert "INTELLIGENCEX_KEY" in er.KEY_ENVS["intelx"]
    assert "WHOIS_API_KEY" in er.KEY_ENVS["email-deep"]
    hide = er._email_hide_env({"reverse_whois": {"state": "done"}})
    assert {"WHOISXML_API_KEY", "WHOIS_API_KEY", "WHOISXMLAPI_KEY"} <= set(hide)
    with patch.dict(os.environ, _key_env(WHOIS_API_KEY="fake")):
        assert er._keys("email-deep")                        # an alias satisfies the key gate
        assert er._has_any(er.EMAIL_METERED["reverse_whois"])


def test_enrich_run_wires_load_env_before_run_case():
    # The CLI/MCP enrich path (intel._run_enrichment) must load .env ITSELF — it never enters
    # cmd_open/cmd_loop. Assert the WIRING, not just _load_env: patch run_case and confirm the key
    # from CTI_API_KEYS_ENV is already in os.environ when it fires. Deleting _run_enrichment's
    # _load_env() call regresses this. _run_enrichment does `import enrichment_run`, the same module
    # object as er, so patching er.run_case intercepts it.
    import intel  # noqa: E402
    seen = []
    with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, _key_env()):
        envf = os.path.join(tmp, "keys.env")
        with open(envf, "w", encoding="utf-8") as fh:
            fh.write("CHONGLUADAO_API_KEY=fake-override-key\n")
        os.environ["CTI_API_KEYS_ENV"] = envf
        os.environ.pop("CHONGLUADAO_API_KEY", None)
        with patch.object(er, "run_case",
                          lambda case, **kw: seen.append(os.environ.get("CHONGLUADAO_API_KEY"))):
            intel._run_enrichment("CASE-X")
    assert seen == ["fake-override-key"], seen

_TESTS = [
    test_keyed_matches_and_persists_index_rows,
    test_free_only_holds_metered_but_runs_unlimited_cld,
    test_default_defer_holds_metered_runs_free_and_cld,
    test_partial_org_resume_and_email_deep_judging,
    test_email_deep_memo_hides_successful_metered_steps_on_retry,
    test_github_rate_limit_with_partial_profile_stays_open,
    test_legacy_unavailable_reopen_only_when_safe_or_explicit,
    test_index_records_empty_outcome,
    test_call_does_not_ledger_cld_manually,
    test_key_aliases_expand_from_registry,
    test_enrich_run_wires_load_env_before_run_case,
]


def check():
    lines = []
    for test in _TESTS:
        try:
            test()
            lines.append(("ok", test.__name__))
        except Exception as exc:
            lines.append(("FAIL", f"{test.__name__}: {exc}"))
    return len(_TESTS) - sum(s == "FAIL" for s, _ in lines), sum(s == "FAIL" for s, _ in lines), lines


if __name__ == "__main__":
    _, failed, lines = check()
    for status, label in lines:
        print(status, label)
    raise SystemExit(bool(failed))
