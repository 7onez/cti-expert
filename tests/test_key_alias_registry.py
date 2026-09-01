#!/usr/bin/env python3
"""Lock — every env-var name a tool accepts for a key MUST be declared in both key registries.

The capability banner (`meta.capability`) and `/apikeys status` decide "is this key present?" from
a registry (`intel_engine/WebPivot/references/api_keys.json` and `scripts/apikeys/registry.json`),
while the tools resolve the key via `_secret(...)`/`_key(...)` over a list of accepted env-names.
If a tool accepts a name the registry doesn't list, a user who sets ONLY that name gets the key
USED but reported MISSING — a false "keyless" caveat in the report / a false "not configured" in
/apikeys. This test pins `TOOL_LOOKUPS` (the names the code actually reads) as a subset of each
registry's canonical+aliases, so the two can never drift silently again.

Companion/required vars (FOFA_EMAIL, PDNS_USERNAME, PDNS_URL, CENSYS_ORG_ID) are NOT key values and
are deliberately excluded from TOOL_LOOKUPS — they must live in `extra`/`companion`/`requires`,
never in `aliases`.

Run:  python3 tests/test_key_alias_registry.py   |   pytest -q tests/test_key_alias_registry.py
"""
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP_JSON = os.path.join(ROOT, "intel_engine", "WebPivot", "references", "api_keys.json")
APIKEYS_JSON = os.path.join(ROOT, "scripts", "apikeys", "registry.json")
WP_TOOLS = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")

# The primary-key env-names each tool accepts, transcribed from the `_secret(...)` / `_key(...)`
# calls in the WebPivot/BinaryPivot tools. Keyed by the api_keys.json canonical env. When a tool's
# accepted-name list changes, update this map AND both registries — that is the whole point.
TOOL_LOOKUPS = {
    "FOFA_KEY": ["FOFA_KEY", "FOFA_API_KEY"],
    "URLSCAN_API_KEY": ["URLSCAN_API_KEY"],
    "CENSYS_PAT": ["CENSYS_PAT", "CENSYS_API_KEY", "CENSYS_TOKEN"],
    "WHOISXML_API_KEY": ["WHOISXML_API_KEY", "WHOISXMLAPI_KEY", "WHOIS_API_KEY"],
    "SERPAPI_KEY": ["SERPAPI_KEY", "SERPAPI_API_KEY", "SERP_API_KEY"],
    "INTELX_KEY": ["INTELX_KEY", "INTELX_API_KEY", "INTELLIGENCEX_KEY"],
    "ANYRUN_API_KEY": ["ANYRUN_API_KEY", "ANY_RUN_API_KEY", "ANYRUN_KEY"],
    "SHODAN_KEY": ["SHODAN_KEY", "SHODAN_API_KEY"],
    "PDNS_PASSWORD": ["PDNS_PASSWORD"],
    "IPINFO_TOKEN": ["IPINFO_TOKEN", "IPINFO_API_KEY"],
    "FLARESOLVERR_URL": ["FLARESOLVERR_URL"],
    "HUNTERHOW_API_KEY": ["HUNTERHOW_API_KEY", "HUNTER_HOW_API_KEY", "HUNTERHOW_KEY"],
    "GRAYHATWARFARE_API_KEY": ["GRAYHATWARFARE_API_KEY", "GRAYHAT_API_KEY", "GHW_API_KEY"],
    "VALIDIN_API_KEY": ["VALIDIN_API_KEY", "VALIDIN_API_KEY_FALLBACK"],
    "QUAKE_API_KEY": ["QUAKE_API_KEY", "QUAKE_API_KEY_FALLBACK", "QUAKE_TOKEN"],
    "ZOOMEYE_API_KEY": ["ZOOMEYE_API_KEY", "ZOOMEYE_API_KEY_FALLBACK", "ZOOMEYE_KEY"],
    "SECURITYTRAILS_API_KEY": ["SECURITYTRAILS_API_KEY", "SECURITYTRAILS_API_KEY_FALLBACK"],
    "DNSLYTICS_API_KEY": ["DNSLYTICS_API_KEY", "DNSLYTICS_API_KEY_FALLBACK"],
    "CERTSPOTTER_API_KEY": ["CERTSPOTTER_API_KEY"],
}

# Vars that are companions/requirements, never key values — must NOT appear in any `aliases`.
NEVER_ALIAS = {"FOFA_EMAIL", "PDNS_USERNAME", "PDNS_URL", "CENSYS_ORG_ID"}


def _cap_registry():
    """api_keys.json entries as {canonical_env: set(env+aliases)} — the capability/banner source."""
    sys.path.insert(0, WP_TOOLS)
    cap = importlib.import_module("wp_capabilities")
    out = {}
    for env, spec in cap.API_KEYS.items():
        if isinstance(spec, dict):
            out[env] = {env, *spec.get("aliases", [])}
    return cap, out


def _apikeys_services():
    """registry.json services as list of (env, set(env+aliases), set(extra))."""
    data = json.load(open(APIKEYS_JSON, encoding="utf-8"))
    svcs = []
    for s in data["services"]:
        svcs.append((s["env"], {s["env"], *s.get("aliases", [])}, set(s.get("extra", []))))
    return svcs


def test_capability_registry_covers_every_tool_lookup():
    _cap, cap_reg = _cap_registry()
    missing = []
    for canonical, names in TOOL_LOOKUPS.items():
        assert canonical in cap_reg, f"api_keys.json has no entry for {canonical}"
        for n in names:
            if n not in cap_reg[canonical]:
                missing.append(f"{canonical}: tool accepts {n} but api_keys.json aliases omit it")
    assert not missing, "; ".join(missing)


def test_apikeys_registry_covers_every_tool_lookup():
    svcs = _apikeys_services()
    problems = []
    for canonical, names in TOOL_LOOKUPS.items():
        nameset = set(names)
        # the service whose env+aliases intersects this key's accepted names
        hits = [(env, keyset) for env, keyset, _extra in svcs if keyset & nameset]
        if len(hits) != 1:
            problems.append(f"{canonical}: matched {len(hits)} apikeys services (want exactly 1)")
            continue
        _env, keyset = hits[0]
        for n in names:
            if n not in keyset:
                problems.append(f"{canonical}: tool accepts {n} but apikeys registry env+aliases omit it")
    assert not problems, "; ".join(problems)


def test_companion_vars_never_declared_as_aliases():
    _cap, cap_reg = _cap_registry()
    offenders = [f"api_keys.json:{env}" for env, keys in cap_reg.items() if keys & NEVER_ALIAS]
    for env, keyset, _extra in _apikeys_services():
        if keyset & NEVER_ALIAS:
            offenders.append(f"registry.json:{env}")
    assert not offenders, f"companion var mis-filed as an alias in: {offenders}"


def test_three_previously_silent_keys_now_registered():
    _cap, cap_reg = _cap_registry()
    for k in ("SECURITYTRAILS_API_KEY", "DNSLYTICS_API_KEY", "CERTSPOTTER_API_KEY"):
        assert k in cap_reg, f"{k} still absent from api_keys.json — banner would go silent on it"
    apikeys_envs = {env for env, _k, _e in _apikeys_services()}
    for k in ("SECURITYTRAILS_API_KEY", "DNSLYTICS_API_KEY", "CERTSPOTTER_API_KEY"):
        assert k in apikeys_envs, f"{k} absent from /apikeys registry"


def test_alias_only_key_is_not_reported_missing():
    """The concrete regression: set ONLY an alias name; capability must report the key PRESENT."""
    cap, _reg = _cap_registry()
    checks = [("WHOISXML_API_KEY", "WHOISXMLAPI_KEY"),
              ("QUAKE_API_KEY", "QUAKE_API_KEY_FALLBACK"),
              ("ZOOMEYE_API_KEY", "ZOOMEYE_KEY")]
    # blank every accepted name (present-but-empty blocks the .env reload; _secret treats "" as
    # absent), then set only the alias under test — process-local, never touches the real .env.
    allnames = {n for names in TOOL_LOOKUPS.values() for n in names}
    saved = {n: os.environ.get(n) for n in allnames}
    try:
        for canonical, alias in checks:
            for n in allnames:
                os.environ[n] = ""
            os.environ[alias] = "ALIASVAL"
            m = cap.capability_meta()
            assert canonical not in m["keys_missing"], f"{alias} set but {canonical} reported missing"
            assert canonical in m["keys_present"], f"{alias} set but {canonical} not reported present"
    finally:
        for n, v in saved.items():
            os.environ.pop(n, None) if v is None else os.environ.__setitem__(n, v)


# Services that live in the /apikeys catalog (scripts/apikeys/registry.json) but are NOT WebPivot
# capability legs — other skills/commands consume them. They MUST NOT appear in api_keys.json, or
# the WebPivot keyless banner would caveat a run on keys it never uses.
NON_WEBPIVOT_KEYS = {
    "HUDSONROCK_API_KEY", "CHONGLUADAO_API_KEY", "CLD_API_KEY", "BLOCKCHAIR_API_KEY",
    "GITHUB_TOKEN", "SUBSCAN_API_KEY", "BRIGHTDATA_SERP_KEY", "GEMINI_API_KEY",
    "GOOGLE_API_KEY", "ZONECRUNCHER_API_KEY",
}


def test_capability_registry_is_exactly_the_webpivot_tool_key_set():
    """The WebPivot banner registry must be EXACTLY the WebPivot capability legs — no missing key
    (silent banner) and no stray key (false caveat on a key WebPivot never reads)."""
    _cap, cap_reg = _cap_registry()
    assert set(cap_reg) == set(TOOL_LOOKUPS), (
        f"api_keys.json canonical set drifted from TOOL_LOOKUPS: "
        f"extra={sorted(set(cap_reg) - set(TOOL_LOOKUPS))} "
        f"missing={sorted(set(TOOL_LOOKUPS) - set(cap_reg))}")


def test_unrelated_keys_stay_out_of_the_webpivot_banner():
    """A key another skill owns (breach/crypto/code/AI) must never leak into api_keys.json."""
    _cap, cap_reg = _cap_registry()
    all_banner_names = {n for keys in cap_reg.values() for n in keys} | set(cap_reg)
    leaked = sorted(NON_WEBPIVOT_KEYS & all_banner_names)
    assert not leaked, f"non-WebPivot key(s) leaked into the capability banner: {leaked}"


_TESTS = [test_capability_registry_covers_every_tool_lookup,
          test_apikeys_registry_covers_every_tool_lookup,
          test_companion_vars_never_declared_as_aliases,
          test_three_previously_silent_keys_now_registered,
          test_alias_only_key_is_not_reported_missing,
          test_capability_registry_is_exactly_the_webpivot_tool_key_set,
          test_unrelated_keys_stay_out_of_the_webpivot_banner]


def check():
    passed = failed = 0
    out = []
    for t in _TESTS:
        label = t.__name__.removeprefix("test_").replace("_", " ")
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            out.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            out.append(("ok", label))
    return passed, failed, out


if __name__ == "__main__":
    _p, _f, _lines = check()
    for _s, _l in _lines:
        print(("ok   " if _s == "ok" else "FAIL ") + _l)
    print(f"\n{_p} passed, {_f} failed")
    raise SystemExit(bool(_f))
