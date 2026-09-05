"""Regression: a seed apex's OWN subdomains are collected like the apex and joined to it — and only
to it.

  1. case_state: a discovered host under a collected apex lands in `subdomains_pending` (not in the
     new-apex `pending`), hoster-plumbing labels (cpanel/autodiscover/www) and dead names are held
     back, and the per-apex cap applies.
  2. ingest: a collected subdomain and its apex both carry the `apex:<registrable>` indicator (rung-1
     same-registration join); two tenants of a SaaS / shared-infra apex get NO such edge (CLAUDE.md
     Rule 5: a managed-platform apex must not fuse unrelated tenants).
  3. wp_subenum: the .env → subfinder provider-config sync fills only empty providers and never
     overwrites a hand-set key; composite credentials use id:secret form.
Synthetic data only: example.com / .example hosts, RFC 5737 addresses, CASE-0001."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools", "kb"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))

import case_state as cs  # noqa: E402
import ingest_webpivot as iw  # noqa: E402
import knowledge_base as kbm  # noqa: E402
import wp_subenum as se  # noqa: E402


def _raw(host, third_party=(), crt_subs=()):
    return {"meta": {"host": host, "fetched_with": "urllib"},
            "artifacts": {"title": host, "http": {"status": 200}, "third_party_hosts": list(third_party)},
            "pivots": [{"kind": "domain", "value": host,
                        "live_results": {"crtsh": {"certs": [], "subdomains": list(crt_subs)},
                                         "dns": {"ips": ["203.0.113.10"]}}}]}


def test_seed_subdomains_go_to_their_own_bucket_with_guards():
    orig_resolve, orig_cap = cs._resolves, cs.SUB_MAX_PER_APEX
    cs._resolves = lambda h, timeout=4.0: not h.startswith("dead.")
    cs.SUB_MAX_PER_APEX = 3
    try:
        with tempfile.TemporaryDirectory() as tmp:
            case = os.path.join(tmp, "cases", "CASE-0001")
            os.makedirs(os.path.join(case, "raw"))
            json.dump(_raw("seed-brand.example",
                           third_party=["client.seed-brand.example", "api.seed-brand.example", "other.example"],
                           crt_subs=["cpanel.seed-brand.example", "www.seed-brand.example", "dead.seed-brand.example",
                                     "shop.seed-brand.example", "panel.seed-brand.example", "sms.seed-brand.example"]),
                      open(os.path.join(case, "raw", "seed-brand.example.json"), "w"))
            orig_case_dir = cs._case_dir
            cs._case_dir = lambda c: case
            try:
                fr = cs.frontier("CASE-0001", max_new=8)
            finally:
                cs._case_dir = orig_case_dir
        subs = fr["subdomains_pending"].get("seed-brand.example") or []
        assert not any(s.endswith("seed-brand.example") for s in fr["pending"]), "subdomain leaked into new-apex pending"
        assert "client.seed-brand.example" in subs and "api.seed-brand.example" in subs, subs
        for held in ("cpanel.seed-brand.example", "www.seed-brand.example", "dead.seed-brand.example"):
            assert held not in subs, held
        assert len(subs) == 3, subs                      # per-apex cap
        assert fr["subdomains"]["dead.seed-brand.example"]["dns"] is False
    finally:
        cs._resolves, cs.SUB_MAX_PER_APEX = orig_resolve, orig_cap


def _ingest(hosts):
    with tempfile.TemporaryDirectory() as tmp:
        kb = kbm.KB(os.path.join(tmp, "knowledge"))
        for h in hosts:
            p = os.path.join(tmp, h + ".json")
            json.dump(_raw(h), open(p, "w"))
            iw.ingest_file(kb, p)
        return [(e["src"], e["rel"], e["dst"]) for e in kb.edges() if e["dst"].startswith("apex:")]


def test_subdomain_and_apex_share_the_registration_indicator():
    edges = _ingest(["seed-brand.example", "client.seed-brand.example"])
    assert ("seed-brand.example", "is_apex", "apex:seed-brand.example") in edges or \
        ("seed-brand.example", "subdomain_of", "apex:seed-brand.example") in edges, edges
    assert ("client.seed-brand.example", "subdomain_of", "apex:seed-brand.example") in edges, edges
    # both point at the SAME indicator → union-find puts them in one cluster
    assert len({d for _, _, d in edges}) == 1


def test_saas_tenants_never_join_on_the_platform_apex():
    # pages.dev / github.io style platforms are in SHARED_INFRA / SAAS suffix lists — two tenants
    # are two operators; the apex edge must not be minted for them
    edges = _ingest(["kit-one.pages.dev", "kit-two.pages.dev"])
    assert not any(d == "apex:pages.dev" for _, _, d in edges), edges


def test_provider_sync_fills_only_empty_entries_and_keeps_hand_set_keys():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "provider-config.yaml")
        open(cfg, "w").write("shodan: []\nsecuritytrails:\n  - HANDSET-KEY\nfofa: []\nbevigil: []\n")
        env = {"SHODAN_KEY": "s-key", "SECURITYTRAILS_API_KEY": "from-env", "FOFA_EMAIL": "a@example.com",
               "FOFA_KEY": "f-key", "INTELX_KEY": "ix-key"}
        r = se.sync_subfinder_providers(config_path=cfg, env=env)
        text = open(cfg).read()
        assert r["filled"] == ["fofa", "intelx", "shodan"], r
        assert "securitytrails" in r["kept"] and "HANDSET-KEY" in text and "from-env" not in text
        assert '"a@example.com:f-key"' in text and '"2.intelx.io:ix-key"' in text
        assert "bevigil" in r["missing"]
        # idempotent: a second sync fills nothing more
        assert se.sync_subfinder_providers(config_path=cfg, env=env)["filled"] == []


_TESTS = [
    test_seed_subdomains_go_to_their_own_bucket_with_guards,
    test_subdomain_and_apex_share_the_registration_indicator,
    test_saas_tenants_never_join_on_the_platform_apex,
    test_provider_sync_fills_only_empty_entries_and_keeps_hand_set_keys,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001 — report every independent contract
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
    raise SystemExit(bool(_failed))
