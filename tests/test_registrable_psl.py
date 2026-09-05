#!/usr/bin/env python3
"""Regression: the eTLD+1 reducer (wp_common._registrable) is Public-Suffix-List aware.

WHAT THIS PROTECTS
------------------
Every collector, the KB ingester, the frontier and the co-tenancy guards key on the registrable
apex. Before the PSL, `horizon.io.vn` reduced to `io.vn` and `zc2.sa.com` to `sa.com`: a second-level
registry suffix became "the operator's apex", got enumerated, and its unrelated tenants were
collected as estate — 300 strangers' hosts in one loop run. This asserts:
  1. the PSL reference is loaded (not the empty fallback) and carries both sections;
  2. registry second-level suffixes (ICANN) and hosting platforms (PRIVATE) keep the tenant label;
  3. wildcard (`*.ck`) and exception (`!www.ck`) rules follow the PSL algorithm;
  4. ordinary hosts, bare apexes and public suffixes themselves are unchanged;
  5. the analyst override list (generic_labels.json → multi_part_tlds) is still honoured.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))

import wp_common as W  # noqa: E402

_TESTS = [
    # (host, expected registrable, label)
    ("horizon.io.vn", "horizon.io.vn", "io.vn (VNNIC second level) keeps the tenant label"),
    ("shop.id.vn", "shop.id.vn", "id.vn (VNNIC second level) keeps the tenant label"),
    ("zc2.sa.com", "zc2.sa.com", "sa.com (CentralNic) keeps the tenant label"),
    ("x.y.ru.com", "y.ru.com", "ru.com (CentralNic): deeper host reduces to tenant.ru.com"),
    ("queue.tov6larek.in.net", "tov6larek.in.net", "in.net (CentralNic) keeps the tenant label"),
    ("kit.pages.dev", "kit.pages.dev", "PRIVATE section: pages.dev tenant is the registrable unit"),
    ("shop.github.io", "shop.github.io", "PRIVATE section: github.io tenant is the registrable unit"),
    ("bbc.co.uk", "bbc.co.uk", "co.uk keeps three labels"),
    ("news.bbc.co.uk", "bbc.co.uk", "deeper co.uk host reduces to the apex"),
    ("a.b.example.com", "example.com", "ordinary host reduces to eTLD+1"),
    ("example.com", "example.com", "bare apex unchanged"),
    ("api.cmsnt.example", "cmsnt.example", "unknown TLD falls back to the last two labels"),
    ("com.vn", "com.vn", "a public suffix itself is returned unchanged"),
    ("io.vn", "io.vn", "a second-level public suffix itself is returned unchanged"),
    ("a.b.ck", "a.b.ck", "wildcard rule *.ck: b.ck is the suffix, a.b.ck registrable"),
    ("sni.cloudflaressl.com", "cloudflaressl.com", "a .com host still reduces normally"),
    ("host.example.com:8443", "example.com", "a :port is dropped before reduction"),
]


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    ok(len(W._PSL_REF["icann"]) > 5000 and len(W._PSL_REF["private"]) > 2000,
       "public_suffix_list.json loaded with both sections (not the empty fallback)")
    ok("io.vn" in W._PSL_RULES and "sa.com" in W._PSL_RULES and "pages.dev" in W._PSL_RULES,
       "the drift suffixes (io.vn, sa.com, pages.dev) are present as rules")
    ok("ck" in W._PSL_WILD and "www.ck" in W._PSL_EXC, "wildcard and exception rules parsed")
    for host, want, label in _TESTS:
        got = W._registrable(host)
        ok(got == want, f"{label}: {host} -> {got}" + ("" if got == want else f" (want {want})"))
    ok(W.public_suffix("horizon.io.vn") == "io.vn" and W.public_suffix("a.b.ck") == "b.ck",
       "public_suffix() exposes the matched suffix")
    ok(W.is_private_suffix("pages.dev") and W.is_private_suffix("x.compute.amazonaws.com")
       and not W.is_private_suffix("io.vn"),
       "is_private_suffix distinguishes hosting platforms (incl. wildcard-derived) from registries")
    ok(all(t in W._PSL_RULES for t in W._MULTI_TLDS),
       "generic_labels.json multi_part_tlds override is merged into the rule set")
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
