#!/usr/bin/env python3
"""
test_references.py — the gate on WebPivot's reference DATA layer (contributor RULE 3 / RULE 5).

Run:  python3 tests/test_references.py               (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_references.py -q    (also works)

WHAT THIS PROTECTS
------------------
Reference files are how an analyst tunes the tooling without editing Python. That only works if
three things hold, and each has a failure mode that is SILENT in production:

  1. Every file parses and is documented. A `_comment` an analyst can't read is a list they will
     not touch — and an undocumented denylist is one nobody dares extend.
  2. Every consumer actually LOADS the file. `load_ref` degrades to a minimal embedded fallback
     when a file is missing or malformed, and warns on stderr — but a warning scrolls past in a
     long run. A module quietly running on its 10-entry fallback instead of its 100-entry data
     file filters almost nothing, and a filter that returns False everywhere MANUFACTURES false
     clusters. So we assert the loaded values are strictly richer than the fallback.
  3. A broken data file degrades LOUDLY. Returning an empty dict would turn every downstream
     `any(... for x in LIST)` filter into False and start clustering on registrar boilerplate.

RULE 5 coverage: `wp_ippivot._MANAGED_MX` and `wp_recon.MAIL_PROVIDERS` are the managed-provider
lists that decide whether shared mail/DNS infrastructure counts as a same-operator link. Proving
they load the real JSON — not the stub — is what keeps a managed provider classified as noise and
a self-hosted host classified as signal.

SCOPE: WebPivot only. Upstream (`intelligence_assist`) also carries this layer in `tools/kb/`,
`BinaryPivot/` and `IntelGraph/`; cti-expert has not vendored those halves yet. When they land,
extend `LOADERS` and `consumers` below — the KB half in particular is RULE 5 clustering logic and
needs its own classification test, which `tests/test_indicator_classification.py` covers today.
"""
import contextlib
import glob
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")

# Generated caches, not analyst-tunable lists: exempt from the per-group `_comment` rule (they
# still need the top-level one). `asn_registry` documents itself through a richer `_meta` block
# and grows by upsert from wp_ippivot, so its single `asns` group is exempt too.
GENERATED = {"cdn_ranges.json", "asn_registry.json"}


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    for p in (os.path.join(ENGINE, "WebPivot", "tools"),):
        if p not in sys.path:
            sys.path.insert(0, p)

    # --- 1. every reference file parses, is documented, has no empty group ------------------
    files = sorted(glob.glob(os.path.join(ENGINE, "*", "references", "*.json")))
    ok(len(files) >= 8, f"found the reference data files ({len(files)})")
    for path in files:
        rel = os.path.relpath(path, ROOT)
        base = os.path.basename(path)
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:
            ok(False, f"{rel} parses ({exc})")
            continue
        ok(isinstance(doc, dict), f"{rel} is a JSON object")
        ok(isinstance(doc.get("_comment"), str) and len(doc["_comment"]) > 40,
           f"{rel} has a top-level _comment an analyst can act on")
        groups = [k for k in doc if not k.startswith("_")]
        ok(bool(groups), f"{rel} defines at least one group")
        if base in GENERATED:
            continue
        for g in groups:
            node = doc[g]
            if not isinstance(node, dict):
                continue
            ok(isinstance(node.get("_comment"), str) and len(node["_comment"]) > 20,
               f"{rel}:{g} documented")
            payload = node.get("values", node.get("entries"))
            if payload is not None:
                ok(len(payload) > 0, f"{rel}:{g} is non-empty")
            # A `values` group is a membership/iteration list — a repeat is always an editing
            # slip, never meaningful, and it silently inflates the candidate counts that a
            # bounded sweep (generate_variants' max_variants) budgets against.
            vals = node.get("values")
            if isinstance(vals, list):
                hashable = [v for v in vals if isinstance(v, (str, int, float, bool))]
                dups = sorted({v for v in hashable if hashable.count(v) > 1})
                ok(not dups, f"{rel}:{g} has no duplicate values"
                             + (f" (found {dups[:4]})" if dups else ""))

    # --- 2. every consumer loaded its DATA FILE, not its embedded fallback -------------------
    # This is the check that matters most: a module silently on its fallback still imports, still
    # runs, still produces output — it just stops filtering. Comparing against the fallback size
    # catches that, and unlike a hardcoded count it does not rot as analysts extend a list.
    import wp_pivots, wp_analyze, wp_assets, wp_recon, wp_ippivot, wp_impersonate  # noqa: E401
    import wp_censys, wp_capabilities                                              # noqa: E401
    import whois_enrich, evidence_report                                           # noqa: E401

    consumers = [
        ("wp_pivots._GENERIC_SUBLABELS", wp_pivots._GENERIC_SUBLABELS,
         wp_pivots._LABELS_FALLBACK["subdomain_labels"]),
        ("wp_pivots.AFFILIATE_PARAMS", wp_pivots.AFFILIATE_PARAMS,
         wp_pivots._PIVOT_FALLBACK["affiliate_params"]),
        ("wp_pivots.SAAS_PIVOTS", wp_pivots.SAAS_PIVOTS,
         wp_pivots._PIVOT_FALLBACK["saas_pivots"]),
        ("wp_analyze._GENERIC_SEGMENTS", wp_analyze._GENERIC_SEGMENTS,
         wp_analyze._SEG_FALLBACK["resource_basename_segments"]),
        ("wp_assets._BACKEND_NOISE_SUFFIXES", wp_assets._BACKEND_NOISE_SUFFIXES,
         wp_assets._BACKEND_FALLBACK["backend_noise_suffixes"]),
        # RULE 5 — managed mail/DNS provider lists. On the fallback a managed provider stops
        # being recognised as shared infrastructure and starts reading as a same-operator link.
        ("wp_recon.MAIL_PROVIDERS", wp_recon.MAIL_PROVIDERS,
         wp_recon._MAIL_FALLBACK["mx_providers"]),
        ("wp_recon.SPF_ESP", wp_recon.SPF_ESP, wp_recon._MAIL_FALLBACK["spf_esp_hosts"]),
        ("wp_recon.DMARC_VENDORS", wp_recon.DMARC_VENDORS,
         wp_recon._MAIL_FALLBACK["dmarc_report_vendors"]),
        ("wp_ippivot._MANAGED_MX", wp_ippivot._MANAGED_MX,
         wp_ippivot._MX_FALLBACK["managed_mx_suffixes"]),
        # Censys renamed every field when it replaced Legacy Search with CenQL, so these templates
        # are the difference between a runnable query and one that silently returns zero hits. On
        # the fallback WebPivot still emits "a Censys query" for four artifact kinds and NOTHING
        # for the other fifteen — the pivot just quietly stops existing. `plan_capabilities` and
        # `credit_costs` are what let a Free-plan 403 read as "your plan can't search, here is the
        # UI link" instead of an opaque error, and what keeps --free-only honest about credits.
        ("wp_censys.CENQL_TEMPLATES", wp_censys.CENQL_TEMPLATES,
         wp_censys._CENSYS_FALLBACK["cenql_templates"]),
        ("wp_censys.PIVOT_KIND_MAP", wp_censys.PIVOT_KIND_MAP,
         wp_censys._CENSYS_FALLBACK["pivot_kind_map"]),
        ("wp_censys.CREDIT_COSTS", wp_censys.CREDIT_COSTS,
         wp_censys._CENSYS_FALLBACK["credit_costs"]),
        ("wp_censys.PLAN_CAPABILITIES", wp_censys.PLAN_CAPABILITIES,
         wp_censys._CENSYS_FALLBACK["plan_capabilities"]),
        ("wp_censys.ENDPOINTS", wp_censys.ENDPOINTS,
         wp_censys._CENSYS_FALLBACK["endpoints"]),
        # The spend guard. On the fallback the run still refuses to overspend (that is why the
        # fallback is the conservative minimum) but loses the analyst's own tuning — the month's
        # grant after buying credits, and the reserve that keeps 1-credit cert lookups affordable.
        ("wp_censys.CREDIT_BUDGET", wp_censys.CREDIT_BUDGET,
         wp_censys._CENSYS_FALLBACK["credit_budget"]),
        # The keyless banner. On the fallback it names four credentials instead of eight, so a run
        # missing SHODAN_KEY or PDNS_* reports FULL capability it does not have — the exact false
        # reassurance the capability layer exists to prevent.
        ("wp_capabilities.API_KEYS", wp_capabilities.API_KEYS,
         wp_capabilities._CAP_FALLBACK["api_keys"]),
        ("wp_capabilities.KEYLESS_BASELINE", wp_capabilities.KEYLESS_BASELINE,
         wp_capabilities._CAP_FALLBACK["keyless_baseline"]),
        ("wp_capabilities.IMPACT_LABELS", wp_capabilities.IMPACT_LABELS,
         wp_capabilities._CAP_FALLBACK["impact_labels"]),
        ("wp_impersonate.TLD_SWEEP", wp_impersonate.TLD_SWEEP,
         wp_impersonate._IMP_FALLBACK["tld_sweep"]),
        ("wp_impersonate.COMBO_AFFIXES", wp_impersonate.COMBO_AFFIXES,
         wp_impersonate._IMP_FALLBACK["combo_affixes"]),
        ("wp_impersonate._QWERTY", wp_impersonate._QWERTY,
         wp_impersonate._IMP_FALLBACK["qwerty_adjacency"]),
        ("wp_impersonate._HOMOGLYPH", wp_impersonate._HOMOGLYPH,
         wp_impersonate._IMP_FALLBACK["homoglyphs"]),
        ("whois_enrich._CALLING_CODES", whois_enrich._CALLING_CODES,
         whois_enrich._GEO_FALLBACK["calling_codes"]),
        ("whois_enrich._COUNTRY_ALIASES", whois_enrich._COUNTRY_ALIASES,
         whois_enrich._GEO_FALLBACK["country_aliases"]),
        ("whois_enrich._PRIVACY_MARKERS", whois_enrich._PRIVACY_MARKERS,
         whois_enrich._WHOIS_FALLBACK["privacy_markers"]),
        ("whois_enrich._PROXY_DOMAINS", whois_enrich._PROXY_DOMAINS,
         whois_enrich._WHOIS_FALLBACK["proxy_email_domains"]),
        ("evidence_report._NOISE_EMAIL_SUBSTR", evidence_report._NOISE_EMAIL_SUBSTR,
         evidence_report._RN_FALLBACK["noise_email_substrings"]),
    ]
    for name, loaded, fallback in consumers:
        ok(len(loaded) > len(fallback),
           f"{name} came from JSON ({len(loaded)} loaded > {len(fallback)} fallback)")

    # --- 3. a broken data file degrades loudly, never silently --------------------------------
    import wp_refs                                                                # noqa: E401
    fb = {"alpha": ["a", "b"], "beta": {"n": 1}}

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        got = wp_refs.load_ref(os.path.join(ROOT, "does", "not", "exist.json"), fb)
    ok(got == fb, "missing data file -> embedded fallback values")
    ok("WARNING" in err.getvalue(), "missing data file -> stderr WARNING (never silent)")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write("{ this is not json")
        broken = fh.name
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        got = wp_refs.load_ref(broken, fb)
    ok(got == fb, "malformed data file -> embedded fallback values")
    ok("WARNING" in err.getvalue(), "malformed data file -> stderr WARNING")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"alpha": {"_comment": "x", "values": ["a", "b", "c"]}}, fh)
        partial = fh.name
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        got = wp_refs.load_ref(partial, fb)
    ok(got["alpha"] == ["a", "b", "c"], "partial data file -> present group read from JSON")
    ok(got["beta"] == {"n": 1}, "partial data file -> absent group from fallback")
    ok("beta" in err.getvalue(), "partial data file -> WARNING names the missing group")

    for p in (broken, partial):
        os.unlink(p)

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_references():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} reference check(s) failed")
        sys.exit(1)
    print(f"PASS — WebPivot reference layer green ({_PASSED} checks: data files documented, "
          f"consumers verified loading real data, broken files degrade loudly)")
