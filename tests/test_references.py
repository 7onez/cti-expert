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
    import wp_censys, wp_capabilities, wp_net                                      # noqa: E401
    import whois_enrich, evidence_report, wp_webamon, wp_moli, wp_vncorp, wp_quarry  # noqa: E401
    import wp_origin_history                                                       # noqa: E401
    import wp_sellers                                                              # noqa: E401
    import wp_appdev                                                               # noqa: E401
    import whois_eras                                                              # noqa: E401
    import wp_crypto_refs                                                          # noqa: E401
    _kb_tools = os.path.join(ENGINE, "tools", "kb")
    if _kb_tools not in sys.path:
        sys.path.append(_kb_tools)
    import noise_filters                                                           # noqa: E401

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
        # urlscan Pro hostname index (audit item 2). On the fallback the walk is one page and A/NS
        # only, so a drop-catch host's MX/SOA eras and zonefile/scan firsts silently vanish from the
        # timeline — narrower evidence presented as complete.
        ("wp_net.URLSCAN_ENDPOINTS", wp_net.URLSCAN_ENDPOINTS,
         wp_net._USCAN_FALLBACK["endpoints"]),
        ("wp_net.URLSCAN_HOSTNAME_CFG.era_types", wp_net.URLSCAN_HOSTNAME_CFG["era_types"],
         wp_net._USCAN_FALLBACK["hostname"]["era_types"]),
        ("wp_net.URLSCAN_HOSTNAME_CFG.first_seen_sources", wp_net.URLSCAN_HOSTNAME_CFG["first_seen_sources"],
         wp_net._USCAN_FALLBACK["hostname"]["first_seen_sources"]),
        ("wp_net.URLSCAN_STRUCTURAL_LABELS", wp_net.URLSCAN_STRUCTURAL_LABELS,
         wp_net._USCAN_FALLBACK["verdict"]["structural_labels"]),
        # dom_assets: the JS/CSS a urlscan-recovered page loaded — on the fallback only 10 resources
        # and two extensions are fetched, so a bundle-heavy SPA loses its API/app-download layer.
        ("wp_net.URLSCAN_DOM_ASSETS_CFG.extensions", wp_net.URLSCAN_DOM_ASSETS_CFG["extensions"],
         wp_net._USCAN_FALLBACK["dom_assets"]["extensions"]),
        # gated: on the fallback only a 403/429/503 or 'just a moment...' is a gate, so a DDoS-Guard
        # or 'Attention Required!' capture is parsed as the operator's kit (CDN selectors as pivots).
        ("wp_net.URLSCAN_GATED_LABELS", wp_net.URLSCAN_GATED_LABELS,
         wp_net._USCAN_FALLBACK["gated"]["labels"]),
        ("wp_net.URLSCAN_GATED_STATUS", wp_net.URLSCAN_GATED_STATUS,
         wp_net._USCAN_FALLBACK["gated"]["statuses"]),
        ("wp_net.URLSCAN_GATED_TITLES", wp_net.URLSCAN_GATED_TITLES,
         wp_net._USCAN_FALLBACK["gated"]["titles"]),
        # resubmit: on the fallback .cc/.ws/.to … read as countries, so an all-gated rescan goes out
        # from an unrelated country; with no alias .uk sends `uk`, which urlscan rejects.
        ("wp_net.URLSCAN_GENERIC_CCTLDS", wp_net.URLSCAN_GENERIC_CCTLDS,
         wp_net._USCAN_FALLBACK["resubmit"]["generic_cctlds"]),
        ("wp_net.URLSCAN_CCTLD_ALIASES", wp_net.URLSCAN_CCTLD_ALIASES,
         wp_net._USCAN_FALLBACK["resubmit"]["cctld_aliases"]),
        ("evidence_report._NOISE_EMAIL_SUBSTR", evidence_report._NOISE_EMAIL_SUBSTR,
         evidence_report._RN_FALLBACK["noise_email_substrings"]),
        # VN business registry (keyless): `sources` are the mirror URL templates — on the fallback only
        # one mirror is asked, so a single dead mirror reads as "no such company"; `label_map` is the
        # Vietnamese label → canonical field map — a shorter map silently drops the director/phone.
        ("wp_vncorp.SOURCES", wp_vncorp.SOURCES, wp_vncorp._VNCORP_FALLBACK["sources"]),
        ("wp_vncorp.LABEL_MAP", wp_vncorp.LABEL_MAP, wp_vncorp._VNCORP_FALLBACK["label_map"]),
        # Webamon (RULE 5 adjacent): `report_fields` is what a scan is reduced to — on the fallback the
        # DNS/ASN/issuer columns vanish from the seed block; `fingerprints.noise` is the list of
        # configuration-level hashes that must NEVER be queried as a same-kit pivot (cert_config alone
        # answers 179k hosts) — a shorter list means a boilerplate hash gets asked as if it were a kit.
        ("wp_webamon.SEARCH.report_fields", wp_webamon.SEARCH["report_fields"],
         wp_webamon._WEBAMON_FALLBACK["search"]["report_fields"]),
        ("wp_webamon.FINGERPRINTS.noise", wp_webamon.FINGERPRINTS["noise"],
         wp_webamon._WEBAMON_FALLBACK["fingerprints"]["noise"]),
        ("wp_webamon.FINGERPRINTS.same_kit", wp_webamon.FINGERPRINTS["same_kit"],
         wp_webamon._WEBAMON_FALLBACK["fingerprints"]["same_kit"]),
        ("wp_quarry.KIND_RUNGS", wp_quarry.KIND_RUNGS, wp_quarry._QUARRY_FALLBACK["kind_rungs"]),
        # Moli: `verified_schemes` is the Gate-0 egress allowlist — on the 1-scheme fallback every
        # SOCKS pool render silently moves to Chromium; `assets` are the pinned, checksummed release
        # archives the installers download — on the empty fallback the default install ships no Moli.
        ("wp_moli.VERIFIED_PROXY_SCHEMES", wp_moli.VERIFIED_PROXY_SCHEMES,
         wp_moli._MOLI_FALLBACK["proxy"]["verified_schemes"]),
        ("wp_moli.ASSETS", wp_moli.ASSETS, wp_moli._MOLI_FALLBACK["assets"]),
        # Historical origin sweep (RULE 5): on the fallback only three edge ASNs and two edge names are
        # known, so an Akamai / Imperva / DDoS-Guard / Sucuri history row reads as an operator ORIGIN
        # and is collected as an IP seed; on the 1-entry parking list a Bodis/ParkingCrew era does too.
        ("wp_origin_history.EDGE_ASNS", wp_origin_history.EDGE_ASNS,
         wp_origin_history._ORIGIN_FALLBACK["edge_asns"]),
        ("wp_origin_history.EDGE_ORG_MARKERS", wp_origin_history.EDGE_ORG_MARKERS,
         wp_origin_history._ORIGIN_FALLBACK["edge_org_markers"]),
        ("wp_origin_history.PARKING_MARKERS", wp_origin_history.PARKING_MARKERS,
         wp_origin_history._ORIGIN_FALLBACK["parking_markers"]),
        ("wp_origin_history.AMBIGUOUS_ASNS", wp_origin_history.AMBIGUOUS_ASNS,
         wp_origin_history._ORIGIN_FALLBACK["ambiguous_asns"]),
        ("wp_origin_history.AMBIGUOUS_ORG_MARKERS", wp_origin_history.AMBIGUOUS_ORG_MARKERS,
         wp_origin_history._ORIGIN_FALLBACK["ambiguous_org_markers"]),
        # ad-network edge + no-owner verdict (RULE 5): on the 3-region fallback an ad network's edge
        # pool outside those regions reads as operator origins and binds unrelated publishers; on the
        # 3-class / 2-suffix fallback fewer IP-only clusters get the deterministic verdict (LLM spend).
        ("wp_origin_history.AD_EDGE_REGION_CIDRS", wp_origin_history.AD_EDGE_REGION_CIDRS,
         wp_origin_history._ORIGIN_FALLBACK["ad_edge"]["region_cidrs"]),
        ("wp_origin_history.NO_OWNER_CONFIDENCE", wp_origin_history.NO_OWNER_CONFIDENCE,
         wp_origin_history._ORIGIN_FALLBACK["no_owner_verdict"]["class_confidence"]),
        ("wp_origin_history.PROVIDER_HOST_SUFFIXES", wp_origin_history.PROVIDER_HOST_SUFFIXES,
         wp_origin_history._ORIGIN_FALLBACK["no_owner_verdict"]["provider_host_suffixes"]),
        # sellers.json payee lookup: `settings` carries the URL, cache path, TTL and download timeout
        # — on the fallback an analyst's cache_path / ttl_days edit is silently ignored and the
        # 110 MB file lands in (or is re-fetched into) the default location on the default cadence.
        ("wp_sellers.SETTINGS", wp_sellers.SETTINGS, wp_sellers._SELLERS_FALLBACK["settings"]),
        # App-store developer lookup: `endpoints` on the fallback drop the other-apps fan-out and
        # the bundle-id lookup; `noise_hosts` on the 2-entry fallback lets a store CDN/policy link
        # read as the developer's own website — and a website match is an OWNER link.
        ("wp_appdev.ENDPOINTS", wp_appdev.ENDPOINTS, wp_appdev._APPDEV_FALLBACK["endpoints"]),
        ("wp_appdev.NOISE_HOSTS", wp_appdev.NOISE_HOSTS, wp_appdev._APPDEV_FALLBACK["noise_hosts"]),
        # WHOIS/TXT owner indicators (whois.privacy_customer, txt.verification). On the fallback no
        # privacy-customer id is extracted at all, TXT verification sees UUIDs only against one
        # provider zone, and registrar NIC-staff mailboxes / RDDS notice text reach registrant terms.
        ("whois_eras.PRIVACY_CUSTOMER_PATTERNS", whois_eras.PRIVACY_CUSTOMER_PATTERNS,
         whois_eras._PC_FALLBACK["privacy_customer_patterns"]),
        ("wp_recon.TXT_TOKEN_SHAPES", wp_recon.TXT_TOKEN_SHAPES, wp_recon._TXTV_FALLBACK["token_shapes"]),
        ("wp_recon.TXT_PROVIDER_ZONES", wp_recon.TXT_PROVIDER_ZONES,
         wp_recon._TXTV_FALLBACK["provider_zones"]),
        ("wp_recon.TXT_IGNORED_PREFIXES", wp_recon.TXT_IGNORED_PREFIXES,
         wp_recon._TXTV_FALLBACK["ignored_prefixes"]),
        ("noise_filters.REGISTRAR_ROLE_LOCALPARTS", noise_filters.REGISTRAR_ROLE_LOCALPARTS,
         noise_filters._FALLBACK["registrar_role_localparts"]),
        ("noise_filters.WHOIS_NOTICE_PHRASES", noise_filters.WHOIS_NOTICE_PHRASES,
         noise_filters._FALLBACK["whois_notice_phrases"]),
        # Email / apex noise (RULE 5): on the fallback srcset filenames (`banner@2x.woff2`) become
        # email indicators, a registry's support@/billing@ box reads as a registrant, and a page's
        # session-replay / attribution / chat-widget vendors seed the frontier as operator apexes.
        ("noise_filters.ASSET_FILENAME_EXTENSIONS", noise_filters.ASSET_FILENAME_EXTENSIONS,
         noise_filters._FALLBACK["asset_filename_extensions"]),
        ("noise_filters.ROLE_EMAIL_LOCALPARTS", noise_filters.ROLE_EMAIL_LOCALPARTS,
         noise_filters._FALLBACK["role_email_localparts"]),
        ("noise_filters.SHARED_INFRA_APEXES", noise_filters.SHARED_INFRA_APEXES,
         noise_filters._FALLBACK["shared_infra_apexes"]),
        ("noise_filters.SAAS_TENANT_SUFFIXES", noise_filters.SAAS_TENANT_SUFFIXES,
         noise_filters._FALLBACK["saas_tenant_suffixes"]),
        # Crypto reference constants: on the 2-entry fallbacks the other BIP/EIP test vectors and burn
        # addresses extract as wallets, and USDC/DAI/BUSD contracts read as one shared payout wallet
        # that clusters every site accepting the token (an owner-rung false merge).
        ("wp_crypto_refs.REFERENCE_ADDRESSES", wp_crypto_refs.REFERENCE_ADDRESSES,
         wp_crypto_refs._CRYPTO_REF_FALLBACK["reference_crypto_addresses"]),
        ("wp_crypto_refs.TOKEN_CONTRACTS", wp_crypto_refs.TOKEN_CONTRACTS,
         wp_crypto_refs._CRYPTO_REF_FALLBACK["token_contracts"]),
    ]
    for name, loaded, fallback in consumers:
        ok(len(loaded) > len(fallback),
           f"{name} came from JSON ({len(loaded)} loaded > {len(fallback)} fallback)")
    binary_tools = os.path.join(ENGINE, "BinaryPivot", "tools")
    if binary_tools not in sys.path:
        sys.path.insert(0, binary_tools)
    import analyze_artifact, bp_anyrun  # noqa: E402
    with open(os.path.join(ENGINE, "BinaryPivot", "references", "binary_indicators.json"),
              encoding="utf-8") as f:
        binary_ref = json.load(f)
    ok(analyze_artifact.DEFAULT_UA == binary_ref["android_user_agent"] and
       "Android" in analyze_artifact.DEFAULT_UA,
       "BinaryPivot download UA comes from Android reference data")
    ok(analyze_artifact.DESKTOP_UA == binary_ref["desktop_user_agent"] and
       "Windows" in analyze_artifact.DESKTOP_UA,
       "BinaryPivot desktop installer UA comes from reference data")
    ok(len(analyze_artifact.APPLE_IDENTITY_PREFIXES) >
       len(analyze_artifact._BP_FALLBACK["apple_signing_identity_prefixes"]),
       f"BinaryPivot Apple signing-identity prefixes came from JSON "
       f"({len(analyze_artifact.APPLE_IDENTITY_PREFIXES)} loaded > "
       f"{len(analyze_artifact._BP_FALLBACK['apple_signing_identity_prefixes'])} fallback)")
    with open(os.path.join(ENGINE, "BinaryPivot", "references", "anyrun.json"),
              encoding="utf-8") as f:
        anyrun_ref = json.load(f)
    ok(bp_anyrun.REQUEST_BUDGET.get("submit_costs") ==
       anyrun_ref["request_budget"]["submit_costs"] == 0,
       "ANY.RUN sandbox submissions do not spend TI Lookup allowance")

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

    # --- 4. the ChongLuaDao usage ledger (scripts/cld/references, outside the section-1 glob) ----
    # cld_api ledgers every request at units from this file; a missing/broken file silently prices
    # every call at _FALLBACK_UNITS=1 — under-reporting endpoints priced higher and mis-tagging
    # unbilled async polls as billed. Prove it parses, is documented, and the consumer loads it.
    cld_ref = os.path.join(ROOT, "scripts", "cld", "references", "cld_usage.json")
    ok(os.path.isfile(cld_ref), "cld_usage.json present under scripts/cld/references/")
    usage = {}
    try:
        with open(cld_ref, encoding="utf-8") as fh:
            usage = json.load(fh)
    except Exception as exc:                                                      # noqa: BLE001
        ok(False, f"cld_usage.json parses ({exc})")
    ok(isinstance(usage.get("_comment"), str) and len(usage["_comment"]) > 40,
       "cld_usage.json has a top-level _comment an analyst can act on")
    tiers = usage.get("tiers") if isinstance(usage, dict) else None
    ok(isinstance(tiers, dict) and set(tiers) >= {"feeds", "ti"},
       "cld_usage.json defines the feeds and ti tiers")
    n_endpoints, units_ok = 0, True
    for tier in (tiers or {}).values():
        if not isinstance(tier, dict):
            continue
        for meta in (tier.get("endpoints") or {}).values():
            n_endpoints += 1
            u = meta.get("units")
            if not isinstance(u, int) or isinstance(u, bool) or u < 0:
                units_ok = False
    ok(n_endpoints > 0, f"cld_usage.json prices its endpoints ({n_endpoints})")
    # units are integers >= 0; poll units are an ESTIMATE the file's own note lets analysts raise
    # to 1, so a specific poll value is deliberately NOT pinned here.
    ok(units_ok, "cld_usage.json units are all integers >= 0")
    scld = os.path.join(ROOT, "scripts", "cld")
    if scld not in sys.path:
        sys.path.insert(0, scld)
    import cld_api                                                                # noqa: E401
    loaded = cld_api._load_usage()
    ok(isinstance(loaded.get("tiers"), dict) and len(loaded["tiers"]) >= 2,
       "cld_api._load_usage() loaded the real file, not the empty-tiers fallback")

    # --- 4b. Spamhaus domain-tag classes (scripts/osint/references, outside the section-1 glob) --
    # On the embedded fallback reputation_check knows 5 adverse tags instead of the official set,
    # so a domain Spamhaus tags scam/tds/snowshoe/dga reads as clean-of-Spamhaus.
    sh_ref = os.path.join(ROOT, "scripts", "osint", "references", "spamhaus_tags.json")
    ok(os.path.isfile(sh_ref), "spamhaus_tags.json present under scripts/osint/references/")
    sosint = os.path.join(ROOT, "scripts", "osint")
    if sosint not in sys.path:
        sys.path.insert(0, sosint)
    import reputation_check                                                       # noqa: E401
    # victim/override groups legitimately equal their fallback; adverse_tags is the richness signal
    ok(len(reputation_check._SH_TAGS["adverse_tags"])
       > len(reputation_check._SPAMHAUS_TAGS_FALLBACK["adverse_tags"]),
       "reputation_check.adverse_tags came from spamhaus_tags.json, not the fallback")
    ok(not (reputation_check._SPAMHAUS_ADVERSE_TAGS
            & (reputation_check._SPAMHAUS_VICTIM_TAGS | reputation_check._SPAMHAUS_OVERRIDE_TAGS)),
       "no Spamhaus tag is both an abuse signal and a victim/override tag")

    # --- 5. the Wayback breaker's thresholds (WebPivot/references/wayback_guard.json) --------
    # A scalar threshold has no "more entries than the fallback" richness signal (the JSON default
    # legitimately equals the embedded fallback: both are 20), so this proves the consumer LOADED
    # the file's own value instead of silently running on the embedded fallback, the same way
    # test_call_timeout.py proves wp_timeouts._reference_default() came from timeouts.json.
    import wp_wayback_guard                                                       # noqa: E401
    wb_ref = os.path.join(ENGINE, "WebPivot", "references", "wayback_guard.json")
    ok(os.path.isfile(wb_ref), "wayback_guard.json present under WebPivot/references/")
    with open(wb_ref, encoding="utf-8") as fh:
        wb_doc = json.load(fh)
    ok(wb_doc.get("fail_limit", {}).get("value") == wp_wayback_guard._reference_fail_limit(),
       "wp_wayback_guard's fail-limit default loads from wayback_guard.json, not the embedded fallback")
    ok(wb_doc.get("adhoc_window_seconds", {}).get("value") == wp_wayback_guard._reference_adhoc_window(),
       "wp_wayback_guard's ad-hoc window loads from wayback_guard.json, not the embedded fallback")
    wg_fb = wp_wayback_guard.GUARD_FALLBACK
    ok(all(wp_wayback_guard.cooldown_seconds(k) == float(wb_doc["cooldown"][k])
           for k in wg_fb["cooldown"]),
       "wp_wayback_guard's cooldowns load from wayback_guard.json → cooldown")
    _saved_mi = os.environ.pop("WAYBACK_MIN_INTERVAL", None)
    try:
        ok(all(wp_wayback_guard.min_interval(k) == float(wb_doc["pace"][k]) for k in wg_fb["pace"]),
           "wp_wayback_guard's per-lane spacing loads from wayback_guard.json → pace")
    finally:
        if _saved_mi is not None:
            os.environ["WAYBACK_MIN_INTERVAL"] = _saved_mi
    ok(wp_wayback_guard.archive_user_agent() == wb_doc["archive_user_agent"]["value"],
       "wp_wayback_guard's archive.org UA loads from wayback_guard.json → archive_user_agent")

    # --- 6. the Wayback client's endpoints (WebPivot/references/wayback_endpoints.json) --------
    import wp_wayback                                                             # noqa: E401
    we_ref = os.path.join(ENGINE, "WebPivot", "references", "wayback_endpoints.json")
    ok(os.path.isfile(we_ref), "wayback_endpoints.json present under WebPivot/references/")
    with open(we_ref, encoding="utf-8") as fh:
        we_doc = json.load(fh)
    ok(wp_wayback.INDEX_ENDPOINTS == we_doc["index"]["value"]
       and wp_wayback.PLAYBACK == we_doc["playback"]["value"]
       and wp_wayback.LATEST_TS == we_doc["latest_timestamp"]["value"]
       and wp_wayback.ATTEMPTS == we_doc["attempts"]["value"]
       and wp_wayback.TOPUP_ROWS == we_doc["truncation_topup_rows"]["value"],
       "wp_wayback's endpoints/retry knobs load from wayback_endpoints.json, not the fallback")
    import wp_wayback_exhaust                                                     # noqa: E401
    ok(wp_wayback_exhaust.DEFAULT_MAX_HOURS == float(we_doc["exhaust"]["default_max_hours"]),
       "wp_wayback_exhaust's default run budget loads from wayback_endpoints.json → exhaust")

    # --- 6a. the CT client's windows + budgets (WebPivot/references/ct_sources.json) ----------
    # On the fallback only crt.sh has an observation window, so every backup's status prints with
    # no "~1 year" caveat and a mirror's partial listing reads as history; the budgets shrink to
    # one CertSpotter page and a 60s crt.sh walk, so a slow-but-alive crt.sh is reported degraded.
    import wp_ct                                                                  # noqa: E401
    ct_ref = os.path.join(ENGINE, "WebPivot", "references", "ct_sources.json")
    with open(ct_ref, encoding="utf-8") as fh:
        ct_doc = json.load(fh)
    ok(len(wp_ct.WINDOWS) > len(wp_ct._CT_FALLBACK["windows"])
       and wp_ct.WINDOWS == ct_doc["windows"]["entries"],
       "wp_ct observation windows load from ct_sources.json → windows, not the fallback")
    ok(all(wp_ct.CRTSH[k] == ct_doc["crtsh"][k] for k in wp_ct._CT_FALLBACK["crtsh"]),
       "wp_ct crt.sh retry/PostgreSQL budgets load from ct_sources.json → crtsh")
    ok(all(wp_ct.BACKUPS[k] == ct_doc["backups"][k] for k in wp_ct._CT_FALLBACK["backups"])
       and all(wp_ct.LISTING[k] == ct_doc["listing"][k] for k in wp_ct._CT_FALLBACK["listing"]),
       "wp_ct backup paging + listing caps load from ct_sources.json → backups/listing")
    import wp_certkit, wp_certindex                                               # noqa: E401
    ok(wp_ct.NETLAS == {k: ct_doc["netlas"][k] for k in wp_ct.NETLAS}
       and wp_ct.CENSYS == {k: ct_doc["censys"][k] for k in wp_ct.CENSYS}
       and wp_certindex.CFG["max_pages"] == ct_doc["certindex"]["max_pages"]
       and wp_certkit.CFG["session_ttl_seconds"] == ct_doc["certkit"]["session_ttl_seconds"],
       "keyed CT backups (CertKit/CertIndex/Netlas/Censys) load from ct_sources.json, not the fallback")
    # On the fallback only crt.sh counts as a real-serial source, so a CertKit/Netlas-backed cert
    # silently loses its FOFA cert.sn pivot.
    swp = os.path.join(ROOT, "scripts", "webpivot")
    if swp not in sys.path:
        sys.path.insert(0, swp)
    import cert_pivot                                                             # noqa: E401
    ok(cert_pivot.REAL_SERIAL_SOURCES == set(ct_doc["real_serial_sources"]["values"])
       and len(cert_pivot.REAL_SERIAL_SOURCES) > len(cert_pivot._CT_SERIAL_FALLBACK["real_serial_sources"]),
       "cert_pivot real-serial CT sources load from ct_sources.json → real_serial_sources, not the fallback")

    # --- 6b. Wayback collection_search + urlscan field_search + exchange_wallets (phase 3) ------
    ok(isinstance(we_doc.get("collection_search"), dict)
       and "search_url" in we_doc["collection_search"]
       and "collections" in we_doc["collection_search"],
       "wayback_endpoints.json carries collection_search (url, collections, timeout)")
    ok(int(we_doc["collection_search"].get("timeout") or 0) >= 60,
       "wayback collection_search timeout >= 60s (measured latency 13-50s)")
    import wp_wayback_search                                                       # noqa: E401
    ok(wp_wayback_search.SEARCH_URL == we_doc["collection_search"]["search_url"]
       and wp_wayback_search.TIMEOUT >= 60
       and "telegram" in wp_wayback_search.COLLECTIONS,
       "wp_wayback_search loads collection_search from wayback_endpoints.json, not the fallback")

    us_ref = os.path.join(ENGINE, "WebPivot", "references", "urlscan_endpoints.json")
    with open(us_ref, encoding="utf-8") as fh:
        us_doc = json.load(fh)
    ok(isinstance(us_doc.get("field_search"), dict) and "page.title" in (us_doc["field_search"].get("fields") or {}),
       "urlscan_endpoints.json carries field_search.fields")
    ok(isinstance(us_doc.get("identifier_rungs"), dict)
       and "google.ua-id" in (us_doc["identifier_rungs"].get("entries") or us_doc["identifier_rungs"]),
       "urlscan_endpoints.json carries identifier_rungs map")

    ex_ref = os.path.join(ENGINE, "WebPivot", "references", "exchange_wallets.json")
    ok(os.path.isfile(ex_ref), "exchange_wallets.json present under WebPivot/references/")
    with open(ex_ref, encoding="utf-8") as fh:
        ex_doc = json.load(fh)
    ok("labels" in ex_doc and ("known_addresses" in ex_doc or "addresses" in ex_doc),
       "exchange_wallets.json has labels + known_addresses groups")

    import wp_publicwww                                                            # noqa: E401
    ok(hasattr(wp_publicwww, "search") and hasattr(wp_publicwww, "publicwww_configured"),
       "wp_publicwww exposes search + publicwww_configured")

    # --- 6c. the proposer's page-selector probe cap (harness/references/pivot_map.json) ------
    # A scalar: JSON default equals the embedded fallback (25), so prove the key was READ from
    # the file (present in the loaded ref) and that the consumer returns the file's own value.
    tools_dir = os.path.join(ENGINE, "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    import selector_types                                                          # noqa: E401
    with open(os.path.join(ENGINE, "harness", "references", "pivot_map.json"),
              encoding="utf-8") as fh:
        pm_doc = json.load(fh)
    ok("page_selector_cap" in selector_types._PIVOT_REF
       and selector_types.page_selector_cap() == int(pm_doc["page_selector_cap"]["max"])
       and selector_types._PAGE_SELECTOR_CAP_FALLBACK == 25,
       "selector_types.page_selector_cap loads from pivot_map.json (fallback 25)")

    # --- 6d. analyst evidence import (tools/kb/references/evidence_import.json) -------------
    # Fallback maps every reliability letter to LOW; the file grades A/B high, so equality with
    # the file (and inequality with the fallback) proves the data was read.
    import evidence_import                                                         # noqa: E401
    with open(os.path.join(ENGINE, "tools", "kb", "references", "evidence_import.json"),
              encoding="utf-8") as fh:
        ei_doc = json.load(fh)
    ok(evidence_import.RELIABILITY_CONFIDENCE == ei_doc["reliability_confidence"]["entries"]
       and evidence_import.RELIABILITY_CONFIDENCE
       != evidence_import._REF_FALLBACK["reliability_confidence"]
       and evidence_import.ADMIRALTY_RE.pattern == ei_doc["admiralty"]["pattern"]
       and evidence_import.SOURCE == ei_doc["provenance"]["source"] == "analyst_import",
       "evidence_import grading + provenance load from evidence_import.json, not the fallback")

    # --- 6e. ledger cost classes (WebPivot/references/api_cost_classes.json) -----------------
    # On the fallback every provider except the reverse-WHOIS preview is `metered`, so a urlscan
    # quota call or a keyless crt.sh lookup reads as a purchase in `api-usage`.
    import api_usage                                                               # noqa: E401
    with open(os.path.join(ENGINE, "WebPivot", "references", "api_cost_classes.json"),
              encoding="utf-8") as fh:
        cc_doc = json.load(fh)
    cc = api_usage.load_cost_classes()
    ok(cc["provider_classes"] == cc_doc["provider_classes"]["entries"]
       and len(cc["provider_classes"]) > len(api_usage._COST_FALLBACK["provider_classes"])
       and cc["rules"]["default_class"] == cc_doc["rules"]["default_class"],
       "api_usage cost classes load from api_cost_classes.json, not the fallback")

    # --- 6f. reverse-WHOIS auto-buy cap (harness/references/reverse_whois.json) --------------
    # A scalar whose JSON default equals the embedded fallback (150): prove the gate returns the
    # file's own value. harness/tools.py imports claude_agent_sdk, so this row skips without it.
    with open(os.path.join(ENGINE, "harness", "references", "reverse_whois.json"),
              encoding="utf-8") as fh:
        rw_doc = json.load(fh)
    try:
        import importlib.util
        hdir = os.path.join(ENGINE, "harness")
        if hdir not in sys.path:
            sys.path.insert(0, hdir)
        spec = importlib.util.spec_from_file_location("harness_tools_refcheck",
                                                      os.path.join(hdir, "tools.py"))
        htools = importlib.util.module_from_spec(spec)
        with contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(htools)
    except ImportError as exc:
        out.append(("skip", f"harness rwhois_auto_cap parity skipped — needs the SDK ({exc})"))
    else:
        ok(htools._rwhois_auto_cap() == int(rw_doc["rwhois_auto_cap"]["value"])
           and htools._RWHOIS_FALLBACK["rwhois_auto_cap"]["value"] == 150,
           "harness _reverse_gate cap loads rwhois_auto_cap from reverse_whois.json (fallback 150)")

    # --- 6g. loop hygiene (pivot_map propose_type_exclude, rungs fact_only_node_classes, ------
    #     noise_filters social apexes + social_platform_ip_ranges). The first two JSON defaults
    #     equal their embedded fallbacks, so prove the group was READ from the file; the IP ranges
    #     fall back to empty, so a non-empty load proves the file.
    ok("propose_type_exclude" in selector_types._PIVOT_REF
       and all(selector_types.propose_excluded(r, t)
               for r, ts in pm_doc["propose_type_exclude"]["entries"].items() for t in ts)
       and selector_types._PROPOSE_TYPE_EXCLUDE_FALLBACK == {"anyrun.lookup": ["ip"]},
       "selector_types.propose_excluded loads propose_type_exclude from pivot_map.json")
    with open(os.path.join(ENGINE, "tools", "kb", "references", "rungs.json"),
              encoding="utf-8") as fh:
        rg_doc = json.load(fh)
    _fo = rg_doc["fact_only_node_classes"]["entries"]
    ok("fact_only_node_classes" in selector_types._RUNGS_REF
       and all(selector_types.fact_only_classes(r) == frozenset(cs) | frozenset(_fo.get("*", []))
               for r, cs in _fo.items())
       and selector_types._FACT_ONLY_NODE_CLASSES_FALLBACK == {"quarry.page": ["page.email", "page.phone"],
                                                               "*": ["wallet.token_contract"]},
       "selector_types.fact_only_classes loads fact_only_node_classes from rungs.json (\"*\" = every route)")
    import noise_filters                                                           # noqa: E401
    with open(os.path.join(ENGINE, "tools", "kb", "references", "noise_filters.json"),
              encoding="utf-8") as fh:
        nf_doc = json.load(fh)
    ok(len(noise_filters.SOCIAL_PLATFORM_IP_RANGES)
       == len(nf_doc["social_platform_ip_ranges"]["values"]) > 0
       and noise_filters._FALLBACK["social_platform_ip_ranges"] == [],
       "noise_filters social_platform_ip_ranges load from noise_filters.json (fallback empty)")
    ok(all(noise_filters.is_shared_infra_apex(a) for a in
           ("twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com",
            "tiktok.com", "youtube.com")),
       "the never-seed social platforms are shared_infra_apexes in noise_filters.json")

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
