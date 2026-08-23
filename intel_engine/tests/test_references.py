#!/usr/bin/env python3
"""
test_references.py — the gate on the reference DATA layer (contributor RULE 3).

Run:  python3 tests/test_references.py              (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_references.py -q   (also works)
      python3 tools/eval/run_eval.py                 (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Reference files are how an analyst tunes the tooling without editing Python. That only works if
four things hold, and each has a failure mode that is SILENT in production:

  1. Every file parses and is documented. A `_comment` an analyst can't read is a list they will
     not touch — and an undocumented denylist is one nobody dares extend.
  2. Every consumer actually LOADS the file. `load_ref` degrades to a minimal embedded fallback
     when a file is missing or malformed, and warns on stderr — but a warning scrolls past in a
     long run. A module quietly running on its 10-entry fallback instead of its 100-entry data
     file filters almost nothing, and a filter that returns False everywhere MANUFACTURES false
     clusters. So we assert the loaded values are strictly richer than the fallback.
  3. Denylists that exist in more than one module stay in sync. WebPivot ships standalone, so it
     carries its own copy of the registrant-noise data; a provider added to one copy and not the
     other is exactly the drift this layer was built to end.
  4. A broken data file degrades LOUDLY. Returning an empty dict would turn every downstream
     `any(... for x in LIST)` filter into False and start clustering on registrar boilerplate.

Also checks the vendored loaders (wp_refs / kb_refs / bp_refs) have not diverged.
"""
import contextlib
import glob
import io
import json
import os
import sys
import shutil
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Generated caches, not analyst-tunable lists: exempt from the per-group `_comment` rule (they
# still need the top-level one). `asn_registry` documents itself through a richer `_meta` block
# and grows by upsert from wp_ippivot, so its single `asns` group is exempt too.
GENERATED = {"cdn_ranges.json", "asn_registry.json"}

# Proxies/registrars seen often enough that a registrant-noise copy missing one is a real gap,
# not a stylistic difference. Add a provider to BOTH data files, then add it here.
MUST_KNOW = ["domainsbyproxy", "withheldforprivacy", "privacyprotect", "namecheap", "godaddy"]

# The three vendored copies of the loader. They must stay byte-identical below the module-name
# line in the docstring: each skill is imported onto other machines standalone, so the loader
# cannot live in a shared package — and distinct module NAMES are required because tools/kb and
# WebPivot/tools both land on sys.path in the same process (ingest_webpivot inserts both), where
# a shared `refs.py` would collide.
LOADERS = ["WebPivot/tools/wp_refs.py", "tools/kb/kb_refs.py", "BinaryPivot/tools/bp_refs.py",
           "IntelGraph/scripts/ig_refs.py", "IntelReport/scripts/ir_refs.py",
           "Engage/tools/en_refs.py"]


def _loader_body(relpath):
    lines = open(os.path.join(ROOT, relpath), encoding="utf-8").read().splitlines(True)
    start = next(i for i, l in enumerate(lines) if l.startswith("import copy"))
    return "".join(lines[start:])


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

    for p in (os.path.join(ROOT, "WebPivot", "tools"),
              os.path.join(ROOT, "tools", "kb"),
              os.path.join(ROOT, "BinaryPivot", "tools"),
              os.path.join(ROOT, "IntelGraph", "scripts"),
              os.path.join(ROOT, "IntelReport", "scripts"),
              os.path.join(ROOT, "harness")):
        if p not in sys.path:
            sys.path.insert(0, p)

    # --- 1. every reference file parses, is documented, has no empty group ------------------
    files = sorted(glob.glob(os.path.join(ROOT, "*", "references", "*.json")) +
                   glob.glob(os.path.join(ROOT, "*", "*", "references", "*.json")))
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

    # --- 2. the vendored loaders have not diverged ------------------------------------------
    ref = _loader_body(LOADERS[0])
    for p in LOADERS[1:]:
        ok(_loader_body(p) == ref, f"{p} is identical to {LOADERS[0]}")

    # --- 3. every consumer loaded its DATA FILE, not its embedded fallback -------------------
    # This is the check that matters most: a module silently on its fallback still imports, still
    # runs, still produces output — it just stops filtering. Comparing against the fallback size
    # catches that, and unlike a hardcoded count it does not rot as analysts extend a list.
    import wp_pivots, wp_analyze, wp_assets, wp_recon, wp_ippivot, wp_impersonate  # noqa: E401
    import wp_censys, wp_capabilities, wp_intelx, wp_docmeta                       # noqa: E401
    import wp_paths, wp_capture, wp_serp                                           # noqa: E401
    import bp_anyrun                                                               # noqa: E401
    import whois_enrich, evidence_report                                           # noqa: E401
    import ingest_webpivot, hypothesize, ingest_report, noise_filters              # noqa: E401
    import wp_common, wp_net, wp_extract, export_graph, calibration                # noqa: E401
    import risk_signals                                                            # noqa: E401
    import analyze_artifact                                                        # noqa: E401
    import case_timeline                                                           # noqa: E401
    import render_report                                                           # noqa: E401
    import victim_profile                                                          # noqa: E401
    import audit                                                                   # noqa: E401
    import case_scope                                                              # noqa: E401
    import wp_liveness                                                             # noqa: E401
    import wp_pssl                                                                 # noqa: E401
    import tools                                                                   # noqa: E401  (harness/tools.py — the context governor)

    consumers = [
        # Passive SSL: this policy is the rail that stops a CDN certificate (served by hundreds of
        # unrelated addresses) from becoming a same-operator edge. On the stub it still "works" and
        # still returns results — it just stops refusing, which is the failure that manufactures an
        # estate out of a CDN's customer list.
        ("wp_pssl.POLICY", wp_pssl.POLICY,
         wp_pssl._PSSL_FALLBACK["clustering_policy"]),
        ("wp_pssl.ENDPOINTS", wp_pssl.ENDPOINTS, wp_pssl._PSSL_FALLBACK["endpoints"]),
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
        ("wp_recon.MAIL_PROVIDERS", wp_recon.MAIL_PROVIDERS,
         wp_recon._MAIL_FALLBACK["mx_providers"]),
        ("wp_recon.SPF_ESP", wp_recon.SPF_ESP, wp_recon._MAIL_FALLBACK["spf_esp_hosts"]),
        ("wp_recon.DMARC_VENDORS", wp_recon.DMARC_VENDORS,
         wp_recon._MAIL_FALLBACK["dmarc_report_vendors"]),
        # Misconfig triage. On the fallback the FTP scan knows four anon-login banners instead of ten
        # (so an anon-accepting box whose banner it hasn't heard of stops being flagged as a triage
        # lead) and leak_classes drops link_local/cgnat — silently narrowing which reserved addresses
        # count as an internal-topology leak. Both fail toward MISSING a lead, never a false one.
        ("wp_recon.ANON_FTP_MARKERS", wp_recon.ANON_FTP_MARKERS,
         wp_recon._MISCONFIG_FALLBACK["anon_ftp_markers"]),
        ("wp_recon.FTP_PROTOCOL_MARKERS", wp_recon.FTP_PROTOCOL_MARKERS,
         wp_recon._MISCONFIG_FALLBACK["ftp_protocol_markers"]),
        ("wp_recon.LEAK_CLASSES", wp_recon.LEAK_CLASSES,
         wp_recon._MISCONFIG_FALLBACK["leak_classes"]),
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
        # IntelX. On the fallback the selector classifier knows five patterns instead of eleven, so
        # a wallet / IBAN / CIDR artifact stops being recognised as searchable at all — and the
        # bucket catalogue empties, which takes the false-cluster control with it: `clusterable()`
        # then denies everything, costing leads (the safe direction, but silently).
        ("wp_intelx.SELECTOR_TYPES", wp_intelx.SELECTOR_TYPES,
         wp_intelx._INTELX_FALLBACK["selector_types"]),
        ("wp_intelx.PIVOT_KIND_MAP", wp_intelx.PIVOT_KIND_MAP,
         wp_intelx._INTELX_FALLBACK["pivot_kind_map"]),
        ("wp_intelx.BUCKETS", wp_intelx.BUCKETS, wp_intelx._INTELX_FALLBACK["buckets"]),
        ("wp_intelx.ENDPOINTS", wp_intelx.ENDPOINTS, wp_intelx._INTELX_FALLBACK["endpoints"]),
        ("wp_intelx.CLUSTERING_POLICY", wp_intelx.CLUSTERING_POLICY,
         wp_intelx._INTELX_FALLBACK["clustering_policy"]),
        # The retrieval PLAN. IntelX returns a bounded page, so what is asked for first is what
        # actually comes back: on the fallback the analyst's tuning is lost (`general_pass`, the
        # full selector order) even though the logs-first guarantee itself survives by design.
        # Losing `selector_priority` silently demotes the DOMAIN — the selector a stealer log is
        # indexed by, and therefore the only one that can name an infected machine.
        ("wp_intelx.SEARCH_PLAN", wp_intelx.SEARCH_PLAN,
         wp_intelx._INTELX_FALLBACK["search_plan"]),
        # The advertising layer. On the fallback the parameter table knows 14 names instead of 37,
        # so a click id it has not heard of stops being recognised as proof of a paid arrival and —
        # worse — stops being stripped for the probe's PLAIN view, which then carries the ad
        # parameters and silently compares the unlocked page against itself. `generic_values` is the
        # base-rate control that keeps `utm_campaign=google` from becoming an operator fingerprint,
        # and `clustering_policy` carries the agency threshold that stops a media buyer's account
        # fusing a dozen unrelated clients into one operator.
        ("wp_serp.AD_PARAMETERS", wp_serp.AD_PARAMETERS, wp_serp._SERP_FALLBACK["ad_parameters"]),
        ("wp_serp.GENERIC_VALUES", wp_serp.GENERIC_VALUES, wp_serp._SERP_FALLBACK["generic_values"]),
        # On the fallback the probe knows 10 anti-bot markers instead of 20, so a challenge wall it
        # has not heard of is scored as a page — and two challenge interstitials differ from each
        # other by design, which is a `divergent` verdict accusing a site of deliberate evasion.
        ("wp_serp.CHALLENGE_MARKERS", wp_serp.CHALLENGE_MARKERS,
         wp_serp._SERP_FALLBACK["challenge_markers"]),
        ("wp_serp.CLUSTERING_POLICY", wp_serp.CLUSTERING_POLICY,
         wp_serp._SERP_FALLBACK["clustering_policy"]),
        ("wp_serp.REGIONS", wp_serp.REGIONS, wp_serp._SERP_FALLBACK["regions"]),
        ("wp_serp.ENDPOINTS", wp_serp.ENDPOINTS, wp_serp._SERP_FALLBACK["endpoints"]),
        # ANY.RUN. On the fallback the observation-field map covers six kinds instead of ten and
        # the clustering policy is empty, so a shared malware FAMILY would be ungraded rather than
        # explicitly context-only — the exact same-kit/same-operator confusion this layer must not
        # introduce into BinaryPivot.
        ("bp_anyrun.QUERY_FIELDS", bp_anyrun.QUERY_FIELDS,
         bp_anyrun._ANYRUN_FALLBACK["query_fields"]),
        ("bp_anyrun.PIVOT_FIELD_MAP", bp_anyrun.PIVOT_FIELD_MAP,
         bp_anyrun._ANYRUN_FALLBACK["pivot_field_map"]),
        ("bp_anyrun.CLUSTERING_POLICY", bp_anyrun.CLUSTERING_POLICY,
         bp_anyrun._ANYRUN_FALLBACK["clustering_policy"]),
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
        ("whois_enrich._PRIVACY_MARKERS", whois_enrich._PRIVACY_MARKERS,
         whois_enrich._WHOIS_FALLBACK["privacy_markers"]),
        ("whois_enrich._PROXY_DOMAINS", whois_enrich._PROXY_DOMAINS,
         whois_enrich._WHOIS_FALLBACK["proxy_email_domains"]),
        ("evidence_report._NOISE_EMAIL_SUBSTR", evidence_report._NOISE_EMAIL_SUBSTR,
         evidence_report._RN_FALLBACK["noise_email_substrings"]),
        # Base-rate control on the estimative scale. On the fallback the renderer knows three
        # ceilings instead of eight, so a saturated crt.sh / passive-DNS / reverse-WHOIS result
        # silently goes back to reading as CORROBORATION and bumps the artifact one notch UP —
        # which is how a hosting provider's parking favicon became a report's headline indicator.
        ("evidence_report._SAT_CEILINGS", evidence_report._SAT_CEILINGS,
         evidence_report._RT_FALLBACK["saturation_ceilings"]),
        ("ingest_webpivot._ROLE_NAME_PLACEHOLDERS", ingest_webpivot._ROLE_NAME_PLACEHOLDERS,
         ingest_webpivot._RN_FALLBACK["role_name_placeholders"]),
        ("ingest_webpivot._ORG_SUFFIX", ingest_webpivot._ORG_SUFFIX,
         ingest_webpivot._RN_FALLBACK["org_suffixes"]),
        ("hypothesize._PROXY_EMAIL", hypothesize._PROXY_EMAIL,
         hypothesize._H_FALLBACK["proxy_email_tokens"]),
        ("ingest_report._NOISE_DOMAINS", ingest_report._NOISE_DOMAINS,
         ingest_report._IR_FALLBACK["report_noise_domains"]),
        ("noise_filters.MANAGED_DNS_SUFFIXES", noise_filters.MANAGED_DNS_SUFFIXES,
         noise_filters._FALLBACK["managed_dns_suffixes"]),
        # Social platform registry + its base rates. On the fallback WebPivot knows 5 platforms
        # instead of 22 (so Telegram/Zalo/WhatsApp contact pivots silently vanish) and 2 builder
        # boilerplate handles instead of 12 (so every Wix site shares "the operator's" socials).
        ("wp_extract.SOCIAL_HOSTS", wp_extract.SOCIAL_HOSTS,
         wp_extract._SP_FALLBACK["social_hosts"]),
        ("wp_extract.BOILERPLATE_SOCIAL_HANDLES", wp_extract.BOILERPLATE_SOCIAL_HANDLES,
         wp_extract._SP_FALLBACK["boilerplate_social_handles"]),
        # Fetch profile. On the fallback the crawler rotates ONE user-agent (defeating rotation
        # entirely) and knows 3 Cloudflare markers instead of 14 — so challenge interstitials get
        # collected AS the site and their favicon/DOM hash clusters every challenged domain.
        ("wp_common.UA_POOL", wp_common.UA_POOL, wp_common._FP_FALLBACK["ua_pool"]),
        ("wp_net._CF_BODY_MARKERS", wp_net._CF_BODY_MARKERS,
         wp_common._FP_FALLBACK["cloudflare_body_markers"]),
        # Public-suffix table. On the fallback bbc.co.uk collapses to co.uk and every unrelated
        # domain under a country's commercial suffix merges into one "apex".
        ("wp_common._MULTI_TLDS", wp_common._MULTI_TLDS,
         wp_common._GLC_FALLBACK["multi_part_tlds"]),
        # Evidence weights — the scoring behind an attribution call. The fallback is deliberately
        # conservative (fewer attribution-grade and fewer corroborating relations), so a broken
        # file makes the scorer claim LESS rather than more.
        ("hypothesize.ATTRIBUTION", hypothesize.ATTRIBUTION,
         hypothesize._EW_FALLBACK["attribution_rels"]),
        ("hypothesize.CORROBORATING", hypothesize.CORROBORATING,
         hypothesize._EW_FALLBACK["corroborating_rels"]),
        ("export_graph.RELNAME", export_graph.RELNAME,
         export_graph._EW_FALLBACK["relation_labels"]),
        # Calibration. On the fallback three estimative labels lose their probability, so a past
        # judgement written with one silently drops out of Brier scoring.
        ("calibration.CONF_PROB", calibration.CONF_PROB,
         calibration._EW_FALLBACK["confidence_probabilities"]),
        # HTML-comment base rates. On the fallback the ingest knows ~13 boilerplate markers
        # instead of ~35, so the Google Analytics / Open Graph / site-builder slot comments that
        # ship identically on millions of pages start seeding `same_comment` edges and fuse
        # unrelated domains into one "shared builder" cluster.
        ("noise_filters.COMMENT_BOILERPLATE", noise_filters.COMMENT_BOILERPLATE,
         noise_filters._FALLBACK["comment_boilerplate"]),
        # Role/registrar mailboxes. On the fallback the list halves and registrar complaint and
        # takedown addresses start seeding `registered_by` registrant clusters.
        ("noise_filters.ROLE_EMAIL_LOCALPARTS", noise_filters.ROLE_EMAIL_LOCALPARTS,
         noise_filters._FALLBACK["role_email_localparts"]),
        ("noise_filters.SHARED_INFRA_APEXES", noise_filters.SHARED_INFRA_APEXES,
         noise_filters._FALLBACK["shared_infra_apexes"]),
        ("analyze_artifact._FAKE_TLD", analyze_artifact._FAKE_TLD,
         analyze_artifact._BP_FALLBACK["fake_tlds"]),
        ("analyze_artifact._PE_SECTION_PACKERS", analyze_artifact._PE_SECTION_PACKERS,
         analyze_artifact._BP_FALLBACK["pe_section_packers"]),
        ("analyze_artifact._ANDROID_PROTECTORS", analyze_artifact._ANDROID_PROTECTORS,
         analyze_artifact._BP_FALLBACK["android_protectors"]),
        # The timeline's citation layer: on the fallback, an evidence table still renders — it
        # just cites four services instead of twenty, and silently drops the link for everything
        # else. A dated claim with no public link is the failure this whole layer exists to stop.
        ("case_timeline.TEMPLATES", case_timeline.TEMPLATES,
         case_timeline._EV_FALLBACK["permalink_templates"]),
        ("case_timeline.GRADING", case_timeline.GRADING,
         case_timeline._EV_FALLBACK["source_grading"]),
        # Victim profiling: on the fallback the panel signatures shrink to two labels, so most
        # victims come back panel='unknown' and the access-vector call silently degrades to
        # "insufficient data" on a set that would otherwise have discriminated cleanly.
        ("victim_profile.PANEL_DNS", victim_profile.PANEL_DNS,
         victim_profile._VP_FALLBACK["panel_dns_signatures"]),
        ("victim_profile.MANAGED_DNS", victim_profile.MANAGED_DNS,
         victim_profile._VP_FALLBACK["managed_dns_operators"]),
        ("victim_profile.SECTORS", victim_profile.SECTORS,
         victim_profile._VP_FALLBACK["victim_sectors"]),
        ("victim_profile.HYPOTHESES", victim_profile.HYPOTHESES,
         victim_profile._VP_FALLBACK["hypotheses"]),
        # Demography: on the fallback, .io/.co read as countries (inventing clusters) and a
        # WHOIS 'SLOVAKIA' never merges with a ccTLD 'SK', halving every country concentration.
        ("victim_profile.GENERIC_TLDS", victim_profile.GENERIC_TLDS,
         victim_profile._VP_FALLBACK["generic_two_letter_tlds"]),
        ("victim_profile.COUNTRY_NAMES", victim_profile.COUNTRY_NAMES,
         victim_profile._VP_FALLBACK["country_names"]),
        # Document/image metadata. On the fallback the parsers still work, but the base-rate lists
        # shrink to a handful — so "Adobe Acrobat", "LibreOffice", "Ghostscript" and the localised
        # default account names stop being recognised as generic and start emitting same-operator
        # edges. That is the false-cluster direction: every unrelated domain hosting a PDF made by
        # the same ordinary tool would be fused into one operator.
        ("wp_docmeta.GENERIC_PRODUCERS", wp_docmeta.GENERIC_PRODUCERS,
         wp_docmeta._DOC_FALLBACK["generic_producers"]),
        ("wp_docmeta.GENERIC_SOFTWARE", wp_docmeta.GENERIC_SOFTWARE,
         wp_docmeta._DOC_FALLBACK["generic_software"]),
        ("wp_docmeta.ROLE_AUTHORS", wp_docmeta.ROLE_AUTHORS,
         wp_docmeta._DOC_FALLBACK["role_authors"]),
        ("wp_docmeta.SKIP_PATH_HINTS", wp_docmeta.SKIP_PATH_HINTS,
         wp_docmeta._DOC_FALLBACK["skip_path_hints"]),
        # The tool-call gate. On the fallback it still blocks hostile egress and still refuses an
        # unapproved sandbox submission (that is why the fallback is the conservative minimum) —
        # but it knows half the tools, so the OTHER half of the outbound/metered surface passes
        # unclassified: the calls are still logged, they are just no longer gated or counted
        # against the credit budget. A gate that silently stops covering `censys` is worse than
        # one that is absent, because the run still prints a governance banner.
        # The case intake. On the fallback three target classes survive instead of six, so a run
        # scoped `confirmed_scam` or `benign_check` silently resolves to `unknown` and loses the
        # class's own disconfirming list — the checks that catch a confidently-stated class being
        # wrong. The scope switches empty out too, so an ad funnel stops turning on the cloaking
        # probe and the collection quietly describes the decoy page.
        ("case_scope.CLASSES", case_scope.CLASSES,
         case_scope._INTAKE_FALLBACK["target_classes"]),
        ("case_scope.QUESTIONS", case_scope.QUESTIONS,
         case_scope._INTAKE_FALLBACK["intake_questions"]),
        ("case_scope.SWITCHES", case_scope.SWITCHES,
         case_scope._INTAKE_FALLBACK["scope_switches"]),
        ("audit.OUTBOUND_TOOLS", audit.OUTBOUND_TOOLS,
         audit._POLICY_FALLBACK["outbound_tools"]),
        ("audit.METERED_TOOLS", audit.METERED_TOOLS,
         audit._POLICY_FALLBACK["metered_tools"]),
        ("audit.MUTATING_TOOLS", audit.MUTATING_TOOLS,
         audit._POLICY_FALLBACK["mutating_tools"]),
        ("audit.REDACT_ARGS", audit.REDACT_ARGS, audit._POLICY_FALLBACK["redact_args"]),
        # Risk scoring. The fallback carries the NRD day-thresholds ONLY — a date comparison still
        # works with no reference data, a denylist match cannot. So on the fallback `bph` and
        # `money_trail` are empty dicts and every bulletproof-hosting / money-trail check matches
        # nothing: a domain on known BPH scores CLEAN. That is the fail-open direction, and it is
        # why this module was moved off its hand-rolled `except: return {}` loader.
        ("risk_signals.RISK_INDICATORS['bph']", risk_signals.RISK_INDICATORS["bph"],
         risk_signals._RISK_FALLBACK["bph"]),
        ("risk_signals.RISK_INDICATORS['money_trail']",
         risk_signals.RISK_INDICATORS["money_trail"],
         risk_signals._RISK_FALLBACK["money_trail"]),
        # URL-path layer. `generic_segments` IS the base-rate control: on the fallback it knows ~20
        # common segments instead of ~145, so the first unlisted-but-universal directory an
        # operator's site happens to use (`/portal/`, `/service/`, `/verify/`) is emitted as a kit
        # fingerprint and fuses every unrelated site that uses the same ordinary word into one
        # cluster. That is the false-cluster direction, and it is silent. `asset_extensions` keeps
        # `app.js` from becoming a "kit"; `locale_segments` keeps one kit in twelve markets from
        # reading as twelve kits.
        ("wp_paths.GENERIC_SEGMENTS", wp_paths.GENERIC_SEGMENTS,
         wp_paths._PATH_FALLBACK["generic_segments"]),
        ("wp_paths.LOCALE_SEGMENTS", wp_paths.LOCALE_SEGMENTS,
         wp_paths._PATH_FALLBACK["locale_segments"]),
        ("wp_paths.VARIABLE_PATTERNS", wp_paths.VARIABLE_PATTERNS,
         wp_paths._PATH_FALLBACK["variable_patterns"]),
        ("wp_paths.ASSET_EXTENSIONS", wp_paths.ASSET_EXTENSIONS,
         wp_paths._PATH_FALLBACK["asset_extensions"]),
        # Evidence capture: on the fallback the capture still runs and still hashes, it just runs
        # on the SMALLER budget and fetches fewer resource kinds — so a bundle silently stops
        # being the whole page. That is survivable only because `skipped_for_budget` says so.
        ("wp_capture.CAPTURE_KINDS", wp_capture.CAPTURE_KINDS,
         wp_capture._CAP_FALLBACK["capture_kinds"]),
        # Report language. On the fallback a Vietnamese render still produces a document — it just
        # produces one with an English cover, English figure captions and, worse, an ESTIMATIVE
        # GLOSSARY missing eight of its ten terms. The glossary is the calibrated confidence scale
        # an author is meant to copy verbatim, so a thinned one invites a paraphrase, and a
        # paraphrased estimative term silently changes what the report claims.
        ("render_report.ESTIMATIVE_TERMS", render_report.ESTIMATIVE_TERMS,
         render_report._I18N_FALLBACK["estimative_terms"]),
        ("render_report.SECTION_NAMES", render_report.SECTION_NAMES,
         render_report._I18N_FALLBACK["section_names"]),
        # Typography. On the stub the report still renders — it just renders in the WRONG
        # fonts, which is the failure nobody notices until a 64-character hash is set in
        # Latin Modern Mono in a narrow table cell and the reader misreads 0 for O.
        ("render_report.MONO_PREF", render_report.MONO_PREF,
         render_report._TYPO_FALLBACK["mono_families"]),
        ("render_report.SERIF_PREF", render_report.SERIF_PREF,
         render_report._TYPO_FALLBACK["serif_families"]),
        ("render_report.SANS_PREF", render_report.SANS_PREF,
         render_report._TYPO_FALLBACK["sans_families"]),
        # Liveness. On the fallback the classifier still refuses to call a 404 dead and still
        # refuses to treat a bot wall as a verdict — those two rules are CODE, not data. What it
        # loses is TEMPLATE RECOGNITION: five parking strings instead of thirty-three, three
        # server-default strings instead of nineteen. Every template it no longer recognises
        # comes back `live`, which is the direction that hurts — the collector then fingerprints
        # a parking page's favicon and analytics and the KB grows a cluster of unrelated domains
        # that all happen to be parked at the same registrar.
        ("wp_liveness.PARKING_MARKERS", wp_liveness.PARKING_MARKERS,
         wp_liveness._LIVE_FALLBACK["parking_markers"]),
        ("wp_liveness.PARKING_NS", wp_liveness.PARKING_NS,
         wp_liveness._LIVE_FALLBACK["parking_nameservers"]),
        ("wp_liveness.SOFT_404_MARKERS", wp_liveness.SOFT_404_MARKERS,
         wp_liveness._LIVE_FALLBACK["soft_404_markers"]),
        ("wp_liveness.SUSPENDED_MARKERS", wp_liveness.SUSPENDED_MARKERS,
         wp_liveness._LIVE_FALLBACK["suspended_markers"]),
        ("wp_liveness.DEFAULT_PAGE_MARKERS", wp_liveness.DEFAULT_PAGE_MARKERS,
         wp_liveness._LIVE_FALLBACK["default_page_markers"]),
        ("wp_liveness.BLOCKED_MARKERS", wp_liveness.BLOCKED_MARKERS,
         wp_liveness._LIVE_FALLBACK["blocked_markers"]),
        # The state vocabulary itself — `reuse_watch` per state is what puts a parked or
        # suspended name back on the re-check list instead of in the discard pile.
        ("wp_liveness.STATES", wp_liveness.STATES, wp_liveness._LIVE_FALLBACK["states"]),
        # Context budget. On the fallback the governor still bounds every tool result and still
        # announces every cut; it just stops knowing WHICH tools deserve the larger allowance, so
        # a collector's evidence gets cut to the same size as a one-line status tool's output.
        ("tools.LARGE_RESULT_TOOLS", tools.LARGE_RESULT_TOOLS,
         tools._CTX_FALLBACK["large_result_tools"]),
    ]
    for name, loaded, fallback in consumers:
        ok(len(loaded) > len(fallback),
           f"{name} came from JSON ({len(loaded)} loaded > {len(fallback)} fallback)")

    # --- 4. cross-module drift on the registrant-noise copies --------------------------------
    wp_rn = json.load(open(os.path.join(ROOT, "WebPivot/references/registrant_noise.json")))
    kb_rn = json.load(open(os.path.join(ROOT, "tools/kb/references/registrant_noise.json")))

    def blob(doc, keys):
        return " | ".join(str(v).lower() for k in keys
                          for v in doc.get(k, {}).get("values", []))

    wp_blob = blob(wp_rn, ["proxy_email_domains", "noise_email_substrings", "privacy_markers"])
    kb_blob = blob(kb_rn, ["proxy_email_domains", "proxy_email_tokens", "privacy_markers"])
    for token in MUST_KNOW:
        ok(token in wp_blob, f"WebPivot registrant_noise knows {token!r}")
        ok(token in kb_blob, f"tools/kb registrant_noise knows {token!r}")

    # --- 4b. THE MIRROR MANIFEST: every declared duplicate holds identical values -------------
    # The token check above only proves a handful of well-known providers are present on both
    # sides. It cannot see a value added to one copy and not the other, and that is the drift
    # that actually happens — the platform-default favicon lists diverged so each side filtered
    # a different builder's icon and let the other's through, silently, with nothing logged.
    # tests/reference_mirrors.json names every group duplicated across skills (matched by
    # file+group, since a mirror may be named differently on each side: social_asset_extensions
    # vs social_handle_noise). Repair with `python3 tools/kb/sync_mirrors.py --union --write`.
    mirrors_path = os.path.join(ROOT, "tests", "reference_mirrors.json")
    ok(os.path.exists(mirrors_path), "the mirror manifest exists")
    if os.path.exists(mirrors_path):
        manifest = json.load(open(mirrors_path, encoding="utf-8"))
        ok(isinstance(manifest.get("_comment"), str) and len(manifest["_comment"]) > 40,
           "reference_mirrors.json explains why mirrors exist")
        ok(bool(manifest.get("mirrors")), "reference_mirrors.json declares at least one mirror")

        def _payload(node):
            if "values" in node:
                return sorted(map(str, node["values"]))
            if "entries" in node:
                return sorted(f"{k}={v}" for k, v in node["entries"].items())
            return sorted(f"{k}={v}" for k, v in node.items() if not k.startswith("_"))

        for entry in manifest.get("mirrors", []):
            concept = entry.get("concept", "?")
            ok(isinstance(entry.get("why"), str) and len(entry["why"]) > 30,
               f"mirror {concept!r} documents WHY it is duplicated")
            can = entry["canonical"]
            can_doc = json.load(open(os.path.join(ROOT, can["file"]), encoding="utf-8"))
            have_can = can["group"] in can_doc
            ok(have_can, f"mirror {concept!r}: canonical group present in {can['file']}")
            if not have_can:
                continue
            want = _payload(can_doc[can["group"]])
            for m in entry["mirrors"]:
                m_doc = json.load(open(os.path.join(ROOT, m["file"]), encoding="utf-8"))
                have_m = m["group"] in m_doc
                ok(have_m, f"mirror {concept!r}: group present in {m['file']}")
                if not have_m:
                    continue
                got = _payload(m_doc[m["group"]])
                extra_can = [v for v in want if v not in got][:4]
                extra_mir = [v for v in got if v not in want][:4]
                detail = ""
                if extra_can:
                    detail += f" only-canonical={extra_can}"
                if extra_mir:
                    detail += f" only-mirror={extra_mir}"
                ok(want == got,
                   f"mirror {concept!r} identical: {can['file']}:{can['group']} == "
                   f"{m['file']}:{m['group']}{detail}")

        # Any group duplicated across skills but NOT declared is drift waiting to happen.
        declared = set()
        for entry in manifest.get("mirrors", []):
            declared.add((entry["canonical"]["file"], entry["canonical"]["group"]))
            for m in entry["mirrors"]:
                declared.add((m["file"], m["group"]))
        # only the two files that genuinely share a purpose across the collector/ingest split
        pair = [("WebPivot/references/registrant_noise.json",
                 "tools/kb/references/registrant_noise.json")]
        for a, b in pair:
            da = json.load(open(os.path.join(ROOT, a), encoding="utf-8"))
            db = json.load(open(os.path.join(ROOT, b), encoding="utf-8"))
            shared = {k for k in da if not k.startswith("_")} & {k for k in db if not k.startswith("_")}
            for g in sorted(shared):
                ok((a, g) in declared or (b, g) in declared,
                   f"group {g!r} shared by both registrant_noise copies is declared in the "
                   f"mirror manifest")

    # --- 5. a broken data file degrades loudly, never silently --------------------------------
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

    # --- 6. assessment.md ownership: a writer overwrites ONLY its own output ------------------
    # Both front-ends render to cases/<case>/assessment.md, and so does the analyst by hand. The
    # loop used a plain open(...,"w") and destroyed hand-written assessments silently. Each writer
    # now claims only its own signature; everything else is diverted to loop_assessment.md.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    sys.path.insert(0, os.path.join(ROOT, "harness"))
    import case_state as cs                                                    # noqa: E401

    shapes = {
        "evidence_report cluster": ("UNCLASSIFIED//FOUO\n\n# Cluster Intelligence Assessment — c\n",
                                    True, False),
        "evidence_report single":  ("# Intelligence Assessment — host.example\n", True, False),
        "harness render_markdown": ("# Assessment\n\n**BLUF —** x\n", False, True),
        "analyst titled":          ("# Assessment — my case\n\n## BLUF\n", False, False),
        "analyst other heading":   ("# site.example — infrastructure assessment\n", False, False),
        "analyst html-comment":    ("<!-- round 3 -->\n# Assessment\n", False, False),
    }
    for label, (text, loop_may, sdk_may) in shapes.items():
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(text)
            p = fh.name
        ok(cs.may_overwrite_assessment(p, cs.EVIDENCE_REPORT_MD) == loop_may,
           f"loop {'may' if loop_may else 'must NOT'} overwrite: {label}")
        ok(cs.may_overwrite_assessment(p, cs.HARNESS_RENDER_MD) == sdk_may,
           f"sdk  {'may' if sdk_may else 'must NOT'} overwrite: {label}")
        os.unlink(p)

    ok(cs.may_overwrite_assessment(os.path.join(ROOT, "no", "such.md"), cs.EVIDENCE_REPORT_MD),
       "absent assessment.md is writable")

    # the SDK writer must resolve tools/ from its own location, not the caller's `root`
    import render                                                              # noqa: E401
    from schemas import Assessment                                             # noqa: E401
    a = Assessment(bluf="t", attribution_level="inconclusive", confidence="low",
                   cluster=[], evidence=[], gaps=[], next_pivots=[])
    T = tempfile.mkdtemp()
    os.makedirs(os.path.join(T, "cases", "c1"))
    ok(os.path.basename(render.save_markdown(a, "c1", T)) == "assessment.md",
       "save_markdown writes assessment.md on a fresh case (root != repo)")
    with open(os.path.join(T, "cases", "c1", "assessment.md"), "w") as fh:
        fh.write("# Assessment — hand written\n\nMINE\n")
    ok(os.path.basename(render.save_markdown(a, "c1", T)) == "loop_assessment.md",
       "save_markdown diverts when an analyst file is present")
    ok("MINE" in open(os.path.join(T, "cases", "c1", "assessment.md")).read(),
       "save_markdown left the analyst file byte-intact")
    shutil.rmtree(T)

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
    print(f"PASS — reference layer green ({_PASSED} checks: data files documented, "
          f"{len(LOADERS)} loaders identical, consumers verified loading real data)")
