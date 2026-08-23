#!/usr/bin/env python3
"""
hypothesize.py — turn shared indicators into testable attribution hypotheses. Zero web I/O.

The IntelAnalysis method (§4) is: state a same-operator hypothesis, then actively try to
BREAK it, then pick the cheapest lead that confirms-or-kills. This tool scaffolds that
deterministically so the analyst (model or human) starts from a structured board, not a blank page:

  1. clusters domains that share KB indicators (union-find over shared indicators),
  2. classifies the binding artifacts into attribution-grade / corroborating / noise (the ladder),
  3. emits, per candidate cluster:
       • HYPOTHESIS  — "these domains are one operator, bound by <artifacts>"
       • CONFIDENCE  — assessed / likely / lead, per the corroboration rule (≥2 attribution-grade,
                       or 1 + a named identity)
       • DISCONFIRM  — the artifact that should NOT be shared if the hypothesis is true, + the check
       • QUESTIONS   — the open analyst / investigation questions to answer next

The model still does the judgment; this hands it the falsifiable board.

Usage:
  python3 tools/kb/hypothesize.py --kb knowledge --min 2
  python3 tools/kb/hypothesize.py --kb knowledge --domain brand-a.example
  python3 tools/kb/hypothesize.py --kb knowledge --min 3 --top 5
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kb_refs  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)
from knowledge_base import KB  # noqa: E402

# ---------------------------------------------------------------- evidence weights (RULE 3)
# DATA: references/evidence_weights.json — the scoring weights behind an attribution call, so an
# analyst can promote or demote a relation without editing Python. See that file's _comment for
# why attribution/corroborating deliberately diverge from the graph projection's own tiers.
# Minimal safety net. Trimmed on purpose and in the CONSERVATIVE direction: on a broken data
# file fewer relations count as attribution-grade and fewer count as corroborating, so the
# scorer makes FEWER claims rather than more. `noise_rels` stays complete — shrinking that one
# would start clustering on managed nameservers, which is the failure that must never happen.
_EW_FALLBACK = {
    "attribution_rels": ["registered_by", "uses_verification"],
    "identity_rels": ["registered_by"],
    "service_rels": ["uses_analytics"],
    "corroborating_rels": ["same_template", "uses_favicon"],
    "noise_rels": ["uses_nameserver"],
}
_EW = kb_refs.load_ref(kb_refs.ref_path(__file__, "evidence_weights.json"), _EW_FALLBACK)

ATTRIBUTION = set(_EW["attribution_rels"])
# identity artifacts an operator legitimately reuses across MANY of their own domains vs.
# third-party SERVICE tokens a shared SEO/marketing agency spreads across UNRELATED clients —
# the latter over-merge, so they get a much stricter fan-out cap (agency-suspect).
_IDENTITY_RELS = set(_EW["identity_rels"])
_SERVICE_RELS = set(_EW["service_rels"])
CORROBORATING = set(_EW["corroborating_rels"])
NOISE = set(_EW["noise_rels"])

# `uses_nameserver` is CONDITIONAL in cti-expert (RULE 5), which is why _tier() below overrides
# the flat `noise_rels` grading for it. Delegation to a managed provider (Cloudflare, GoDaddy,
# Route 53 …) is shared by millions of unrelated domains and must never cluster — but delegation
# to a nameserver the operator RUNS THEMSELVES is one of the strongest links available: you cannot
# point a domain at ns1.<their-host>.com without controlling that zone.
# noise_filters.MANAGED_DNS_SUFFIXES is the list that tells them apart; is_managed_ns() applies it.
try:
    from noise_filters import MANAGED_DNS_SUFFIXES
except Exception:  # noqa: BLE001 — keep hypothesize usable standalone
    MANAGED_DNS_SUFFIXES = ("ns.cloudflare.com", "cloudflare.com", "domaincontrol.com",
                            "registrar-servers.com", "awsdns", "azure-dns.com")


def is_managed_ns(indicator):
    """True if this nameserver belongs to a public managed-DNS/registrar provider."""
    host = str(indicator or "").split(":", 1)[-1].strip().lower().rstrip(".")
    return any(host == s or host.endswith("." + s) or s in host for s in MANAGED_DNS_SUFFIXES)


# ---------------------------------------------------------------- reference data (RULE 3)
# privacy-proxy / registrar-role / protected-whois emails — shared by thousands of UNRELATED
# domains, so they must never drive clustering (they'd chain the whole KB into one blob) —
# plus placeholder registrants and empty-hash parser artifacts. All DATA, in
# references/registrant_noise.json, shared with ingest_webpivot.py and ingest_report.py.
_H_FALLBACK = {
    "proxy_email_tokens": ("privacy", "protect", "proxy", "whoisguard", "redacted", "withheld",
                           "abuse@", "registrar", "noreply", "no-reply"),
    "placeholder_person_markers": ("domain admin", "redacted", "privacy", "whois",
                                   "not disclosed", "reactivation period", "pending delete"),
    "junk_hash_prefixes": ("da39a3ee5e6b4b0d", "e3b0c44298fc1c14", "d41d8cd98f00b204",
                           "g-recaptcha"),
}
_H_REF = kb_refs.load_ref(kb_refs.ref_path(__file__, "registrant_noise.json"), _H_FALLBACK)
_PROXY_EMAIL = tuple(_H_REF["proxy_email_tokens"])
_PLACEHOLDER_PERSON = tuple(_H_REF["placeholder_person_markers"])
# sha1("") / sha256("") prefix / md5("") ; plus recaptcha mis-parsed as a GA id
_JUNK_HASH = tuple(_H_REF["junk_hash_prefixes"])


def _is_proxy(indicator_type, indicator):
    v = indicator.lower()
    if indicator_type == "email":
        return any(p in v for p in _PROXY_EMAIL)
    if indicator_type == "person":
        return any(p in v for p in _PLACEHOLDER_PERSON)
    return False


def _is_junk(indicator):
    return any(j in indicator.lower() for j in _JUNK_HASH)


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _tier(rel, indicator=None):
    if rel == "uses_nameserver":
        # self-hosted NS = zone control = attribution; managed provider = noise. See is_managed_ns.
        return "noise" if (indicator is None or is_managed_ns(indicator)) else "attribution"
    if rel in ATTRIBUTION:
        return "attribution"
    if rel in CORROBORATING:
        return "corroborating"
    return "noise"


def build_clusters(kb, min_domains, max_fanout=40, service_fanout=15):
    """Union-find domains that share any >=min_domains indicator. Returns clusters + their bindings.

    Only *discriminating* indicators drive the union: a proxy/registrar email, or any indicator
    linked to more than `max_fanout` domains, is shared infrastructure (a reseller, a common CDN,
    an ad network) — clustering on it chains unrelated groups into one giant false operator. Those
    broad indicators are dropped from clustering (reported via `--show-dropped`).
    """
    shared = kb.shared_indicators(min_domains)
    uf = _UF()
    union_bindings, support, dropped = [], [], []
    for s in shared:
        rels = set(s["rels"])
        # a SERVICE token (analytics/verification) on many domains is agency-shared, not one
        # operator — cap it far tighter than an identity artifact (registrant/wallet).
        is_service_only = bool(rels & _SERVICE_RELS) and not (rels & _IDENTITY_RELS)
        cap = service_fanout if is_service_only else max_fanout
        if (_is_proxy(s["indicator_type"], s["indicator"]) or _is_junk(s["indicator"])
                or s["domain_count"] > cap):
            if is_service_only and s["domain_count"] > cap:
                s = dict(s, _agency_suspect=True)
            dropped.append(s)
            continue
        is_attr = any(_tier(r, s["indicator"]) == "attribution" for r in s["rels"])
        if is_attr:
            union_bindings.append(s)      # ONLY identity/owner artifacts merge operators
        else:
            support.append(s)             # kit/corroborating: reported, but never merges clusters
    # union only on attribution-grade identity artifacts (same-operator, not same-kit)
    for s in union_bindings:
        doms = s["domains"]
        for d in doms[1:]:
            uf.union(doms[0], d)
    groups = {}
    for s in union_bindings:
        for d in s["domains"]:
            groups.setdefault(uf.find(d), set()).add(d)
    # attach every binding (attribution + supporting kit) that stays WITHIN the formed group
    out = []
    for root, doms in groups.items():
        gbind = [s for s in (union_bindings + support) if len(set(s["domains"]) & doms) >= 2]
        out.append({"domains": sorted(doms), "bindings": gbind})
    return out, dropped


def _classify_bindings(bindings):
    tiers = {"attribution": [], "corroborating": [], "noise": []}
    for s in bindings:
        for rel in s["rels"]:
            t = _tier(rel)
            tiers[t].append((rel, s["indicator_type"], s["indicator"], s["domain_count"]))
    for t in tiers:
        tiers[t] = sorted(set(tiers[t]), key=lambda x: -x[3])
    return tiers


def _confidence(tiers):
    attr = tiers["attribution"]
    named = [x for x in attr if x[0] == "registered_by"]
    if len(attr) >= 2:
        return "assessed", "≥2 independent attribution-grade artifacts"
    if len(attr) == 1 and named:
        return "assessed", "1 attribution-grade + a named identity (registrant)"
    if len(attr) == 1:
        return "likely", "1 attribution-grade artifact; needs a 2nd to confirm"
    if tiers["corroborating"]:
        return "lead", "only corroborating artifacts — a lead, not a finding"
    return "weak", "bound only by noise-tier indicators"


def _disconfirm(tiers):
    checks = []
    if any(x[0] == "registered_by" for x in tiers["attribution"]):
        checks.append("Pull WHOIS (current + history) on every domain — a DIFFERENT registrant "
                      "email/name on one breaks the single-operator claim.")
    if any(x[0] in ("uses_analytics", "uses_verification") for x in tiers["attribution"]):
        checks.append("Check for a CONFLICTING analytics/verification property on any member — "
                      "a second owner-token means two operators, not one.")
    checks.append("Resolve the origin IP (behind CDN) for each — an IP in a different ASN on one "
                  "domain weakens shared-infrastructure.")
    if not tiers["attribution"]:
        checks.append("This cluster rests on shared kit/template only — a registrant or owner-token "
                      "lookup must confirm before asserting same-operator (kits are sold/shared).")
    return checks


def _questions(cluster, tiers):
    q = ["Who registered these — one registrant email/name across all, or several? "
         "(recover from WHOIS history if current is privacy-masked)",
         "Is any crypto wallet / payment handle reused across the set? (attribution-grade — same payee)",
         "Are the domains newly-registered (NRD)? run risk_signals.py — young + shared kit = one batch.",
         "Do they share an ORIGIN IP (not just a CDN edge)? which is the true backend/broker node?"]
    if tiers["attribution"]:
        top = tiers["attribution"][0]
        q.append(f"The strongest link is {top[1]}:{top[2]} ({top[0]}) on {top[3]} domains — "
                 f"reverse-search it: does it pull in domains OUTSIDE this seed set?")
    q.append("Which single domain, if removed, disconnects the cluster? (betweenness — that's the broker.)")
    return q


def emit(clusters, top):
    clusters = sorted(clusters, key=lambda c: (-len(_classify_bindings(c["bindings"])["attribution"]),
                                               -len(c["domains"])))
    print(f"# Attribution hypotheses — {len(clusters)} candidate cluster(s), showing top {min(top, len(clusters))}\n")
    for i, c in enumerate(clusters[:top], 1):
        tiers = _classify_bindings(c["bindings"])
        conf, why = _confidence(tiers)
        print(f"## H{i}  [{conf}] — {why}")
        print(f"HYPOTHESIS: the {len(c['domains'])} domains below are ONE operator.")
        print("  domains: " + ", ".join(c["domains"][:12]) +
              (f"  (+{len(c['domains']) - 12} more)" if len(c["domains"]) > 12 else ""))
        for t in ("attribution", "corroborating", "noise"):
            if tiers[t]:
                shown = ", ".join(f"{it}:{iv}({n})" for rel, it, iv, n in tiers[t][:5])
                print(f"  {t}: {shown}" + (" …" if len(tiers[t]) > 5 else ""))
        print("  DISCONFIRM (try to break it):")
        for chk in _disconfirm(tiers):
            print(f"    - {chk}")
        print("  OPEN QUESTIONS:")
        for question in _questions(c, tiers):
            print(f"    ? {question}")
        print()


def main():
    ap = argparse.ArgumentParser(description="Generate falsifiable attribution hypotheses from the KB.")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--min", type=int, default=2, help="shared-indicator threshold")
    ap.add_argument("--domain", help="only clusters containing this domain")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--max-fanout", type=int, default=40,
                    help="an identity artifact on more than N domains is a reseller/proxy, not a link (default 40)")
    ap.add_argument("--service-fanout", type=int, default=15,
                    help="a SERVICE token (GA/GSC/hotjar) on more than N domains is agency-shared, not one operator (default 15)")
    ap.add_argument("--show-dropped", action="store_true",
                    help="list the broad/proxy/agency indicators excluded from clustering")
    a = ap.parse_args()
    kb = KB(a.kb)
    clusters, dropped = build_clusters(kb, a.min, a.max_fanout, a.service_fanout)
    if a.show_dropped and dropped:
        print(f"# dropped {len(dropped)} broad indicator(s) — NOT clustered on (proxy/junk, or fan-out over cap):")
        for s in sorted(dropped, key=lambda x: -x["domain_count"])[:20]:
            tag = "  ⚠AGENCY-SUSPECT (service token — verify operator vs shared agency)" if s.get("_agency_suspect") else ""
            print(f"    [{s['domain_count']}] {s['indicator_type']}:{s['indicator']}{tag}")
        print()
    if a.domain:
        clusters = [c for c in clusters if a.domain in c["domains"]]
        if not clusters:
            print(f"# {a.domain}: not in any shared-indicator cluster at --min {a.min}.")
            return
    if not clusters:
        print(f"# no clusters at --min {a.min}. Lower the threshold or collect more.")
        return
    emit(clusters, a.top)


if __name__ == "__main__":
    main()
