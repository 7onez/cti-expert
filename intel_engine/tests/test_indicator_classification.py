#!/usr/bin/env python3
"""Indicator-classification tests (CLAUDE.md RULE 5).

The KB's clustering logic decides whether two domains get attributed to one operator. Wrong in
either direction is expensive: a false merge names an innocent party, a false split loses the
case. RULE 5 therefore requires any change to that classification to ship with a test covering
at least one managed DNS provider and one self-hosted nameserver.

Run:  python3 tests/test_indicator_classification.py      (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_indicator_classification.py -q   (also works)

No case data here — only placeholders and generic public constants (registrar / privacy-proxy
boilerplate, managed-DNS suffixes), which CLAUDE.md explicitly permits in tracked files.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools", "kb"))

from ingest_webpivot import _is_privacy, _is_role_placeholder, _norm_name  # noqa: E402
from noise_filters import (is_managed_dns, is_noise_email, is_noise_phone,  # noqa: E402
                           is_parking_host, is_shared_infra_apex)

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")


# ---------------------------------------------------------------------------
# 1. Generic registrant ROLE placeholders must NEVER become a clustering edge.
#
# Regression: `Domain Admin` contains no privacy-signalling word, so the _PRIV token list
# missed it, and it became a high-confidence `registered_by -> person` edge that merged every
# unrelated domain whose registrar emitted that same placeholder.
# ---------------------------------------------------------------------------
ROLE_PLACEHOLDERS_SUPPRESSED = [
    "Domain Admin",            # the actual regression
    "domain admin",
    "DOMAIN ADMIN",
    "Domain  Admin",           # collapsed whitespace
    "Domain-Admin",            # punctuation stripped
    "Domain Admin.",           # trailing punctuation
    "Domain Administrator",
    "Domain Manager",
    "DNS Admin",
    "Hostmaster",
    "Administrator",
    "Statutory Masking Enabled",
    "Not Available",
    "N/A",
    "Unknown",
    "Anonymous",
]
for name in ROLE_PLACEHOLDERS_SUPPRESSED:
    check(f"role placeholder suppressed: {name!r}", _is_role_placeholder(name), True)


# ---------------------------------------------------------------------------
# 2. The other direction — REAL registrant identities must still cluster.
#
# Over-filtering is the costlier failure: it silently destroys true attribution. An exact
# normalised match (not substring) is what protects these.
# ---------------------------------------------------------------------------
REAL_NAMES_PRESERVED = [
    "Registrant Name",              # SKILL.md placeholder for a real person
    "Operator A",
    "Admin Solutions GmbH",         # contains "admin" — must survive
    "Domain Manager Services Ltd",  # contains "domain manager" — must survive
    "Administrator Holdings SARL",
    "Hostmaster Technologies Inc",
    "Owner Group Limited",
]
for name in REAL_NAMES_PRESERVED:
    check(f"real name preserved: {name!r}", _is_role_placeholder(name), False)
    check(f"real name not privacy: {name!r}", _is_privacy(name), False)


# ---------------------------------------------------------------------------
# 3. Privacy-SIGNALLING names stay filtered — the pre-existing _PRIV behaviour is not regressed.
# ---------------------------------------------------------------------------
PRIVACY_NAMES = [
    "REDACTED FOR PRIVACY",
    "Redacted for Privacy",
    "WhoisGuard Protected",
    "Withheld for Privacy Purposes",
    "Data Protected",
    "Not Disclosed",
    "Registration Private",
    "Perfect Privacy LLC",
]
for name in PRIVACY_NAMES:
    check(f"privacy name filtered: {name!r}", _is_privacy(name), True)


# ---------------------------------------------------------------------------
# 4. Normalisation behaves as documented.
# ---------------------------------------------------------------------------
check("_norm_name punctuation+case+space", _norm_name("  Domain-ADMIN.  "), "domain admin")
check("_norm_name empty", _norm_name(""), "")
check("_norm_name None", _norm_name(None), "")


# ---------------------------------------------------------------------------
# 5. RULE 5's explicit requirement: nameserver classification, both directions.
#
# `uses_nameserver` is CONDITIONAL. Delegation to a managed provider is noise (rung 10) — those
# NS are shared by millions of unrelated domains. Delegation to a nameserver the operator runs
# themselves is attribution-grade (rung 5): you cannot point a domain at ns1.<their-host>
# without controlling that zone.
# ---------------------------------------------------------------------------
MANAGED_DNS = [
    "ns1.dns-parking.com",      # Hostinger default/parking NS — regression, was missing
    "ns2.dns-parking.com",
    "ns3.dns-parking.com",
    "kate.ns.cloudflare.com",
    "ns01.domaincontrol.com",   # GoDaddy's real NS pattern
    "ns17.secureserver.net",    # GoDaddy / Wild West Domains — regression, was missing
    "dns1.registrar-servers.com",
]
for ns in MANAGED_DNS:
    check(f"managed DNS is noise: {ns!r}", is_managed_dns(ns), True)

SELF_HOSTED_DNS = [
    "ns1.site-a.example",       # operator-run zone -> attribution-grade
    "ns2.site-a.example",
    "dns1.operator-a.example",
]
for ns in SELF_HOSTED_DNS:
    check(f"self-hosted DNS is attribution-grade: {ns!r}", is_managed_dns(ns), False)

# Parking / marketplace hosts: matched on label boundaries like nameservers. A raw substring check
# made jordan.com "parking" (⊃ dan.com), so an operator apex that merely ENDS like a provider was
# shared infrastructure — never seeded, never clustered.
PARKING_HOSTS = [
    "dan.com", "www.dan.com",              # dotted entry: exact domain and its subdomains
    "img.sedoparking.com",
    "ns1.parkingcrew.net",                 # bare entry: a whole label
    "afternic.com",
]
for h in PARKING_HOSTS:
    check(f"parking host is noise: {h!r}", is_parking_host(h), True)

NOT_PARKING = [
    "jordan.com",                          # ⊃ dan.com
    "casedo.com",                          # ⊃ sedo.com
    "treasureabove.com",                   # ⊃ above.com
    "myparkingcrewshop.com",               # bare word inside a label
    "site-a.example",
]
for h in NOT_PARKING:
    check(f"look-alike domain is NOT parking: {h!r}", is_parking_host(h), False)
    check(f"look-alike apex is NOT shared infra: {h!r}", is_shared_infra_apex(h), False)


# ---------------------------------------------------------------------------
# 6. Registrant EMAIL classification, both directions (RULE 5).
#
# Regression: privacy tokens were raw substrings of the whole address and role local-parts were
# noise on ANY domain, so an operator's own legal@ / proxyshop / protectorsgroup / whoisthat
# address could never become a `registered_by` edge. Tokens now match whole labels / hyphen
# segments; role mailboxes are noise only on a registrar / registry / privacy-proxy domain.
# ---------------------------------------------------------------------------
PROVIDER_EMAILS = [                       # real registrar / privacy-proxy mailboxes — noise
    "abuse@godaddy.com",
    "registry-abuse@cloudflare.com",
    "x.protect@withheldforprivacy.com",
    "owner-1234@domainsbyproxy.com",
    "contact@contactprivacy.com",
    "client@whoisguard.com",
    "c1@data-protected.net",
    "a1@whoissecure.net",
    "reg@domain-contact.org",
    "info@yinsibaohu.aliyun.com",
    "abuse@nic.example",                  # registry role mailbox
    "noreply@abuse.registrar.example",    # abuse.<provider> host — whatever the local-part
]
for em in PROVIDER_EMAILS:
    check(f"provider email is noise: {em!r}", is_noise_email(em), True)

OPERATOR_EMAILS = [                       # operator / self-hosted mailboxes — keep as leads
    "legal@operator.example",
    "abuse@operator.example",
    "ops@proxyshop.example",
    "owner@protectorsgroup.example",
    "x@anonymous-bank.example",
    "boss@whoisthat.example",
    "registrant@163.com",
]
for em in OPERATOR_EMAILS:
    check(f"operator email is NOT noise: {em!r}", is_noise_email(em), False)

# The same vocabulary judges a registrant ORG when deciding whether a phone is the proxy's.
check("privacy-proxy org makes its phone noise",
      is_noise_phone("442071838750", registrant_org="Domains By Proxy, LLC"), True)
check("privacy-proxy org (compound word) makes its phone noise",
      is_noise_phone("442071838750", registrant_org="WhoisGuard, Inc."), True)
check("operator org does NOT make its phone noise",
      is_noise_phone("442071838750", registrant_org="Protectors Group LLC"), False)
check("operator org with a privacy-looking prefix does NOT make its phone noise",
      is_noise_phone("442071838750", registrant_org="Anonymous Bank"), False)


# ---------------------------------------------------------------------------
if FAILURES:
    print(f"FAIL — {len(FAILURES)} classification check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("PASS — all indicator-classification checks green "
      f"({len(ROLE_PLACEHOLDERS_SUPPRESSED)} role placeholders, "
      f"{len(REAL_NAMES_PRESERVED)} real names, {len(PRIVACY_NAMES)} privacy names, "
      f"{len(MANAGED_DNS)} managed NS, {len(SELF_HOSTED_DNS)} self-hosted NS)")


def test_indicator_classification():
    """pytest entry point — the module body does the work at import time."""
    assert not FAILURES, FAILURES
