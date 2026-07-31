#!/usr/bin/env python3
"""
noise_filters.py — the single, data-driven source of truth for "this is shared
INFRASTRUCTURE, not a shared OPERATOR."

WHY THIS EXISTS
---------------
Some indicators are technically "shared by N domains" but say nothing about common
ownership because millions of unrelated sites share them: a Cloudflare nameserver, a
Sedo parking favicon, a parking IP. Before this module those judgments lived in the
analyst's head (and in scattered memory notes), so the same false cluster kept coming
back — e.g. phantom.com (legit) "clustered" with a scam domain purely because both use
`samara.ns.cloudflare.com`. Codifying the denylist here, and importing it in the ingester
and the `shared_indicators` query, turns a recurring judgment call into a systematic filter.

A shared *authoritative/private* nameserver is still a real signal — only the big
managed-DNS providers are noise. Same idea as `cdn_ranges.py` for hosting IPs: shared CDN
edge = noise, shared origin = signal.

Add to these lists as you meet new managed-DNS / parking providers; that is the whole
maintenance model. Everything downstream reads from here.
"""
import re

# Managed / registrar DNS whose nameservers are shared by millions of unrelated domains.
# A `uses_nameserver` edge to one of these must NOT create a same-operator cluster.
MANAGED_DNS_SUFFIXES = (
    "ns.cloudflare.com",            # Cloudflare (sage/samara/finley/… .ns.cloudflare.com)
    "cloudflare.com",
    "dnsowl.com",                   # NameSilo
    "domaincontrol.com",            # GoDaddy
    "registrar-servers.com",        # Namecheap
    "namecheaphosting.com",
    "awsdns",                       # AWS Route 53 (awsdns-xx.net/org/com/co.uk)
    "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
    "googledomains.com", "google.com",  # Google Domains / Cloud DNS (ns-cloud-*.googledomains.com)
    "dnsmadeeasy.com", "nsone.net", "dns.he.net",
    "name-services.com",            # eNom
    "worldnic.com",                 # Network Solutions
    "sedoparking.com", "sedo.com",  # Sedo parking DNS
    "parkingcrew.net", "bodis.com", "above.com", "fabulous.com",  # PPC parkers
    "dan.com", "afternic.com", "uniregistrymarket.link",          # domain marketplaces
    "hichina.com", "alidns.com",    # Alibaba
    "cloudns.net",
    "gandi.net",                    # Gandi (ns-1-a/ns-107-c.gandi.net) — used across whole
                                    # unrelated registrar populations; NOT an operator link
    "wixdns.net", "wix.com",        # Wix
    "shopify.com",
    "dnsimple.com", "digitalocean.com", "linode.com", "vultr.com",
    "hostgator.com", "bluehost.com", "siteground.net", "inmotionhosting.com",
    "namebrightdns.com", "rzone.de", "hetzner.com", "ovh.net", "ovh.ca",
    "mysecurecloudhost.com",        # reseller DNS seen in CASE-0001 (tradeinforeign.com)
    "he.net", "freedns.afraid.org",
    "ui-dns.com", "ui-dns.de", "ui-dns.org", "ui-dns.biz",   # IONOS
    "1and1.com", "ionos.com",
)

# Favicon mmh3 (Shodan/FOFA) hashes of parking / for-sale / marketplace pages. Sharing one
# clusters parked domains, not an operator. Extend as you spot new parking favicons.
PARKING_FAVICON_MMH3 = {
    643372374,      # Sedo parking default favicon
    0,              # empty / missing favicon
}

# Host substrings that mark parking / sinkhole / marketplace infra (not operator infra).
PARKING_HOST_SUBSTRINGS = (
    "sedoparking.com", "sedo.com", "parkingcrew", "bodis.com", "above.com",
    "fabulous.com", "dan.com", "afternic", "hugedomains.com", "namesilo.com",
    "uniregistry", "voodoo.com", "parklogic", "skenzo", "domainsponsor",
    "img.sedoparking.com",
)


# Role/abuse email local-parts and registrar/privacy email domains. These appear in WHOIS
# as registrar abuse contacts or privacy proxies, NOT the registrant — so a `registered_by`
# edge to one clusters every domain at that registrar. Registrant clustering must ignore them.
ROLE_EMAIL_LOCALPARTS = (
    "abuse", "registry-abuse", "domainabuse", "abuse-contact", "abusecomplaints",
    "hostmaster", "postmaster", "compliance", "legal", "noc", "dns",
)
REGISTRAR_EMAIL_DOMAINS = (
    "cloudflare.com", "tucows.com", "namecheap.com", "godaddy.com", "enom.com",
    "namesilo.com", "publicdomainregistry.com", "name.com", "gandi.net", "ovh.net",
    "key-systems.net", "1api.net", "registrar-servers.com", "google.com", "markmonitor.com",
    "csctld.com", "cscglobal.com", "porkbun.com", "dynadot.com", "hostinger.com",
    # privacy proxies (belt-and-suspenders; ingester already has _is_privacy)
    "whoisguard.com", "withheldforprivacy.com", "privacyguardian.org",
    "contactprivacy.com", "domainsbyproxy.com", "identity-protect.org", "privacyprotect.org",
)


def _host(x: str) -> str:
    return (x or "").strip().lower().rstrip(".")


def is_managed_dns(nameserver: str) -> bool:
    """True if the nameserver belongs to a big managed/registrar/parking DNS provider.

    Match on DNS-label boundaries, never a raw substring: an unanchored `s in ns` wrongly
    flags an operator's own nameserver whose domain merely CONTAINS a provider suffix
    (e.g. `ns1.jordan.com` ⊃ `dan.com`, `ns1.casedo.com` ⊃ `sedo.com`), silently dropping it
    from clustering. Dotted suffixes match as an exact-or-parent domain; bare labels like
    `awsdns` (Route 53's `ns-2048.awsdns-64.co.uk`) match only as a whole dot/dash-delimited
    label."""
    ns = _host(nameserver)
    for s in MANAGED_DNS_SUFFIXES:
        if "." in s:
            if ns == s or ns.endswith("." + s):
                return True
        elif re.search(r"(?:^|[.\-])" + re.escape(s) + r"(?:[.\-]|$)", ns):
            return True
    return False


def is_parking_favicon(mmh3_hash) -> bool:
    try:
        return int(mmh3_hash) in PARKING_FAVICON_MMH3
    except (TypeError, ValueError):
        return False


def is_parking_host(host: str) -> bool:
    h = _host(host)
    return any(s in h for s in PARKING_HOST_SUBSTRINGS)


# Substrings that mark a WHOIS privacy-proxy email domain, whatever the provider. Catches
# the long tail (data-protected.net, whoissecure.net, yinsibaohu.aliyun.com, domain-contact.org…)
# without enumerating every proxy. Kept conservative so real consumer domains (163.com, gmail) pass.
PRIVACY_EMAIL_TOKENS = (
    "privacy", "protect", "whois", "redact", "withheld", "proxy", "gdpr", "anonym",
    "yinsibaohu", "data-protect", "domain-contact", "dnstination", "identity-protect",
    "whoisguard", "contactprivacy", "domainsbyproxy", "secureserver",
)


def is_noise_email(email: str) -> bool:
    """True if the email is a registrar/registry role or privacy-proxy address — shared by
    every domain at that provider, so it must not seed a registrant cluster."""
    e = _host(email)
    if "@" not in e:
        return False
    local, _, dom = e.partition("@")
    if local in ROLE_EMAIL_LOCALPARTS or local.startswith("abuse"):
        return True
    if any(dom == d or dom.endswith("." + d) for d in REGISTRAR_EMAIL_DOMAINS):
        return True
    return any(tok in dom for tok in PRIVACY_EMAIL_TOKENS)


def is_noise_indicator(indicator_value: str) -> bool:
    """Dispatch on a KB indicator id ('ns:...', 'favicon:...', 'google_analytics_ga4:...')
    → True if it is shared infrastructure / a malformed extraction that must not seed a
    cluster. Unknown/other indicator kinds → False."""
    v = (indicator_value or "").strip()
    if v.startswith("ns:"):
        return is_managed_dns(v[3:])
    if v.startswith("favicon:"):
        return is_parking_favicon(v.split(":", 1)[1])
    if v.startswith("google_analytics_ga4:"):
        # canonical GA4 is UPPERCASE G-XXXXXXXXXX; anything else (g-recaptcha, g-signin…)
        # is a mis-extracted web-component class, not a measurement ID.
        return not re.fullmatch(r"G-[A-Z0-9]{8,12}", v.split(":", 1)[1])
    return False


if __name__ == "__main__":  # tiny self-test / lookup CLI
    import sys
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print(f"{arg!r}: managed_dns={is_managed_dns(arg)} "
                  f"parking_host={is_parking_host(arg)} "
                  f"noise_indicator={is_noise_indicator(arg)}")
    else:
        assert is_managed_dns("samara.ns.cloudflare.com")
        assert is_managed_dns("ns1.dnsowl.com")
        assert not is_managed_dns("ns1.private-operator.example")
        assert is_noise_indicator("ns:samara.ns.cloudflare.com")
        assert is_noise_indicator("favicon:643372374")
        assert not is_noise_indicator("favicon:123456789")
        assert not is_noise_indicator("google_tag_manager:GTM-XYZ")
        assert is_noise_email("registry-abuse@cloudflare.com")
        assert is_noise_email("domainabuse@tucows.com")
        assert is_noise_email("abuse@anything.example")
        assert not is_noise_email("registrant@163.com")    # a real registrant email, keep
        assert not is_noise_email("operator@gmail.com")
        print("noise_filters self-test: OK")
