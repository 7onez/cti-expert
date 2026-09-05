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

DATA LIVES IN JSON, NOT HERE
---------------------------
Every denylist is loaded from `references/noise_filters.json` (sibling directory). That file is
DATA an analyst edits directly — add a managed-DNS provider or a privacy-proxy phone without
touching code or redeploying. This module holds only the matching LOGIC (label-boundary NS
matching, exact-vs-parent apex rules, phone normalisation). Adding to the JSON is the whole
maintenance model; everything downstream reads from here.

If the JSON is missing or unparseable the module falls back to a MINIMAL embedded safety net and
warns on stderr — it never silently disables filtering, because a filter that quietly returns
False everywhere manufactures false clusters.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kb_refs  # noqa: E402 — the shared references/*.json loader

_REF_PATH = kb_refs.ref_path(__file__, "noise_filters.json")

# Minimal safety net used ONLY if the JSON cannot be read. Deliberately small: it covers the
# highest-frequency false-cluster sources so a broken deploy degrades instead of failing open.
_FALLBACK = {
    "managed_dns_suffixes": ["ns.cloudflare.com", "cloudflare.com", "domaincontrol.com",
                             "registrar-servers.com", "awsdns", "dns-parking.com"],
    "generic_nameserver_labels": ["ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
                                  "nameserver", "nsbak", "a", "b", "c", "d"],
    "parking_favicon_mmh3": [643372374, 0, -1896664326],
    "platform_default_favicon_mmh3": [-908198569],
    "noise_tracker_ids": ["UA-26575989-44"],
    "social_handle_noise": [".png", ".jpg", ".svg", ".css", ".js"],
    "bulk_registrant_max_domains": {"max_domains": 200},
    "reverse_search_edge_cap": {"max_hits": 500},
    "shared_hosting_max_cohosts": {"max_cohosts": 12},
    "comment_boilerplate": ["litespeed", "wordpress", "google tag manager", "gtag",
                            "google analytics", "open graph", "start of head", "end of head",
                            "start of body", "end of body", "cache", "begin", "end"],
    "comment_min_length": {"chars": 24},
    "dom_skeleton_min_tags": {"tags": 12},
    "parking_host_substrings": ["sedoparking.com", "sedo.com", "parkingcrew", "bodis.com"],
    "role_email_localparts": ["abuse", "hostmaster", "postmaster"],
    "registrar_email_domains": ["cloudflare.com", "namecheap.com", "godaddy.com",
                                "withheldforprivacy.com", "privacyprotect.org"],
    "privacy_email_tokens": ["privacy", "protect", "whois", "redact", "withheld", "proxy"],
    "privacy_proxy_phones": [],
    "placeholder_phones": ["0000000000", "5555555555", "1234567890"],
    "phone_length": {"min_digits": 7, "max_digits": 15},
    "shared_infra_apexes": ["google.com", "cloudflare.com", "amazonaws.com", "gmail.com"],
    "saas_tenant_suffixes": ["pages.dev", "vercel.app", "github.io", "myshopify.com"],
}


def _load_ref(path: str = _REF_PATH) -> dict:
    """Read the denylist data file. Values live under a `values` key alongside an analyst-facing
    `_comment`; scalars (phone_length) are read directly. Delegates to the shared loader so this
    module and the rest of the KB degrade identically when a data file is broken."""
    return kb_refs.load_ref(path, _FALLBACK)


_REF = _load_ref()

# Managed / registrar DNS whose nameservers are shared by millions of unrelated domains.
# A `uses_nameserver` edge to one of these must NOT create a same-operator cluster.
MANAGED_DNS_SUFFIXES = tuple(_REF["managed_dns_suffixes"])

# Nameserver labels that identify nothing (ns1, dns2, nsbak). DISPLAY-only — see the group's
# _comment. Never consulted when deciding a clustering edge; that is managed_dns_suffixes' job.
GENERIC_NAMESERVER_LABELS = frozenset(str(x).strip().lower()
                                      for x in _REF["generic_nameserver_labels"])

# Favicon mmh3 (Shodan/FOFA) hashes of parking / for-sale / marketplace pages, unioned with the
# DEFAULT icons of hosted platforms/funnel builders. Distinct groups in the JSON because they mean
# different things; one predicate here because the treatment is identical — never a clustering hub.
PARKING_FAVICON_MMH3 = ({int(x) for x in _REF["parking_favicon_mmh3"]} |
                        {int(x) for x in _REF["platform_default_favicon_mmh3"]})

# Base-rate control on cluster building: a reverse search returning at least this many hits
# describes shared infrastructure, so its hits must not become domain->indicator edges.
REVERSE_SEARCH_EDGE_CAP = int(_REF["reverse_search_edge_cap"]["max_hits"])

# Above this many domains, a registrant CONTACT is a shared registration service, not an owner.
# Tighter than the artifact cap above: a contact is a much weaker hub than a technical artifact.
BULK_REGISTRANT_MAX_DOMAINS = int(_REF["bulk_registrant_max_domains"]["max_domains"])

# Above this many distinct registrable apexes on one IP, the IP is shared/bulk hosting (or a CDN
# edge): `hosted_on` to it is co-tenancy, never an owner link. ONE number, read by the KB ingester
# (fact, not edge), the cluster partition (ignored as a binder) and the frontier (case_state
# MAX_IP_COHOSTS) — so the frontier and the KB can never disagree about which IP is a landlord.
SHARED_HOSTING_MAX_COHOSTS = int(_REF["shared_hosting_max_cohosts"]["max_cohosts"])

# HTML-comment boilerplate (substring match) + the length floor below which a comment is a
# section marker, not a fingerprint.
COMMENT_BOILERPLATE = tuple(_REF["comment_boilerplate"])
COMMENT_MIN_LENGTH = int(_REF["comment_min_length"]["chars"])

# Minimum tag count before a DOM tag-skeleton hash is distinctive enough to cluster on.
DOM_SKELETON_MIN_TAGS = int(_REF["dom_skeleton_min_tags"]["tags"])

# Relations that carry TEMPLATE / BUILD artifacts rather than owner-set identity: a cache-plugin's
# inline CSS, an HTML comment, the DOM skeleton — and the page's JS BUNDLE hash. A vendor that sells
# or installs a template leaves the same bundle on every buyer's site; a same_bundle edge merged a
# template vendor with 60 of its customers into one "operator". Kept as EVIDENCE edges, never as
# cluster binders (query._components / intel._write_clusters / --strong).
BOILERPLATE_RELS = frozenset({"same_inline_css", "same_comment", "same_template", "same_bundle"})

# Scraped social "handles" that are really static assets or templating placeholders.
SOCIAL_HANDLE_NOISE = tuple(_REF["social_handle_noise"])
# {u} ${name} %s %(x)s <user> :user — every templating dialect a bundle might ship.
_PLACEHOLDER_RE = re.compile(r"\{[^/}]*\}|\$\{[^}]*\}|%[sd]\b|%\([^)]*\)|<[^/>]+>|^:\w+$")
# Per-network routing words (never an account) and the networks whose account sits behind a
# router word in the SECOND path segment. DATA: references/noise_filters.json.
_SOCIAL_RESERVED = {k: frozenset(str(x).lower() for x in v)
                    for k, v in (_REF.get("social_reserved_paths") or {}).items()}
_SOCIAL_SECOND = {k: frozenset(str(x).lower() for x in v)
                  for k, v in (_REF.get("social_second_segment_networks") or {}).items()}
# Library / vendor / platform credit accounts (a polyfill banner, a theme author) — never the operator.
_SOCIAL_NOISE_ACCOUNTS = {k: frozenset(str(x).lower() for x in v)
                          for k, v in (_REF.get("social_noise_accounts") or {}).items()}

# Analytics/tag IDs belonging to a hosting PLATFORM's own parking/default pages, not to the
# site owner. Clustering on one links every tenant of that provider.
NOISE_TRACKER_IDS = {str(x).strip().upper() for x in _REF["noise_tracker_ids"]}

# Host substrings that mark parking / sinkhole / marketplace infra (not operator infra).
PARKING_HOST_SUBSTRINGS = tuple(_REF["parking_host_substrings"])

# Role/abuse email local-parts and registrar/privacy email domains. These appear in WHOIS
# as registrar abuse contacts or privacy proxies, NOT the registrant — so a `registered_by`
# edge to one clusters every domain at that registrar. Registrant clustering must ignore them.
ROLE_EMAIL_LOCALPARTS = tuple(_REF["role_email_localparts"])
REGISTRAR_EMAIL_DOMAINS = tuple(_REF["registrar_email_domains"])

# Registrable apexes that are shared infrastructure — CDN, analytics, social, SaaS, registrar,
# parking, marketplace. Matched exact-or-parent, so `foo.cloudfront.net` is caught by
# `cloudfront.net`. Never an operator lead: an expired case domain resolves or redirects here, so
# passive-DNS / urlscan report it as "related" when it is the landlord, not a sibling.
SHARED_INFRA_APEXES = frozenset(_REF["shared_infra_apexes"])

# Platforms where the APEX is infrastructure but `<tenant>.<suffix>` is a REAL, separately-owned
# site — scam operators host on these constantly. Suffix-matching these as shared infra would
# silently drop live targets, so they are matched EXACTLY (bare apex = noise, tenant = keep).
SAAS_TENANT_SUFFIXES = frozenset(_REF["saas_tenant_suffixes"])


def _host(x: str) -> str:
    return (x or "").strip().lower().rstrip(".")


def is_shared_infra_apex(apex: str) -> bool:
    """True if a registrable apex is shared infrastructure and must never become an investigation
    seed. Exact-or-parent for SHARED_INFRA_APEXES; EXACT-only for SAAS_TENANT_SUFFIXES, because
    `victim-shop.myshopify.com` / `kit.pages.dev` are real targets while the bare platform apex is
    not. Also defers to is_parking_host for the parking/marketplace substrings."""
    a = _host(apex)
    if not a or "." not in a:
        return True
    if a in SAAS_TENANT_SUFFIXES:          # bare platform apex — noise
        return True
    if any(a.endswith("." + s) for s in SAAS_TENANT_SUFFIXES):
        return False                       # a tenant on that platform — a real, separate target
    if any(a == d or a.endswith("." + d) for d in SHARED_INFRA_APEXES):
        return True
    return is_parking_host(a)


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


def is_noise_tracker(tracker_id) -> bool:
    """True for an analytics/tag ID owned by a hosting platform's own parking/default pages.
    Exact match — a tenant's real ID must never be caught by a prefix rule."""
    if tracker_id is None:
        return False
    return str(tracker_id).strip().upper() in NOISE_TRACKER_IDS


def is_parking_host(host: str) -> bool:
    h = _host(host)
    return any(s in h for s in PARKING_HOST_SUBSTRINGS)


# Substrings that mark a WHOIS privacy-proxy email domain, whatever the provider. Catches
# the long tail (data-protected.net, whoissecure.net, yinsibaohu.aliyun.com, domain-contact.org…)
# without enumerating every proxy. Kept conservative so real consumer domains (163.com, gmail) pass.
PRIVACY_EMAIL_TOKENS = tuple(_REF["privacy_email_tokens"])


def is_noise_email(email: str) -> bool:
    """True if the email is a registrar/registry role or privacy-proxy address — shared by
    every domain at that provider, so it must not seed a registrant cluster."""
    e = _host(email)
    if "@" not in e:
        return False
    local, _, dom = e.partition("@")
    if local in ROLE_EMAIL_LOCALPARTS or local.startswith("abuse"):
        return True
    # abuse.<registrar>.tld — the role is in the DOMAIN, not the local-part, so `takedown@` or
    # `noreply@` on such a host is still registrar boilerplate rather than a registrant.
    if dom.split(".")[0] == "abuse":
        return True
    if any(dom == d or dom.endswith("." + d) for d in REGISTRAR_EMAIL_DOMAINS):
        return True
    return any(tok in dom for tok in PRIVACY_EMAIL_TOKENS)


def is_saturated_reverse(total) -> bool:
    """True if a reverse-search result set is too large to build same-owner edges from.

    An artifact carried by this many hosts is shared infrastructure by definition; fanning its
    hits out into edges is what makes a hosted platform's default favicon the biggest cluster in
    the KB. Catches the long tail no per-value denylist can enumerate.
    """
    try:
        return total is not None and int(total) >= REVERSE_SEARCH_EDGE_CAP
    except (TypeError, ValueError):
        return False


def is_noise_social_handle(handle: str) -> bool:
    """True if a scraped social 'handle' is a static asset or an unsubstituted template
    placeholder rather than somebody's account."""
    h = (handle or "").strip().strip("/").lower()
    if not h:
        return True
    if h.endswith(SOCIAL_HANDLE_NOISE):
        return True
    return bool(_PLACEHOLDER_RE.search(h))


def social_handle(net: str, url: str):
    """The ACCOUNT a scraped social link points at, or None when the link is not an account.

    `github.com/zloirock/core-js` -> `zloirock` (the repo is content, the user is the identity);
    `youtube.com/embed/<id>`, `youtube.com/vi/<id>/0.jpg`, `facebook.com/sharer.php?u=…`,
    `twitter.com/intent/tweet` -> None (players, thumbnails, share widgets); `youtube.com/c/<name>`,
    `t.me/s/<name>`, `zalo.me/g/<group>` -> the second segment; `youtube.com/@name` -> `name`; a
    bare host (`https://zalo.me`) -> None. Taking the LAST path segment — the old rule — made
    `LICENSE`, `core-js`, `embed` and `zalo.me` shared "contacts" that merged unrelated sites."""
    try:
        from urllib.parse import urlparse, parse_qs
        u = str(url or "").strip()
        if u.startswith("//"):                  # protocol-relative (`//img.youtube.com/vi/`)
            u = "https:" + u
        pr = urlparse(u if "://" in u else "https://" + u)
    except Exception:  # noqa: BLE001
        return None
    segs = [s for s in (pr.path or "").split("/") if s]
    net = (net or "").lower()
    if not segs:
        return None
    first = segs[0].lower()
    if first.startswith("@") and len(first) > 1:
        handle = segs[0][1:]
    elif net == "facebook" and first == "profile.php":
        ids = parse_qs(pr.query or "").get("id") or []
        handle = ids[0] if ids else None
    elif first in _SOCIAL_SECOND.get(net, ()):
        handle = segs[1] if len(segs) > 1 and not is_noise_social_handle(segs[1]) else None
    elif first in _SOCIAL_RESERVED.get("*", ()) or first in _SOCIAL_RESERVED.get(net, ()):
        handle = None
    elif is_noise_social_handle(segs[0]):
        handle = None                   # a file (share.png, index.html) is never an account
    else:
        handle = segs[0]
    if handle and handle.lower() in _SOCIAL_NOISE_ACCOUNTS.get(net, ()):
        return None                     # an OSS / platform credit (core-js, jQuery…), not the operator
    return handle


def is_bulk_registrant(count) -> bool:
    """True if this many domains under one registrant contact makes it a shared registration
    service (reseller / IT agency / corporate-services firm / resale portfolio) rather than an
    owner. Read by BOTH ingest paths so they cannot disagree about where the line sits."""
    try:
        return count is not None and int(count) > BULK_REGISTRANT_MAX_DOMAINS
    except (TypeError, ValueError):
        return False


def is_shared_hosting_ip(cohost_count) -> bool:
    """True if this many distinct apexes answering on one IP make it shared/bulk hosting — its
    co-tenants are strangers, and a `hosted_on` edge to it must never bind a cluster."""
    try:
        return cohost_count is not None and int(cohost_count) > SHARED_HOSTING_MAX_COHOSTS
    except (TypeError, ValueError):
        return False


def is_boilerplate_comment(comment: str) -> bool:
    """True if an HTML comment is builder/plugin boilerplate rather than an operator tell."""
    cl = " ".join((comment or "").split()).lower()
    if len(cl) < COMMENT_MIN_LENGTH:
        return True
    return any(b in cl for b in COMMENT_BOILERPLATE)


# Registrant PHONE noise. A privacy/proxy provider publishes ONE phone across every domain it
# fronts, so a naive `registered_by -> phone` edge merges thousands of unrelated domains — the
# same trap as the `Domain Admin` role-placeholder name and the registrar abuse email above.
#
# Two mechanisms, because enumerating every provider's number is hopeless:
#   1. a small denylist of numbers VERIFIED in-case (each seen published as the contact block of
#      a named privacy org, alongside that org's own postal address), and
#   2. the general rule — ANY phone in a record whose registrant email/org is already
#      privacy-flagged belongs to the PROXY, not the registrant. This needs no new constants and
#      covers providers not listed here, so prefer passing the context arguments.
# Extend `privacy_proxy_phones` in the JSON only with numbers you have actually observed.
def _normalize_phone(phone: str) -> str:
    """Digits only, with an international prefix (leading '+' or '00') stripped, so the same
    number written `+354.421 2434` / `00354-4212434` / `3544212434` compares equal. Applied to
    the JSON lists too, so analysts may enter numbers in any format."""
    p = str(phone or "").strip()
    p = re.sub(r"^\+", "", p)
    p = re.sub(r"\D", "", p)
    if p.startswith("00") and len(p) > 9:
        p = p[2:]
    return p


PRIVACY_PROXY_PHONES = frozenset(_normalize_phone(p) for p in _REF["privacy_proxy_phones"])

# Obvious filler a registrar/registrant typed to satisfy a required field. Exact matches only —
# a general "sequential digits" test would eat real numbers.
PLACEHOLDER_PHONES = frozenset(_normalize_phone(p) for p in _REF["placeholder_phones"])

_PHONE_MIN = int((_REF.get("phone_length") or {}).get("min_digits", 7))
_PHONE_MAX = int((_REF.get("phone_length") or {}).get("max_digits", 15))


def is_noise_phone(phone, registrant_email: str = None, registrant_org: str = None) -> bool:
    """True if a registrant phone is a privacy-proxy/registrar number, filler, or malformed —
    i.e. shared by every domain at that provider, so it must not seed a registrant cluster.

    Pass `registrant_email` / `registrant_org` from the SAME WHOIS record when you have them:
    a phone sitting in a privacy-proxied record is the proxy's, whatever the number, which
    catches providers absent from PRIVACY_PROXY_PHONES."""
    p = _normalize_phone(phone)
    if not p:
        return False                       # nothing to judge — let the caller decide
    if len(p) < _PHONE_MIN or len(p) > _PHONE_MAX:   # bounds from the JSON (E.164 caps at 15)
        return True
    if p in PLACEHOLDER_PHONES:
        return True
    if len(set(p)) == 1:                   # 4444444444 etc.
        return True
    if p in PRIVACY_PROXY_PHONES:
        return True
    if registrant_email and is_noise_email(registrant_email):
        return True
    if registrant_org:
        org = (registrant_org or "").strip().lower()
        if any(tok in org for tok in PRIVACY_EMAIL_TOKENS):
            return True
    return False


def is_noise_indicator(indicator_value: str) -> bool:
    """Dispatch on a KB indicator id ('ns:...', 'favicon:...', 'google_analytics_ga4:...')
    → True if it is shared infrastructure / a malformed extraction that must not seed a
    cluster. Unknown/other indicator kinds → False."""
    v = (indicator_value or "").strip()
    if v.startswith("ns:"):
        return is_managed_dns(v[3:])
    if v.startswith("favicon:"):
        return is_parking_favicon(v.split(":", 1)[1])
    if v.startswith("phone:"):
        return is_noise_phone(v.split(":", 1)[1])
    if v.startswith("google_analytics_ga4:"):
        # canonical GA4 is UPPERCASE G-XXXXXXXXXX; anything else (g-recaptcha, g-signin…)
        # is a mis-extracted web-component class, not a measurement ID.
        return not re.fullmatch(r"G-[A-Z0-9]{8,12}", v.split(":", 1)[1])
    if v.startswith(("api_endpoint:", "websocket:")):
        # A backend harvested from a JS bundle (wp_assets) is only an operator link when the
        # host is the operator's OWN infrastructure. A backend that is a hosted platform apex
        # (a BaaS, a CDN, a parking/marketplace host) is shared by every tenant on it — the
        # same same-KIT-not-same-OPERATOR trap as a shared nameserver.
        # is_shared_infra_apex already matches a host against its parent apexes, so the
        # full backend hostname can be passed straight through.
        return is_shared_infra_apex(v.split(":", 1)[1])
    return False


if __name__ == "__main__":  # tiny self-test / lookup CLI
    import sys
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print(f"{arg!r}: managed_dns={is_managed_dns(arg)} "
                  f"parking_host={is_parking_host(arg)} "
                  f"noise_indicator={is_noise_indicator(arg)}")
    else:
        # --- data file: must be present and complete, else filtering silently degrades ---
        assert os.path.exists(_REF_PATH), f"missing data file {_REF_PATH}"
        _fresh = _load_ref()
        for _k in _FALLBACK:
            assert _k in _fresh, f"{_REF_PATH} is missing key {_k!r}"
        assert len(MANAGED_DNS_SUFFIXES) > len(_FALLBACK["managed_dns_suffixes"]), \
            "loaded the fallback, not the JSON — check references/noise_filters.json"
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
        # --- registrant phone ---
        assert _normalize_phone("+354.421 2434") == "3544212434"
        assert _normalize_phone("00354-4212434") == "3544212434"
        assert is_noise_phone("3544212434")                # privacy proxy, bare
        assert is_noise_phone("+354.421 2434")             # same number, formatted
        assert is_noise_phone("18022274003")               # privacy proxy
        assert is_noise_phone("5555555555")                # filler
        assert is_noise_phone("4444444444")                # single repeated digit
        assert is_noise_phone("12345")                     # too short to be an MSISDN
        assert is_noise_phone("1234567890123456789")       # longer than E.164
        assert not is_noise_phone("")                      # nothing to judge — caller decides
        assert not is_noise_phone("442071838750")          # a real registrant number, keep
        assert not is_noise_phone("998725725676")          # real intl number, keep
        # context rule: any phone inside a privacy-proxied record belongs to the proxy
        assert is_noise_phone("442071838750",
                              registrant_email="x.protect@withheldforprivacy.com")
        assert is_noise_phone("442071838750",
                              registrant_org="Privacy service provided by Withheld for Privacy ehf")
        assert not is_noise_phone("442071838750", registrant_email="operator@example.com")
        assert is_noise_indicator("phone:3544212434")
        assert not is_noise_indicator("phone:442071838750")
        print("noise_filters self-test: OK")
