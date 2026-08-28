"""wp_ippivot — passive IP-address pivoting for WebPivot (the IPPivot half of domain+IP).

Given a bare IP, exhaust the passive OSINT surface WITHOUT ever touching the target:
  - IPinfo.io       → ASN, org/company, hostname (PTR), geo, hosting/privacy flags, abuse contact
  - classify_ip     → is it a CDN/cloud EDGE (shared noise) or an origin candidate?
  - FOFA ip="…"     → open ports, service banners, co-hosted domains/titles (passive index)
  - Shodan host     → ports + services + hostnames (ONLY if SHODAN_KEY is set)
  - dig / nslookup  → PTR (reverse DNS), MX / NS / TXT (SPF/DMARC) via the recursive resolver

**Passive by design:** every source above is an index or a recursive-resolver query. Nothing here
opens a connection to the target IP, so an IP run is not attributable to the analyst.

Noise handling: an IP on a known CDN/cloud edge (classify_ip) or a registry-flagged noisy hosting
ASN is NOT a same-operator pivot — it is recorded as INFORMATION and the provider's ASN + abuse
contact is banked to `references/asn_registry.json` for later enrichment. An ORIGIN-candidate IP
becomes a HIGH `ip` pivot whose FOFA reverse (co-hosted domains) links same-operator infrastructure.
"""
import os
import re
import json
import socket
import shutil
import ipaddress
import subprocess
import concurrent.futures
import urllib.request
import urllib.error
from urllib.parse import urlencode

from wp_common import *      # noqa  — DEFAULT_UA, _secret, uniq, strip_www, _registrable
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
from wp_recon import fofa_search, scan_misconfig
from wp_analyze import classify_ip
from wp_censys import censys_host, censys_configured, censys_queries, attach_censys_queries
from wp_intelx import attach_intelx_queries  # IntelX selector builder (keyless — no key needed)
from wp_hunterhow import attach_hunterhow_queries  # Hunter.how query builder (keyless — no key needed)
import wp_validin  # Validin reverse-IP (FREE key; runs even under --free-only)
try:
    import api_usage                      # licensed-API credit ledger
except Exception:
    api_usage = None

_ASN_REGISTRY = ref_path(__file__, "asn_registry.json")

# MX hostnames that belong to a managed mail provider — a shared one is NOT an operator pivot.
# DATA: references/third_party_noise.json -> managed_mx_suffixes (add providers there).
_MX_FALLBACK = {"managed_mx_suffixes": [
    "google.com", "googlemail.com", "outlook.com", "protection.outlook.com", "zoho.com",
    "yandex.net", "qq.com", "163.com", "amazonaws.com", "secureserver.net", "cloudflare.com"]}
_MANAGED_MX = tuple(
    load_ref(ref_path(__file__, "third_party_noise.json"), _MX_FALLBACK)["managed_mx_suffixes"])


# --------------------------------------------------------------------------- input detection
def ip_mode_target(src: str):
    """Return the normalized IP if `src` is a bare IP address (v4 or v6), else None.

    Accepts an optional scheme/brackets/zone (e.g. `1.2.3.4`, `[2001:db8::1]`, `ip://1.2.3.4`).
    A hostname or URL with a path returns None — those stay on the domain/HTML flow."""
    if not src:
        return None
    s = src.strip()
    s = re.sub(r"^[a-zA-Z]+://", "", s)          # strip any scheme
    s = s.split("/")[0].strip()                  # drop a path if present
    if s.startswith("[") and s.endswith("]"):    # bracketed IPv6
        s = s[1:-1]
    s = s.split("%")[0]                           # drop an IPv6 zone id
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


# --------------------------------------------------------------------------- IPinfo.io
def _asn_from_org(org: str):
    """('AS13335', 'Cloudflare, Inc.') from an IPinfo `org` string 'AS13335 Cloudflare, Inc.'."""
    if not org:
        return (None, None)
    m = re.match(r"\s*(AS\d+)\s+(.*)$", org.strip())
    if m:
        return (m.group(1), m.group(2).strip() or None)
    return (None, org.strip() or None)


#: Per-process memo. A case re-resolves the SAME addresses on every host — one Cloudflare pair
#: can appear on twenty domains — and IPinfo bills per lookup, so without this a 20-host case
#: buys the same answer twenty times. An address's ASN/country does not change inside one run,
#: so the cache is exact rather than a staleness gamble.
_IPINFO_CACHE: dict[str, dict] = {}


def ipinfo_lookup(ip: str, timeout: int = 15) -> dict:
    """IPinfo.io lookup — keyless (rate-limited) or richer with IPINFO_TOKEN.

    Returns {ip, asn, org_name, hostname, city, region, country, abuse, is_hosting, raw}.
    `hostname` is IPinfo's PTR; `abuse` (email/contact) and `asn`/`company`/`privacy` blocks are
    only populated on token plans — parsed when present, absent-safe otherwise."""
    if ip in _IPINFO_CACHE:
        return _IPINFO_CACHE[ip]
    token = _secret("IPINFO_TOKEN", "IPINFO_API_KEY")
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += "?" + urlencode({"token": token})
    out = {"ip": ip}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA,
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:
        if api_usage:
            api_usage.record("ipinfo", "lookup", credits=0, query=ip, ok=False)
        return {"ip": ip, "error": str(e)}
    if api_usage:
        api_usage.record("ipinfo", "lookup", credits=1, query=ip)
    out["raw"] = data
    asn, org_name = _asn_from_org(data.get("org", ""))
    # token plans return a structured `asn` block instead of the `org` string
    asn_block = data.get("asn") or {}
    if isinstance(asn_block, dict) and asn_block.get("asn"):
        asn = asn_block.get("asn") or asn
        org_name = asn_block.get("name") or org_name
    comp = data.get("company") or {}
    out.update({
        "asn": asn,
        "org_name": org_name or (comp.get("name") if isinstance(comp, dict) else None),
        "hostname": data.get("hostname"),
        "city": data.get("city"), "region": data.get("region"), "country": data.get("country"),
    })
    ab = data.get("abuse") or {}
    if isinstance(ab, dict) and (ab.get("email") or ab.get("name")):
        out["abuse"] = {k: ab.get(k) for k in ("name", "email", "phone", "address", "network")
                        if ab.get(k)}
    priv = data.get("privacy") or {}
    out["is_hosting"] = bool(priv.get("hosting") or priv.get("relay") or priv.get("proxy")
                             or priv.get("vpn") or priv.get("tor")) if isinstance(priv, dict) else False
    if isinstance(priv, dict):
        # Keep WHICH privacy flag fired, not just the boolean: "hosting" is ordinary for a scam
        # site's server, while vpn/proxy/tor on an address the operator connected FROM is a
        # different statement entirely, and collapsing them loses that.
        out["privacy_flags"] = sorted(k for k in ("hosting", "proxy", "vpn", "tor", "relay")
                                      if priv.get(k))
    _IPINFO_CACHE[ip] = out
    return out


def ip_summary(ip: str) -> str:
    """One human line for an address: `1.2.3.4 · AS13335 Cloudflare (US) · hosting`.

    The domain table, the assessment and the run banner all need the same one-liner; deriving it
    here keeps three renderers from inventing three different formats for the same fact."""
    d = ipinfo_lookup(ip)
    if d.get("error"):
        return f"{ip} · lookup failed"
    bits = [ip]
    who = " ".join(x for x in (d.get("asn"), d.get("org_name")) if x)
    if who:
        bits.append(who + (f" ({d['country']})" if d.get("country") else ""))
    elif d.get("country"):
        bits.append(d["country"])
    if d.get("privacy_flags"):
        bits.append("/".join(d["privacy_flags"]))
    return " · ".join(bits)


# --------------------------------------------------------------------------- DNS (dig / nslookup)
def _dig(name: str, rrtype: str, reverse: bool = False, timeout: int = 8):
    exe = shutil.which("dig")
    if not exe:
        return None
    args = [exe, "+short", "+time=%d" % max(1, timeout // 2), "+tries=1"]
    args += (["-x", name] if reverse else [name, rrtype])
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return None
    # `dig +short TXT` wraps each record in double quotes (`"v=spf1 …"`); strip them so SPF/DMARC
    # prefix matching works (mirrors wp_net's _txt_records). Without this, mail.spf/mail.dmarc are
    # silently None on every IPPivot run.
    return [ln.strip().strip('"').rstrip(".") for ln in out.splitlines() if ln.strip()]


def _nslookup(name: str, rrtype: str, reverse: bool = False, timeout: int = 8):
    exe = shutil.which("nslookup")
    if not exe:
        return None
    args = [exe] + ([] if reverse else ["-type=%s" % rrtype]) + [name]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return None
    vals = []
    for ln in out.splitlines():
        low = ln.lower()
        if reverse and "name =" in low:
            vals.append(ln.split("=", 1)[1].strip().rstrip("."))
        elif rrtype == "MX" and "mail exchanger" in low:
            vals.append(ln.split("=", 1)[1].strip().rstrip("."))
        elif rrtype == "NS" and "nameserver" in low:
            vals.append(ln.split("=", 1)[1].strip().rstrip("."))
        elif rrtype == "TXT" and "text =" in low:
            vals.append(ln.split("=", 1)[1].strip().strip('"'))
    return vals or None


def dns_records(name: str, types=("A", "AAAA", "MX", "NS", "TXT", "SOA")) -> dict:
    """Resolve `name`'s DNS records via `dig` (preferred) or `nslookup` fallback.

    Returns {rrtype: [values]} for the non-empty types only. Recursive-resolver queries — passive,
    never a connection to any target host."""
    recs = {}
    for t in types:
        vals = _dig(name, t) or _nslookup(name, t)
        if vals:
            recs[t] = uniq(vals)
    return recs


def reverse_dns(ip: str, timeout: int = 8):
    """PTR (reverse-DNS) hostname for an IP — dig -x, then socket.gethostbyaddr."""
    vals = _dig(ip, "PTR", reverse=True, timeout=timeout) or _nslookup(ip, "PTR", reverse=True,
                                                                       timeout=timeout)
    if vals:
        return vals[0]
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def mail_intel(name: str, txt_records=None) -> dict:
    """Mail posture for a name: MX servers, the registrable domains they live on, and SPF/DMARC.

    Returns {mx:[...], mail_domains:[...], managed:bool, spf:str|None, dmarc:str|None}. `managed`
    is True when every MX belongs to a shared mail provider (Google/Microsoft/…): that's noise, not
    an operator pivot; a self-hosted MX on the operator's own domain is the pivotable case."""
    mx = dns_records(name, ("MX",)).get("MX", [])
    hosts = [re.sub(r"^\d+\s+", "", m).strip().rstrip(".") for m in mx]     # strip MX priority
    hosts = [h for h in hosts if h]
    mail_domains = uniq([_registrable(h) for h in hosts if _registrable(h)])
    managed = bool(hosts) and all(h.endswith(_MANAGED_MX) for h in hosts)
    txt = txt_records if txt_records is not None else dns_records(name, ("TXT",)).get("TXT", [])
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc_txt = dns_records("_dmarc." + name, ("TXT",)).get("TXT", []) if name else []
    dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), None)
    return {"mx": hosts, "mail_domains": mail_domains, "managed": managed,
            "spf": spf, "dmarc": dmarc}


# --------------------------------------------------------------------------- FOFA / Shodan (ports)
def fofa_ip(ip: str, full: bool = False) -> dict:
    """FOFA `ip="<ip>"` → {ports:[...], services:[...], co_domains:[...], misconfig:[...], total, error?}.

    Passive: reads FOFA's index of what was last seen on the IP — no packet to the target. Aggregates
    open ports, service fingerprints (protocol/server), and co-hosted domains (same-operator leads).
    Requests the `banner` field so `scan_misconfig` can flag an internal-IP leak or an anonymous-FTP
    service on the box (a FOFA tier that does not return `banner` simply yields an empty misconfig
    list, never an error here). None if no FOFA key is configured."""
    res = fofa_search(f'ip="{ip}"', size=200,
                      fields="ip,port,protocol,host,domain,title,server,banner", full=full)
    if res is None:
        return None
    if res.get("error"):
        return {"error": res["error"], "query": res.get("query")}
    ports, services, co = set(), set(), set()
    for row in res.get("results", []):
        if row.get("port"):
            ports.add(str(row["port"]))
        svc = "/".join(x for x in (row.get("protocol"), row.get("server")) if x)
        if svc:
            services.add(svc)
        d = (row.get("domain") or "").strip()
        if d and not d.replace(".", "").isdigit():
            co.add(d)
    return {"query": res.get("query"), "total": res.get("total"),
            "ports": sorted(ports, key=lambda p: int(p) if p.isdigit() else 0),
            "services": sorted(services), "co_domains": sorted(co)[:80],
            "misconfig": scan_misconfig(res.get("results", []), self_ip=ip)}


def shodan_host(ip: str, timeout: int = 20) -> dict:
    """Shodan host lookup → {ports:[...], services:[...], hostnames:[...], org, asn}. Only when
    SHODAN_KEY is set (Shodan has no keyless host API). Passive index read. None without a key."""
    key = _secret("SHODAN_KEY", "SHODAN_API_KEY")
    if not key:
        return None
    url = f"https://api.shodan.io/shodan/host/{ip}?" + urlencode({"key": key})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:
        if api_usage:
            api_usage.record("shodan", "host", credits=0, query=ip, ok=False)
        return {"error": str(e)}
    if api_usage:
        api_usage.record("shodan", "host", credits=1, query=ip)
    services = uniq([d.get("product") for d in data.get("data", []) if d.get("product")])
    return {"ports": sorted(map(str, data.get("ports", []))), "services": services,
            "hostnames": data.get("hostnames", []), "org": data.get("org"),
            "asn": data.get("asn")}


# --------------------------------------------------------------------------- ASN registry (refs)
def asn_registry_load(path=None) -> dict:
    try:
        with open(path or _ASN_REGISTRY, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"_meta": {"note": "known hosting/CDN ASNs -> generic provider facts (no case data)"},
                "asns": {}}


def asn_registry_upsert(asn: str, name=None, abuse=None, noise=None, kind=None, path=None,
                        reg=None) -> dict:
    """Bank GENERIC provider facts for an ASN so later runs can enrich/skip it.

    Records ONLY provider-level metadata (asn, org name, abuse contact(s), noise flag, kind) — NEVER
    a target IP, domain, or case id (repo CLAUDE.md RULE 1). Merges into an existing entry. Pass the
    already-loaded `reg` to avoid a redundant re-read. Returns the (updated) entry."""
    path = path or _ASN_REGISTRY
    reg = reg if reg is not None else asn_registry_load(path)
    asns = reg.setdefault("asns", {})
    e = asns.setdefault(asn, {"asn": asn})
    if name and not e.get("name"):
        e["name"] = name
    if kind:
        e["kind"] = kind
    if noise is not None:
        e["noise"] = bool(noise)
    if abuse:
        contacts = set(e.get("abuse_contacts") or [])
        contacts.update([a for a in (abuse if isinstance(abuse, (list, set)) else [abuse]) if a])
        if contacts:
            e["abuse_contacts"] = sorted(contacts)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(reg, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception:
        pass
    return e


# Above this many sites on one IP, a reverse-IP returns unrelated tenants — the IP is a shared
# host / load balancer (CF, AWS ELB, cPanel reseller…), not a same-operator origin. A dedicated
# operator box is well under this even for a prolific actor.
SHARED_TENANT_MAX = 200


def is_noise_provider(classified: dict, ipinfo: dict, registry: dict, tenant_total=None):
    """(is_noise, reason) — an IP whose reverse-search returns unrelated tenants, so it is NOT a
    same-operator origin. Noise when: classify_ip says CDN/cloud edge; the ASN is flagged noise in
    the registry (AWS/GCP/Azure/DO/OVH/…); IPinfo flags hosting/relay; OR many sites resolve to it
    (shared host / load balancer). The last check is provider-agnostic — it catches an AWS ELB or a
    shared cPanel box even when the range/ASN isn't in our lists."""
    if classified.get("cdn") is True:
        return True, "CDN/cloud edge (%s) — shared, reverse-IP returns unrelated tenants" % (
            classified.get("provider") or "shared edge")
    asn = ipinfo.get("asn")
    entry = (registry.get("asns") or {}).get(asn or "", {})
    if entry.get("noise"):
        return True, "ASN %s flagged noise in asn_registry (%s)" % (asn, entry.get("name") or "")
    if ipinfo.get("is_hosting"):
        return True, "IPinfo flags hosting/relay infrastructure (%s)" % (ipinfo.get("org_name") or "")
    if tenant_total and tenant_total > SHARED_TENANT_MAX:
        return True, ("~%d sites resolve to this IP — shared host / load balancer, not a "
                      "same-operator origin" % tenant_total)
    return False, ""


# --------------------------------------------------------------------------- assemble result
def _distinctive_ptr(ptr: str, ip: str) -> bool:
    """A PTR worth a pivot: not the provider's default reverse (which usually embeds the IP octets
    or a generic cloud suffix). e.g. `mail.operator.example` is distinctive; `1-2-3-4.provider.net`
    is not."""
    if not ptr:
        return False
    octets = ip.replace(".", "-"), ip.replace(".", ""), ip
    low = ptr.lower()
    if any(o in low for o in octets):
        return False
    return True


def build_ip_result(ip: str, args=None, fofa_full: bool = False, free_only: bool = False) -> dict:
    """Run the full passive IP recon and return a WebPivot-shaped result: {meta, artifacts, pivots}.

    The result flows through the SAME pivot_extract output path (JSON / --leads / --report /
    --master) as a domain run, so IP and domain evidence land in one case with one schema."""
    case = getattr(args, "case", None)

    # The four sources are independent network I/O — run them concurrently (bound wall-clock to the
    # slowest, not the sum), mirroring wp_analyze.enrich_live. reverse_dns→mail_intel is one branch
    # because mail is keyed on the PTR's registrable domain (self-hosted infra), when present.
    def _rev_mail():
        p = reverse_dns(ip)
        pr = _registrable(p) if p else None
        return p, (mail_intel(pr) if pr else None)

    jobs = {"ipinfo": lambda: ipinfo_lookup(ip), "fofa": lambda: fofa_ip(ip, full=fofa_full),
            "shodan": lambda: shodan_host(ip), "revmail": _rev_mail}
    # Censys host lookup — 1 credit, and the ONE Censys endpoint a free plan can call. It adds the
    # forward+reverse DNS names Censys resolved for the IP (co-hosted hostnames FOFA/Shodan miss)
    # and the per-service cert fingerprints. Metered, so --free-only skips it like FOFA.
    if censys_configured() and not free_only:
        jobs["censys"] = lambda: censys_host(ip)
    if wp_validin.validin_configured() and wp_validin.ENABLED:
        jobs["validin"] = lambda: wp_validin.ip_lookup(ip)   # FREE reverse-IP -> co-hosted domains
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {k: ex.submit(fn) for k, fn in jobs.items()}
        res = {k: fu.result() for k, fu in futs.items()}
    ipinfo, fofa, shodan = res["ipinfo"], res["fofa"], res["shodan"]
    censys = res.get("censys") if isinstance(res.get("censys"), dict) else {}
    validin = res.get("validin") if isinstance(res.get("validin"), dict) else {}
    # a skipped/errored Censys call is still recorded (the analyst must see WHY), but must not
    # contribute names or ports as if it had answered
    cen_ok = censys and not censys.get("error") and not censys.get("skipped")
    ptr, mail = res["revmail"]
    ptr_reg = _registrable(ptr) if ptr else None
    classified = classify_ip(ip)                    # local (cached CDN ranges) — no network
    registry = asn_registry_load()
    noise, noise_reason = is_noise_provider(classified, ipinfo, registry,
                                            tenant_total=(fofa or {}).get("total"))

    f, s = fofa or {}, shodan or {}
    c = censys if cen_ok else {}
    ports = sorted(set(f.get("ports", []) + s.get("ports", []) + c.get("ports", [])),
                   key=lambda p: int(p) if str(p).isdigit() else 0)
    services = uniq(f.get("services", []) + s.get("services", [])
                    + [p for svc in c.get("services", []) for p in svc.get("software", [])])
    co_domains = uniq(f.get("co_domains", []) + s.get("hostnames", []) + c.get("dns_names", [])
                      + (validin.get("domains") or []))

    artifacts = {"ip_intel": {
        "ipinfo": {k: ipinfo.get(k) for k in
                   ("asn", "org_name", "hostname", "country", "abuse", "is_hosting") if ipinfo.get(k)},
        "classification": classified, "ptr": ptr,
        "ports": ports, "services": services, "co_hosted_domains": co_domains,
        "mail": mail, "noise": noise, "noise_reason": noise_reason,
    }}
    if censys:
        artifacts["ip_intel"]["censys"] = censys
    if validin:
        artifacts["ip_intel"]["validin"] = validin
    result = {"meta": {"host": ip, "final_url": ip, "kind": "ip",
                       "source": "IPPivot", "case": case},
              "artifacts": artifacts, "pivots": []}
    pivots = result["pivots"]

    def add(kind, value, confidence, queries, note="", live=None):
        p = {"kind": kind, "value": value, "confidence": confidence, "note": note,
             "queries": queries}
        if live is not None:
            p["live_results"] = live
        pivots.append(p)

    asn = ipinfo.get("asn")
    org = ipinfo.get("org_name")
    _abuse = (ipinfo.get("abuse") or {}).get("email")
    abuse_emails = [_abuse] if _abuse else []

    if noise:
        # Not an operator pivot — record as INFORMATION and bank the provider for later enrichment.
        if asn:
            asn_registry_upsert(asn, name=org, abuse=abuse_emails, noise=True,
                                kind=(classified.get("kind") or "hosting"), reg=registry)
        add("ip:information", ip, "information", [
            {"service": "IPinfo", "query": f"https://ipinfo.io/{ip}"},
            {"service": "note", "query": noise_reason},
        ], f"IP on a NOISE provider — not a same-operator pivot. {noise_reason}. Provider "
           f"{asn or ''} {org or ''} banked to asn_registry for enrichment.")
    else:
        # Origin candidate — the FOFA/reverse-IP co-tenants ARE same-operator leads.
        add("ip", ip, "high", [
            {"service": "FOFA", "query": f'ip="{ip}"'},
            {"service": "Validin / DNSlytics reverse-IP", "query": ip},
            {"service": "urlscan.io", "query": f"ip:{ip}"},
            {"service": "Shodan", "query": f"ip:{ip}" if not shodan else f"https://www.shodan.io/host/{ip}"},
            {"service": "Censys (lookup — free plan)",
             "query": f"python3 wp_censys.py host {ip}"},
        ] + censys_queries("ip", ip),
           "Origin-candidate IP (not a shared CDN/cloud edge). Domains co-hosted here are strong "
           "same-operator leads — reverse it and pull the co-tenants.",
           live={"co_hosted_domains": co_domains} if co_domains else None)

    # ASN / abuse — always informational (also the enrichment hook for takedown contact)
    if asn or org:
        add("ip:asn", f"{asn or ''} {org or ''}".strip(), "information", [
            {"service": "bgp.he.net", "query": f"https://bgp.he.net/{asn}" if asn else org},
            {"service": "IPinfo", "query": f"https://ipinfo.io/{ip}"},
        ] + ([{"service": "abuse contact", "query": e} for e in abuse_emails]),
           "Hosting ASN / org (and abuse contact when known) — provenance + takedown routing; "
           "banked to asn_registry.")

    if ports:
        add("ip:ports", ", ".join(ports), "information", [
            {"service": "FOFA", "query": f'ip="{ip}"'},
        ] + ([{"service": "Shodan", "query": f"https://www.shodan.io/host/{ip}"}] if shodan else []),
           f"Open ports / services seen on the IP: {', '.join(services) if services else 'n/a'}. "
           f"An unusual admin/panel port or a distinctive banner narrows the operator.")

    # Misconfiguration triage — a leaked internal address (dual-homed box exposing its topology) or
    # an anonymous-FTP service, read PASSIVELY from the FOFA index. Emitted as a MEDIUM lead, never
    # fetched: connecting to the box's FTP is active + attributable and victim data has handling
    # implications (see references/misconfig_signals.json). A distinct signal from co-tenancy — it
    # says the box is operator-run and sloppy, and can hand you the real origin / internal map.
    misconfig = (fofa or {}).get("misconfig") or []
    if misconfig:
        artifacts["ip_intel"]["misconfig"] = misconfig
        leaks = sorted({f"{m['address']} ({m['leak_class']})"
                        for m in misconfig if m["type"] == "internal_ip_leak"})
        anon_ports = sorted({m.get("port") or "21"
                             for m in misconfig if m["type"] == "anon_ftp"})
        parts = []
        if leaks:
            parts.append("internal address(es) leaked into the public banner: " + ", ".join(leaks))
        if anon_ports:
            parts.append("ANONYMOUS FTP accepted on port(s) " + ", ".join(anon_ports))
        add("ip:misconfig", "; ".join(parts), "medium", [
            {"service": "FOFA", "query": f'ip="{ip}"'},
            {"service": "note", "query": "PASSIVE flag — do NOT auto-connect (see note)"},
        ], "Misconfiguration triage lead on this box, read passively from the index (no packet "
           "sent). " + ". ".join(parts) + ". A leaked RFC1918/loopback address means the box is "
           "dual-homed and exposing internal topology — pivot the leaked host or redirect for the "
           "real origin / internal service map, and it marks the asset as operator-run and sloppy "
           "(a CDN edge never leaks this). Anonymous FTP can hold the phishing kit, uploaded victim "
           "logs or builder configs and is HIGH-value — but CONNECTING is active + attributable (it "
           "tells the operator they are being examined) and victim data carries handling/legal "
           "implications: a human decides that step, the tool never auto-connects.")

    # Censys saw the leaf certificate(s) this IP actually serves — the strongest artifact an IP
    # run can yield, because the same cert on a DIFFERENT IP is a same-operator link that survives
    # the domain rotation the whole IP layer is trying to see through. Free-plan reachable: the
    # certificate LOOKUP resolves the fingerprint to its full hostname list, no search entitlement.
    for fp in ((censys.get("cert_fingerprints") or [])[:5] if cen_ok else []):
        add("tls_cert:fingerprint_sha256", fp, "high", [
            {"service": "Censys (lookup — free plan)", "query": f"python3 wp_censys.py cert {fp}"},
            {"service": "crt.sh", "query": f"https://crt.sh/?q={fp}"},
        ] + censys_queries("tls_cert:fingerprint_sha256", fp),
           f"Leaf certificate served on {ip} (seen by Censys). Every other host serving this exact "
           f"cert is the same operator/deployment; the Censys certificate lookup returns the cert's "
           f"own full hostname list.")

    if ptr and _distinctive_ptr(ptr, ip):
        add("ip:ptr", ptr, "medium", [
            {"service": "FOFA", "query": f'host="{ptr}"'},
            {"service": "crt.sh", "query": f"%.{ptr_reg}" if ptr_reg else ptr},
            {"service": "search engine", "query": f'"{ptr}"'},
        ], "Distinctive reverse-DNS (PTR) name — a self-chosen hostname, not the provider default; "
           "pivot its registrable domain.")

    if mail and mail.get("mx") and not mail.get("managed"):
        add("ip:mx", ", ".join(mail["mx"]), "medium", [
            {"service": "crt.sh (mail domain)", "query": ", ".join(f"%.{d}" for d in mail["mail_domains"])},
            {"service": "search engine", "query": ", ".join(f'"{h}"' for h in mail["mx"])},
        ], f"Self-hosted mail: MX {', '.join(mail['mx'])} on {', '.join(mail['mail_domains'])}. "
           f"Not a managed provider — the mail domain is an operator asset."
           + (f" SPF: {mail['spf']}" if mail.get("spf") else ""))

    from wp_pivots import sort_pivots
    return {"meta": result["meta"], "artifacts": artifacts,
            "pivots": sort_pivots(attach_hunterhow_queries(attach_intelx_queries(attach_censys_queries(pivots))))}


__all__ = ["ip_mode_target", "ipinfo_lookup", "dns_records", "reverse_dns", "mail_intel",
           "fofa_ip", "shodan_host", "asn_registry_load", "asn_registry_upsert",
           "is_noise_provider", "build_ip_result"]
