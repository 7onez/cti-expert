#!/usr/bin/env python3
"""msft_recon.py — M365 / Entra ID tenant recon from a domain, entirely keyless and passive.

Microsoft publishes tenant metadata at unauthenticated endpoints so that clients can discover
where to authenticate. That makes it readable by anyone, and it answers questions that matter in
a fraud investigation: does this company actually run M365 (a shell company usually does not), is
authentication FEDERATED to somewhere else (the federation host is often the real operator's
infrastructure), and which OTHER domains does the same tenant own — that last one is a
same-owner link as strong as a shared registrant.

Every request goes to login.microsoftonline.com, never to the target. The target learns nothing.

Usage:
  msft_recon.py example.com
  msft_recon.py example.com --pretty -o tenant.json
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "cti-expert/msft_recon (OSINT research)"
AUTOD = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"


def _get_json(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def user_realm(domain):
    """NameSpaceType tells you Managed (M365-native), Federated (ADFS/3rd-party IdP) or Unknown."""
    url = ("https://login.microsoftonline.com/getuserrealm.srf?login="
           + urllib.parse.quote(f"user@{domain}") + "&json=1")
    d, err = _get_json(url)
    if err or not d:
        return {"error": err or "no data"}
    return {"namespace_type": d.get("NameSpaceType"), "federation_brand": d.get("FederationBrandName"),
            "cloud_instance": d.get("CloudInstanceName"), "domain_name": d.get("DomainName"),
            "auth_url": d.get("AuthURL"), "federation_protocol": d.get("FederationProtocol")}


def tenant_id(domain):
    url = f"https://login.microsoftonline.com/{urllib.parse.quote(domain)}/.well-known/openid-configuration"
    d, err = _get_json(url)
    if err or not d:
        return {"error": err or "no data"}
    tid = None
    m = re.search(r"/([0-9a-f-]{36})/", d.get("token_endpoint") or "")
    if m:
        tid = m.group(1)
    return {"tenant_id": tid, "issuer": d.get("issuer"),
            "tenant_region_scope": d.get("tenant_region_scope"),
            "token_endpoint": d.get("token_endpoint")}


def tenant_domains(domain, timeout=25):
    """Every domain federated to the same tenant — a same-OWNER link, not merely same-host.

    Uses the unauthenticated Autodiscover GetFederationInformation SOAP call. It is noisy XML but
    it is the only keyless way to enumerate a tenant's other verified domains.
    """
    body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
 xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
 xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">{AUTOD}</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>{domain}</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body></soap:Envelope>"""
    try:
        req = urllib.request.Request(
            AUTOD, data=body.encode(),
            headers={"Content-Type": "text/xml; charset=utf-8", "User-Agent": "AutodiscoverClient",
                     "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
                                   'Autodiscover/GetFederationInformation"'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            xml = r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return {"error": type(e).__name__, "domains": []}
    doms = re.findall(r"<Domain>([^<]+)</Domain>", xml)
    seen, out = set(), []
    for d in doms:
        dl = d.strip().lower()
        if dl and dl not in seen:
            seen.add(dl)
            out.append(dl)
    res = {"domains": out, "count": len(out)}
    # Microsoft restricted this endpoint: as of 2026-08-28 it echoes back only the queried
    # domain instead of the tenant's full verified-domain list. Returning [domain] with no
    # caveat would read as "this tenant owns exactly one domain" — an ABSENCE OF RECORD
    # presented as a finding, which is the specific error this toolkit exists to avoid.
    if len(out) <= 1:
        res["enumeration"] = "RESTRICTED"
        res["caveat"] = ("Autodiscover returned only the queried domain. Microsoft no longer "
                         "discloses a tenant's other verified domains here, so this is NOT "
                         "evidence the tenant owns one domain. To enumerate siblings, pivot on "
                         "the tenant_id via CT logs / reverse-WHOIS instead.")
    else:
        res["enumeration"] = "OK"
    return res


def main():
    ap = argparse.ArgumentParser(description="Keyless M365/Entra tenant recon for a domain.")
    ap.add_argument("domain")
    ap.add_argument("--no-domains", action="store_true", help="skip tenant-domain enumeration")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    dom = a.domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    out = {"domain": dom, "realm": user_realm(dom), "tenant": tenant_id(dom)}
    if not a.no_domains:
        out["tenant_domains"] = tenant_domains(dom)

    realm, tenant = out["realm"], out["tenant"]
    ns = realm.get("namespace_type")
    if tenant.get("tenant_id"):
        out["verdict"] = f"M365 tenant CONFIRMED ({ns or 'unknown namespace'})"
    elif ns in (None, "Unknown"):
        out["verdict"] = ("no M365 tenant — absence of record, NOT evidence the company is fake; "
                          "plenty of real businesses run Google Workspace or self-hosted mail")
    else:
        out["verdict"] = f"namespace {ns} but no tenant id resolved"
    if ns == "Federated":
        out["note"] = ("authentication is FEDERATED — the auth_url host is third-party or "
                       "operator-run infrastructure and is itself a pivot")

    print(f"{dom}: {out['verdict']}"
          + (f"; {out.get('tenant_domains', {}).get('count', 0)} tenant domain(s)"
             if not a.no_domains else ""), file=sys.stderr)
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
