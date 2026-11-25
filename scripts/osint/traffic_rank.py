#!/usr/bin/env python3
"""traffic_rank.py — popularity rank for a domain, and what a rank actually tells you.

Backs /traffic. SKILL.md promised "traffic estimation, ranking, audience data". Estimation and
audience demographics come only from paid panels (SimilarWeb, Semrush) and their numbers for
low-traffic domains are modelled guesses, not measurements — reporting them as fact about a scam
site would be inventing evidence. So this returns the figures that are free and real: the Tranco
rank and, when asked for, the NetAPI Top 1M rank, two aggregated top-1M lists (how they relate is
below).

THE ANALYTIC POINT IS USUALLY THE ABSENCE. A funnel domain that has been "operating for years"
according to its own copy, and is unranked in a 1M-entry list, is contradicting itself. That
inference is what this supports. A domain ranked in one list and absent from the other is a
borderline case, not a contradiction.

THE TWO LISTS ARE NOT INDEPENDENT. Tranco averages five provider lists (Cisco Umbrella, Majestic,
Farsight, CrUX, Cloudflare Radar) over the past 30 days with the Dowdall rule. The NetAPI Top 1M
is rebuilt every day from the Majestic Million link-graph ranking, DNS query popularity and CrUX,
merged with reciprocal rank fusion, reduced to registrable domains, with domains registered less
than 30 days ago dropped (https://netapi.com/top-1-mln-websites/). Their inputs overlap, so
"absent from both" is one finding read twice, not two confirmations. What the second list does
add: a daily snapshot next to a 30-day average (a site that rose or fell this month shows in one
before the other), a different aggregation, and an answer when the other API is rate-limited.

THE NETAPI LOOKUP IS OPT-IN. /traffic fires for every Domain and Org target, and each lookup
sends the domain under investigation to a third party. Tranco is queried as before; NetAPI only
with --netapi (or CTI_TRAFFIC_NETAPI=1 for a session), otherwise its row reads "not consulted".

THE LOOKUP IS THE REGISTRABLE DOMAIN. Both lists hold registrable domains, so www.example.com or
shop.example.com is looked up as example.com, and both names are reported ("www" in front of a
public suffix, www.co.uk, is the registrable label and stays). A platform from the PSL's private
section (github.io, blogspot.com) is a domain both lists rank and is looked up. A site on such a
platform (user.github.io) is not: the lists rank the platform as a whole, never its tenants. Nor is
an input that is not a domain name (no known TLD, a public suffix, an IP address, an IDN the stdlib
IDNA 2003 codec would map to another name): Tranco answers such a query with an empty list, which
would read as "unranked".

ONLY A WELL-FORMED ANSWER COUNTS. A response that is not the documented shape (an error object,
a missing or mistyped field, a body that is not a JSON object, a top-1M rank above one million) is
reported as "unavailable (...)", never as "unranked": a malformed 200 is absence of collection,
not evidence of absence. What each service answers for a name it cannot use: NetAPI, HTTP 400 with
{"error": {"code": "invalid_domain"}}; Tranco, HTTP 200 with {"ranks": []}, hence the check above.

A TRANCO RANK CAN BE ABOVE ONE MILLION. The Tranco API ranks the full list, so a rank such as
3,704,275 is kept and reported as outside the top 1M: the domain is measured, and less popular than
every top-1M domain.

Keyless. Passive — Tranco and NetAPI are queried, never the target.

Usage:
  traffic_rank.py example.com
  traffic_rank.py a.example b.example --netapi --pretty
"""
# /// script
# requires-python = ">=3.9"
# ///
import argparse
import ipaddress
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

_WP = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                                    "intel_engine", "WebPivot", "tools"))
if _WP not in sys.path:
    sys.path.append(_WP)
from wp_ua import DEFAULT_UA as UA  # noqa: E402 — the one User-Agent source (Android Chrome)
import wp_http  # noqa: E402 — the one transport
from wp_common import (  # noqa: E402 — the one PSL
    _PSL_PRIVATE, _PSL_WILD, _registrable, has_known_tld, public_suffix, strip_www)

TOP_N = 1_000_000
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _get(url, timeout=20):
    r = wp_http.request(url, timeout=timeout, bounded=True)
    if r.status is None:
        return None, r.error.split(":", 1)[0]
    if not r.ok:
        # An error answer names its reason: NetAPI's 400 carries {"error": {"code": ...}}.
        try:
            e = json.loads(r.body).get("error")
            code = e.get("code") if isinstance(e, dict) else e
            if isinstance(code, str) and code:
                return None, f"HTTP {r.status} {code}"
        except Exception:  # noqa: BLE001
            pass
        return None, f"HTTP {r.status}"
    try:
        return json.loads(r.body), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def _malformed(why):
    """A 200 that is not the documented shape: absence of collection, never "unranked"."""
    return {"status": f"unavailable (malformed response: {why})"}


def _error_body(d):
    """A 200 whose body carries an error: absence of collection, never "unranked"."""
    e = d.get("error")
    if isinstance(e, dict):
        e = e.get("code") or e.get("message") or "error object"
    return {"status": f"unavailable (error in the response: {e})"}


def _is_rank(v):
    """A list position: a real integer >= 1 (bool is an int subclass in Python and is refused)."""
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def _date(v):
    return v if isinstance(v, str) and v else None


def lookup_name(raw):
    """(host as given, registrable domain to look up, None) or (host, None, why it is not one)."""
    host = (raw or "").strip().lower()
    # The authority only: no scheme, path, query or fragment (a fragment can hold an "@"),
    # then no userinfo.
    host = re.split(r"[/?#]", re.sub(r"^[a-z][a-z0-9+.-]*://", "", host), maxsplit=1)[0]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):                       # [IPv6] or [IPv6]:port
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:                     # host:port; a bare IPv6 has several colons
        host = host.split(":")[0]
    host = host.rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host, None, "an IP address, not a domain name"
    except ValueError:
        pass
    if host and not host.isascii():
        # The stdlib codec is IDNA 2003, as in wp_common: it maps some characters to others
        # (ß -> ss), which is another domain. Such a name is refused, not looked up as that one.
        try:
            ace = host.encode("idna").decode("ascii")
            if ace.encode("ascii").decode("idna") != unicodedata.normalize("NFC", host):
                return host, None, "an IDN that IDNA 2003 maps to another name"
        except UnicodeError:
            return host, None, "not a valid domain name"
        host = ace
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(p) for p in labels) or not has_known_tld(host):
        return host, None, "not a domain name with a known TLD"
    # The PSL helpers drop a leading "www." before they look, so "bare" is what they saw.
    bare = strip_www(host)
    suffix = public_suffix(host)
    if bare == suffix:
        if suffix in _PSL_PRIVATE:
            # A platform from the PSL's private section (github.io, blogspot.com, pages.dev) is a
            # domain both lists rank: look the platform up.
            return host, suffix, None
        if bare != host:
            # "www" in front of an ICANN suffix (www.co.uk, www.com, www.ck) is the registrable
            # label, not a subdomain.
            return host, host, None
        return host, None, "a public suffix, not a registrable domain"
    parent = suffix.partition(".")[2]          # the parent of a wildcard rule's suffix
    if suffix in _PSL_PRIVATE or (parent in _PSL_WILD and parent in _PSL_PRIVATE):
        # Both lists rank the platform (github.io), never a site on it (user.github.io): its rank
        # would be the platform's, and "unranked" would say nothing about the site.
        return host, None, f"a site on the shared platform {suffix}, which the lists rank as a whole"
    return host, _registrable(host) or host, None


def tranco(domain):
    d, err = _get("https://tranco-list.eu/api/ranks/domain/" + urllib.parse.quote(domain))
    if err:
        return {"status": f"unavailable ({err})"}
    if not isinstance(d, dict):
        return _malformed("not a JSON object")
    if "error" in d:
        return _error_body(d)
    ranks = d.get("ranks")
    if not isinstance(ranks, list):
        return _malformed('no "ranks" list')
    if not ranks:
        return {"status": "ok", "ranked": False, "in_top_1m": False, "latest_rank": None,
                "meaning": ("not in the Tranco list. The list covers roughly the top 1M domains, "
                            "so this means low or no measurable popularity — NOT that the domain "
                            "is malicious, and not that it has no visitors.")}
    hist = []
    for r in ranks[:10]:
        if not isinstance(r, dict) or not _is_rank(r.get("rank")):
            return _malformed('a "ranks" entry without an integer rank >= 1')
        hist.append({"date": _date(r.get("date")), "rank": r["rank"]})
    latest = hist[0]["rank"]
    if latest > TOP_N:
        return {"status": "ok", "ranked": True, "in_top_1m": False, "latest_rank": latest,
                "latest_date": hist[0]["date"], "history": hist,
                "meaning": (f"in the full Tranco list at #{latest:,}, outside the top 1M: "
                            "measured, but less popular than every top-1M domain")}
    return {"status": "ok", "ranked": True, "in_top_1m": True, "latest_rank": latest,
            "latest_date": hist[0]["date"], "history": hist,
            "meaning": "present in the Tranco top-1M; lower number = more popular"}


def netapi(domain):
    d, err = _get("https://netapi.com/api-json/?method=domain-rank&domain=" + urllib.parse.quote(domain))
    if err:
        return {"status": f"unavailable ({err})"}
    if not isinstance(d, dict):
        return _malformed("not a JSON object")
    if "error" in d:
        return _error_body(d)
    listed = d.get("in_top_1m")
    if not isinstance(listed, bool):
        return _malformed('no boolean "in_top_1m"')
    if not listed:
        if d.get("rank") is not None:
            return _malformed('"in_top_1m" is false but a rank is given')
        return {"status": "ok", "ranked": False, "in_top_1m": False, "latest_rank": None,
                "latest_date": _date(d.get("snapshot_date")),
                "meaning": ("not in the NetAPI Top 1M. Same reading as an unranked Tranco result: "
                            "low or no measurable popularity, NOT maliciousness.")}
    if not _is_rank(d.get("rank")):
        return _malformed('"in_top_1m" is true without an integer rank >= 1')
    if d["rank"] > TOP_N:
        return _malformed('"in_top_1m" is true with a rank above 1,000,000')
    return {"status": "ok", "ranked": True, "in_top_1m": True, "latest_rank": d["rank"],
            "latest_date": _date(d.get("snapshot_date")),
            "meaning": "present in the NetAPI Top 1M, rebuilt daily. Lower number = more popular"}


NETAPI_OFF = {"status": "not consulted",
              "why": ("the lookup sends the domain to netapi.com; run with --netapi "
                      "(or CTI_TRAFFIC_NETAPI=1) to consult the NetAPI Top 1M")}


def main():
    ap = argparse.ArgumentParser(description="Free popularity ranks (Tranco, NetAPI Top 1M) for a domain.")
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--netapi", action="store_true",
                    help="also look the domain up in the NetAPI Top 1M (sends it to netapi.com)")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    use_netapi = (a.netapi or
                  os.environ.get("CTI_TRAFFIC_NETAPI", "").strip().lower() in ("1", "true", "yes"))

    rows = []
    for raw in a.domains:
        host, dom, why = lookup_name(raw)
        if dom is None:
            # Not looked up anywhere, whatever the switch: one reason for both rows.
            skipped = {"status": f"not collected ({why})"}
            rows.append({"queried": host, "domain": None, "tranco": skipped, "netapi": dict(skipped)})
            print(f"{host}: NOT LOOKED UP ({why})", file=sys.stderr)
            continue
        t = tranco(dom)
        n = netapi(dom) if use_netapi else NETAPI_OFF
        rows.append({"queried": host, "domain": dom, "tranco": t, "netapi": n})
        shown = dom if dom == host else f"{dom} (for {host})"
        for name, r in (("Tranco", t), ("NetAPI", n)):
            when = r.get("latest_date") or "date not given"
            if r.get("status") == "not consulted":
                print(f"{shown}: {name} not consulted (--netapi or CTI_TRAFFIC_NETAPI=1 to ask)",
                      file=sys.stderr)
            elif r.get("status") != "ok":
                print(f"{shown}: {name} rank {r['status'].replace('unavailable', 'UNAVAILABLE', 1)} — absence of collection", file=sys.stderr)
            elif r.get("in_top_1m"):
                print(f"{shown}: {name} #{r['latest_rank']:,} ({when})", file=sys.stderr)
            elif r.get("ranked"):
                print(f"{shown}: {name} #{r['latest_rank']:,} ({when}), outside the top 1M", file=sys.stderr)
            else:
                print(f"{shown}: UNRANKED in the {name} top-1M", file=sys.stderr)

    out = {"results": rows,
           "not_collected": {
               "traffic_estimate": "paid panels only (SimilarWeb/Semrush); their low-traffic "
                                   "figures are modelled, not measured — not reported here",
               "audience_demographics": "paid panels only; same reason"}}
    txt = json.dumps(out, indent=2 if a.pretty else None, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
