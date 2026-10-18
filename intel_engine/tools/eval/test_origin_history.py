#!/usr/bin/env python3
"""Offline gate for the historical ORIGIN-IP sweep (WebPivot/tools/wp_origin_history.py) and its
consumers: the frontier (ips_pending / previous-owner leads / per-host cap / leaf anchor), the IP-raw
co-tenant miner (stale-tenancy hold, shared-hosting guard, PTR as a related lead only), the loop's hop
bookkeeping, propose()'s IP candidates, and the KB ingest rails.

Rails defended (SKILL.md RULE 5 — never name an innocent party):
  * a CDN / WAF / DDoS-protection / parking / non-routable address is never an origin — by CIDR,
    by the ASN the history source named, or by its org name; a VPS ASN ('Akamai Connected Cloud'
    is Linode) is NOT mistaken for the Akamai CDN
  * an address last seen BEFORE the current registration is the previous owner's — never collected
  * a historical/undated origin's CURRENT co-tenants are leads, never seeds, never KB edges
  * a CDN-classified history row vetoes a hosted_on edge another source proposed

All network seams are absent: the CDN index is a fake, every input is synthetic (RFC 5737 / .example).
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ENGINE = os.path.dirname(TOOLS)
for _p in (TOOLS, os.path.join(TOOLS, "kb"), os.path.join(ENGINE, "WebPivot", "tools"), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import case_state as CS  # noqa: E402
import wp_origin_history as OH  # noqa: E402

SEED = "seed.example"
TODAY = datetime.date.today()


def _d(days_ago):
    return (TODAY - datetime.timedelta(days=days_ago)).isoformat()


class _FakeCdn:
    """cdn_ranges stand-in: only 127/8, 10/8 and 192.168/16 are bogons (so RFC 5737 test addresses
    read as routable), 192.0.2.0/24 is a published 'cloudflare' edge range and 203.0.113.0/24 a
    'google_cloud' customer-compute range."""
    EDGE = ipaddress.ip_network("192.0.2.0/24")
    GCE = ipaddress.ip_network("203.0.113.0/24")

    @staticmethod
    def is_bogon(ip):
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"))

    @classmethod
    def classify(cls, ip, idx):
        a = ipaddress.ip_address(ip)
        if a in cls.EDGE:
            return {"ip": ip, "cdn": True, "provider": "cloudflare", "kind": "cdn"}
        if a in cls.GCE:
            return {"ip": ip, "cdn": True, "provider": "google_cloud", "kind": "cloud"}
        return {"ip": ip, "cdn": False, "provider": None, "kind": "origin_candidate"}

    @staticmethod
    def load_ranges(*a, **k):
        return {"fake": True}


def _domain_raw(host, lr, created=None, related_urlscan=None):
    obj = {"meta": {"host": host}, "artifacts": {"whois": {"created": created}} if created else {},
           "pivots": [{"kind": "domain", "value": host, "live_results": lr}]}
    if related_urlscan:
        obj["related_urlscan"] = related_urlscan
    return obj


def _ip_raw(ip, cohosts, ctx=None, ptr=None):
    meta = {"host": ip, "kind": "ip", "source": "IPPivot"}
    if ctx:
        meta["origin_context"] = ctx
    pivots = [{"kind": "ip", "value": ip}]
    if ptr:
        pivots.append({"kind": "ip:ptr", "value": ptr})
    return {"meta": meta, "pivots": pivots,
            "artifacts": {"ip_intel": {"classification": {"ip": ip, "cdn": False, "kind": "origin_candidate"},
                                       "co_hosted_domains": cohosts, "ptr": ptr}}}


def _case(tmp, raws, hops, depth=2, consumed=()):
    cdir = os.path.join(tmp, "cases", "CASE-0001")
    os.makedirs(os.path.join(cdir, "raw"), exist_ok=True)
    for name, obj in raws.items():
        with open(os.path.join(cdir, "raw", f"{name}.json"), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    st = CS.load_state(cdir)
    st["hops"], st["expansion_depth"], st["consumed"] = dict(hops), depth, list(consumed)
    CS.save_state(cdir, st)
    return cdir


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    saved_cdn = OH._cdn
    saved_root, saved_kb, saved_benign = CS.ROOT, CS.KB_DIR, list(CS._BENIGN)
    saved_cs_cdn, saved_cs_idx = CS._cdn, list(CS._CDN_IDX)
    OH._cdn = lambda: (_FakeCdn, {"fake": True})
    CS._cdn = _FakeCdn
    CS._CDN_IDX[:] = [{"fake": True}]
    try:
        # --- 1. classification ------------------------------------------------------------------
        c = OH.classify
        ok(c("192.0.2.10")["status"] == "cdn", "published CDN range → cdn (CIDR wins)")
        ok(c("198.51.100.1", asn=20940)["status"] == "cdn", "edge-only ASN reported by the source (Akamai CDN) → cdn")
        amb = c("198.51.100.2", org="DDoS-Guard Ltd")
        ok(amb["status"] == "ambiguous" and c("198.51.100.2", asn="AS57724")["status"] == "ambiguous",
           "DDoS-Guard (org or ASN) → ambiguous: sells proxying AND servers, collected but held")
        ok(c("198.51.100.2", asn="AS19551")["status"] == "cdn", "Imperva (edge-only ASN) stays cdn")
        ok(c("203.0.113.5")["status"] == "origin", "customer Google Cloud compute range → origin (rented VM)")
        ok(not CS._is_cdn_ip("203.0.113.5") and CS._is_cdn_ip("192.0.2.5"),
           "frontier co-host guard: GCE is NOT an edge (count guard applies), Cloudflare still is")
        ok(c("198.51.100.3", org="Sedo GmbH")["status"] == "parking", "parking farm org → parking")
        ok(c("127.0.0.1")["status"] == "bogon", "registrar 127.0.0.1 answer → bogon")
        ok(c("not-an-ip")["status"] == "invalid", "garbage → invalid")
        ok(c("198.51.100.4", asn="AS20473", org="Vultr")["status"] == "origin", "VPS network → origin")
        ok(c("198.51.100.5", org="Akamai Connected Cloud")["status"] == "origin",
           "'Akamai Connected Cloud' (Linode VPS) is NOT the Akamai CDN — stays an origin")
        ok(c("198.51.100.6", org="Akamai International B.V.")["status"] == "cdn",
           "Akamai CDN legal name with no ASN on the row → cdn")
        ok(c("198.51.100.7", org="Sedona Hosting LLC")["status"] == "origin",
           "whole-word match: 'Sedona' is not the Sedo parking farm")
        _saved = OH._cdn
        OH._cdn = lambda: (_FakeCdn, None)
        ok(c("198.51.100.8")["status"] == "undetermined",
           "no CDN range index → undetermined, never an origin seed")
        OH._cdn = _saved
        ok(not OH.build({"pssl": {"clusterable": False, "all_ips": ["198.51.100.9"]}}, None, SEED)["ips"],
           "a non-clusterable (shared / CDN) passive-SSL cert contributes no history rows")
        ok(OH._overlap({"first_seen": "2024-01-01", "last_seen": "2024-06-30"},
                       {"first_seen": "2024-05-01", "last_seen": "2025-01-01"}) == ("overlapping", "2024-05..2024-06")
           and OH._overlap({"first_seen": "2020-01-01", "last_seen": "2020-02-01"},
                           {"first_seen": "2020-02-11", "last_seen": "2021-01-01"}) == ("disjoint", "gap 10 days")
           and OH._overlap({}, {"first_seen": "2020-01-01", "last_seen": "2020-02-01"})[0] == "undated",
           "tenancy overlap: overlapping / disjoint (gap) / undated")

        # --- 2. build: merge, dates, live flag, urlscan page-domain filter -----------------------
        lr = {"dns": {"ips": ["192.0.2.20"]},
              "pdns": {"records": [{"rrtype": "A", "rdata": "198.51.100.10", "rrname": SEED,
                                    "time_first": "2024-01-01T00:00:00Z", "time_last": _d(20)}]},
              "securitytrails_dns_history": {"eras": [{"ip": "198.51.100.10", "first_seen": "2023-06-01",
                                                       "last_seen": "2024-03-01", "org": "Vultr"}]},
              "webamon_servers": {"servers": [{"ip": "198.51.100.11", "asn": 20940, "asn_name": "Akamai",
                                               "first_seen": "2025-01-01", "last_seen": "2025-02-01"}]},
              "validin": {"dns": [{"rrtype": "CNAME", "rdata": "x.example"}]}}
        rel = {"all_scans": [{"domain": SEED, "ip": "198.51.100.12", "time": _d(400)},
                             {"domain": "loader.example", "ip": "198.51.100.13", "time": _d(10)}]}
        blk = OH.build(lr, {"related_urlscan": rel}, SEED)
        rows = {r["ip"]: r for r in blk["ips"]}
        r10 = rows.get("198.51.100.10") or {}
        ok(r10.get("sources") == ["pdns", "securitytrails_dns_history"] and r10.get("first_seen") == "2023-06-01"
           and r10.get("last_seen") == _d(20), "two sources merge into one row with the widest window")
        ok(rows.get("192.0.2.20", {}).get("live") and rows["192.0.2.20"]["status"] == "cdn",
           "the live CDN edge is recorded as live + cdn")
        ok(rows.get("198.51.100.11", {}).get("status") == "cdn", "Webamon's ASN classifies its row")
        ok("198.51.100.12" in rows and "198.51.100.13" not in rows,
           "urlscan scans count only when the PAGE was this host (a page that loaded it is not hosting)")
        ok(blk["origin_candidates"][0] == "198.51.100.10", "origins rank first, most corroborated first")

        # --- 3. eras ------------------------------------------------------------------------------
        e = OH.era
        ok(e({"live": True}) == "current", "live → current")
        ok(e({"last_seen": "2020-01-01"}, registered_on="2022-05-01") == "previous_owner",
           "last seen before the current registration → previous_owner")
        ok(e({"last_seen": _d(30)}) == "recent" and e({"last_seen": _d(900)}) == "historical",
           "recency window splits recent / historical")
        ok(e({}) == "undated", "no date anywhere → undated")

        with tempfile.TemporaryDirectory() as tmp:
            CS.ROOT, CS.KB_DIR, CS._BENIGN = tmp, os.path.join(tmp, "knowledge"), []
            os.makedirs(CS.KB_DIR, exist_ok=True)
            os.environ["HARNESS_KB"] = CS.KB_DIR

            # --- 4. frontier: pending origin IPs, previous-owner lead, edges dropped, leaf anchor ---
            seed_lr = {"dns": {"ips": ["192.0.2.30"]},
                       "securitytrails_dns_history": {"eras": [
                           {"ip": "198.51.100.40", "first_seen": _d(200), "last_seen": _d(15)},   # recent
                           {"ip": "198.51.100.41", "first_seen": "2023-01-01", "last_seen": "2023-09-01"},  # historical
                           {"ip": "198.51.100.42", "first_seen": "2018-01-01", "last_seen": "2019-01-01"},  # prev owner
                           {"ip": "198.51.100.43", "first_seen": _d(90), "last_seen": _d(60), "org": "Sedo"},
                           {"ip": "127.0.0.1", "first_seen": "2019-06-01", "last_seen": "2019-07-01"}]},
                       "webamon_servers": {"servers": [{"ip": "198.51.100.44", "asn": 19551,
                                                        "first_seen": _d(50), "last_seen": _d(40)}]}}
            leaf_lr = {"securitytrails_dns_history": {"eras": [
                {"ip": "198.51.100.60", "first_seen": _d(100), "last_seen": _d(5)}]}}
            raws = {SEED: _domain_raw(SEED, seed_lr, created="2022-01-01"),
                    "leaf.example": _domain_raw("leaf.example", leaf_lr)}
            cdir = _case(tmp, raws, {SEED: 0, "leaf.example": 2}, depth=2)
            fr = CS.frontier(cdir, max_new=8)
            ok(fr["ips_pending"] == ["198.51.100.40", "198.51.100.41"],
               f"recent then historical origins queued; CDN/WAF/parking/bogon/prev-owner not ({fr['ips_pending']})")
            d40 = fr["origin_ips"].get("198.51.100.40") or {}
            ok(d40.get("era") == "recent" and d40.get("hop") == 0 and d40.get("cotenants") == "seedable",
               "origin detail carries era, the host's hop, and co-tenant seedability")
            ok((fr["origin_ips"].get("198.51.100.41") or {}).get("cotenants", "").startswith("held"),
               "a historical origin's co-tenants are marked held")
            ok(any(l.get("check") == "previous-owner origin IP" and l.get("ip") == "198.51.100.42"
                   for l in fr["co_tenancy_leads"]), "previous-owner era surfaces as a lead, not a seed")
            ok("198.51.100.60" not in fr["ips_pending"], "a LEAF host's origins never widen the estate")
            ok(not set(fr["ips_pending"]) & set(fr["pending"]), "IPs never enter the domain `pending` list")

            # --- 5. loop promotion: the IP inherits its host's hop ---------------------------------
            import intel as INTEL
            hops = {SEED: 0}
            batch = INTEL._promote(fr, hops, 2)
            ok("198.51.100.40" in batch and hops.get("198.51.100.40") == 0,
               "_promote batches origin IPs at the host's hop (an attribute of the host)")

            # --- 6. propose(): free IP collect candidates ------------------------------------------
            import test_propose
            restore_pivot_routes = test_propose._install_pivot_routes_stub()
            try:
                cands = [x for x in CS.propose(cdir, probe=False) if x.type == "ip" and x.tool == "collect"]
            finally:
                restore_pivot_routes()
            ok({x.selector for x in cands} == {"198.51.100.40", "198.51.100.41"}
               and all(not x.metered and x.est_hits == 1 and x.rung == "kit" for x in cands),
               "propose(): one free, kit-rung IP collect per pending origin")

            # --- 7. per-host cap + case-wide round cap ----------------------------------------------
            many = {"securitytrails_dns_history": {"eras": [
                {"ip": f"198.51.100.{100 + i}", "first_seen": _d(60), "last_seen": _d(10 + i)} for i in range(12)]}}
            cdir2 = _case(os.path.join(tmp, "b"), {SEED: _domain_raw(SEED, many)}, {SEED: 0})
            fr2 = CS.frontier(cdir2, max_new=8)
            ok(len(fr2["ips_pending"]) == min(OH.MAX_IPS_PER_HOST, OH.MAX_IP_SEEDS_PER_ROUND)
               and fr2["ips_pending"][0] == "198.51.100.100",
               f"per-host cap keeps the most recent {OH.MAX_IPS_PER_HOST} ({len(fr2['ips_pending'])})")

            # --- 8. collected origin IP raws: co-tenant mining rails -------------------------------
            ctx_recent = {"hosts": [SEED], "era": "recent", "stale": False, "last_seen": _d(15)}
            ctx_stale = {"hosts": [SEED], "era": "historical", "stale": True, "last_seen": "2023-09-01"}
            raws3 = {SEED: _domain_raw(SEED, seed_lr, created="2022-01-01"),
                     "198.51.100.40": _ip_raw("198.51.100.40", ["sib-one.example", "sib-two.example"],
                                              ctx_recent, ptr="box.opsdomain.example"),
                     "198.51.100.41": _ip_raw("198.51.100.41", ["later-tenant.example"], ctx_stale),
                     "198.51.100.45": _ip_raw("198.51.100.45",
                                              [f"t{i}.example" for i in range(CS.MAX_IP_COHOSTS + 3)], ctx_recent)}
            hops3 = {SEED: 0, "198.51.100.40": 0, "198.51.100.41": 0, "198.51.100.45": 0}
            cdir3 = _case(os.path.join(tmp, "c"), raws3, hops3)
            fr3 = CS.frontier(cdir3, max_new=0)
            cands3 = fr3["candidates"]
            ok("sib-one.example" in cands3 and "ip_cohost" in cands3["sib-one.example"]["sources"],
               "recent origin's co-tenants seed through the co-host route (neighbour rung)")
            ok("later-tenant.example" not in cands3 and any(
                l.get("check") == "historical-origin co-tenancy" and l.get("ip") == "198.51.100.41"
                for l in fr3["co_tenancy_leads"]),
               "historical origin's CURRENT co-tenants are held as a dated lead, never seeded")
            ok(not any(a.startswith("t") and a.endswith(".example") and a[1:-8].isdigit() for a in cands3),
               "an origin answering > MAX_IP_COHOSTS apexes is shared hosting — no co-tenant seeds")
            _leads = {}
            CS._enrichment_leads_from_raw(raws3["198.51.100.40"], _leads)
            ok(not _leads, "a collected origin IP raw yields no apex-scoped phonebook/dork/GitHub legs")
            ok("198.51.100.45" in CS.shared_hosting_ips(cdir3), "IPPivot raw counts toward shared_hosting_ips")
            ok("opsdomain.example" not in cands3 and any(r["apex"] == "opsdomain.example" for r in fr3["related_leads"]),
               "a PTR name is a related lead to triage, never a seed")
            ok("198.51.100.40" not in fr3["ips_pending"], "an already collected origin IP is not re-queued")

            # --- 8b. an UNSTAMPED IP raw (harness collect without WP_CASE_DIR) still holds stale co-tenants
            raws4 = {SEED: _domain_raw(SEED, seed_lr, created="2022-01-01"),
                     "198.51.100.41": _ip_raw("198.51.100.41", ["later-tenant.example"])}
            cdir4 = _case(os.path.join(tmp, "d"), raws4, {SEED: 0, "198.51.100.41": 0})
            fr4 = CS.frontier(cdir4, max_new=0)
            ok("later-tenant.example" not in fr4["candidates"] and any(
                l.get("check") == "historical-origin co-tenancy" for l in fr4["co_tenancy_leads"]),
               "unstamped IP raw: frontier recomputes origin_context — stale co-tenants stay leads")

            # --- 9. origin_context (what IPPivot stamps into meta) ----------------------------------
            ctx = OH.origin_context(cdir3, "198.51.100.41")
            ok(ctx and ctx["hosts"] == [SEED] and ctx["era"] == "historical" and ctx["stale"] is True,
               "origin_context: host, era and staleness of the tenancy")

            # --- 9b. ambiguous network: collected, co-tenants always held (frontier + ingest) --------
            amb_lr = {"securitytrails_dns_history": {"eras": [
                {"ip": "198.51.100.80", "first_seen": _d(60), "last_seen": _d(5), "org": "DDoS-Guard Ltd"}]}}
            cdir5 = _case(os.path.join(tmp, "e"), {SEED: _domain_raw(SEED, amb_lr)}, {SEED: 1})
            fr5 = CS.frontier(cdir5, max_new=8)
            d80 = fr5["origin_ips"].get("198.51.100.80") or {}
            ok(fr5["ips_pending"] == ["198.51.100.80"] and d80.get("ambiguous") and "held" in d80.get("cotenants", ""),
               "an ambiguous (recent) origin is queued for collection with co-tenants marked held")
            with open(os.path.join(cdir5, "raw", "198.51.100.80.json"), "w", encoding="utf-8") as fh:
                json.dump(_ip_raw("198.51.100.80", ["behind-edge.example"]), fh)   # unstamped
            st5 = CS.load_state(cdir5)
            st5["hops"]["198.51.100.80"] = 1
            CS.save_state(cdir5, st5)
            fr5b = CS.frontier(cdir5, max_new=0)
            ok("behind-edge.example" not in fr5b["candidates"] and any(
                l.get("check") == "ambiguous-network co-tenancy" for l in fr5b["co_tenancy_leads"]),
               "ambiguous network: co-tenants are a lead even though the tenancy is recent")

            # --- 9c. loop and harness agree on an origin IP's hop -------------------------------------
            cdir6 = _case(os.path.join(tmp, "f"), {"sub.seed.example": _domain_raw("sub.seed.example", seed_lr)},
                          {SEED: 0, "sub.seed.example": 1}, depth=3)
            fr6 = CS.frontier(cdir6, max_new=8)
            loop_hops = {SEED: 0, "sub.seed.example": 1}
            INTEL._promote(fr6, loop_hops, 3)
            harness_hop = CS.record_origin_ip_hop(cdir6, "198.51.100.40", ["sub.seed.example"])
            ok(loop_hops.get("198.51.100.40") == harness_hop == 1,
               f"origin IP hop: loop {loop_hops.get('198.51.100.40')} == harness {harness_hop} == host hop 1")

            # --- 9d. the origin_history tool's CLI (offline, case path) ---------------------------------
            summ = OH.case_summary(cdir3)
            row = next((s for s in summ if s["host"] == SEED), {})
            ok(row and {o["ip"] for o in row["origins"] if o["collected"]} >= {"198.51.100.40", "198.51.100.41"}
               and row["counts"].get("cdn", 0) >= 1,
               "case_summary: per-host origins flagged collected, suppressed edges counted")
            ok(OH.origin_context(cdir3, "198.51.100.99") is None, "an IP no case host used has no context")

            # --- 9e. SECOND LOOK: history named no network, the IP lookup does ------------------------
            plain_lr = {"passivedns": {"hosts": [{"host": SEED, "ip": "198.51.100.90"},
                                                 {"host": SEED, "ip": "198.51.100.91"}]},
                        "dns": {"ips": ["198.51.100.90", "198.51.100.91"]}}
            raws7 = {SEED: _domain_raw(SEED, plain_lr)}
            for ip_, asn_, cohost in (("198.51.100.90", "AS57724", "ddg-tenant.example"),
                                      ("198.51.100.91", "AS20940", "akamai-tenant.example")):
                r_ = _ip_raw(ip_, [cohost])
                r_["artifacts"]["ip_intel"]["ipinfo"] = {"asn": asn_, "org_name": "Some Network"}
                raws7[ip_] = r_
            cdir7 = _case(os.path.join(tmp, "g"), raws7, {SEED: 0, "198.51.100.90": 0, "198.51.100.91": 0})
            fr7 = CS.frontier(cdir7, max_new=0)
            checks7 = {l.get("ip"): l.get("check") for l in fr7["co_tenancy_leads"]}
            ok("ddg-tenant.example" not in fr7["candidates"]
               and checks7.get("198.51.100.90") == "ambiguous-network co-tenancy",
               "IP lookup says DDoS-Guard (AS57724): co-tenants held although history named no network")
            ok("akamai-tenant.example" not in fr7["candidates"]
               and checks7.get("198.51.100.91") == "edge network (IP lookup)",
               "IP lookup says Akamai CDN (AS20940): co-tenants never seeded")
            hist_lead = next((l for l in fr3["co_tenancy_leads"]
                              if l.get("check") == "historical-origin co-tenancy"), {})
            ok(hist_lead.get("domains") == ["later-tenant.example"], "origin-sweep leads carry the FULL domain list")

            # --- 9f. cloud/VPS box (IP lookup flags hosting): ≤ threshold auto, above → approval ----
            vps_n = OH.VPS_AUTO_MAX_COTENANTS
            raws8 = {SEED: _domain_raw(SEED, plain_lr)}
            for ip_, n_ in (("198.51.100.90", vps_n), ("198.51.100.91", vps_n + 1)):
                r_ = _ip_raw(ip_, [f"v{n_}t{i}.example" for i in range(n_)], ctx_recent)
                r_["artifacts"]["ip_intel"].update({"noise": True, "noise_reason": "ASN flagged noise",
                                                    "ipinfo": {"asn": "AS20473", "org_name": "Vultr"}})
                raws8[ip_] = r_
            cdir8 = _case(os.path.join(tmp, "h"), raws8, {SEED: 0, "198.51.100.90": 0, "198.51.100.91": 0})
            fr8 = CS.frontier(cdir8, max_new=0)
            small = {f"v{vps_n}t{i}.example" for i in range(vps_n)}
            ok(small <= set(fr8["candidates"]) and all(
                fr8["candidates"][d]["sources"] == ["ip_cohost"] for d in small),
               f"VPS box with {vps_n} co-tenants: all queued automatically as neighbours")
            big = sorted(f"v{vps_n + 1}t{i}.example" for i in range(vps_n + 1))
            vlead = next((l for l in fr8["co_tenancy_leads"] if l.get("ip") == "198.51.100.91"), {})
            ok(vlead.get("check") == "vps co-tenancy — approve" and vlead.get("domains") == big
               and vlead.get("sample_apexes") == big and not set(big) & set(fr8["candidates"]),
               f"VPS box with {vps_n + 1} co-tenants: nothing queued, approval lead lists every domain")
            vcands = [x for x in CS._domain_cands_from_frontier({"co_tenancy_leads": [vlead]}, 25)]
            ok({x.selector for x in vcands} == set(big) and all(x.est_hits > 25 for x in vcands),
               "every VPS co-tenant becomes its own approval item (est_hits above auto_max)")
            ok(all(f"approve_ip:198.51.100.91" in x.sources for x in vcands),
               "each VPS approval item carries its box, so the approved run can record the approval")

            # --- 9g. ONE count on both sides; the reverse index's own total; analyst approval ----------
            import ingest_webpivot as IW
            from knowledge_base import KB as _RealKB

            class _K:
                def __init__(self):
                    self.edges = []

                def add_edge(self, *a, **k):
                    self.edges.append(a)

                def add_fact(self, *a, **k):
                    pass

                def touch(self, *a, **k):
                    pass

                def save_evidence(self, *a, **k):
                    return "ev"

            def _vps(ip_, names_, ctx_, total=None):
                r_ = _ip_raw(ip_, names_, ctx_)
                r_["artifacts"]["ip_intel"].update({"noise": True, "ipinfo": {"asn": "AS20473", "org_name": "Vultr"}})
                if total is not None:
                    r_["artifacts"]["ip_intel"]["cohost_total"] = total
                return r_

            # (a) 11 co-tenants, 2 of them the case hosts that resolved there → 9 others on BOTH sides
            ctx_two = dict(ctx_recent, hosts=[SEED, "case-two.example"])
            others = [f"p{i}.example" for i in range(vps_n - 1)]
            r_a = _vps("198.51.100.93", others + [SEED, "case-two.example"], ctx_two)
            cdir9 = _case(os.path.join(tmp, "i"), {SEED: _domain_raw(SEED, plain_lr), "198.51.100.93": r_a},
                          {SEED: 0, "198.51.100.93": 0})
            fr9 = CS.frontier(cdir9, max_new=0)
            front_auto = (set(others) <= set(fr9["candidates"])
                          and not any(l.get("ip") == "198.51.100.93" for l in fr9["co_tenancy_leads"]))
            k9 = _K()
            IW._ingest_ip(k9, r_a, r_a["meta"], "198.51.100.93", TODAY.isoformat(), TODAY.isoformat())
            ok(front_auto and bool(k9.edges),
               "11 co-tenants incl. 2 case hosts: frontier AND ingest both count 9 → automatic on both sides")

            # (b) a short list on a box the reverse index says answers for 300 sites → approval, no link
            r_b = _vps("198.51.100.94", [f"q{i}.example" for i in range(5)], ctx_recent, total=300)
            cdir10 = _case(os.path.join(tmp, "j"), {SEED: _domain_raw(SEED, plain_lr), "198.51.100.94": r_b},
                           {SEED: 0, "198.51.100.94": 0})
            fr10 = CS.frontier(cdir10, max_new=0)
            k10 = _K()
            IW._ingest_ip(k10, r_b, r_b["meta"], "198.51.100.94", TODAY.isoformat(), TODAY.isoformat())
            ok(any(l.get("check") == "vps co-tenancy — approve" for l in fr10["co_tenancy_leads"])
               and "q0.example" not in fr10["candidates"] and not k10.edges,
               "5 listed but cohost_total 300: never automatic — approval lead, no seeds, no links")

            # (c) analyst approves 2 of the 11-site box's domains: ONLY those are seeded and linked
            okd = big[:2]
            CS.record_approved_cohost(cdir8, "198.51.100.91", okd)
            fr8b = CS.frontier(cdir8, max_new=0)
            rest_lead = next((l for l in fr8b["co_tenancy_leads"] if l.get("ip") == "198.51.100.91"), {})
            ok(set(okd) <= set(fr8b["candidates"]) and not set(big[2:]) & set(fr8b["candidates"])
               and rest_lead.get("domains") == big[2:],
               "approve 2 of 11: those 2 seeded; the 9 others stay an approval lead (never turn automatic)")
            kb8 = _RealKB(os.path.join(tmp, "kb8"))
            IW.ingest_file(kb8, os.path.join(cdir8, "raw", "198.51.100.91.json"))
            linked = {e["src"] for e in kb8.edges() if e["rel"] == "hosted_on" and e["dst"] == "ip:198.51.100.91"}
            ok(linked == set(okd), f"ingest_file after approving 2: exactly those 2 linked ({sorted(linked)})")
            kb8b = _RealKB(os.path.join(tmp, "kb8b"))
            IW.ingest_file(kb8b, os.path.join(cdir8, "raw", "198.51.100.90.json"))
            ok({e["src"] for e in kb8b.edges() if e["rel"] == "hosted_on"} == small,
               "ingest_file, unapproved small VPS box: its co-tenants link automatically")

            # (d) partition: 15-site box (a landlord), analyst approves 2 — they and the case host bind,
            #     the 13 others and a collected stranger resolving there do not
            box = "198.51.100.96"
            fifteen = [f"r{i:02d}.example" for i in range(15)]
            seed_hist = {"securitytrails_dns_history": {"eras": [
                {"ip": box, "first_seen": _d(90), "last_seen": _d(3)}]}}
            r_d = _vps(box, fifteen, dict(ctx_recent, hosts=[SEED]))
            raws11 = {SEED: _domain_raw(SEED, seed_hist), box: r_d,
                      "rogue.example": _domain_raw("rogue.example", {"dns": {"ips": [box]}})}
            for d_ in fifteen[:2]:
                raws11[d_] = _domain_raw(d_, {"dns": {"ips": [box]}})
            cdir11 = _case(os.path.join(tmp, "k"), raws11, {SEED: 0, box: 0})
            ok(box in CS.shared_hosting_ips(cdir11), "15-site box is a landlord for the partition")

            def _partition():
                import query as Q
                kdir = tempfile.mkdtemp(dir=tmp)
                kb_ = _RealKB(kdir)
                for f_ in sorted(os.listdir(os.path.join(cdir11, "raw"))):
                    IW.ingest_file(kb_, os.path.join(cdir11, "raw", f_))
                restrict = {SEED, "rogue.example", *fifteen[:2]}
                comps = Q._components(kb_, kdir, 8, restrict, noise_ips=CS.shared_hosting_ips(cdir11),
                                      allow_edge=CS.approved_edge_allow(cdir11))
                return [set(c) for c in comps], kb_
            comps0, kb0 = _partition()
            ok(any(e["src"] == SEED and e["dst"] == f"ip:{box}" and e["rel"] == "hosted_on" for e in kb0.edges()),
               "ingest_file on the DOMAIN raw writes its domain → ip: link from origin history")
            ok(all(len(c) == 1 for c in comps0), "no approval: the 15-site box binds nothing")
            CS.record_approved_cohost(cdir11, box, fifteen[:2])
            comps1, _ = _partition()
            ok({SEED, *fifteen[:2]} in comps1 and {"rogue.example"} in comps1,
               "approve 2 of 15: those 2 + the case host bind; a collected stranger on the box does not")

            # (f) --all approval of an 11-site box, through the REAL clustering step at its default cap
            #     (8): the case host + all 11 approved sites form ONE cluster bound by ip:<box>
            box2 = "198.51.100.97"
            eleven = [f"s{i:02d}.example" for i in range(11)]
            raws12 = {SEED: _domain_raw(SEED, {"securitytrails_dns_history": {"eras": [
                          {"ip": box2, "first_seen": _d(90), "last_seen": _d(3)}]}}),
                      box2: _vps(box2, eleven, dict(ctx_recent, hosts=[SEED]))}
            cdir12 = _case(os.path.join(tmp, "m"), raws12, {SEED: 0, box2: 0, **{d_: 1 for d_ in eleven}})
            saved_argv = sys.argv
            try:
                sys.argv = ["case_state.py", "approve-cohost", cdir12, box2, "typo.example"]
                rc_typo = CS.main()
                sys.argv = ["case_state.py", "approve-cohost", cdir12, box2, "--all"]
                rc_all = CS.main()
            finally:
                sys.argv = saved_argv
            ok(rc_typo == 2 and not (OH.approved_cohosts(cdir12).get(box2) or {}).get("domains", set()) - set(eleven)
               and rc_all == 0, "approve-cohost rejects a domain not on the lead; --all records the lead's 11")
            for d_ in eleven:
                with open(os.path.join(cdir12, "raw", f"{d_}.json"), "w", encoding="utf-8") as fh:
                    json.dump(_domain_raw(d_, {"dns": {"ips": [box2]}}), fh)
            kdir12 = os.path.join(tmp, "kb12")
            kb12 = _RealKB(kdir12)
            for f_ in sorted(os.listdir(os.path.join(cdir12, "raw"))):
                IW.ingest_file(kb12, os.path.join(cdir12, "raw", f_))
            saved_kb_path = INTEL.KB
            try:
                INTEL.KB = kdir12
                cl12 = INTEL._write_clusters(cdir12, "CASE-0001", hosts=[SEED, *eleven])
            finally:
                INTEL.KB = saved_kb_path
            big12 = next((c for c in cl12 if SEED in c["domains"]), {})
            ok(set(big12.get("domains") or []) == {SEED, *eleven}
               and any(f"ip:{box2}" in b["indicator"] for b in big12.get("binding_indicators") or []),
               "--all of 11 at the default cap (8): case host + 11 sites are ONE cluster, bound by ip:<box>")

            # (g) one platform tenant approved ≠ every tenant of the platform
            box3 = "198.51.100.98"
            tenants = ["kit.pages.dev", "other.pages.dev"] + [f"t{i:02d}.example" for i in range(10)]
            cdir13 = _case(os.path.join(tmp, "n"), {SEED: _domain_raw(SEED, plain_lr),
                                                     box3: _vps(box3, tenants, ctx_recent)}, {SEED: 0, box3: 0})
            CS.record_approved_cohost(cdir13, box3, ["kit.pages.dev"])
            fr13 = CS.frontier(cdir13, max_new=0)
            k13 = _K()
            raw13 = json.load(open(os.path.join(cdir13, "raw", f"{box3}.json")))
            IW._ingest_ip(k13, raw13, dict(raw13["meta"], cohost_approved_domains=["kit.pages.dev"]),
                          box3, TODAY.isoformat(), TODAY.isoformat())
            ok("kit.pages.dev" in fr13["candidates"] and "other.pages.dev" not in fr13["candidates"]
               and {a[1] for a in k13.edges} == {"kit.pages.dev"}
               and OH.approval_allows(OH.approved_cohosts(cdir13), "kit.pages.dev", f"ip:{box3}")
               and not OH.approval_allows(OH.approved_cohosts(cdir13), "other.pages.dev", f"ip:{box3}"),
               "approving kit.pages.dev seeds, links and binds ONLY that tenant, never other.pages.dev")

            # (e) approve-cohost CLI (in-process, so the stand-in CDN index applies): --all records the
            #     lead's CURRENT list; neither domains nor --all → error
            saved_argv = sys.argv
            try:
                sys.argv = ["case_state.py", "approve-cohost", cdir10, "198.51.100.94"]
                rc_bad = CS.main()
                sys.argv = sys.argv + ["--all"]
                rc_good = CS.main()
            finally:
                sys.argv = saved_argv
            rec = (OH.approved_cohosts(cdir10).get("198.51.100.94") or {})
            ok(rc_bad == 2 and rc_good == 0 and rec.get("domains") == {f"q{i}.example" for i in range(5)},
               "approve-cohost: refuses with no domains, --all freezes the lead's current list")

        # --- 10. KB ingest rails ---------------------------------------------------------------------
        import ingest_webpivot as IW

        class _KB:
            def __init__(self):
                self.edges, self.facts = [], []

            def add_edge(self, *a, **k):
                self.edges.append((a, k))

            def add_fact(self, *a, **k):
                self.facts.append(a)

            def touch(self, *a, **k):
                pass

            def save_evidence(self, *a, **k):
                return "ev"

        kb = _KB()
        lr_veto = {"pdns": {"records": [{"rrtype": "A", "rdata": "198.51.100.70", "time_first": 1700000000,
                                         "time_last": 1710000000}]},
                   "origin_history": {"ips": [
                       {"ip": "198.51.100.70", "status": "cdn", "sources": ["pdns", "webamon_servers"]},
                       {"ip": "198.51.100.71", "status": "origin", "sources": ["securitytrails_dns_history"],
                        "first_seen": "2024-01-01", "last_seen": "2024-06-01"}]}}
        IW._resolved_ip_edges(kb, SEED, lr_veto, TODAY.isoformat(), "ev")
        targets = {a[4]: k.get("attrs") for a, k in kb.edges}
        ok("ip:198.51.100.70" not in targets,
           "a pdns A record on an address origin_history classed cdn produces NO hosted_on edge")
        ok((targets.get("ip:198.51.100.71") or {}).get("first_seen") == "2024-01-01"
           and "history:securitytrails_dns_history" in (targets.get("ip:198.51.100.71") or {}).get("via", ""),
           "a history-only origin becomes a dated hosted_on edge")

        kb2 = _KB()
        IW._ingest_ip(kb2, _ip_raw("198.51.100.41", ["later-tenant.example"], ctx_stale),
                      {"host": "198.51.100.41", "kind": "ip", "origin_context": ctx_stale},
                      "198.51.100.41", TODAY.isoformat(), TODAY.isoformat())
        ok(not kb2.edges and any(f[2] == "co_tenant" for f in kb2.facts),
           "stale-tenancy origin: co-tenants ingested as facts, never clustering edges")
        ok(any(f[2] == "origin_of" for f in kb2.facts), "the origin context is recorded on the ip: indicator")
        kb3 = _KB()
        IW._ingest_ip(kb3, _ip_raw("198.51.100.40", ["sib-one.example"], ctx_recent),
                      {"host": "198.51.100.40", "kind": "ip", "origin_context": ctx_recent},
                      "198.51.100.40", TODAY.isoformat(), TODAY.isoformat())
        ok(any(a[4] == "ip:198.51.100.40" for a, _k in kb3.edges), "recent origin: co-tenant edge kept")
        kb4 = _KB()
        ctx_amb = dict(ctx_recent, ambiguous=True)
        IW._ingest_ip(kb4, _ip_raw("198.51.100.80", ["behind-edge.example"], ctx_amb),
                      {"host": "198.51.100.80", "kind": "ip", "origin_context": ctx_amb},
                      "198.51.100.80", TODAY.isoformat(), TODAY.isoformat())
        ok(not kb4.edges, "ambiguous network: recent co-tenants are facts at ingest, never clustering edges")
        for ip_, asn_ in (("198.51.100.90", "AS57724"), ("198.51.100.91", "AS20940")):
            kb5 = _KB()
            r_ = _ip_raw(ip_, ["tenant.example"], ctx_recent)
            r_["artifacts"]["ip_intel"]["ipinfo"] = {"asn": asn_}
            IW._ingest_ip(kb5, r_, {"host": ip_, "kind": "ip", "origin_context": ctx_recent},
                          ip_, TODAY.isoformat(), TODAY.isoformat())
            ok(not kb5.edges, f"ingest second look: {asn_} box with a recent context writes no co-tenant edges")
        for n_, want_edges in ((OH.VPS_AUTO_MAX_COTENANTS, True), (OH.VPS_AUTO_MAX_COTENANTS + 1, False)):
            kb6 = _KB()
            r_ = _ip_raw("198.51.100.92", [f"t{i}.example" for i in range(n_)], ctx_recent)
            r_["artifacts"]["ip_intel"].update({"noise": True, "ipinfo": {"asn": "AS20473", "org_name": "Vultr"}})
            IW._ingest_ip(kb6, r_, {"host": "198.51.100.92", "kind": "ip", "origin_context": ctx_recent},
                          "198.51.100.92", TODAY.isoformat(), TODAY.isoformat())
            ok(bool(kb6.edges) == want_edges,
               f"ingest VPS box with {n_} co-tenants: {'linked' if want_edges else 'facts only until approved'}")

        # --- 11. shared-origin list stays bounded (one VPS, 12 hosts → 66 pairs) -----------------------
        import evidence_report as ER
        many = [_domain_raw(f"h{i}.seed.example", {"dns": {"ips": ["198.51.100.95"]}}) for i in range(12)]
        sec = "\n".join(ER._origin_history_section(many))
        line = next((l for l in sec.splitlines() if l.startswith("- `198.51.100.95`")), "")
        ok(line.count("↔") == ER._MAX_ORIGIN_PAIRS and "+56 more pair(s)" in line,
           "shared historical origin: pairs capped, the remainder counted")
    finally:
        OH._cdn = saved_cdn
        CS.ROOT, CS.KB_DIR, CS._BENIGN = saved_root, saved_kb, saved_benign
        CS._cdn = saved_cs_cdn
        CS._CDN_IDX[:] = saved_cs_idx
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    print(f"\n{p}/{p + f} passed")
    sys.exit(1 if f else 0)
